//! The file loop and the compress path, in the order GNU gzip 1.15 was
//! observed to check things for each operand: open (without following a
//! final symlink unless `-f` or `-c`), then directory, regular file,
//! set-user-ID, sticky bit and link count, then the suffix, then the
//! output's existence; compress; copy the input's mode, owner and times;
//! remove the input. Decompression, `-t` and `-l` (`decompress.rs`) follow
//! the same order with their own suffix rules.
//!
//! Exit codes: 0, 1 for an error, 2 for a warning; across operands an error
//! is never lowered to a warning.
//!
//! Output is written under a temporary name in the output's directory and
//! published only once complete (`host::publish`), so a failure never
//! leaves a partial file, and an output that appears meanwhile is refused,
//! never replaced.

use std::fs::{self, File, Metadata};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use super::args::{Mode, Settings};
use super::list::Lister;
use super::messages::{self as m, PROGRAM, printf, quote, ratio};
use crate::compat::gzip::member::{Engine, Header, compress_member};
use crate::compat::host::{
    Host, InFile, Published, create_temp, publish, same_file, stdin_file, strerror,
};

mod decompress;

/// The suffixes gzip will not compress again, matched without regard to
/// ASCII case (observed: `gzip f.GZ`, `f-Z`, `f.TAZ` are skipped; `f.bz2`,
/// `f_GZ`, `f.tz` are compressed).
const KNOWN_SUFFIXES: [&[u8]; 7] = [b".gz", b".z", b"-gz", b"-z", b"_z", b".tgz", b".taz"];

/// The OS byte GNU writes (observed: 3, Unix, on macOS and Linux).
const OS_UNIX: u8 = 3;

/// The run has stopped (a terminal refused, or a write to standard output
/// failed); the code is in [`Gz::exit`].
struct Stop;
type Step = Result<(), Stop>;

/// Run the operation `s` describes against `host`; returns the exit code.
pub(super) fn execute(mut s: Settings, host: &mut Host, err: &mut dyn Write) -> u8 {
    let files = std::mem::take(&mut s.files);
    let mut g = Gz {
        s,
        host,
        err,
        exit: 0,
        stdout: None,
        stdin_named: false,
        list: Lister::default(),
        stale: None,
        time_stamp: 0,
        descend: None,
    };
    let run = if files.is_empty() {
        g.treat_stdin()
    } else {
        files.iter().try_for_each(|f| g.treat(f))
    };
    // `-l`'s totals, unless the run was stopped.
    if run.is_ok() && g.s.mode == Mode::List {
        let (verbose, quiet) = (g.s.verbose > 0, g.s.quiet);
        let mut list = std::mem::take(&mut g.list);
        list.finish(g.stdout_writer(), verbose, quiet, files.len());
        g.list = list;
    }
    g.finish();
    g.exit
}

struct Gz<'a> {
    s: Settings,
    host: &'a mut Host,
    err: &'a mut dyn Write,
    /// The worst outcome so far: 0, 2 (warning) or 1 (error).
    exit: u8,
    /// Standard output, opened on first use and kept for every member.
    stdout: Option<BufWriter<Box<dyn Write + Send>>>,
    /// A file has been compressed: from now on standard input is stored
    /// under the name `stdin` (observed: `gzip a -` names it, `gzip - a`
    /// does not).
    stdin_named: bool,
    /// `-l`'s running state.
    list: Lister,
    /// The last output written under `-k`, which a run-ending failure in
    /// the next input's header removes (see `decompress::refused`).
    stale: Option<PathBuf>,
    /// The time `-lv` dates an input by: the last input file's
    /// modification time (or `-N`'s stored one), which a pipe on standard
    /// input does not change.
    time_stamp: i64,
    /// Under `-r`, the entries of the directory the last operand turned
    /// out to be, for [`Gz::treat`] to visit next (`recurse` leaves them
    /// here rather than recursing, so depth costs heap, not stack).
    descend: Option<Vec<Vec<u8>>>,
}

/// Counts the bytes written through it.
struct Counting<'w> {
    inner: &'w mut dyn Write,
    n: u64,
}

impl Write for Counting<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let k = self.inner.write(buf)?;
        self.n += k as u64;
        Ok(k)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// What one compression produced.
struct Packed {
    bytes_in: u64,
    /// The deflate body: what `-v`'s ratio counts.
    body: u64,
}

impl Gz<'_> {
    fn say(&mut self, fmt: &str, args: &[&[u8]]) {
        printf(self.err, fmt, args);
    }

    /// A warning: printed unless quiet, and exit 2 unless already worse.
    fn warn(&mut self, fmt: &str, args: &[&[u8]]) {
        if !self.s.quiet {
            self.say(fmt, args);
        }
        if self.exit == 0 {
            self.exit = 2;
        }
    }

    /// An error: always printed, exit 1.
    fn error(&mut self, fmt: &str, args: &[&[u8]]) {
        self.say(fmt, args);
        self.exit = 1;
    }

    /// Flush standard output at the end of the run.
    fn finish(&mut self) {
        if let Some(mut out) = self.stdout.take()
            && let Err(e) = out.flush()
        {
            self.error(m::IO_FAILED, &[PROGRAM, b"stdout", &strerror(&e)]);
        }
    }

    // ---- standard input ----

    /// Compress standard input to standard output (`-` or no operands).
    fn treat_stdin(&mut self) -> Step {
        if self.s.mode != Mode::Compress {
            return self.decompress_stdin();
        }
        if !self.s.force && (self.host.stdout_is_tty() || self.s.presume_tty) {
            if !self.s.quiet {
                self.say(m::NOT_TO_TERMINAL, &[PROGRAM, PROGRAM]);
            }
            self.exit = 1;
            return Err(Stop);
        }
        // A regular file on standard input gives its time; a pipe gives 0.
        let meta = match self.host {
            Host::Real => stdin_file().ok().and_then(|f| f.metadata().ok()),
            Host::Sandbox(_) => None,
        };
        let name = (!self.s.no_name && self.stdin_named).then(|| m::STDIN_NAME.to_vec());
        let mtime = self.mtime_of(b"stdin", meta.as_ref());
        let mut input = self.host.stdin();
        let header = self.header(name, mtime);
        let level = self.s.level;
        let r = pack(&header, level, &mut input, self.stdout_writer());
        let p = match r {
            Ok(p) => p,
            Err(e) => {
                self.error(m::IO_FAILED, &[PROGRAM, b"stdout", &strerror(&e)]);
                return Err(Stop);
            }
        };
        if self.s.verbose > 0 {
            let line = format!("{}\n", ratio(p.bytes_in, p.body));
            let _ = self.err.write_all(line.as_bytes());
        }
        Ok(())
    }

    fn stdout_writer(&mut self) -> &mut dyn Write {
        let host = &*self.host;
        self.stdout.get_or_insert_with(|| host.out_writer(None))
    }

    // ---- files ----

    /// One operand, and under `-r` everything below it: depth first, each
    /// directory's entries in the order it lists them, with an explicit
    /// stack of the entries still to visit at each level (final review,
    /// item 4: a frame per level could exhaust the stack on a tree as deep
    /// as `PATH_MAX` allows).
    fn treat(&mut self, name: &[u8]) -> Step {
        let mut stack: Vec<std::vec::IntoIter<Vec<u8>>> = Vec::new();
        let mut next = name.to_vec();
        loop {
            self.treat_one(&next)?;
            if let Some(entries) = self.descend.take() {
                stack.push(entries.into_iter());
            }
            next = loop {
                let Some(level) = stack.last_mut() else {
                    return Ok(());
                };
                match level.next() {
                    Some(child) => break child,
                    None => {
                        stack.pop();
                    }
                }
            };
        }
    }

    /// One name: the checks, then compression (or [`Gz::treat_compressed`]).
    fn treat_one(&mut self, name: &[u8]) -> Step {
        if name == b"-" {
            return self.treat_stdin();
        }
        if self.s.mode != Mode::Compress {
            return self.treat_compressed(name);
        }
        let qname = quote(name);
        let path = self.host.path(name);
        let follow = self.s.force || self.s.to_stdout;
        let opened =
            open_input(self.host, &path, follow).and_then(|f| f.metadata().map(|md| (f, md)));
        let (file, meta) = match opened {
            Ok(x) => x,
            Err(e) => {
                self.error(m::OPEN_FAILED, &[PROGRAM, &qname, &strerror(&e)]);
                return Ok(());
            }
        };
        if meta.is_dir() {
            drop(file);
            if self.s.recursive {
                return self.recurse(name);
            }
            self.warn(m::IS_DIRECTORY, &[PROGRAM, &qname]);
            return Ok(());
        }
        if !self.s.to_stdout && !self.file_checks(&qname, &meta) {
            return Ok(());
        }
        if self.s.to_stdout {
            return self.compress_to_stdout(name, file, &meta);
        }
        self.compress_to_file(name, path, file, &meta);
        Ok(())
    }

    /// The checks an input meets when it is to be replaced by an output
    /// file: a regular file, not set-user-ID, not sticky (unless `-f`), no
    /// other links (unless `-f`). False, with the warning given, if not.
    fn file_checks(&mut self, qname: &[u8], meta: &Metadata) -> bool {
        if !meta.is_file() {
            self.warn(m::NOT_REGULAR, &[PROGRAM, qname]);
            return false;
        }
        let mode = mode_of(meta);
        if mode & 0o4000 != 0 {
            self.warn(m::SET_USER_ID, &[PROGRAM, qname]);
            return false;
        }
        if mode & 0o1000 != 0 && !self.s.force {
            self.warn(m::STICKY, &[PROGRAM, qname]);
            return false;
        }
        let others = other_links(meta);
        if others > 0 && !self.s.force {
            let s: &[u8] = if others > 1 { b"s" } else { b"" };
            let n = others.to_string();
            self.warn(m::HAS_LINKS, &[PROGRAM, qname, n.as_bytes(), s]);
            return false;
        }
        true
    }

    /// `-r` on a directory: every entry, in the order the directory lists
    /// them (read in full first, so outputs created meanwhile are not
    /// visited), left in `descend` for [`Gz::treat`] to visit.
    fn recurse(&mut self, name: &[u8]) -> Step {
        let entries: Vec<Vec<u8>> = match fs::read_dir(self.host.path(name)) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().as_encoded_bytes().to_vec())
                .collect(),
            Err(e) => {
                self.error(m::OPEN_FAILED, &[PROGRAM, &quote(name), &strerror(&e)]);
                return Ok(());
            }
        };
        let children = entries
            .into_iter()
            .map(|e| {
                let mut child = name.to_vec();
                if !child.ends_with(b"/") {
                    child.push(b'/');
                }
                child.extend_from_slice(&e);
                child
            })
            .collect();
        self.descend = Some(children);
        Ok(())
    }

    /// `-c`: one member onto standard output.
    fn compress_to_stdout(&mut self, name: &[u8], mut file: InFile, meta: &Metadata) -> Step {
        let qname = quote(name);
        self.stdin_named = true;
        self.verbose_name(&qname);
        let header = self.file_header(name, meta);
        let level = self.s.level;
        let r = pack(&header, level, &mut file, self.stdout_writer());
        let p = match r {
            Ok(p) => p,
            Err(e) => {
                self.error(m::IO_FAILED, &[PROGRAM, b"stdout", &strerror(&e)]);
                return Err(Stop);
            }
        };
        self.verbose_done(p.bytes_in, p.body, m::STDOUT_NAME);
        Ok(())
    }

    /// Compress `name` to `name` + suffix.
    fn compress_to_file(&mut self, name: &[u8], path: PathBuf, mut file: InFile, meta: &Metadata) {
        let qname = quote(name);
        if !self.s.force
            && let Some(suf) = self.suffix_of(name)
        {
            // Under `-r` the note needs `-v` (observed: `gzip -r d` over
            // `d/b.gz` is silent, `gzip -rv d` prints it).
            let shown = if self.s.recursive {
                self.s.verbose > 0
            } else {
                !self.s.quiet
            };
            if shown {
                self.say(m::HAS_SUFFIX, &[PROGRAM, &qname, &suf]);
            }
            return;
        }
        let out_name = [name, &self.s.suffix].concat();
        let qout = quote(&out_name);
        let out_path = self.host.path(&out_name);
        let Some(replace) = self.may_write(&out_path, &qout, &path, meta) else {
            return;
        };
        let (tmp, tmp_file) = match create_temp(&parent_of(&out_path), "gzip") {
            Ok(t) => t,
            Err(e) => {
                self.error(m::OPEN_FAILED, &[PROGRAM, &qout, &strerror(&e)]);
                return;
            }
        };
        self.stdin_named = true;
        self.verbose_name(&qname);
        let header = self.file_header(name, meta);
        let level = self.s.level;
        let packed = {
            let mut w = self.host.out_writer(Some(tmp_file));
            pack(&header, level, &mut file, &mut w).and_then(|p| w.flush().map(|()| p))
        };
        let p = match packed {
            Ok(p) => p,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                self.error(m::IO_FAILED, &[PROGRAM, &qout, &strerror(&e)]);
                return;
            }
        };
        if self.commit(&tmp, &out_path, &qout, meta, None, replace, &path, &qname) {
            self.verbose_done(p.bytes_in, p.body, &qout);
        }
    }

    /// Whether the output `out_path` may be written: `Some(replace)`, or
    /// `None` when it exists and is not to be replaced (said, exit 2). With
    /// `-f` it is removed first, and a failure to remove it is an error
    /// (exit 1, the run goes on; observed: `gzip -df a.gz` with a directory
    /// `a` says `gzip: a: Operation not permitted`, macOS's `unlink` error,
    /// and so does `gzip -f a` with a directory `a.gz`); otherwise a
    /// terminal on standard input is asked. Ruling T8-5: when the output
    /// is the input itself (`gzip -dNf a.gz` storing `a.gz`, or `A.GZ` on
    /// a case-insensitive volume), it is not removed first, so a failed
    /// decode leaves the input; the publish's rename replaces it on
    /// success. "Is the input" is judged by identity (`input_meta`, the
    /// opened input's), never by spelling; off unix, where there is no
    /// identity, by `input`'s spelling.
    fn may_write(
        &mut self,
        out_path: &Path,
        qout: &[u8],
        input: &Path,
        input_meta: &Metadata,
    ) -> Option<bool> {
        if fs::symlink_metadata(out_path).is_err() {
            return Some(false);
        }
        if self.s.force {
            let is_input = fs::metadata(out_path)
                .is_ok_and(|o| same_file(&o, input_meta).unwrap_or(out_path == input));
            if !is_input && let Err(e) = fs::remove_file(out_path) {
                self.error(m::IO_FAILED, &[PROGRAM, qout, &strerror(&e)]);
                return None;
            }
            return Some(true);
        }
        self.say(m::ALREADY_EXISTS, &[PROGRAM, qout]);
        if self.host.stdin_is_tty() {
            self.say(m::ASK_OVERWRITE, &[]);
            if ask_yes() {
                return Some(true);
            }
        }
        self.say(m::NOT_OVERWRITTEN, &[]);
        if self.exit == 0 {
            self.exit = 2;
        }
        None
    }

    /// Finish a written output `tmp`: the input's mode, owner and times
    /// (the modification time `mtime` instead, when given), then publish it
    /// as `out_path` and remove the input `path` unless `-k` (or it is
    /// `out_path`). False if it
    /// was not published (said).
    #[allow(clippy::too_many_arguments)]
    fn commit(
        &mut self,
        tmp: &Path,
        out_path: &Path,
        qout: &[u8],
        meta: &Metadata,
        mtime: Option<std::time::SystemTime>,
        replace: bool,
        path: &Path,
        qname: &[u8],
    ) -> bool {
        // The mode, owner and times of the input, as GNU copies them; a
        // failure to copy them does not undo the output.
        let _ = crate::compat::copy_metadata_with_mtime(meta, tmp, mtime);
        // The output never keeps the sticky bit (observed: `chmod 1644 a;
        // gzip -f a` makes a 0644 `a.gz`).
        #[cfg(unix)]
        if mode_of(meta) & 0o1000 != 0 {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(
                tmp,
                fs::Permissions::from_mode(mode_of(meta) & 0o7777 & !0o1000),
            );
        }
        match publish(tmp, out_path, replace) {
            Ok(Published::Done) => {}
            Ok(Published::Exists) => {
                self.say(m::ALREADY_EXISTS, &[PROGRAM, qout]);
                self.say(m::NOT_OVERWRITTEN, &[]);
                if self.exit == 0 {
                    self.exit = 2;
                }
                return false;
            }
            Err(e) => {
                let _ = fs::remove_file(tmp);
                self.error(m::IO_FAILED, &[PROGRAM, qout, &strerror(&e)]);
                return false;
            }
        }
        // Ruling T8-4: never remove the input when the output now stands in
        // its place (`gzip -dNf a.gz` with a stored name `a.gz`, or `A.GZ`
        // on a case-insensitive volume): GNU loses both, stuffr keeps the
        // decoded file.
        if !self.s.keep
            && still_the_input(path, meta, out_path)
            && let Err(e) = fs::remove_file(path)
        {
            self.error(m::IO_FAILED, &[PROGRAM, qname, &strerror(&e)]);
            return false;
        }
        true
    }

    /// The suffix `name` already has, as written in `name`, or `None`. Only
    /// the last path component counts, and it must be longer than the
    /// suffix (`.gz` alone and `d/.gz` are compressed). `-S`'s suffix is
    /// tried first when it holds an uppercase letter, last otherwise
    /// (observed: `-S Z` names `z` for `b.gz`, `-S z` names `.gz`).
    fn suffix_of(&self, name: &[u8]) -> Option<Vec<u8>> {
        let base = name.rsplit(|&b| b == b'/').next().unwrap_or(name);
        let custom: &[u8] = &self.s.suffix;
        let mut order: Vec<&[u8]> = KNOWN_SUFFIXES.to_vec();
        if custom.iter().any(u8::is_ascii_uppercase) {
            order.insert(0, custom);
        } else {
            order.push(custom);
        }
        order.into_iter().find_map(|suf| {
            (base.len() > suf.len() && base[base.len() - suf.len()..].eq_ignore_ascii_case(suf))
                .then(|| base[base.len() - suf.len()..].to_vec())
        })
    }

    // ---- headers and -v ----

    fn header(&self, name: Option<Vec<u8>>, mtime: u32) -> Header {
        Header {
            text: false,
            mtime,
            xfl: match self.s.level {
                1 => 4,
                9 => 2,
                _ => 0,
            },
            os: OS_UNIX,
            extra: None,
            name,
            comment: None,
            hcrc: false,
            len: 0,
        }
    }

    /// A file's header: its last path component as FNAME and its
    /// modification time, unless `-n`/`-m` (or it is not a regular file,
    /// which stores time 0; observed with `gzip -c FIFO`).
    fn file_header(&mut self, name: &[u8], meta: &Metadata) -> Header {
        let base = name.rsplit(|&b| b == b'/').next().unwrap_or(name);
        let fname = (!self.s.no_name).then(|| base.to_vec());
        let mtime = self.mtime_of(name, Some(meta));
        self.header(fname, mtime)
    }

    /// The MTIME field for an input: its modification time in seconds when
    /// it is a regular file and times are kept, else 0. A time gzip cannot
    /// store (before 1970, or past 2106) is 0 with a warning.
    fn mtime_of(&mut self, name: &[u8], meta: Option<&Metadata>) -> u32 {
        let Some(meta) = meta.filter(|md| md.is_file() && !self.s.no_time) else {
            return 0;
        };
        let secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        match secs.and_then(|s| u32::try_from(s).ok()) {
            Some(s) => s,
            None => {
                self.warn(m::TIMESTAMP_RANGE, &[PROGRAM, &quote(name)]);
                0
            }
        }
    }

    fn verbose_name(&mut self, qname: &[u8]) {
        if self.s.verbose > 0 {
            self.say(m::VERBOSE_NAME, &[qname]);
        }
    }

    /// `-v`'s ratio of `whole` bytes against `part` (the compressed side
    /// less what is not counted), then the output's name.
    fn verbose_done(&mut self, whole: u64, part: u64, out: &[u8]) {
        if self.s.verbose > 0 {
            let r = ratio(whole, part);
            let _ = self.err.write_all(r.as_bytes());
            let tail = if self.s.keep {
                m::CREATED
            } else {
                m::REPLACED_WITH
            };
            self.say(tail, &[out]);
        }
    }
}

/// The directory an output goes in.
fn parent_of(out_path: &Path) -> PathBuf {
    match out_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Whether the input's name `path` should be removed after the output
/// `out_path` was published: it still names the input (`meta`'s file) and
/// not the output. Judged by identity, so a name that differs from
/// `out_path` only in case, on a volume that folds case, is not removed.
/// A symbolic link (an input given with `-f`) is judged as the link, not
/// what it now leads to: removing it never touches the output's data, so
/// it goes unless the link entry is itself the output's (`a.gz -> a`
/// under `-df` and `l -> l.gz` under `-f` lose the link, as GNU's do,
/// though the link now leads to the fresh output). When `path` cannot be
/// looked up its removal is attempted, so the error is GNU's; off unix,
/// where there is no identity, the spellings decide.
fn still_the_input(path: &Path, meta: &Metadata, out_path: &Path) -> bool {
    if let Ok(link) = fs::symlink_metadata(path)
        && link.file_type().is_symlink()
    {
        let entry = fs::symlink_metadata(out_path).ok();
        return match entry.and_then(|o| same_file(&link, &o)) {
            Some(is_output) => !is_output,
            None => path != out_path,
        };
    }
    let Ok(now) = fs::metadata(path) else {
        return path != out_path;
    };
    let out = fs::metadata(out_path).ok();
    match (same_file(&now, meta), out.and_then(|o| same_file(&now, &o))) {
        (Some(was_input), Some(is_output)) => was_input && !is_output,
        (Some(was_input), None) => was_input,
        _ => path != out_path,
    }
}

/// Write one member of `input` to `out`.
fn pack(h: &Header, level: u32, input: &mut dyn Read, out: &mut dyn Write) -> io::Result<Packed> {
    let mut c = Counting { inner: out, n: 0 };
    let (_crc, bytes_in) = compress_member(h, level, Engine::Miniz, input, &mut c)?;
    let header_len = 10 + h.name.as_ref().map_or(0, |n| n.len() as u64 + 1);
    Ok(Packed {
        bytes_in,
        body: c.n.saturating_sub(header_len + 8),
    })
}

/// Open an input as GNU does: without following a final symlink unless
/// `follow` (its error is then `ELOOP`), and without blocking on a FIFO
/// that has no writer (non-blocking for the open only). Tracked by `host`.
fn open_input(host: &Host, path: &Path, follow: bool) -> io::Result<InFile> {
    open_file(path, follow).map(|f| host.track(path, f))
}

fn open_file(path: &Path, follow: bool) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = libc::O_NONBLOCK;
        if !follow {
            flags |= libc::O_NOFOLLOW;
        }
        let f = File::options().read(true).custom_flags(flags).open(path)?;
        let fd = f.as_raw_fd();
        // SAFETY: `fd` is a descriptor this function owns (through `f`);
        // F_GETFL/F_SETFL only read and change its status flags.
        unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(fd, libc::F_SETFL, fl & !libc::O_NONBLOCK);
            }
        }
        Ok(f)
    }
    #[cfg(not(unix))]
    {
        let _ = follow;
        File::open(path)
    }
}

/// The permission and special bits of `meta` (0 off unix).
fn mode_of(meta: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

/// The input's other hard links.
fn other_links(meta: &Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.nlink().saturating_sub(1)
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

/// Read the answer to the overwrite question from the terminal: yes when
/// the line starts with `y` or `Y` (observed: `y`, `Y`, `yes` overwrite;
/// `n`, an empty line and end of file do not).
fn ask_yes() -> bool {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    let mut stdin = io::stdin().lock();
    loop {
        match stdin.read(&mut byte) {
            Ok(1) if byte[0] != b'\n' => line.push(byte[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            _ => break,
        }
    }
    matches!(line.first(), Some(b'y' | b'Y'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gz(suffix: &[u8]) -> Settings {
        Settings {
            mode: Mode::Compress,
            to_stdout: false,
            force: false,
            keep: false,
            recursive: false,
            quiet: false,
            verbose: 0,
            no_name: false,
            no_time: false,
            restore: false,
            level: 6,
            suffix: suffix.to_vec(),
            presume_tty: false,
            files: vec![],
        }
    }

    fn suffix(custom: &[u8], name: &[u8]) -> Option<String> {
        let mut err = Vec::new();
        let mut host = Host::Real;
        let g = Gz {
            s: gz(custom),
            host: &mut host,
            err: &mut err,
            exit: 0,
            stdout: None,
            stdin_named: false,
            list: Lister::default(),
            stale: None,
            time_stamp: 0,
            descend: None,
        };
        g.suffix_of(name).map(|s| String::from_utf8(s).unwrap())
    }

    /// Each expectation is what GNU 1.15's "already has X suffix" note
    /// named for that file and `-S`.
    #[test]
    fn suffixes_match_the_binary() {
        assert_eq!(suffix(b".gz", b"a.gz").as_deref(), Some(".gz"));
        assert_eq!(suffix(b".gz", b"A.GZ").as_deref(), Some(".GZ"));
        assert_eq!(suffix(b".gz", b"f_Z").as_deref(), Some("_Z"));
        assert_eq!(suffix(b".gz", b"f.TAZ").as_deref(), Some(".TAZ"));
        assert_eq!(suffix(b".gz", b"f_GZ"), None);
        assert_eq!(suffix(b".gz", b"f.bz2"), None);
        assert_eq!(suffix(b".gz", b".gz"), None);
        assert_eq!(suffix(b".gz", b"d/.gz"), None);
        assert_eq!(suffix(b".gz", b"d/y.gz").as_deref(), Some(".gz"));
        assert_eq!(suffix(b"z", b"a.gz").as_deref(), Some(".gz"));
        assert_eq!(suffix(b"Z", b"a.gz").as_deref(), Some("z"));
        assert_eq!(suffix(b"Z", b"a.GZ").as_deref(), Some("Z"));
        assert_eq!(suffix(b"z", b"a.GZ").as_deref(), Some(".GZ"));
        assert_eq!(suffix(b"Gz", b"a.gz").as_deref(), Some("gz"));
        assert_eq!(suffix(b"gz", b"a.gz").as_deref(), Some(".gz"));
        assert_eq!(suffix(b"q", b"k.Q").as_deref(), Some("Q"));
        assert_eq!(suffix(b".x", b"c.Gz").as_deref(), Some(".Gz"));
        assert_eq!(suffix(b".X", b"f.x").as_deref(), Some(".x"));
    }
}
