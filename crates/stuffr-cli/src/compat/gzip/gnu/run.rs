//! The file loop and the compress path, in the order GNU gzip 1.15 was
//! observed to check things for each operand: open (without following a
//! final symlink unless `-f` or `-c`), then directory, regular file and
//! link count, then the suffix, then the output's existence; compress;
//! copy the input's mode, owner and times; remove the input.
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
use super::messages::{self as m, PROGRAM, printf, quote, ratio};
use crate::compat::copy_metadata_from;
use crate::compat::gzip::member::{Engine, Header, compress_member};
use crate::compat::host::{Host, Published, create_temp, publish, stdin_file, strerror};

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
    if s.mode != Mode::Compress {
        printf(err, m::NOT_YET, &[PROGRAM]);
        return 1;
    }
    let files = std::mem::take(&mut s.files);
    let mut g = Gz {
        s,
        host,
        err,
        exit: 0,
        stdout: None,
        stdin_named: false,
    };
    let _ = if files.is_empty() {
        g.treat_stdin()
    } else {
        files.iter().try_for_each(|f| g.treat(f))
    };
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

    /// One operand: the checks, then compression.
    fn treat(&mut self, name: &[u8]) -> Step {
        if name == b"-" {
            return self.treat_stdin();
        }
        let qname = quote(name);
        let path = self.host.path(name);
        let follow = self.s.force || self.s.to_stdout;
        let opened = open_input(&path, follow).and_then(|f| f.metadata().map(|md| (f, md)));
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
        if !self.s.to_stdout {
            if !meta.is_file() {
                self.warn(m::NOT_REGULAR, &[PROGRAM, &qname]);
                return Ok(());
            }
            let others = other_links(&meta);
            if others > 0 && !self.s.force {
                let s: &[u8] = if others > 1 { b"s" } else { b"" };
                let n = others.to_string();
                self.warn(m::HAS_LINKS, &[PROGRAM, &qname, n.as_bytes(), s]);
                return Ok(());
            }
        }
        if self.s.to_stdout {
            return self.compress_to_stdout(name, file, &meta);
        }
        self.compress_to_file(name, path, file, &meta);
        Ok(())
    }

    /// `-r` on a directory: every entry, in the order the directory lists
    /// them (read in full first, so outputs created meanwhile are not
    /// visited).
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
        for e in entries {
            let mut child = name.to_vec();
            if !child.ends_with(b"/") {
                child.push(b'/');
            }
            child.extend_from_slice(&e);
            self.treat(&child)?;
        }
        Ok(())
    }

    /// `-c`: one member onto standard output.
    fn compress_to_stdout(&mut self, name: &[u8], mut file: File, meta: &Metadata) -> Step {
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
        self.verbose_done(&p, m::STDOUT_NAME);
        Ok(())
    }

    /// Compress `name` to `name` + suffix.
    fn compress_to_file(&mut self, name: &[u8], path: PathBuf, mut file: File, meta: &Metadata) {
        let qname = quote(name);
        if !self.s.force
            && let Some(suf) = self.suffix_of(name)
        {
            if !self.s.quiet {
                self.say(m::HAS_SUFFIX, &[PROGRAM, &qname, &suf]);
            }
            return;
        }
        let out_name = [name, &self.s.suffix].concat();
        let qout = quote(&out_name);
        let out_path = self.host.path(&out_name);
        let mut replace = false;
        if fs::symlink_metadata(&out_path).is_ok() {
            if self.s.force {
                replace = true;
            } else {
                self.say(m::ALREADY_EXISTS, &[PROGRAM, &qout]);
                if self.host.stdin_is_tty() {
                    self.say(m::ASK_OVERWRITE, &[]);
                    replace = ask_yes();
                }
                if !replace {
                    self.say(m::NOT_OVERWRITTEN, &[]);
                    if self.exit == 0 {
                        self.exit = 2;
                    }
                    return;
                }
            }
        }
        let dir = match out_path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let (tmp, tmp_file) = match create_temp(&dir, "gzip") {
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
        // The mode, owner and times of the input, as GNU copies them; a
        // failure to copy them does not undo the output.
        let _ = copy_metadata_from(meta, &tmp);
        match publish(&tmp, &out_path, replace) {
            Ok(Published::Done) => {}
            Ok(Published::Exists) => {
                self.say(m::ALREADY_EXISTS, &[PROGRAM, &qout]);
                self.say(m::NOT_OVERWRITTEN, &[]);
                if self.exit == 0 {
                    self.exit = 2;
                }
                return;
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                self.error(m::IO_FAILED, &[PROGRAM, &qout, &strerror(&e)]);
                return;
            }
        }
        if !self.s.keep
            && let Err(e) = fs::remove_file(&path)
        {
            self.error(m::IO_FAILED, &[PROGRAM, &qname, &strerror(&e)]);
            return;
        }
        self.verbose_done(&p, &qout);
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

    fn verbose_done(&mut self, p: &Packed, out: &[u8]) {
        if self.s.verbose > 0 {
            let r = ratio(p.bytes_in, p.body);
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
/// that has no writer (non-blocking for the open only).
fn open_input(path: &Path, follow: bool) -> io::Result<File> {
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
