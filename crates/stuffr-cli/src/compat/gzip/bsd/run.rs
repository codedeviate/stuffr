//! Compression, ported from Apple's `gzip.c` (file_cmds-479): `main`'s
//! operand loop, `handle_pathname`, `handle_dir`, `handle_file`,
//! `file_compress`, `check_outfile`, `gz_compress`, `handle_stdout`,
//! `copymodes`, `unlink_input`, `print_verbage` and `print_ratio`, with the
//! `__APPLE__` branches (the operand named twice when it cannot be
//! stat'ed; `fcopyfile` of ACLs and extended attributes and
//! `clear_type_and_creator`).
//!
//! Every warning is `maybe_warn`/`maybe_warnx`: printed unless `-q`, and
//! the exit code becomes 1; nothing stops the run. An existing output
//! declined at the terminal is the one refusal that leaves the code alone.
//!
//! The output file is created as gzip creates it, exclusively (a dangling
//! symbolic link in its place fails with `EEXIST`), but under a temporary
//! name in its directory, published by hard link only once complete
//! (`host::publish`), so an interrupted run leaves no partial `.gz`. The
//! deflate output is gathered in gzip's 64 KiB buffer (`BUFLEN`) and
//! written a buffer at a time, then the trailer on its own, so a failing
//! write fails where gzip's does.

use std::fs::{self, File, Metadata};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::args::Settings;
use super::messages::{self as m, printf};
use crate::compat::gzip::member::{Engine, Header, compress_body, write_header, write_trailer};
use crate::compat::host::{Host, Published, create_temp, publish, stdin_file, strerror};

/// `BUFLEN`: gzip's read and write size.
const BUFLEN: usize = 64 * 1024;

/// `PATH_MAX`, `outfile`'s size: the platform's own (1024 on macOS and
/// the BSDs, 4096 on Linux); 1024 where there is no `libc`.
#[cfg(unix)]
const PATH_MAX: usize = libc::PATH_MAX as usize;
#[cfg(not(unix))]
const PATH_MAX: usize = 1024;

/// The longest file name component (`NAME_MAX`).
const NAME_MAX: usize = 255;

/// `S_ISUID` and `S_ISGID` (POSIX's values, as `st_mode` bits).
#[cfg(unix)]
const S_ISUID: u32 = 0o4000;
#[cfg(unix)]
const S_ISGID: u32 = 0o2000;

/// `OS_CODE`: Unix.
const OS_CODE: u8 = 3;

/// The suffixes `check_suffix` tries after `suffixes[0]` (`.gz`, or
/// `-S`'s), in table order; then the last entry, `.gz`, or empty after
/// `-S ''`.
const SUFFIXES: [&[u8]; 13] = [
    b".gz", b".z", b"-gz", b"-z", b"_z", b".taz", b".tgz", b".bz2", b".tbz", b".tbz2", b".Z",
    b".xz", b".lz",
];

/// The engine Apple's zlib output comes from: C zlib on the C tier, the
/// compatible miniz elsewhere.
fn engine() -> Engine {
    #[cfg(feature = "zlib-c")]
    {
        Engine::ZlibC
    }
    #[cfg(not(feature = "zlib-c"))]
    {
        Engine::Miniz
    }
}

/// Run the compress operation `s` describes for the invoked `name`;
/// returns the exit code.
pub(super) fn execute(
    name: &'static str,
    mut s: Settings,
    host: &mut Host,
    err: &mut dyn Write,
) -> u8 {
    let files = std::mem::take(&mut s.files);
    let mut g = Gz {
        name,
        s,
        host,
        err,
        exit_value: 0,
        stdout: None,
        stdin_closed: false,
        answers: Vec::new(),
    };
    if files.is_empty() {
        g.handle_stdout();
    } else {
        for f in &files {
            g.handle_pathname(f);
        }
    }
    if let Some(mut out) = g.stdout.take() {
        let _ = out.flush();
    }
    g.exit_value
}

struct Gz<'a> {
    name: &'static str,
    s: Settings,
    host: &'a mut Host,
    err: &'a mut dyn Write,
    exit_value: u8,
    /// Standard output, opened on first use.
    stdout: Option<io::BufWriter<Box<dyn Write + Send>>>,
    /// A failed output creation `fclose`s standard input (`file_compress`):
    /// from then on it cannot be stat'ed, and is no terminal.
    stdin_closed: bool,
    /// What stdio has read from the terminal and `fgets` not yet taken.
    answers: Vec<u8>,
}

/// What `gz_compress` returns: the bytes read and the bytes written
/// (`*gsizep`), `None` where gzip has -1.
struct Sizes {
    read: Option<u64>,
    written: Option<u64>,
}

/// An input that remembers whether a read failed, and counts what it read.
struct Tracked<'r> {
    inner: &'r mut dyn Read,
    failed: Option<io::Error>,
    n: u64,
}

impl Read for Tracked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.inner.read(buf) {
                Ok(k) => {
                    self.n += k as u64;
                    return Ok(k);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    let again = io::Error::new(e.kind(), e.to_string());
                    self.failed = Some(e);
                    return Err(again);
                }
            }
        }
    }
}

/// gzip's output buffer: bytes gather until `BUFLEN`, then are written
/// whole (and flushed through the host's writer); `out_tot` counts what
/// was written. A failed write is remembered.
struct Chunks<'w> {
    inner: &'w mut dyn Write,
    buf: Vec<u8>,
    out_tot: u64,
    failed: Option<io::Error>,
}

impl Chunks<'_> {
    fn emit(&mut self, n: usize) -> io::Result<()> {
        let r = self
            .inner
            .write_all(&self.buf[..n])
            .and_then(|()| self.inner.flush());
        match r {
            Ok(()) => {
                self.out_tot += n as u64;
                self.buf.drain(..n);
                Ok(())
            }
            Err(e) => {
                let again = io::Error::new(e.kind(), e.to_string());
                self.failed = Some(e);
                Err(again)
            }
        }
    }

    /// The end of the deflate stream: whatever is buffered.
    fn finish(&mut self) -> io::Result<()> {
        let n = self.buf.len();
        if n == 0 {
            return Ok(());
        }
        self.emit(n)
    }
}

impl Write for Chunks<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while self.buf.len() >= BUFLEN {
            self.emit(BUFLEN)?;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Gz<'_> {
    // ---- maybe_warn and friends ----

    fn mark(&mut self) {
        if self.exit_value == 0 {
            self.exit_value = 1;
        }
    }

    /// `maybe_warnx`.
    fn warnx(&mut self, fmt: &str, args: &[&[u8]]) {
        if !self.s.quiet {
            printf(self.err, m::PREFIX, &[self.name.as_bytes()]);
            printf(self.err, fmt, args);
            printf(self.err, m::NEWLINE, &[]);
        }
        self.mark();
    }

    /// `maybe_warn`: [`Self::warnx`] with the error's text.
    fn warn(&mut self, fmt: &str, args: &[&[u8]], e: &io::Error) {
        if !self.s.quiet {
            printf(self.err, m::PREFIX, &[self.name.as_bytes()]);
            printf(self.err, fmt, args);
            printf(self.err, m::ERRNO_SUFFIX, &[&strerror(e)]);
        }
        self.mark();
    }

    // ---- operands ----

    /// `handle_pathname`, compressing.
    fn handle_pathname(&mut self, path: &[u8]) {
        if path == b"-" {
            self.handle_stdout();
            return;
        }
        let p = self.host.path(path);
        // `stat`, then (without -f or -c) `lstat`, whose answer wins.
        let follow = self.s.force || self.s.to_stdout;
        let sb = fs::metadata(&p).and_then(|md| {
            if follow {
                Ok(md)
            } else {
                fs::symlink_metadata(&p)
            }
        });
        let sb = match sb {
            Ok(sb) => sb,
            Err(e) => {
                self.warn(m::CANT_STAT, &[path, path], &e);
                return;
            }
        };
        if sb.is_dir() {
            if self.s.recursive {
                self.handle_dir(path);
            } else {
                self.warnx(m::IS_DIRECTORY, &[path]);
            }
            return;
        }
        if sb.is_file() {
            self.handle_file(path, &sb);
        } else {
            self.warnx(m::NOT_REGULAR, &[path]);
        }
    }

    /// `handle_dir`: `fts_open(FTS_PHYSICAL | FTS_NOCHDIR)` with no
    /// comparison function, so each directory in the order it lists its
    /// entries, read in full before any is visited, depth first. A child
    /// is `PATH/NAME` with the root as given. Only regular files are
    /// compressed; symbolic links (the root's too) and other files are
    /// skipped without a word.
    fn handle_dir(&mut self, dir: &[u8]) {
        match fs::symlink_metadata(self.host.path(dir)) {
            Ok(md) if md.is_dir() => self.walk(dir),
            Ok(_) => {}
            Err(e) => self.warn(m::PATH_ONLY, &[dir], &e),
        }
    }

    fn walk(&mut self, dir: &[u8]) {
        let rd = match fs::read_dir(self.host.path(dir)) {
            Ok(rd) => rd,
            Err(e) => {
                // FTS_DNR: `warn("%s", path)`.
                self.warn(m::PATH_ONLY, &[dir], &e);
                return;
            }
        };
        let mut entries: Vec<(Vec<u8>, io::Result<Metadata>)> = Vec::new();
        for e in rd {
            match e {
                Ok(e) => {
                    let md = fs::symlink_metadata(e.path());
                    entries.push((e.file_name().as_encoded_bytes().to_vec(), md));
                }
                Err(e) => {
                    self.warn(m::PATH_ONLY, &[dir], &e);
                    break;
                }
            }
        }
        for (entry, md) in entries {
            let mut child = dir.to_vec();
            child.push(b'/');
            child.extend_from_slice(&entry);
            match md {
                Err(e) => self.warn(m::PATH_ONLY, &[&child], &e),
                Ok(md) if md.is_dir() => self.walk(&child),
                Ok(md) if md.is_file() => self.handle_file(&child, &md),
                Ok(_) => {}
            }
        }
    }

    /// `handle_file`, compressing: then `-v`'s line, with the size `sb`
    /// gave and the bytes written.
    fn handle_file(&mut self, file: &[u8], sb: &Metadata) {
        let Some((outfile, gsize)) = self.file_compress(file) else {
            return;
        };
        if self.s.verbose {
            let nfile = (!self.s.to_stdout).then_some(outfile.as_slice());
            self.print_verbage(Some(file), nfile, sb.len(), gsize);
        }
    }

    /// `file_compress`: `Some((outfile, bytes written))`, or `None` where
    /// gzip returns -1.
    fn file_compress(&mut self, file: &[u8]) -> Option<(Vec<u8>, u64)> {
        let path = self.host.path(file);
        let mut input = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                self.warn(m::CANT_OPEN, &[file], &e);
                return None;
            }
        };
        let isb = match input.metadata() {
            Ok(md) => md,
            Err(e) => {
                self.warn(m::COULDNT_STAT, &[file], &e);
                return None;
            }
        };
        let mtime = mtime_of(&isb);
        let origname = basename(file).to_vec();
        if self.s.to_stdout {
            let mut out = self.take_stdout();
            let sizes = self.gz_compress(&mut input, &mut out, &origname, mtime);
            self.stdout = Some(out);
            return match sizes {
                Sizes {
                    read: Some(_),
                    written: Some(w),
                } => Some((Vec::new(), w)),
                _ => None,
            };
        }
        let links = nlink(&isb);
        if links > 1 && !self.s.force {
            let others = (links - 1).to_string();
            let plural: &[u8] = if links == 1 { b"" } else { b"s" };
            self.warnx(m::HAS_LINKS, &[file, others.as_bytes(), plural]);
            return None;
        }
        if !self.s.force
            && let Some(suff) = self.check_suffix(file)
            && !suff.is_empty()
        {
            self.warnx(m::HAS_SUFFIX, &[file, &suff]);
            return None;
        }
        let outfile = out_name(file, &self.s.suffix);
        let out_path = self.host.path(&outfile);
        let replace_input = self.check_outfile(&outfile, &out_path, &isb)?;
        let (tmp, tmp_file) = match create_exclusive(&out_path, replace_input) {
            Ok(t) => t,
            Err(e) => {
                self.warn(m::COULD_NOT_CREATE, &[&outfile], &e);
                self.stdin_closed = true;
                return None;
            }
        };
        let fd_copy = tmp_file.try_clone();
        let sizes = {
            let mut w = self.host.out_writer(Some(tmp_file));
            let sizes = self.gz_compress(&mut input, &mut w, &origname, mtime);
            let _ = w.flush();
            sizes
        };
        let Sizes { read, written } = sizes;
        let Some(size) = written else {
            // A write failed: what reached the file is not what was
            // counted (`(uintmax_t)-1`).
            let on_disk = fs::metadata(&tmp).map_or(0, |md| md.len()).to_string();
            let _ = fs::remove_file(&tmp);
            self.warnx(
                m::WRONG_SIZE,
                &[
                    &outfile,
                    on_disk.as_bytes(),
                    u64::MAX.to_string().as_bytes(),
                ],
            );
            self.warnx(m::LEAVING_ORIGINAL, &[file]);
            return None;
        };
        if read.is_none() {
            // Implementer ruling (see mod.rs): gzip keeps the cut-short
            // output and removes the input after a read error; stuffr says
            // the same and keeps the input instead.
            let _ = fs::remove_file(&tmp);
            return Some((outfile, size));
        }
        let fd = match fd_copy {
            Ok(fd) => fd,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                self.warn(m::COULD_NOT_CREATE, &[&outfile], &e);
                return None;
            }
        };
        // Published first, then gzip's sequence on the same descriptor: an
        // ACL copied from the input ("deny delete") or an immutable flag
        // would otherwise refuse the temporary name's removal.
        // Over the input itself (see `check_outfile`) by rename; anything
        // else must not be replaced.
        match publish(&tmp, &out_path, replace_input) {
            Ok(Published::Done) => {}
            Ok(Published::Exists) => {
                // Something took the name meanwhile: gzip's exclusive
                // create would have failed, and closed standard input.
                let e = io::Error::from_raw_os_error(eexist());
                self.warn(m::COULD_NOT_CREATE, &[&outfile], &e);
                self.stdin_closed = true;
                return None;
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                self.warn(m::COULD_NOT_CREATE, &[&outfile], &e);
                self.stdin_closed = true;
                return None;
            }
        }
        #[cfg(target_os = "macos")]
        apple_copy_attributes(&input, &fd);
        self.copymodes(&fd, &isb, &outfile);
        drop(input);
        self.unlink_input(&path, &isb, &out_path);
        Some((outfile, size))
    }

    /// `check_suffix(file, 0)`: the first suffix of the table `file` ends
    /// with (case-sensitive, whole operand, longer than the suffix).
    fn check_suffix(&self, file: &[u8]) -> Option<Vec<u8>> {
        let last: &[u8] = if self.s.empty_last_suffix {
            b""
        } else {
            b".gz"
        };
        let first: &[u8] = &self.s.suffix;
        std::iter::once(first)
            .chain(SUFFIXES)
            .chain(std::iter::once(last))
            .find(|suf| suf.len() < file.len() && file.ends_with(suf))
            .map(<[u8]>::to_vec)
    }

    /// `check_outfile`: `Some` when the output may be created, `None` when
    /// it may not (said). An existing one (followed through symbolic
    /// links) is unlinked under `-f` (whatever that does), asked about at
    /// a terminal, else refused.
    ///
    /// `Some(true)`: the existing output is the input itself (`isb`'s file:
    /// `a.txt` a symlink to `a.txt.gz`, or a name `out_name` cut back to
    /// itself). gzip unlinks it here and loses it if compressing then
    /// fails; stuffr leaves it until the new output replaces it (Ruling
    /// T8-4/T8-5, carried over).
    fn check_outfile(&mut self, outfile: &[u8], out_path: &Path, isb: &Metadata) -> Option<bool> {
        let Ok(osb) = fs::metadata(out_path) else {
            return Some(false);
        };
        let is_input = same_file(&osb, isb);
        let unlink = |p: &Path| {
            if !is_input {
                let _ = fs::remove_file(p);
            }
        };
        if self.s.force {
            unlink(out_path);
            return Some(is_input);
        }
        if !self.stdin_closed && self.host.stdin_is_tty() {
            printf(self.err, m::ASK_OVERWRITE, &[outfile]);
            let answer = self.fgets(9);
            if !matches!(answer.first(), Some(b'y' | b'Y')) {
                printf(self.err, m::NOT_OVERWRITING, &[]);
                return None;
            }
            unlink(out_path);
            return Some(is_input);
        }
        self.warnx(m::ALREADY_EXISTS, &[outfile]);
        None
    }

    /// `fgets(ans, size, stdin)`: at most `size - 1` bytes, through the
    /// newline, from what stdio has buffered, reading the terminal (a line
    /// per read) when that is empty. End of file gives nothing (gzip's
    /// default answer, `n`).
    fn fgets(&mut self, size: usize) -> Vec<u8> {
        let mut line = Vec::new();
        while line.len() < size - 1 {
            if self.answers.is_empty() && !self.read_terminal() {
                break;
            }
            let b = self.answers.remove(0);
            line.push(b);
            if b == b'\n' {
                break;
            }
        }
        line
    }

    /// One `read` of standard input into `answers`; false at end of file.
    fn read_terminal(&mut self) -> bool {
        let Ok(mut f) = stdin_file() else {
            return false;
        };
        let mut buf = [0u8; 4096];
        loop {
            match f.read(&mut buf) {
                Ok(0) => return false,
                Ok(n) => {
                    self.answers.extend_from_slice(&buf[..n]);
                    return true;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
    }

    /// `copymodes`: owner (a refused `fchown` drops the set-id bits), then
    /// the set-id and permission bits (never the sticky bit), the access
    /// and modification times, and the file flags if the input has any, on
    /// the output's descriptor.
    fn copymodes(&mut self, fd: &File, isb: &Metadata, outfile: &[u8]) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::MetadataExt;
            let raw = fd.as_raw_fd();
            let mut mode = isb.mode();
            // SAFETY: `raw` is an open descriptor `fd` owns; fchown only
            // reads its arguments.
            if unsafe { libc::fchown(raw, isb.uid(), isb.gid()) } < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EPERM) {
                    self.warn(m::COULDNT_FCHOWN, &[outfile], &e);
                }
                mode &= !(S_ISUID | S_ISGID);
            }
            mode &= 0o6777;
            // SAFETY: as above; the mode fits `mode_t` (12 bits).
            if unsafe { libc::fchmod(raw, mode as libc::mode_t) } < 0 {
                let e = io::Error::last_os_error();
                self.warn(m::COULDNT_FCHMOD, &[outfile], &e);
            }
            let times = [
                libc::timespec {
                    tv_sec: isb.atime() as libc::time_t,
                    tv_nsec: isb.atime_nsec() as _,
                },
                libc::timespec {
                    tv_sec: isb.mtime() as libc::time_t,
                    tv_nsec: isb.mtime_nsec() as _,
                },
            ];
            // SAFETY: `times` is two valid timespecs; `raw` is open.
            if unsafe { libc::futimens(raw, times.as_ptr()) } < 0 {
                let e = io::Error::last_os_error();
                self.warn(m::COULDNT_FUTIMENS, &[outfile], &e);
            }
        }
        #[cfg(not(unix))]
        let _ = (fd, isb, outfile);
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            use std::os::macos::fs::MetadataExt;
            let flags = isb.st_flags();
            // SAFETY: `fd` is open; fchflags only reads its arguments.
            if flags != 0 && unsafe { libc::fchflags(fd.as_raw_fd(), flags) } < 0 {
                let e = io::Error::last_os_error();
                self.warn(m::COULDNT_FCHFLAGS, &[outfile], &e);
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (fd, isb, outfile);
    }

    /// `unlink_input`: unless `-k`, remove the input if its name still
    /// names the file that was read (a symbolic link given with `-f` is
    /// removed, not its target). Never the output itself (Ruling T8-4's
    /// rule, carried over).
    fn unlink_input(&mut self, path: &Path, isb: &Metadata, out_path: &Path) {
        if self.s.keep || path == out_path {
            return;
        }
        let Ok(nsb) = fs::metadata(path) else {
            return;
        };
        if same_file(&nsb, isb) {
            let _ = fs::remove_file(path);
        }
    }

    // ---- standard input ----

    /// `handle_stdout`: standard input to standard output, unnamed, with
    /// its own time if it is a regular file and the current time if not.
    fn handle_stdout(&mut self) {
        if !self.s.force && self.host.stdout_is_tty() {
            self.warnx(m::STDOUT_IS_TERMINAL, &[]);
            return;
        }
        let sb = if self.stdin_closed {
            Err(io::Error::from_raw_os_error(ebadf()))
        } else {
            match self.host {
                Host::Real => stdin_file().and_then(|f| f.metadata()).map(Some),
                // A sandbox's standard input is a pipe.
                Host::Sandbox(_) => Ok(None),
            }
        };
        let mtime = match sb {
            Ok(Some(sb)) if sb.is_file() => mtime_of(&sb),
            Ok(_) => now_u32(),
            Err(e) => {
                self.warn(m::CANT_STAT_STDIN, &[], &e);
                return;
            }
        };
        let mut input = self.host.stdin();
        let mut out = self.take_stdout();
        let sizes = self.gz_compress(&mut input, &mut out, b"", mtime);
        self.stdout = Some(out);
        if self.s.verbose
            && let Sizes {
                read: Some(usize),
                written: Some(gsize),
            } = sizes
        {
            self.print_verbage(None, None, usize, gsize);
        }
    }

    fn take_stdout(&mut self) -> io::BufWriter<Box<dyn Write + Send>> {
        match self.stdout.take() {
            Some(w) => w,
            None => self.host.out_writer(None),
        }
    }

    // ---- the member ----

    /// `gz_compress`: one member of `input` to `out`. The header (FNAME
    /// `origname` unless empty, MTIME, XFL 4 at level 1 and 2 at level 9,
    /// OS 3; `-n` stores neither name nor time) shares gzip's first buffer
    /// with the deflate stream; the trailer is written on its own.
    fn gz_compress(
        &mut self,
        input: &mut dyn Read,
        out: &mut dyn Write,
        origname: &[u8],
        mtime: u32,
    ) -> Sizes {
        let (origname, mtime) = if self.s.no_name {
            (&b""[..], 0)
        } else {
            (origname, mtime)
        };
        let header = Header {
            text: false,
            mtime,
            xfl: match self.s.level {
                1 => 4,
                9 => 2,
                _ => 0,
            },
            os: OS_CODE,
            extra: None,
            name: (!origname.is_empty()).then(|| origname.to_vec()),
            comment: None,
            hcrc: false,
            len: 0,
        };
        let mut chunks = Chunks {
            inner: out,
            buf: Vec::with_capacity(BUFLEN),
            out_tot: 0,
            failed: None,
        };
        let mut rd = Tracked {
            inner: input,
            failed: None,
            n: 0,
        };
        let body = write_header(&header, &mut chunks)
            .and_then(|()| compress_body(self.s.level, engine(), &mut rd, &mut chunks))
            .and_then(|sums| chunks.finish().map(|()| sums));
        let (crc, total) = match body {
            Ok(sums) => sums,
            Err(e) => {
                return if let Some(e) = rd.failed.take() {
                    self.warn(m::READ, &[], &e);
                    Sizes {
                        read: None,
                        written: Some(chunks.out_tot),
                    }
                } else if let Some(e) = chunks.failed.take() {
                    self.warn(m::WRITE, &[], &e);
                    Sizes {
                        read: Some(rd.n),
                        written: None,
                    }
                } else {
                    let _ = e;
                    self.warnx(m::DEFLATE_FAILED, &[]);
                    Sizes {
                        read: None,
                        written: Some(chunks.out_tot),
                    }
                };
            }
        };
        let mut trailer = Vec::with_capacity(8);
        let _ = write_trailer(crc, total, &mut trailer);
        let written = chunks
            .inner
            .write_all(&trailer)
            .and_then(|()| chunks.inner.flush());
        match written {
            Ok(()) => Sizes {
                read: Some(total),
                written: Some(chunks.out_tot + 8),
            },
            Err(e) => {
                self.warn(m::WRITE, &[], &e);
                Sizes {
                    read: None,
                    written: Some(chunks.out_tot),
                }
            }
        }
    }

    // ---- -v ----

    /// `print_verbage`.
    fn print_verbage(&mut self, file: Option<&[u8]>, nfile: Option<&[u8]>, usize: u64, gsize: u64) {
        if let Some(f) = file {
            let tabs = if f.len() < 7 {
                m::TABS_SHORT
            } else {
                m::TAB_LONG
            };
            printf(self.err, m::VERBOSE_NAME, &[f, tabs.as_bytes()]);
        }
        let r = format!("{:>5}", print_ratio(usize, gsize));
        printf(self.err, m::RATIO, &[r.as_bytes()]);
        if let Some(n) = nfile {
            printf(self.err, m::REPLACED_WITH, &[n]);
        }
        printf(self.err, m::NEWLINE, &[]);
        let _ = self.err.flush();
    }
}

/// `print_ratio`'s number before `%5s%%`: the size reduction in tenths of
/// a percent, `"%2.2d."` with the point moved before the last digit. More
/// than doubled is `-99.9`; the values are halved until `in` fits 20 bits,
/// then divided in 32-bit unsigned arithmetic, as gzip does.
fn print_ratio(input: u64, output: u64) -> String {
    let (mut inp, out) = (input as i64, output as i64);
    let mut diff = inp - out / 2;
    let percent10: i32 = if inp == 0 && out == 0 {
        0
    } else if diff < 0 {
        -999
    } else {
        while inp > 0x10_0000 {
            diff >>= 1;
            inp >>= 1;
        }
        if inp != 0 {
            ((diff as u32).wrapping_mul(2000) / (inp as u32)).wrapping_sub(1000) as i32
        } else {
            0
        }
    };
    let digits = format!("{:02}", percent10.unsigned_abs());
    let mut b = if percent10 < 0 {
        format!("-{digits}.")
    } else {
        format!("{digits}.")
    }
    .into_bytes();
    let len = b.len();
    b[len - 1] = b[len - 2];
    b[len - 2] = b'.';
    String::from_utf8(b).unwrap_or_default()
}

/// `basename(3)` of a regular file's operand: after the last `/`.
fn basename(file: &[u8]) -> &[u8] {
    file.rsplit(|&b| b == b'/').next().unwrap_or(file)
}

/// `outfile`: the operand and the suffix, cut to `PATH_MAX - 1` bytes by
/// overwriting its tail with the suffix when longer (`file_compress`).
fn out_name(file: &[u8], suffix: &[u8]) -> Vec<u8> {
    if file.len() + suffix.len() < PATH_MAX {
        return [file, suffix].concat();
    }
    let keep = PATH_MAX - 1 - suffix.len();
    [&file[..keep.min(file.len())], suffix].concat()
}

/// `open(outfile, O_WRONLY | O_CREAT | O_EXCL, 0600)`, as a temporary file
/// beside it: the errors that open would give (an existing name, a
/// dangling link included, is `EEXIST`; a name component too long is
/// `ENAMETOOLONG`; a missing or unwritable directory), and the temporary.
/// With `replace_input` the name is the input's own, which gzip has
/// unlinked by now and stuffr has kept, so its existence is no error.
fn create_exclusive(out_path: &Path, replace_input: bool) -> io::Result<(PathBuf, File)> {
    let too_long = out_path
        .file_name()
        .is_some_and(|n| n.as_encoded_bytes().len() > NAME_MAX);
    if too_long {
        return Err(io::Error::from_raw_os_error(enametoolong()));
    }
    let parent = match out_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    // The directory must be there and searchable before the name can
    // exist (`ENOENT`/`ENOTDIR` come first).
    fs::metadata(&parent)?;
    if !replace_input && fs::symlink_metadata(out_path).is_ok() {
        return Err(io::Error::from_raw_os_error(eexist()));
    }
    create_temp(&parent, "gzip")
}

/// The header's MTIME: `(uint32_t)st_mtime`, wrapped, not checked.
fn mtime_of(md: &Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.mtime() as u32
    }
    #[cfg(not(unix))]
    {
        md.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as u32)
    }
}

/// `(uint32_t)time(NULL)`.
fn now_u32() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32)
}

fn nlink(md: &Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.nlink()
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        1
    }
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        true
    }
}

fn ebadf() -> i32 {
    #[cfg(unix)]
    {
        libc::EBADF
    }
    #[cfg(not(unix))]
    {
        9
    }
}

fn eexist() -> i32 {
    #[cfg(unix)]
    {
        libc::EEXIST
    }
    #[cfg(not(unix))]
    {
        17
    }
}

fn enametoolong() -> i32 {
    #[cfg(unix)]
    {
        libc::ENAMETOOLONG
    }
    #[cfg(not(unix))]
    {
        38
    }
}

/// `fcopyfile(in, out, 0, COPYFILE_ACL | COPYFILE_XATTR)` then
/// `clear_type_and_creator(out)`: the input's ACL and extended attributes,
/// then the Finder type and creator cleared if the output has Finder info.
/// Failures are ignored, as gzip ignores them.
#[cfg(target_os = "macos")]
fn apple_copy_attributes(input: &File, out: &File) {
    use std::os::fd::AsRawFd;
    let (i, o) = (input.as_raw_fd(), out.as_raw_fd());
    // SAFETY: both descriptors are open; a null state is allowed.
    unsafe {
        libc::fcopyfile(
            i,
            o,
            std::ptr::null_mut(),
            libc::COPYFILE_ACL | libc::COPYFILE_XATTR,
        );
    }
    #[repr(C)]
    struct FinderBuf {
        length: u32,
        info: [u8; 32],
    }
    let mut alist = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_FNDRINFO,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut abuf = FinderBuf {
        length: 0,
        info: [0; 32],
    };
    let size = std::mem::size_of::<FinderBuf>();
    // SAFETY: `alist` and `abuf` are valid for the sizes passed; the
    // kernel writes at most `size` bytes into `abuf`.
    let got =
        unsafe { libc::fgetattrlist(o, (&raw mut alist).cast(), (&raw mut abuf).cast(), size, 0) };
    if got == 0 && abuf.length as usize == size {
        abuf.info[..8].fill(0);
        // SAFETY: as above; `info` is 32 bytes.
        unsafe {
            libc::fsetattrlist(
                o,
                (&raw mut alist).cast(),
                abuf.info.as_mut_ptr().cast(),
                abuf.info.len(),
                0,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each expectation is `print_ratio`'s, worked through gzip's integer
    /// arithmetic (and seen from `/usr/bin/gzip -v` where marked).
    #[test]
    fn print_ratio_matches_gzip() {
        assert_eq!(print_ratio(0, 0), "0.0");
        assert_eq!(print_ratio(0, 20), "-99.9"); // `gzip -v` of an empty file
        assert_eq!(print_ratio(6, 26), "-99.9"); // observed: `hello\n`
        assert_eq!(print_ratio(0, 1), "0.0");
        assert_eq!(print_ratio(100, 100), "0.0");
        assert_eq!(print_ratio(100, 50), "50.0");
        // `out / 2` is integer division: 999 halves to 499.
        assert_eq!(print_ratio(1000, 999), "0.2");
        assert_eq!(print_ratio(1000, 1001), "0.0");
        assert_eq!(print_ratio(1000, 1010), "-1.0");
        assert_eq!(print_ratio(100, 199), "-98.0");
        assert_eq!(print_ratio(100, 200), "-100.0");
        assert_eq!(print_ratio(100, 0), "100.0");
        assert_eq!(format!("{:>5}", print_ratio(1000, 999)), "  0.2");
        // Past the 20-bit reduction.
        assert_eq!(print_ratio(3 << 20, 3060), "99.9");
    }

    #[test]
    fn out_name_is_cut_to_path_max() {
        assert_eq!(out_name(b"a", b".gz"), b"a.gz");
        let long = vec![b'x'; PATH_MAX - 2];
        let o = out_name(&long, b".gz");
        assert_eq!(o.len(), PATH_MAX - 1);
        assert!(o.ends_with(b"x.gz"));
        assert_eq!(out_name(&long[..PATH_MAX - 4], b".gz").len(), PATH_MAX - 1);
        // A name ending in the suffix can be cut back to itself.
        let mut own = vec![b'y'; PATH_MAX - 4];
        own.extend_from_slice(b".gz");
        assert_eq!(out_name(&own, b".gz"), own);
    }
}
