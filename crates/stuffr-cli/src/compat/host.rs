//! The process plumbing shared by the compatibility families: names as
//! bytes, C library behaviours the ported tools rely on (`strerror`, sticky
//! end of file), the input reader that reads the way libbzip2 does, the
//! sandbox the fuzz targets run under, and the helpers that create and
//! publish an output file (`create_temp`, `publish`) and restore `SIGPIPE`
//! (`reset_sigpipe`).
//!
//! Nothing here knows a tool's messages or flags; each family keeps its own
//! checks and wording and calls these helpers.

use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, BufRead, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// `BZ_MAX_UNUSED`: libbzip2's read size, and bzip2's output chunk.
pub(crate) const CHUNK: usize = 5000;

/// The most a sandboxed run may write, to standard output and files
/// together. Past it a write fails with `ENOSPC`, the code a full disk gives.
/// A bzip2 stream of a few dozen bytes can expand to tens of MiB, so without
/// a cap a fuzzer's short input could fill memory or disk; 8 MiB is past any
/// block's ordinary output (a 900k block of text) and bounds what a bomb can
/// cost.
pub(crate) const SANDBOX_OUTPUT_CAP: u64 = 8 * 1024 * 1024;

/// Restore `SIGPIPE`'s default action. The tools die of it writing to a
/// closed pipe; Rust ignores the signal by default, so a compat entry point
/// restores it, on that path only.
pub(crate) fn reset_sigpipe() {
    #[cfg(unix)]
    // SAFETY: setting a signal's disposition to SIG_DFL installs no handler
    // and touches no Rust state; it is done before any other thread or I/O.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

/// Create a temporary output file in `dir`, `create_new`, mode 0600, named
/// `.stuffr-{family}-{pid}-{n}.tmp`; a name already taken moves on to the
/// next `n`.
pub(crate) fn create_temp(dir: &Path, family: &str) -> io::Result<(PathBuf, File)> {
    let mut opts = File::options();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    for n in 0u32.. {
        let tmp = dir.join(format!(".stuffr-{family}-{}-{n}.tmp", std::process::id()));
        match opts.open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && n < 1000 => {}
            Err(e) => return Err(e),
        }
    }
    unreachable!("the loop returns")
}

/// What [`publish`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Published {
    /// The temporary file is now `out`.
    Done,
    /// `out` appeared meanwhile; it was left alone and the temporary file
    /// was removed.
    Exists,
}

/// Publish the finished temporary file `tmp` as `out`.
///
/// Without `force`, publishing must not replace anything: an `O_EXCL` open
/// of `out` would refuse a file that appeared after the existence check, and
/// a rename would silently replace it. So the temporary is hard-linked to
/// `out`, which fails with `EEXIST` exactly where that open would, and then
/// unlinked. Where the filesystem has no hard links, rename is the fallback.
/// With `force`, any existing output was already removed on purpose, and
/// rename keeps that intent.
pub(crate) fn publish(tmp: &Path, out: &Path, force: bool) -> io::Result<Published> {
    if force {
        fs::rename(tmp, out)?;
        return Ok(Published::Done);
    }
    match fs::hard_link(tmp, out) {
        Ok(()) => fs::remove_file(tmp)?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(tmp);
            return Ok(Published::Exists);
        }
        Err(_) => fs::rename(tmp, out)?,
    }
    Ok(Published::Done)
}

/// Bytes to a path. On unix this is exact.
pub(crate) fn path(b: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(OsString::from_vec(b.to_vec()))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(b).into_owned())
    }
}

/// C's `strerror(errno)` for an error: the OS text without Rust's
/// ` (os error N)` suffix.
pub(crate) fn strerror(e: &io::Error) -> Vec<u8> {
    match e.raw_os_error() {
        Some(n) => errno_text(n),
        None => e.to_string().into_bytes(),
    }
}

pub(crate) fn errno_text(n: i32) -> Vec<u8> {
    let s = io::Error::from_raw_os_error(n).to_string();
    let suffix = format!(" (os error {n})");
    s.strip_suffix(&suffix).unwrap_or(&s).as_bytes().to_vec()
}

/// `notAStandardFile`: anything but a regular file, judged without following
/// a final symlink; "if in doubt, return True".
pub(crate) fn not_a_standard_file(p: &Path) -> bool {
    fs::symlink_metadata(p).map_or(true, |m| !m.file_type().is_file())
}

/// `countHardLinks`.
pub(crate) fn count_hard_links(p: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(p).map_or(0, |m| m.nlink().saturating_sub(1))
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        0
    }
}

/// What kind of file an input is: what `perror` says about a cut-short
/// stream depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Regular,
    Device,
    Pipe,
}

pub(crate) fn kind_of(f: &File) -> Kind {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        match f.metadata().map(|m| m.file_type()) {
            Ok(t) if t.is_fifo() || t.is_socket() => Kind::Pipe,
            Ok(t) if t.is_char_device() || t.is_block_device() => Kind::Device,
            _ => Kind::Regular,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = f;
        Kind::Regular
    }
}

/// Standard input as a `File`, so it can be rewound (bzip2's `-f` copy of a
/// non-bzip2 input) and read without Rust's own stdin buffer.
pub(crate) fn stdin_file() -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(File::from(io::stdin().as_fd().try_clone_to_owned()?))
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Standard output, unbuffered by Rust (the caller buffers).
pub(crate) fn stdout_writer() -> Box<dyn Write + Send> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        if let Ok(fd) = io::stdout().as_fd().try_clone_to_owned() {
            return Box::new(File::from(fd));
        }
    }
    Box::new(io::stdout())
}

/// The input of a decompression or test, read the way libbzip2 reads it:
/// `CHUNK` bytes at a time, each read filling its buffer unless the input
/// ends, the next one only once the last is used up. That matters for a
/// pipe, where bzip2's `-f` copy of a non-bzip2 input can only copy what
/// libbzip2 has not yet taken. End of file is sticky, as in C stdio, so a
/// terminal's ^D ends the input once and for all.
pub(crate) struct Input {
    src: InputSrc,
    buf: Box<[u8; CHUNK]>,
    pos: usize,
    len: usize,
    eof: bool,
    pub(crate) kind: Kind,
}

pub(crate) enum InputSrc {
    File(File),
    Stdin(io::Stdin),
    /// A sandboxed run's standard input: read like a pipe, never rewound.
    Bytes(io::Cursor<Vec<u8>>),
}

impl Read for InputSrc {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            InputSrc::File(f) => f.read(buf),
            InputSrc::Stdin(s) => s.read(buf),
            InputSrc::Bytes(c) => c.read(buf),
        }
    }
}

impl Input {
    pub(crate) fn file(f: File) -> Self {
        let kind = kind_of(&f);
        Self::new(InputSrc::File(f), kind)
    }

    pub(crate) fn stdin() -> Self {
        match stdin_file() {
            Ok(f) => Self::file(f),
            Err(_) => Self::new(InputSrc::Stdin(io::stdin()), Kind::Pipe),
        }
    }

    /// Bytes standing in for standard input, as a pipe would deliver them.
    pub(crate) fn bytes(data: Vec<u8>) -> Self {
        Self::new(InputSrc::Bytes(io::Cursor::new(data)), Kind::Pipe)
    }

    fn new(src: InputSrc, kind: Kind) -> Self {
        Self {
            src,
            buf: Box::new([0; CHUNK]),
            pos: 0,
            len: 0,
            eof: false,
            kind,
        }
    }

    /// One read from the source, honouring sticky end of file.
    fn read_src(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.eof {
            return Ok(0);
        }
        loop {
            match self.src.read(buf) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(0);
                }
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Copy the input to `out` as bzip2's `trycat` does: from the start when
    /// it can be rewound, otherwise whatever libbzip2 has not yet read.
    pub(crate) fn copy_raw(&mut self, out: &mut dyn Write) -> io::Result<()> {
        // `rewind`, whose failure (on a pipe) bzip2 ignores. Either way the
        // buffered bytes are gone: about to be re-read, or already consumed.
        if let InputSrc::File(f) = &mut self.src
            && f.seek(SeekFrom::Start(0)).is_ok()
        {
            self.eof = false;
        }
        self.pos = 0;
        self.len = 0;
        let mut buf = [0u8; CHUNK];
        loop {
            let n = self.read_src(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            out.write_all(&buf[..n])?;
        }
    }
}

impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let avail = self.fill_buf()?;
        let n = avail.len().min(out.len());
        out[..n].copy_from_slice(&avail[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Input {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos == self.len {
            let mut n = 0;
            let mut chunk = [0u8; CHUNK];
            while n < CHUNK {
                match self.read_src(&mut chunk[n..])? {
                    0 => break,
                    k => n += k,
                }
            }
            self.buf[..n].copy_from_slice(&chunk[..n]);
            self.pos = 0;
            self.len = n;
        }
        Ok(&self.buf[self.pos..self.len])
    }

    fn consume(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.len);
    }
}

/// Counts what passes through to the destination: `nbytes_out`.
pub(crate) struct Counting<W> {
    pub(crate) inner: W,
    pub(crate) n: Arc<AtomicU64>,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let k = self.inner.write(buf)?;
        self.n.fetch_add(k as u64, Ordering::Relaxed);
        Ok(k)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// What the family takes from its process: the directory operands resolve
/// against, standard input and output, and whether those are terminals.
/// Standard error is passed separately, as it always was.
pub(crate) enum Host {
    /// The process itself.
    Real,
    /// `run_in`'s: nothing of the process is touched.
    Sandbox(Sandbox),
}

/// A sandboxed run's stand-ins for the process state.
pub(crate) struct Sandbox {
    /// Operands resolve against this directory, never the process's cwd.
    pub(crate) dir: PathBuf,
    /// Standard input, taken by the first read of it (a run reads it once).
    pub(crate) stdin: Option<Vec<u8>>,
    /// Standard output, captured.
    pub(crate) stdout: Arc<Mutex<Vec<u8>>>,
    /// Bytes still allowed to reach standard output and output files, all
    /// together; past it a write fails as a full disk does.
    pub(crate) budget: Arc<AtomicU64>,
}

impl Host {
    /// An operand, or a name derived from one, as a path to open.
    pub(crate) fn path(&self, b: &[u8]) -> PathBuf {
        match self {
            Host::Real => path(b),
            Host::Sandbox(s) => s.dir.join(path(b)),
        }
    }

    /// `isatty(fileno(stdin))`; a sandbox has no terminal.
    pub(crate) fn stdin_is_tty(&self) -> bool {
        matches!(self, Host::Real) && crate::compat::stdin_is_tty()
    }

    /// `isatty(fileno(stdout))`; a sandbox has no terminal.
    pub(crate) fn stdout_is_tty(&self) -> bool {
        matches!(self, Host::Real) && crate::compat::stdout_is_tty()
    }

    /// Standard input as a decompression or compression input.
    pub(crate) fn stdin(&mut self) -> Input {
        match self {
            Host::Real => Input::stdin(),
            Host::Sandbox(s) => Input::bytes(s.stdin.take().unwrap_or_default()),
        }
    }

    /// Count `n` bytes a test decoded, which go nowhere. Always `Ok` for
    /// the real process; in a sandbox they are charged to the same budget
    /// as output, because a few dozen bytes of bzip2 can decode to tens of
    /// MiB and `-t` would otherwise be the one unbounded path.
    pub(crate) fn charge(&self, n: u64) -> io::Result<()> {
        match self {
            Host::Real => Ok(()),
            Host::Sandbox(s) => take(&s.budget, n),
        }
    }

    /// The output of a run: standard output, or the temporary file.
    pub(crate) fn out_writer(&self, f: Option<File>) -> BufWriter<Box<dyn Write + Send>> {
        let w: Box<dyn Write + Send> = match (self, f) {
            (Host::Real, Some(f)) => Box::new(f),
            (Host::Real, None) => stdout_writer(),
            (Host::Sandbox(s), f) => {
                let inner: Box<dyn Write + Send> = match f {
                    Some(f) => Box::new(f),
                    None => Box::new(Captured(s.stdout.clone())),
                };
                Box::new(Capped {
                    inner,
                    budget: s.budget.clone(),
                })
            }
        };
        BufWriter::with_capacity(64 * 1024, w)
    }
}

/// A sandboxed run's standard output.
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut v = self.0.lock().unwrap_or_else(|p| p.into_inner());
        v.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A writer that fails with `ENOSPC` once its shared budget is spent: what
/// bzip2 meets on a full disk, which it reports as an I/O error, exit 1.
struct Capped {
    inner: Box<dyn Write + Send>,
    budget: Arc<AtomicU64>,
}

impl Write for Capped {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Reserve the whole write first, so the budget can never wrap; a
        // write the budget cannot hold fails whole, as a full disk would.
        let want = buf.len() as u64;
        take(&self.budget, want)?;
        let n = match self.inner.write(buf) {
            Ok(n) => n,
            Err(e) => {
                self.budget.fetch_add(want, Ordering::Relaxed);
                return Err(e);
            }
        };
        // Give back what a short write did not use.
        self.budget.fetch_add(want - n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Take `n` from `budget`, or fail with `ENOSPC` when less than `n` is
/// left. Never wraps. A `compare_exchange` loop rather than `fetch_update`:
/// clippy on stable 1.99 denies `fetch_update` as deprecated (renamed
/// `try_update`), and `try_update` is newer than the 1.88 MSRV.
fn take(budget: &AtomicU64, n: u64) -> io::Result<()> {
    let mut left = budget.load(Ordering::Relaxed);
    loop {
        let rest = left.checked_sub(n).ok_or_else(no_space)?;
        match budget.compare_exchange_weak(left, rest, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(()),
            Err(now) => left = now,
        }
    }
}

fn no_space() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::ENOSPC)
    }
    #[cfg(not(unix))]
    {
        io::Error::from(io::ErrorKind::StorageFull)
    }
}

/// Write `fmt` with `%s`/`%d` replaced by `args` in order and `%%` by `%`,
/// as C's `fprintf` does for these formats. Write errors are ignored, as
/// the reference tools ignore `fprintf`'s result.
pub(crate) fn printf(w: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
    let mut out = Vec::with_capacity(fmt.len() + 64);
    let mut args = args.iter();
    let mut bytes = fmt.as_bytes().iter().copied();
    while let Some(b) = bytes.next() {
        if b != b'%' {
            out.push(b);
            continue;
        }
        match bytes.next() {
            Some(b'%') => out.push(b'%'),
            Some(b's' | b'd') => out.extend_from_slice(args.next().copied().unwrap_or_default()),
            // Only `%s`, `%d` and `%%` occur in the strings above.
            Some(other) => out.extend_from_slice(&[b'%', other]),
            None => out.push(b'%'),
        }
    }
    let _ = w.write_all(&out);
}

/// Set only the access and modification times (`utime`).
pub(crate) fn set_times(meta: &Metadata, to: &Path) -> io::Result<()> {
    let mut times = fs::FileTimes::new();
    if let Ok(t) = meta.accessed() {
        times = times.set_accessed(t);
    }
    if let Ok(t) = meta.modified() {
        times = times.set_modified(t);
    }
    File::options().write(true).open(to)?.set_times(times)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A write the budget cannot hold fails whole and leaves the budget
    /// as it was; nothing wraps.
    #[test]
    fn the_capped_writer_never_wraps_its_budget() {
        let budget = Arc::new(AtomicU64::new(10));
        let mut w = Capped {
            inner: Box::new(io::sink()),
            budget: budget.clone(),
        };
        assert_eq!(w.write(b"1234567").unwrap(), 7);
        assert_eq!(budget.load(Ordering::Relaxed), 3);
        let e = w.write(b"1234567").unwrap_err();
        assert_eq!(e.kind(), no_space().kind());
        assert_eq!(budget.load(Ordering::Relaxed), 3);
        assert_eq!(w.write(b"123").unwrap(), 3);
        assert_eq!(budget.load(Ordering::Relaxed), 0);
        assert!(w.write(b"x").is_err());
        assert_eq!(w.write(b"").unwrap(), 0);
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stuffr-host-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An output that appears between the existence check and publishing is
    /// reported, never clobbered, and the temporary is removed.
    #[test]
    fn publish_never_replaces_an_output_that_appeared_meanwhile() {
        let dir = scratch("exists");
        let (tmp, out) = (dir.join(".tmp"), dir.join("a.out"));
        fs::write(&tmp, b"new").unwrap();
        fs::write(&out, b"appeared").unwrap();
        assert_eq!(publish(&tmp, &out, false).unwrap(), Published::Exists);
        assert!(!tmp.exists(), "the temporary is left");
        assert_eq!(fs::read(&out).unwrap(), b"appeared");
        fs::write(&tmp, b"new").unwrap();
        fs::remove_file(&out).unwrap();
        assert_eq!(publish(&tmp, &out, false).unwrap(), Published::Done);
        assert!(!tmp.exists());
        assert_eq!(fs::read(&out).unwrap(), b"new");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_with_force_replaces() {
        let dir = scratch("force");
        let (tmp, out) = (dir.join(".tmp"), dir.join("a.out"));
        fs::write(&tmp, b"new").unwrap();
        fs::write(&out, b"old").unwrap();
        assert_eq!(publish(&tmp, &out, true).unwrap(), Published::Done);
        assert!(!tmp.exists());
        assert_eq!(fs::read(&out).unwrap(), b"new");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn create_temp_names_the_family_and_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("temp");
        let (a, _fa) = create_temp(&dir, "gzip").unwrap();
        let (b, _fb) = create_temp(&dir, "gzip").unwrap();
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_str().unwrap().to_owned();
        assert!(
            name.starts_with(&format!(".stuffr-gzip-{}-", std::process::id()))
                && name.ends_with(".tmp"),
            "{name}"
        );
        assert_eq!(
            fs::metadata(&a).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
