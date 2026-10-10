//! Files and streams for the bzip2 family: names as bytes, C library
//! behaviours bzip2 relies on (`strerror`, `remove`, sticky end of file),
//! and the input reader that reads the way libbzip2 does.

use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, BufRead, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::run::CHUNK;

/// Bytes to a path. On unix this is exact.
pub(super) fn path(b: &[u8]) -> PathBuf {
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
pub(super) fn strerror(e: &io::Error) -> Vec<u8> {
    match e.raw_os_error() {
        Some(n) => errno_text(n),
        None => e.to_string().into_bytes(),
    }
}

pub(super) fn errno_text(n: i32) -> Vec<u8> {
    let s = io::Error::from_raw_os_error(n).to_string();
    let suffix = format!(" (os error {n})");
    s.strip_suffix(&suffix).unwrap_or(&s).as_bytes().to_vec()
}

/// C's `remove`: a file, or failing that an empty directory. The result is
/// ignored where bzip2 ignores it.
pub(super) fn c_remove(p: &Path) {
    if fs::remove_file(p).is_err() {
        let _ = fs::remove_dir(p);
    }
}

/// `notAStandardFile`: anything but a regular file, judged without following
/// a final symlink; "if in doubt, return True".
pub(super) fn not_a_standard_file(p: &Path) -> bool {
    fs::symlink_metadata(p).map_or(true, |m| !m.file_type().is_file())
}

/// `countHardLinks`.
pub(super) fn count_hard_links(p: &Path) -> u64 {
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
pub(super) enum Kind {
    Regular,
    Device,
    Pipe,
}

pub(super) fn kind_of(f: &File) -> Kind {
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
pub(super) fn stdin_file() -> io::Result<File> {
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
pub(super) fn stdout_writer() -> Box<dyn Write + Send> {
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
pub(super) struct Input {
    src: InputSrc,
    buf: Box<[u8; CHUNK]>,
    pos: usize,
    len: usize,
    eof: bool,
    pub(super) kind: Kind,
}

pub(super) enum InputSrc {
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
    pub(super) fn file(f: File) -> Self {
        let kind = kind_of(&f);
        Self::new(InputSrc::File(f), kind)
    }

    pub(super) fn stdin() -> Self {
        match stdin_file() {
            Ok(f) => Self::file(f),
            Err(_) => Self::new(InputSrc::Stdin(io::stdin()), Kind::Pipe),
        }
    }

    /// Bytes standing in for standard input, as a pipe would deliver them.
    pub(super) fn bytes(data: Vec<u8>) -> Self {
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
    pub(super) fn copy_raw(&mut self, out: &mut dyn Write) -> io::Result<()> {
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
pub(super) struct Counting<W> {
    pub(super) inner: W,
    pub(super) n: Arc<AtomicU64>,
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
pub(super) enum Host {
    /// The process itself.
    Real,
    /// `run_in`'s: nothing of the process is touched.
    Sandbox(Sandbox),
}

/// A sandboxed run's stand-ins for the process state.
pub(super) struct Sandbox {
    /// Operands resolve against this directory, never the process's cwd.
    pub(super) dir: PathBuf,
    /// Standard input, taken by the first read of it (a run reads it once).
    pub(super) stdin: Option<Vec<u8>>,
    /// Standard output, captured.
    pub(super) stdout: Arc<Mutex<Vec<u8>>>,
    /// Bytes still allowed to reach standard output and output files, all
    /// together; past it a write fails as a full disk does.
    pub(super) budget: Arc<AtomicU64>,
}

impl Host {
    /// An operand, or a name derived from one, as a path to open.
    pub(super) fn path(&self, b: &[u8]) -> PathBuf {
        match self {
            Host::Real => path(b),
            Host::Sandbox(s) => s.dir.join(path(b)),
        }
    }

    /// `isatty(fileno(stdin))`; a sandbox has no terminal.
    pub(super) fn stdin_is_tty(&self) -> bool {
        matches!(self, Host::Real) && crate::compat::stdin_is_tty()
    }

    /// `isatty(fileno(stdout))`; a sandbox has no terminal.
    pub(super) fn stdout_is_tty(&self) -> bool {
        matches!(self, Host::Real) && crate::compat::stdout_is_tty()
    }

    /// Standard input as a decompression or compression input.
    pub(super) fn stdin(&mut self) -> Input {
        match self {
            Host::Real => Input::stdin(),
            Host::Sandbox(s) => Input::bytes(s.stdin.take().unwrap_or_default()),
        }
    }

    /// The output of a run: standard output, or the temporary file.
    pub(super) fn out_writer(&self, f: Option<File>) -> BufWriter<Box<dyn Write + Send>> {
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
        let left = self.budget.load(Ordering::Relaxed);
        if left == 0 && !buf.is_empty() {
            return Err(no_space());
        }
        let take = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let n = self.inner.write(&buf[..take])?;
        self.budget.fetch_sub(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
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

/// Set only the access and modification times (`utime`).
pub(super) fn set_times(meta: &Metadata, to: &Path) -> io::Result<()> {
    let mut times = fs::FileTimes::new();
    if let Ok(t) = meta.accessed() {
        times = times.set_accessed(t);
    }
    if let Ok(t) = meta.modified() {
        times = times.set_modified(t);
    }
    File::options().write(true).open(to)?.set_times(times)
}
