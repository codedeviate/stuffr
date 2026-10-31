//! Where zip writes the archive: the temporary archive (`mkstemp`) or
//! standard output, as [`ZWrite`]s, and the end of the temporary: `replace`.
//!
//! The file sink is buffered as zip's stdio stream is (`setvbuf(y, ...,
//! ZBSZ)`): a write the system refuses fails when the buffer is flushed, as
//! `fwrite` fails in zip, and a sandbox's output budget is charged there too.

use std::fs::File;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use super::zipfile::ZWrite;
use crate::compat::host::{self, CleanupGuard, Host};

/// ziperr.h codes `replace` returns.
const ZE_TEMP: i32 = 10;
const ZE_WRITE: i32 = 14;
const ZE_CREAT: i32 = 15;
/// tailor.h:ZBSZ, the archive's stdio buffer.
const ZBSZ: usize = 16384;

/// A file the archive is written to: the temporary archive, or standard
/// output when it is a file. Buffered as zip's stdio stream is (`ZBSZ`), so
/// a failing write shows where zip's would.
pub(crate) struct FileSink {
    f: BufWriter<Charged>,
    pos: u64,
    /// The buffer's size when the stream is a plain `fopen` one (zipsplit's
    /// files): a write goes through as libc's `fwrite` makes it.
    stdio: Option<(usize, bool)>,
    /// stdio's error flag: the first write error (its `errno`), sticky.
    err: Option<(Option<i32>, io::ErrorKind)>,
}

impl FileSink {
    /// The file `f`, a sandbox's output `budget` charged as the buffer
    /// reaches it.
    pub(crate) fn new(f: File, budget: Option<Arc<AtomicU64>>) -> FileSink {
        FileSink::with_capacity(ZBSZ, f, budget)
    }

    /// [`FileSink::new`] with another buffer: zipsplit's files are stdio's
    /// default (`st_blksize`, 4096), not zip's `ZBSZ`.
    pub(crate) fn with_capacity(cap: usize, f: File, budget: Option<Arc<AtomicU64>>) -> FileSink {
        FileSink {
            f: BufWriter::with_capacity(
                cap,
                Charged {
                    f,
                    budget,
                    #[cfg(test)]
                    limit: FILE_SIZE_LIMIT.with(|l| l.get()),
                },
            ),
            pos: 0,
            stdio: None,
            err: None,
        }
    }

    /// zipsplit's streams: `FileSink::with_capacity` whose writes are libc's
    /// `fwrite` as well. What fills the buffer is flushed, whole blocks go
    /// out directly and the last part, shorter than a block, stays in the
    /// buffer until the stream is flushed or closed; where a write error
    /// shows (a limit on the file's size) depends on it. glibc retries a
    /// direct write until it has all gone (`bsd` false); Apple's
    /// `__sfvwrite` takes a short direct write as progress and works out
    /// what is left again, which may then be less than a block and stay
    /// buffered (`bsd`: measured under `ulimit -f` against `/usr/bin/zipsplit`).
    pub(crate) fn stdio(
        cap: usize,
        f: File,
        budget: Option<Arc<AtomicU64>>,
        bsd: bool,
    ) -> FileSink {
        let mut s = FileSink::with_capacity(cap, f, budget);
        s.stdio = Some((cap, bsd));
        s
    }

    fn fwrite(&mut self, mut buf: &[u8], cap: usize, bsd: bool) -> io::Result<()> {
        if !bsd {
            let space = cap - self.f.buffer().len();
            if buf.len() <= space {
                return self.f.write_all(buf);
            }
            self.f.write_all(&buf[..space])?;
            self.f.flush()?;
            let rest = &buf[space..];
            let direct = rest.len() - rest.len() % cap;
            self.f.write_all(&rest[..direct])?;
            return self.f.write_all(&rest[direct..]);
        }
        while !buf.is_empty() {
            let space = cap - self.f.buffer().len();
            if !self.f.buffer().is_empty() && buf.len() > space {
                // fill and flush
                self.f.write_all(&buf[..space])?;
                self.f.flush()?;
                buf = &buf[space..];
            } else if buf.len() >= cap {
                // write directly, a block at a time
                let n = self.f.get_mut().write(&buf[..cap])?;
                if n == 0 {
                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                }
                buf = &buf[n..];
            } else {
                return self.f.write_all(buf);
            }
        }
        Ok(())
    }

    /// Remember a failed write as stdio's error flag does.
    fn failed(&mut self, e: io::Error) -> io::Error {
        if self.err.is_none() {
            self.err = Some((e.raw_os_error(), e.kind()));
        }
        e
    }
}

/// The file under the buffer, charging a sandbox's budget for what reaches
/// it: as a file size limit, a write takes what is left of the budget,
/// and once it is spent a write fails as a full disk does.
pub(crate) struct Charged {
    f: File,
    budget: Option<Arc<AtomicU64>>,
    /// Test builds: `ulimit -f` for the archive (bytes), `EFBIG` past it.
    #[cfg(test)]
    limit: Option<u64>,
}

#[cfg(test)]
thread_local! {
    /// The tests' `ulimit -f` for the archives a run writes from this
    /// thread: the measured failures (fix report 1) reproduced in a sandbox.
    pub(crate) static FILE_SIZE_LIMIT: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

impl Write for Charged {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        let buf = match self.limit.as_mut() {
            Some(left) => {
                if *left == 0 && !buf.is_empty() {
                    #[cfg(unix)]
                    return Err(io::Error::from_raw_os_error(libc::EFBIG));
                    #[cfg(not(unix))]
                    return Err(io::Error::other("file too large"));
                }
                let n = (buf.len() as u64).min(*left) as usize;
                *left -= n as u64;
                &buf[..n]
            }
            None => buf,
        };
        let Some(b) = &self.budget else {
            return self.f.write(buf);
        };
        // as a file size limit: what fits is written, then nothing
        let left = b.load(std::sync::atomic::Ordering::Relaxed);
        let want = (buf.len() as u64).min(left);
        if want == 0 && !buf.is_empty() {
            host::take(b, 1)?;
        }
        host::take(b, want)?;
        let n = self.f.write(&buf[..want as usize]);
        if let Ok(n) = &n {
            // give back what a short write did not use
            b.fetch_add(want - *n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        n
    }
    fn flush(&mut self) -> io::Result<()> {
        self.f.flush()
    }
}

impl Write for FileSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let r = match self.stdio {
            Some((cap, bsd)) => self.fwrite(buf, cap, bsd),
            None => self.f.write_all(buf),
        };
        if let Err(e) = r {
            return Err(self.failed(e));
        }
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.f.flush().map_err(|e| self.failed(e))
    }
}

impl ZWrite for FileSink {
    fn seekable(&self) -> bool {
        true
    }
    fn offset(&self) -> u64 {
        self.pos
    }
    fn seek_to(&mut self, at: u64) -> io::Result<()> {
        self.flush()?;
        self.f.get_mut().f.seek(SeekFrom::Start(at)).map(|_| ())
    }
    fn write_here(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.f.write_all(bytes).map_err(|e| self.failed(e))
    }
    fn seek_end(&mut self) -> io::Result<()> {
        self.flush()?;
        let pos = self.pos;
        self.f.get_mut().f.seek(SeekFrom::Start(pos)).map(|_| ())
    }
    fn seek_here(&mut self) -> io::Result<()> {
        self.flush()?;
        let f = &mut self.f.get_mut().f;
        let here = f.stream_position()?;
        f.seek(SeekFrom::Start(here)).map(|_| ())
    }
    fn ferror(&self) -> Option<io::Error> {
        self.err.map(|(code, kind)| match code {
            Some(c) => io::Error::from_raw_os_error(c),
            None => io::Error::from(kind),
        })
    }
    fn seek_raw(&mut self, at: u64) -> io::Result<()> {
        self.flush()?;
        self.f.get_mut().f.seek(SeekFrom::Start(at)).map(|_| ())
    }
    fn tell_raw(&mut self) -> io::Result<u64> {
        self.flush()?;
        self.f.get_mut().f.stream_position()
    }
    fn set_offset(&mut self, at: u64) {
        self.pos = at;
    }
}

/// The archive while no split is open (between closing one and opening the
/// next): every call fails.
pub(crate) struct Closed;

impl Write for Closed {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(9))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ZWrite for Closed {
    fn seekable(&self) -> bool {
        false
    }
    fn offset(&self) -> u64 {
        0
    }
    fn seek_to(&mut self, _at: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(9))
    }
    fn write_here(&mut self, _bytes: &[u8]) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(9))
    }
    fn seek_end(&mut self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(9))
    }
    fn seek_here(&mut self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(9))
    }
    fn ferror(&self) -> Option<io::Error> {
        None
    }
}

/// A stream the archive is written to that cannot be rewound (a pipe, a
/// sandbox's standard output).
pub(crate) struct StreamSink {
    pub(crate) w: BufWriter<Box<dyn Write + Send>>,
    pub(crate) pos: u64,
    err: Option<(Option<i32>, io::ErrorKind)>,
}

impl StreamSink {
    pub(crate) fn new(w: BufWriter<Box<dyn Write + Send>>) -> StreamSink {
        StreamSink {
            w,
            pos: 0,
            err: None,
        }
    }
}

impl Write for StreamSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Err(e) = self.w.write_all(buf) {
            if self.err.is_none() {
                self.err = Some((e.raw_os_error(), e.kind()));
            }
            return Err(e);
        }
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl ZWrite for StreamSink {
    fn seekable(&self) -> bool {
        false
    }
    fn offset(&self) -> u64 {
        self.pos
    }
    fn seek_to(&mut self, _at: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(29))
    }
    fn write_here(&mut self, _bytes: &[u8]) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(29))
    }
    fn seek_end(&mut self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(29))
    }
    fn seek_here(&mut self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(29))
    }
    fn ferror(&self) -> Option<io::Error> {
        self.err.map(|(code, kind)| match code {
            Some(c) => io::Error::from_raw_os_error(c),
            None => io::Error::from(kind),
        })
    }
}

/// Standard output as the archive: a file when `lseek` works on it
/// (`is_seekable`), else a stream.
pub(crate) fn stdout_sink(host: &Host) -> Box<dyn ZWrite> {
    #[cfg(unix)]
    if matches!(host, Host::Real) {
        use std::os::fd::AsFd;
        if let Ok(fd) = io::stdout().as_fd().try_clone_to_owned() {
            let mut f = File::from(fd);
            if let Ok(p) = f.stream_position()
                && f.seek(SeekFrom::Start(p)).is_ok()
            {
                return Box::new(FileSink::new(f, None));
            }
        }
    }
    Box::new(StreamSink::new(host.out_writer(None)))
}

/// A temporary archive (`mkstemp("ziXXXXXX")` in the archive's directory or
/// `-b`'s), removed unless it was published.
pub(crate) struct Temp {
    pub(crate) path: Option<PathBuf>,
}

impl Drop for Temp {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// `mkstemp(template)`: `dir` + `zi` + six random characters, created new,
/// mode 0600, and armed for zip's interrupt handler (`ZIP_SIGNALS`: removed
/// if the run is interrupted before the guard drops). The name tried last
/// is returned with the error.
pub(crate) fn mkstemp(host: &Host, dir: &[u8]) -> (Vec<u8>, io::Result<(File, CleanupGuard)>) {
    mkstemp_with(matches!(host, Host::Real), &|b: &[u8]| host.path(b), dir)
}

/// [`mkstemp`] for a caller without a [`Host`]: `real` arms the handler,
/// `resolve` makes a name a path.
pub(crate) fn mkstemp_with(
    real: bool,
    resolve: &dyn Fn(&[u8]) -> PathBuf,
    dir: &[u8],
) -> (Vec<u8>, io::Result<(File, CleanupGuard)>) {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
        ^ (u64::from(std::process::id()) << 32);
    let mut name = Vec::new();
    for _ in 0..100 {
        name = dir.to_vec();
        name.extend_from_slice(super::messages::TEMP_TEMPLATE.as_bytes());
        for _ in 0..6 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            name.push(CHARS[(seed % CHARS.len() as u64) as usize]);
        }
        match host::create_new_armed_if(real, &resolve(&name), host::ZIP_SIGNALS) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            r => return (name, r),
        }
    }
    (name, Err(io::Error::from(io::ErrorKind::AlreadyExists)))
}

/// fileio.c:replace: `rename` the temporary onto the archive, or copy it
/// over it when the archive has other links or is a symbolic link
/// (respected: written through, for an archive updated in place,
/// `in_place`, whose link leads to a non-empty regular file), or when the
/// rename crosses devices. Any other symbolic link at `d` is refused
/// (deviation 31, [`refused_output_link`]). `Err` is the ziperr code and
/// the system's answer.
///
/// SIGINT and SIGTERM are held back meanwhile (ruling Z32, deviation 30):
/// between the archive's unlink and the rename, or while the copy rewrites
/// it, zip's handler would remove the armed temporary and leave no whole
/// archive at all. Held, the interrupt is answered once this returns, when
/// the temporary is the archive. After a failure the temporary is disarmed
/// inside the hold (ruling Z34), so it survives under its own name even
/// when the archive was already unlinked or truncated: the handler then
/// removes nothing (zip's would remove it).
// port: fileio.c:replace
pub(crate) fn replace(d: &Path, s: &Path, in_place: bool) -> Result<(), (i32, io::Error)> {
    host::with_zip_signals_held(|| {
        let r = replace_now(d, s, in_place);
        if r.is_err() {
            host::disarm_cleanup();
        }
        r
    })
}

/// In a test's forked child: raise SIGINT at the two points of [`replace`]
/// where the archive is not whole (after its unlink, after the copy's
/// truncation). Set only after `fork`, so no other test sees it.
#[cfg(all(test, unix))]
pub(crate) static RAISE_MID_REPLACE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, unix))]
fn mid_replace() {
    if RAISE_MID_REPLACE.load(std::sync::atomic::Ordering::SeqCst) {
        // SAFETY: raise is async-signal-safe and touches no Rust state.
        unsafe { libc::raise(libc::SIGINT) };
    }
}

/// Deviation 31 (hardening, ruling T5): a symbolic link at an output name
/// zip must not write through. Info-ZIP writes through any link there,
/// creating the file a dangling one names. stuffr refuses a link at an
/// output name that is not the archive being read (`-O`/`--out`, `-F`'s
/// output, split parts) whatever it points at; at the archive being
/// updated in place (`in_place`) it keeps Info-ZIP's update through the
/// link only when the link leads to a non-empty regular file, an archive
/// zip actually read, and refuses a dangling link or one to an empty file,
/// a directory or a device.
pub(crate) fn refused_output_link(p: &Path, in_place: bool) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
        && !(in_place && std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() > 0))
}

/// The error a [`refused_output_link`] is reported with: what an
/// `O_NOFOLLOW` open of it answers (`ELOOP`).
pub(crate) fn link_refusal() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        io::Error::other("the archive's name is a symbolic link to no file")
    }
}

fn replace_now(d: &Path, s: &Path, in_place: bool) -> Result<(), (i32, io::Error)> {
    if refused_output_link(d, in_place) {
        return Err((ZE_CREAT, link_refusal()));
    }
    if let Ok(t) = std::fs::symlink_metadata(d) {
        #[cfg(unix)]
        let copy = {
            use std::os::unix::fs::MetadataExt;
            t.nlink() > 1 || t.file_type().is_symlink()
        };
        #[cfg(not(unix))]
        let copy = t.file_type().is_symlink();
        if !copy {
            std::fs::remove_file(d).map_err(|e| (ZE_CREAT, e))?;
            #[cfg(all(test, unix))]
            mid_replace();
        } else {
            return copy_over(d, s);
        }
    }
    match std::fs::rename(s, d) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) => copy_over(d, s),
        Err(e) => Err((ZE_CREAT, e)),
    }
}

/// fileio.c:replace's copy: `s` into `d`, then `s` removed. Reached only
/// through [`replace`], under its held signals.
fn copy_over(d: &Path, s: &Path) -> Result<(), (i32, io::Error)> {
    let mut f = File::open(s).map_err(|e| (ZE_TEMP, e))?;
    let mut g = File::create(d).map_err(|e| (ZE_CREAT, e))?;
    #[cfg(all(test, unix))]
    mid_replace();
    if let Err(e) = io::copy(&mut f, &mut g).and_then(|_| g.flush()) {
        let _ = std::fs::remove_file(d);
        return Err((ZE_WRITE, e));
    }
    let _ = std::fs::remove_file(s);
    Ok(())
}
