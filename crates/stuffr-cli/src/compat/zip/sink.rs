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
use crate::compat::host::{self, Host};

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
    /// stdio's error flag: the first write error (its `errno`), sticky.
    err: Option<(Option<i32>, io::ErrorKind)>,
}

impl FileSink {
    /// The file `f`, a sandbox's output `budget` charged as the buffer
    /// reaches it.
    pub(crate) fn new(f: File, budget: Option<Arc<AtomicU64>>) -> FileSink {
        FileSink {
            f: BufWriter::with_capacity(
                ZBSZ,
                Charged {
                    f,
                    budget,
                    #[cfg(test)]
                    limit: FILE_SIZE_LIMIT.with(|l| l.get()),
                },
            ),
            pos: 0,
            err: None,
        }
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
        if let Err(e) = self.f.write_all(buf) {
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
    fn ferror(&self) -> Option<io::Error> {
        self.err.map(|(code, kind)| match code {
            Some(c) => io::Error::from_raw_os_error(c),
            None => io::Error::from(kind),
        })
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
/// mode 0600. The name tried last is returned with the error.
pub(crate) fn mkstemp(host: &Host, dir: &[u8]) -> (Vec<u8>, io::Result<File>) {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
        ^ (u64::from(std::process::id()) << 32);
    let mut name = Vec::new();
    for _ in 0..100 {
        name = dir.to_vec();
        name.extend_from_slice(b"zi");
        for _ in 0..6 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            name.push(CHARS[(seed % CHARS.len() as u64) as usize]);
        }
        let mut opts = File::options();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(host.path(&name)) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            r => return (name, r),
        }
    }
    (name, Err(io::Error::from(io::ErrorKind::AlreadyExists)))
}

/// fileio.c:replace for a new archive: `rename` the temporary onto it, or
/// copy it when the rename crosses devices. `Err` is the ziperr code and
/// the system's answer.
// port: fileio.c:replace
pub(crate) fn replace(d: &Path, s: &Path) -> Result<(), (i32, io::Error)> {
    // an existing destination is Task 7's (links respected, unlinked first)
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

/// fileio.c:replace's copy: `s` into `d`, then `s` removed.
pub(crate) fn copy_over(d: &Path, s: &Path) -> Result<(), (i32, io::Error)> {
    let mut f = File::open(s).map_err(|e| (ZE_TEMP, e))?;
    let mut g = File::create(d).map_err(|e| (ZE_CREAT, e))?;
    if let Err(e) = io::copy(&mut f, &mut g).and_then(|_| g.flush()) {
        let _ = std::fs::remove_file(d);
        return Err((ZE_WRITE, e));
    }
    let _ = std::fs::remove_file(s);
    Ok(())
}
