//! `file_io.c`: opening the input with its refusals, the output, reading,
//! sparse writing, copying the input's attributes, and removing the input
//! after success, from XZ Utils 5.8.4 (0BSD, `LICENSE-xz`).
//!
//! **The output is a temporary file** (`.stuffr-xz-<pid>-<n>.tmp`, beside
//! it) published under its name once complete, never written in place: an
//! interrupt removes the temporary (armed in `host.rs` for the real
//! process), and without `-f` the publish refuses a name that appeared
//! meanwhile. Before the temporary is made, the output's name is created
//! and removed again with `O_EXCL`, so a name that exists, a missing or
//! unwritable directory and a name too long are refused with the errors
//! xz's own `open(O_EXCL)` gives, at the point xz gives them.
//!
//! **An input that is also the output is never lost** (spec deviation 4):
//! with `-f`, an output that is the input's own file (`same_file`, by
//! device and inode) is not removed first, as xz removes it, but replaced
//! by the publish's rename, so a failure or an interrupt leaves the input.
//!
//! **Sparse output** (decompressing to a regular file, unless
//! `--no-sparse`): a chunk of `IO_BUFFER_SIZE` zero bytes is skipped with a
//! seek, and a trailing hole is closed by writing its last byte, as
//! io_write and io_close do; the bytes and size are the same as written
//! out. Not done for standard output in `>>` (`O_APPEND`) mode, where xz
//! lifts the flag for the run (the bytes are the same), nor in a sandbox.
//!
//! **Not reproduced:** `O_NONBLOCK` on standard input and output (xz sets
//! and restores it; here reads simply block, and `--flush-timeout` polls
//! before each read instead of after `EAGAIN`, which waits the same way);
//! `posix_fadvise`. A sandboxed run never syncs.

use std::fs::{self, File, Metadata};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::args::{Args, OpMode};
use super::message::{Messages, mask_nonprint};
use super::messages as m;
use super::suffix;
use crate::compat::host::{
    self, CleanupGuard, Host, InFile, Published, arm_cleanup, create_temp, publish, strerror,
};

/// `IO_BUFFER_SIZE`: the read and write size, and the sparse unit.
pub(crate) const IO_BUFFER_SIZE: usize = 8192;

/// The input's bytes.
enum Src {
    File(InFile),
    Other(Box<dyn Read>),
}

impl Read for Src {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Src::File(f) => f.read(buf),
            Src::Other(r) => r.read(buf),
        }
    }
}

/// Where the output goes.
enum Out {
    /// The real process: a file (standard output's descriptor, or the
    /// temporary), written unbuffered as `write(2)` writes.
    Raw(File),
    /// A sandbox: its capped standard output or file, flushed after each
    /// write so a full budget fails where a full disk would.
    Capped(BufWriter<Box<dyn Write + Send>>),
}

/// The output file being written.
struct DestFile {
    /// The temporary, and a handle on it for attributes and syncing.
    tmp: PathBuf,
    handle: File,
    /// `dest_st`, taken when it was created.
    meta: Option<Metadata>,
    /// Its name as given (`dest_name`) and as a path.
    path: PathBuf,
    /// It is the input's own file, replaced by the publish (deviation 4).
    replace: bool,
    /// `--synchronous`'s directory, opened before the output.
    dir: Option<File>,
    _guard: CleanupGuard,
}

/// file_io.c's `file_pair`.
pub(crate) struct FilePair {
    /// `src_name` as given (`(stdin)` for standard input); masked when
    /// printed.
    pub(crate) src_name: Vec<u8>,
    /// `None` for standard input.
    src_path: Option<PathBuf>,
    src: Src,
    /// `src_st` (`None` for standard input, which xz never `fstat`s).
    src_meta: Option<Metadata>,
    pub(crate) src_eof: bool,
    pub(crate) src_has_seen_input: bool,
    pub(crate) flush_needed: bool,
    /// `--flush-timeout` when compressing (`mytime_get_flush_timeout`'s
    /// `opt_flush_timeout`), else 0; `next_flush` once input is seen.
    flush_timeout: u64,
    next_flush: Instant,
    /// The real process (not a sandbox).
    real: bool,
    out: Option<Out>,
    dest_name: Vec<u8>,
    dest: Option<DestFile>,
    dest_try_sparse: bool,
    dest_pending_sparse: u64,
}

/// `strerror(EEXIST)`, which an exclusive create gives an existing name.
fn eexist() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::EEXIST)
    }
    #[cfg(not(unix))]
    {
        io::Error::from(io::ErrorKind::AlreadyExists)
    }
}

/// POSIX `dirname` of a name that does not end in `/`.
fn dirname(name: &[u8]) -> Vec<u8> {
    match name.iter().rposition(|&b| b == b'/') {
        None => b".".to_vec(),
        Some(i) => {
            let head = &name[..i];
            let trimmed = head
                .iter()
                .rposition(|&b| b != b'/')
                .map_or(&b""[..], |j| &head[..=j]);
            if trimmed.is_empty() {
                b"/".to_vec()
            } else {
                trimmed.to_vec()
            }
        }
    }
}

/// The directory a path's file is in.
fn parent_of(p: &Path) -> PathBuf {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

#[cfg(unix)]
fn errno(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// Whether a failed open of `path` was `O_NOFOLLOW` meeting a symbolic
/// link (io_open_src_real: FreeBSD's `EMLINK`, NetBSD's `EFTYPE`, else
/// `ELOOP` with an `lstat` that says so).
#[cfg(unix)]
fn was_symlink(e: &io::Error, path: &Path, follow: bool) -> bool {
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    {
        let _ = (path, follow);
        errno(e) == libc::EMLINK
    }
    #[cfg(target_os = "netbsd")]
    {
        let _ = (path, follow);
        errno(e) == libc::EFTYPE
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd")))]
    {
        errno(e) == libc::ELOOP
            && !follow
            && fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
    }
}

impl FilePair {
    /// file_io.c: io_open_src: standard input (`name` `None`) or the file
    /// `name`, with xz's refusals said. `None` when it is not to be coded.
    pub(crate) fn open_src(
        a: &Args,
        name: Option<&[u8]>,
        host: &mut Host,
        msg: &mut Messages,
        err: &mut dyn Write,
    ) -> Option<FilePair> {
        let real = matches!(host, Host::Real);
        let mut pair = FilePair {
            src_name: name.unwrap_or(m::STDIN_NAME).to_vec(),
            src_path: None,
            src: Src::Other(Box::new(io::empty())),
            src_meta: None,
            src_eof: false,
            src_has_seen_input: false,
            flush_needed: false,
            flush_timeout: if a.op == OpMode::Compress {
                a.coder.flush_timeout
            } else {
                0
            },
            next_flush: Instant::now(),
            real,
            out: None,
            dest_name: Vec::new(),
            dest: None,
            dest_try_sparse: false,
            dest_pending_sparse: 0,
        };
        let Some(name) = name else {
            pair.src = match host {
                Host::Real => match host::stdin_file() {
                    Ok(f) => Src::File(InFile::from(f)),
                    Err(_) => Src::Other(Box::new(io::stdin())),
                },
                Host::Sandbox(_) => Src::Other(Box::new(host.stdin())),
            };
            return Some(pair);
        };
        if name.is_empty() {
            msg.error(err, m::EMPTY_FILENAME, &[]);
            return None;
        }
        let shown = mask_nonprint(name);
        let path = host.path(name);
        // Symlinks are followed only when writing to standard output or
        // with --force or --keep; only regular files are taken when the
        // output goes to disk.
        let follow = a.to_stdout || a.force || a.keep;
        let reg_files_only = !a.to_stdout;
        let mut opts = File::options();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NONBLOCK so a FIFO's open does not wait for a writer.
            let mut flags = libc::O_NOCTTY | libc::O_NONBLOCK;
            if !follow {
                flags |= libc::O_NOFOLLOW;
            }
            opts.custom_flags(flags);
        }
        #[cfg(not(unix))]
        if !follow && fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            msg.warning(err, m::IS_SYMLINK, &[&shown]);
            return None;
        }
        let file = match opts.open(&path) {
            Ok(f) => f,
            Err(e) => {
                #[cfg(unix)]
                if was_symlink(&e, &path, follow) {
                    msg.warning(err, m::IS_SYMLINK, &[&shown]);
                    return None;
                }
                msg.error(err, m::NAME_COLON, &[&shown, &strerror(&e)]);
                return None;
            }
        };
        #[cfg(unix)]
        clear_nonblock(&file);
        let meta = match file.metadata() {
            Ok(md) => md,
            Err(e) => {
                msg.error(err, m::NAME_COLON, &[&shown, &strerror(&e)]);
                return None;
            }
        };
        if meta.is_dir() {
            msg.warning(err, m::IS_DIRECTORY, &[&shown]);
            return None;
        }
        if reg_files_only && !meta.is_file() {
            msg.warning(err, m::NOT_REGULAR, &[&shown]);
            return None;
        }
        #[cfg(unix)]
        if reg_files_only && !a.force && !a.keep {
            use std::os::unix::fs::MetadataExt;
            // S_ISUID | S_ISGID and S_ISVTX (mode_t's width differs by
            // platform; the bits do not).
            let mode = meta.mode();
            if mode & 0o6000 != 0 {
                msg.warning(err, m::SETID, &[&shown]);
                return None;
            }
            if mode & 0o1000 != 0 {
                msg.warning(err, m::STICKY, &[&shown]);
                return None;
            }
            if meta.nlink() > 1 {
                msg.warning(err, m::HARD_LINKS, &[&shown]);
                return None;
            }
        }
        pair.src = Src::File(host.track(&path, file));
        pair.src_path = Some(path);
        pair.src_meta = Some(meta);
        Some(pair)
    }

    /// The milliseconds `io_read` may wait for input before a flush is
    /// due (`mytime_get_flush_timeout`), `None` to wait for ever.
    fn flush_wait(&self) -> Option<i32> {
        if self.flush_timeout == 0 || !self.src_has_seen_input || !self.real {
            return None;
        }
        let left = self.next_flush.saturating_duration_since(Instant::now());
        Some(i32::try_from(left.as_millis()).unwrap_or(i32::MAX))
    }

    /// file_io.c: io_read: fill `buf` unless the input ends (`src_eof`) or
    /// a flush is due (`flush_needed`). `None` after a read error (said).
    pub(crate) fn read(
        &mut self,
        buf: &mut [u8],
        msg: &mut Messages,
        err: &mut dyn Write,
    ) -> Option<usize> {
        let mut pos = 0;
        while pos < buf.len() {
            #[cfg(unix)]
            if let Some(timeout) = self.flush_wait()
                && let Src::File(f) = &self.src
            {
                use std::os::fd::AsRawFd;
                let mut pfd = libc::pollfd {
                    fd: f.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one valid pollfd for the call.
                let ret = unsafe { libc::poll(&mut pfd, 1, timeout) };
                if ret == 0 {
                    self.flush_needed = true;
                    return Some(pos);
                }
                if ret == -1 {
                    let e = io::Error::last_os_error();
                    if matches!(errno(&e), libc::EINTR | libc::EAGAIN) {
                        continue;
                    }
                    let name = mask_nonprint(&self.src_name);
                    msg.error(err, m::POLL_FAILED, &[&name, &strerror(&e)]);
                    return None;
                }
            }
            match self.src.read(&mut buf[pos..]) {
                Ok(0) => {
                    self.src_eof = true;
                    break;
                }
                Ok(n) => {
                    pos += n;
                    if !self.src_has_seen_input {
                        self.src_has_seen_input = true;
                        self.next_flush =
                            Instant::now() + Duration::from_millis(self.flush_timeout);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    let name = mask_nonprint(&self.src_name);
                    msg.error(err, m::READ_ERROR, &[&name, &strerror(&e)]);
                    return None;
                }
            }
        }
        Some(pos)
    }

    /// file_io.c: io_fix_src_pos: hand back the `n` bytes read past the end
    /// of the data, where the input can seek.
    pub(crate) fn fix_src_pos(&mut self, n: u64) {
        if n > 0
            && let Src::File(f) = &mut self.src
            && let Ok(back) = i64::try_from(n)
        {
            let _ = f.seek(SeekFrom::Current(-back));
        }
    }

    /// file_io.c: io_open_dest: standard output, or the output named from
    /// the input's name (removed first under `-f`). False once a refusal
    /// is said.
    pub(crate) fn open_dest(
        &mut self,
        a: &Args,
        host: &mut Host,
        msg: &mut Messages,
        err: &mut dyn Write,
    ) -> bool {
        let sparse = a.sparse && a.op == OpMode::Decompress;
        if a.to_stdout || self.src_path.is_none() {
            self.dest_name = m::STDOUT_NAME.to_vec();
            match host {
                Host::Real => match stdout_file() {
                    Ok(f) => {
                        self.dest_try_sparse = sparse && stdout_can_be_sparse(&f);
                        self.out = Some(Out::Raw(f));
                    }
                    Err(_) => self.out = Some(Out::Capped(host.out_writer(None))),
                },
                Host::Sandbox(_) => self.out = Some(Out::Capped(host.out_writer(None))),
            }
            return true;
        }
        let Some(dest) = suffix::dest_name(
            &self.src_name,
            a.op,
            a.format,
            a.suffix.as_deref(),
            msg,
            err,
        ) else {
            return false;
        };
        let shown = mask_nonprint(&dest);
        let path = host.path(&dest);
        // --synchronous's directory comes first: nothing to clean up yet.
        let mut dir = None;
        if a.coder.synchronous && self.real {
            let name = dirname(&dest);
            match open_dir(&host.path(&name)) {
                Ok(d) => dir = Some(d),
                Err(e) => {
                    msg.error(
                        err,
                        m::OPEN_DIR_FAILED,
                        &[&mask_nonprint(&name), &strerror(&e)],
                    );
                    return false;
                }
            }
        }
        // Deviation 4: the input's own file is replaced, never removed.
        let replace = a.force
            && fs::metadata(&path).is_ok_and(|o| {
                self.src_meta
                    .as_ref()
                    .is_some_and(|s| host::same_file(&o, s) == Some(true))
            });
        if a.force
            && !replace
            && let Err(e) = fs::remove_file(&path)
            && e.kind() != io::ErrorKind::NotFound
        {
            msg.error(err, m::CANNOT_REMOVE, &[&shown, &strerror(&e)]);
            return false;
        }
        if !replace && let Err(e) = probe_exclusive(&path) {
            msg.error(err, m::NAME_COLON, &[&shown, &strerror(&e)]);
            return false;
        }
        let (tmp, file) = match create_temp(&parent_of(&path), "xz") {
            Ok(t) => t,
            Err(e) => {
                msg.error(err, m::NAME_COLON, &[&shown, &strerror(&e)]);
                return false;
            }
        };
        let guard = arm_cleanup(host, &tmp);
        let handle = match file.try_clone() {
            Ok(h) => h,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                msg.error(err, m::NAME_COLON, &[&shown, &strerror(&e)]);
                return false;
            }
        };
        self.out = Some(match host {
            Host::Real => {
                self.dest_try_sparse = sparse;
                Out::Raw(file)
            }
            Host::Sandbox(_) => Out::Capped(host.out_writer(Some(file))),
        });
        self.dest_name = dest;
        self.dest = Some(DestFile {
            meta: handle.metadata().ok(),
            tmp,
            handle,
            path,
            replace,
            dir,
            _guard: guard,
        });
        true
    }

    /// The message for a failed write: none for `EPIPE` (file_io.c:
    /// io_write_buf). Under `-t`, where nothing is opened, a sandbox's
    /// budget running out is said as standard output's.
    pub(crate) fn write_failed(&self, e: &io::Error, msg: &mut Messages, err: &mut dyn Write) {
        if e.kind() != io::ErrorKind::BrokenPipe {
            let dest: &[u8] = if self.dest_name.is_empty() {
                m::STDOUT_NAME
            } else {
                &self.dest_name
            };
            let name = mask_nonprint(dest);
            msg.error(err, m::WRITE_ERROR, &[&name, &strerror(e)]);
        }
    }

    /// file_io.c: io_write_buf.
    fn write_buf(&mut self, buf: &[u8], msg: &mut Messages, err: &mut dyn Write) -> bool {
        let r = match &mut self.out {
            Some(Out::Raw(f)) => f.write_all(buf),
            Some(Out::Capped(w)) => w.write_all(buf).and_then(|()| w.flush()),
            None => Ok(()),
        };
        match r {
            Ok(()) => true,
            Err(e) => {
                self.write_failed(&e, msg, err);
                false
            }
        }
    }

    /// file_io.c: io_write: a chunk of `IO_BUFFER_SIZE` zero bytes is a
    /// hole when the output may be sparse. False once a failure is said.
    pub(crate) fn write(&mut self, buf: &[u8], msg: &mut Messages, err: &mut dyn Write) -> bool {
        if self.dest_try_sparse {
            if buf.len() == IO_BUFFER_SIZE {
                // Treat a hole as data once it would not fit an off_t with
                // room to spare.
                if buf.iter().all(|&b| b == 0) && self.dest_pending_sparse < 1 << 62 {
                    self.dest_pending_sparse += buf.len() as u64;
                    return true;
                }
            } else if buf.is_empty() {
                return true;
            }
            if self.dest_pending_sparse > 0 {
                if let Err(e) = self.seek_out(self.dest_pending_sparse) {
                    let name = mask_nonprint(&self.dest_name);
                    msg.error(err, m::SPARSE_SEEK_FAILED, &[&name, &strerror(&e)]);
                    return false;
                }
                self.dest_pending_sparse = 0;
            }
        }
        self.write_buf(buf, msg, err)
    }

    /// Skip `n` bytes of the output.
    fn seek_out(&mut self, n: u64) -> io::Result<()> {
        let n = i64::try_from(n).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        match &mut self.out {
            Some(Out::Raw(f)) => f.seek(SeekFrom::Current(n)).map(|_| ()),
            _ => Err(io::Error::from(io::ErrorKind::Unsupported)),
        }
    }

    /// file_io.c: io_close: a trailing hole closed, the attributes copied
    /// and the output synced, then published (or removed when not
    /// `success`), then the input removed after a success unless kept.
    pub(crate) fn close(
        mut self,
        a: &Args,
        mut success: bool,
        msg: &mut Messages,
        err: &mut dyn Write,
    ) {
        if success && self.dest_try_sparse && self.dest_pending_sparse > 0 {
            match self.seek_out(self.dest_pending_sparse - 1) {
                Err(e) => {
                    let name = mask_nonprint(&self.dest_name);
                    msg.error(err, m::SPARSE_SEEK_FAILED, &[&name, &strerror(&e)]);
                    success = false;
                }
                Ok(()) => {
                    if !self.write_buf(&[0], msg, err) {
                        success = false;
                    }
                }
            }
        }
        let out = self.out.take();
        if let Some(dest) = self.dest.take() {
            let shown = mask_nonprint(&self.dest_name);
            if success {
                if let Some(src) = &self.src_meta {
                    copy_attrs(&dest, src, &shown, msg, err);
                }
                if a.coder.synchronous
                    && self.real
                    && let Err(e) = dest.handle.sync_all()
                {
                    msg.error(err, m::SYNC_FILE_FAILED, &[&shown, &strerror(&e)]);
                    success = false;
                }
            }
            drop(dest.handle);
            if let Err(e) = close_out(out) {
                msg.error(err, m::CLOSE_FAILED, &[&shown, &strerror(&e)]);
                success = false;
            }
            if success {
                success = self.publish(
                    &dest.tmp,
                    &dest.path,
                    a.force || dest.replace,
                    &shown,
                    msg,
                    err,
                );
                if success
                    && let Some(dir) = &dest.dir
                    && let Err(e) = dir.sync_all()
                {
                    msg.error(err, m::SYNC_DIR_FAILED, &[&shown, &strerror(&e)]);
                    success = false;
                }
            } else {
                let _ = fs::remove_file(&dest.tmp);
            }
        } else if let Some(Out::Capped(mut w)) = out {
            let _ = w.flush();
        }
        // The input, closed, and removed after a success unless kept.
        let src = std::mem::replace(&mut self.src, Src::Other(Box::new(io::empty())));
        drop(src);
        if success
            && !a.keep
            && let (Some(path), Some(meta)) = (&self.src_path, &self.src_meta)
        {
            unlink(&self.src_name, path, meta, a.force, msg, err);
        }
    }

    /// The finished temporary published as the output; false (said) when
    /// that fails, the temporary then removed.
    fn publish(
        &self,
        tmp: &Path,
        path: &Path,
        replace: bool,
        shown: &[u8],
        msg: &mut Messages,
        err: &mut dyn Write,
    ) -> bool {
        match publish(tmp, path, replace) {
            Ok(Published::Done) => true,
            Ok(Published::Exists) => {
                msg.error(err, m::NAME_COLON, &[shown, &strerror(&eexist())]);
                false
            }
            Err(e) => {
                let _ = fs::remove_file(tmp);
                msg.error(err, m::NAME_COLON, &[shown, &strerror(&e)]);
                false
            }
        }
    }
}

/// Close the output, reporting what `close(2)` (or a sandbox's flush)
/// says.
fn close_out(out: Option<Out>) -> io::Result<()> {
    match out {
        Some(Out::Raw(f)) => {
            #[cfg(unix)]
            {
                use std::os::fd::IntoRawFd;
                let fd = f.into_raw_fd();
                // SAFETY: `fd` was just released by its owner and is
                // closed once, here.
                if unsafe { libc::close(fd) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }
            #[cfg(not(unix))]
            {
                drop(f);
                Ok(())
            }
        }
        Some(Out::Capped(mut w)) => w.flush(),
        None => Ok(()),
    }
}

/// `O_EXCL` on the output's name, removed again at once: the errors
/// io_open_dest_real's open gives (`EEXIST` for any existing name, a
/// dangling link or a directory included; a missing or unwritable
/// directory; a name too long).
fn probe_exclusive(path: &Path) -> io::Result<()> {
    let mut opts = File::options();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK);
    }
    drop(opts.open(path)?);
    let _ = fs::remove_file(path);
    Ok(())
}

/// `open(dir, O_SEARCH | O_DIRECTORY | O_NOCTTY | O_NONBLOCK)` (O_SEARCH
/// is O_RDONLY where it is missing).
fn open_dir(path: &Path) -> io::Result<File> {
    let mut opts = File::options();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_DIRECTORY | libc::O_NOCTTY | libc::O_NONBLOCK);
    }
    opts.open(path)
}

/// Standard output as a file of its own (a duplicate descriptor), so its
/// writes are `write(2)`s and it can seek over holes.
fn stdout_file() -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(File::from(io::stdout().as_fd().try_clone_to_owned()?))
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// io_open_dest_real's sparse rule for standard output: a regular file,
/// written at its end, not in `O_APPEND` mode (where xz lifts the flag for
/// the run and stuffr writes the zeros instead).
fn stdout_can_be_sparse(f: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let Ok(md) = f.metadata() else {
            return false;
        };
        if !md.is_file() {
            return false;
        }
        // SAFETY: F_GETFL on a valid descriptor only reads its flags.
        let flags = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) };
        if flags == -1 || flags & libc::O_APPEND != 0 {
            return false;
        }
        let mut f = f;
        f.stream_position().is_ok_and(|pos| pos == md.len())
    }
    #[cfg(not(unix))]
    {
        let _ = f;
        false
    }
}

/// Make reads of a just-opened input block again (it was opened
/// `O_NONBLOCK` so that a FIFO's open would not wait).
#[cfg(unix)]
fn clear_nonblock(f: &File) {
    use std::os::fd::AsRawFd;
    let fd = f.as_raw_fd();
    // SAFETY: F_GETFL/F_SETFL on a valid descriptor change only its
    // status flags.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags != -1 && flags & libc::O_NONBLOCK != 0 {
            libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
}

/// file_io.c: io_copy_attrs onto the finished temporary: the owner (said
/// only when root), the group (with the permissions narrowed if it cannot
/// be set), the permission bits without set-id and sticky, the times.
fn copy_attrs(
    dest: &DestFile,
    src: &Metadata,
    shown: &[u8],
    msg: &mut Messages,
    err: &mut dyn Write,
) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let fd = dest.handle.as_raw_fd();
        let last = || strerror(&io::Error::last_os_error());
        // SAFETY: fchown/fchmod/geteuid on a valid descriptor; -1 leaves
        // that id unchanged.
        unsafe {
            if libc::fchown(fd, src.uid(), libc::gid_t::MAX) != 0 && libc::geteuid() == 0 {
                msg.warning(err, m::CANNOT_SET_OWNER, &[shown, &last()]);
            }
        }
        let src_mode = src.mode();
        let dest_gid = dest.meta.as_ref().map_or(src.gid(), MetadataExt::gid);
        // SAFETY: as above.
        let group_failed =
            dest_gid != src.gid() && unsafe { libc::fchown(fd, libc::uid_t::MAX, src.gid()) } != 0;
        let mode = if group_failed {
            msg.warning(err, m::CANNOT_SET_GROUP, &[shown, &last()]);
            // 'group' at least as strict as 'other' and vice versa.
            let m = ((src_mode & 0o070) >> 3) & (src_mode & 0o007);
            (src_mode & 0o700) | (m << 3) | m
        } else {
            src_mode & 0o777
        };
        // SAFETY: as above.
        if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 {
            msg.warning(err, m::CANNOT_SET_PERMISSIONS, &[shown, &last()]);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (shown, &msg, &err);
    }
    let mut times = fs::FileTimes::new();
    if let Ok(t) = src.accessed() {
        times = times.set_accessed(t);
    }
    if let Ok(t) = src.modified() {
        times = times.set_modified(t);
    }
    let _ = dest.handle.set_times(times);
}

/// file_io.c: io_unlink: remove the input if it is still the file that was
/// read (`stat` under `-f`, else `lstat`, by device and inode).
fn unlink(
    name: &[u8],
    path: &Path,
    known: &Metadata,
    force: bool,
    msg: &mut Messages,
    err: &mut dyn Write,
) {
    let shown = mask_nonprint(name);
    let now = if force {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    let same = now.is_ok_and(|n| host::same_file(&n, known) != Some(false));
    if !same {
        msg.warning(err, m::MOVED, &[&shown]);
        return;
    }
    if let Err(e) = fs::remove_file(path) {
        msg.warning(err, m::CANNOT_REMOVE, &[&shown, &strerror(&e)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirname_is_posix() {
        assert_eq!(dirname(b"a.xz"), b".");
        assert_eq!(dirname(b"d/a.xz"), b"d");
        assert_eq!(dirname(b"d//a.xz"), b"d");
        assert_eq!(dirname(b"/a.xz"), b"/");
        assert_eq!(dirname(b"//a.xz"), b"/");
        assert_eq!(dirname(b"x/y/a"), b"x/y");
    }
}
