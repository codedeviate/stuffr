//! The process plumbing shared by the compatibility families: names as
//! bytes, C library behaviours the ported tools rely on (`strerror`, sticky
//! end of file), the input reader that reads the way libbzip2 does, the
//! sandbox the fuzz targets run under, and the helpers that create and
//! publish an output file (`create_temp`, `publish`), restore `SIGPIPE`
//! (`reset_sigpipe`) and remove a partial output on interrupt (`arm_cleanup`).
//!
//! Nothing here knows a tool's messages or flags; each family keeps its own
//! checks and wording and calls these helpers.

use std::collections::BTreeMap;
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

/// The signals whose arrival removes an armed output: the six xz 5.8.4's
/// signals.c `signals_init` hooks, in its order.
///
/// SIGPIPE: the Rust runtime starts every process with SIGPIPE ignored, and
/// `install_handlers` (as signals.c) leaves an ignored signal alone, so a
/// family calls `reset_sigpipe()` before arming; SIGPIPE then carries the
/// cleanup handler like the rest. `reset_sigpipe` cannot tell the runtime's
/// ignore from a parent's, so under a parent that ignores SIGPIPE stuffr
/// still hooks it: where xz would see `EPIPE` and report a write error, a
/// stuffr run removes its partial output and dies of SIGPIPE (the bzip2
/// family's documented SIGPIPE deviation, in the same direction).
#[cfg(unix)]
const CLEANUP_SIGNALS: [libc::c_int; 6] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGPIPE,
    libc::SIGXCPU,
    libc::SIGXFSZ,
];

/// The slot's size: `PATH_MAX`, the terminating NUL included.
#[cfg(unix)]
const SLOT_LEN: usize = libc::PATH_MAX as usize;

/// The armed path, NUL-terminated, for the handler to `unlink`. A fixed
/// static, so the handler never allocates or locks.
#[cfg(unix)]
struct PathSlot(std::cell::UnsafeCell<[u8; SLOT_LEN]>);

// SAFETY: the slot is written only by `arm_cleanup`, with `ARMED` false and
// the cleanup signals blocked on the writing thread, and read only by the
// handler after it has seen `ARMED` true (Acquire, pairing with the Release
// that follows the write). One compat run per process arms at a time.
#[cfg(unix)]
unsafe impl Sync for PathSlot {}

#[cfg(unix)]
static SLOT: PathSlot = PathSlot(std::cell::UnsafeCell::new([0; SLOT_LEN]));

/// Whether `SLOT` holds a path the handler should remove.
#[cfg(unix)]
static ARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// What a run holds while its output is partial; dropping it disarms the
/// handler, so a published output is never removed.
#[must_use = "dropping the guard disarms the cleanup at once"]
pub(crate) struct CleanupGuard {
    #[cfg(unix)]
    armed: bool,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.armed {
            ARMED.store(false, Ordering::Release);
        }
    }
}

/// Arm the removal of `path`, the run's partial output, should one of
/// `CLEANUP_SIGNALS` arrive before the guard drops; the signal is then
/// re-raised at its default action, so the process dies of it, as xz does
/// (signals.c: `signal_handler`, `signals_exit`).
///
/// The caller drops the guard right after a successful publish, and on every
/// error path after removing the file itself. Under `Host::Sandbox` nothing
/// is armed and no handler installed. A path the slot cannot hold (or one
/// with a NUL) is not armed. Arming never allocates. Call `reset_sigpipe()`
/// first, or SIGPIPE stays ignored and unhooked (see `CLEANUP_SIGNALS`).
/// One arm at a time: arm the temporary right after `create_temp` and drop
/// the guard once it is published or removed, before arming another.
pub(crate) fn arm_cleanup(host: &Host, path: &Path) -> CleanupGuard {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        if matches!(host, Host::Sandbox(_)) || bytes.len() >= SLOT_LEN || bytes.contains(&0) {
            return CleanupGuard { armed: false };
        }
        debug_assert!(
            !ARMED.load(Ordering::Acquire),
            "arm_cleanup: another output is still armed"
        );
        install_handlers();
        // SAFETY: sigset_t is plain data, initialised by sigemptyset before
        // use. Blocking the cleanup signals on this thread while the slot is
        // written means this thread's handler never sees it half-written;
        // `ARMED` is false meanwhile, so a handler on another thread reads
        // nothing. The write stays inside the slot (len < SLOT_LEN), and the
        // previous mask is restored after.
        unsafe {
            let mut block: libc::sigset_t = std::mem::zeroed();
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut block);
            for sig in CLEANUP_SIGNALS {
                libc::sigaddset(&mut block, sig);
            }
            libc::pthread_sigmask(libc::SIG_BLOCK, &block, &mut old);
            ARMED.store(false, Ordering::SeqCst);
            let slot = SLOT.0.get().cast::<u8>();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), slot, bytes.len());
            slot.add(bytes.len()).write(0);
            ARMED.store(true, Ordering::Release);
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        }
        CleanupGuard { armed: true }
    }
    #[cfg(not(unix))]
    {
        let _ = (host, path);
        CleanupGuard {}
    }
}

/// Install `on_cleanup_signal` for each cleanup signal not already carrying
/// it. As signals.c does, a signal the parent left ignored stays ignored
/// (`nohup`), and `SA_RESTART` is off. Queried per signal rather than
/// latched in a flag, so it holds in a child forked mid-install.
#[cfg(unix)]
fn install_handlers() {
    let handler = on_cleanup_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: sigaction structs are plain data, zeroed then filled; a query
    // passes a null new action. The handler only makes async-signal-safe
    // calls (`on_cleanup_signal`), and the mask blocks every cleanup
    // signal while it runs, so one handler never interrupts another.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut action.sa_mask);
        for sig in CLEANUP_SIGNALS {
            libc::sigaddset(&mut action.sa_mask, sig);
        }
        action.sa_flags = 0;
        action.sa_sigaction = handler;
        for sig in CLEANUP_SIGNALS {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, std::ptr::null(), &mut old) == 0
                && (old.sa_sigaction == libc::SIG_IGN || old.sa_sigaction == handler)
            {
                continue;
            }
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

/// The handler: remove the armed path, restore the default action, re-raise.
/// It never allocates or locks.
#[cfg(unix)]
extern "C" fn on_cleanup_signal(sig: libc::c_int) {
    if ARMED.load(Ordering::Acquire) {
        // SAFETY: `ARMED` true means the slot holds a NUL-terminated path,
        // written before the Release store this load pairs with; unlink is
        // async-signal-safe.
        unsafe { libc::unlink(SLOT.0.get().cast::<libc::c_char>()) };
    }
    // SAFETY: signal and raise are async-signal-safe. The re-raised signal
    // is blocked until this handler returns, then delivered at SIG_DFL,
    // which ends the process with that signal.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// The signals that ask for a progress line: xz 5.8.4's message.c
/// `message_progress_sigs`, SIGALRM, then SIGINFO where the system has it
/// (Apple and the BSDs), then SIGUSR1.
#[cfg(unix)]
const PROGRESS_SIGNALS: &[libc::c_int] = &[
    libc::SIGALRM,
    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    libc::SIGINFO,
    libc::SIGUSR1,
];

/// message.c's `progress_needs_updating`: set by a progress signal, taken
/// by the coder loop when it next polls (`message_progress_update`).
pub(crate) static PROGRESS_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// message.c: message_init's handlers. Every progress signal sets
/// [`PROGRESS_REQUESTED`]; the handler does nothing else. As message.c
/// does, a signal the parent left ignored is hooked all the same (only
/// signals.c's termination signals keep an inherited `SIG_IGN`).
/// `SA_RESTART` is on: xz retries every call such a signal interrupts, and
/// so do stuffr's, so the only difference is fewer retries. Under
/// `Host::Sandbox` nothing is installed.
pub(crate) fn install_progress_signals(host: &Host) {
    #[cfg(unix)]
    if matches!(host, Host::Real) {
        let handler = on_progress_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: a zeroed sigaction filled in before use; the handler only
        // stores to an atomic, which is async-signal-safe.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            action.sa_sigaction = handler;
            for &sig in PROGRESS_SIGNALS {
                libc::sigaction(sig, &action, std::ptr::null_mut());
            }
        }
    }
    #[cfg(not(unix))]
    let _ = host;
}

/// message.c: progress_signal_handler.
#[cfg(unix)]
extern "C" fn on_progress_signal(_sig: libc::c_int) {
    PROGRESS_REQUESTED.store(true, Ordering::Relaxed);
}

/// Milliseconds the process has spent stopped by SIGTSTP since it started
/// (mytime.c: mytime_sigtstp_handler adds them to `start_time`).
static STOPPED_MS: AtomicU64 = AtomicU64::new(0);

/// mytime.c: mytime_now: a monotonic clock in milliseconds
/// (`CLOCK_MONOTONIC`, as xz reads it where `clock_gettime` exists).
fn monotonic_ms() -> u64 {
    #[cfg(unix)]
    {
        // SAFETY: a zeroed timespec for clock_gettime to fill; the call is
        // async-signal-safe, so the SIGTSTP handler may make it too.
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        (ts.tv_sec as u64).wrapping_mul(1000) + (ts.tv_nsec as u64) / 1_000_000
    }
    #[cfg(not(unix))]
    {
        static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        BASE.get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
    }
}

/// The progress indicator's clock: [`monotonic_ms`] less the time spent
/// stopped, so that, as with xz's SIGTSTP handler, a stopped run's elapsed
/// time and speed leave the stop out.
pub(crate) fn running_ms() -> u64 {
    monotonic_ms().wrapping_sub(STOPPED_MS.load(Ordering::Relaxed))
}

/// signals.c: signals_init's SIGTSTP handler (`USE_SIGTSTP_HANDLER`,
/// mytime.c: mytime_sigtstp_handler), unless the parent left SIGTSTP
/// ignored. Like the other handlers of signals_init, it blocks every
/// hooked signal while it runs. Under `Host::Sandbox` nothing is
/// installed.
pub(crate) fn install_stop_handler(host: &Host) {
    #[cfg(unix)]
    if matches!(host, Host::Real) {
        let handler = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: zeroed sigaction structs, a query with a null new action;
        // the handler only makes async-signal-safe calls.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGTSTP, std::ptr::null(), &mut old) == 0
                && old.sa_sigaction == libc::SIG_IGN
            {
                return;
            }
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&mut action.sa_mask);
            for &sig in CLEANUP_SIGNALS.iter().chain(PROGRESS_SIGNALS) {
                libc::sigaddset(&mut action.sa_mask, sig);
            }
            libc::sigaddset(&mut action.sa_mask, libc::SIGTSTP);
            action.sa_flags = 0;
            action.sa_sigaction = handler;
            libc::sigaction(libc::SIGTSTP, &action, std::ptr::null_mut());
        }
    }
    #[cfg(not(unix))]
    let _ = host;
}

/// mytime.c: mytime_sigtstp_handler: stop (`raise(SIGSTOP)`), and once
/// continued, count the time stopped.
#[cfg(unix)]
extern "C" fn on_stop_signal(_sig: libc::c_int) {
    let t = monotonic_ms();
    // SAFETY: raise is async-signal-safe; the process stops here until a
    // SIGCONT.
    unsafe { libc::raise(libc::SIGSTOP) };
    STOPPED_MS.fetch_add(monotonic_ms().wrapping_sub(t), Ordering::Relaxed);
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

/// Whether `a` and `b` describe one file: the same device and inode.
/// Spelling never decides this: on a case-insensitive or normalising file
/// system two different paths can name one file. Off unix there is no
/// identity to compare, and the answer is `None`; each caller says what
/// that means for it.
pub(crate) fn same_file(a: &Metadata, b: &Metadata) -> Option<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(a.dev() == b.dev() && a.ino() == b.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        None
    }
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

/// What a sandboxed run did to one input path: how many times it opened it,
/// how many bytes it read from it over all those opens, and the largest
/// length it had when opened (a run can rewrite a file it later opens:
/// `gzip -f a a.gz`). Only inputs
/// opened through [`Host::track`] are counted (the gzip family's); the fuzz
/// target holds each to its read bound.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InputReads {
    /// Successful opens.
    pub opens: u64,
    /// Bytes read, over every open.
    pub bytes: u64,
    /// The largest length the file had at an open.
    pub len: u64,
}

/// A sandboxed run's [`InputReads`], by the path opened.
pub(crate) type ReadLog = Arc<Mutex<BTreeMap<PathBuf, InputReads>>>;

/// An input file, counting what is read from it when the run is
/// sandboxed ([`Host::track`]). Derefs to the `File` for metadata and the
/// descriptor; reads go through `Read`, so they are counted. Never read
/// through `&File` (`Read for &File`), which would bypass the count.
#[derive(Debug)]
pub(crate) struct InFile {
    file: File,
    log: Option<(ReadLog, PathBuf)>,
}

impl InFile {
    /// Another handle on the same open file, counted against the same path.
    pub(crate) fn try_clone(&self) -> io::Result<InFile> {
        Ok(InFile {
            file: self.file.try_clone()?,
            log: self.log.clone(),
        })
    }
}

impl From<File> for InFile {
    /// An uncounted input.
    fn from(file: File) -> Self {
        InFile { file, log: None }
    }
}

impl std::ops::Deref for InFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}

impl Read for InFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(buf)?;
        if let Some((log, path)) = &self.log {
            let mut log = log.lock().unwrap_or_else(|p| p.into_inner());
            log.entry(path.clone()).or_default().bytes += n as u64;
        }
        Ok(n)
    }
}

impl Seek for InFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
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
    File(InFile),
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
    pub(crate) fn file(f: impl Into<InFile>) -> Self {
        let f = f.into();
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
    /// What the run opened and read, by path ([`Host::track`]).
    pub(crate) reads: ReadLog,
}

impl Host {
    /// An operand, or a name derived from one, as a path to open.
    pub(crate) fn path(&self, b: &[u8]) -> PathBuf {
        match self {
            Host::Real => path(b),
            Host::Sandbox(s) => s.dir.join(path(b)),
        }
    }

    /// An input `f`, just opened at `path`: counted (one open, and every
    /// byte read through it) in a sandbox, plain for the real process.
    pub(crate) fn track(&self, path: &Path, f: File) -> InFile {
        match self {
            Host::Real => InFile::from(f),
            Host::Sandbox(s) => {
                let len = f.metadata().map_or(0, |m| m.len());
                let mut log = s.reads.lock().unwrap_or_else(|p| p.into_inner());
                let entry = log.entry(path.to_path_buf()).or_default();
                entry.opens += 1;
                entry.len = entry.len.max(len);
                InFile {
                    file: f,
                    log: Some((s.reads.clone(), path.to_path_buf())),
                }
            }
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

    /// `isatty(STDERR_FILENO)`; a sandbox has no terminal.
    pub(crate) fn stderr_is_tty(&self) -> bool {
        use std::io::IsTerminal;
        matches!(self, Host::Real) && io::stderr().is_terminal()
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

    /// While the guard lives the slot holds the path, NUL-terminated; once
    /// it drops the handler is armed with nothing. A path the slot cannot
    /// hold is never armed (a truncated one would name another file).
    #[cfg(unix)]
    #[test]
    fn arm_then_drop_disarms() {
        use std::os::unix::ffi::OsStrExt;
        let dir = scratch("arm");
        let file = dir.join("partial.xz");
        fs::write(&file, b"partial").unwrap();
        let bytes = file.as_os_str().as_bytes();
        {
            let _guard = arm_cleanup(&Host::Real, &file);
            assert!(ARMED.load(Ordering::Acquire), "not armed");
            // SAFETY: no handler runs (no signal is sent), and this test is
            // the only in-process arm, so nothing writes the slot meanwhile.
            let slot = unsafe { &*SLOT.0.get() };
            assert_eq!(&slot[..bytes.len()], bytes);
            assert_eq!(slot[bytes.len()], 0);
        }
        assert!(!ARMED.load(Ordering::Acquire), "still armed after drop");

        let long = dir.join("x".repeat(SLOT_LEN));
        let guard = arm_cleanup(&Host::Real, &long);
        assert!(!ARMED.load(Ordering::Acquire), "an over-long path armed");
        drop(guard);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Fork, run `child` in the child, and return its raw wait status.
    /// `child` runs after `fork` in a multithreaded process, so it calls only
    /// async-signal-safe functions and never allocates; it ends the child
    /// itself (`_exit` or a signal), and `_exit(99)` catches a return.
    #[cfg(unix)]
    fn in_child(child: impl FnOnce()) -> libc::c_int {
        // SAFETY: the child runs `child` (async-signal-safe calls only, by
        // this function's contract) and `_exit`s; it never returns into the
        // test harness. The parent only waits.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
            if pid == 0 {
                child();
                libc::_exit(99);
            }
            let mut status = 0;
            while libc::waitpid(pid, &mut status, 0) < 0 {
                assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
            }
            status
        }
    }

    /// Start a child at the default dispositions, whatever this process has
    /// installed (another test's arm) or inherited (`nohup`).
    #[cfg(unix)]
    fn default_dispositions() {
        for sig in CLEANUP_SIGNALS {
            // SAFETY: SIG_DFL installs no handler and touches no Rust state.
            unsafe { libc::signal(sig, libc::SIG_DFL) };
        }
    }

    /// The real path end to end, as xz's signals.c behaves: an armed run
    /// that takes any of the six signals xz hooks loses its partial output
    /// and dies of that same signal.
    #[cfg(unix)]
    #[test]
    fn an_interrupt_removes_the_armed_file() {
        let dir = scratch("interrupt");
        for sig in CLEANUP_SIGNALS {
            let file = dir.join(format!("partial-{sig}.xz"));
            fs::write(&file, b"partial").unwrap();
            let status = in_child(|| {
                default_dispositions();
                // ARMED is inherited at fork, where `arm_then_drop_disarms`
                // may hold it; this child's arm is its only one.
                ARMED.store(false, Ordering::SeqCst);
                let _guard = arm_cleanup(&Host::Real, &file);
                // SAFETY: raise is async-signal-safe; the handler unlinks
                // the armed path and re-raises at SIG_DFL, ending the child.
                unsafe { libc::raise(sig) };
            });
            assert!(
                libc::WIFSIGNALED(status),
                "signal {sig}: the child exited (status {status:#x})"
            );
            assert_eq!(libc::WTERMSIG(status), sig);
            assert!(!file.exists(), "signal {sig}: the partial file survived");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// A sandboxed run never touches the process's signal dispositions.
    #[cfg(unix)]
    #[test]
    fn sandbox_never_installs_handlers() {
        let dir = scratch("sandbox-signals");
        let file = dir.join("partial.xz");
        fs::write(&file, b"partial").unwrap();
        let host = Host::Sandbox(Sandbox {
            dir: dir.clone(),
            stdin: None,
            stdout: Arc::default(),
            budget: Arc::new(AtomicU64::new(0)),
            reads: ReadLog::default(),
        });
        let status = in_child(|| {
            default_dispositions();
            // ARMED is inherited from the parent at fork, where another
            // test may hold it; clear it so the check below sees only this
            // arm.
            ARMED.store(false, Ordering::SeqCst);
            let _guard = arm_cleanup(&host, &file);
            let mut all_default = !ARMED.load(Ordering::Acquire);
            for sig in CLEANUP_SIGNALS {
                // SAFETY: a zeroed sigaction is a valid out-parameter, and a
                // query (null new action) changes nothing.
                unsafe {
                    let mut old: libc::sigaction = std::mem::zeroed();
                    let queried = libc::sigaction(sig, std::ptr::null(), &mut old) == 0;
                    all_default &= queried && old.sa_sigaction == libc::SIG_DFL;
                }
            }
            // SAFETY: _exit is async-signal-safe and ends the child.
            unsafe { libc::_exit(if all_default { 0 } else { 1 }) };
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "a sandboxed arm installed a handler (status {status:#x})"
        );
        assert!(file.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// message.c's message_init: every progress signal (SIGALRM, SIGINFO
    /// where there is one, SIGUSR1) only sets the flag, and the process
    /// lives on; one the parent left ignored is hooked all the same. A
    /// sandbox installs nothing.
    #[cfg(unix)]
    #[test]
    fn progress_signals_only_set_the_flag() {
        for &sig in PROGRESS_SIGNALS {
            let status = in_child(|| {
                // SAFETY: SIG_IGN installs no handler; the parent's `nohup`.
                unsafe { libc::signal(sig, libc::SIG_IGN) };
                PROGRESS_REQUESTED.store(false, Ordering::SeqCst);
                install_progress_signals(&Host::Real);
                // SAFETY: raise is async-signal-safe; the handler stores.
                unsafe { libc::raise(sig) };
                let set = PROGRESS_REQUESTED.load(Ordering::SeqCst);
                // SAFETY: _exit ends the child.
                unsafe { libc::_exit(if set { 0 } else { 1 }) };
            });
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "signal {sig}: status {status:#x}"
            );
        }
        assert!(PROGRESS_SIGNALS.contains(&libc::SIGUSR1));
        #[cfg(target_vendor = "apple")]
        assert!(PROGRESS_SIGNALS.contains(&libc::SIGINFO));
        let host = Host::Sandbox(Sandbox {
            dir: std::env::temp_dir(),
            stdin: None,
            stdout: Arc::default(),
            budget: Arc::new(AtomicU64::new(0)),
            reads: ReadLog::default(),
        });
        let status = in_child(|| {
            let mut all_default = true;
            for &sig in PROGRESS_SIGNALS.iter().chain(&[libc::SIGTSTP]) {
                // SAFETY: SIG_DFL installs no handler.
                unsafe { libc::signal(sig, libc::SIG_DFL) };
            }
            install_progress_signals(&host);
            install_stop_handler(&host);
            for &sig in PROGRESS_SIGNALS.iter().chain(&[libc::SIGTSTP]) {
                // SAFETY: a zeroed sigaction is a valid out-parameter; a
                // query changes nothing.
                unsafe {
                    let mut old: libc::sigaction = std::mem::zeroed();
                    let queried = libc::sigaction(sig, std::ptr::null(), &mut old) == 0;
                    all_default &= queried && old.sa_sigaction == libc::SIG_DFL;
                }
            }
            // SAFETY: _exit ends the child.
            unsafe { libc::_exit(if all_default { 0 } else { 1 }) };
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "a sandbox installed a progress handler (status {status:#x})"
        );
    }

    /// mytime.c's SIGTSTP handler: the process stops by SIGSTOP, and once
    /// continued the time it spent stopped is left out of the running
    /// clock. An ignored SIGTSTP stays ignored.
    #[cfg(unix)]
    #[test]
    fn a_stop_is_left_out_of_the_running_clock() {
        // SAFETY: the child makes only async-signal-safe calls and the
        // atomics' loads, then `_exit`s; the parent waits for it to stop,
        // continues it, and reaps it.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
            if pid == 0 {
                libc::signal(libc::SIGTSTP, libc::SIG_DFL);
                install_stop_handler(&Host::Real);
                let before = STOPPED_MS.load(Ordering::SeqCst);
                libc::raise(libc::SIGTSTP);
                let stopped = STOPPED_MS.load(Ordering::SeqCst) - before;
                libc::_exit(if stopped >= 150 { 0 } else { 1 });
            }
            let mut status = 0;
            while libc::waitpid(pid, &mut status, libc::WUNTRACED) < 0 {}
            assert!(libc::WIFSTOPPED(status), "status {status:#x}");
            assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
            std::thread::sleep(std::time::Duration::from_millis(250));
            libc::kill(pid, libc::SIGCONT);
            while libc::waitpid(pid, &mut status, 0) < 0 {}
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "the stop was not counted (status {status:#x})"
            );
        }
        let status = in_child(|| {
            // SAFETY: SIG_IGN installs no handler; then a query.
            unsafe {
                libc::signal(libc::SIGTSTP, libc::SIG_IGN);
                install_stop_handler(&Host::Real);
                let mut old: libc::sigaction = std::mem::zeroed();
                libc::sigaction(libc::SIGTSTP, std::ptr::null(), &mut old);
                libc::_exit(if old.sa_sigaction == libc::SIG_IGN {
                    0
                } else {
                    1
                });
            }
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "an ignored SIGTSTP was hooked (status {status:#x})"
        );
    }
}
