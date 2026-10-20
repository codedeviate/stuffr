//! The process plumbing shared by the compatibility families: names as
//! bytes, C library behaviours the ported tools rely on (`strerror`, sticky
//! end of file), the input reader that reads the way libbzip2 does, the
//! sandbox the fuzz targets run under, and the helpers that create and
//! publish an output file (`create_temp`, `publish`), restore `SIGPIPE`
//! (`reset_sigpipe`), and either remove a partial output on interrupt
//! (`arm_cleanup`, which dies of the signal; `arm_cleanup_exit`, which
//! exits 2) or record the interrupt for the run to answer
//! (`arm_interrupt_flag`).
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

/// The signals a family hooks: a set of `libc` signal numbers.
pub(crate) type Signals = &'static [std::os::raw::c_int];

/// The signals whose arrival removes an armed output: the six xz 5.8.4's
/// signals.c `signals_init` hooks, in its order.
///
/// SIGPIPE: the Rust runtime starts every process with SIGPIPE ignored, and
/// `install_handlers` (as signals.c) leaves an ignored signal alone, so a
/// family calls `reset_sigpipe()` before arming; SIGPIPE then carries the
/// cleanup handler like the rest. `reset_sigpipe` cannot tell the runtime's
/// ignore from a parent's, so under a parent that ignores SIGPIPE stuffr
/// still hooks it: where xz would see `EPIPE`, say nothing and exit 0
/// (observed with 5.8.4: `(trap '' PIPE; xz -c big | head -c1)`), a stuffr
/// run removes its partial output and dies of SIGPIPE (the bzip2 family's
/// documented SIGPIPE deviation, in the same direction).
#[cfg(unix)]
pub(crate) const XZ_SIGNALS: Signals = &[
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGPIPE,
    libc::SIGXCPU,
    libc::SIGXFSZ,
];
#[cfg(not(unix))]
pub(crate) const XZ_SIGNALS: Signals = &[];

/// GNU gzip 1.15 (measured 2026-10-12): INT, TERM, HUP, PIPE, XCPU and XFSZ
/// remove the partial output and kill the process; QUIT and USR1 are not
/// handled; an inherited ignore is kept. The same six as xz.
pub(crate) const GNU_GZIP_SIGNALS: Signals = XZ_SIGNALS;

/// Apple's `/usr/bin/gzip` (measured 2026-10-12): SIGINT only.
#[cfg(unix)]
pub(crate) const APPLE_GZIP_SIGNALS: Signals = &[libc::SIGINT];
#[cfg(not(unix))]
pub(crate) const APPLE_GZIP_SIGNALS: Signals = &[];

/// bzip2 1.0.8 (measured 2026-10-12): INT, TERM and HUP, installed with
/// `signal()`, which overrides an inherited ignore.
#[cfg(unix)]
pub(crate) const BZIP2_SIGNALS: Signals = &[libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
#[cfg(not(unix))]
pub(crate) const BZIP2_SIGNALS: Signals = &[];

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
    #[cfg(unix)]
    kind: GuardKind,
}

/// How an armed run answers its signal.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardKind {
    /// [`arm_cleanup`]: remove the output and die of the signal; the
    /// handler stays installed after the guard drops.
    Reraise,
    /// [`arm_cleanup_exit`]: remove the output and exit 2; dropping the
    /// guard puts SIGINT back to `SIG_DFL` (zstd's `clearHandler`).
    Exit,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.armed {
            if self.kind == GuardKind::Exit {
                // SAFETY: setting SIGINT to SIG_DFL installs no handler and
                // touches no Rust state (fileio.c: clearHandler).
                unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
            }
            ARMED.store(false, Ordering::Release);
        }
    }
}

/// Write `bytes` (shorter than `SLOT_LEN`, no NUL) into the slot,
/// NUL-terminated, and mark it armed, with `signals` blocked on this thread
/// meanwhile.
#[cfg(unix)]
fn fill_slot(bytes: &[u8], signals: Signals) {
    debug_assert!(bytes.len() < SLOT_LEN && !bytes.contains(&0));
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
        for &sig in signals {
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
}

/// Arm the removal of `path`, the run's partial output, should one of
/// `signals` arrive before the guard drops; the signal is then
/// re-raised at its default action, so the process dies of it, as xz does
/// (signals.c: `signal_handler`, `signals_exit`).
///
/// Arm through `create_temp_armed`, which leaves no unarmed window. Under
/// `Host::Sandbox` nothing is armed and no handler installed. A path the slot cannot hold (or one
/// with a NUL) is not armed. Arming never allocates. Call `reset_sigpipe()`
/// first, or SIGPIPE stays ignored and unhooked (see `XZ_SIGNALS`). The
/// signals are the family's (`XZ_SIGNALS`, `GNU_GZIP_SIGNALS`,
/// `APPLE_GZIP_SIGNALS`); a process runs one family, so one set is installed.
/// One arm at a time: keep the guard `create_temp_armed` returns no longer
/// than that run's scope (before arming another). A
/// caller may hold it to the end of its function: once the temporary is
/// published or removed its unique name no longer exists, so a late signal
/// unlinks nothing, and no second arm is made in that scope.
pub(crate) fn arm_cleanup(host: &Host, path: &Path, signals: Signals) -> CleanupGuard {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        let kind = GuardKind::Reraise;
        if matches!(host, Host::Sandbox(_)) || bytes.len() >= SLOT_LEN || bytes.contains(&0) {
            return CleanupGuard { armed: false, kind };
        }
        debug_assert!(
            !ARMED.load(Ordering::Acquire),
            "arm_cleanup: another output is still armed"
        );
        install_handlers(signals);
        fill_slot(bytes, signals);
        CleanupGuard { armed: true, kind }
    }
    #[cfg(not(unix))]
    {
        let _ = (host, path, signals);
        CleanupGuard {}
    }
}

/// Install `on_cleanup_signal` for each cleanup signal not already carrying
/// it. As signals.c does, a signal the parent left ignored stays ignored
/// (`nohup`), and `SA_RESTART` is off. Queried per signal rather than
/// latched in a flag, so it holds in a child forked mid-install.
#[cfg(unix)]
fn install_handlers(signals: Signals) {
    let handler = on_cleanup_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: sigaction structs are plain data, zeroed then filled; a query
    // passes a null new action. The handler only makes async-signal-safe
    // calls (`on_cleanup_signal`), and the mask blocks every cleanup
    // signal while it runs, so one handler never interrupts another.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut action.sa_mask);
        for &sig in signals {
            libc::sigaddset(&mut action.sa_mask, sig);
        }
        action.sa_flags = 0;
        action.sa_sigaction = handler;
        for &sig in signals {
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

/// zstd 1.5.7's addHandler (fileio.c): arm the removal of `path`, the run's
/// output file, should SIGINT arrive before the guard drops; the handler
/// ([`on_interrupt_exit`]) then removes it, writes a newline to standard
/// error and exits 2, so the process exits rather than dying of the signal
/// (R6). Only SIGINT is hooked, installed as `signal()` installs it, over
/// an inherited ignore; every other signal keeps its disposition, so
/// SIGTERM still kills and leaves the file. Dropping the guard puts SIGINT
/// back to `SIG_DFL` (clearHandler).
///
/// As addHandler does, only a regular file is armed: for anything else
/// (`/dev/null`, a missing path) nothing is installed and SIGINT keeps its
/// default action. Nothing is armed under `Host::Sandbox`, or for a path
/// the slot cannot hold. It shares the slot with [`arm_cleanup`]: one
/// family per process, one arm at a time. Prefer [`create_temp_armed_exit`]
/// for a new temporary, which leaves no unarmed window.
pub(crate) fn arm_cleanup_exit(host: &Host, path: &Path) -> CleanupGuard {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        let unarmed = CleanupGuard {
            armed: false,
            kind: GuardKind::Exit,
        };
        if matches!(host, Host::Sandbox(_)) || bytes.len() >= SLOT_LEN || bytes.contains(&0) {
            return unarmed;
        }
        // UTIL_isRegularFile: stat, following a final symlink.
        if !fs::metadata(path).is_ok_and(|m| m.is_file()) {
            return unarmed;
        }
        debug_assert!(
            !ARMED.load(Ordering::Acquire),
            "arm_cleanup_exit: another output is still armed"
        );
        const INT: Signals = &[libc::SIGINT];
        fill_slot(bytes, INT);
        let handler = on_interrupt_exit as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: a zeroed sigaction filled in before use. The handler only
        // makes async-signal-safe calls (`on_interrupt_exit`). SIGINT is
        // blocked while it runs (no SA_NODEFER) and SA_RESTART is on, as
        // BSD and glibc `signal()` install a handler.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            action.sa_sigaction = handler;
            libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
        }
        CleanupGuard {
            armed: true,
            kind: GuardKind::Exit,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (host, path);
        CleanupGuard {}
    }
}

/// zstd 1.5.7's INThandler (fileio.c), with `_exit` for `exit`, which is not
/// async-signal-safe; zstd arms only a file destination, so no buffered
/// standard output is lost by not flushing (R6). It never allocates or
/// locks.
#[cfg(unix)]
extern "C" fn on_interrupt_exit(_sig: libc::c_int) {
    // SAFETY: signal is async-signal-safe; ignoring SIGINT installs no
    // handler.
    unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
    if ARMED.load(Ordering::Acquire) {
        // SAFETY: `ARMED` true means the slot holds a NUL-terminated path,
        // written before the Release store this load pairs with; unlink is
        // async-signal-safe.
        unsafe { libc::unlink(SLOT.0.get().cast::<libc::c_char>()) };
    }
    // SAFETY: write and _exit are async-signal-safe; the buffer is a
    // one-byte static literal.
    unsafe {
        libc::write(2, b"\n".as_ptr().cast(), 1);
        libc::_exit(2);
    }
}

/// Set by `on_interrupt_signal`; read and cleared by [`take_interrupt`].
#[cfg(unix)]
static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// What a run holds while its interrupt flag is armed; dropping it puts the
/// previous dispositions back.
#[must_use = "dropping the guard disarms the flag at once"]
pub(crate) struct InterruptGuard {
    #[cfg(unix)]
    old: Vec<(libc::c_int, libc::sigaction)>,
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        for (sig, old) in &self.old {
            // SAFETY: restoring a disposition sigaction itself returned.
            unsafe { libc::sigaction(*sig, old, std::ptr::null_mut()) };
        }
    }
}

/// bzip2.c's `signal(SIGINT, mySignalCatcher)` and its siblings: each of
/// `signals` sets a flag the run polls ([`take_interrupt`]), so the reply
/// (a message, `cleanUpAndFail`) is written by ordinary code, not by the
/// handler. As `signal()` does, an inherited `SIG_IGN` is overridden.
/// `SA_RESTART` is on, so an interrupted call resumes and the poll sees the
/// flag. Under `Host::Sandbox` nothing is installed.
pub(crate) fn arm_interrupt_flag(host: &Host, signals: Signals) -> InterruptGuard {
    #[cfg(unix)]
    {
        let mut old = Vec::new();
        if matches!(host, Host::Sandbox(_)) {
            return InterruptGuard { old };
        }
        INTERRUPTED.store(false, Ordering::SeqCst);
        let handler = on_interrupt_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: zeroed sigaction structs filled before use; the handler
        // only stores an atomic, which is async-signal-safe.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            action.sa_sigaction = handler;
            for &sig in signals {
                let mut prev: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, &action, &mut prev) == 0 {
                    old.push((sig, prev));
                }
            }
        }
        InterruptGuard { old }
    }
    #[cfg(not(unix))]
    {
        let _ = (host, signals);
        InterruptGuard {}
    }
}

#[cfg(unix)]
extern "C" fn on_interrupt_signal(_sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Whether an armed signal has arrived since the last call; clears it.
/// Always `false` under `Host::Sandbox`, so an in-process run never takes
/// a flag a real run's signal set.
pub(crate) fn take_interrupt(host: &Host) -> bool {
    #[cfg(unix)]
    {
        !matches!(host, Host::Sandbox(_)) && INTERRUPTED.swap(false, Ordering::SeqCst)
    }
    #[cfg(not(unix))]
    {
        let _ = host;
        false
    }
}

/// unzip 6.0 (unzip.c: `unzip()`, measured 2026-10-20 on Apple's and
/// Ubuntu's): SIGINT, SIGTERM and SIGABRT end the run through `handler()`
/// (echo back on, `EXIT(IZ_CTRLC)`), installed with `signal()`, which
/// overrides an inherited ignore; SIGHUP and SIGQUIT keep their default.
/// unzip.c also hooks SIGBUS, SIGILL and SIGSEGV ("zipfile corrupt"), which
/// only a crash raises; those are left to the Rust runtime.
#[cfg(unix)]
pub(crate) const UNZIP_SIGNALS: Signals = &[libc::SIGINT, libc::SIGTERM, libc::SIGABRT];
#[cfg(not(unix))]
pub(crate) const UNZIP_SIGNALS: Signals = &[];

/// The code and message [`on_interrupt_exit_code`] ends the process with.
#[cfg(unix)]
static EXIT_CODE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(1);
#[cfg(unix)]
static EXIT_MESSAGE: std::sync::atomic::AtomicPtr<u8> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
#[cfg(unix)]
static EXIT_MESSAGE_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// What a run holds while [`arm_interrupt_exit`]'s handler is installed;
/// dropping it puts the previous dispositions back.
#[must_use = "dropping the guard disarms the handler at once"]
pub(crate) struct InterruptExitGuard {
    #[cfg(unix)]
    old: Vec<(libc::c_int, libc::sigaction)>,
}

impl Drop for InterruptExitGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        for (sig, old) in &self.old {
            // SAFETY: restoring a disposition sigaction itself returned.
            unsafe { libc::sigaction(*sig, old, std::ptr::null_mut()) };
        }
    }
}

/// unzip.c's `SET_SIGHANDLER(sig, handler)` for each of `signals`: on
/// arrival, the terminal mode a [`TtyMode`] changed is put back (`echon()`),
/// `message` is written to standard error and the process exits with
/// `code` at once. Nothing is removed: a partial output stays, as unzip
/// leaves it. As `signal()` does, an inherited `SIG_IGN` is overridden and
/// `SA_RESTART` is on. Under `Host::Sandbox` nothing is installed.
///
/// The handler calls `_exit`, where unzip's calls `exit()` (not
/// async-signal-safe): every message is flushed as it is written, so at
/// most the one being written when the signal lands is lost.
pub(crate) fn arm_interrupt_exit(
    host: &Host,
    signals: Signals,
    code: i32,
    message: &'static [u8],
) -> InterruptExitGuard {
    #[cfg(unix)]
    {
        let mut old = Vec::new();
        if matches!(host, Host::Sandbox(_)) {
            return InterruptExitGuard { old };
        }
        EXIT_CODE.store(code, Ordering::SeqCst);
        EXIT_MESSAGE_LEN.store(message.len(), Ordering::SeqCst);
        EXIT_MESSAGE.store(message.as_ptr().cast_mut(), Ordering::SeqCst);
        let handler = on_interrupt_exit_code as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: zeroed sigaction structs filled before use; the handler
        // only makes async-signal-safe calls (`on_interrupt_exit_code`).
        // Every hooked signal is blocked while it runs, so it runs once.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&mut action.sa_mask);
            for &sig in signals {
                libc::sigaddset(&mut action.sa_mask, sig);
            }
            action.sa_flags = libc::SA_RESTART;
            action.sa_sigaction = handler;
            for &sig in signals {
                let mut prev: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, &action, &mut prev) == 0 {
                    old.push((sig, prev));
                }
            }
        }
        InterruptExitGuard { old }
    }
    #[cfg(not(unix))]
    {
        let _ = (host, signals, code, message);
        InterruptExitGuard {}
    }
}

/// [`arm_interrupt_exit`]'s handler: unzip's `handler()` (`echon()`, then
/// `EXIT(IZ_CTRLC)`). It never allocates or locks.
#[cfg(unix)]
extern "C" fn on_interrupt_exit_code(_sig: libc::c_int) {
    restore_saved_tty();
    let msg = EXIT_MESSAGE.load(Ordering::SeqCst);
    let len = EXIT_MESSAGE_LEN.load(Ordering::SeqCst);
    // SAFETY: write and _exit are async-signal-safe; `msg` is null or a
    // `&'static [u8]` of `len` bytes stored by `arm_interrupt_exit`.
    unsafe {
        if !msg.is_null() && len > 0 {
            libc::write(2, msg.cast(), len);
        }
        libc::_exit(EXIT_CODE.load(Ordering::SeqCst));
    }
}

/// The terminal whose mode a [`TtyMode`] has changed, for the interrupt
/// handler to put back: its descriptor (`-1`: none) and saved mode.
#[cfg(unix)]
static TTY_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

#[cfg(unix)]
struct TtySlot(std::cell::UnsafeCell<std::mem::MaybeUninit<libc::termios>>);

// SAFETY: the slot is written only by `TtyMode::set`, with `TTY_FD` at -1
// and the exit signals blocked on the writing thread, and read only after
// `TTY_FD` is seen >= 0 (Acquire, pairing with the Release after the
// write). One `TtyMode` exists at a time.
#[cfg(unix)]
unsafe impl Sync for TtySlot {}

#[cfg(unix)]
static TTY_SAVED: TtySlot = TtySlot(std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit()));

/// Put back the mode a live [`TtyMode`] saved, if there is one
/// (`tcsetattr(TCSAFLUSH)`, which is async-signal-safe): the signal path of
/// the guard's restore.
#[cfg(unix)]
pub(crate) fn restore_saved_tty() {
    let fd = TTY_FD.load(Ordering::Acquire);
    if fd >= 0 {
        // SAFETY: `TTY_FD` >= 0 means the slot holds the termios written
        // before the Release store this load pairs with.
        unsafe {
            libc::tcsetattr(fd, libc::TCSAFLUSH, (*TTY_SAVED.0.get()).as_ptr());
        }
    }
}

/// A terminal's mode changed for one read (ttyio.c's `echoff()`/`echon()`
/// pair, `zgetch()`'s cbreak mode), put back exactly as it was when the
/// guard drops: on every path, an error's early return and a panic's
/// unwind included, and by [`arm_interrupt_exit`]'s handler when a signal
/// ends the run meanwhile. Both changes use `TCSAFLUSH`, as ttyio.c's
/// `STTY` does, so input typed ahead of the read is discarded.
#[cfg(unix)]
pub(crate) struct TtyMode {
    fd: libc::c_int,
    saved: libc::termios,
}

#[cfg(unix)]
impl TtyMode {
    /// `GTTY(fd)`, `change` applied to a copy, `STTY(fd)`. `None` when
    /// `fd` is not a terminal (the C's `GTTY` and `STTY` then fail and
    /// change nothing).
    pub(crate) fn set(fd: libc::c_int, change: impl FnOnce(&mut libc::termios)) -> Option<TtyMode> {
        // SAFETY: termios is plain data, filled by tcgetattr before use.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr writes into the termios we own.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return None;
        }
        debug_assert!(TTY_FD.load(Ordering::Acquire) < 0, "one TtyMode at a time");
        // SAFETY: sigset_t is plain data, initialised by sigemptyset. The
        // exit signals are blocked on this thread while the slot is
        // written, and `TTY_FD` is -1 meanwhile, so no handler reads it
        // half-written; the previous mask is restored after.
        unsafe {
            let mut block: libc::sigset_t = std::mem::zeroed();
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut block);
            for &sig in UNZIP_SIGNALS {
                libc::sigaddset(&mut block, sig);
            }
            libc::pthread_sigmask(libc::SIG_BLOCK, &block, &mut old);
            (*TTY_SAVED.0.get()).write(saved);
            TTY_FD.store(fd, Ordering::Release);
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        }
        let mut t = saved;
        change(&mut t);
        // SAFETY: tcsetattr reads the termios we own.
        unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &t) };
        Some(TtyMode { fd, saved })
    }
}

#[cfg(unix)]
impl Drop for TtyMode {
    fn drop(&mut self) {
        // Put the mode back first, then clear the slot: a signal between
        // the two restores the same mode again.
        // SAFETY: tcsetattr reads the termios we own.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
        TTY_FD.store(-1, Ordering::Release);
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
            for &sig in XZ_SIGNALS.iter().chain(PROGRESS_SIGNALS) {
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

/// `create_temp` and `arm_cleanup` with `signals` held back between them,
/// so no signal can find the new temporary unarmed (GNU gzip blocks its
/// signals across the `open` for the same reason). A signal that arrived
/// meanwhile is delivered when the mask is restored, with the temporary
/// already armed. Under `Host::Sandbox`, and off unix, nothing is armed.
pub(crate) fn create_temp_armed(
    host: &Host,
    dir: &Path,
    family: &str,
    signals: Signals,
) -> io::Result<(PathBuf, File, CleanupGuard)> {
    held_back(signals, || {
        create_temp(dir, family).map(|(p, f)| {
            let g = arm_cleanup(host, &p, signals);
            (p, f, g)
        })
    })
}

/// `create_temp` and `arm_cleanup_exit` with SIGINT held back between
/// them, as [`create_temp_armed`] does for its signals, so no SIGINT finds
/// the new temporary unarmed. Under `Host::Sandbox`, and off unix, nothing
/// is armed.
pub(crate) fn create_temp_armed_exit(
    dir: &Path,
    family: &str,
    host: &Host,
) -> io::Result<(PathBuf, File, CleanupGuard)> {
    #[cfg(unix)]
    const INT: Signals = &[libc::SIGINT];
    #[cfg(not(unix))]
    const INT: Signals = &[];
    held_back(INT, || {
        create_temp(dir, family).map(|(p, f)| {
            let g = arm_cleanup_exit(host, &p);
            (p, f, g)
        })
    })
}

/// Run `f` with `signals` blocked on this thread, then restore the mask; a
/// signal that arrived meanwhile is delivered on the restore. Off unix, just
/// `f`.
fn held_back<T>(signals: Signals, f: impl FnOnce() -> T) -> T {
    #[cfg(unix)]
    {
        // SAFETY: sigset_t is plain data, initialised by sigemptyset; the
        // previous mask is restored below whatever `f` returns.
        let mut block: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut block);
            for &sig in signals {
                libc::sigaddset(&mut block, sig);
            }
            libc::pthread_sigmask(libc::SIG_BLOCK, &block, &mut old);
        }
        let made = f();
        // SAFETY: restoring the mask saved above.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
        made
    }
    #[cfg(not(unix))]
    {
        let _ = signals;
        f()
    }
}

/// `__compat-signal-test exit FILE`: the interrupt integration test's
/// helper, in debug builds only (argv[0] picks it, so nothing of the stuffr
/// CLI changes). It arms FILE with [`arm_cleanup_exit`], creates
/// `FILE.ready` to say so, and waits up to a minute for a signal; reaching
/// the end exits 0, which the test reads as a miss. A bad mode or argument
/// count exits 64.
#[cfg(all(unix, debug_assertions))]
pub(crate) fn signal_test(args: &[OsString]) -> std::process::ExitCode {
    let [mode, file] = args else {
        return std::process::ExitCode::from(64);
    };
    if mode != "exit" {
        return std::process::ExitCode::from(64);
    }
    let file = Path::new(file);
    let _guard = arm_cleanup_exit(&Host::Real, file);
    let mut ready = file.as_os_str().to_owned();
    ready.push(".ready");
    if fs::write(&ready, b"").is_err() {
        return std::process::ExitCode::from(64);
    }
    std::thread::sleep(std::time::Duration::from_secs(60));
    std::process::ExitCode::SUCCESS
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
    ///
    /// `stop` is asked before each chunk; `Ok(true)` if it said stop.
    pub(crate) fn copy_raw(
        &mut self,
        out: &mut dyn Write,
        stop: &mut dyn FnMut() -> bool,
    ) -> io::Result<bool> {
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
            if stop() {
                return Ok(true);
            }
            let n = self.read_src(&mut buf)?;
            if n == 0 {
                return Ok(false);
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

/// The machine's logical and physical core counts, read once per run: the
/// real process reads them as zstd's util.c does on its platform
/// (`UTIL_countLogicalCores`, `UTIL_countPhysicalCores`; zstd's R3 of
/// 0.14.0), a sandboxed run sees [`Cores::SANDBOX`]. Shared by the zstd and
/// lz4 families (R4 of 0.15.0; lz4 1.10.0 asks `hw.logicalcpu` on macOS,
/// probed with an interposed `sysctlbyname`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cores {
    /// `UTIL_countLogicalCores()`.
    pub logical: u32,
    /// `UTIL_countPhysicalCores()`.
    pub physical: u32,
}

impl Cores {
    /// The machine a sandboxed run sees (zstd's R3, lz4's R4).
    pub(crate) const SANDBOX: Cores = Cores {
        logical: 8,
        physical: 4,
    };

    /// The machine's counts, as util.c's `UTIL_countCores` reads them.
    pub(crate) fn detect() -> Cores {
        let (logical, physical) = count_cores();
        Cores {
            logical: logical.max(1),
            physical: physical.max(1),
        }
    }
}

/// util.c (`__APPLE__`): `sysctlbyname("hw.logicalcpu")` and
/// `"hw.physicalcpu"`, 1 when the entry is missing.
#[cfg(target_vendor = "apple")]
fn count_cores() -> (u32, u32) {
    fn read(name: &std::ffi::CStr) -> u32 {
        let mut n: i32 = 0;
        let mut size = std::mem::size_of::<i32>();
        // SAFETY: `name` is NUL-terminated, `n` is valid for `size` bytes,
        // and no new value is set.
        let r = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&mut n as *mut i32).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if r == 0 && n > 0 { n as u32 } else { 1 }
    }
    (read(c"hw.logicalcpu"), read(c"hw.physicalcpu"))
}

/// util.c (`__linux__`): `sysconf(_SC_NPROCESSORS_ONLN)`, and for the
/// physical count that divided by `/proc/cpuinfo`'s `siblings` / `cpu
/// cores` ratio when hyperthreading shows.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn count_cores() -> (u32, u32) {
    // SAFETY: `sysconf` only reads system configuration.
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if online <= 0 {
        return (1, 1);
    }
    let logical = online as u32;
    let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") else {
        return (logical, logical);
    };
    (logical, physical_from_cpuinfo(logical, &info))
}

/// util.c's `/proc/cpuinfo` walk: the last `siblings` and `cpu cores`
/// values (`atoi` of the text after `:`); a line without `:` stops the walk
/// and keeps `numCores`.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn physical_from_cpuinfo(online: u32, info: &str) -> u32 {
    fn atoi(s: &str) -> i64 {
        let s = s.trim_start();
        let (neg, digits) = match s.as_bytes().first() {
            Some(b'-') => (true, &s[1..]),
            Some(b'+') => (false, &s[1..]),
            _ => (false, s),
        };
        let n = digits
            .bytes()
            .take_while(u8::is_ascii_digit)
            .fold(0i64, |n, b| {
                n.saturating_mul(10).saturating_add(i64::from(b - b'0'))
            });
        if neg { -n } else { n }
    }
    let (mut siblings, mut cpu_cores) = (0i64, 0i64);
    for line in info.lines() {
        // fgets(buff, 80): a longer line is read in pieces, but the keys
        // only ever start a line, so only its first piece can match.
        let line = line.get(..79).unwrap_or(line);
        for (key, slot) in [("siblings", &mut siblings), ("cpu cores", &mut cpu_cores)] {
            if line.starts_with(key) {
                match line.find(':') {
                    Some(at) => *slot = atoi(&line[at + 1..]),
                    None => return online,
                }
            }
        }
    }
    let ratio = if siblings != 0 && cpu_cores != 0 && siblings > cpu_cores {
        siblings / cpu_cores
    } else {
        1
    };
    if ratio != 0 && i64::from(online) > ratio {
        (i64::from(online) / ratio) as u32
    } else {
        online
    }
}

/// util.c (the other POSIX systems): `sysconf(_SC_NPROCESSORS_ONLN)` for
/// both.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn count_cores() -> (u32, u32) {
    // SAFETY: `sysconf` only reads system configuration.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let n = if n > 0 { n as u32 } else { 1 };
    (n, n)
}

/// Elsewhere (Windows: util.c asks `GetLogicalProcessorInformation`): the
/// standard library's count for both.
#[cfg(not(unix))]
fn count_cores() -> (u32, u32) {
    let n = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    (n, n)
}

/// The cores `host` runs on: the machine's for the real process, the fixed
/// [`Cores::SANDBOX`] for a sandboxed run.
pub(crate) fn cores(host: &Host) -> Cores {
    match host {
        Host::Real => Cores::detect(),
        Host::Sandbox(_) => Cores::SANDBOX,
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

    #[test]
    fn detected_counts_are_positive() {
        let c = Cores::detect();
        assert!(c.logical >= 1 && c.physical >= 1, "{c:?}");
    }

    #[test]
    fn a_sandbox_sees_the_fixed_machine() {
        let host = Host::Sandbox(Sandbox {
            dir: PathBuf::new(),
            stdin: None,
            stdout: Arc::default(),
            budget: Arc::new(AtomicU64::new(0)),
            reads: Arc::default(),
        });
        assert_eq!(cores(&host), Cores::SANDBOX);
        assert_eq!(cores(&Host::Real), Cores::detect());
    }

    #[test]
    fn cpuinfo_divides_by_the_hyperthreading_ratio() {
        let ht = "processor\t: 0\nsiblings\t: 8\ncpu cores\t: 4\n";
        assert_eq!(physical_from_cpuinfo(16, ht), 8);
        assert_eq!(
            physical_from_cpuinfo(2, ht),
            2,
            "online not above the ratio"
        );
        assert_eq!(physical_from_cpuinfo(4, "processor\t: 0\n"), 4);
        assert_eq!(physical_from_cpuinfo(4, "siblings 8\n"), 4, "no colon");
        let no_ht = "siblings\t: 4\ncpu cores\t: 4\n";
        assert_eq!(physical_from_cpuinfo(4, no_ht), 4);
    }

    #[cfg(unix)]
    #[test]
    fn signal_sets_are_the_measured_ones() {
        // Measured 2026-10-12 (spec, section 3): GNU gzip 1.15 handles
        // xz's six; Apple's gzip SIGINT only; bzip2 1.0.8 INT, TERM, HUP.
        assert_eq!(
            XZ_SIGNALS,
            &[
                libc::SIGINT,
                libc::SIGTERM,
                libc::SIGHUP,
                libc::SIGPIPE,
                libc::SIGXCPU,
                libc::SIGXFSZ
            ]
        );
        assert_eq!(GNU_GZIP_SIGNALS, XZ_SIGNALS);
        assert_eq!(APPLE_GZIP_SIGNALS, &[libc::SIGINT]);
        assert_eq!(BZIP2_SIGNALS, &[libc::SIGINT, libc::SIGTERM, libc::SIGHUP]);
    }

    #[cfg(unix)]
    #[test]
    fn the_flag_records_a_signal_once_and_restores_on_drop() {
        // SIGUSR2: no test and no family uses it, so arming it here cannot
        // disturb a test running beside this one.
        let host = Host::Real;
        let guard = arm_interrupt_flag(&host, &[libc::SIGUSR2]);
        assert!(!take_interrupt(&host));
        // SAFETY: raise is safe; the handler only stores an atomic.
        unsafe { libc::raise(libc::SIGUSR2) };
        assert!(take_interrupt(&host));
        assert!(!take_interrupt(&host));
        drop(guard);
        let mut now: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: a query with a null new action.
        unsafe { libc::sigaction(libc::SIGUSR2, std::ptr::null(), &mut now) };
        assert_eq!(now.sa_sigaction, libc::SIG_DFL);
    }

    #[test]
    fn a_sandbox_never_sees_an_interrupt() {
        let host = Host::Sandbox(Sandbox {
            dir: PathBuf::new(),
            stdin: None,
            stdout: Arc::default(),
            budget: Arc::new(AtomicU64::new(0)),
            reads: ReadLog::default(),
        });
        let _g = arm_interrupt_flag(&host, BZIP2_SIGNALS);
        assert!(!take_interrupt(&host));
    }

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
            let _guard = arm_cleanup(&Host::Real, &file, XZ_SIGNALS);
            assert!(ARMED.load(Ordering::Acquire), "not armed");
            // SAFETY: no handler runs (no signal is sent), and this test is
            // the only in-process arm, so nothing writes the slot meanwhile.
            let slot = unsafe { &*SLOT.0.get() };
            assert_eq!(&slot[..bytes.len()], bytes);
            assert_eq!(slot[bytes.len()], 0);
        }
        assert!(!ARMED.load(Ordering::Acquire), "still armed after drop");

        let long = dir.join("x".repeat(SLOT_LEN));
        let guard = arm_cleanup(&Host::Real, &long, XZ_SIGNALS);
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
        for &sig in XZ_SIGNALS {
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
        for &sig in XZ_SIGNALS {
            let file = dir.join(format!("partial-{sig}.xz"));
            fs::write(&file, b"partial").unwrap();
            let status = in_child(|| {
                default_dispositions();
                // ARMED is inherited at fork, where `arm_then_drop_disarms`
                // may hold it; this child's arm is its only one.
                ARMED.store(false, Ordering::SeqCst);
                let _guard = arm_cleanup(&Host::Real, &file, XZ_SIGNALS);
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

    /// The calling thread's current signal mask.
    #[cfg(unix)]
    fn current_mask() -> libc::sigset_t {
        // SAFETY: a query (null new set) into a zeroed out-parameter.
        unsafe {
            let mut cur: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut cur);
            cur
        }
    }

    #[cfg(unix)]
    fn same_mask(a: &libc::sigset_t, b: &libc::sigset_t) -> bool {
        // SAFETY: both sets are initialised; sigismember only reads them.
        (1..32).all(|s| unsafe { libc::sigismember(a, s) == libc::sigismember(b, s) })
    }

    /// The new temporary is armed on return, with the path in the slot, and
    /// disarmed when the guard drops.
    #[cfg(unix)]
    #[test]
    fn create_temp_armed_arms_the_new_temporary() {
        use std::os::unix::ffi::OsStrExt;
        let dir = scratch("temp-armed");
        let status = in_child(|| {
            default_dispositions();
            ARMED.store(false, Ordering::SeqCst);
            let code = match create_temp_armed(&Host::Real, &dir, "xz", XZ_SIGNALS) {
                Err(_) => 1,
                Ok((path, _file, guard)) => {
                    let bytes = path.as_os_str().as_bytes();
                    // SAFETY: no handler runs in this child; nothing else
                    // writes the slot.
                    let slot = unsafe { &*SLOT.0.get() };
                    let armed = ARMED.load(Ordering::Acquire);
                    let held = &slot[..bytes.len()] == bytes && slot[bytes.len()] == 0;
                    drop(guard);
                    let released = !ARMED.load(Ordering::Acquire);
                    if !armed {
                        2
                    } else if !held {
                        3
                    } else if !released {
                        4
                    } else {
                        0
                    }
                }
            };
            // SAFETY: _exit is async-signal-safe and ends the child.
            unsafe { libc::_exit(code) };
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "status {status:#x}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A failed creation arms nothing and leaves the signal mask as it was.
    #[cfg(unix)]
    #[test]
    fn create_temp_armed_failure_leaves_nothing_armed_and_the_mask_restored() {
        let dir = scratch("temp-armed-fail").join("missing");
        let status = in_child(|| {
            default_dispositions();
            ARMED.store(false, Ordering::SeqCst);
            let before = current_mask();
            let failed = create_temp_armed(&Host::Real, &dir, "xz", XZ_SIGNALS).is_err();
            let after = current_mask();
            let code = if !failed {
                1
            } else if ARMED.load(Ordering::Acquire) {
                2
            } else if !same_mask(&before, &after) {
                3
            } else {
                0
            };
            // SAFETY: _exit is async-signal-safe and ends the child.
            unsafe { libc::_exit(code) };
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "status {status:#x}"
        );
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }

    /// Under a sandbox the file is created and nothing is armed.
    #[cfg(unix)]
    #[test]
    fn create_temp_armed_in_a_sandbox_arms_nothing() {
        let dir = scratch("temp-armed-sandbox");
        let host = Host::Sandbox(Sandbox {
            dir: dir.clone(),
            stdin: None,
            stdout: Arc::default(),
            budget: Arc::new(AtomicU64::new(0)),
            reads: ReadLog::default(),
        });
        let status = in_child(|| {
            default_dispositions();
            ARMED.store(false, Ordering::SeqCst);
            let code = match create_temp_armed(&host, &dir, "xz", XZ_SIGNALS) {
                Err(_) => 1,
                Ok((path, _file, _guard)) => {
                    if !path.exists() {
                        2
                    } else if ARMED.load(Ordering::Acquire) {
                        3
                    } else {
                        0
                    }
                }
            };
            // SAFETY: _exit is async-signal-safe and ends the child.
            unsafe { libc::_exit(code) };
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "status {status:#x}"
        );
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
            let _guard = arm_cleanup(&host, &file, XZ_SIGNALS);
            let mut all_default = !ARMED.load(Ordering::Acquire);
            for &sig in XZ_SIGNALS {
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

    /// The SIGINT disposition, queried.
    #[cfg(unix)]
    fn sigint_action() -> libc::sighandler_t {
        // SAFETY: a zeroed sigaction is a valid out-parameter, and a query
        // (null new action) changes nothing.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGINT, std::ptr::null(), &mut old);
            old.sa_sigaction
        }
    }

    /// zstd's addHandler/clearHandler: arming a regular file installs the
    /// exit handler on SIGINT (over an inherited ignore, as `signal()`
    /// does) and nothing else; dropping the guard disarms and puts SIGINT
    /// back to `SIG_DFL`, not to what it was. A path that is not a regular
    /// file arms nothing and installs nothing.
    #[cfg(unix)]
    #[test]
    fn exit_kind_restores_sig_dfl_on_drop() {
        let dir = scratch("exit-kind");
        let file = dir.join("partial.zst");
        fs::write(&file, b"partial").unwrap();
        let status = in_child(|| {
            default_dispositions();
            // SAFETY: SIG_IGN installs no handler; the parent's `nohup`.
            unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
            ARMED.store(false, Ordering::SeqCst);
            let handler = on_interrupt_exit as extern "C" fn(libc::c_int) as libc::sighandler_t;
            let guard = arm_cleanup_exit(&Host::Real, &file);
            let armed = ARMED.load(Ordering::Acquire) && sigint_action() == handler;
            let term_default = {
                // SAFETY: a query into a zeroed out-parameter.
                let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
                unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut old) };
                old.sa_sigaction == libc::SIG_DFL
            };
            drop(guard);
            let restored = !ARMED.load(Ordering::Acquire) && sigint_action() == libc::SIG_DFL;
            // A directory is not a regular file: nothing armed, SIGINT kept.
            // SAFETY: as above.
            unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
            let g = arm_cleanup_exit(&Host::Real, &dir);
            let skipped = !ARMED.load(Ordering::Acquire) && sigint_action() == libc::SIG_IGN;
            drop(g);
            let untouched = sigint_action() == libc::SIG_IGN;
            let code = match (armed, term_default, restored, skipped, untouched) {
                (false, ..) => 1,
                (_, false, ..) => 2,
                (_, _, false, ..) => 3,
                (_, _, _, false, _) => 4,
                (.., false) => 5,
                _ => 0,
            };
            // SAFETY: _exit is async-signal-safe and ends the child.
            unsafe { libc::_exit(code) };
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "status {status:#x}"
        );
        assert!(file.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A sandboxed exit-style arm, directly or through
    /// `create_temp_armed_exit`, arms nothing and leaves SIGINT alone.
    #[cfg(unix)]
    #[test]
    fn sandbox_installs_nothing() {
        let dir = scratch("exit-sandbox");
        let file = dir.join("partial.zst");
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
            ARMED.store(false, Ordering::SeqCst);
            let g = arm_cleanup_exit(&host, &file);
            let direct = !ARMED.load(Ordering::Acquire) && sigint_action() == libc::SIG_DFL;
            drop(g);
            let made = match create_temp_armed_exit(&dir, "zstd", &host) {
                Ok((path, _file, _g)) => {
                    path.exists()
                        && !ARMED.load(Ordering::Acquire)
                        && sigint_action() == libc::SIG_DFL
                }
                Err(_) => false,
            };
            let after = sigint_action() == libc::SIG_DFL;
            let code = match (direct, made, after) {
                (false, ..) => 1,
                (_, false, _) => 2,
                (.., false) => 3,
                _ => 0,
            };
            // SAFETY: _exit is async-signal-safe and ends the child.
            unsafe { libc::_exit(code) };
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "status {status:#x}"
        );
        assert!(file.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// `create_temp_armed_exit` arms the new temporary, regular by
    /// construction, and an interrupt then removes it and exits 2.
    #[cfg(unix)]
    #[test]
    fn create_temp_armed_exit_arms_the_new_temporary() {
        let dir = scratch("exit-temp");
        let status = in_child(|| {
            default_dispositions();
            ARMED.store(false, Ordering::SeqCst);
            // The handler's "\n" would land in the test's output.
            // SAFETY: open and dup2 are async-signal-safe; the path is a
            // NUL-terminated literal.
            unsafe {
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
                libc::dup2(null, 2);
            }
            if let Ok((_path, _file, _guard)) = create_temp_armed_exit(&dir, "zstd", &Host::Real) {
                // SAFETY: raise is async-signal-safe; the handler removes
                // the temporary and `_exit(2)`s.
                unsafe { libc::raise(libc::SIGINT) };
            }
            // SAFETY: _exit is async-signal-safe and ends the child.
            unsafe { libc::_exit(1) };
        });
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 2,
            "status {status:#x}"
        );
        assert!(
            fs::read_dir(&dir).unwrap().next().is_none(),
            "the temporary survived"
        );
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
