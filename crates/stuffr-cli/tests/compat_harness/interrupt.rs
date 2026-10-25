//! Interrupting a run part-way: the partial-output cleanup each family's
//! reference does on a signal (0.13.1). Unix only.
//!
//! The wait after the signal is bounded (`HANG_DEADLINE`). bzip2 1.0.8's
//! `mySignalCatcher` calls `fprintf` and then `cleanUpAndFail`, which calls
//! `fprintf`, `fclose`, `remove` and `exit`, all inside the signal handler and
//! none async-signal-safe. A SIGINT that lands while bzip2 holds a stdio or
//! malloc lock (the `-v`/`-q` progress output, a malloc in the compressor)
//! deadlocks it; one `make check` saw `/usr/bin/bzip2 -q a` stall for 20
//! minutes. That is a defect of the reference, not of stuffr, so a reference
//! that hangs is a miss of the attempt (retried, then the comparison is
//! skipped with a note); a stuffr that hangs panics, always.

use std::cell::Cell;
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

pub struct Interrupted {
    pub status: ExitStatus,
    pub stderr: Vec<u8>,
    /// The run's directory afterwards, sorted.
    pub left: Vec<String>,
}

#[derive(Clone, Copy)]
pub enum Inherit {
    /// SIGINT at its default action in the child.
    Default,
    /// SIGINT ignored in the child, as `trap '' INT` or `nohup` leaves it.
    IgnoreInt,
}

/// The random 4 MiB block [`big_input`] repeats, built once per process.
fn big_block() -> &'static [u8] {
    static BLOCK: OnceLock<Vec<u8>> = OnceLock::new();
    BLOCK.get_or_init(|| super::random(4 << 20, 0x5157_0013))
}

/// The pieces of [`big_input`]`(mib)` in order: the block, repeated, the
/// last one cut to fit. Lets a caller stream the input instead of holding it.
fn big_pieces(mib: usize) -> impl Iterator<Item = &'static [u8]> {
    let block = big_block();
    let mut left = mib << 20;
    std::iter::from_fn(move || {
        let n = left.min(block.len());
        left -= n;
        (n > 0).then(|| &block[..n])
    })
}

/// An incompressible input of `mib` MiB (up to 256): one random 4 MiB block
/// repeated. The repeat distance is far beyond gzip's 32 KiB window and
/// bzip2's 900 KB blocks, so it stays incompressible to both, and building
/// it costs a fraction of `mib` MiB of `random()` in a debug build.
///
/// 0.16.1: built at the size asked for. It used to be one shared 256 MiB
/// buffer that every caller copied from, so an interrupt test held 256 MiB
/// on top of its input whatever size it used.
pub fn big_input(mib: usize) -> Vec<u8> {
    assert!(mib <= 256, "big_input holds at most 256 MiB, not {mib}");
    let mut v = Vec::with_capacity(mib << 20);
    for piece in big_pieces(mib) {
        v.extend_from_slice(piece);
    }
    v
}

/// `exe args` (the reference, a filter) over [`big_input`]`(mib)` streamed
/// to its standard input, so only the output is ever held; `None` where
/// [`super::require_reference`] skips the reference.
pub fn big_input_through(exe: &str, args: &[&str], mib: usize) -> Option<Vec<u8>> {
    use std::io::Write;
    if !super::require_reference(Path::new(exe)) {
        return None;
    }
    let mut child = super::spawn(
        Command::new(exe)
            .args(args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped()),
    )
    .unwrap();
    let mut si = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        for piece in big_pieces(mib) {
            if si.write_all(piece).is_err() {
                break;
            }
        }
    });
    // Sized for an incompressible input plus framing, so the buffer is not
    // doubled past it while it grows.
    let mut out = Vec::with_capacity((mib << 20) + (mib << 10) + 4096);
    child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    let status = child.wait().unwrap();
    writer.join().unwrap();
    assert!(status.success(), "{exe} {args:?}");
    Some(out)
}

/// How long a signalled child gets to exit before it counts as hung, when the
/// signal is expected to end the run (`Inherit::Default`).
const HANG_DEADLINE: Duration = Duration::from_secs(30);

/// How long a child that ignores the signal (`Inherit::IgnoreInt`) gets: it
/// is expected to finish its whole job, a debug-build `gzip -9` of 64 MiB
/// (about 8 s here, far more on a slow runner), so only a real hang should
/// reach this. A hung stuffr panics and a hung reference is a miss, as with
/// `HANG_DEADLINE`.
const IGNORED_SIGNAL_DEADLINE: Duration = Duration::from_secs(600);

thread_local! {
    /// Set when the last `interrupt_env` on this thread lost its attempt to a
    /// hung *reference* (never to a hung stuffr, which panics).
    static REFERENCE_HUNG: Cell<bool> = const { Cell::new(false) };
}

/// True, once, if an `interrupt_env` on this thread returned `None` because
/// the reference hung after the signal rather than finishing early.
pub fn take_reference_hung() -> bool {
    REFERENCE_HUNG.with(|h| h.replace(false))
}

/// Whether `exe` is the stuffr binary under test (directly or by a link).
/// When either path cannot be resolved it counts as stuffr, so a hang
/// fails the test rather than passing as a reference's miss (0.16.0: the
/// check used to fail open).
fn is_stuffr(exe: &Path) -> bool {
    match (
        std::fs::canonicalize(exe),
        std::fs::canonicalize(env!("CARGO_BIN_EXE_stuffr")),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => true,
    }
}

static INTERRUPT_LOCK: Mutex<()> = Mutex::new(());

/// Held for a whole interrupt test, so at most one runs at a time in a test
/// binary: each writes up to 256 MiB and spawns a debug-build run beside the
/// reference, which starves the timed differential cases on a small runner.
/// Taken before (never inside) the harness's `spawn_lock`.
pub fn interrupt_lock() -> MutexGuard<'static, ()> {
    INTERRUPT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The input size for a case that is fast per byte (a near-stored decompress,
/// a raw copy): three times the attempt's size, capped at what `big_input`
/// holds, so even the first attempt leaves the run seconds to be signalled.
pub fn fast_size(mib: usize) -> usize {
    (mib * 3).min(256)
}

pub fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Runs `exe` (argv[0] = `name`) with `args` in `dir`; waits until a
/// directory entry satisfies `ready`, sends `sig`, waits up to
/// `HANG_DEADLINE` (`IGNORED_SIGNAL_DEADLINE` if the child ignores it) for exit. `None` if the run ended before the signal could
/// be sent, or if a reference (not stuffr) hung after it
/// ([`take_reference_hung`] tells which); stuffr hanging panics.
pub fn interrupt(
    exe: &Path,
    name: &str,
    args: &[&str],
    dir: &Path,
    inherit: Inherit,
    sig: i32,
    ready: &dyn Fn(&str) -> bool,
) -> Option<Interrupted> {
    interrupt_env(exe, name, args, dir, &[], inherit, sig, ready)
}

/// [`interrupt`] with extra environment variables for the run (a family
/// that picks its personality from one, as gzip does).
#[allow(clippy::too_many_arguments)]
pub fn interrupt_env(
    exe: &Path,
    name: &str,
    args: &[&str],
    dir: &Path,
    env: &[(&str, &str)],
    inherit: Inherit,
    sig: i32,
    ready: &dyn Fn(&str) -> bool,
) -> Option<Interrupted> {
    interrupt_when(
        exe,
        name,
        args,
        dir,
        env,
        inherit,
        sig,
        Ready::Listing(ready),
    )
}

/// [`interrupt_env`] for a run that writes to standard output (`-c`, a
/// filter) and creates nothing in `dir` to wait on: standard output is a
/// pipe, and the run counts as ready once its first byte arrives (the rest
/// is drained on a thread, so the child never blocks on a full pipe). A
/// program that installs its signal handlers before it writes anything is
/// then sure to have them in place when the signal lands.
#[allow(clippy::too_many_arguments)]
pub fn interrupt_once_stdout_has_data(
    exe: &Path,
    name: &str,
    args: &[&str],
    dir: &Path,
    env: &[(&str, &str)],
    inherit: Inherit,
    sig: i32,
) -> Option<Interrupted> {
    interrupt_when(exe, name, args, dir, env, inherit, sig, Ready::Stdout)
}

/// When an interrupt run is ready for its signal.
enum Ready<'a> {
    /// An entry of the run's directory satisfies the predicate.
    Listing(&'a dyn Fn(&str) -> bool),
    /// The run has written to its standard output (a pipe).
    Stdout,
}

#[allow(clippy::too_many_arguments)]
fn interrupt_when(
    exe: &Path,
    name: &str,
    args: &[&str],
    dir: &Path,
    env: &[(&str, &str)],
    inherit: Inherit,
    sig: i32,
    ready: Ready,
) -> Option<Interrupted> {
    let mut cmd = Command::new(exe);
    cmd.arg0(name).args(args).current_dir(dir);
    cmd.envs(env.iter().copied());
    let stdout = match ready {
        Ready::Listing(_) => Stdio::null(),
        Ready::Stdout => Stdio::piped(),
    };
    cmd.stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            let int = match inherit {
                Inherit::Default => libc::SIG_DFL,
                Inherit::IgnoreInt => libc::SIG_IGN,
            };
            libc::signal(libc::SIGINT, int);
            for s in [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT, libc::SIGPIPE] {
                libc::signal(s, libc::SIG_DFL);
            }
            Ok(())
        });
    }
    REFERENCE_HUNG.with(|h| h.set(false));
    let mut child = super::spawn(&mut cmd).expect("spawn");
    // With `Ready::Stdout`: set at the first byte; the thread then drains
    // standard output to its end.
    let wrote = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _drain = child.stdout.take().map(|mut out| {
        let wrote = wrote.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            while let Ok(n) = out.read(&mut buf) {
                if n == 0 {
                    break;
                }
                wrote.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        })
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            return None;
        }
        let is_ready = match ready {
            Ready::Listing(f) => listing(dir).iter().any(|n| f(n)),
            Ready::Stdout => wrote.load(std::sync::atomic::Ordering::SeqCst),
        };
        if is_ready {
            break;
        }
        if Instant::now() >= deadline {
            // Do not leave the child running behind the panic.
            let _ = child.kill();
            let _ = child.wait();
            panic!("{name} {args:?}: never became ready");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    // Drain stderr on a thread, so a chatty child can neither fill the pipe
    // nor leave us blocked in a read after a kill.
    let mut pipe = child.stderr.take().expect("piped stderr");
    let reader = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = pipe.read_to_end(&mut v);
        v
    });
    // SAFETY: kill on a child we spawned and have not reaped.
    unsafe { libc::kill(child.id() as i32, sig) };
    let hang_at = Instant::now()
        + match inherit {
            Inherit::Default => HANG_DEADLINE,
            Inherit::IgnoreInt => IGNORED_SIGNAL_DEADLINE,
        };
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break Some(st);
        }
        if Instant::now() >= hang_at {
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        let stderr = reader.join().unwrap_or_default();
        let note = format!(
            "{name} {args:?}: hung after the signal ({sig}); stderr so far: {:?}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(!is_stuffr(exe), "{note}");
        eprintln!("note: reference {note}; attempt counted as a miss");
        REFERENCE_HUNG.with(|h| h.set(true));
        return None;
    };
    let stderr = reader.join().unwrap_or_default();
    Some(Interrupted {
        status,
        stderr,
        left: listing(dir),
    })
}

/// `interrupt` over `input(mib)` written to `dir/file`, retrying once with
/// four times the input if the run finished before the signal (it ended
/// first, or exited 0 between ready and the kill); a second miss fails the
/// test rather than passing silently. Cases whose work is fast per byte pass
/// an `input` that scales `mib` up. `None` only when the reference hung after
/// the signal on every attempt (see the module doc): the caller skips that
/// comparison; a hung stuffr panics inside.
#[allow(clippy::too_many_arguments)]
pub fn interrupt_with_input(
    exe: &Path,
    name: &str,
    args: &[&str],
    dir: &Path,
    file: &str,
    input: &dyn Fn(usize) -> Vec<u8>,
    inherit: Inherit,
    sig: i32,
    ready: &dyn Fn(&str) -> bool,
) -> Option<Interrupted> {
    interrupt_with_input_env(exe, name, args, dir, &[], file, input, inherit, sig, ready)
}

/// [`interrupt_with_input`] with extra environment variables.
#[allow(clippy::too_many_arguments)]
pub fn interrupt_with_input_env(
    exe: &Path,
    name: &str,
    args: &[&str],
    dir: &Path,
    env: &[(&str, &str)],
    file: &str,
    input: &dyn Fn(usize) -> Vec<u8>,
    inherit: Inherit,
    sig: i32,
    ready: &dyn Fn(&str) -> bool,
) -> Option<Interrupted> {
    let mut hung = false;
    for mib in [64, 256] {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(file), input(mib)).unwrap();
        // A run that exited 0 was over before the signal landed (a test
        // thread descheduled for a few tens of milliseconds is enough on a
        // fast case): a miss, like `None`. No caller expects success here.
        match interrupt_env(exe, name, args, dir, env, inherit, sig, ready) {
            Some(r) if !r.status.success() => return Some(r),
            _ => hung |= take_reference_hung(),
        }
    }
    if hung {
        eprintln!("note: {name} {args:?}: the reference hung after the signal; comparison skipped");
        return None;
    }
    panic!("{name} {args:?}: finished before the signal even at the larger size");
}

pub fn killed_by(r: &Interrupted, sig: i32) -> bool {
    r.status.signal() == Some(sig)
}

/// [`stored_gzip`] of [`big_input`]`(mib)`, built without holding the
/// input: the gzip file alone is held.
pub fn stored_gzip_of_big(mib: usize) -> Vec<u8> {
    // A stored block (65535 bytes) is far shorter than the 4 MiB block, so
    // each one is cut from at most two neighbouring repeats of it.
    let block = big_block();
    let len = mib << 20;
    let mut crc = flate2::Crc::new();
    let mut v = Vec::with_capacity(stored_gzip_len(len));
    v.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]);
    if len == 0 {
        v.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    let mut at = 0;
    while at < len {
        let n = (len - at).min(65535);
        v.push(u8::from(at + n == len));
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v.extend_from_slice(&(!(n as u16)).to_le_bytes());
        let mut done = 0;
        while done < n {
            let off = (at + done) % block.len();
            let piece = &block[off..block.len().min(off + n - done)];
            crc.update(piece);
            v.extend_from_slice(piece);
            done += piece.len();
        }
        at += n;
    }
    v.extend_from_slice(&crc.sum().to_le_bytes());
    v.extend_from_slice(&(len as u32).to_le_bytes());
    v
}

/// The size of [`stored_gzip`] over `n` bytes: header, five bytes per
/// stored block (one block even when empty), trailer.
fn stored_gzip_len(n: usize) -> usize {
    10 + 5 * n.div_ceil(65535).max(1) + n + 8
}

/// A gzip file holding `data` as stored deflate blocks: valid, fast to
/// make, and as large as its input, so a run over it lasts.
pub fn stored_gzip(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(stored_gzip_len(data.len()));
    v.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]);
    let mut chunks = data.chunks(65535).peekable();
    if chunks.peek().is_none() {
        v.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(c) = chunks.next() {
        v.push(u8::from(chunks.peek().is_none()));
        v.extend_from_slice(&(c.len() as u16).to_le_bytes());
        v.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        v.extend_from_slice(c);
    }
    v.extend_from_slice(&super::crc32(data).to_le_bytes());
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v
}

/// A zip archive of one stored entry `name` holding `data` (unix mode
/// 0644): valid, fast to make, as large as its input, so an extraction of
/// it lasts (the unzip family).
pub fn stored_zip(name: &[u8], data: &[u8]) -> Vec<u8> {
    let crc = super::crc32(data);
    let size = u32::try_from(data.len()).expect("under 4 GiB");
    let n = u16::try_from(name.len()).unwrap();
    let mut v = Vec::with_capacity(data.len() + 200);
    v.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    for x in [20u16, 0, 0, 0, 0x5021] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    for x in [crc, size, size] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&n.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(name);
    v.extend_from_slice(data);
    let cd_at = u32::try_from(v.len()).unwrap();
    v.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    for x in [0x031eu16, 20, 0, 0, 0, 0x5021] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    for x in [crc, size, size] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    for x in [n, 0, 0, 0, 0] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(name);
    let cd_len = u32::try_from(v.len()).unwrap() - cd_at;
    v.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    for x in [0u16, 0, 1, 1] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&cd_len.to_le_bytes());
    v.extend_from_slice(&cd_at.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v
}

/// A `ready` predicate for a family's partial output: an entry whose name
/// satisfies `named` and that already holds data (so the run is past the
/// point where it armed its cleanup).
pub fn has_data<'a>(dir: &'a Path, named: &'a dyn Fn(&str) -> bool) -> impl Fn(&str) -> bool + 'a {
    move |n| named(n) && std::fs::metadata(dir.join(n)).is_ok_and(|m| m.len() > 0)
}
