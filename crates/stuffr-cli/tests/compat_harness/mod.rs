//! Differential harness: run a real reference tool and stuffr invoked through
//! a symlink of the same name with identical arguments, input files, stdin,
//! tty state and environment, then compare everything observable.
//!
//! Unix only. The caller declares it as `#[cfg(unix)] mod compat_harness;`.
#![allow(dead_code)] // each test crate uses a different subset

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Where the reference tools live; also used to decompress stuffr's output.
pub const REFERENCE_DIR: &str = "/usr/bin";
/// The mtime every input file gets, so runs cannot differ by wall clock.
pub const INPUT_MTIME: u64 = 1_000_000_000;
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Case<'a> {
    /// The invoked name, e.g. `"bunzip2"`.
    pub name: &'a str,
    pub args: Vec<&'a str>,
    /// Created in the working directory before running.
    pub files: Vec<(&'a str, Vec<u8>)>,
    /// Fed to stdin: through a pipe, or, with `tty_stdin`, typed at the
    /// terminal (framed with `\n` if needed, then ^D). A canonical-mode line
    /// is limited by `MAX_CANON` (1024 bytes on macOS), so keep tty input to
    /// about 1 KiB of plain text with no control characters.
    pub stdin: Option<Vec<u8>>,
    pub tty_stdin: bool,
    pub tty_stdout: bool,
    /// Extra environment. The environment is otherwise cleared and only
    /// `PATH` and `LANG` are set, so `BZIP2`/`BZIP` never leak in.
    pub env: Vec<(&'a str, &'a str)>,
    /// Byte identity of compressed output is promised. When false, stuffr's
    /// compressed outputs are instead round-tripped through the reference.
    pub compare_output_bytes: bool,
    /// What a compressed stdout should decompress to, when that is not the
    /// stdin (or every input file concatenated in order).
    pub expect_stdout_plain: Option<Vec<u8>>,
    /// Run in the working directory after `files` are created and before the
    /// program starts: symlinks, hard links, permission changes.
    pub setup: Option<fn(&Path)>,
}

/// File bytes, mode (permission bits) and mtime (seconds).
pub type Tree = BTreeMap<String, (Vec<u8>, u32, i64)>;

pub struct Run {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub tree: Tree,
    /// Unix seconds when this run began (before its inputs were created).
    pub start: i64,
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Serialises pty creation through spawn so no concurrently spawned child
/// can inherit a master between `openpty` and its close-on-exec flag.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "stuffr-harness-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("work")).unwrap();
        Scratch(d)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Whether the reference tool `exe` is installed. When it is not, print
/// `skipped: <tool> not installed` and return false — except on CI (the
/// `CI` environment variable is set), where a missing reference is a
/// failure: every test that skips on it would otherwise pass vacuously.
pub fn require_reference(exe: &Path) -> bool {
    if exe.exists() {
        return true;
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "CI is set but the reference tool {} is not installed",
        exe.display()
    );
    eprintln!("skipped: {} not installed", exe.display());
    false
}

/// Run the reference tool `tool_dir/<name>`. `None` when it is missing (see
/// [`require_reference`], which panics instead on CI).
pub fn reference(tool_dir: &str, c: &Case) -> Option<Run> {
    let exe = Path::new(tool_dir).join(c.name);
    if !require_reference(&exe) {
        return None;
    }
    let s = Scratch::new();
    Some(execute(&exe, &s, c))
}

/// Run stuffr through a symlink named `c.name`.
pub fn stuffr_as(c: &Case) -> Run {
    let s = Scratch::new();
    let bin = s.0.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let link = bin.join(c.name);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
    execute(&link, &s, c)
}

fn execute(exe: &Path, s: &Scratch, c: &Case) -> Run {
    let work = s.0.join("work");
    let start = now_secs();
    for (name, bytes) in &c.files {
        let p = work.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, bytes).unwrap();
        let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(INPUT_MTIME))
            .unwrap();
    }
    if let Some(setup) = c.setup {
        setup(&work);
    }

    let guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut cmd = Command::new(exe);
    cmd.args(&c.args)
        .current_dir(&work)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .envs(c.env.iter().copied());

    let mut stdin_master: Option<std::fs::File> = None;
    let mut stdout_master: Option<std::fs::File> = None;
    if c.tty_stdin {
        let (m, sl) = openpty();
        cmd.stdin(Stdio::from(sl));
        stdin_master = Some(std::fs::File::from(m));
    } else if c.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    if c.tty_stdout {
        let (m, sl) = openpty();
        cmd.stdout(Stdio::from(sl));
        stdout_master = Some(std::fs::File::from(m));
    } else {
        cmd.stdout(Stdio::piped());
    }
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {exe:?}: {e}"));
    drop(cmd); // closes our copies of the pty slaves
    drop(guard);

    let writer = if let Some(m) = &stdin_master {
        // Type the input, then end-of-file. Canonical mode honours ^D only at
        // the start of a line, so add a newline unless the data ends in one.
        let mut data = c.stdin.clone().unwrap_or_default();
        if !data.is_empty() && !data.ends_with(b"\n") {
            data.push(b'\n');
        }
        data.push(0x04);
        let mut m = m.try_clone().unwrap();
        Some(std::thread::spawn(move || {
            let _ = m.write_all(&data); // child may exit early
        }))
    } else {
        child.stdin.take().map(|mut si| {
            let data = c.stdin.clone().unwrap_or_default();
            std::thread::spawn(move || {
                let _ = si.write_all(&data); // child may exit early
            })
        })
    };
    let out_t = stdout_master
        .take()
        .map(drain)
        .or_else(|| child.stdout.take().map(drain));
    let err_t = child.stderr.take().map(drain);

    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{exe:?} {:?} timed out after {TIMEOUT:?}", c.args);
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    // Deliberately not joined: a child that never reads the terminal leaves
    // the writer blocked once the pty buffer is full, and joining would hang
    // the test. Dropping the handle detaches it; the thread ends when the
    // master (and its clone) close or the write fails.
    drop(writer);
    let stdout = out_t.map(|t| t.join().unwrap()).unwrap_or_default();
    drop(stdin_master);
    let stderr_raw = err_t.map(|t| t.join().unwrap()).unwrap_or_default();

    let stderr = normalise_stderr(&stderr_raw, exe, c.name);

    let code = status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(0));
    Run {
        code,
        stdout,
        stderr,
        tree: snapshot(&work),
        start,
    }
}

/// The only normalisation: the program path becomes the bare invoked name.
/// Only a whole occurrence is replaced, one followed by `:`, whitespace or
/// the end of the text, so a longer path that merely starts with the
/// program path (`/x/bzip2.bak`) is left alone.
pub fn normalise_stderr(raw: &[u8], exe: &Path, name: &str) -> String {
    let text = String::from_utf8_lossy(raw);
    let path = exe.to_str().unwrap();
    let mut out = String::with_capacity(text.len());
    let mut rest: &str = &text;
    while let Some(i) = rest.find(path) {
        let after = &rest[i + path.len()..];
        let whole = after
            .chars()
            .next()
            .is_none_or(|c| c == ':' || c.is_whitespace());
        out.push_str(&rest[..i]);
        out.push_str(if whole { name } else { path });
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Read to end-of-file on a worker thread. A pty master reports hang-up as
/// 0 on macOS and as `EIO` on Linux, and only those two count as end of file.
/// `Interrupted` is retried; anything else panics, so the `join().unwrap()`
/// surfaces it rather than handing back a silently truncated stream.
fn drain<R: Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut v = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => v.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break, // Linux hang-up
                Err(e) => panic!("read failed: {e}"),
            }
        }
        v
    })
}

// glibc declares these `const`, the BSDs and macOS declare them mutable.
#[cfg(any(target_os = "linux", target_os = "android"))]
const NULL_TERMIOS: *const libc::termios = std::ptr::null();
#[cfg(any(target_os = "linux", target_os = "android"))]
const NULL_WINSIZE: *const libc::winsize = std::ptr::null();
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const NULL_TERMIOS: *mut libc::termios = std::ptr::null_mut();
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const NULL_WINSIZE: *mut libc::winsize = std::ptr::null_mut();

/// Open a pty pair, close-on-exec on both ends.
fn openpty() -> (OwnedFd, OwnedFd) {
    let (mut m, mut s) = (0, 0);
    // SAFETY: out-pointers are valid; the null name/termios/winsize are allowed.
    let rc = unsafe {
        libc::openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            NULL_TERMIOS,
            NULL_WINSIZE,
        )
    };
    assert_eq!(rc, 0, "openpty failed: {}", std::io::Error::last_os_error());
    // SAFETY: openpty returned two fresh descriptors we now own.
    let (m, s) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
    for fd in [&m, &s] {
        // SAFETY: valid descriptor.
        let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        assert_eq!(rc, 0, "fcntl: {}", std::io::Error::last_os_error());
    }
    // Typed input must not echo into the master's read queue, and `\r` must
    // not turn into `\n`; canonical mode stays on so ^D means end of file.
    // SAFETY: `t` is fully initialised by a successful tcgetattr.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(s.as_raw_fd(), &mut t), 0);
        t.c_lflag &= !(libc::ECHO | libc::ECHONL);
        t.c_iflag &= !libc::ICRNL;
        assert_eq!(libc::tcsetattr(s.as_raw_fd(), libc::TCSANOW, &t), 0);
    }
    (m, s)
}

fn snapshot(work: &Path) -> Tree {
    let mut t = Tree::new();
    walk(work, work, &mut t);
    t
}

fn walk(root: &Path, dir: &Path, t: &mut Tree) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        let md = fs::symlink_metadata(&p).unwrap();
        let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
        let mode = md.mode() & 0o7777;
        if md.is_dir() {
            // Directory mtimes move with every entry; record mode only.
            t.insert(format!("{rel}/"), (Vec::new(), mode, 0));
            walk(root, &p, t);
        } else if md.file_type().is_symlink() {
            let target = fs::read_link(&p).unwrap();
            t.insert(
                rel,
                (
                    target.to_string_lossy().into_owned().into_bytes(),
                    mode,
                    md.mtime(),
                ),
            );
        } else {
            // A file the case made unreadable is recorded, not fatal.
            let bytes = fs::read(&p).unwrap_or_else(|_| b"<unreadable>".to_vec());
            t.insert(rel, (bytes, mode, md.mtime()));
        }
    }
}

fn is_bz2_name(n: &str) -> bool {
    n.ends_with(".bz2") || n.ends_with(".tbz2") || n.ends_with(".tbz")
}

/// Decompress with the reference `bzip2 -dc`; `Err` carries its stderr.
pub fn ref_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(Path::new(REFERENCE_DIR).join("bzip2"))
        .arg("-dc")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run reference bzip2: {e}"))?;
    let mut si = child.stdin.take().unwrap();
    let data = data.to_vec();
    let w = std::thread::spawn(move || {
        let _ = si.write_all(&data);
    });
    let o = child.wait_with_output().map_err(|e| e.to_string())?;
    let _ = w.join();
    if o.status.success() {
        Ok(o.stdout)
    } else {
        Err(String::from_utf8_lossy(&o.stderr).into_owned())
    }
}

/// The original a compressed output named `name` should decompress to.
fn original_for(c: &Case, name: &str) -> Option<Vec<u8>> {
    let base = name.strip_suffix(".bz2").map(str::to_owned).or_else(|| {
        name.strip_suffix(".tbz2")
            .or(name.strip_suffix(".tbz"))
            .map(|b| format!("{b}.tar"))
    })?;
    c.files
        .iter()
        .find(|(n, _)| *n == base)
        .map(|(_, b)| b.clone())
}

fn describe_bytes(b: &[u8]) -> String {
    let head: Vec<String> = b.iter().take(32).map(|x| format!("{x:02x}")).collect();
    format!(
        "{} bytes [{}{}]",
        b.len(),
        head.join(" "),
        if b.len() > 32 { " ..." } else { "" }
    )
}

fn first_diff(a: &[u8], b: &[u8]) -> String {
    match a.iter().zip(b).position(|(x, y)| x != y) {
        Some(i) => format!("first difference at offset {i}"),
        None => "one is a prefix of the other".to_owned(),
    }
}

/// Both outputs are bzip2 streams (`BZh<N>`) and the block-size digits differ.
fn block_digit_mismatch(reference: &[u8], ours: &[u8]) -> Option<String> {
    if reference.len() > 3 && reference.starts_with(b"BZh") && ours.len() > 3 {
        let (r, s) = (reference[3], ours[3]);
        if r != s {
            return Some(format!(
                "block-size digit differs: reference {:?} vs stuffr {:?}",
                r as char, s as char
            ));
        }
    }
    None
}

/// An mtime pair is acceptable when equal; otherwise a copied input mtime
/// (`INPUT_MTIME`) must match exactly, and freshly created files must each
/// lie within a couple of seconds of their own run's wall-clock window.
fn mtime_ok(r: i64, r_start: i64, s: i64, s_start: i64, now: i64) -> bool {
    if r == s {
        return true;
    }
    let pinned = INPUT_MTIME as i64;
    if r == pinned || s == pinned {
        return false;
    }
    let within = |t: i64, start: i64| t >= start - 2 && t <= now + 2;
    within(r, r_start) && within(s, s_start)
}

/// Full comparison of `r` (reference) against `s` (stuffr). Panics with every
/// difference listed, not just the first.
pub fn assert_same(c: &Case, r: &Run, s: &Run) {
    let mut d: Vec<String> = Vec::new();
    if r.code != s.code {
        d.push(format!(
            "exit code: reference {} vs stuffr {}",
            r.code, s.code
        ));
    }
    if r.stderr != s.stderr {
        d.push(format!(
            "stderr differs:\n  reference: {:?}\n  stuffr:    {:?}",
            r.stderr, s.stderr
        ));
    }

    // stdout
    if c.compare_output_bytes || !s.stdout.starts_with(b"BZh") {
        if r.stdout != s.stdout {
            d.push(format!(
                "stdout differs ({}):\n  reference: {}\n  stuffr:    {}",
                first_diff(&r.stdout, &s.stdout),
                describe_bytes(&r.stdout),
                describe_bytes(&s.stdout)
            ));
        }
    } else {
        let want = c
            .expect_stdout_plain
            .clone()
            .or_else(|| c.stdin.clone())
            .unwrap_or_else(|| c.files.iter().flat_map(|(_, b)| b.clone()).collect());
        if let Some(e) = block_digit_mismatch(&r.stdout, &s.stdout) {
            d.push(format!("stdout {e}"));
        }
        match ref_decompress(&s.stdout) {
            Ok(got) if got == want => {}
            Ok(got) => d.push(format!(
                "stdout round-trip mismatch: want {}, got {}",
                describe_bytes(&want),
                describe_bytes(&got)
            )),
            Err(e) => d.push(format!("reference bzip2 rejects stuffr's stdout: {e}")),
        }
    }

    // tree
    let now = now_secs();
    let names: std::collections::BTreeSet<&String> = r.tree.keys().chain(s.tree.keys()).collect();
    for n in names {
        match (r.tree.get(n), s.tree.get(n)) {
            (Some(_), None) => d.push(format!(
                "tree: {n} removed in stuffr (exists in reference only)"
            )),
            (None, Some(_)) => d.push(format!("tree: {n} added in stuffr (exists in stuffr only)")),
            (Some((rb, rm, rt)), Some((sb, sm, st))) => {
                if rm != sm {
                    d.push(format!("tree: {n} mode reference {rm:o} vs stuffr {sm:o}"));
                }
                if !mtime_ok(*rt, r.start, *st, s.start, now) {
                    d.push(format!("tree: {n} mtime reference {rt} vs stuffr {st}"));
                }
                if rb == sb {
                    continue;
                }
                if !c.compare_output_bytes && is_bz2_name(n) {
                    if let Some(e) = block_digit_mismatch(rb, sb) {
                        d.push(format!("tree: {n} {e}"));
                    }
                    match (ref_decompress(sb), original_for(c, n)) {
                        (Ok(got), Some(want)) if got == want => {}
                        (Ok(got), Some(want)) => d.push(format!(
                            "tree: {n} round-trip mismatch: want {}, got {}",
                            describe_bytes(&want),
                            describe_bytes(&got)
                        )),
                        (Ok(_), None) => d.push(format!(
                            "tree: {n} decompresses but its original is unknown"
                        )),
                        (Err(e), _) => {
                            d.push(format!("tree: reference bzip2 rejects stuffr's {n}: {e}"))
                        }
                    }
                } else {
                    d.push(format!(
                        "tree: {n} bytes differ ({}):\n  reference: {}\n  stuffr:    {}",
                        first_diff(rb, sb),
                        describe_bytes(rb),
                        describe_bytes(sb)
                    ));
                }
            }
            (None, None) => unreachable!(),
        }
    }

    if !d.is_empty() {
        panic!(
            "{} {:?}: stuffr differs from the reference in {} way(s):\n{}",
            c.name,
            c.args,
            d.len(),
            d.iter()
                .map(|x| format!(" - {x}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
