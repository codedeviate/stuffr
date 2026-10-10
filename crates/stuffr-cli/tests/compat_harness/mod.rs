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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Where the reference tools live; also used to decompress stuffr's output.
pub const REFERENCE_DIR: &str = "/usr/bin";
/// The mtime every input file gets, so runs cannot differ by wall clock.
const INPUT_MTIME: u64 = 1_000_000_000;
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Case<'a> {
    /// The invoked name, e.g. `"bunzip2"`.
    pub name: &'a str,
    pub args: Vec<&'a str>,
    /// Created in the working directory before running.
    pub files: Vec<(&'a str, Vec<u8>)>,
    /// Piped to stdin. Ignored when `tty_stdin` is set.
    pub stdin: Option<Vec<u8>>,
    pub tty_stdin: bool,
    pub tty_stdout: bool,
    /// Extra environment. The environment is otherwise cleared and only
    /// `PATH` and `LANG` are set, so `BZIP2`/`BZIP` never leak in.
    pub env: Vec<(&'a str, &'a str)>,
    /// Byte identity of compressed output is promised. When false, stuffr's
    /// compressed outputs are instead round-tripped through the reference.
    pub compare_output_bytes: bool,
}

/// File bytes, mode (permission bits) and mtime (seconds).
pub type Tree = BTreeMap<String, (Vec<u8>, u32, i64)>;

pub struct Run {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub tree: Tree,
}

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

/// Run the reference tool `tool_dir/<name>`. `None` (after printing
/// `skipped: <tool> not installed`) when it is missing.
pub fn reference(tool_dir: &str, c: &Case) -> Option<Run> {
    let exe = Path::new(tool_dir).join(c.name);
    if !exe.exists() {
        eprintln!("skipped: {} not installed", c.name);
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

    let mut cmd = Command::new(exe);
    cmd.args(&c.args)
        .current_dir(&work)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .envs(c.env.iter().copied());

    let mut stdin_master = None;
    let mut stdout_master = None;
    if c.tty_stdin {
        let (m, sl) = openpty();
        cmd.stdin(Stdio::from(sl));
        stdin_master = Some(m);
    } else if c.stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    if c.tty_stdout {
        let (m, sl) = openpty();
        cmd.stdout(Stdio::from(sl));
        stdout_master = Some(m);
    } else {
        cmd.stdout(Stdio::piped());
    }
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {exe:?}: {e}"));
    drop(cmd); // closes our copies of the pty slaves

    let writer = if !c.tty_stdin {
        child.stdin.take().map(|mut si| {
            let data = c.stdin.clone().unwrap_or_default();
            std::thread::spawn(move || {
                let _ = si.write_all(&data); // child may exit early
            })
        })
    } else {
        None
    };
    let out_t = child.stdout.take().map(drain);
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
    if let Some(w) = writer {
        let _ = w.join();
    }
    let mut stdout = out_t.map(|t| t.join().unwrap()).unwrap_or_default();
    if let Some(m) = stdout_master {
        stdout = read_master(m);
    }
    drop(stdin_master);
    let stderr_raw = err_t.map(|t| t.join().unwrap()).unwrap_or_default();

    // The only normalisation: the program path becomes the bare name.
    let stderr = String::from_utf8_lossy(&stderr_raw).replace(exe.to_str().unwrap(), c.name);

    let code = status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(0));
    Run {
        code,
        stdout,
        stderr,
        tree: snapshot(&work),
    }
}

fn drain<R: Read + Send + 'static>(mut r: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = r.read_to_end(&mut v);
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
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    (m, s)
}

/// Everything the child wrote to the terminal, once all slaves are closed.
fn read_master(m: OwnedFd) -> Vec<u8> {
    let mut f = std::fs::File::from(m);
    let mut v = Vec::new();
    let mut buf = [0u8; 8192];
    // Linux reports EIO at hang-up, macOS reports 0; both end the loop.
    while let Ok(n) = f.read(&mut buf) {
        if n == 0 {
            break;
        }
        v.extend_from_slice(&buf[..n]);
    }
    v
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
            t.insert(rel, (fs::read(&p).unwrap(), mode, md.mtime()));
        }
    }
}

fn is_bz2_name(n: &str) -> bool {
    n.ends_with(".bz2") || n.ends_with(".tbz2") || n.ends_with(".tbz")
}

/// Decompress with the reference `bzip2 -dc`; `Err` carries its stderr.
fn ref_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
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
            .stdin
            .clone()
            .unwrap_or_else(|| c.files.iter().flat_map(|(_, b)| b.clone()).collect());
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
    let names: std::collections::BTreeSet<&String> = r.tree.keys().chain(s.tree.keys()).collect();
    for n in names {
        match (r.tree.get(n), s.tree.get(n)) {
            (Some(_), None) => d.push(format!("tree: {n} exists in reference only")),
            (None, Some(_)) => d.push(format!("tree: {n} exists in stuffr only")),
            (Some((rb, rm, rt)), Some((sb, sm, st))) => {
                if rm != sm {
                    d.push(format!("tree: {n} mode reference {rm:o} vs stuffr {sm:o}"));
                }
                if rt != st {
                    d.push(format!("tree: {n} mtime reference {rt} vs stuffr {st}"));
                }
                if rb == sb {
                    continue;
                }
                if !c.compare_output_bytes && is_bz2_name(n) {
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
