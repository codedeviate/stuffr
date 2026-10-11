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

/// Apple's gzip (one program; the invoked name sets the mode).
pub const APPLE_GZIP_DIR: &str = "/usr/bin";

/// GNU gzip's directory on this platform: Linux `/usr/bin`, macOS the
/// keg-only Homebrew install (never `brew link`ed; addressed by path).
pub fn gnu_gzip_dir() -> &'static str {
    if cfg!(target_os = "macos") {
        "/opt/homebrew/opt/gzip/bin"
    } else {
        "/usr/bin"
    }
}

/// The installed GNU gzip's `(major, minor)`, parsed from the last word of
/// `gzip --version`'s first line (`gzip 1.12`). `None` when the binary is
/// absent or the line does not parse.
pub fn gnu_gzip_version() -> Option<(u32, u32)> {
    let exe = Path::new(gnu_gzip_dir()).join("gzip");
    let out = Command::new(exe)
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let word = text.lines().next()?.split_whitespace().last()?.to_owned();
    let mut it = word.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    Some((major, minor))
}

const XZ_VERSION_LINE: &str = "XZ_VERSION=50080042";
const XZ_LINKS: [&str; 5] = ["unxz", "xzcat", "lzma", "unlzma", "lzcat"];

/// Whether `<dir>/xz --robot --version` says it is XZ Utils 5.8.4.
fn is_xz_5_8_4(dir: &Path) -> bool {
    Command::new(dir.join("xz"))
        .args(["--robot", "--version"])
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains(XZ_VERSION_LINE))
}

/// A directory holding `xz` and its five links. `xz` itself is `exe`; when
/// the links are not all beside it (a bare binary), they are made, as
/// symlinks to it, in a temporary directory that lives as long as the test
/// process's temp dir (a few inodes; never removed).
fn dir_with_links(exe: &Path) -> Option<PathBuf> {
    let parent = exe.parent()?;
    if XZ_LINKS.iter().all(|l| parent.join(l).exists()) {
        return Some(parent.to_path_buf());
    }
    let dir = std::env::temp_dir().join(format!("stuffr-xz-links-{}", std::process::id()));
    fs::create_dir_all(&dir).ok()?;
    let target = fs::canonicalize(exe).ok()?;
    for name in std::iter::once("xz").chain(XZ_LINKS) {
        let l = dir.join(name);
        let _ = fs::remove_file(&l);
        std::os::unix::fs::symlink(&target, &l).ok()?;
    }
    Some(dir)
}

/// `xz` on `PATH`, like a shell's lookup.
fn xz_on_path() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("xz"))
        .find(|p| p.is_file())
}

/// The directory holding XZ Utils 5.8.4's `xz` and its links `unxz`,
/// `xzcat`, `lzma`, `unlzma` and `lzcat`.
///
/// Looked up in this order, the first one that is exactly 5.8.4 (`xz
/// --robot --version` prints `XZ_VERSION=50080042`) winning:
/// 1. `$STUFFR_XZ_REFERENCE`, the path of an `xz` (CI builds the release
///    tarball there; `make install` puts the five links beside it, and if
///    they are absent they are made in a temp dir);
/// 2. Homebrew's keg, `/opt/homebrew/opt/xz/bin`;
/// 3. `xz` on `PATH`.
///
/// `None` when there is none: a skip with a note locally, a panic under `CI`
/// (the rule of [`require_reference`]), so every test that skips on it would
/// otherwise pass vacuously. A tool of another release is no reference:
/// stuffr promises 5.8.4's bytes.
pub fn xz_dir() -> Option<&'static str> {
    static DIR: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let found = DIR.get_or_init(|| {
        let candidates = [
            std::env::var_os("STUFFR_XZ_REFERENCE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            Some(PathBuf::from("/opt/homebrew/opt/xz/bin/xz")),
            xz_on_path(),
        ];
        for exe in candidates.into_iter().flatten() {
            if !exe.is_file() {
                continue;
            }
            let Some(dir) = dir_with_links(&exe) else {
                continue;
            };
            if is_xz_5_8_4(&dir) {
                return dir.to_str().map(str::to_owned);
            }
        }
        None
    });
    match found {
        Some(d) => Some(d.as_str()),
        None => {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI is set but there is no XZ Utils 5.8.4 reference (looked at \
                 $STUFFR_XZ_REFERENCE, /opt/homebrew/opt/xz/bin, PATH)"
            );
            eprintln!("skipped: XZ Utils 5.8.4 not installed");
            None
        }
    }
}

/// Whether `s` is an xz elapsed time: `m:ss` or `h:mm:ss`.
fn is_xz_elapsed(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    let digits = |p: &str, n: Option<usize>| {
        !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && n.is_none_or(|n| p.len() == n)
    };
    match parts.as_slice() {
        [m, ss] => digits(m, None) && digits(ss, Some(2)),
        [h, mm, ss] => digits(h, None) && digits(mm, Some(2)) && digits(ss, Some(2)),
        _ => false,
    }
}

/// Whether `s` is an xz speed: `123 KiB/s`, `1.2 MiB/s` (K, M or G).
fn is_xz_speed(s: &str) -> bool {
    let Some((num, unit)) = s.split_once(' ') else {
        return false;
    };
    matches!(unit, "KiB/s" | "MiB/s" | "GiB/s")
        && !num.is_empty()
        && num.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && num.bytes().filter(|&b| b == b'.').count() <= 1
        && !num.starts_with('.')
        && !num.ends_with('.')
}

/// Split a progress line after the `= 0.611` ratio of its size block
/// (`<n> <unit> / <n> <unit> = <ratio>`). `None` when `line` has no such
/// block.
fn split_after_ratio(line: &str) -> Option<(&str, &str)> {
    let eq = line.find(" = ")?;
    if !line[..eq].contains(" / ") {
        return None;
    }
    let after = &line[eq + 3..];
    let end = after
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(after.len());
    let ratio = &after[..end];
    let ok = ratio.len() >= 2 && ratio.bytes().filter(|&b| b == b'.').count() == 1;
    ok.then(|| line.split_at(eq + 3 + end))
}

/// Replace the speed and elapsed-time fields of xz's `-v` progress lines
/// with `<speed>` and `<elapsed>`, and nothing else: they are the only part
/// of xz's output that depends on how fast the run was.
///
/// Both shapes of the final line are covered:
/// - stderr not a terminal (what the differential suite sees):
///   `name: 19.1 MiB / 19.1 MiB = 1.000, 3.9 MiB/s, 0:04`, the speed present
///   from 3 s and the time from 1 s (`message.c` `progress_flush`);
/// - the terminal format, `\r 100 %   1,234 B / 300.0 KiB = 0.004
///   1.2 MiB/s   0:00`, whose column padding follows the speed's width, so
///   its blanks are collapsed.
///
/// A line is touched only if it carries a size block (`a / b = ratio`) and
/// the field's whole text has xz's exact shape; the sizes, the ratio, the
/// name and every other line stay as they are.
pub fn normalise_xz_progress(stderr: &str) -> String {
    let mut out = String::with_capacity(stderr.len());
    for line in stderr.split_inclusive('\n') {
        let (body, nl) = match line.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (line, ""),
        };
        let Some((head, tail)) = split_after_ratio(body) else {
            out.push_str(line);
            continue;
        };
        out.push_str(head);
        if let Some(fields) = tail.strip_prefix(", ") {
            // Non-terminal: `, <speed>`, `, <elapsed>`, `, <speed>, <elapsed>`.
            let fs: Vec<&str> = fields.split(", ").collect();
            let ok = match fs.as_slice() {
                [t] => is_xz_elapsed(t),
                [s, t] => is_xz_speed(s) && is_xz_elapsed(t),
                _ => false,
            };
            if ok {
                for f in fs {
                    out.push_str(", ");
                    out.push_str(if is_xz_elapsed(f) {
                        "<elapsed>"
                    } else {
                        "<speed>"
                    });
                }
            } else {
                out.push_str(tail);
            }
        } else if tail.starts_with(' ') {
            // Terminal: blanks, speed, blanks, time, blanks.
            let toks: Vec<&str> = tail.split_whitespace().collect();
            let mut mapped: Vec<&str> = Vec::new();
            let mut i = 0;
            let mut ok = true;
            while i < toks.len() {
                if i + 1 < toks.len() && is_xz_speed(&format!("{} {}", toks[i], toks[i + 1])) {
                    mapped.push("<speed>");
                    i += 2;
                } else if is_xz_elapsed(toks[i]) {
                    mapped.push("<elapsed>");
                    i += 1;
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                for m in mapped {
                    out.push(' ');
                    out.push_str(m);
                }
            } else {
                out.push_str(tail);
            }
        } else {
            out.push_str(tail);
        }
        out.push_str(nl);
    }
    out
}

/// How compressed output is judged when its bytes are not promised
/// identical, and which tool decodes it.
#[derive(Clone, Copy, Debug)]
pub enum Roundtrip {
    /// bzip2 streams (`BZh`, `.bz2`), decoded by the reference `bzip2 -dc`.
    Bzip2,
    /// gzip members (`1f 8b`, `.gz`/`.tgz`/`-S`), decoded by `ref_gzip -dc`
    /// (an absolute path). The header up to the end of FNAME is compared
    /// byte-for-byte.
    Gzip { ref_gzip: &'static str },
    /// xz streams (`fd 37 7a 58 5a 00`, `.xz`/`.txz`; `.lzma`/`.tlz` and raw
    /// by name or `-S`), decoded by `ref_xz -dc` (an absolute path), with
    /// `--format=lzma|raw` added as the case's arguments or invoked name
    /// ask. The stream header (magic, stream flags) is compared byte for
    /// byte.
    Xz { ref_xz: &'static str },
}

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
    /// Which compressed format the comparison understands.
    pub roundtrip: Roundtrip,
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
    ref_decompress_with(&Roundtrip::Bzip2, data)
}

/// Decompress with the reference tool `rt` names; `Err` carries its stderr.
pub fn ref_decompress_with(rt: &Roundtrip, data: &[u8]) -> Result<Vec<u8>, String> {
    ref_decompress_args(rt, &[], data)
}

/// Decompress for case `c`: as [`ref_decompress_with`], with the reference
/// told the stream format (and raw filter chain) `c` compressed with.
pub fn ref_decompress_case(c: &Case, data: &[u8]) -> Result<Vec<u8>, String> {
    let extra = match c.roundtrip {
        Roundtrip::Xz { .. } => xz_decode_args(c),
        _ => Vec::new(),
    };
    ref_decompress_args(&c.roundtrip, &extra, data)
}

/// The `xz -dc` options that make the reference read what `c` wrote: the
/// last `--format`/`-F` (else `lzma` when `c` is invoked as `lzma`, `unlzma`
/// or `lzcat`), and for `raw` the filter options of `c`, since a raw stream
/// carries no header to say which chain it is.
fn xz_decode_args(c: &Case) -> Vec<String> {
    const FILTERS: [&str; 9] = [
        "--lzma1",
        "--lzma2",
        "--delta",
        "--x86",
        "--arm",
        "--powerpc",
        "--ia64",
        "--sparc",
        "--riscv",
    ];
    let mut format: Option<String> = match c.name {
        "lzma" | "unlzma" | "lzcat" => Some("lzma".into()),
        _ => None,
    };
    let mut filters: Vec<String> = Vec::new();
    let mut it = c.args.iter();
    while let Some(a) = it.next() {
        if *a == "--" {
            break;
        }
        let value = if let Some(v) = a.strip_prefix("--format=") {
            Some(v.to_owned())
        } else if *a == "--format" || *a == "-F" {
            it.next().map(|v| (*v).to_owned())
        } else {
            a.strip_prefix("-F")
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        if let Some(v) = value {
            format = Some(v);
        } else if FILTERS.iter().any(|f| a.starts_with(f)) {
            filters.push((*a).to_owned());
        }
    }
    let mut v = Vec::new();
    match format.as_deref() {
        Some("lzma" | "alone") => v.push("--format=lzma".to_owned()),
        Some("raw") => {
            v.push("--format=raw".to_owned());
            v.extend(filters);
        }
        _ => {}
    }
    v
}

fn ref_decompress_args(rt: &Roundtrip, extra: &[String], data: &[u8]) -> Result<Vec<u8>, String> {
    let (exe, what) = match rt {
        Roundtrip::Bzip2 => (Path::new(REFERENCE_DIR).join("bzip2"), "bzip2"),
        Roundtrip::Gzip { ref_gzip } => (PathBuf::from(ref_gzip), "gzip"),
        Roundtrip::Xz { ref_xz } => (PathBuf::from(ref_xz), "xz"),
    };
    let mut child = Command::new(exe)
        .arg("-dc")
        .args(extra)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run reference {what}: {e}"))?;
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

/// Whether `b` opens with the compressed-stream magic of `rt`.
fn has_magic(rt: &Roundtrip, b: &[u8]) -> bool {
    match rt {
        Roundtrip::Bzip2 => b.starts_with(b"BZh"),
        Roundtrip::Gzip { .. } => b.starts_with(&[0x1f, 0x8b]),
        Roundtrip::Xz { .. } => b.starts_with(&XZ_MAGIC),
    }
}

/// The magic of an `.xz` stream header. `.lzma` and raw streams have none:
/// they are recognised by name (`is_compressed_name`) only.
const XZ_MAGIC: [u8; 6] = [0xfd, b'7', b'z', b'X', b'Z', 0];

/// The `-S`/`--suffix` operand of `args`, if any: `-S X`, `-SX`, `--suffix X`,
/// `--suffix=X` (or an abbreviation, `--su=X`), and `S` inside a short cluster
/// (`-kS .z`, `-kS.z`). A cluster's `b` takes the rest of it as its own
/// operand, so an `S` after it is not an option. Options after `--` are
/// operands and do not count. When several are given the last wins, as in
/// both references.
pub fn gzip_custom_suffix<'a>(args: &[&'a str]) -> Option<&'a str> {
    let mut found = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if *a == "--" {
            break;
        }
        // `--suffix` or any unambiguous abbreviation of it (`--su`), with
        // its operand inline or next.
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            if name.len() >= 2 && "suffix".starts_with(name) {
                found = inline.or_else(|| it.next().copied()).or(found);
            }
            continue;
        }
        let Some(cluster) = a.strip_prefix('-').filter(|c| !c.starts_with('-')) else {
            continue;
        };
        for (i, ch) in cluster.char_indices() {
            match ch {
                'S' => {
                    let rest = &cluster[i + 1..];
                    found = if rest.is_empty() {
                        it.next().copied().or(found)
                    } else {
                        Some(rest)
                    };
                    break;
                }
                // `-b N`: the rest of the cluster (or the next word) is N.
                'b' => {
                    if i + 1 == cluster.len() {
                        it.next();
                    }
                    break;
                }
                _ => {}
            }
        }
    }
    found
}

/// The suffix case `c` compresses with: `-S` in its arguments, or in
/// `$GZIP`, whose words come first (Apple's `prepend_gzip`).
fn case_suffix<'a>(c: &Case<'a>) -> Option<&'a str> {
    let mut words: Vec<&'a str> = c
        .env
        .iter()
        .filter(|(k, _)| *k == "GZIP")
        .flat_map(|(_, v)| v.split([' ', '\t']).filter(|w| !w.is_empty()))
        .collect();
    words.extend(c.args.iter().copied());
    gzip_custom_suffix(&words)
}

/// Whether tree entry `n` is a compressed output of this case.
fn is_compressed_name(c: &Case, n: &str) -> bool {
    match c.roundtrip {
        Roundtrip::Bzip2 => is_bz2_name(n),
        Roundtrip::Gzip { .. } => {
            n.ends_with(".gz")
                || n.ends_with(".tgz")
                || case_suffix(c).is_some_and(|s| !s.is_empty() && n.ends_with(s))
        }
        Roundtrip::Xz { .. } => {
            [".xz", ".txz", ".lzma", ".tlz"]
                .iter()
                .any(|s| n.ends_with(s))
                || gzip_custom_suffix(&c.args).is_some_and(|s| !s.is_empty() && n.ends_with(s))
        }
    }
}

/// Length of the gzip header through the end of FNAME (the NUL included), or
/// of the fixed 10 bytes plus FEXTRA when there is no FNAME. `None` when the
/// bytes are not a well-formed gzip header that far.
fn gzip_header_through_fname(b: &[u8]) -> Option<usize> {
    if b.len() < 10 || b[0] != 0x1f || b[1] != 0x8b {
        return None;
    }
    let flg = b[3];
    let mut at = 10;
    if flg & 0x04 != 0 {
        let xlen = u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]) as usize;
        at += 2 + xlen;
        if at > b.len() {
            return None;
        }
    }
    if flg & 0x08 != 0 {
        let nul = b.get(at..)?.iter().position(|&x| x == 0)?;
        at += nul + 1;
    }
    Some(at)
}

/// Difference in the gzip header up to the end of FNAME, if any.
fn gzip_header_mismatch(reference: &[u8], ours: &[u8]) -> Option<String> {
    let (rl, sl) = (
        gzip_header_through_fname(reference),
        gzip_header_through_fname(ours),
    );
    match (rl, sl) {
        (Some(rl), Some(sl)) if reference[..rl] == ours[..sl] => None,
        (Some(rl), Some(sl)) => Some(format!(
            "gzip header (through FNAME) differs:\n    reference: {}\n    stuffr:    {}",
            describe_bytes(&reference[..rl]),
            describe_bytes(&ours[..sl])
        )),
        _ => Some(format!(
            "gzip header (through FNAME) unreadable: reference {}, stuffr {}",
            if rl.is_some() { "ok" } else { "malformed" },
            if sl.is_some() { "ok" } else { "malformed" }
        )),
    }
}

/// The original a compressed output named `name` should decompress to.
fn original_for(c: &Case, name: &str) -> Option<Vec<u8>> {
    let base = match c.roundtrip {
        Roundtrip::Bzip2 => name.strip_suffix(".bz2").map(str::to_owned).or_else(|| {
            name.strip_suffix(".tbz2")
                .or(name.strip_suffix(".tbz"))
                .map(|b| format!("{b}.tar"))
        })?,
        Roundtrip::Gzip { .. } => name
            .strip_suffix(".gz")
            .map(str::to_owned)
            .or_else(|| name.strip_suffix(".tgz").map(|b| format!("{b}.tar")))
            .or_else(|| {
                case_suffix(c)
                    .filter(|s| !s.is_empty())
                    .and_then(|s| name.strip_suffix(s))
                    .map(str::to_owned)
            })?,
        Roundtrip::Xz { .. } => name
            .strip_suffix(".xz")
            .or_else(|| name.strip_suffix(".lzma"))
            .map(str::to_owned)
            .or_else(|| {
                name.strip_suffix(".txz")
                    .or_else(|| name.strip_suffix(".tlz"))
                    .map(|b| format!("{b}.tar"))
            })
            .or_else(|| {
                gzip_custom_suffix(&c.args)
                    .filter(|s| !s.is_empty())
                    .and_then(|s| name.strip_suffix(s))
                    .map(str::to_owned)
            })?,
    };
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

fn tool_name(rt: &Roundtrip) -> &'static str {
    match rt {
        Roundtrip::Bzip2 => "bzip2",
        Roundtrip::Gzip { .. } => "gzip",
        Roundtrip::Xz { .. } => "xz",
    }
}

/// The format-specific part of comparing two compressed streams whose bytes
/// are not promised identical: bzip2's block-size digit, or gzip's header
/// through FNAME.
fn stream_mismatch(rt: &Roundtrip, reference: &[u8], ours: &[u8]) -> Option<String> {
    match rt {
        Roundtrip::Bzip2 => block_digit_mismatch(reference, ours),
        Roundtrip::Gzip { .. } => gzip_header_mismatch(reference, ours),
        Roundtrip::Xz { .. } => xz_header_mismatch(reference, ours),
    }
}

/// Difference in an `.xz` stream header's magic and stream flags (the first
/// eight bytes: they carry the check type), if both are `.xz` streams. The
/// header's CRC32 follows from them, so it is not compared.
fn xz_header_mismatch(reference: &[u8], ours: &[u8]) -> Option<String> {
    if !(reference.starts_with(&XZ_MAGIC) && ours.starts_with(&XZ_MAGIC)) {
        return None;
    }
    let (r, s) = (reference.get(..8)?, ours.get(..8)?);
    (r != s).then(|| {
        format!(
            "xz stream header differs:\n    reference: {}\n    stuffr:    {}",
            describe_bytes(r),
            describe_bytes(s)
        )
    })
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
    if c.compare_output_bytes || !has_magic(&c.roundtrip, &s.stdout) {
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
        if let Some(e) = stream_mismatch(&c.roundtrip, &r.stdout, &s.stdout) {
            d.push(format!("stdout {e}"));
        }
        match ref_decompress_case(c, &s.stdout) {
            Ok(got) if got == want => {}
            Ok(got) => d.push(format!(
                "stdout round-trip mismatch: want {}, got {}",
                describe_bytes(&want),
                describe_bytes(&got)
            )),
            Err(e) => d.push(format!(
                "reference {} rejects stuffr's stdout: {e}",
                tool_name(&c.roundtrip)
            )),
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
                if !c.compare_output_bytes
                    && (is_compressed_name(c, n) || has_magic(&c.roundtrip, sb))
                {
                    if let Some(e) = stream_mismatch(&c.roundtrip, rb, sb) {
                        d.push(format!("tree: {n} {e}"));
                    }
                    match (ref_decompress_case(c, sb), original_for(c, n)) {
                        (Ok(got), Some(want)) if got == want => {}
                        (Ok(got), Some(want)) => d.push(format!(
                            "tree: {n} round-trip mismatch: want {}, got {}",
                            describe_bytes(&want),
                            describe_bytes(&got)
                        )),
                        (Ok(_), None) => d.push(format!(
                            "tree: {n} decompresses but its original is unknown"
                        )),
                        (Err(e), _) => d.push(format!(
                            "tree: reference {} rejects stuffr's {n}: {e}",
                            tool_name(&c.roundtrip)
                        )),
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

// ---- peak memory of a streaming decoder ----

/// Run stuffr as `name` on `file` (written with `input`) in a scratch
/// directory, with only `env` in the environment; check it exits 0 having
/// printed exactly `plain` and nothing on standard error; return its peak
/// memory in bytes. Shared by 0.11.0's `bzcat_streams_a_large_input` and
/// 0.12.0's `zcat_streams_a_large_input` (Ruling P6).
///
/// - **Linux:** the largest `RssAnon` in `/proc/<pid>/status`, sampled
///   every 5 ms, counting only samples taken once `/proc/<pid>/exe` is the
///   stuffr binary. Not `getrusage`: there a child's `ru_maxrss` includes
///   the parent's resident set at spawn, and this test process holds the
///   64 MiB input and its copies (CI measured 264-268 MiB). Not `VmHWM`
///   either: it also counts file-backed pages, the touched part of a debug
///   binary of hundreds of MiB among them (CI measured 220-233 MiB). The
///   claim under test is that the decoder holds neither the input nor the
///   output, which is anonymous memory, flat after the first block, so
///   sampling loses nothing. Before the exec completes `/proc/<pid>` can
///   still describe the spawning test process (CI measured 155 MiB of
///   RssAnon that way). The status at the peak and a timeline are printed.
/// - **Elsewhere:** `getrusage(RUSAGE_CHILDREN)`'s `ru_maxrss`, the largest
///   child this process has waited for (bytes on macOS, which spawns
///   without copying the parent, so the figure is the child's own).
pub fn decoder_peak_rss(
    name: &str,
    file: &str,
    input: &[u8],
    plain: &[u8],
    env: &[(&str, &str)],
) -> u64 {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "stuffr-rss-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("bin")).unwrap();
    let link = dir.join("bin").join(name);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
    fs::write(dir.join(file), input).unwrap();
    let mut child = Command::new(&link)
        .arg(file)
        .current_dir(&dir)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut v = Vec::new();
        out.read_to_end(&mut v).unwrap();
        v
    });
    #[cfg(target_os = "linux")]
    let peak = linux_rss_anon_peak(&mut child);
    let st = child.wait().unwrap();
    let got = reader.join().unwrap();
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    let _ = fs::remove_dir_all(&dir);
    assert!(st.success(), "{st:?}: {err}");
    assert_eq!(err, "");
    assert!(got == plain, "decoded output differs");
    #[cfg(not(target_os = "linux"))]
    let peak = {
        // SAFETY: `ru` is a valid out-pointer; getrusage only writes it.
        let ru = unsafe {
            let mut ru: libc::rusage = std::mem::zeroed();
            assert_eq!(libc::getrusage(libc::RUSAGE_CHILDREN, &mut ru), 0);
            ru
        };
        let peak = ru.ru_maxrss as u64;
        eprintln!("peak child RSS: {:.1} MiB", peak as f64 / 1048576.0);
        peak
    };
    peak
}

/// The sampling loop of [`decoder_peak_rss`] on Linux: until `child`
/// exits, the largest `RssAnon` seen while it is stuffr.
#[cfg(target_os = "linux")]
fn linux_rss_anon_peak(child: &mut std::process::Child) -> u64 {
    let status = format!("/proc/{}/status", child.id());
    let exe_link = format!("/proc/{}/exe", child.id());
    let stuffr_exe = fs::canonicalize(env!("CARGO_BIN_EXE_stuffr")).unwrap();
    let mut peak = 0u64;
    let mut at_peak = String::new();
    let mut timeline = Vec::new();
    let t0 = Instant::now();
    while child.try_wait().unwrap().is_none() {
        let is_stuffr = fs::read_link(&exe_link).is_ok_and(|e| e == stuffr_exe);
        if let Ok(s) = fs::read_to_string(&status)
            && let Some(kb) = s
                .lines()
                .find_map(|l| l.strip_prefix("RssAnon:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        {
            if timeline.len() < 40 {
                timeline.push(format!(
                    "{}ms:{}{}k",
                    t0.elapsed().as_millis(),
                    if is_stuffr { "" } else { "(not stuffr)" },
                    kb
                ));
            }
            if is_stuffr && kb * 1024 > peak {
                peak = kb * 1024;
                at_peak = s
                    .lines()
                    .filter(|l| {
                        l.starts_with("Name") || l.starts_with("Vm") || l.starts_with("Rss")
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    eprintln!("RssAnon timeline: {}", timeline.join(" "));
    assert!(
        peak > 0,
        "RssAnon was never sampled while the process was stuffr"
    );
    eprintln!("/proc status at the peak: {at_peak}");
    eprintln!("peak RssAnon: {:.1} MiB", peak as f64 / 1048576.0);
    peak
}

// ---- deterministic test data (no RNG dependency) ----

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// `n` pseudo-random bytes from `seed` (nonzero).
pub fn random(n: usize, seed: u64) -> Vec<u8> {
    let mut r = XorShift(seed);
    (0..n).map(|_| (r.next() >> 24) as u8).collect()
}

const WORDS: &[&str] = &[
    "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "stuffr", "gzip", "member",
    "deflate", "header", "and", "of", "a", "to", "in", "file",
];

/// Plain text: words, spaces and newlines only (safe to type at a tty).
pub fn text(n: usize, seed: u64) -> Vec<u8> {
    let mut r = XorShift(seed);
    let mut v = Vec::with_capacity(n + 16);
    while v.len() < n {
        v.extend_from_slice(WORDS[(r.next() % WORDS.len() as u64) as usize].as_bytes());
        v.push(if r.next().is_multiple_of(9) {
            b'\n'
        } else {
            b' '
        });
    }
    v.truncate(n);
    v
}

/// Text interleaved with runs of random bytes and long repeats.
pub fn mixed(n: usize, seed: u64) -> Vec<u8> {
    let mut r = XorShift(seed);
    let mut v = Vec::with_capacity(n + 4096);
    while v.len() < n {
        match r.next() % 3 {
            0 => v.extend(text(2048, r.next())),
            1 => v.extend(random(512, r.next() | 1)),
            _ => v.extend(std::iter::repeat_n(b'z', (r.next() % 3000) as usize)),
        }
    }
    v.truncate(n);
    v
}

/// A short period repeated to `n` bytes.
pub fn repetitive(n: usize) -> Vec<u8> {
    b"abcabcabd".iter().copied().cycle().take(n).collect()
}

// ---- running a group of differential cases ----

/// Cases left out on this reference, and why: counted as known oracle
/// skips by [`run_group`].
pub struct Skipped {
    pub count: usize,
    pub why: String,
}

impl Skipped {
    pub fn none() -> Self {
        Skipped {
            count: 0,
            why: String::new(),
        }
    }

    /// Record `n` more skipped cases, for `why`.
    pub fn add(&mut self, n: usize, why: &str) {
        self.count += n;
        if !self.why.is_empty() {
            self.why.push_str("; ");
        }
        self.why.push_str(why);
    }
}

/// The text of a caught panic.
pub fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Run `one` over every case, a few at a time, and fail once listing every
/// case that differed (`one` panics with the differences, or returns false
/// when the reference is absent). Prints "N of M cases compared" (M
/// includes the known oracle skips, which are named); on CI every case not
/// skipped for a known reason must have run.
pub fn run_group(
    group: &str,
    cases: &[Case],
    skipped: Skipped,
    one: &(dyn Fn(&Case) -> bool + Sync),
) {
    let run_one = |c: &Case| -> Result<bool, String> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| one(c))).map_err(panic_text)
    };
    let workers = std::thread::available_parallelism().map_or(2, |n| n.get().min(8));
    let next = AtomicUsize::new(0);
    let mut results: Vec<(usize, Result<bool, String>)> = std::thread::scope(|sc| {
        let hs: Vec<_> = (0..workers)
            .map(|_| {
                sc.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(c) = cases.get(i) else { break out };
                        out.push((i, run_one(c)));
                    }
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    results.sort_by_key(|(i, _)| *i);
    let mut failures = Vec::new();
    let mut ran = 0;
    for (_, r) in results {
        match r {
            Ok(true) => ran += 1,
            Ok(false) => {}
            Err(p) => failures.push(p),
        }
    }
    let total = cases.len() + skipped.count;
    if skipped.count > 0 {
        println!(
            "{group}: {ran} of {total} cases compared, {} skipped: {}",
            skipped.count, skipped.why
        );
    } else {
        println!("{group}: {ran} of {total} cases compared");
    }
    if std::env::var_os("CI").is_some() {
        assert_eq!(
            ran,
            cases.len(),
            "{group}: CI is set but only {ran} of {} cases were compared",
            cases.len()
        );
    }
    assert!(
        failures.is_empty(),
        "{group}: {} of {} cases differ:\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

// ---- Apple's gzip ----

/// The Apple gzip release the BSD personality reproduces: what its usage
/// text and `-V` print.
pub const APPLE_GZIP_VERSION_LINE: &str = "Apple gzip 487.0.1";

/// The installed Apple gzip's `-V` line (on standard error), `None` when
/// it is absent.
pub fn apple_gzip_version_line() -> Option<&'static str> {
    static V: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        let out = Command::new(Path::new(APPLE_GZIP_DIR).join("gzip"))
            .arg("-V")
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stderr).into_owned();
        text.lines().next().map(str::to_owned)
    })
    .as_deref()
}

/// The length of an Apple `print_ratio` token (`%5s%%`: spaces, an
/// optional `-`, digits, `.`, one digit, `%`) at the start of `b`.
fn apple_ratio_at(b: &[u8]) -> Option<usize> {
    let mut i = b.iter().take_while(|&&c| c == b' ').count();
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    let d = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
    if d == 0 {
        return None;
    }
    i += d;
    (b.get(i) == Some(&b'.')
        && b.get(i + 1).is_some_and(u8::is_ascii_digit)
        && b.get(i + 2) == Some(&b'%'))
    .then_some(i + 3)
}

/// Blank Apple's `-v` ratios, which count compressed bytes: at a line's
/// start (standard input's line) and after `name:\t\t  ` or `name:\t  `.
/// Everything else in the line is kept.
pub fn blank_apple_ratios(s: &str) -> String {
    s.split_inclusive('\n')
        .map(|line| {
            let at = line.find(":\t").map(|i| {
                let tabs = line[i + 1..].bytes().take_while(|&b| b == b'\t').count();
                i + 1 + tabs
            });
            let start = at.unwrap_or(0);
            match apple_ratio_at(&line.as_bytes()[start..]) {
                Some(n) => format!("{}<ratio>{}", &line[..start], &line[start + n..]),
                None => line.to_owned(),
            }
        })
        .collect()
}

/// Apple's gzip stores the current time for standard input that is not a
/// regular file. Where both runs' standard output hold a member header at
/// the same offset whose times differ, each within its own run's
/// wall-clock window, take the reference's time, so the rest is compared
/// byte for byte (on the compatible tier only the first member's header is
/// compared, at offset 0, which this covers).
pub fn mask_stdin_mtimes(r: &Run, s: &mut Run) {
    let now = now_secs();
    let within = |t: u32, start: i64| (start - 2..=now + 2).contains(&i64::from(t));
    let n = r.stdout.len().min(s.stdout.len());
    let magic = [0x1f, 0x8b, 0x08];
    let mut k = 0;
    while k + 8 <= n {
        if r.stdout[k..k + 3] == magic && s.stdout[k..k + 3] == magic {
            let t = |b: &[u8]| u32::from_le_bytes([b[k + 4], b[k + 5], b[k + 6], b[k + 7]]);
            let (rt, st) = (t(&r.stdout), t(&s.stdout));
            if rt != st && within(rt, r.start) && within(st, s.start) {
                s.stdout[k + 4..k + 8].copy_from_slice(&r.stdout[k + 4..k + 8]);
            }
        }
        k += 1;
    }
}

/// Run case `c` against Apple's gzip and stuffr and compare (panicking
/// with every difference). Normalised first, and nothing else:
///
/// - the installed reference's version line becomes
///   [`APPLE_GZIP_VERSION_LINE`] when another macOS ships another release,
///   so its usage text is still compared;
/// - stuffr's `-V`/`-L` first line names stuffr (Ruling T9-1): `Apple gzip
///   (stuffr X) 487.0.1` is read as `Apple gzip 487.0.1`, the rest compared;
/// - standard input's stored time ([`mask_stdin_mtimes`]);
/// - on the compatible tier only (`!c.compare_output_bytes`), `-v`'s
///   ratios (Ruling T9-2).
///
/// When the installed release is not [`APPLE_GZIP_VERSION_LINE`]'s, each
/// difference is prefixed with both releases.
///
/// False when the reference is absent (skip; panics instead under `CI`).
pub fn apple_compare(c: &Case) -> bool {
    let Some(mut r) = reference(APPLE_GZIP_DIR, c) else {
        return false;
    };
    let mut s = stuffr_as(c);
    if let Some(line) = apple_gzip_version_line()
        && line != APPLE_GZIP_VERSION_LINE
        && line.starts_with("Apple gzip ")
    {
        r.stderr = r.stderr.replace(line, APPLE_GZIP_VERSION_LINE);
    }
    let ours = format!("Apple gzip (stuffr {}) ", env!("CARGO_PKG_VERSION"));
    if s.stderr.contains(&ours) {
        assert!(
            r.stderr.contains(APPLE_GZIP_VERSION_LINE),
            "stuffr printed its version line, the reference {:?}",
            r.stderr
        );
        s.stderr = s.stderr.replacen(&ours, "Apple gzip ", 1);
    }
    mask_stdin_mtimes(&r, &mut s);
    if !c.compare_output_bytes {
        r.stderr = blank_apple_ratios(&r.stderr);
        s.stderr = blank_apple_ratios(&s.stderr);
    }
    // Another release on this macOS: every difference says so, since it
    // may be the release's and not stuffr's.
    match apple_gzip_version_line().filter(|l| *l != APPLE_GZIP_VERSION_LINE) {
        None => assert_same(c, &r, &s),
        Some(release) => {
            let same = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_same(c, &r, &s);
            }));
            if let Err(p) = same {
                panic!(
                    "[the reference is {release}; this suite targets {APPLE_GZIP_VERSION_LINE}, \
                     so this difference may be the release's]\n{}",
                    panic_text(p)
                );
            }
        }
    }
    true
}

// ---- gzip-family fixtures, built here so both sides read the same bytes ----

/// A gzip member's header fields; `magic2` is `0x8b`, or `0x9e` for the
/// old magic.
#[derive(Clone, Copy)]
pub struct Member<'b> {
    pub data: &'b [u8],
    pub name: Option<&'b [u8]>,
    pub mtime: u32,
    pub extra: Option<&'b [u8]>,
    pub comment: Option<&'b [u8]>,
    pub hcrc: bool,
    pub magic2: u8,
}

pub fn plain_member(data: &[u8]) -> Member<'_> {
    Member {
        data,
        name: None,
        mtime: 0,
        extra: None,
        comment: None,
        hcrc: false,
        magic2: 0x8b,
    }
}

pub fn crc32(b: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(b);
    c.sum()
}

pub fn deflate_raw(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// One member, the header written by hand (RFC 1952) over flate2's raw
/// deflate; `crc`/`isize` override the trailer.
pub fn member_with(m: Member, crc: Option<u32>, isize: Option<u32>) -> Vec<u8> {
    let mut flg = 0u8;
    for (on, bit) in [
        (m.hcrc, 2),
        (m.extra.is_some(), 4),
        (m.name.is_some(), 8),
        (m.comment.is_some(), 16),
    ] {
        if on {
            flg |= bit;
        }
    }
    let mut v = vec![0x1f, m.magic2, 8, flg];
    v.extend_from_slice(&m.mtime.to_le_bytes());
    v.extend_from_slice(&[0, 3]);
    if let Some(e) = m.extra {
        v.extend_from_slice(&(e.len() as u16).to_le_bytes());
        v.extend_from_slice(e);
    }
    for f in [m.name, m.comment].into_iter().flatten() {
        v.extend_from_slice(f);
        v.push(0);
    }
    if m.hcrc {
        let c = (crc32(&v) & 0xffff) as u16;
        v.extend_from_slice(&c.to_le_bytes());
    }
    v.extend(deflate_raw(m.data));
    v.extend_from_slice(&crc.unwrap_or_else(|| crc32(m.data)).to_le_bytes());
    v.extend_from_slice(&isize.unwrap_or(m.data.len() as u32).to_le_bytes());
    v
}

pub fn member(m: Member) -> Vec<u8> {
    member_with(m, None, None)
}

/// A member storing `name`.
pub fn gzm(data: &[u8], name: &[u8]) -> Vec<u8> {
    member(Member {
        name: Some(name),
        ..plain_member(data)
    })
}

/// The old Unix `pack` format: a canonical Huffman code in pack's
/// layout (level `i` holds codes of length `i + 1`, internal nodes take
/// a level's smallest codes, EOB is the last leaf), as
/// `stuffr-formats`' own `pack.rs` tests encode it.
pub fn pack(data: &[u8]) -> Vec<u8> {
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let mut syms: Vec<usize> = (0..256).filter(|&b| freq[b] > 0).collect();
    if syms.is_empty() {
        syms.push(0);
    }
    let n = syms.len() + 1;
    let mut w: Vec<u64> = syms.iter().map(|&b| freq[b]).collect();
    w.push(0);
    let mut parent = vec![usize::MAX; 2 * n];
    let mut live: Vec<usize> = (0..n).collect();
    while live.len() > 1 {
        live.sort_by_key(|&i| std::cmp::Reverse((w[i], i)));
        let a = live.pop().unwrap();
        let b = live.pop().unwrap();
        let p = w.len();
        w.push(w[a] + w[b]);
        parent[a] = p;
        parent[b] = p;
        live.push(p);
    }
    let len: Vec<usize> = (0..n)
        .map(|i| {
            let (mut d, mut c) = (0, i);
            while parent[c] != usize::MAX {
                c = parent[c];
                d += 1;
            }
            d
        })
        .collect();
    let maxlen = *len.iter().max().unwrap();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| (len[i], i == n - 1, i));
    let mut count = vec![0usize; maxlen];
    for &i in &order {
        count[len[i] - 1] += 1;
    }
    let mut inodes = vec![0u32; maxlen];
    for l in (0..maxlen - 1).rev() {
        inodes[l] = (inodes[l + 1] + count[l + 1] as u32) / 2;
    }
    let mut code = vec![0u32; n];
    let mut at = vec![0u32; maxlen];
    for &i in &order {
        let l = len[i] - 1;
        code[i] = inodes[l] + at[l];
        at[l] += 1;
    }
    let mut out = vec![0x1f, 0x1e];
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.push(maxlen as u8);
    for (l, &c) in count.iter().enumerate() {
        out.push(if l + 1 == maxlen { c - 2 } else { c } as u8);
    }
    for &i in &order {
        if i != n - 1 {
            out.push(syms[i] as u8);
        }
    }
    let mut pos = [usize::MAX; 256];
    for (k, &b) in syms.iter().enumerate() {
        pos[b] = k;
    }
    let (mut acc, mut nb) = (0u32, 0u32);
    let mut put = |c: u32, l: usize, out: &mut Vec<u8>| {
        for bit in (0..l).rev() {
            acc = (acc << 1) | ((c >> bit) & 1);
            nb += 1;
            if nb == 8 {
                out.push(acc as u8);
                acc = 0;
                nb = 0;
            }
        }
    };
    for &b in data {
        let k = pos[b as usize];
        put(code[k], len[k], &mut out);
    }
    put(code[n - 1], len[n - 1], &mut out);
    if nb > 0 {
        out.push((acc << (8 - nb)) as u8);
    }
    out
}

/// A zip entry: method 0 (stored) or 8 (deflated); any other method's
/// data is the plain bytes (GNU refuses those before reading). With
/// flag 8 the sizes and CRC follow in a signed data descriptor.
pub struct ZipEntry<'b> {
    pub name: &'b [u8],
    pub data: &'b [u8],
    pub method: u16,
    pub flags: u16,
}

pub fn zip(entries: &[ZipEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for e in entries {
        let body = if e.method == 8 {
            deflate_raw(e.data)
        } else {
            e.data.to_vec()
        };
        let crc = crc32(e.data);
        let dd = e.flags & 8 != 0;
        let offset = out.len() as u32;
        let (lcrc, lc, lu) = if dd {
            (0, 0, 0)
        } else {
            (crc, body.len() as u32, e.data.len() as u32)
        };
        out.extend_from_slice(b"PK\x03\x04");
        for v in [20u16, e.flags, e.method, 0, 0] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in [lcrc, lc, lu] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(e.name);
        out.extend_from_slice(&body);
        if dd {
            out.extend_from_slice(b"PK\x07\x08");
            for v in [crc, body.len() as u32, e.data.len() as u32] {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        central.extend_from_slice(b"PK\x01\x02");
        for v in [20u16, 20, e.flags, e.method, 0, 0] {
            central.extend_from_slice(&v.to_le_bytes());
        }
        for v in [crc, body.len() as u32, e.data.len() as u32] {
            central.extend_from_slice(&v.to_le_bytes());
        }
        for v in [e.name.len() as u16, 0, 0, 0, 0] {
            central.extend_from_slice(&v.to_le_bytes());
        }
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(e.name);
    }
    let cd_at = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend(central);
    out.extend_from_slice(b"PK\x05\x06");
    for v in [0u16, 0, entries.len() as u16, entries.len() as u16] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

pub fn zip1(data: &[u8], method: u16, flags: u16) -> Vec<u8> {
    zip(&[ZipEntry {
        name: b"plain",
        data,
        method,
        flags,
    }])
}

pub fn filter_through(exe: &str, args: &[&str], data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if !require_reference(Path::new(exe)) {
        return None;
    }
    let mut child = Command::new(exe)
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut si = child.stdin.take().unwrap();
    let d = data.to_vec();
    let w = std::thread::spawn(move || {
        let _ = si.write_all(&d);
    });
    let out = child.wait_with_output().unwrap();
    w.join().unwrap();
    assert!(out.status.success(), "{exe} {args:?}");
    Some(out.stdout)
}

/// `data` compressed by stuffr's own `id` codec (`bzip2`, `xz`, `lzip`,
/// `compress`), at `level` or the format's default: inputs for the foreign
/// formats a `gunzip` reads, with no tool beyond the reference needed.
pub fn stuffr_encode(id: &'static str, data: &[u8], level: Option<i32>) -> Vec<u8> {
    let codec = stuffr::registry()
        .codec(stuffr::FormatId::new(id))
        .unwrap_or_else(|| panic!("{id} is not in this build"));
    let buf = stuffr::testing::SharedBuf::new();
    let opts = stuffr::EncodeOpts {
        level,
        ..Default::default()
    };
    let mut sink = codec.encoder(Box::new(buf.clone()), &opts).unwrap();
    sink.write_all(data).unwrap();
    sink.finish().unwrap();
    buf.contents()
}
