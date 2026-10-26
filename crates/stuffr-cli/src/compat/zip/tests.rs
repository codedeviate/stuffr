//! Unit tests for the zip family's run: the flavour, the dispatch
//! through `run_in`, and the exit contract of a command line that gets past
//! the checks.

use std::ffi::OsString;

use super::*;

#[test]
fn the_default_flavour_follows_the_platform() {
    let apple = cfg!(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ));
    let want = if apple {
        Flavour::Apple
    } else {
        Flavour::Ubuntu
    };
    assert_eq!(default_flavour(), want);
}

/// `STUFFR_ZIP_FLAVOR` selects `apple` or `ubuntu`, unset or empty is the
/// default, and anything else (another case, a blank) is refused.
#[test]
fn the_flavour_variable_rejects_other_values() {
    let d = default_flavour();
    assert_eq!(flavour_from(None), Ok(d));
    assert_eq!(flavour_from(Some("".into())), Ok(d));
    assert_eq!(flavour_from(Some("apple".into())), Ok(Flavour::Apple));
    assert_eq!(flavour_from(Some("ubuntu".into())), Ok(Flavour::Ubuntu));
    for bad in ["Apple", "UBUNTU", " apple", "debian", "gnu"] {
        assert_eq!(flavour_from(Some(bad.into())), Err(bad.into()));
    }
}

fn go(name: &str, args: &[&str], stdin: &[u8]) -> (i32, String, String) {
    let dir = std::env::temp_dir();
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err) = run_in(&dir, name, args, stdin, Flavour::Apple);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// Each of the four names reaches its program.
#[test]
fn run_in_reaches_each_program() {
    for (name, header) in [
        ("zip", "Zip 3.0 (July 5th 2008), by stuffr "),
        ("zipcloak", "ZipCloak 3.0 (July 5th 2008), by stuffr "),
        ("zipnote", "ZipNote 3.0 (July 5th 2008), by stuffr "),
        ("zipsplit", "ZipSplit 3.0 (July 5th 2008), by stuffr "),
    ] {
        let (code, out, err) = go(name, &["-h"], b"");
        assert_eq!((code, err.as_str()), (0, ""), "{name}");
        assert!(out.contains(header), "{name}: {out}");
    }
    // a helper with no arguments shows its help, as zip's `-h`
    let (code, out, _) = go("zipnote", &[], b"");
    assert_eq!(code, 0);
    assert!(out.contains("Usage: \x20zipnote [-w] [-q] [-b path] zipfile"));
}

/// A sandbox has no terminal: zip with no arguments is a filter (no help),
/// and `-v` alone prints the version screen.
#[test]
fn a_sandbox_is_not_a_terminal() {
    // zip as a filter: standard input to standard output, a pipe (so a
    // data descriptor follows the data)
    let dir = std::env::temp_dir();
    let (code, out, err) = run_in(&dir, "zip", vec![], b"data", Flavour::Apple);
    assert_eq!(
        (code, err.as_slice()),
        (0, &b"  adding: - (deflated -49%)\n"[..])
    );
    assert!(out.starts_with(b"PK\x03\x04") && out.windows(4).any(|w| w == b"PK\x07\x08"));
    let (code, out, _) = go("zip", &["-v"], b"");
    assert_eq!(code, 0);
    assert!(out.contains("Zip special compilation options:"), "{out}");
}

#[test]
fn the_exit_codes_are_the_ziperr_ones() {
    for c in [
        0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19,
    ] {
        assert!(EXIT_CODES.contains(&c));
    }
    assert!(!EXIT_CODES.contains(&1));
    assert!(!EXIT_CODES.contains(&17));
}

/// `ziperr` of a code that says why the system refused prints that first.
#[test]
fn an_io_error_gets_the_zip_io_error_line() {
    let env = |_: &str| None;
    let mut err = Vec::new();
    let host = Host::Sandbox(Sandbox {
        dir: std::env::temp_dir(),
        stdin: None,
        stdout: Arc::default(),
        budget: Arc::new(AtomicU64::new(1 << 20)),
        reads: Arc::default(),
    });
    let mut z = Zr::new(host, Flavour::Apple, "zip", &env, &mut err);
    let e = io::Error::from_raw_os_error(2);
    assert_eq!(z.ziperr_os(18, b"nosuch", &e), Exit { code: 18 });
    let out = match &z.host {
        Host::Sandbox(s) => s.stdout.lock().unwrap().clone(),
        Host::Real => unreachable!(),
    };
    z.set_line(false);
    drop(z);
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "zip I/O error: No such file or directory\nzip error: File not found or no read permission (nosuch)\n"
    );
}

/// `asctime`'s shape, in UTC.
#[test]
fn asctime_is_c_asctime() {
    let host = Host::Sandbox(Sandbox {
        dir: std::env::temp_dir(),
        stdin: None,
        stdout: Arc::default(),
        budget: Arc::new(AtomicU64::new(0)),
        reads: Arc::default(),
    });
    assert_eq!(asctime(&host, 116_989_432), "Sun Sep 16 01:03:52 1973\n");
    assert_eq!(
        asctime(&host, 1_000_000_000),
        "Sun Sep \x209 01:46:40 2001\n"
    );
    assert_eq!(asctime(&host, 0), "Thu Jan \x201 00:00:00 1970\n");
}

/// A sandbox's `-lf` log is charged to the output budget like any file
/// (0.19.0 Task 12): what the budget holds is written, the rest is lost
/// (a failed `fprintf` to the log is never looked at), and the budget ends
/// at what was not taken.
#[test]
fn the_log_is_charged_to_the_sandbox_budget() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("stuffr-zipcharge-{}-log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let budget = Arc::new(AtomicU64::new(10));
    let host = Host::Sandbox(Sandbox {
        dir,
        stdin: None,
        stdout: Arc::default(),
        budget: budget.clone(),
        reads: Arc::default(),
    });
    let env = |_: &str| None;
    let mut err = Vec::new();
    let mut z = Zr::new(host, Flavour::Apple, "zip", &env, &mut err);
    z.log = Some(Box::new(std::fs::File::create(&path).unwrap()));
    z.log_write(b"12345678");
    z.log_write(b"abcdef");
    drop(z);
    let written = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(written, b"12345678");
    assert_eq!(budget.load(std::sync::atomic::Ordering::Relaxed), 2);
}

/// A pattern file (`-i @names`) is a tracked open of the sandbox: counted
/// once, with the bytes read (0.19.0 Task 12).
#[test]
fn a_pattern_file_is_a_tracked_open() {
    let dir = std::env::temp_dir().join(format!("stuffr-zippat-{}-d", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("names"), b"a\nb\n").unwrap();
    let args: Vec<OsString> = ["-i", "@names", "out.zip", "a"]
        .iter()
        .map(OsString::from)
        .collect();
    let (_, _, _, reads) = run_in_counted(Flavour::Apple, &dir, "zip", &args, b"");
    let _ = std::fs::remove_dir_all(&dir);
    let r = reads
        .iter()
        .find(|(p, _)| p.ends_with("names"))
        .map(|(_, r)| *r)
        .expect("the pattern file was opened through Host::track");
    assert_eq!((r.opens, r.bytes, r.len), (1, 4, 4));
}

/// A scratch directory, removed on drop (`stuffr-zipsig-<pid>-<tag>`).
#[cfg(unix)]
struct SigScratch(std::path::PathBuf);

#[cfg(unix)]
impl SigScratch {
    fn new(tag: &str) -> SigScratch {
        let d = std::env::temp_dir().join(format!("stuffr-zipsig-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        SigScratch(d)
    }
}

#[cfg(unix)]
impl Drop for SigScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Ruling Z32, deviation 30: a SIGINT that arrives while `replace()` has
/// the archive unlinked (rename path) or truncated (copy path: a hard-linked
/// or symbolic-linked archive) is held back until the archive is whole. The
/// run then answers it as zip's handler does: `\n` + the error text on
/// `mesg`, exit 9, and the (already published) temporary is gone. The
/// signal is raised by `sink`'s test hook at exactly those points, in a
/// forked child, so nothing depends on timing.
#[cfg(unix)]
#[test]
fn an_interrupt_during_replace_leaves_a_whole_archive() {
    use crate::compat::host;
    use crate::compat::zip::sink;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::Ordering;

    for shape in ["plain", "hardlink", "symlink"] {
        let s = SigScratch::new(shape);
        let real = s.0.join("real.zip");
        let archive = s.0.join("a.zip");
        let tmp = s.0.join("zi123456");
        std::fs::write(&real, b"OLD ARCHIVE BYTES").unwrap();
        match shape {
            "plain" => std::fs::rename(&real, &archive).unwrap(),
            "hardlink" => std::fs::hard_link(&real, &archive).unwrap(),
            _ => std::os::unix::fs::symlink(&real, &archive).unwrap(),
        }
        let new = vec![b'N'; 300_000];
        let capture = std::fs::File::create(s.0.join("mesg")).unwrap();
        let cfd = capture.as_raw_fd();
        // SAFETY: the child calls sigaction, open, write, rename, unlink,
        // raise and _exit (std's fs calls on short paths use stack buffers)
        // and never returns into the harness; the parent only waits.
        let status = unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
            if pid == 0 {
                host::disarm_inherited();
                libc::dup2(cfd, 1);
                host::install_zip_abort(&Host::Real, messages::INTERRUPTED_ABORTING);
                host::zip_mesg_state(&Host::Real, false, false);
                let made = host::create_new_armed_if(true, &tmp, host::ZIP_SIGNALS);
                let Ok((mut f, _armed)) = made else {
                    libc::_exit(20);
                };
                if std::io::Write::write_all(&mut f, &new).is_err() {
                    libc::_exit(21);
                }
                drop(f);
                sink::RAISE_MID_REPLACE.store(true, Ordering::SeqCst);
                let r = sink::replace(&archive, &tmp);
                // the signal is delivered when replace() restores the mask:
                // reaching here means it was not answered
                libc::_exit(if r.is_ok() { 22 } else { 23 });
            }
            let mut status = 0;
            while libc::waitpid(pid, &mut status, 0) < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR)
                );
            }
            status
        };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 9,
            "{shape}: status {status:#x}"
        );
        assert_eq!(
            std::fs::read(&archive).ok().map(|b| b.len()),
            Some(new.len()),
            "{shape}: the archive is not the whole new one"
        );
        assert!(
            std::fs::read(&archive).unwrap() == new,
            "{shape}: not the new bytes"
        );
        if shape != "plain" {
            assert!(
                std::fs::read(&real).unwrap() == new,
                "{shape}: through the link"
            );
        }
        assert!(!tmp.exists(), "{shape}: the temporary survived");
        let mut want = b"\n".to_vec();
        want.extend_from_slice(messages::INTERRUPTED_ABORTING);
        assert_eq!(
            String::from_utf8_lossy(&std::fs::read(s.0.join("mesg")).unwrap()),
            String::from_utf8_lossy(&want),
            "{shape}: zip's answer"
        );
    }
}

/// Ruling Z34: when `replace()` fails after the archive was truncated (the
/// copy path over a hard-linked archive, the copy cut by `RLIMIT_FSIZE`),
/// the temporary is the only whole copy. A SIGINT held meanwhile is answered
/// as zip's handler answers it (`\n` + the text, exit 9), but the temporary
/// is kept under its own name.
#[cfg(unix)]
#[test]
fn an_interrupt_after_a_failed_replace_keeps_the_temporary() {
    use crate::compat::host;
    use crate::compat::zip::sink;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::Ordering;

    let s = SigScratch::new("failed");
    let real = s.0.join("real.zip");
    let archive = s.0.join("a.zip");
    let tmp = s.0.join("zi654321");
    std::fs::write(&real, b"OLD ARCHIVE BYTES").unwrap();
    std::fs::hard_link(&real, &archive).unwrap();
    let new = vec![b'N'; 300_000];
    let capture = std::fs::File::create(s.0.join("mesg")).unwrap();
    let cfd = capture.as_raw_fd();
    // SAFETY: as in `an_interrupt_during_replace_leaves_a_whole_archive`;
    // setrlimit and signal(SIGXFSZ, SIG_IGN) only change this child.
    let status = unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            host::disarm_inherited();
            libc::dup2(cfd, 1);
            host::install_zip_abort(&Host::Real, messages::INTERRUPTED_ABORTING);
            host::zip_mesg_state(&Host::Real, false, false);
            let made = host::create_new_armed_if(true, &tmp, host::ZIP_SIGNALS);
            let Ok((mut f, _armed)) = made else {
                libc::_exit(20);
            };
            if std::io::Write::write_all(&mut f, &new).is_err() {
                libc::_exit(21);
            }
            drop(f);
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let limit = libc::rlimit {
                rlim_cur: 4096,
                rlim_max: libc::RLIM_INFINITY,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                libc::_exit(24);
            }
            sink::RAISE_MID_REPLACE.store(true, Ordering::SeqCst);
            let r = sink::replace(&archive, &tmp);
            libc::_exit(if r.is_ok() { 22 } else { 23 });
        }
        let mut status = 0;
        while libc::waitpid(pid, &mut status, 0) < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
        }
        status
    };
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 9,
        "status {status:#x}"
    );
    assert!(
        std::fs::read(&tmp).ok().as_deref() == Some(&new[..]),
        "the temporary, the only whole copy, is gone or cut"
    );
    let mut want = b"\n".to_vec();
    want.extend_from_slice(messages::INTERRUPTED_ABORTING);
    assert_eq!(
        String::from_utf8_lossy(&std::fs::read(s.0.join("mesg")).unwrap()),
        String::from_utf8_lossy(&want),
        "zip's answer"
    );
}
