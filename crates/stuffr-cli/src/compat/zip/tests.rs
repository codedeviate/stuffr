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
    z.mesg_line_started = false;
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
