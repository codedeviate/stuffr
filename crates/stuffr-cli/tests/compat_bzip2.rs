//! Differential tests: stuffr invoked as `bzip2` and friends against the
//! real 1.0.8 tools.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;

    fn kib() -> Vec<u8> {
        (0..1024u32).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn case<'a>(args: Vec<&'a str>) -> Case<'a> {
        Case {
            name: "bzip2",
            args,
            files: vec![("a.txt", kib())],
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![],
            compare_output_bytes: true,
            expect_stdout_plain: None,
            setup: None,
        }
    }

    /// The harness against itself: identical runs must compare equal.
    #[test]
    fn reference_against_itself_is_clean() {
        let c = case(vec!["a.txt"]);
        let Some(a) = reference(REFERENCE_DIR, &c) else {
            return;
        };
        let b = reference(REFERENCE_DIR, &c).unwrap();
        assert_eq!(a.code, 0);
        assert!(a.tree.contains_key("a.bz2") || a.tree.contains_key("a.txt.bz2"));
        assert_same(&c, &a, &b);
    }

    /// A missing reference skips locally and fails on CI.
    #[test]
    fn a_missing_reference_fails_only_on_ci() {
        let missing = std::path::Path::new("/nonexistent/stuffr-no-such-tool");
        let r = std::panic::catch_unwind(|| require_reference(missing));
        if std::env::var_os("CI").is_some() {
            assert!(r.is_err(), "CI is set, so a missing reference must panic");
        } else {
            assert_eq!(r.ok(), Some(false));
        }
        assert!(require_reference(std::path::Path::new("/bin/sh")));
    }

    /// A pty on stdout makes bzip2 refuse to write compressed data to it.
    #[test]
    fn tty_stdout_is_a_terminal_for_the_reference() {
        let mut c = case(vec!["-c", "a.txt"]);
        c.tty_stdout = true;
        let Some(r) = reference(REFERENCE_DIR, &c) else {
            return;
        };
        assert_eq!(r.code, 1, "stderr: {}", r.stderr);
        assert!(
            r.stderr
                .contains("I won't write compressed data to a terminal"),
            "{}",
            r.stderr
        );
    }

    #[test]
    fn selftest_bzip2_c_one_kib() {
        let c = case(vec!["-c", "a.txt"]);
        let Some(r) = reference(REFERENCE_DIR, &c) else {
            return;
        };
        let s = stuffr_as(&c);
        assert_same(&c, &r, &s);
    }

    /// Typed input reaches a tool that reads the terminal, and ^D ends it.
    #[test]
    fn tty_stdin_is_fed_and_closed() {
        for data in [&b"hello world\n"[..], &b"no trailing newline"[..]] {
            let mut c = case(vec!["-c"]);
            c.files.clear();
            c.stdin = Some(data.to_vec());
            c.tty_stdin = true;
            let Some(a) = reference(REFERENCE_DIR, &c) else {
                return;
            };
            let b = reference(REFERENCE_DIR, &c).unwrap();
            assert_eq!(a.code, 0, "stderr: {}", a.stderr);
            assert!(a.stdout.starts_with(b"BZh"));
            // Delivery: what the tool compressed is exactly what was typed.
            let mut want = data.to_vec();
            if !want.ends_with(b"\n") {
                want.push(b'\n');
            }
            assert_eq!(ref_decompress(&a.stdout).unwrap(), want);
            assert_same(&c, &a, &b);
        }
    }

    /// More than a pty buffer's worth of output must not deadlock.
    #[test]
    fn tty_stdout_larger_than_the_pty_buffer() {
        let big: Vec<u8> = (0..1_048_576u32)
            .map(|i| b'a' + (i.wrapping_mul(2654435761) >> 28) as u8)
            .collect();
        let mut mk = case(vec!["-c"]);
        mk.files.clear();
        mk.stdin = Some(big.clone());
        let Some(packed) = reference(REFERENCE_DIR, &mk) else {
            return;
        };
        let mut c = case(vec!["big.bz2"]);
        c.name = "bzcat";
        c.files = vec![("big.bz2", packed.stdout)];
        c.tty_stdout = true;
        let Some(a) = reference(REFERENCE_DIR, &c) else {
            return;
        };
        let b = reference(REFERENCE_DIR, &c).unwrap();
        assert_eq!(a.code, 0, "stderr: {}", a.stderr);
        assert!(a.stdout.len() >= 1_048_576, "{}", a.stdout.len());
        assert_same(&c, &a, &b);
    }

    // ---- sensitivity: assert_same must notice each single difference ----

    fn base_run() -> Run {
        let mut tree = Tree::new();
        tree.insert("a.txt".into(), (kib(), 0o644, INPUT_MTIME as i64));
        tree.insert("a.txt.bz2".into(), (b"BZh9xyz".to_vec(), 0o644, now_secs()));
        Run {
            code: 0,
            stdout: b"out".to_vec(),
            stderr: "bzip2: msg\n".into(),
            tree,
            start: now_secs(),
        }
    }

    /// The panic message `assert_same` produced, or `None` if it passed.
    fn verdict(c: &Case, r: &Run, s: &Run) -> Option<String> {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_same(c, r, s)));
        res.err().map(|p| {
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        })
    }

    fn mutated(c: &Case, mutate: impl FnOnce(&mut Run)) -> Option<String> {
        let r = base_run();
        let mut s = base_run();
        mutate(&mut s);
        verdict(c, &r, &s)
    }

    /// `assert_same` must panic, and the message must name `needle` and no
    /// other kind of difference.
    fn notices(c: &Case, mutate: impl FnOnce(&mut Run), needle: &str) {
        let msg = mutated(c, mutate).expect("assert_same did not notice the difference");
        assert!(msg.contains(needle), "message lacks {needle:?}:\n{msg}");
        assert!(
            msg.contains("in 1 way(s)"),
            "more than one difference:\n{msg}"
        );
    }

    #[test]
    fn identical_runs_pass() {
        assert_eq!(mutated(&case(vec![]), |_| {}), None);
    }

    #[test]
    fn notices_mode() {
        notices(
            &case(vec![]),
            |s| s.tree.get_mut("a.txt.bz2").unwrap().1 = 0o600,
            "mode reference",
        );
    }

    #[test]
    fn notices_pinned_input_mtime() {
        notices(
            &case(vec![]),
            |s| s.tree.get_mut("a.txt").unwrap().2 += 1,
            "a.txt mtime",
        );
    }

    #[test]
    fn mtime_window_accepts_two_wall_clock_times() {
        let now = now_secs();
        let r = base_run();
        let mut s = base_run();
        s.tree.get_mut("a.txt.bz2").unwrap().2 = now - 1;
        assert_eq!(verdict(&case(vec![]), &r, &s), None);
    }

    #[test]
    fn mtime_window_rejects_a_time_far_outside() {
        notices(
            &case(vec![]),
            |s| s.tree.get_mut("a.txt.bz2").unwrap().2 = now_secs() - 1000,
            "a.txt.bz2 mtime",
        );
    }

    #[test]
    fn notices_removed_file() {
        notices(
            &case(vec![]),
            |s| {
                s.tree.remove("a.txt");
            },
            "removed in stuffr",
        );
    }

    #[test]
    fn notices_added_file() {
        notices(
            &case(vec![]),
            |s| {
                s.tree.insert("extra".into(), (vec![], 0o644, now_secs()));
            },
            "added in stuffr",
        );
    }

    #[test]
    fn notices_stderr_text() {
        notices(
            &case(vec![]),
            |s| s.stderr = "bzip2: other\n".into(),
            "stderr differs",
        );
    }

    #[test]
    fn notices_stdout_bytes() {
        notices(
            &case(vec![]),
            |s| s.stdout = b"oux".to_vec(),
            "stdout differs",
        );
    }

    #[test]
    fn notices_output_bytes_when_identity_is_promised() {
        notices(
            &case(vec![]),
            |s| s.tree.get_mut("a.txt.bz2").unwrap().0 = b"BZh9xyy".to_vec(),
            "a.txt.bz2 bytes differ",
        );
    }

    #[test]
    fn notices_exit_code() {
        notices(&case(vec![]), |s| s.code = 3, "exit code");
    }

    /// Real output at -1 against -9: both are valid bzip2 and decompress to
    /// the same data, so only the block-size digit can tell them apart.
    #[test]
    fn notices_block_digit_in_roundtrip_mode() {
        let mut c9 = case(vec!["-c", "-9", "a.txt"]);
        c9.compare_output_bytes = false;
        let Some(r) = reference(REFERENCE_DIR, &c9) else {
            return;
        };
        let c1 = case(vec!["-c", "-1", "a.txt"]);
        let s = reference(REFERENCE_DIR, &c1).unwrap();
        assert_eq!(r.stdout[3], b'9');
        assert_eq!(s.stdout[3], b'1');
        let msg = verdict(&c9, &r, &s).expect("block digit difference not noticed");
        assert!(msg.contains("block-size digit"), "{msg}");
        assert!(msg.contains("in 1 way(s)"), "{msg}");
    }

    #[test]
    fn program_path_is_normalised_to_the_bare_name() {
        let exe = std::path::Path::new("/tmp/x/bzip2");
        let norm = |raw: &str| normalise_stderr(raw.as_bytes(), exe, "bzip2");
        assert_eq!(norm("/tmp/x/bzip2: oops\n"), "bzip2: oops\n");
        assert_eq!(
            norm("see /tmp/x/bzip2 and /tmp/x/bzip2\n"),
            "see bzip2 and bzip2\n"
        );
        // Nothing else is touched, including other paths.
        assert_eq!(norm("/tmp/y/bzip2: oops\n"), "/tmp/y/bzip2: oops\n");
        // Only a whole occurrence: a longer path that starts with it stays.
        assert_eq!(
            norm("/tmp/x/bzip2.bak: oops /tmp/x/bzip2/sub\n"),
            "/tmp/x/bzip2.bak: oops /tmp/x/bzip2/sub\n"
        );
        assert_eq!(norm("at end /tmp/x/bzip2"), "at end bzip2");
        assert_eq!(norm("/tmp/x/bzip2\tx"), "bzip2\tx");
    }

    #[test]
    fn a_different_message_still_differs_after_normalisation() {
        let exe = std::path::Path::new("/tmp/x/bzip2");
        let r = base_run();
        let mut s = base_run();
        s.stderr = normalise_stderr(b"/tmp/x/bzip2: different\n", exe, "bzip2");
        let msg = verdict(&case(vec![]), &r, &s).expect("not noticed");
        assert!(msg.contains("stderr differs"), "{msg}");
        // And the same message through a different program path is equal.
        s.stderr = normalise_stderr(b"/tmp/x/bzip2: msg\n", exe, "bzip2");
        assert_eq!(verdict(&case(vec![]), &r, &s), None);
    }
}

/// stuffr as `bzip2`, `bunzip2` and `bzcat` against bzip2 1.0.8, case by case.
/// Every case runs both programs on identical inputs and compares the exit
/// code, stderr, stdout and the resulting file tree (bytes, modes, mtimes).
#[cfg(unix)]
mod differential {
    use super::compat_harness::*;
    use std::path::Path;
    use std::process::{Command, Stdio};

    // ---- deterministic data (no RNG dependency) ----

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

    fn random(n: usize, seed: u64) -> Vec<u8> {
        let mut r = XorShift(seed);
        (0..n).map(|_| (r.next() >> 24) as u8).collect()
    }

    const WORDS: &[&str] = &[
        "the",
        "quick",
        "brown",
        "fox",
        "jumps",
        "over",
        "lazy",
        "dog",
        "stuffr",
        "bzip2",
        "block",
        "sorting",
        "compressor",
        "and",
        "of",
        "a",
        "to",
        "in",
        "file",
    ];

    /// Plain text: words, spaces and newlines only (safe to type at a tty).
    fn text(n: usize, seed: u64) -> Vec<u8> {
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
    fn mixed(n: usize, seed: u64) -> Vec<u8> {
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

    fn repetitive(n: usize) -> Vec<u8> {
        b"abcabcabd".iter().copied().cycle().take(n).collect()
    }

    fn kib_text() -> Vec<u8> {
        text(1024, 7)
    }

    /// Compress with the reference tool; `None` when it is not installed.
    /// Compress with the reference; `None` when it is missing (a panic on
    /// CI, see `require_reference`).
    fn ref_bz(data: &[u8], level: &str) -> Option<Vec<u8>> {
        let exe = Path::new(REFERENCE_DIR).join("bzip2");
        if !require_reference(&exe) {
            return None;
        }
        let mut child = Command::new(exe)
            .args(["-c", level])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut si = child.stdin.take().unwrap();
        let d = data.to_vec();
        let w = std::thread::spawn(move || {
            use std::io::Write;
            let _ = si.write_all(&d);
        });
        let out = child.wait_with_output().unwrap();
        w.join().unwrap();
        assert!(out.status.success());
        Some(out.stdout)
    }

    fn case<'a>(name: &'a str, args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        Case {
            name,
            args: args.to_vec(),
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![],
            compare_output_bytes: true,
            expect_stdout_plain: None,
            setup: None,
        }
    }

    fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// Run every case (reference, then stuffr) and fail once, listing every
    /// case that differed. `adjust` may edit stuffr's run before comparing.
    /// Cases run a few at a time: each is two independent processes in
    /// their own scratch directories.
    fn check_all_with(group: &str, cases: &[Case], adjust: fn(&mut Run, &mut Run)) {
        let one = |c: &Case| -> Result<bool, String> {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let Some(mut r) = reference(REFERENCE_DIR, c) else {
                    return false;
                };
                let mut s = stuffr_as(c);
                adjust(&mut r, &mut s);
                assert_same(c, &r, &s);
                true
            }))
            .map_err(panic_text)
        };
        let workers = std::thread::available_parallelism().map_or(2, |n| n.get().min(8));
        let next = std::sync::atomic::AtomicUsize::new(0);
        let results: Vec<(usize, Result<bool, String>)> = std::thread::scope(|sc| {
            let hs: Vec<_> = (0..workers)
                .map(|_| {
                    sc.spawn(|| {
                        let mut out = Vec::new();
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(c) = cases.get(i) else { break out };
                            out.push((i, one(c)));
                        }
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        let mut results = results;
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
        println!("{group}: {ran} of {} cases compared", cases.len());
        // A missing reference skips a case; on CI that must not pass quietly.
        if std::env::var_os("CI").is_some() {
            assert_eq!(
                ran,
                cases.len(),
                "{group}: CI is set but only {ran} of {} cases were compared \
                 (is the reference bzip2 installed?)",
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

    fn check_all(group: &str, cases: &[Case]) {
        check_all_with(group, cases, |_, _| {});
    }

    // ---- setups (run in the working directory before the program) ----

    fn link_l_txt(d: &Path) {
        std::os::unix::fs::symlink("a.txt", d.join("l.txt")).unwrap();
    }
    fn link_l_bz2(d: &Path) {
        std::os::unix::fs::symlink("a.bz2", d.join("l.bz2")).unwrap();
    }
    fn dangling_output(d: &Path) {
        std::os::unix::fs::symlink("nowhere", d.join("a.txt.bz2")).unwrap();
    }
    fn hard_link(d: &Path) {
        std::fs::hard_link(d.join("a.txt"), d.join("h.txt")).unwrap();
    }
    fn two_hard_links(d: &Path) {
        std::fs::hard_link(d.join("a.txt"), d.join("h.txt")).unwrap();
        std::fs::hard_link(d.join("a.txt"), d.join("i.txt")).unwrap();
    }
    fn mode(d: &Path, name: &str, m: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join(name), std::fs::Permissions::from_mode(m)).unwrap();
    }
    fn unreadable(d: &Path) {
        mode(d, "a.txt", 0o000);
    }
    fn mode_640(d: &Path) {
        mode(d, "a.txt", 0o640);
    }
    fn mode_604_bz2(d: &Path) {
        mode(d, "a.bz2", 0o604);
    }
    fn subdir(d: &Path) {
        std::fs::create_dir(d.join("d")).unwrap();
    }
    fn empty_dir_output(d: &Path) {
        std::fs::create_dir(d.join("a.txt.bz2")).unwrap();
    }

    // ---- groups ----

    /// Each flag alone, in clusters and in long form; `--`; the no-op and
    /// unknown flags; `-h`; environment options.
    #[test]
    fn flags() {
        let t = kib_text();
        let Some(bz) = ref_bz(&t, "-9") else { return };
        let a = || vec![("a.txt", t.clone())];
        let b = || vec![("a.bz2", bz.clone())];
        let ab = || vec![("a.txt", t.clone()), ("a.bz2", bz.clone())];
        let mut cases = vec![
            case("bzip2", &["a.txt"], a()),
            case("bzip2", &["-k", "a.txt"], a()),
            case("bzip2", &["--keep", "a.txt"], a()),
            case("bzip2", &["-c", "a.txt"], a()),
            case("bzip2", &["--stdout", "a.txt"], a()),
            case("bzip2", &["-z", "a.txt"], a()),
            case("bzip2", &["--compress", "a.txt"], a()),
            case("bzip2", &["-f", "a.txt"], a()),
            case("bzip2", &["--force", "a.txt"], a()),
            case("bzip2", &["-q", "a.txt"], a()),
            case("bzip2", &["--quiet", "a.txt"], a()),
            case("bzip2", &["-v", "a.txt"], a()),
            case("bzip2", &["--verbose", "a.txt"], a()),
            case("bzip2", &["-s", "a.txt"], a()),
            case("bzip2", &["--small", "a.txt"], a()),
            case("bzip2", &["-s9", "a.txt"], a()),
            case("bzip2", &["-s1", "a.txt"], a()),
            case("bzip2", &["--fast", "a.txt"], a()),
            case("bzip2", &["--best", "a.txt"], a()),
            case("bzip2", &["--exponential", "a.txt"], a()),
            case("bzip2", &["-zc9", "a.txt"], a()),
            case("bzip2", &["-kv", "a.txt"], a()),
            case("bzip2", &["-v", "-4", "a.txt"], a()),
            case("bzip2", &["a.txt", "-k"], a()),
            case("bzip2", &["-d", "-z", "a.txt"], a()),
            case("bzip2", &["-", "a.txt"], a()),
            case("bzip2", &["--", "a.txt"], a()),
            case("bzip2", &["-k", "--", "-c"], vec![("-c", t.clone())]),
            case("bzip2", &["--repetitive-fast", "a.txt"], a()),
            case("bzip2", &["--repetitive-best", "a.txt"], a()),
            case("bzip2", &["-x"], a()),
            case("bzip2", &["-kx", "a.txt"], a()),
            case("bzip2", &["--bogus", "a.txt"], a()),
            case("bzip2", &["--bogus", "-x"], a()),
            case("bzip2", &["-h"], a()),
            case("bzip2", &["--help"], a()),
            case("bzip2", &["-x", "-h"], a()),
            case("bzip2", &["-h", "-x"], a()),
            case("bzip2", &["--help", "-x"], a()),
            case("bzip2", &["-c", "-t", "a.txt"], a()),
            case("bzip2", &["-ct"], a()),
            case("bzip2", &["-d", "a.bz2"], b()),
            case("bzip2", &["--decompress", "a.bz2"], b()),
            case("bzip2", &["-dkv", "a.bz2"], b()),
            case("bzip2", &["-dc", "a.bz2"], b()),
            case("bzip2", &["-ds", "a.bz2"], b()),
            case("bzip2", &["-t", "a.bz2"], b()),
            case("bzip2", &["--test", "a.bz2"], b()),
            case("bzip2", &["-tv", "a.bz2"], b()),
            case("bzip2", &["-tq", "a.bz2"], b()),
            case("bzip2", &["-tdv", "a.bz2"], b()),
            case("bzip2", &["-td", "a.bz2"], b()),
            case("bzip2", &["-v", "a.txt", "-d", "a.bz2"], ab()),
            case("bunzip2", &["a.bz2"], b()),
            case("bunzip2", &["-k", "a.bz2"], b()),
            case("bunzip2", &["-z", "a.txt"], a()),
            case("bunzip2", &["-t", "a.bz2"], b()),
            case("bunzip2", &["-c", "a.bz2"], b()),
            case("bzcat", &["a.bz2"], b()),
            case("bzcat", &["-z", "a.txt"], a()),
            case("bzcat", &["-t", "a.bz2"], b()),
            case("bzcat", &["-v", "a.bz2"], b()),
            case("bzcat", &["-k", "a.bz2"], b()),
        ];
        let mut env = |vars: Vec<(&'static str, &'static str)>, args: &[&'static str]| {
            let mut c = case("bzip2", args, ab());
            c.env = vars;
            cases.push(c);
        };
        env(vec![("BZIP2", "-9 -v")], &["-1", "a.txt"]);
        env(vec![("BZIP2", "-1 -v")], &["a.txt"]);
        env(vec![("BZIP", "-k")], &["a.txt"]);
        env(vec![("BZIP2", "-c"), ("BZIP", "-1")], &["a.txt"]);
        env(vec![("BZIP2", "  -k\t-v  ")], &["a.txt"]);
        env(vec![("BZIP2", "a.txt")], &["-k"]);
        env(vec![("BZIP2", "-x")], &["a.txt"]);
        env(vec![("BZIP", "-d")], &["a.bz2"]);
        env(vec![("BZIP2", "--")], &["-k", "a.txt"]);
        check_all("flags", &cases);
    }

    /// Whether the reference exits straight after printing the licence, as
    /// Debian's bzip2 does (its `20-legacy.patch` adds `exit(0)` after
    /// `license()`; ubuntu-latest inherits it). Upstream 1.0.8 carries on and
    /// compresses stdin, so `bzip2 -V </dev/null` writes an empty stream.
    fn reference_exits_after_license() -> Option<bool> {
        let exe = Path::new(REFERENCE_DIR).join("bzip2");
        if !require_reference(&exe) {
            return None;
        }
        let out = Command::new(exe)
            .arg("-V")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .unwrap();
        Some(out.stdout.is_empty())
    }

    const REF_LICENSE_FIRST: &str =
        "bzip2, a block-sorting file compressor.  Version 1.0.8, 13-Jul-2019.\n";

    /// Swap stuffr's licence first line for upstream's, after checking it.
    fn licence_line(r: &mut Run, s: &mut Run) {
        let first = format!(
            "bzip2 (stuffr {}), a block-sorting file compressor.  \
             Version 1.0.8, 13-Jul-2019.\n",
            env!("CARGO_PKG_VERSION")
        );
        assert!(
            r.stderr.contains(REF_LICENSE_FIRST),
            "reference has no licence line"
        );
        assert!(
            s.stderr.contains(&first),
            "stuffr's licence line is not {first:?}: {:?}",
            s.stderr
        );
        // Only the licence's own first line differs; usage() keeps it.
        assert!(!s.stderr.contains(&format!("{REF_LICENSE_FIRST}   \n")));
        s.stderr = s.stderr.replace(&first, REF_LICENSE_FIRST);
    }

    /// For a reference that exits after the licence: compare the licence
    /// text only. What follows it (stdout, files, exit code) is the patched
    /// reference's behaviour, not upstream's, which stuffr follows.
    fn licence_text_only(r: &mut Run, s: &mut Run) {
        licence_line(r, s);
        s.code = r.code;
        s.stdout = r.stdout.clone();
        s.tree = r.tree.clone();
    }

    /// `-L`, `-V`, `--license` and `--version` print bzip2's licence text; the
    /// first line names stuffr, and everything after it is bzip2's verbatim.
    /// The licence does not stop upstream bzip2, so each case also checks
    /// what happens next.
    ///
    /// A deviation of the test oracle, not of stuffr: on a reference carrying
    /// Debian's `20-legacy.patch` (exit after the licence) the continuation
    /// cases are skipped and only the licence text is compared.
    #[test]
    fn license_and_version() {
        let Some(legacy) = reference_exits_after_license() else {
            return;
        };
        let t = kib_text();
        let bz = ref_bz(b"x", "-9").unwrap();
        let a = || vec![("a.txt", t.clone())];
        // The decompressing names read stdin after the licence: give them a
        // stream.
        let fed = |name: &'static str, args: &[&'static str]| {
            let mut c = case(name, args, vec![]);
            c.stdin = Some(bz.clone());
            c
        };
        let alone = vec![
            case("bzip2", &["-L"], vec![]),
            case("bzip2", &["-V"], vec![]),
            case("bzip2", &["--license"], vec![]),
            case("bzip2", &["--version"], vec![]),
        ];
        if legacy {
            println!(
                "license: the reference exits after the licence (Debian's \
                 20-legacy.patch); skipping the continuation cases and \
                 comparing the licence text only"
            );
            check_all_with("license", &alone, licence_text_only);
            return;
        }
        let mut cases = alone;
        cases.extend([
            case("bzip2", &["-LV"], vec![]),
            case("bzip2", &["-V", "-k", "a.txt"], a()),
            case("bzip2", &["-V", "-x"], vec![]),
            fed("bunzip2", &["-L"]),
            fed("bzcat", &["--version"]),
        ]);
        check_all_with("license", &cases, licence_line);
    }

    /// Levels 1-9 and the default, over six inputs, compressed bytes compared
    /// exactly, with `-v` so the statistics line is compared too.
    #[test]
    fn compress() {
        let inputs: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("one", b"x".to_vec()),
            ("text", kib_text()),
            ("mixed", mixed(1 << 20, 11)),
            ("random", random(1 << 20, 12)),
            ("repetitive", repetitive(4 << 20)),
        ];
        let levels = ["", "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9"];
        let mut cases = Vec::new();
        for (name, data) in &inputs {
            for l in levels {
                let mut args = vec!["-v"];
                if !l.is_empty() {
                    args.push(l);
                }
                args.push(name);
                cases.push(case("bzip2", &args, vec![(name, data.clone())]));
            }
        }
        // The same through a pipe.
        for (_, data) in &inputs[..4] {
            let mut c = case("bzip2", &["-v"], vec![]);
            c.stdin = Some(data.clone());
            cases.push(c);
        }
        check_all("compress", &cases);
    }

    /// Name mapping, concatenated streams, trailing garbage, damaged and
    /// truncated files, not-bzip2 files, and `-t`.
    #[test]
    fn decompress() {
        let t = kib_text();
        let big = mixed(300_000, 21);
        let Some(bz) = ref_bz(&t, "-9") else { return };
        let bz_big = ref_bz(&big, "-1").unwrap();
        let bz2nd = ref_bz(b"second stream\n", "-3").unwrap();
        let cat2 = [bz.clone(), bz2nd.clone()].concat();
        let with = |tail: &[u8]| [bz.clone(), tail.to_vec()].concat();
        let mut damaged = bz_big.clone();
        let mid = damaged.len() / 2;
        damaged[mid] ^= 0x55;
        let mut bad_crc = bz.clone();
        let n = bad_crc.len();
        bad_crc[n - 2] ^= 0x01;

        let mut cases = Vec::new();
        for name in ["a.bz2", "a.bz", "a.tbz2", "a.tbz", "a.dat", "a"] {
            cases.push(case("bunzip2", &[name], vec![(name, bz.clone())]));
            cases.push(case("bunzip2", &["-v", name], vec![(name, bz.clone())]));
        }
        cases.push(case("bunzip2", &[".bz2"], vec![(".bz2", bz.clone())]));
        let files: Vec<(&str, Vec<u8>, &str)> = vec![
            ("cat2.bz2", cat2.clone(), "concatenated"),
            ("big.bz2", bz_big.clone(), "multi-block"),
            ("zeros.bz2", with(&[0u8; 40]), "trailing zeros"),
            ("garb.bz2", with(b"garbage"), "trailing text"),
            ("digit.bz2", with(b"BZhX..."), "trailing bad digit"),
            (
                "blockmagic.bz2",
                with(b"BZh9xxxxxxxxxx"),
                "trailing bad block",
            ),
            ("damaged.bz2", damaged.clone(), "damaged"),
            ("crc.bz2", bad_crc.clone(), "stream CRC"),
            ("plain.bz2", t.clone(), "not bzip2"),
        ];
        for (name, data, _) in &files {
            let name: &str = name;
            for args in [
                vec![name],
                vec!["-k", name],
                vec!["-v", name],
                vec!["-q", name],
                vec!["-f", name],
                vec!["-c", name],
                vec!["-cf", name],
                vec!["-t", name],
                vec!["-tv", name],
                vec!["-tq", name],
            ] {
                let mut c = case("bunzip2", &args, vec![(name, data.clone())]);
                c.compare_output_bytes = true;
                cases.push(c);
            }
            let mut c = case("bunzip2", &[], vec![]);
            c.stdin = Some(data.clone());
            cases.push(c);
            let mut c = case("bunzip2", &["-f"], vec![]);
            c.stdin = Some(data.clone());
            cases.push(c);
            let mut c = case("bzip2", &["-t"], vec![]);
            c.stdin = Some(data.clone());
            cases.push(c);
        }
        // Several operands: a failure that ends the run, and one that does not.
        cases.push(case(
            "bunzip2",
            &["damaged.bz2", "a.bz2"],
            vec![("damaged.bz2", damaged.clone()), ("a.bz2", bz.clone())],
        ));
        cases.push(case(
            "bunzip2",
            &["-q", "damaged.bz2", "a.bz2"],
            vec![("damaged.bz2", damaged.clone()), ("a.bz2", bz.clone())],
        ));
        cases.push(case(
            "bunzip2",
            &["plain.bz2", "a.bz2"],
            vec![("plain.bz2", t.clone()), ("a.bz2", bz.clone())],
        ));
        cases.push(case(
            "bzip2",
            &["-t", "plain.bz2", "damaged.bz2", "a.bz2"],
            vec![
                ("plain.bz2", t.clone()),
                ("damaged.bz2", damaged.clone()),
                ("a.bz2", bz.clone()),
            ],
        ));
        check_all("decompress", &cases);
    }

    /// The line `perror` prints after "*Possible* reason follows.", blanked:
    /// its text is whatever `errno` libc left behind.
    fn blank_perror(stderr: &str) -> String {
        const AFTER: &str = "*Possible* reason follows.\n";
        let mut out = String::with_capacity(stderr.len());
        let mut rest = stderr;
        while let Some(i) = rest.find(AFTER) {
            let (head, tail) = rest.split_at(i + AFTER.len());
            out.push_str(head);
            let end = tail.find('\n').map_or(tail.len(), |n| n + 1);
            out.push_str("<perror>\n");
            rest = &tail[end..];
        }
        out.push_str(rest);
        out
    }

    fn perror_blanked(r: &mut Run, s: &mut Run) {
        r.stderr = blank_perror(&r.stderr);
        s.stderr = blank_perror(&s.stderr);
    }

    #[test]
    fn blank_perror_replaces_only_that_line() {
        let text = "\nbunzip2: Compressed file ends unexpectedly;\n\tperhaps it is \
                    corrupted?  *Possible* reason follows.\nbunzip2: Success\n\tInput \
                    file = a, output file = b\n";
        assert_eq!(
            blank_perror(text),
            "\nbunzip2: Compressed file ends unexpectedly;\n\tperhaps it is \
             corrupted?  *Possible* reason follows.\n<perror>\n\tInput file = a, \
             output file = b\n"
        );
        assert_eq!(blank_perror("no such line\n"), "no such line\n");
    }

    /// A stream cut short is reported with `perror`, whose text is whatever
    /// `errno` libc left behind. stuffr reproduces it as measured on macOS,
    /// where the comparison is exact; elsewhere only that one line is
    /// blanked on both sides, and everything else is still compared.
    #[test]
    fn decompress_truncated() {
        let big = mixed(300_000, 22);
        let Some(bz) = ref_bz(&big, "-2") else { return };
        let t = kib_text();
        let bzt = ref_bz(&t, "-9").unwrap();
        let mut cases = Vec::new();
        let files: Vec<(&str, Vec<u8>)> = vec![
            ("trunc.bz2", bz[..bz.len() / 2].to_vec()),
            ("short.bz2", bz[..20].to_vec()),
            ("empty.bz2", vec![]),
            ("tailb.bz2", [bzt.clone(), b"B".to_vec()].concat()),
            ("tailbzh.bz2", [bzt.clone(), b"BZh".to_vec()].concat()),
            ("bz.bz2", b"BZ".to_vec()),
        ];
        for (name, data) in &files {
            let name: &str = name;
            for args in [
                vec![name],
                vec!["-v", name],
                vec!["-q", name],
                vec!["-c", name],
                vec!["-t", name],
                vec!["-tv", name],
            ] {
                cases.push(case("bunzip2", &args, vec![(name, data.clone())]));
            }
            let mut c = case("bunzip2", &[], vec![]);
            c.stdin = Some(data.clone());
            cases.push(c);
            cases.push(case(
                "bunzip2",
                &[name, "a.bz2"],
                vec![(name, data.clone()), ("a.bz2", bzt.clone())],
            ));
        }
        // A character device (and, as stdin, /dev/null) is empty: cut short.
        cases.push(case("bunzip2", &["-c", "/dev/null"], vec![]));
        cases.push(case("bunzip2", &[], vec![]));
        if cfg!(target_os = "macos") {
            check_all("decompress_truncated", &cases);
        } else {
            check_all_with("decompress_truncated", &cases, perror_blanked);
        }
    }

    /// Existing outputs, `-k`, symlinks, non-regular and unreadable inputs,
    /// several operands, compressed suffixes, hard links, metadata.
    #[test]
    fn files() {
        let t = kib_text();
        let Some(bz) = ref_bz(&t, "-9") else { return };
        let a = || vec![("a.txt", t.clone())];
        let with_setup = |mut c: Case<'static>, f: fn(&Path)| {
            c.setup = Some(f);
            c
        };
        let long: &'static str = Box::leak("x".repeat(1100).into_boxed_str());
        let long_ok: &'static str = Box::leak("y".repeat(1024).into_boxed_str());
        let cases = vec![
            // existing output
            case(
                "bzip2",
                &["a.txt"],
                vec![("a.txt", t.clone()), ("a.txt.bz2", b"old".to_vec())],
            ),
            case(
                "bzip2",
                &["-f", "a.txt"],
                vec![("a.txt", t.clone()), ("a.txt.bz2", b"old".to_vec())],
            ),
            case(
                "bunzip2",
                &["a.bz2"],
                vec![("a.bz2", bz.clone()), ("a", b"old".to_vec())],
            ),
            case(
                "bunzip2",
                &["-f", "a.bz2"],
                vec![("a.bz2", bz.clone()), ("a", b"old".to_vec())],
            ),
            case(
                "bunzip2",
                &["-fk", "a.bz2"],
                vec![("a.bz2", bz.clone()), ("a", b"old".to_vec())],
            ),
            with_setup(case("bzip2", &["a.txt"], a()), dangling_output),
            with_setup(case("bzip2", &["-f", "a.txt"], a()), dangling_output),
            with_setup(case("bzip2", &["a.txt"], a()), empty_dir_output),
            with_setup(case("bzip2", &["-f", "a.txt"], a()), empty_dir_output),
            // keep and remove
            case("bzip2", &["-k", "a.txt"], a()),
            case("bzip2", &["a.txt"], a()),
            case("bunzip2", &["-k", "a.bz2"], vec![("a.bz2", bz.clone())]),
            // symlinks
            with_setup(case("bzip2", &["l.txt"], a()), link_l_txt),
            with_setup(case("bzip2", &["-f", "l.txt"], a()), link_l_txt),
            with_setup(case("bzip2", &["-c", "l.txt"], a()), link_l_txt),
            with_setup(
                case("bunzip2", &["l.bz2"], vec![("a.bz2", bz.clone())]),
                link_l_bz2,
            ),
            with_setup(
                case("bunzip2", &["-f", "l.bz2"], vec![("a.bz2", bz.clone())]),
                link_l_bz2,
            ),
            with_setup(
                case("bzip2", &["-t", "l.bz2"], vec![("a.bz2", bz.clone())]),
                link_l_bz2,
            ),
            // non-regular files (a character device stands in for a FIFO,
            // which would block the reference forever in its existence check)
            case("bzip2", &["/dev/null"], vec![]),
            case("bzip2", &["-f", "/dev/null"], vec![]),
            case("bzip2", &["-c", "/dev/null"], vec![]),
            case("bzip2", &["-t", "/dev/null"], vec![]),
            with_setup(case("bzip2", &["d"], vec![]), subdir),
            with_setup(case("bunzip2", &["d"], vec![]), subdir),
            with_setup(case("bzip2", &["-t", "d"], vec![]), subdir),
            with_setup(case("bzip2", &["-c", "d"], vec![]), subdir),
            // unreadable and missing
            with_setup(case("bzip2", &["a.txt"], a()), unreadable),
            with_setup(case("bunzip2", &["a.txt"], a()), unreadable),
            with_setup(case("bzip2", &["-t", "a.txt"], a()), unreadable),
            with_setup(case("bzip2", &["-c", "a.txt"], a()), unreadable),
            case("bzip2", &["missing"], vec![]),
            case("bunzip2", &["missing.bz2"], vec![]),
            case("bzcat", &["missing.bz2"], vec![]),
            case("bzip2", &["-t", "missing.bz2"], vec![]),
            case("bzip2", &[long], vec![]),
            case("bzip2", &[long_ok], vec![]),
            // several operands, the worst code wins
            case("bzip2", &["missing", "a.txt"], a()),
            case(
                "bzip2",
                &["a.txt", "missing", "b.txt"],
                vec![("a.txt", t.clone()), ("b.txt", b"b".to_vec())],
            ),
            case(
                "bunzip2",
                &["a.bz2", "missing.bz2", "plain.bz2"],
                vec![("a.bz2", bz.clone()), ("plain.bz2", t.clone())],
            ),
            case(
                "bzip2",
                &["-v", "a.txt", "much-longer-name.txt"],
                vec![("a.txt", t.clone()), ("much-longer-name.txt", t.clone())],
            ),
            // a compressed suffix is skipped on compress
            case("bzip2", &["a.bz2"], vec![("a.bz2", bz.clone())]),
            case("bzip2", &["-q", "a.bz"], vec![("a.bz", bz.clone())]),
            case("bzip2", &["-c", "a.tbz2"], vec![("a.tbz2", bz.clone())]),
            case(
                "bzip2",
                &["a.tbz", "a.txt"],
                vec![("a.tbz", bz.clone()), ("a.txt", t.clone())],
            ),
            // hard links
            with_setup(case("bzip2", &["a.txt"], a()), hard_link),
            with_setup(case("bzip2", &["a.txt"], a()), two_hard_links),
            with_setup(case("bzip2", &["-f", "a.txt"], a()), hard_link),
            with_setup(case("bzip2", &["-c", "a.txt"], a()), hard_link),
            // mtime and permissions copied
            with_setup(case("bzip2", &["a.txt"], a()), mode_640),
            with_setup(case("bzip2", &["-k", "a.txt"], a()), mode_640),
            with_setup(
                case("bunzip2", &["a.bz2"], vec![("a.bz2", bz.clone())]),
                mode_604_bz2,
            ),
            with_setup(
                case(
                    "bunzip2",
                    &["a.bz2"],
                    vec![("a.bz2", [bz.clone(), b"junk".to_vec()].concat())],
                ),
                mode_604_bz2,
            ),
            case("bzip2", &["sub/a.txt"], vec![("sub/a.txt", t.clone())]),
        ];
        // `bzip2 -f /dev/null` compresses the device and then removes its
        // input, as both tools do: run as root, that deletes /dev/null.
        let root = unsafe { libc::geteuid() } == 0;
        let cases: Vec<_> = cases
            .into_iter()
            .filter(|c| {
                let destructive = c.name == "bzip2" && c.args == ["-f", "/dev/null"];
                if root && destructive {
                    eprintln!(
                        "files: skipping `bzip2 -f /dev/null` as root (it removes /dev/null)"
                    );
                }
                !(root && destructive)
            })
            .collect();
        check_all("files", &cases);
    }

    /// No operands (stdin to stdout), `bzcat` over several files, and the
    /// terminal refusals.
    #[test]
    fn streams() {
        let t = kib_text();
        let Some(bz) = ref_bz(&t, "-9") else { return };
        let bz2 = ref_bz(b"second\n", "-5").unwrap();
        let piped = |name: &'static str, args: &[&'static str], data: Vec<u8>| {
            let mut c = case(name, args, vec![]);
            c.stdin = Some(data);
            c
        };
        let tty_in = |name: &'static str, args: &[&'static str]| {
            let mut c = case(name, args, vec![]);
            c.stdin = Some(t.clone());
            c.tty_stdin = true;
            c
        };
        let tty_out = |name: &'static str, args: &[&'static str], files| {
            let mut c = case(name, args, files);
            c.tty_stdout = true;
            c
        };
        let cases = vec![
            piped("bzip2", &[], t.clone()),
            piped("bzip2", &["-c"], t.clone()),
            piped("bzip2", &["-3"], t.clone()),
            piped("bunzip2", &[], bz.clone()),
            piped("bzcat", &[], bz.clone()),
            piped("bzip2", &["-d"], bz.clone()),
            piped("bzip2", &["-dv"], bz.clone()),
            piped("bzip2", &["-tv"], bz.clone()),
            piped("bzip2", &["-d", "-"], bz.clone()),
            case(
                "bzcat",
                &["a.bz2", "b.bz2"],
                vec![("a.bz2", bz.clone()), ("b.bz2", bz2.clone())],
            ),
            case(
                "bzcat",
                &["a.bz2", "plain", "b.bz2"],
                vec![
                    ("a.bz2", bz.clone()),
                    ("plain", t.clone()),
                    ("b.bz2", bz2.clone()),
                ],
            ),
            case(
                "bzip2",
                &["-c", "a.txt", "b.txt"],
                vec![("a.txt", t.clone()), ("b.txt", b"bee".to_vec())],
            ),
            case(
                "bzip2",
                &["-dc", "a.bz2", "b.bz2"],
                vec![("a.bz2", bz.clone()), ("b.bz2", bz2.clone())],
            ),
            tty_out("bzip2", &[], vec![]),
            tty_out("bzip2", &["-f"], vec![]),
            tty_out("bzip2", &["-c", "a.txt"], vec![("a.txt", t.clone())]),
            tty_out("bzip2", &["-cf", "a.txt"], vec![("a.txt", t.clone())]),
            tty_out(
                "bzip2",
                &["-c", "a.txt", "a.bz2"],
                vec![("a.txt", t.clone()), ("a.bz2", bz.clone())],
            ),
            tty_out("bzcat", &["a.bz2"], vec![("a.bz2", bz.clone())]),
            tty_out("bzip2", &["a.txt"], vec![("a.txt", t.clone())]),
            tty_in("bunzip2", &[]),
            tty_in("bunzip2", &["-f"]),
            tty_in("bzcat", &[]),
            tty_in("bzip2", &["-t"]),
            tty_in("bzip2", &["-tf"]),
            tty_in("bzip2", &["-c"]),
        ];
        check_all("streams", &cases);
    }

    /// Verbosity of two or more adds libbzip2's internal trace, which stuffr
    /// does not reproduce (a known deviation): exit code and files only.
    #[test]
    fn verbosity_two_and_above_exit_code_and_files() {
        let t = kib_text();
        let Some(bz) = ref_bz(&t, "-9") else { return };
        let cases = vec![
            case("bzip2", &["-vv", "a.txt"], vec![("a.txt", t.clone())]),
            case("bzip2", &["-vvvvv", "a.txt"], vec![("a.txt", t.clone())]),
            case("bunzip2", &["-vv", "a.bz2"], vec![("a.bz2", bz.clone())]),
            case("bzip2", &["-tvv", "a.bz2"], vec![("a.bz2", bz.clone())]),
        ];
        check_all_with("verbosity", &cases, |r, s| s.stderr = r.stderr.clone());
    }

    /// Review focus 3: a corrupt input leaves no output behind and keeps the
    /// input, exactly as bzip2 does.
    #[test]
    fn a_corrupt_input_leaves_no_output_and_keeps_the_input() {
        let big = mixed(400_000, 31);
        let Some(mut bz) = ref_bz(&big, "-1") else {
            return;
        };
        let mid = bz.len() / 2;
        bz[mid] ^= 0xff;
        let c = case("bunzip2", &["c.bz2"], vec![("c.bz2", bz.clone())]);
        let Some(r) = reference(REFERENCE_DIR, &c) else {
            return;
        };
        let s = stuffr_as(&c);
        assert_same(&c, &r, &s);
        assert_eq!(s.code, 2);
        assert_eq!(s.tree.len(), 1, "{:?}", s.tree.keys());
        assert_eq!(s.tree["c.bz2"].0, bz);
    }

    /// Run `exe big.bz2` with stdout a pipe whose read end is closed after
    /// the first read; how the process ended.
    fn closed_pipe_status(exe: &Path, dir: &Path) -> std::process::ExitStatus {
        use std::io::Read;
        let mut child = Command::new(exe)
            .arg("big.bz2")
            .current_dir(dir)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut buf = [0u8; 4096];
        let _ = out.read(&mut buf).unwrap();
        drop(out);
        let st = child.wait().unwrap();
        let mut err = String::new();
        let _ = child.stderr.take().unwrap().read_to_string(&mut err);
        assert_eq!(err, "", "{exe:?} wrote to stderr");
        st
    }

    /// bzip2 is killed by SIGPIPE writing to a closed pipe, silently, and so
    /// is stuffr as `bzcat` (it restores the signal's default action on the
    /// compatibility path only).
    #[test]
    fn a_closed_stdout_pipe_ends_bzcat_by_sigpipe() {
        use std::os::unix::process::ExitStatusExt;
        let plain = text(4 << 20, 51);
        let dir = std::env::temp_dir().join(format!("stuffr-sigpipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let link = dir.join("bin").join("bzcat");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        // Compress with stuffr itself, so the test runs without a reference.
        let zip = dir.join("bin").join("bzip2");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &zip).unwrap();
        std::fs::write(dir.join("big"), &plain).unwrap();
        let st = Command::new(&zip)
            .arg("big")
            .current_dir(&dir)
            .env_clear()
            .status()
            .unwrap();
        assert!(st.success());

        let ours = closed_pipe_status(&link, &dir);
        assert_eq!(
            ours.signal(),
            Some(libc::SIGPIPE),
            "stuffr as bzcat: {ours:?}"
        );
        let reference = Path::new(REFERENCE_DIR).join("bzcat");
        if require_reference(&reference) {
            let theirs = closed_pipe_status(&reference, &dir);
            assert_eq!(
                theirs.signal(),
                Some(libc::SIGPIPE),
                "reference: {theirs:?}"
            );
        } else {
            println!("skipped the reference half: bzcat not installed");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review focus 4: `bzcat` streams a 64 MiB input in bounded memory.
    ///
    /// The bound: stuffr's decoder holds one libbzip2 state (about 3.6 MB at
    /// `-9`, the bzip2 maximum), a 5000-byte input buffer and a 5000-byte
    /// output buffer, whatever the input size; 64 MiB of peak RSS is the
    /// asserted ceiling (the input alone would exceed it if it were held).
    #[test]
    fn bzcat_streams_a_large_input() {
        const N: usize = 64 << 20;
        let plain = mixed(N, 41);
        let Some(bz) = ref_bz(&plain, "-9") else {
            return;
        };
        #[cfg(target_os = "linux")]
        {
            let peak = linux_bzcat_peak(&bz, &plain);
            eprintln!("peak RSS (VmHWM): {:.1} MiB", peak as f64 / 1048576.0);
            assert!(peak < 64 << 20, "peak RSS {peak} bytes is not under 64 MiB");
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut c = case("bzcat", &["big.bz2"], vec![("big.bz2", bz)]);
            c.expect_stdout_plain = Some(plain.clone());
            let s = stuffr_as(&c);
            assert_eq!(s.code, 0, "{}", s.stderr);
            assert_eq!(s.stderr, "");
            assert!(s.stdout == plain, "decoded output differs");

            // SAFETY: `ru` is a valid out-pointer; getrusage only writes it.
            let ru = unsafe {
                let mut ru: libc::rusage = std::mem::zeroed();
                assert_eq!(libc::getrusage(libc::RUSAGE_CHILDREN, &mut ru), 0);
                ru
            };
            // macOS reports bytes. RUSAGE_CHILDREN is the largest child this
            // process has waited for, so it covers stuffr's run (and the
            // reference compressor's, which is smaller still). macOS spawns
            // without copying the parent, so the figure is the child's own.
            let peak = ru.ru_maxrss as u64;
            eprintln!("peak child RSS: {:.1} MiB", peak as f64 / 1048576.0);
            assert!(peak < 64 << 20, "peak RSS {peak} bytes is not under 64 MiB");
        }
    }

    /// Linux: run stuffr as `bzcat` on `bz` and return its peak RSS, from
    /// `/proc/<pid>/status`'s `VmHWM` sampled while it runs.
    ///
    /// Not `getrusage`: on Linux a child's `ru_maxrss` includes the parent's
    /// resident set at spawn (exec records the vforked mm's high-water mark),
    /// and this test process holds the 64 MiB input and its copies, so CI
    /// measured 264-268 MiB for a decoder that peaks near 15 MiB. `VmHWM`
    /// belongs to the post-exec mm alone and never decreases, so the last
    /// sample before exit is the peak up to that moment; the decoder's memory
    /// is flat after its first block, so sampling every 5 ms loses nothing.
    #[cfg(target_os = "linux")]
    fn linux_bzcat_peak(bz: &[u8], plain: &[u8]) -> u64 {
        use std::io::Read;
        let dir = std::env::temp_dir().join(format!("stuffr-rss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let link = dir.join("bin").join("bzcat");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        std::fs::write(dir.join("big.bz2"), bz).unwrap();
        let mut child = Command::new(&link)
            .arg("big.bz2")
            .current_dir(&dir)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let status = format!("/proc/{}/status", child.id());
        let mut out = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut v = Vec::new();
            out.read_to_end(&mut v).unwrap();
            v
        });
        let mut peak = 0u64;
        while child.try_wait().unwrap().is_none() {
            if let Ok(s) = std::fs::read_to_string(&status)
                && let Some(kb) = s
                    .lines()
                    .find_map(|l| l.strip_prefix("VmHWM:"))
                    .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            {
                peak = peak.max(kb * 1024);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let st = child.wait().unwrap();
        let got = reader.join().unwrap();
        let mut err = String::new();
        let _ = child.stderr.take().unwrap().read_to_string(&mut err);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(st.success(), "{st:?}: {err}");
        assert_eq!(err, "");
        assert!(got == plain, "decoded output differs");
        assert!(peak > 0, "VmHWM was never sampled");
        peak
    }
}
