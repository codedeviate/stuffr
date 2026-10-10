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
    #[ignore = "enabled by Task 4"]
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
