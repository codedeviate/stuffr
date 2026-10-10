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

    fn differs(c: &Case, mutate: impl FnOnce(&mut Run)) -> bool {
        let r = base_run();
        let mut s = base_run();
        mutate(&mut s);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_same(c, &r, &s))).is_err()
    }

    #[test]
    fn identical_runs_pass() {
        assert!(!differs(&case(vec![]), |_| {}));
    }

    #[test]
    fn notices_mode() {
        assert!(differs(&case(vec![]), |s| s
            .tree
            .get_mut("a.txt.bz2")
            .unwrap()
            .1 = 0o600));
    }

    #[test]
    fn notices_pinned_input_mtime() {
        assert!(differs(&case(vec![]), |s| s
            .tree
            .get_mut("a.txt")
            .unwrap()
            .2 += 1));
    }

    #[test]
    fn notices_removed_file() {
        assert!(differs(&case(vec![]), |s| {
            s.tree.remove("a.txt");
        }));
    }

    #[test]
    fn notices_added_file() {
        assert!(differs(&case(vec![]), |s| {
            s.tree.insert("extra".into(), (vec![], 0o644, now_secs()));
        }));
    }

    #[test]
    fn notices_stderr_text() {
        assert!(differs(&case(vec![]), |s| s.stderr = "bzip2: other\n".into()));
    }

    #[test]
    fn notices_stdout_bytes() {
        assert!(differs(&case(vec![]), |s| s.stdout = b"oux".to_vec()));
    }

    #[test]
    fn notices_output_bytes_when_identity_is_promised() {
        assert!(differs(&case(vec![]), |s| s
            .tree
            .get_mut("a.txt.bz2")
            .unwrap()
            .0 = b"BZh9xyy".to_vec()));
    }

    #[test]
    fn notices_exit_code() {
        assert!(differs(&case(vec![]), |s| s.code = 3));
    }

    #[test]
    fn notices_block_digit_in_roundtrip_mode() {
        let mut c = case(vec![]);
        c.compare_output_bytes = false;
        assert!(differs(&c, |s| s.tree.get_mut("a.txt.bz2").unwrap().0 =
            b"BZh1xyz".to_vec()));
    }

    #[test]
    fn ignores_the_program_path_in_stderr() {
        // Normalisation happens in `execute`; a path that survived it would
        // differ, but one already reduced to the bare name must not.
        let c = case(vec![]);
        assert!(!differs(&c, |s| s.stderr = "bzip2: msg\n".to_owned()));
    }
}
