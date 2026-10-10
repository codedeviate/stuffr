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
}
