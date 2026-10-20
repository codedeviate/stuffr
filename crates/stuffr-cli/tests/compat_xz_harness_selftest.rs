//! The xz side of the differential harness against itself: `assert_same`
//! must notice each single kind of difference and name it, the progress
//! normaliser must hide the timing fields and nothing else, and the
//! reference lookup must accept only XZ Utils 5.8.4.
//!
//! Every run here is REFERENCE-shaped: stuffr is never run as `xz` (the
//! binary answers to that name from Task 5 on), so the sensitivity tests
//! build two `Run`s by hand, or run the real `xz` twice.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::path::Path;

    /// The one real `-v` line a non-terminal stderr gets from 5.8.4 once the
    /// run has lasted past 3 s (recorded with `xz -v -9e -T1 -k r 2> err.txt`
    /// over 20 MB of random bytes): size, ratio, speed, elapsed time.
    const LONG_RUN: &str = "r: 19.1 MiB / 19.1 MiB = 1.000, 3.9 MiB/s, 0:04\n";
    /// The same run's line before 3 s (no speed) and before 1 s (no time):
    /// recorded from `xz -v -k b 2> err.txt` over 300 KB of one letter.
    const SHORT_RUN: &str = "b: 188 B / 300.8 KiB = 0.001\n";
    /// What the terminal progress line looks like (the harness cannot make
    /// stderr a terminal, so this one is from the source's format string,
    /// `message.c` `progress_flush`, and the brief's recorded example).
    const TTY_LINE: &str =
        "\r 100 %        1,234 B / 300.0 KiB = 0.004   1.2 MiB/s       0:00             \n";

    fn xz() -> Option<&'static str> {
        xz_dir()
    }

    fn roundtrip(dir: &str) -> Roundtrip {
        Roundtrip::Xz {
            ref_xz: Box::leak(format!("{dir}/xz").into_boxed_str()),
        }
    }

    fn case<'a>(dir: &str, args: Vec<&'a str>) -> Case<'a> {
        Case {
            name: "xz",
            args,
            files: vec![(
                "a",
                b"the quick brown fox jumps over the lazy dog\n".repeat(40),
            )],
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![],
            compare_output_bytes: true,
            tz: None,
            unzip_flavour: None,
            tty_ctl: false,
            tty_signal: None,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: roundtrip(dir),
        }
    }

    fn run(code: i32, stderr: &str) -> Run {
        Run {
            code,
            stdout: Vec::new(),
            stderr: stderr.to_owned(),
            tree: Tree::new(),
            start: now_secs(),
        }
    }

    fn verdict(c: &Case, r: &Run, s: &Run) -> Option<String> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_same(c, r, s)))
            .err()
            .map(panic_text)
    }

    #[test]
    fn reference_is_5_8_4() {
        let Some(dir) = xz() else {
            assert!(
                std::env::var_os("CI").is_none(),
                "xz_dir returned None under CI instead of panicking"
            );
            return;
        };
        let out = std::process::Command::new(format!("{dir}/xz"))
            .args(["--robot", "--version"])
            .env_clear()
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("XZ_VERSION=50080042"),
            "{out:?}"
        );
        for link in ["unxz", "xzcat", "lzma", "unlzma", "lzcat"] {
            assert!(Path::new(dir).join(link).exists(), "{dir}/{link}");
        }
    }

    #[test]
    fn normalise_hides_only_timing() {
        // Two runs of different speed and duration normalise equal...
        let a = normalise_xz_progress(LONG_RUN);
        let b = normalise_xz_progress("r: 19.1 MiB / 19.1 MiB = 1.000, 123 KiB/s, 1:02:03\n");
        assert_eq!(a, b);
        assert_eq!(a, "r: 19.1 MiB / 19.1 MiB = 1.000, <speed>, <elapsed>\n");
        assert_eq!(
            normalise_xz_progress("r: 19.1 MiB / 19.1 MiB = 1.000, 0.5 KiB/s, 0:01\n"),
            a
        );
        // ...including a line that has only an elapsed time, or neither.
        assert_eq!(
            normalise_xz_progress("r: 1 B / 2 B = 0.500, 0:01\n"),
            "r: 1 B / 2 B = 0.500, <elapsed>\n"
        );
        assert_eq!(normalise_xz_progress(SHORT_RUN), SHORT_RUN);
        // The terminal format too, whatever the column padding.
        let t = normalise_xz_progress(TTY_LINE);
        assert_eq!(
            t,
            normalise_xz_progress(
                "\r 100 %        1,234 B / 300.0 KiB = 0.004    12 KiB/s     1:02:03             \n"
            )
        );
        assert!(t.contains("<speed>") && t.contains("<elapsed>"), "{t:?}");
        // ...but a one-character change anywhere else does not.
        assert_ne!(
            a,
            normalise_xz_progress(&LONG_RUN.replace("1.000", "1.001"))
        );
        assert_ne!(
            a,
            normalise_xz_progress(&LONG_RUN.replace("19.1 MiB /", "19.2 MiB /"))
        );
        assert_ne!(a, normalise_xz_progress(&LONG_RUN.replace("r:", "q:")));
        assert_ne!(
            t,
            normalise_xz_progress(&TTY_LINE.replace("0.004", "0.005"))
        );
        // Lines that are not progress lines are untouched, timing-looking
        // text included.
        let msg = "xz: a: File format not recognized, 0:01\nxz: 3 MiB/s\n";
        assert_eq!(normalise_xz_progress(msg), msg);
    }

    #[test]
    fn assert_same_sees_one_byte_of_stderr() {
        let Some(dir) = xz() else { return };
        let c = case(dir, vec!["no-such-file"]);
        let r = run(1, "xz: no-such-file: No such file or directory\n");
        let same = run(1, "xz: no-such-file: No such file or directory\n");
        assert_eq!(verdict(&c, &r, &same), None);
        let s = run(1, "xz: no-such-file: No such file or directory.\n");
        let msg = verdict(&c, &r, &s).expect("assert_same missed a one-byte stderr difference");
        assert!(msg.contains("stderr differs"), "{msg}");
        assert!(msg.contains("in 1 way(s)"), "{msg}");
    }

    #[test]
    fn assert_same_sees_the_exit_code() {
        let Some(dir) = xz() else { return };
        let c = case(dir, vec!["no-such-file"]);
        let r = run(1, "xz: x\n");
        let s = run(2, "xz: x\n");
        let msg = verdict(&c, &r, &s).expect("assert_same missed an exit code difference");
        assert!(msg.contains("exit code: reference 1 vs stuffr 2"), "{msg}");
        assert!(msg.contains("in 1 way(s)"), "{msg}");
    }

    /// Through the real reference: a clean `-k` run twice is the same, and an
    /// output the reference cannot decode is caught when bytes are not promised.
    #[test]
    fn xz_outputs_are_judged_by_decoding() {
        let Some(dir) = xz() else { return };
        let mut c = case(dir, vec!["-k", "a"]);
        c.compare_output_bytes = false;
        let r = reference(dir, &c).unwrap();
        let s = reference(dir, &c).unwrap();
        assert_eq!(verdict(&c, &r, &s), None);
        // A stuffr output that is not a valid stream.
        let mut bad = reference(dir, &c).unwrap();
        let (bytes, mode, mtime) = bad.tree.get("a.xz").cloned().unwrap();
        let mut broken = bytes.clone();
        let n = broken.len();
        broken[n - 14] ^= 0xff; // the index/footer region
        bad.tree.insert("a.xz".into(), (broken, mode, mtime));
        let msg = verdict(&c, &r, &bad).expect("a corrupt a.xz was accepted");
        assert!(msg.contains("reference xz rejects stuffr's a.xz"), "{msg}");
    }
}
