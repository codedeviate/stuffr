//! The zstd side of the differential harness against itself: `assert_same`
//! must notice each single kind of difference and name it, the progress
//! normaliser must hide the timing fields and nothing else, the help
//! normaliser must remove exactly the benchmark and trace blocks, and the
//! reference lookup must accept only zstd 1.5.7.
//!
//! Every run here is REFERENCE-shaped: stuffr is not run as `zstd` (the
//! binary answers to that name from Task 4 on), so the sensitivity tests
//! build two `Run`s by hand, or run the real `zstd` twice.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::path::Path;

    /// The one `-vv` completion line 1.5.7 prints (recorded with
    /// `zstd -vv -k -f b -o b.zst 2> err.txt` over 300 KB of one repeated
    /// word).
    const COMPLETED: &str = "b : Completed in 0.00 sec  (cpu load : 100%)\n";

    fn zstd() -> Option<&'static str> {
        zstd_dir()
    }

    fn case<'a>(dir: &str, args: Vec<&'a str>) -> Case<'a> {
        Case {
            name: "zstd",
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
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Zstd {
                ref_zstd: Box::leak(format!("{dir}/zstd").into_boxed_str()),
            },
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
    fn reference_is_1_5_7() {
        let Some(dir) = zstd() else {
            assert!(
                std::env::var_os("CI").is_none(),
                "zstd_dir returned None under CI instead of panicking"
            );
            return;
        };
        let out = |arg: &str| {
            let o = std::process::Command::new(format!("{dir}/zstd"))
                .arg(arg)
                .env_clear()
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        assert_eq!(out("-qV"), "1.5.7\n");
        let v = out("-vV");
        let supports = v.lines().nth(1).unwrap_or_default();
        for w in ["gzip", "lz4", "lzma", "xz"] {
            assert!(supports.contains(w), "{supports:?} lacks {w}");
        }
        for link in ["unzstd", "zstdcat", "zstdmt"] {
            assert!(Path::new(dir).join(link).exists(), "{dir}/{link}");
        }
    }

    #[test]
    fn normalise_hides_only_timing() {
        let a = normalise_zstd_progress(COMPLETED);
        assert_eq!(a, "b : Completed in <elapsed> sec  (cpu load : <cpu>%)\n");
        // Another speed and duration normalise equal...
        assert_eq!(
            a,
            normalise_zstd_progress("b : Completed in 12.34 sec  (cpu load : 367%)\n")
        );
        // ...a line around it is kept, and so is a name that looks like one.
        let doc = format!("b :  0.02%   (300000 B =>     56 B, b.zst)\n{COMPLETED}tail");
        assert_eq!(
            normalise_zstd_progress(&doc),
            format!("b :  0.02%   (300000 B =>     56 B, b.zst)\n{}tail", a)
        );
        // ...but a one-character change anywhere else does not.
        assert_ne!(a, normalise_zstd_progress(&COMPLETED.replace("b :", "c :")));
        assert_ne!(
            a,
            normalise_zstd_progress(&COMPLETED.replace("sec  (", "sec (")),
            "the two blanks are part of the shape"
        );
        let size = "b :  0.02%   (300000 B =>     56 B, b.zst)\n";
        assert_ne!(
            normalise_zstd_progress(size),
            normalise_zstd_progress(&size.replace("56 B", "57 B"))
        );
        // Text that is not the completion line is untouched, timing-looking
        // text included.
        let msg = "zstd: a: 3 sec  (cpu load : 4%)\nCompleted in soon\n\
                   Completed in 1.5 sec  (cpu load : x%)\n";
        assert_eq!(normalise_zstd_progress(msg), msg);
    }

    #[test]
    fn assert_same_sees_one_byte_of_stderr() {
        let Some(dir) = zstd() else { return };
        let c = case(dir, vec!["no-such-file"]);
        let r = run(
            1,
            "zstd: can't stat no-such-file : No such file or directory -- ignored\n",
        );
        let same = run(
            1,
            "zstd: can't stat no-such-file : No such file or directory -- ignored\n",
        );
        assert_eq!(verdict(&c, &r, &same), None);
        let s = run(
            1,
            "zstd: can't stat no-such-file : No such file or directory -- ignored.\n",
        );
        let msg = verdict(&c, &r, &s).expect("assert_same missed a one-byte stderr difference");
        assert!(msg.contains("stderr differs"), "{msg}");
        assert!(msg.contains("in 1 way(s)"), "{msg}");
    }

    #[test]
    fn assert_same_sees_the_exit_code() {
        let Some(dir) = zstd() else { return };
        let c = case(dir, vec!["no-such-file"]);
        let r = run(1, "zstd: x\n");
        let s = run(2, "zstd: x\n");
        let msg = verdict(&c, &r, &s).expect("assert_same missed an exit code difference");
        assert!(msg.contains("exit code: reference 1 vs stuffr 2"), "{msg}");
        assert!(msg.contains("in 1 way(s)"), "{msg}");
    }

    /// The reference's own `-H`, which lists `--trace` and the benchmark
    /// options (Homebrew builds without `ZSTD_NOTRACE` and `ZSTD_NOBENCH`).
    fn reference_help(dir: &str) -> String {
        let o = std::process::Command::new(format!("{dir}/zstd"))
            .arg("-H")
            .env_clear()
            .output()
            .unwrap();
        String::from_utf8(o.stdout).unwrap()
    }

    #[test]
    fn strip_bench_help_removes_only_the_bench_block() {
        let Some(dir) = zstd() else { return };
        let help = reference_help(dir);
        // The pinned blocks are what the reference prints, once each.
        assert_eq!(help.matches(ZSTD_BENCH_HELP).count(), 1, "bench block");
        assert_eq!(help.matches(ZSTD_TRACE_HELP).count(), 1, "trace line");
        let stripped = strip_bench_help(&help);
        assert!(!stripped.contains("Benchmark options"), "{stripped}");
        assert!(!stripped.contains("--trace"), "{stripped}");
        assert!(!stripped.contains("--priority"), "{stripped}");
        assert_eq!(
            stripped.len(),
            help.len() - ZSTD_BENCH_HELP.len() - ZSTD_TRACE_HELP.len()
        );
        // Everything else is there, in order: re-inserting the two blocks
        // where they were gives the original back.
        let at_trace = help.find(ZSTD_TRACE_HELP).unwrap();
        let at_bench = help.find(ZSTD_BENCH_HELP).unwrap() - ZSTD_TRACE_HELP.len();
        let mut back = stripped.clone();
        back.insert_str(at_bench, ZSTD_BENCH_HELP);
        back.insert_str(at_trace, ZSTD_TRACE_HELP);
        assert_eq!(back, help);
        // A help that already lacks them, and the short help, are unchanged.
        assert_eq!(strip_bench_help(&stripped), stripped);
        assert_eq!(strip_bench_help("zstd: bad usage\n"), "zstd: bad usage\n");
        // A different benchmark section is not removed: one changed byte
        // keeps the block, so the comparison fails on it.
        let altered = help.replace("Default: 3]\n  -e#", "Default: 4]\n  -e#");
        assert_ne!(altered, help);
        assert!(strip_bench_help(&altered).contains("Benchmark options"));
    }

    /// Through the real reference: a clean `-k` run twice is the same, a
    /// stream of another kind is named, and an output the reference cannot
    /// decode is caught when bytes are not promised.
    #[test]
    fn zstd_outputs_are_judged_by_decoding() {
        let Some(dir) = zstd() else { return };
        let mut c = case(dir, vec!["-k", "a"]);
        c.compare_output_bytes = false;
        let r = reference(dir, &c).unwrap();
        let s = reference(dir, &c).unwrap();
        assert_eq!(verdict(&c, &r, &s), None);
        // A stuffr output that is not a valid frame.
        let mut bad = reference(dir, &c).unwrap();
        let (bytes, mode, mtime) = bad.tree.get("a.zst").cloned().unwrap();
        let mut broken = bytes.clone();
        let n = broken.len();
        broken[n - 6] ^= 0xff;
        bad.tree.insert("a.zst".into(), (broken, mode, mtime));
        let msg = verdict(&c, &r, &bad).expect("a corrupt a.zst was accepted");
        assert!(
            msg.contains("reference zstd rejects stuffr's a.zst"),
            "{msg}"
        );
        // A gzip member where a zstd frame was promised.
        let mut gz = reference(dir, &c).unwrap();
        let (_, mode, mtime) = gz.tree.get("a.zst").cloned().unwrap();
        let member = case(dir, vec!["-k", "--format=gzip", "a"]);
        let g = reference(dir, &member).unwrap();
        let (gbytes, _, _) = g.tree.get("a.gz").cloned().unwrap();
        gz.tree.insert("a.zst".into(), (gbytes, mode, mtime));
        let msg = verdict(&c, &r, &gz).expect("a gzip member passed for a zstd frame");
        assert!(
            msg.contains("stream format differs: reference zstd, stuffr gzip"),
            "{msg}"
        );
    }
}
