//! brotli's compressed bytes, case by case: stuffr as `brotli` against
//! brotli 1.2.1.
//!
//! On the C tier (`brotli-c`, libbrotli 1.2.1 driven as `c/tools/brotli.c`
//! drives it) every `.br` is compared byte for byte. On the pure tier the
//! same cases run with `compare_output_bytes: false`: the reference decodes
//! stuffr's stream back to the input. `-D` is refused there (ruling T1-b):
//! its cases check the refusal instead. Standard error, the exit code and
//! the file tree are compared on both.
//!
//! The inputs are made here, deterministically: empty, one byte, 158 KB of
//! text, 300 KB of random bytes and 3 MiB of mixed data (text, random runs
//! and long repeats).

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod bytes {
    use super::compat_harness::*;

    /// The C tier promises the reference's bytes.
    const EXACT: bool = cfg!(feature = "brotli-c");

    fn ref_brotli() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| format!("{}/brotli", brotli_dir().unwrap_or("/nonexistent")))
    }

    fn case(
        args: Vec<String>,
        files: Vec<(&'static str, Vec<u8>)>,
        plain: Vec<u8>,
    ) -> Case<'static> {
        let args: Vec<&'static str> = args
            .into_iter()
            .map(|a| &*Box::leak(a.into_boxed_str()))
            .collect();
        Case {
            name: "brotli",
            args,
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("LC_ALL", "C")],
            compare_output_bytes: EXACT,
            tz: None,
            unzip_flavour: None,
            zip_flavour: None,
            zip_tree: None,
            tty_ctl: false,
            tty_signal: None,
            expect_stdout_plain: Some(plain),
            setup: None,
            roundtrip: Roundtrip::Brotli {
                ref_brotli: ref_brotli(),
            },
        }
    }

    fn inputs() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one", b"x".to_vec()),
            ("text", text(158_000, 91)),
            ("random", random(300_000, 92)),
            ("mixed", mixed(3 << 20, 93)),
        ]
    }

    fn check(group: &str, cases: &[Case]) {
        let one = |c: &Case| -> bool {
            let Some(dir) = brotli_dir() else {
                return false;
            };
            let Some(r) = reference(dir, c) else {
                return false;
            };
            let s = stuffr_as(c);
            assert_same(c, &r, &s);
            true
        };
        let start = std::time::Instant::now();
        run_group(group, cases, Skipped::none(), &one);
        println!("{group}: {:.1} s", start.elapsed().as_secs_f64());
    }

    /// Every quality 0..=11 at windows 0 (chosen by size), 10, 16, 22, 24.
    #[test]
    fn bytes_match_every_quality_and_window() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for q in 0..=11 {
                for w in [0, 10, 16, 22, 24] {
                    let args = vec![
                        "-c".into(),
                        "-q".into(),
                        q.to_string(),
                        "-w".into(),
                        w.to_string(),
                        name.into(),
                    ];
                    cases.push(case(args, vec![(name, data.clone())], data.clone()));
                }
            }
        }
        check("bytes_match_every_quality_and_window", &cases);
    }

    /// Inputs of exactly one and two read buffers (`PROCESS` of a full
    /// buffer, then `FINISH` of nothing), and one past 16 MiB (the chosen
    /// window stops at 24 and the input outgrows it), at the default
    /// window, to a file and from standard input.
    #[test]
    fn large_input_bytes_match() {
        let mut cases = Vec::new();
        for (name, data, qualities) in [
            ("buf1", mixed(1 << 19, 95), &[0, 5, 11][..]),
            ("buf2", text(2 << 19, 96), &[1, 9, 11][..]),
            ("big", mixed(17 << 20, 97), &[1, 5, 9][..]),
        ] {
            for q in qualities {
                let args = vec!["-q".into(), q.to_string(), name.into()];
                cases.push(case(args, vec![(name, data.clone())], data.clone()));
                let mut c = case(
                    vec!["-c".into(), "-q".into(), q.to_string()],
                    vec![],
                    data.clone(),
                );
                c.stdin = Some(data.clone());
                cases.push(c);
            }
        }
        check("large_input_bytes_match", &cases);
    }

    /// `--large_window` 25 and 30 (`BROTLI_PARAM_LARGE_WINDOW` set), and
    /// `-w 0` from standard input (24).
    #[test]
    fn large_window_bytes_match() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for w in [25, 30] {
                for q in [1, 5, 9, 11] {
                    let args = vec![
                        "-c".into(),
                        format!("--large_window={w}"),
                        "-q".into(),
                        q.to_string(),
                        name.into(),
                    ];
                    cases.push(case(args, vec![(name, data.clone())], data.clone()));
                }
            }
            let mut c = case(
                vec!["-c".into(), "-q".into(), "9".into()],
                vec![],
                data.clone(),
            );
            c.stdin = Some(data.clone());
            cases.push(c);
        }
        check("large_window_bytes_match", &cases);
    }

    /// `-C`: the comment is a metadata block before the data.
    #[test]
    fn comment_bytes_match() {
        // `foo`, one byte, and the 80-byte maximum.
        let max = "QUFB".repeat(26) + "QUE=";
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for comment in ["Zm9v", "Zg==", max.as_str()] {
                for q in [0, 5, 11] {
                    let args = vec![
                        "-c".into(),
                        "-C".into(),
                        comment.into(),
                        "-q".into(),
                        q.to_string(),
                        name.into(),
                    ];
                    cases.push(case(args, vec![(name, data.clone())], data.clone()));
                }
            }
            // To a file, with a large window.
            let args = vec![
                "-C".into(),
                "Zm9v".into(),
                "--large_window=26".into(),
                "-q".into(),
                "4".into(),
                name.into(),
            ];
            cases.push(case(args, vec![(name, data.clone())], data.clone()));
        }
        if EXACT {
            check("comment_bytes_match", &cases);
            return;
        }
        // The pure tier refuses a one-byte comment (its encoder would write
        // that metadata block's header wrong): `failed to emit metadata`.
        let (one, rest): (Vec<_>, Vec<_>) =
            cases.into_iter().partition(|c| c.args.contains(&"Zg=="));
        check("comment_bytes_match", &rest);
        for c in &one {
            let s = stuffr_as(c);
            let input = c.args.last().unwrap();
            assert_eq!(
                (s.code, s.stderr.clone(), s.stdout.len()),
                (1, format!("failed to emit metadata [{input}]\n"), 0),
                "{:?}",
                c.args
            );
        }
    }

    /// `-D`: a raw dictionary (C tier); the pure tier refuses it.
    #[test]
    fn dictionary_bytes_match() {
        let dict = text(64 << 10, 94);
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for q in [0, 2, 5, 9, 10, 11] {
                for w in ["0", "18", "24"] {
                    let args = vec![
                        "-c".into(),
                        "-D".into(),
                        "dict".into(),
                        "-q".into(),
                        q.to_string(),
                        "-w".into(),
                        w.into(),
                        name.into(),
                    ];
                    cases.push(case(
                        args,
                        vec![(name, data.clone()), ("dict", dict.clone())],
                        data.clone(),
                    ));
                }
            }
        }
        if EXACT {
            check("dictionary_bytes_match", &cases);
            return;
        }
        for c in &cases {
            let s = stuffr_as(c);
            assert_eq!(
                (s.code, s.stderr.as_str(), s.stdout.len()),
                (
                    1,
                    "-D is not supported by this build (pure tier); build with --features brotli-c\n",
                    0
                ),
                "{:?}",
                c.args
            );
        }
    }
}
