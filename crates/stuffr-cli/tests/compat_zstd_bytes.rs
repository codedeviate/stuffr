//! zstd's compressed bytes, case by case: stuffr as `zstd` and `zstdmt`
//! against zstd 1.5.7, over the spec's byte-identity catalogue.
//!
//! On the C tier (`zstd-c`) every output is compared byte for byte. On the
//! pure tier the same cases run with `compare_output_bytes: false`: the
//! reference decodes stuffr's output to the input (spec deviation 7: one
//! `Fastest` frame whatever the parameters). Standard error, the exit code
//! and the file tree are compared on both; the cases run at `-q` or to
//! standard output, so no summary (whose sizes are the tier's own) is
//! printed.
//!
//! The catalogue: four inputs (300 KB of text, `/bin/ls`, 50 KB random,
//! empty) at `--fast=5`, `-3`, 1-19 and `--ultra` 20-22; `-T1`, `-T4` and
//! `zstdmt`; `--long`, `--long=30`, `--rsyncable`, `--no-check`,
//! `--no-content-size`, `--stream-size`, `--zstd=wlog=…` and
//! `--target-compressed-block-size`.
//!
//! Dictionaries (Task 8): `-D` with the reference's trained dictionary and
//! with raw content, and `--patch-from`, over the inputs at levels 1, 3,
//! 19 and `--fast=3`, with `--long` and threads. The pure tier refuses to
//! compress with either (spec deviation 7), which is pinned instead.
//!
//! `--format=` (Task 6), over the same four inputs at levels 1, 3, 9, 19,
//! 0 and `--fast=1`: gzip is compared byte for byte with C zlib (`zlib-c`;
//! spike S2 measured zlib's deflate and header identical to the
//! reference's, the OS byte included), xz and lzma with liblzma (`xz-c`,
//! 5.8.4 on both sides) and lz4 with liblz4 (`lz4-c`, 1.10.0 via
//! `stuffr::lz4_opts`); elsewhere the reference decodes stuffr's output to
//! the input.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod bytes {
    use super::compat_harness::*;

    /// The C tier promises zstd's bytes.
    const EXACT: bool = cfg!(feature = "zstd-c");

    fn ref_zstd() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| format!("{}/zstd", zstd_dir().unwrap_or("/nonexistent")))
    }

    fn case<'a>(name: &'a str, args: Vec<&'a str>, files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        Case {
            name,
            args,
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("LC_ALL", "C")],
            compare_output_bytes: EXACT,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Zstd {
                ref_zstd: ref_zstd(),
            },
        }
    }

    /// The spec's four inputs.
    fn inputs() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("text", text(300_000, 71)),
            ("ls", std::fs::read("/bin/ls").expect("/bin/ls")),
            ("random", random(50_000, 72)),
            ("empty", Vec::new()),
        ]
    }

    fn check(group: &str, cases: &[Case]) {
        let one = |c: &Case| -> bool {
            let Some(dir) = zstd_dir() else { return false };
            let Some(r) = reference(dir, c) else {
                return false;
            };
            let s = stuffr_as(c);
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
    }

    /// `--fast=5`, `-3`, 1-19 and `--ultra` 20-22.
    fn levels() -> Vec<Vec<&'static str>> {
        const DIGITS: [&str; 22] = [
            "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9", "-10", "-11", "-12", "-13",
            "-14", "-15", "-16", "-17", "-18", "-19", "-20", "-21", "-22",
        ];
        let mut v = vec![vec!["--fast=5"], vec!["--fast=3"]];
        for (i, d) in DIGITS.iter().enumerate() {
            if i >= 19 {
                v.push(vec!["--ultra", d]);
            } else {
                v.push(vec![d]);
            }
        }
        v
    }

    /// Every level over every input, file to file and to standard output.
    #[test]
    fn every_level_of_every_input() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for level in levels() {
                let mut file = vec!["-q", "-k"];
                file.extend(level.iter().copied());
                file.push(name);
                cases.push(case("zstd", file, vec![(name, data.clone())]));
                let mut out = vec!["-c"];
                out.extend(level.iter().copied());
                out.push(name);
                cases.push(case("zstd", out, vec![(name, data.clone())]));
            }
        }
        check("every_level_of_every_input", &cases);
    }

    /// The thread counts and `zstdmt`, at the default level and at 19.
    #[test]
    fn threads() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for args in [
                &["-T1"][..],
                &["-T4"],
                &["-T0"],
                &["--single-thread"],
                &["-19", "-T4"],
            ] {
                let mut a = vec!["-c"];
                a.extend(args.iter().copied());
                a.push(name);
                cases.push(case("zstd", a, vec![(name, data.clone())]));
            }
            cases.push(case("zstdmt", vec!["-c", name], vec![(name, data.clone())]));
        }
        check("threads", &cases);
    }

    /// The frame and parameter options.
    #[test]
    fn parameters() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for args in [
                &["--long"][..],
                &["--long=30"],
                &["--rsyncable"],
                &["--no-check"],
                &["--no-content-size"],
                &["--zstd=wlog=20,clog=16,hlog=17,slog=3,mml=5,tlen=16,strat=5"],
                &["--zstd=wlog=23"],
                &["--target-compressed-block-size=2000"],
                &["-19", "--long", "-T1"],
            ] {
                let mut a = vec!["-c"];
                a.extend(args.iter().copied());
                a.push(name);
                cases.push(case("zstd", a, vec![(name, data.clone())]));
            }
            // --stream-size describes standard input.
            let size = format!("--stream-size={}", data.len());
            let size: &'static str = Box::leak(size.into_boxed_str());
            let mut c = case("zstd", vec!["-c", size], Vec::new());
            c.stdin = Some(data.clone());
            cases.push(c);
            let mut c = case("zstd", vec!["-c"], Vec::new());
            c.stdin = Some(data.clone());
            cases.push(c);
        }
        check("parameters", &cases);
    }

    /// Whether `--format=f`'s bytes are promised on this build.
    fn foreign_exact(f: &str) -> bool {
        (f == "gzip" && cfg!(feature = "zlib-c"))
            || (matches!(f, "xz" | "lzma") && cfg!(feature = "xz-c"))
            || (f == "lz4" && cfg!(feature = "lz4-c"))
    }

    /// `--format=gzip|xz|lzma|lz4` over every input, file to file and to
    /// standard output.
    #[test]
    fn foreign_formats() {
        let mut cases = Vec::new();
        for f in ["gzip", "xz", "lzma", "lz4"] {
            let fa: &'static str = Box::leak(format!("--format={f}").into_boxed_str());
            for level in ["-1", "-3", "-9", "-19", "-0", "--fast=1"] {
                for (name, data) in inputs() {
                    for mut args in [vec!["-q", "-k"], vec!["-c"]] {
                        args.extend([fa, level, name]);
                        let mut c = case("zstd", args, vec![(name, data.clone())]);
                        c.compare_output_bytes = foreign_exact(f);
                        cases.push(c);
                    }
                }
            }
        }
        check("foreign_formats", &cases);
    }

    /// 0.15.0 Task 7: `--format=lz4` is plain `LZ4F` streaming (64 KiB
    /// linked blocks, content size and checksum, level capped at 12), which
    /// `lz4_opts::Encoder::new_plain` reproduces: byte-identical on the C
    /// tier (compared on the pure tier by decoding), from files, to standard
    /// output and from standard input (content size unknown), at the levels
    /// either side of liblz4's HC switch (3) and cap (12), over inputs of
    /// zero, one and several blocks.
    #[test]
    fn zstd_format_lz4_is_byte_identical() {
        let mut inputs = inputs();
        inputs.push(("one", b"x".to_vec()));
        inputs.push(("block", text(65_536, 75)));
        inputs.push(("big", text(1_500_000, 76)));
        let exact_lz4 = EXACT_LZ4 && zstd_lz4_is_1_10();
        let mut cases = Vec::new();
        for level in [
            "-1", "-2", "-3", "-4", "-9", "-12", "-13", "-19", "--fast=3", "-0",
        ] {
            for (name, data) in &inputs {
                for extra in [&[][..], &["--no-check"], &["--no-content-size"]] {
                    let mut a = vec!["-c", "--format=lz4", level];
                    a.extend(extra.iter().copied());
                    a.push(name);
                    let mut c = case("zstd", a, vec![(name, data.clone())]);
                    c.compare_output_bytes = exact_lz4;
                    cases.push(c);
                }
                let mut a = vec!["-q", "-k", "--format=lz4", level];
                a.push(name);
                let mut c = case("zstd", a, vec![(name, data.clone())]);
                c.compare_output_bytes = exact_lz4;
                cases.push(c);
                // Standard input: the size is not known.
                let mut c = case("zstd", vec!["-c", "--format=lz4", level], Vec::new());
                c.stdin = Some(data.clone());
                c.compare_output_bytes = exact_lz4;
                cases.push(c);
            }
        }
        check("zstd_format_lz4_is_byte_identical", &cases);
    }

    /// Whether `--format=lz4`'s bytes are promised on this build.
    const EXACT_LZ4: bool = cfg!(feature = "lz4-c");

    /// Spec deviation 7: the pure tier's answer to compressing with a
    /// dictionary or a prefix, `EXM_THROW(1, …)`.
    const PURE_REFUSAL: &str = "zstd: error 1 : dictionary compression is not available in this build (stuffr pure tier) \n";

    /// The C tier compares as [`check`]; the pure tier pins the refusal
    /// (every case here compresses quietly, so it is all stuffr prints).
    fn check_dictionary(group: &str, cases: &[Case]) {
        if EXACT {
            check(group, cases);
            return;
        }
        let one = |c: &Case| -> bool {
            if zstd_dir().is_none() {
                return false;
            }
            let s = stuffr_as(c);
            assert_eq!(
                (s.code, s.stderr.as_str()),
                (1, PURE_REFUSAL),
                "{:?}",
                c.args
            );
            assert!(s.stdout.is_empty(), "{:?}", c.args);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
    }

    fn dict_levels() -> [&'static [&'static str]; 6] {
        [
            &["-1"],
            &["-3"],
            &["-19"],
            &["--fast=3"],
            &["-3", "-T2"],
            &["-19", "--long"],
        ]
    }

    /// `-D`: the reference's trained dictionary and raw content, every
    /// input, the levels, to standard output and to a file.
    #[test]
    fn dictionary_bytes() {
        let dict = zstd_trained_dictionary().unwrap_or_default().to_vec();
        let raw = text(6000, 73);
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for level in dict_levels() {
                for d in ["dict", "raw"] {
                    let files = vec![
                        (name, data.clone()),
                        ("dict", dict.clone()),
                        ("raw", raw.clone()),
                    ];
                    let mut a = vec!["-c", "-D", d];
                    a.extend(level.iter().copied());
                    a.push(name);
                    cases.push(case("zstd", a, files.clone()));
                    let mut a = vec!["-q", "-k", "-D", d, "--no-dictID"];
                    a.extend(level.iter().copied());
                    a.push(name);
                    cases.push(case("zstd", a, files));
                }
            }
        }
        check_dictionary("dictionary_bytes", &cases);
    }

    /// `--patch-from`: an old file and a new one that differs in a few
    /// places, both ways round, at the levels.
    #[test]
    fn patch_from_bytes() {
        let old = text(300_000, 74);
        let mut new = old.clone();
        for (i, at) in [10_000usize, 90_000, 150_000, 280_000].iter().enumerate() {
            new.splice(*at..*at, format!("<edit {i}>").into_bytes());
        }
        let files = vec![("old", old), ("new", new), ("ls", inputs()[1].1.clone())];
        let mut cases = Vec::new();
        for level in dict_levels() {
            for (from, to) in [("old", "new"), ("new", "old"), ("old", "ls")] {
                let p: &'static str = Box::leak(format!("--patch-from={from}").into_boxed_str());
                let mut a = vec!["-c", p];
                a.extend(level.iter().copied());
                a.push(to);
                cases.push(case("zstd", a, files.clone()));
            }
        }
        cases.push(case(
            "zstd",
            vec!["-q", "-k", "--patch-from", "old", "-o", "p.zst", "new"],
            files,
        ));
        check_dictionary("patch_from_bytes", &cases);
    }
}
