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
//! `--target-compressed-block-size`. `-D` and `--patch-from` are Task 8's
//! (dictionaries), `--format=` Task 6's.

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
}
