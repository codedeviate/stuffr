//! lz4's compressed bytes, case by case: stuffr as `lz4` and `lz4c` against
//! lz4 1.10.0, over the spec's byte-identity catalogue.
//!
//! On the C tier (`lz4-c`) every output is compared byte for byte. On the
//! pure tier the same cases run with `compare_output_bytes: false`: the
//! reference decodes stuffr's output to the input (spec deviation 6).
//! Standard error, the exit code and the file tree are compared on both;
//! the cases run at `-q` or to standard output, so no summary (whose sizes
//! are the tier's own) is printed.
//!
//! The catalogue (spec section 4): four inputs (300 KB of text, `/bin/ls`,
//! 50 KB random, empty) at `--fast=5`, `-0` to `-12`, `--favor-decSpeed`,
//! each `-B`, `-BD`, `-BX`, `--no-frame-crc`, `--content-size`, `-l` and
//! `-D`, alone and combined; the inputs that cross a frame's 4 MiB jobs
//! and a legacy frame's 8 MiB blocks; the levels at the edge of `i32`
//! (ruling T3-d); `lz4c`'s legacy levels. `zstd --format=lz4` is Task 7's.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod bytes {
    use super::compat_harness::*;

    /// The C tier promises lz4's bytes.
    const EXACT: bool = cfg!(feature = "lz4-c");

    fn ref_lz4() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| format!("{}/lz4", lz4_dir().unwrap_or("/nonexistent")))
    }

    fn case(
        name: &'static str,
        args: Vec<&'static str>,
        files: Vec<(&'static str, Vec<u8>)>,
    ) -> Case<'static> {
        Case {
            name,
            args,
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("LC_ALL", "C")],
            compare_output_bytes: EXACT,
            tz: None,
            unzip_flavour: None,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Lz4 { ref_lz4: ref_lz4() },
        }
    }

    /// The spec's four inputs.
    fn inputs() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("text", text(300_000, 81)),
            ("ls", std::fs::read("/bin/ls").expect("/bin/ls")),
            ("random", random(50_000, 82)),
            ("empty", Vec::new()),
        ]
    }

    fn check(group: &str, cases: &[Case]) {
        let one = |c: &Case| -> bool {
            let Some(dir) = lz4_dir() else { return false };
            let Some(r) = reference(dir, c) else {
                return false;
            };
            let s = stuffr_as(c);
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
    }

    /// The catalogue's settings: every level, then every frame option
    /// alone and in the combinations the CLI's users reach for.
    const SETTINGS: [&[&str]; 35] = [
        &["--fast=5"],
        &["--fast=1"],
        &["-0"],
        &["-1"],
        &["-2"],
        &["-3"],
        &["-4"],
        &["-5"],
        &["-6"],
        &["-7"],
        &["-8"],
        &["-9"],
        &["-10"],
        &["-11"],
        &["-12"],
        &["--favor-decSpeed"],
        &["--favor-decSpeed", "-12"],
        &["-B4"],
        &["-B5"],
        &["-B6"],
        &["-B7"],
        &["-B32"],
        &["-B100000"],
        &["-BD"],
        &["-B4", "-BD"],
        &["-BX"],
        &["-B4", "-BD", "-BX", "-9"],
        &["--no-frame-crc"],
        &["--content-size"],
        &["--content-size", "-B4", "-BD"],
        &["-l"],
        &["-l", "-9"],
        &["-l", "--fast=3"],
        &["-D", "dict"],
        &["-D", "dict", "-B4", "-BD", "-9"],
    ];

    /// Every setting over every input, to standard output and to a file.
    #[test]
    fn the_catalogue_matches_the_reference() {
        let dict = text(80 << 10, 83);
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for set in SETTINGS {
                let mut files = vec![(name, data.clone())];
                if set.contains(&"-D") {
                    files.push(("dict", dict.clone()));
                }
                let mut out = vec!["-c"];
                out.extend(set.iter().copied());
                out.push(name);
                // Standard output holds the input's frame only (not the
                // dictionary's).
                cases.push(Case {
                    tz: None,
                    unzip_flavour: None,
                    expect_stdout_plain: Some(data.clone()),
                    ..case("lz4", out, files.clone())
                });
                let mut file = vec!["-q"];
                file.extend(set.iter().copied());
                file.push(name);
                cases.push(case("lz4", file, files));
            }
        }
        check("the_catalogue_matches_the_reference", &cases);
    }

    /// Inputs past one 4 MiB job (a streamed frame), exactly one job, and
    /// past a legacy block's 8 MiB, with the settings that change how the
    /// jobs join.
    #[test]
    fn large_inputs_match_the_reference() {
        let big = mixed(9 << 20, 84);
        let four = text(4 << 20, 85);
        let dict = text(80 << 10, 86);
        let mut cases = Vec::new();
        for (name, data) in [("big", big), ("four", four)] {
            for set in [
                &["-1"][..],
                &["-9"],
                &["--fast=4"],
                &["-B4", "-BD"],
                &["-B6", "-BX"],
                &["--content-size"],
                &["-l"],
                &["-D", "dict", "-BD"],
                &["-D", "dict"],
            ] {
                let mut files = vec![(name, data.clone())];
                if set.contains(&"-D") {
                    files.push(("dict", dict.clone()));
                }
                let mut args = vec!["-c"];
                args.extend(set.iter().copied());
                args.push(name);
                cases.push(Case {
                    tz: None,
                    unzip_flavour: None,
                    expect_stdout_plain: Some(data.clone()),
                    ..case("lz4", args, files)
                });
            }
        }
        check("large_inputs_match_the_reference", &cases);
    }

    /// Ruling T3-d: `--fast=2147483646`, `--fast=2147483647`,
    /// `--fast=2147483648`, `-2147483648` and `LZ4_CLEVEL=2147483648`, with
    /// and without `-l` (probe 2026-10-16: `i32::MIN` and, for frames,
    /// `i32::MIN + 1` write level 1's bytes; the rest are capped).
    #[test]
    fn extreme_levels_match_the_reference() {
        let data = text(300_000, 87);
        let mut cases = Vec::new();
        for legacy in [false, true] {
            for level in [
                "--fast=2147483646",
                "--fast=2147483647",
                "--fast=2147483648",
                "-2147483648",
            ] {
                let mut args = vec!["-c", level, "text"];
                if legacy {
                    args.insert(0, "-l");
                }
                cases.push(case("lz4", args, vec![("text", data.clone())]));
            }
            let args = if legacy {
                vec!["-l", "-c", "text"]
            } else {
                vec!["-c", "text"]
            };
            let mut c = case("lz4", args, vec![("text", data.clone())]);
            c.env.push(("LZ4_CLEVEL", "2147483648"));
            cases.push(c);
        }
        check("extreme_levels_match_the_reference", &cases);
    }

    /// `lz4c`'s legacy levels (`-c0`, `-c1`, `-c2`, `-hc`) write what the
    /// levels they stand for write.
    #[test]
    fn lz4c_legacy_levels_match_the_reference() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for set in [&["-c0"][..], &["-c1"], &["-c2"], &["-hc"]] {
                let mut args = vec!["-q"];
                args.extend(set.iter().copied());
                args.extend([name, "out.lz4"]);
                cases.push(case("lz4c", args, vec![(name, data.clone())]));
            }
        }
        check("lz4c_legacy_levels_match_the_reference", &cases);
    }
}
