//! Apple gzip's compressed bytes, case by case: stuffr as `gzip` with
//! `STUFFR_GZIP_FLAVOR=bsd` against `/usr/bin/gzip`.
//!
//! On the C tier (`zlib-c`) every output is compared byte for byte: the
//! header, zlib's deflate stream and the trailer. stuffr vendors zlib 1.3.2
//! and Apple links 1.2.12, so this suite is also the check that the two
//! still deflate alike. On the compatible tier (miniz) the same cases run
//! with `compare_output_bytes: false`: the reference decodes stuffr's output
//! and the header is compared through FNAME.
//!
//! The matrix is the planning spike's: five inputs (300 KB of text, 300 KB
//! of binary, 50 KB of random bytes, empty, `abc` x 100000) at levels 1-9,
//! 45 cases, file to file. Then `-n` against the default, `-c` against file
//! output, and standard input (which stores the current time, masked by
//! `compat_harness::mask_stdin_mtimes`).
//!
//! macOS only (Ruling P7: the module is gated, not the file).

#[cfg(not(target_os = "macos"))]
#[test]
fn apple_gzip_is_the_reference_and_exists_only_on_macos() {
    println!("skipped: the Apple byte suite needs /usr/bin/gzip, which only macOS has");
}

#[cfg(target_os = "macos")]
mod compat_harness;

#[cfg(target_os = "macos")]
mod bytes {
    use super::compat_harness::*;

    /// The C tier promises Apple's bytes.
    const EXACT: bool = cfg!(feature = "zlib-c");

    fn gz<'a>(args: &[&'a str], files: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
        Case {
            name: "gzip",
            args: args.to_vec(),
            files,
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("STUFFR_GZIP_FLAVOR", "bsd")],
            compare_output_bytes: EXACT,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Gzip {
                ref_gzip: "/usr/bin/gzip",
            },
        }
    }

    /// A fixed binary pattern: a byte ramp with a slow second ramp mixed
    /// in, so it has structure but is not text.
    fn binary(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31) ^ ((i >> 9) as u8))
            .collect()
    }

    fn inputs() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("text", text(300_000, 21)),
            ("binary", binary(300_000)),
            ("random", random(50_000, 22)),
            ("empty", Vec::new()),
            ("abc", b"abc".repeat(100_000)),
        ]
    }

    fn check(group: &str, cases: &[Case]) {
        run_group(group, cases, Skipped::none(), &apple_compare);
    }

    /// The 45: every input at every level, file to file.
    #[test]
    fn every_level_of_every_input() {
        let levels = ["-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9"];
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for l in levels {
                cases.push(gz(&[l, name], vec![(name, data.clone())]));
            }
        }
        assert_eq!(cases.len(), 45);
        check("every_level_of_every_input", &cases);
    }

    /// `-n` against the default (no name, time 0), and `-N`.
    #[test]
    fn names_and_times() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for args in [&[][..], &["-n"], &["-N"], &["-n", "-9"], &["-n", "-1"]] {
                let mut a = args.to_vec();
                a.push(name);
                cases.push(gz(&a, vec![(name, data.clone())]));
            }
        }
        check("names_and_times", &cases);
    }

    /// `-c` against file output: the same member on standard output.
    #[test]
    fn stdout_and_files() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for args in [&["-c"][..], &["-c", "-1"], &["-c", "-9"], &["-cn"], &["-k"]] {
                let mut a = args.to_vec();
                a.push(name);
                cases.push(gz(&a, vec![(name, data.clone())]));
            }
        }
        let all = inputs();
        let names: Vec<&str> = all.iter().map(|(n, _)| *n).collect();
        let mut both = vec!["-c"];
        both.extend(&names);
        cases.push(gz(&both, all.clone()));
        let mut files = vec!["-6"];
        files.extend(&names);
        cases.push(gz(&files, all));
        check("stdout_and_files", &cases);
    }

    /// Standard input through a pipe, at three levels and with `-n`.
    #[test]
    fn standard_input() {
        let mut cases = Vec::new();
        for (_, data) in inputs() {
            for args in [&[][..], &["-1"], &["-9"], &["-n"], &["-c"]] {
                let mut c = gz(args, vec![]);
                c.stdin = Some(data.clone());
                cases.push(c);
            }
        }
        check("standard_input", &cases);
    }
}
