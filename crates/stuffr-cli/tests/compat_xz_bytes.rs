//! xz's compressed bytes, case by case: stuffr as `xz` and `lzma` against
//! XZ Utils 5.8.4, over the compression catalogue.
//!
//! On the C tier (`xz-c`) every output is compared byte for byte: `.xz`,
//! `.lzma` and raw, whatever the preset, check, thread count, Block size,
//! Block list or filter chain. On the pure tier the same cases run with
//! `compare_output_bytes: false`: the reference decodes stuffr's output to
//! the input, and an `.xz` stream header (magic, flags, check) is compared.
//! Standard error, the exit code and the file tree are compared on both.
//!
//! The catalogue: presets 0-9 with and without `-e` over six inputs (empty,
//! 1 B, 1 KiB of text, 1 MiB mixed, 1 MiB random, 1 MiB repetitive); each
//! `--check`; `-T0`/`-T1`/`-T4`/`-T+1`; `--block-size`; `--block-list`
//! with `--filtersN`; every BCJ filter, delta, and the `--lzma1=`/
//! `--lzma2=`/`--filters=` option strings; `.lzma` and raw. The 4 MiB
//! repetitive input runs at the default preset and thread counts only:
//! `-e` over it costs about 8 s a preset on the pure tier's debug build.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod bytes {
    use super::compat_harness::*;

    /// The C tier promises xz's bytes.
    const EXACT: bool = cfg!(feature = "xz-c");

    fn ref_xz() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| format!("{}/xz", xz_dir().unwrap_or("/nonexistent")))
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
            tz: None,
            unzip_flavour: None,
            zip_flavour: None,
            zip_tree: None,
            tty_ctl: false,
            tty_signal: None,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Xz { ref_xz: ref_xz() },
        }
    }

    /// `xz ARGS NAME` over the one input `NAME`.
    fn xz<'a>(args: &[&'a str], name: &'a str, data: Vec<u8>) -> Case<'a> {
        let mut a = args.to_vec();
        a.push(name);
        case("xz", a, vec![(name, data)])
    }

    fn inputs() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one", b"x".to_vec()),
            ("text", text(1024, 61)),
            ("mixed", mixed(1 << 20, 62)),
            ("random", random(1 << 20, 63)),
            ("rep", repetitive(1 << 20)),
        ]
    }

    fn mixed_1m() -> Vec<u8> {
        mixed(1 << 20, 62)
    }

    fn rep_4m() -> Vec<u8> {
        repetitive(4 << 20)
    }

    fn check(group: &str, cases: &[Case]) {
        let one = |c: &Case| -> bool {
            let Some(dir) = xz_dir() else { return false };
            let Some(r) = reference(dir, c) else {
                return false;
            };
            let s = stuffr_as(c);
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
    }

    const PRESETS: [&str; 20] = [
        "-0", "-0e", "-1", "-1e", "-2", "-2e", "-3", "-3e", "-4", "-4e", "-5", "-5e", "-6", "-6e",
        "-7", "-7e", "-8", "-8e", "-9", "-9e",
    ];

    /// Every preset, with and without `-e`, over every input, file to file
    /// (the input removed, `NAME.xz` made with its mode and mtime).
    #[test]
    fn every_preset_of_every_input() {
        let mut cases = Vec::new();
        for (name, data) in inputs() {
            for p in PRESETS {
                cases.push(xz(&[p], name, data.clone()));
            }
        }
        for p in ["-6", "-9"] {
            cases.push(xz(&[p], "rep4", rep_4m()));
        }
        check("every_preset_of_every_input", &cases);
    }

    /// Each `--check`, to a file and to standard output.
    #[test]
    fn checks() {
        let mut cases = Vec::new();
        for (long, c) in [
            ("--check=none", "none"),
            ("--check=crc32", "crc32"),
            ("--check=crc64", "crc64"),
            ("--check=sha256", "sha256"),
        ] {
            for (name, data) in [("text", text(1024, 61)), ("mixed", mixed_1m())] {
                cases.push(xz(&[long], name, data.clone()));
                cases.push(xz(&["-C", c, "-c", "-T1"], name, data));
            }
        }
        check("checks", &cases);
    }

    /// The thread counts: `-T0` (the default), one thread single-threaded,
    /// four, and one thread in threaded mode; with `--block-size`.
    #[test]
    fn threads_and_block_size() {
        let mut cases = Vec::new();
        for t in ["-T0", "-T1", "-T4", "-T+1", "--threads=2"] {
            cases.push(xz(&[t, "-c"], "mixed", mixed_1m()));
            cases.push(xz(&[t, "-c"], "rep4", rep_4m()));
            cases.push(xz(&[t, "--block-size=1MiB", "-c"], "mixed", mixed_1m()));
            cases.push(xz(&[t, "--block-size=1MiB", "-c"], "rep4", rep_4m()));
        }
        cases.push(xz(&["-T1", "--block-size=1000"], "text", text(1024, 61)));
        check("threads_and_block_size", &cases);
    }

    /// `--block-list`: as the brief has it (refused: `--filters1` lacks its
    /// LZMA2), then working chains, single- and multi-threaded, and with
    /// `--block-size` splitting its entries.
    #[test]
    fn block_lists() {
        let verbatim = [
            "--block-list=64KiB,1:128KiB,0",
            "--filters1=delta:dist=4",
            "--filters2=x86",
            "-c",
        ];
        let working = [
            "--block-list=64KiB,1:128KiB,2:64KiB,0",
            "--filters1=delta:dist=4 lzma2:preset=1",
            "--filters2=x86 lzma2",
        ];
        let mut cases = vec![xz(&verbatim, "mixed", mixed_1m())];
        for t in ["-T1", "-T4"] {
            let mut a = working.to_vec();
            a.extend([t, "-c"]);
            cases.push(xz(&a, "mixed", mixed_1m()));
            let mut a = working.to_vec();
            a.extend([t, "--block-size=100KiB", "-c"]);
            cases.push(xz(&a, "mixed", mixed_1m()));
            cases.push(xz(
                &[t, "--block-list=1000,2000,0", "-c"],
                "text",
                text(5000, 64),
            ));
            cases.push(xz(
                &[t, "--block-list=1:1000", "-c"],
                "text",
                text(1024, 61),
            ));
        }
        check("block_lists", &cases);
    }

    /// Every BCJ filter before LZMA2, delta, and the option strings.
    #[test]
    fn filters() {
        let bcj = [
            "--x86",
            "--powerpc",
            "--ia64",
            "--arm",
            "--armthumb",
            "--arm64",
            "--sparc",
            "--riscv",
        ];
        let mut cases = Vec::new();
        for f in bcj {
            cases.push(xz(&[f, "--lzma2", "-c"], "mixed", mixed_1m()));
            cases.push(xz(&[f, "--lzma2", "-T1", "-c"], "text", text(1024, 61)));
        }
        for args in [
            &["--x86=start=16", "--lzma2", "-c"][..],
            &["--arm64=start=4096", "--lzma2=preset=1", "-c"],
            &["--delta=dist=4", "--lzma2", "-c"],
            &["--delta", "--lzma2", "-T1", "-c"],
            &[
                "--lzma2=preset=1,dict=1MiB,lc=1,lp=1,pb=0,mode=fast,nice=32,mf=hc4,depth=16",
                "-c",
            ],
            &[
                "--lzma2=dict=64KiB,mf=bt2,nice=273,mode=normal",
                "-T1",
                "-c",
            ],
            &["--lzma2=preset=9e,lc=4,lp=0", "-c"],
            &["--filters=x86 lzma2:preset=1", "-c"],
            &["--filters=delta:dist=2--lzma2:dict=1MiB", "-T1", "-c"],
            &["--filters=3e", "-c"],
            &["--x86", "--x86", "--lzma2", "-c"],
            &["--lzma2", "-6", "-c"],
            &["--x86", "-c"],
            &["--x86", "-T1", "-c"],
            &["--arm=start=1", "--lzma2", "-c"],
            &["--arm=start=1", "--lzma2", "-T1", "-c"],
        ] {
            cases.push(xz(args, "mixed", mixed_1m()));
        }
        // The threaded encoder checks a chain when a Block opens: an empty
        // input is an empty Stream.
        cases.push(xz(&["--arm=start=1", "--lzma2", "-c"], "empty", Vec::new()));
        cases.push(xz(
            &["--arm=start=1", "--lzma2", "-T1", "-c"],
            "empty",
            Vec::new(),
        ));
        check("filters", &cases);
    }

    /// `.lzma` (as `lzma` and with `-F lzma`), raw with and without
    /// filters, and lzip refused for compression.
    #[test]
    fn lzma_and_raw() {
        let mut cases = Vec::new();
        for (name, data) in [("text", text(1024, 61)), ("mixed", mixed_1m())] {
            for p in ["-0", "-6", "-9e"] {
                cases.push(case("lzma", vec![p, name], vec![(name, data.clone())]));
                cases.push(xz(&["-F", "lzma", p, "-c"], name, data.clone()));
            }
            cases.push(xz(&["--format=alone", "-k"], name, data.clone()));
            cases.push(xz(
                &["-F", "lzma", "--lzma1=preset=3,lc=4", "-c"],
                name,
                data.clone(),
            ));
            cases.push(xz(&["-F", "lzma", "--lzma2", "-c"], name, data.clone()));
            cases.push(xz(
                &["-F", "lzma", "--x86", "--lzma1", "-c"],
                name,
                data.clone(),
            ));
            cases.push(xz(&["-F", "raw", "-c"], name, data.clone()));
            cases.push(xz(&["-F", "raw", "-1", "-c"], name, data.clone()));
            cases.push(xz(
                &["-F", "raw", "--lzma1=preset=1", "-c"],
                name,
                data.clone(),
            ));
            cases.push(xz(
                &["-F", "raw", "--lzma2=preset=2", "-c"],
                name,
                data.clone(),
            ));
            cases.push(xz(
                &["-F", "raw", "--x86", "--lzma1", "-c"],
                name,
                data.clone(),
            ));
            cases.push(xz(
                &["-F", "raw", "--filters=delta lzma2", "-c"],
                name,
                data.clone(),
            ));
            cases.push(xz(&["-F", "raw", "-S", ".raw", "-k"], name, data.clone()));
            cases.push(xz(&["-F", "xz", "--lzma1", "-c"], name, data.clone()));
            cases.push(xz(&["-F", "lzip"], name, data));
        }
        check("lzma_and_raw", &cases);
    }
}
