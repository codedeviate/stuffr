//! The zstd compatibility family against zstd 1.5.7: stuffr invoked as
//! `zstd`, `unzstd`, `zstdcat` and `zstdmt`, compared with the reference
//! (stdout, stderr, exit code, the file tree) through `compat_harness`,
//! every case under `LC_ALL=C`.
//!
//! Part 1 (Task 4): the argument surface. Options refused and their
//! messages, the help texts, `-V`, `ZSTD_CLEVEL`/`ZSTD_NBTHREADS`, and every
//! option accepted. Until compression exists (Task 5) an accepted option
//! is compared through a run that stops after the whole command line is
//! read: [`STOP`] adds `-D` and `--patch-from` together, which zstdcli.c
//! refuses after parsing, the thread count, the level limit and the
//! console checks, so every warning on the way is compared too. The cases
//! that run the coder are written here and ignored until Task 5.
//!
//! The only normalisations: the banner (`-V`, `-H`, `-v`'s welcome line),
//! which names stuffr (spec deviation 1; checked exactly before it is
//! masked), and in `-H` the reference's benchmark section and `--trace`
//! line, which a `ZSTD_NOBENCH`/`ZSTD_NOTRACE` build does not print (R13;
//! `strip_bench_help` removes exactly those blocks). The texts of the
//! refused benchmark and trace options, which the reference accepts, are
//! pinned by `cli.rs`'s unit tests.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;

    fn ref_zstd() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| format!("{}/zstd", zstd_dir().unwrap_or("/nonexistent")))
    }

    fn text() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog\n".repeat(40)
    }

    // ---- cases ----

    fn case<'a>(name: &'a str, args: &[&'a str]) -> Case<'a> {
        Case {
            name,
            args: args.to_vec(),
            files: vec![("a", text()), ("d", text()), ("p", text())],
            stdin: None,
            tty_stdin: false,
            tty_stdout: false,
            env: vec![("LC_ALL", "C")],
            compare_output_bytes: false,
            expect_stdout_plain: None,
            setup: None,
            roundtrip: Roundtrip::Zstd {
                ref_zstd: ref_zstd(),
            },
        }
    }

    fn zstd<'a>(args: &[&'a str]) -> Case<'a> {
        case("zstd", args)
    }

    fn with_env<'a>(mut c: Case<'a>, k: &'a str, v: &'a str) -> Case<'a> {
        c.env.push((k, v));
        c
    }

    fn fed<'a>(mut c: Case<'a>, stdin: Vec<u8>) -> Case<'a> {
        c.stdin = Some(stdin);
        c
    }

    /// Appended to a command line, ends the run once every option is
    /// read: zstdcli.c refuses `-D` with `--patch-from` (exit 1) after the
    /// thread count, the console checks and the level limit.
    const STOP: [&str; 4] = ["-D", "d", "--patch-from=p", "a"];

    /// `args` followed by [`STOP`].
    fn stopped<'a>(name: &'a str, args: &[&'a str]) -> Case<'a> {
        let mut all = args.to_vec();
        all.extend(STOP);
        case(name, &all)
    }

    // ---- normalisation ----

    /// zstdcli.c's `WELCOME_MESSAGE`, as the reference prints it.
    const REFERENCE_BANNER: &str = "*** Zstandard CLI (64-bit) v1.5.7, by Yann Collet ***\n";

    /// Spec deviation 1: stuffr's banner.
    fn our_banner() -> String {
        format!(
            "*** Zstandard CLI (stuffr {}; zstd 1.5.7 compatible) (64-bit) v1.5.7, by Yann Collet ***\n",
            env!("CARGO_PKG_VERSION")
        )
    }

    /// Each side's banner, exactly, becomes `<banner>`: a banner where the
    /// other side has none, or a banner that is not exactly the expected
    /// one, still differs.
    fn mask_banners(r: &mut Run, s: &mut Run) {
        let ours = our_banner();
        let mask = |t: &str, banner: &str| t.replace(banner, "<banner>\n");
        r.stderr = mask(&r.stderr, REFERENCE_BANNER);
        s.stderr = mask(&s.stderr, &ours);
        if let Ok(t) = std::str::from_utf8(&r.stdout) {
            r.stdout = mask(t, REFERENCE_BANNER).into_bytes();
        }
        if let Ok(t) = std::str::from_utf8(&s.stdout) {
            s.stdout = mask(t, &ours).into_bytes();
        }
    }

    /// Run every case against the reference and stuffr.
    fn check(group: &str, cases: &[Case]) {
        let one = |c: &Case| -> bool {
            let Some(dir) = zstd_dir() else { return false };
            let Some(mut r) = reference(dir, c) else {
                return false;
            };
            let mut s = stuffr_as(c);
            // R13: the reference's `-H` lists the benchmark and `--trace`.
            if let Ok(t) = std::str::from_utf8(&r.stdout) {
                r.stdout = strip_bench_help(t).into_bytes();
            }
            mask_banners(&mut r, &mut s);
            assert_same(c, &r, &s);
            true
        };
        run_group(group, cases, Skipped::none(), &one);
    }

    // ---- flags: refused ----

    /// Options the reference refuses, each with its message and exit 1, and
    /// nothing written: unknown options, numbers that overflow or carry
    /// junk, missing and separated arguments, malformed parameter strings.
    #[test]
    fn flags_refused() {
        let cases: Vec<Case> = [
            // Unknown.
            &["-Y"][..],
            &["--frob"],
            &["--frob=1"],
            &["-qY"],
            &["-qqY"],
            &["-vY"],
            &["-kY", "a"],
            &["-T5x"],
            &["-Mx"],
            &["-1KiBx"],
            &["-Y", "-h"],
            &["--best"],
            &["--no-name"],
            &["--fastx"],
            &["--fast=0"],
            &["--longx"],
            &["--long5"],
            &["--train-coverx"],
            &["--format=bz2"],
            &["--rsyncable=1"],
            &["--ultra=1"],
            // Overflow.
            &["-T99999999999"],
            &["-M99999999999"],
            &["-99999999999"],
            &["-4294967296"],
            &["-5000000K"],
            &["-4096M"],
            &["--memory=99999999999"],
            &["--memory=4096M"],
            &["--threads=4294967296"],
            &["--block-size=99999999999999999999"],
            &["--stream-size=18446744073709551616"],
            &["--fast=99999999999"],
            &["--long=99999999999"],
            &["--zstd=wlog=99999999999"],
            &["--adapt=min=99999999999"],
            &["--train-cover=k=99999999999"],
            &["-qq", "-T99999999999"],
            // Junk after a number.
            &["--memory=1Q"],
            &["--memory=1KBx"],
            &["--threads=x"],
            &["--block-size=1Q"],
            &["--stream-size=1x"],
            &["--size-hint=1 "],
            &["--target-compressed-block-size=x"],
            &["--maxdict=x"],
            &["--dictID=1x"],
            // Missing and separated arguments.
            &["-o"],
            &["-ofoo"],
            &["-o", "-c"],
            &["-D"],
            &["-Dfoo"],
            &["--memory"],
            &["--memory", "-5"],
            &["--memlimit-decompress=5"],
            &["--threads"],
            &["--block-size"],
            &["--maxdict"],
            &["--dictID"],
            &["--stream-size"],
            &["--size-hint"],
            &["--target-compressed-block-size"],
            &["--output-dir-flat"],
            &["--output-dir-mirror"],
            &["--auto-threads"],
            &["--auto-threads", "-T0"],
            &["--filelist"],
            &["--patch-from"],
            &["-qq", "-o"],
            // Empty output directories.
            &["--output-dir-flat="],
            &["--output-dir-mirror="],
            &["--output-dir-flat", ""],
            // Malformed parameter strings.
            &["--zstd="],
            &["--zstd=foo=1"],
            &["--zstd=wlog=1,"],
            &["--zstd=wlog=x"],
            &["--zstd=wlog"],
            &["-vv", "--zstd=foo=1"],
            &["--adapt="],
            &["--adapt=min=5,max=1"],
            &["--adapt=lo=1"],
            &["--adapt=min=1x"],
            &["-vv", "--adapt=min=5,max=1"],
            &["--train-cover=x"],
            &["--train-cover=k=1,"],
            &["--train-cover=f=2"],
            &["--train-cover=shrinkx"],
            &["--train-fastcover=accel=x"],
            &["--train-legacy=x"],
            &["--train-legacy=s=5x"],
            // `-p` pauses after a refusal (zstdcli.c's `_end`), not after
            // an overflow (`exit`).
            &["-p", "--frob"],
            &["-p", "-T99999999999"],
        ]
        .iter()
        .map(|a| zstd(a))
        .collect();
        check("flags_refused", &cases);
    }

    // ---- help and version ----

    // ---- the environment ----

    #[test]
    fn environment() {
        let mut cases: Vec<Case> = Vec::new();
        for v in [
            "19",
            "-5",
            "+3",
            "abc",
            "99",
            "",
            " 3",
            "3x",
            "-",
            "99999999999",
            "4294967295",
        ] {
            cases.push(with_env(zstd(&["-h"]), "ZSTD_CLEVEL", v));
            cases.push(with_env(zstd(&["-q", "-V"]), "ZSTD_CLEVEL", v));
        }
        // The level limit's warning, ZSTD_CLEVEL above 19.
        for v in ["99", "20", "19", "-99999"] {
            cases.push(with_env(
                zstd(&["-d", "--show-default-cparams"]),
                "ZSTD_CLEVEL",
                v,
            ));
        }
        // ZSTD_NBTHREADS is read after the arguments, for a default count.
        for v in ["2", "x", "99999999999", "", "0", "3x"] {
            cases.push(with_env(stopped("zstd", &[]), "ZSTD_NBTHREADS", v));
            cases.push(with_env(stopped("zstd", &["-vvvv"]), "ZSTD_NBTHREADS", v));
            cases.push(with_env(stopped("zstd", &["-q"]), "ZSTD_NBTHREADS", v));
            cases.push(with_env(stopped("zstd", &["-T1"]), "ZSTD_NBTHREADS", v));
            cases.push(with_env(stopped("zstd", &["-d"]), "ZSTD_NBTHREADS", v));
        }
        cases.push(with_env(zstd(&["--adapt"]), "ZSTD_NBTHREADS", "0"));
        check("environment", &cases);
    }

    /// ZSTD_CLEVEL and ZSTD_NBTHREADS compressing.
    #[test]
    #[ignore = "Task 5"]
    fn environment_compressing() {
        let mut cases: Vec<Case> = Vec::new();
        for v in ["19", "-5", "abc", "99", "1"] {
            cases.push(with_env(fed(zstd(&[]), text()), "ZSTD_CLEVEL", v));
            cases.push(with_env(zstd(&["-k", "a"]), "ZSTD_CLEVEL", v));
        }
        for v in ["2", "x", "99999999999", "0"] {
            cases.push(with_env(fed(zstd(&["-vv"]), text()), "ZSTD_NBTHREADS", v));
        }
        check("environment_compressing", &cases);
    }

    // ---- flags: accepted ----

    /// Every option in `zstd -H`, and the hidden ones, alone; each run
    /// stops at [`STOP`] once the command line is read.
    #[test]
    fn flags_parse() {
        let mut cases: Vec<Case> = Vec::new();
        for args in ACCEPTED {
            cases.push(stopped("zstd", args));
        }
        for name in ["unzstd", "zstdcat", "zstdmt"] {
            cases.push(stopped(name, &[]));
            cases.push(stopped(name, &["-v"]));
        }
        check("flags_parse", &cases);
    }

    /// The options of `zstd -H` and the hidden ones zstdcli.c accepts,
    /// each spelled the ways it can be.
    const ACCEPTED: &[&[&str]] = &[
        &["-o", "out"],
        &["-o=out"],
        &["-k"],
        &["--keep"],
        &["--rm"],
        &["-1"],
        &["-19"],
        &["-20"],
        &["-22"],
        &["-1000"],
        &["-3000000000"],
        &["-1K"],
        &["-d"],
        &["--decompress"],
        &["--uncompress"],
        &["-z"],
        &["--compress"],
        &["-t"],
        &["--test"],
        &["-f"],
        &["--force"],
        &["-c"],
        &["--stdout"],
        &["-v"],
        &["-vv"],
        &["-vvv"],
        &["-vvvv"],
        &["-q"],
        &["-qq"],
        &["--verbose"],
        &["--quiet"],
        &["--progress"],
        &["--no-progress"],
        &["--asyncio"],
        &["--no-asyncio"],
        &["--check"],
        &["--no-check"],
        &["-C"],
        &["--ultra"],
        &["--ultra", "-20"],
        &["--ultra", "-23"],
        &["--fast"],
        &["--fast=5"],
        &["--fast=99999999"],
        &["--fast=5x"],
        &["--adapt"],
        &["--adapt=min=1,max=19"],
        &["--adapt=max=3"],
        &["--long"],
        &["--long=27"],
        &["--long=31"],
        &["--long=x"],
        &["-T0"],
        &["-T0", "-vvvv"],
        &["-T0", "--auto-threads=logical", "-vvvv"],
        &["-T0", "--auto-threads", "physical", "-vvvv"],
        &["-T0", "--single-thread", "-vvvv"],
        &["-T1"],
        &["-T4"],
        &["-T", "-vvvv"],
        &["-T4294967295", "-vvvv"],
        &["--threads=2"],
        &["--threads", "2"],
        &["--single-thread"],
        &["-B1K"],
        &["-B4"],
        &["--block-size=1K"],
        &["--rsyncable"],
        &["--exclude-compressed"],
        &["--stream-size=10"],
        &["--size-hint=100"],
        &["--target-compressed-block-size=1K"],
        &["--no-dictID"],
        &["--compress-literals"],
        &["--no-compress-literals"],
        &["--row-match-finder"],
        &["--no-row-match-finder"],
        &["--format=zstd"],
        &["--format=gzip"],
        &["--format=xz"],
        &["--format=lzma"],
        &["--format=lz4"],
        &["--mmap-dict"],
        &["--no-mmap-dict"],
        &["-M10"],
        &["-M"],
        &["--memory=10M"],
        &["--memory", "10MiB"],
        &["--memory="],
        &["--memlimit=1KB"],
        &["--sparse"],
        &["--no-sparse"],
        &["--pass-through"],
        &["--no-pass-through"],
        &["--content-size"],
        &["--no-content-size"],
        &["--show-default-cparams"],
        &[
            "--zstd=windowLog=20,chainLog=16,hashLog=17,searchLog=1,minMatch=5,targetLength=0,strategy=2",
        ],
        &["--zstd=wlog=20,clog=16,hlog=17,slog=1,mml=5,tlen=8,strat=9"],
        &["--zstd=overlapLog=3,ldmHashLog=20,ldmMinMatch=32,ldmBucketSizeLog=4,ldmHashRateLog=6"],
        &["--zstd=ovlog=3,lhlog=20,lmml=32,lblog=4,lhrlog=6"],
        &["--zstd=strat=12"],
        &["--max"],
        &["--priority=rt"],
        &["-n"],
        &["-S"],
        &["-s5"],
        &["-P50"],
        &["-p5"],
        &["-p"],
        &["--output-dir-flat=o"],
        &["--output-dir-flat", "o"],
        &["--output-dir-mirror=o"],
        &["--maxdict=4K"],
        &["--dictID=5"],
        &["--fake-stdin-is-console"],
        &["--fake-stdout-is-console"],
        &["--fake-stderr-is-console"],
        // Aggregated.
        &["-19kfcqv"],
        &["-dkT2"],
        &["-1kM5v"],
        &["-3kM5kT2"],
        &["-T2M"],
        &["-1K2"],
        &["-cdfkvvq"],
        &["-zt"],
        &["-of", "out"],
    ];

    /// Every accepted option compressing (or decompressing) for real.
    #[test]
    #[ignore = "Task 5"]
    fn flags_accepted() {
        let mut cases: Vec<Case> = Vec::new();
        for args in ACCEPTED {
            cases.push(fed(zstd(args), text()));
            let mut with_file = args.to_vec();
            with_file.extend(["-k", "a"]);
            cases.push(zstd(&with_file));
        }
        // `--` makes the rest operands, `-h` and STOP's words included.
        cases.push(zstd(&["-k", "--", "-h", "a"]));
        cases.push(zstd(&["-k", "--", "-x"]));
        check("flags_accepted", &cases);
    }

    /// The level limit's warning, compressing.
    #[test]
    #[ignore = "Task 5"]
    fn levels_above_19_warn() {
        let cases: Vec<Case> = [
            &["-20"][..],
            &["-22"],
            &["--ultra", "-20"],
            &["--ultra", "-23"],
            &["--long", "-22"],
            &["--patch-from=p", "-22"],
            &["--max"],
        ]
        .iter()
        .map(|a| fed(zstd(a), text()))
        .collect();
        check("levels_above_19_warn", &cases);
    }

    // ---- --show-default-cparams ----

    // ---- names ----

    /// Each of the four names over standard input.
    #[test]
    #[ignore = "Task 5"]
    fn names_on_stdin() {
        let Some(dir) = zstd_dir() else { return };
        let packed = std::process::Command::new(format!("{dir}/zstd"))
            .args(["-c", "/dev/null"])
            .output()
            .unwrap()
            .stdout;
        let cases = vec![
            fed(case("zstd", &[]), text()),
            fed(case("zstdmt", &[]), text()),
            fed(case("unzstd", &[]), packed.clone()),
            fed(case("zstdcat", &[]), packed),
            fed(case("zstdcat", &[]), text()),
        ];
        check("names_on_stdin", &cases);
    }
}
