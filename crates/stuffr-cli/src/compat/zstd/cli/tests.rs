//! cli.rs unit tests: the parser against zstdcli.c's rules, and the texts
//! the differential suite cannot compare (the benchmark and trace options
//! the reference has and a `ZSTD_NOBENCH`/`ZSTD_NOTRACE` build refuses).

use super::*;

/// Parse `args` as `program`, with `env` as the environment: the result,
/// standard output and standard error.
fn run_env(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> (Result<Command, Stop>, String, String) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let lookup = |k: &str| {
        env.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| OsString::from(v))
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = parse(program, &lookup, &args, Cores::SANDBOX, &mut out, &mut err);
    (
        r,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn run(args: &[&str]) -> (Result<Command, Stop>, String, String) {
    run_env("zstd", args, &[])
}

fn ok(args: &[&str]) -> Command {
    let (r, _, err) = run(args);
    r.unwrap_or_else(|s| panic!("{args:?}: {s:?} {err}"))
}

fn stop(args: &[&str]) -> (Stop, String, String) {
    let (r, out, err) = run(args);
    (r.expect_err("a stop"), out, err)
}

fn usage_text(program: &str) -> String {
    let mut v = Vec::new();
    usage(&mut v, program);
    String::from_utf8(v).unwrap()
}

const CLEAN_1: Stop = Stop {
    code: 1,
    clean: true,
    pause: false,
};
const EXIT_1: Stop = Stop {
    code: 1,
    clean: false,
    pause: false,
};
const CLEAN_0: Stop = Stop {
    code: 0,
    clean: true,
    pause: false,
};

#[test]
fn numbers_take_k_and_m_suffixes_and_refuse_overflow() {
    let r = |s: &str| {
        let mut p = 0;
        let v = read_u32_checked(s.as_bytes(), &mut p);
        (v, p)
    };
    assert_eq!(r("19"), (Some(19), 2));
    assert_eq!(r("1K"), (Some(1024), 2));
    assert_eq!(r("1KB"), (Some(1024), 3));
    assert_eq!(r("1KiB"), (Some(1024), 4));
    assert_eq!(r("2M"), (Some(2 << 20), 2));
    assert_eq!(r("2MiBx"), (Some(2 << 20), 4));
    assert_eq!(r("1Bi"), (Some(1), 1));
    assert_eq!(r("x"), (Some(0), 0));
    assert_eq!(r("4294967295"), (Some(u32::MAX), 10));
    assert_eq!(r("4294967296").0, None);
    assert_eq!(r("99999999999").0, None);
    assert_eq!(r("4194303K"), (Some(4194303 << 10), 8));
    assert_eq!(r("4194304K").0, None);
    assert_eq!(r("4095M"), (Some(4095 << 20), 5));
    assert_eq!(r("4096M").0, None);
    let mut p = 0;
    assert_eq!(
        read_size_checked(b"16777215MiB", &mut p),
        Some(16777215 << 20)
    );
    let mut p = 0;
    assert_eq!(read_size_checked(b"18446744073709551616", &mut p), None);
}

#[test]
fn short_options_aggregate() {
    let c = ok(&["-19dkv", "a"]);
    assert_eq!(
        (c.level, c.op, c.display_level),
        (19, Operation::Decompress, 3)
    );
    assert_eq!(c.files, [b"a".to_vec()]);
    let c = ok(&["-3kM5kT2", "-", "--", "-x"]);
    assert_eq!((c.level, c.prefs.workers, c.prefs.memory_limit), (3, 2, 5));
    assert_eq!(c.files, [STDINMARK.to_vec(), b"-x".to_vec()]);
    // `K` and `M` are suffixes after any number, a level's too.
    assert_eq!(ok(&["-1K2"]).level, 2);
    assert_eq!(ok(&["-1Kv"]).display_level, 3);
    assert_eq!(stop(&["-5000000K"]).0, EXIT_1);
    // A level past i32::MAX wraps, as `(int)readU32FromChar` does.
    assert_eq!(ok(&["-3000000000"]).level, -1294967296);
}

/// zstdcli.c's NEXT_FIELD: `-o=NAME`, or the next argument; a value that
/// starts with `-` is refused; after `-o` the rest of a cluster is still
/// options, so `-ofoo` needs a next argument and then reads `foo` as
/// `-f -o -o`.
#[test]
fn next_field_takes_the_value_after_equals_or_the_next_argument() {
    assert_eq!(ok(&["-o=foo"]).out_file.as_deref(), Some(&b"foo"[..]));
    assert_eq!(ok(&["-o", "foo"]).out_file.as_deref(), Some(&b"foo"[..]));
    let (s, _, err) = stop(&["-ofoo"]);
    assert_eq!(
        (s, err.as_str()),
        (CLEAN_1, "error: missing command argument \n")
    );
    let (s, _, err) = stop(&["-o", "-c"]);
    assert_eq!(
        (s, err.as_str()),
        (
            CLEAN_1,
            "error: command cannot be separated from its argument by another command \n"
        )
    );
    let (s, _, err) = stop(&["-ofo", "x"]);
    assert_eq!(
        (s, err.as_str()),
        (CLEAN_1, "error: missing command argument \n")
    );
    // `T` is no suffix, `M` is: `-T2M` is two MiB workers.
    assert_eq!(ok(&["-T2M"]).prefs.workers, 2 << 20);
    let c = ok(&["-of", "x"]);
    assert_eq!(c.out_file.as_deref(), Some(&b"x"[..]));
    assert!(c.prefs.overwrite);
    assert_eq!(ok(&["-D", "d"]).dict_file.as_deref(), Some(&b"d"[..]));
    // `--memlimit` is matched by prefix, so this takes the next argument.
    let (s, _, err) = stop(&["--memlimit-decompress=5"]);
    assert_eq!(
        (s, err.as_str()),
        (CLEAN_1, "error: missing command argument \n")
    );
    assert_eq!(ok(&["--memory=5K"]).prefs.memory_limit, 5 << 10);
    assert_eq!(ok(&["--memory", "5"]).prefs.memory_limit, 5);
    assert_eq!(ok(&["--memory="]).prefs.memory_limit, 0);
    let (s, _, err) = stop(&["--memory=5x"]);
    assert_eq!(
        (s, err.as_str()),
        (
            EXIT_1,
            "error: only numeric values with optional suffixes K, KB, KiB, M, MB, MiB are allowed \n"
        )
    );
}

#[test]
fn overflow_is_said_and_exits_1_without_the_pause() {
    let (s, _, err) = stop(&["-p", "-T99999999999"]);
    assert_eq!(
        (s, err.as_str()),
        (
            EXIT_1,
            "error: numeric value overflows 32-bit unsigned int \n"
        )
    );
    let (s, _, err) = stop(&["--block-size=99999999999999999999"]);
    assert_eq!(
        (s, err.as_str()),
        (EXIT_1, "error: numeric value overflows size_t \n")
    );
    let (s, _, err) = stop(&["--adapt=min=99999999999"]);
    assert_eq!(
        (s, err.as_str()),
        (EXIT_1, "error: numeric value overflows 32-bit int \n")
    );
    let (s, _, err) = stop(&["-qq", "-T99999999999"]);
    assert_eq!((s, err.as_str()), (EXIT_1, ""));
}

#[test]
fn an_incorrect_parameter_prints_the_short_usage_from_level_2() {
    let (s, out, err) = stop(&["-Y"]);
    assert_eq!(s, CLEAN_1);
    assert!(out.is_empty());
    assert_eq!(
        err,
        format!("Incorrect parameter: -Y \n{}", usage_text("zstd"))
    );
    let (s, _, err) = stop(&["-q", "--frob=1"]);
    assert_eq!(
        (s, err.as_str()),
        (CLEAN_1, "Incorrect parameter: --frob=1 \n")
    );
    let (_, _, err) = stop(&["-qq", "--frob"]);
    assert_eq!(err, "");
    // `-p` before it: the stop goes through `_end`, which pauses.
    let (s, _, _) = stop(&["-p", "--frob"]);
    assert_eq!(
        s,
        Stop {
            code: 1,
            clean: true,
            pause: true
        }
    );
}

/// R13 and spec deviation 5: the benchmark and trace options are unknown,
/// as in a `ZSTD_NOBENCH`/`ZSTD_NOTRACE` build. zstdcli.c:1236-1270 put `b`,
/// `e` and `i` under `#ifndef ZSTD_NOBENCH`, so they reach the `default:`
/// arm (zstdcli.c:1298-1303, "Incorrect parameter: -%c"); zstdcli.c:1107
/// puts `--trace` under `#ifndef ZSTD_NOTRACE`, so it falls through to
/// badUsage (zstdcli.c:1181).
#[test]
fn benchmark_and_trace_are_refused_as_a_nobench_notrace_build_refuses_them() {
    for (args, shown) in [
        (&["-b"][..], "-b"),
        (&["-b19"], "-b"),
        (&["-e3"], "-e"),
        (&["-i3"], "-i"),
        (&["-3b"], "-b"),
        (&["--trace", "log"], "--trace"),
        (&["--trace=log"], "--trace=log"),
    ] {
        let (s, out, err) = stop(args);
        assert_eq!(s, CLEAN_1, "{args:?}");
        assert!(out.is_empty());
        assert_eq!(
            err,
            format!("Incorrect parameter: {shown} \n{}", usage_text("zstd")),
            "{args:?}"
        );
    }
    // The reference's (benchmark) build's meanings, kept: `-B#` the job
    // size, `-S` nothing outside the benchmark, `-p#` a benchmark value.
    let c = ok(&["-B4K", "-S", "-p5"]);
    assert_eq!((c.prefs.job_size, c.main_pause, c.level), (4096, false, 3));
    assert!(ok(&["-p"]).main_pause);
    // `--trace-file-stat` is its own option.
    assert!(ok(&["--trace-file-stat"]).prefs.trace_file_stat);
}

#[test]
fn help_and_version_stop_with_0() {
    let (s, out, err) = stop(&["-h", "-Y"]);
    assert_eq!((s, out, err), (CLEAN_0, usage_text("zstd"), String::new()));
    let (s, out, _) = stop(&["-H"]);
    assert_eq!(s, CLEAN_0);
    let banner = format!(
        "*** Zstandard CLI (stuffr {}; zstd 1.5.7 compatible) (64-bit) v1.5.7, by Yann Collet ***\n",
        env!("CARGO_PKG_VERSION")
    );
    assert!(out.starts_with(&format!("{banner}\n{}", usage_text("zstd"))));
    assert!(out.contains("Advanced options:\n"));
    assert!(out.ends_with("[Default: Random]\n"), "{out}");
    assert!(!out.contains("Benchmark options") && !out.contains("--trace"));
    assert_eq!(stop(&["--help"]).1, out);
    let (_, cat, _) = run_env("zstdcat", &["-H"], &[]);
    let line = |v: &str| {
        let mut l = Vec::new();
        printf(&mut l, m::ADV_PASS_THROUGH, &[v.as_bytes()]);
        String::from_utf8(l).unwrap()
    };
    assert!(cat.contains(&line("Enabled")) && !cat.contains(&line("Disabled")));
    assert!(out.contains(&line("Disabled")));

    assert_eq!(stop(&["-V"]).1, banner);
    assert_eq!(stop(&["--version"]).1, banner);
    assert_eq!(stop(&["-Vv"]).1, banner);
    let supports = "*** supports: zstd, zstd legacy v0.5+, gzip, lz4, lzma, xz \n";
    assert_eq!(stop(&["-vV"]).1, format!("{banner}{supports}"));
    // -vvV: zstd's own library and POSIX lines are not printed (deviation 1).
    assert_eq!(stop(&["-vvV"]).1, format!("{banner}{supports}"));
    assert_eq!(stop(&["-qV"]).1, "1.5.7\n");
    assert_eq!(stop(&["-qqV"]).1, "1.5.7\n");
    let (_, cat, _) = run_env("zstdcat", &["-V"], &[]);
    assert_eq!(cat, "1.5.7\n");
    let (_, cat, _) = run_env("zstdcat", &["-vV"], &[]);
    assert_eq!(cat, banner);
}

#[test]
fn the_gzip_name_adds_its_help_lines() {
    let (_, out, _) = run_env("gzip", &["-H"], &[]);
    assert!(out.contains("Do not store original filename when compressing.\n\n\n"));
    assert!(out.contains("Compatibility alias for `-9`.\n"));
    let (_, out, _) = run_env("zstd", &["-H"], &[]);
    assert!(!out.contains("Compatibility alias"));
}

#[test]
fn names_preset_as_exe_name_match_says() {
    assert!(exe_name_match("unzstd", "unzstd"));
    assert!(exe_name_match("unzstd.exe", "unzstd"));
    assert!(!exe_name_match("unzstd-1.5", "unzstd"));
    assert!(!exe_name_match("unzstd", "unzstdx"));
    assert_eq!(last_name_from_path(b"/a/b\\c/zstdcat"), b"zstdcat");
    assert_eq!(last_name_from_path(b"C:\\x\\zstd.exe"), b"zstd.exe");

    let (c, _, _) = run_env("unzstd", &[], &[]);
    assert_eq!(c.unwrap().op, Operation::Decompress);
    let (c, _, _) = run_env("zstdcat", &[], &[]);
    let c = c.unwrap();
    assert_eq!(c.op, Operation::Decompress);
    assert_eq!(c.out_file.as_deref(), Some(STDOUTMARK));
    assert!(c.force_stdout && c.follow_links && c.prefs.overwrite);
    assert_eq!((c.prefs.pass_through, c.display_level), (1, 1));
    let (c, _, err) = run_env("zstdmt", &["-v"], &[]);
    assert_eq!(c.unwrap().prefs.workers, 4);
    assert!(
        err.ends_with("Note: 4 physical core(s) detected \n"),
        "{err}"
    );
    let (c, _, _) = run_env("zstd.exe", &["-k"], &[]);
    assert_eq!(c.unwrap().prefs.workers, 2);
    let (c, _, _) = run_env("gzip", &[], &[]);
    let c = c.unwrap();
    assert_eq!((c.level, c.suffix, c.prefs.ctype), (6, ".gz", CType::Gzip));
    assert!(c.prefs.remove_src);
    let (c, _, _) = run_env("unxz", &[], &[]);
    let c = c.unwrap();
    assert_eq!((c.op, c.prefs.ctype), (Operation::Decompress, CType::Xz));
}

#[test]
fn threads_resolve_as_zstdcli_resolves_them() {
    // The default: ZSTDCLI_NBTHREADS_DEFAULT on the sandbox's 8 logical.
    assert_eq!(ok(&[]).prefs.workers, 2);
    assert_eq!(ok(&["-d"]).prefs.workers, 1);
    assert_eq!(ok(&["-T0"]).prefs.workers, 4);
    assert_eq!(ok(&["-T0", "--auto-threads=logical"]).prefs.workers, 8);
    assert_eq!(ok(&["-T0", "--auto-threads", "x"]).prefs.workers, 4);
    assert_eq!(ok(&["-T0", "--single-thread"]).prefs.workers, 0);
    assert_eq!(ok(&["--single-thread", "-T3"]).prefs.workers, 3);
    assert_eq!(ok(&["--threads=5"]).prefs.workers, 5);
    // -T4294967295 is (int)-1, "unset", so the default applies.
    assert_eq!(ok(&["-T4294967295"]).prefs.workers, 2);
    let (_, _, err) = run(&["-d", "-T2"]);
    assert_eq!(
        err,
        "Warning : decompression does not support multi-threading\n"
    );
    let (_, _, err) = run(&["-vvv", "-T4294967294"]);
    assert!(
        err.ends_with("Compressing with 4294967294 worker threads \n"),
        "{err}"
    );
}

#[test]
fn the_environment_is_read_as_zstdcli_reads_it() {
    let level = |v: &str| {
        let (r, _, err) = run_env("zstd", &["-q"], &[("ZSTD_CLEVEL", v)]);
        (r.unwrap().level, err)
    };
    assert_eq!(level("19"), (19, String::new()));
    assert_eq!(level("-5"), (-5, String::new()));
    assert_eq!(level("+4"), (4, String::new()));
    assert_eq!(level("99"), (99, String::new()));
    let not_int = |v: &str| {
        format!("Ignore environment variable setting ZSTD_CLEVEL={v}: not a valid integer value \n")
    };
    // Read before the arguments, so `-q` does not silence it.
    for v in ["abc", "", " 3", "3x", "-", "--3"] {
        assert_eq!(level(v), (3, not_int(v)), "{v:?}");
    }
    assert_eq!(
        level("99999999999"),
        (
            3,
            "Ignore environment variable setting ZSTD_CLEVEL=99999999999: numeric value too large \n"
                .to_string()
        )
    );
    // A level argument overrides it.
    let (r, _, _) = run_env("zstd", &["-7"], &[("ZSTD_CLEVEL", "19")]);
    assert_eq!(r.unwrap().level, 7);

    let threads = |args: &[&str], v: &str| {
        let (r, _, err) = run_env("zstd", args, &[("ZSTD_NBTHREADS", v)]);
        (r.unwrap().prefs.workers, err)
    };
    assert_eq!(threads(&[], "3"), (3, String::new()));
    assert_eq!(threads(&[], "0"), (0, String::new()));
    assert_eq!(
        threads(&[], "x"),
        (
            2,
            "Ignore environment variable setting ZSTD_NBTHREADS=x: not a valid unsigned value \n"
                .into()
        )
    );
    assert_eq!(
        threads(&[], "99999999999"),
        (
            2,
            "Ignore environment variable setting ZSTD_NBTHREADS=99999999999: numeric value too large \n"
                .into()
        )
    );
    // Read after the arguments (at the current level), and only for a
    // default count.
    assert_eq!(threads(&["-q"], "x"), (2, String::new()));
    assert_eq!(threads(&["-T1"], "x"), (1, String::new()));
    assert_eq!(threads(&["-d"], "x"), (1, String::new()));
}

#[test]
fn fast_long_and_ultra() {
    let c = ok(&["--fast"]);
    assert_eq!(c.level, -1);
    assert_eq!(c.train, None);
    let c = ok(&["--fast=5"]);
    assert_eq!(c.level, -5);
    assert_eq!(ok(&["--fast=99999999"]).level, -131072);
    assert_eq!(ok(&["--fast=5x"]).level, -5);
    for bad in ["--fast=0", "--fastx", "--longx", "--long5"] {
        let (s, _, err) = stop(&[bad]);
        assert_eq!(s, CLEAN_1, "{bad}");
        assert!(
            err.starts_with(&format!("Incorrect parameter: {bad} \n")),
            "{err}"
        );
    }
    let c = ok(&["--long"]);
    assert!(c.ultra && c.prefs.ldm);
    assert_eq!(c.cparam(CParamKey::WindowLog), 27);
    assert_eq!(ok(&["--long=31"]).cparam(CParamKey::WindowLog), 31);
    assert_eq!(ok(&["--long=x"]).cparam(CParamKey::WindowLog), 0);
    // --long sets the window only when --zstd= has not.
    assert_eq!(
        ok(&["--zstd=wlog=20", "--long=30"]).cparam(CParamKey::WindowLog),
        20
    );
    assert_eq!(
        ok(&["--long=30", "--zstd=wlog=20"]).cparam(CParamKey::WindowLog),
        20
    );
    assert!(ok(&["--patch-from=x"]).ultra);
    assert!(ok(&["--ultra"]).ultra);
    assert!(!ok(&["-22"]).ultra);
}

#[test]
fn zstd_parameters_parse_every_key() {
    let c = ok(&[
        "--zstd=windowLog=20,clog=21,hashLog=22,slog=4,minMatch=5,tlen=64,strat=7,ovlog=3,ldmHashLog=20,lmml=32,lblog=4,ldmHashRateLog=6",
    ]);
    assert_eq!(
        c.cparams_overrides,
        [
            (CParamKey::WindowLog, 20),
            (CParamKey::ChainLog, 21),
            (CParamKey::HashLog, 22),
            (CParamKey::SearchLog, 4),
            (CParamKey::MinMatch, 5),
            (CParamKey::TargetLength, 64),
            (CParamKey::Strategy, 7),
        ]
    );
    assert_eq!(c.prefs.overlap_log, Some(3));
    assert_eq!(
        (
            c.prefs.ldm_hash_log,
            c.prefs.ldm_min_match,
            c.prefs.ldm_bucket_size_log,
            c.prefs.ldm_hash_rate_log
        ),
        (20, 32, Some(4), Some(6))
    );
    // `--zstd=` selects the zstd format.
    assert_eq!(
        ok(&["--format=xz", "--zstd=mml=4"]).prefs.ctype,
        CType::Zstd
    );
    for bad in [
        "--zstd=",
        "--zstd=foo=1",
        "--zstd=wlog=1,",
        "--zstd=wlog=x",
        "--zstd=wlog",
    ] {
        let (s, _, err) = stop(&[bad]);
        assert_eq!(s, CLEAN_1, "{bad}");
        assert!(
            err.starts_with(&format!("Incorrect parameter: {bad} \n")),
            "{err}"
        );
    }
    // Display level 4 says why, for an unknown key only.
    let (_, _, err) = stop(&["-vv", "--zstd=foo=1"]);
    assert!(
        err.starts_with("invalid compression parameter \nIncorrect parameter: --zstd=foo=1 \n")
    );
    let (_, _, err) = stop(&["-vv", "--zstd=wlog=1x"]);
    assert!(err.starts_with("Incorrect parameter"), "{err}");
}

#[test]
fn max_sets_zstdclis_maximum_parameters() {
    let c = ok(&["--max"]);
    assert!(c.ultra && c.prefs.ldm);
    let all: Vec<u32> = CPARAM_KEYS.iter().map(|&k| c.cparam(k)).collect();
    assert_eq!(all, [31, 30, 30, 30, 3, 131072, 9]);
    assert_eq!(c.prefs.overlap_log, Some(9));
    assert_eq!(
        (
            c.prefs.ldm_hash_log,
            c.prefs.ldm_min_match,
            c.prefs.ldm_bucket_size_log,
            c.prefs.ldm_hash_rate_log
        ),
        (30, 16, Some(8), Some(0))
    );
}

#[test]
fn adapt_parameters() {
    let c = ok(&["--adapt=min=-3,max=12"]);
    assert!(c.prefs.adapt);
    assert_eq!((c.prefs.adapt_min, c.prefs.adapt_max), (-3, 12));
    let c = ok(&["--adapt"]);
    assert_eq!((c.prefs.adapt_min, c.prefs.adapt_max), (-131072, 22));
    for bad in [
        "--adapt=",
        "--adapt=min=5,max=1",
        "--adapt=lo=1",
        "--adapt=min=1x",
    ] {
        let (s, _, err) = stop(&[bad]);
        assert_eq!(s, CLEAN_1, "{bad}");
        assert!(
            err.starts_with(&format!("Incorrect parameter: {bad} \n")),
            "{err}"
        );
    }
    let (_, _, err) = stop(&["-vv", "--adapt=min=5,max=1"]);
    assert!(
        err.starts_with("incoherent adaptation limits \nIncorrect"),
        "{err}"
    );
}

#[test]
fn train_parameters() {
    let c = ok(&["--train", "a"]);
    let t = c.train.unwrap();
    assert_eq!(c.out_file.as_deref(), Some(&b"dictionary"[..]));
    assert_eq!(t.dict, DictType::FastCover);
    assert_eq!(t.fastcover, default_fastcover());
    assert_eq!(
        (t.selectivity, t.max_dict, t.dict_id, t.level),
        (9, 112640, 0, 3)
    );

    let c = ok(&[
        "-o",
        "mine",
        "--train-cover=k=64,d=8,steps=3,split=80,shrink",
        "-19",
    ]);
    assert_eq!(c.out_file.as_deref(), Some(&b"mine"[..]));
    let t = c.train.unwrap();
    assert_eq!(t.dict, DictType::Cover);
    assert_eq!(
        t.cover,
        TrainAlgo::Cover {
            k: 64,
            d: 8,
            steps: 3,
            split: 0.8,
            shrink: Some(1)
        }
    );
    assert_eq!(t.level, 19);
    // Bare: every field zero (memset), shrink off.
    let t = ok(&["--train-fastcover"]).train.unwrap();
    assert_eq!(
        t.fastcover,
        TrainAlgo::Fastcover {
            k: 0,
            d: 0,
            f: 0,
            steps: 0,
            split: 0.0,
            accel: 0,
            shrink: None
        }
    );
    let t = ok(&["--train-fastcover=f=20,accel=2,shrink=5"])
        .train
        .unwrap();
    assert!(matches!(
        t.fastcover,
        TrainAlgo::Fastcover {
            f: 20,
            accel: 2,
            shrink: Some(5),
            ..
        }
    ));
    let t = ok(&[
        "--train-legacy=selectivity=5",
        "--maxdict=4K",
        "--dictID=1234",
    ])
    .train
    .unwrap();
    assert_eq!(
        (t.dict, t.selectivity, t.max_dict, t.dict_id),
        (DictType::Legacy, 5, 4096, 1234)
    );
    assert_eq!(ok(&["--train-legacy", "-s4"]).train.unwrap().selectivity, 4);
    // --fast=N sets the dictionary's level, --fast does not.
    assert_eq!(ok(&["--train", "--fast=4"]).train.unwrap().level, -4);
    assert_eq!(ok(&["--train", "--fast"]).train.unwrap().level, 3);
    for bad in [
        "--train-cover=x",
        "--train-cover=k=1,",
        "--train-coverx",
        "--train-cover=f=2",
        "--train-fastcover=accel=x",
        "--train-legacy=x",
        "--train-legacy=s=5x",
        "--train-cover=shrinkx",
    ] {
        let (s, _, err) = stop(&[bad]);
        assert_eq!(s, CLEAN_1, "{bad}");
        assert!(
            err.starts_with(&format!("Incorrect parameter: {bad} \n")),
            "{err}"
        );
    }
    // Display level 4 echoes them (the split through a double, as in C).
    let (_, _, err) = run(&["-vv", "--train-cover=k=5,split=29,shrink=3"]);
    assert!(
        err.starts_with("cover: k=5\nd=0\nsteps=0\nsplit=28\nshrink3\n"),
        "{err}"
    );
    let (_, _, err) = run(&["-vv", "--train-fastcover=d=6"]);
    assert!(
        err.starts_with("cover: k=0\nd=6\nf=0\nsteps=0\nsplit=0\naccel=0\nshrink=0\n"),
        "{err}"
    );
    let (_, _, err) = run(&["-vv", "--train-legacy=s=7"]);
    assert!(err.starts_with("legacy: selectivity=7\n"), "{err}");
}

#[test]
fn switches_reach_the_preferences() {
    let c = ok(&[
        "--no-check",
        "--sparse",
        "--no-pass-through",
        "--no-asyncio",
        "--no-dictID",
        "--rm",
        "--no-content-size",
        "--row-match-finder",
        "--compress-literals",
        "--rsyncable",
        "--exclude-compressed",
        "--no-progress",
        "--mmap-dict",
        "--format=lz4",
        "--stream-size=1K",
        "--size-hint=9999999999",
        "--target-compressed-block-size=2K",
        "--output-dir-flat",
        "o",
        "--output-dir-mirror=m",
        "--filelist=l",
        "--filelist",
        "k",
        "--show-default-cparams",
        "--fake-stdin-is-console",
        "-r",
    ]);
    let p = &c.prefs;
    assert_eq!((p.checksum, p.sparse, p.pass_through), (0, 2, 0));
    assert!(!p.async_io && !p.dict_id && p.remove_src && !p.content_size);
    assert_eq!(p.row_match_finder, ParamSwitch::Enable);
    assert_eq!(p.literal_compression, ParamSwitch::Enable);
    assert!(p.rsyncable && p.exclude_compressed && p.fake_stdin_console);
    assert_eq!(
        (p.progress, p.mmap_dict),
        (Progress::Never, ParamSwitch::Enable)
    );
    assert_eq!((p.ctype, c.suffix), (CType::Lz4, ".lz4"));
    assert_eq!(
        (p.stream_size, p.size_hint, p.target_cblock_size),
        (1024, i32::MAX, 2048)
    );
    assert_eq!(c.out_dir_flat.as_deref(), Some(&b"o"[..]));
    assert_eq!(c.out_dir_mirror.as_deref(), Some(&b"m"[..]));
    assert_eq!(c.filelists, [b"l".to_vec(), b"k".to_vec()]);
    assert!(c.show_default_cparams && c.recursive);
    let (s, _, err) = stop(&["--output-dir-flat="]);
    assert_eq!(
        (s, err.as_str()),
        (
            CLEAN_1,
            "error: output dir cannot be empty string (did you mean to pass '.' instead?)\n"
        )
    );
    assert_eq!(ok(&["-kC", "--check"]).prefs.checksum, 2);
    assert!(!ok(&["--rm", "-k"]).prefs.remove_src);
    // Not gzip: gzip's own options are unknown.
    assert_eq!(stop(&["--best"]).0, CLEAN_1);
    let (c, _, _) = run_env("gzip", &["--best", "--no-name"], &[]);
    assert_eq!(c.unwrap().level, 9);
}

#[test]
fn an_argument_ends_at_a_nul_as_a_c_string_does() {
    let c = ok(&["-1\u{0}9", "a\u{0}b"]);
    assert_eq!(c.level, 1);
    assert_eq!(c.files, [b"a".to_vec()]);
}

/// zstdcli.c:708-735, printDefaultCParams, against the reference's output
/// (zstd 1.5.7, `--show-default-cparams -c FILE`, captured 2026-10-13).
#[test]
fn default_cparams_print_as_the_reference_prints_them() {
    let show = |size: Option<u64>, dict: u64, level: i32| {
        let mut v = Vec::new();
        print_default_cparams(&mut v, b"f", size, dict, level);
        let s = String::from_utf8(v).unwrap();
        let mut lines = s.lines();
        let head = lines.next().unwrap().to_string();
        let nums: Vec<String> = lines
            .map(|l| l.split(" : ").nth(1).unwrap().to_string())
            .collect();
        (head, nums.join(","))
    };
    let k = |head: &str, nums: &str| (head.to_string(), nums.to_string());
    assert_eq!(
        show(Some(1), 0, 1),
        k("f (1 bytes)", "10,6,7,1,5,0,ZSTD_fast (1)")
    );
    assert_eq!(
        show(Some(200000), 0, 1),
        k("f (200000 bytes)", "18,13,14,1,6,0,ZSTD_fast (1)")
    );
    assert_eq!(
        show(Some(1 << 20), 0, 1),
        k("f (1048576 bytes)", "19,13,14,1,7,0,ZSTD_fast (1)")
    );
    assert_eq!(
        show(Some(1), 0, 3),
        k("f (1 bytes)", "10,6,7,2,4,0,ZSTD_dfast (2)")
    );
    assert_eq!(show(Some(200000), 0, 3).1, "18,16,16,1,4,0,ZSTD_dfast (2)");
    assert_eq!(show(Some(1 << 20), 0, 3).1, "20,16,17,1,5,0,ZSTD_dfast (2)");
    assert_eq!(show(Some(5000), 0, 3).1, "13,13,14,2,4,0,ZSTD_dfast (2)");
    assert_eq!(show(Some(1), 0, 19).1, "10,7,7,8,3,256,ZSTD_btultra2 (9)");
    assert_eq!(
        show(Some(200000), 0, 19).1,
        "18,19,19,8,3,256,ZSTD_btultra2 (9)"
    );
    assert_eq!(
        show(Some(1 << 20), 0, 19).1,
        "20,21,21,7,3,256,ZSTD_btultra2 (9)"
    );
    assert_eq!(
        show(Some(5000), 0, 19).1,
        "13,14,14,8,3,256,ZSTD_btultra2 (9)"
    );
    assert_eq!(show(Some(1), 0, -5).1, "10,6,7,1,5,5,ZSTD_fast (1)");
    assert_eq!(show(Some(1 << 20), 0, -5).1, "19,12,13,1,6,5,ZSTD_fast (1)");
    assert_eq!(
        show(None, 0, 3),
        k("f (src size unknown)", "21,16,17,1,5,0,ZSTD_dfast (2)")
    );
    assert_eq!(show(None, 0, 22).1, "27,27,25,9,3,999,ZSTD_btultra2 (9)");
    // -D with a 110 KiB dictionary; --patch-from with a 200000-byte file.
    assert_eq!(
        show(Some(1 << 20), 112640, 3).1,
        "21,16,17,1,5,0,ZSTD_dfast (2)"
    );
    assert_eq!(
        show(Some(1 << 20), 200000, 19).1,
        "21,22,22,7,3,256,ZSTD_btultra2 (9)"
    );
    // A dictionary file whose size is unknown (missing): zstd passes
    // UTIL_FILESIZE_UNKNOWN on, and libzstd's arithmetic wraps.
    assert_eq!(
        show(Some(5000), u64::MAX, 3).1,
        "14,14,15,2,4,0,ZSTD_dfast (2)"
    );
}

#[test]
fn actual_cparams_overlay_the_zstd_parameters() {
    let c = ok(&["--zstd=strat=12,wlog=15"]);
    let mut v = Vec::new();
    print_actual_cparams(&mut v, Some(5000), 0, 3, &c);
    assert_eq!(
        String::from_utf8(v).unwrap(),
        "--zstd=wlog=15,clog=13,hlog=14,slog=2,mml=4,tlen=0,strat=12\n"
    );
}
