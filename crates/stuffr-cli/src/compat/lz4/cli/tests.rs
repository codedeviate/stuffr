//! Unit tests for the lz4 command line: every rule `cli.rs` states, from
//! the probes it cites. The differential suite (`tests/compat_lz4.rs`)
//! compares the same rules with the reference binary; these pin what it
//! cannot reach (names other than the four links, the parsed fields, the
//! thread rule on other machines, the decision table's terminals).

use super::*;

/// `parse` as `program`, with `env` for the environment; the result, then
/// standard output and standard error.
fn run(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> (Result<Command, Stop>, String, String) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let lookup = |k: &str| {
        env.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| OsString::from(v))
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = parse(
        program.as_bytes(),
        &lookup,
        &args,
        Cores::SANDBOX,
        &mut out,
        &mut err,
    );
    (
        r,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// A command `lz4 args` must parse to, with nothing printed.
fn ok(args: &[&str]) -> Command {
    ok_as("lz4", args)
}

fn ok_as(program: &str, args: &[&str]) -> Command {
    let (r, out, err) = run(program, args, &[]);
    assert_eq!((out.as_str(), err.as_str()), ("", ""), "{program} {args:?}");
    r.unwrap_or_else(|s| panic!("{program} {args:?}: {s:?}"))
}

/// The stop `lz4 args` ends in, and its standard error.
fn stop(args: &[&str]) -> (Stop, String) {
    let (r, _, err) = run("lz4", args, &[]);
    match r {
        Ok(cmd) => panic!("{args:?} parsed: {cmd:?}"),
        Err(s) => (s, err),
    }
}

fn names(v: &[&str]) -> Vec<Vec<u8>> {
    v.iter().map(|n| n.as_bytes().to_vec()).collect()
}

fn file(n: &str) -> Output {
    Output::File(n.as_bytes().to_vec())
}

const USAGE_ERROR: Stop = Stop {
    code: 1,
    pause: false,
};

// ---- names (R12) ----

#[test]
fn the_program_name_is_the_last_component_after_a_slash_or_backslash() {
    let p = |s: &str| String::from_utf8(program_name(s.as_bytes()).to_vec()).unwrap();
    assert_eq!(p("lz4"), "lz4");
    assert_eq!(p("/usr/local/bin/unlz4"), "unlz4");
    assert_eq!(p("a\\b/c\\unlz4"), "unlz4");
    assert_eq!(p("x\\unlz4.exe"), "unlz4.exe");
    assert_eq!(p("unlz4\\"), "");
    assert_eq!(p("unlz4/"), "");
}

#[test]
fn a_name_matches_itself_or_itself_and_a_dot() {
    // probe: `exec -a NAME lz4` on standard input holding a frame.
    for (program, name, want) in [
        ("unlz4", "unlz4", true),
        ("unlz4.exe", "unlz4", true),
        ("unlz4.", "unlz4", true),
        ("unlz4.1", "unlz4", true),
        ("unlz4.exe.bak", "unlz4", true),
        ("unlz4.EXE", "unlz4", true),
        ("unlz4-1", "unlz4", false),
        ("xunlz4", "unlz4", false),
        ("UNLZ4", "unlz4", false),
        ("Unlz4", "unlz4", false),
        ("unlz4_", "unlz4", false),
        ("lz4unlz4", "unlz4", false),
        ("unlz", "unlz4", false),
        ("lz4cat", "lz4cat", true),
        ("lz4cat.x", "lz4cat", true),
        ("lz4cat-1", "lz4cat", false),
        ("LZ4CAT", "lz4cat", false),
        ("lz4c", "lz4c", true),
        ("lz4c.exe", "lz4c", true),
        ("lz4c.", "lz4c", true),
        ("lz4c-x", "lz4c", false),
        ("xlz4c", "lz4c", false),
        ("LZ4C", "lz4c", false),
        ("lz4cat", "lz4c", false),
        ("lz4", "lz4c", false),
    ] {
        assert_eq!(
            name_matches(program.as_bytes(), name),
            want,
            "{program} as {name}"
        );
    }
}

#[test]
fn each_name_presets_its_mode() {
    assert_eq!(ok_as("lz4", &[]).mode, Mode::Auto);
    for n in ["unlz4", "unlz4.exe", "unlz4.1"] {
        assert_eq!(ok_as(n, &[]).mode, Mode::Decompress, "{n}");
    }
    for n in ["unlz4-1", "xunlz4", "UNLZ4"] {
        assert_eq!(ok_as(n, &[]).mode, Mode::Auto, "{n}");
    }
    // lz4.1: "lz4cat is equivalent to lz4 -dcfm", at display level 1.
    let c = ok_as("lz4cat", &[]);
    assert_eq!(c.mode, Mode::Decompress);
    assert!(c.force && c.force_stdout && c.multiple);
    assert_eq!((c.output, c.display_level), (Output::Stdout, 1));
    assert!(!ok_as("lz4cat", &[]).legacy_cli);
    for n in ["lz4c", "lz4c.exe"] {
        assert!(ok_as(n, &[]).legacy_cli, "{n}");
    }
    assert!(!ok_as("lz4", &[]).legacy_cli);
}

// ---- numbers ----

#[test]
fn numbers_wrap_and_take_k_and_m_suffixes() {
    fn r(s: &str) -> (u32, &str) {
        let mut p = 0;
        let n = read_u32(s.as_bytes(), &mut p);
        (n, &s[p..])
    }
    assert_eq!(r("12x"), (12, "x"));
    assert_eq!(r(""), (0, ""));
    assert_eq!(r("x"), (0, "x"));
    assert_eq!(r("4294967396"), (100, ""));
    assert_eq!(r("42949672960"), (0, ""));
    assert_eq!(r("64K"), (65536, ""));
    assert_eq!(r("64KB"), (65536, ""));
    assert_eq!(r("64KiB"), (65536, ""));
    assert_eq!(r("64Ki"), (65536, ""));
    assert_eq!(r("64KBB"), (65536, "B"));
    assert_eq!(r("64k"), (64, "k"));
    assert_eq!(r("1M"), (1 << 20, ""));
    assert_eq!(r("1MiB"), (1 << 20, ""));
    assert_eq!(r("4194305K"), (1024, ""));
    assert_eq!(r("4096M"), (0, ""));
    assert_eq!(r("K"), (0, ""));
    assert_eq!(r("1i"), (1, "i"));
}

// ---- R4 ----

#[test]
fn the_automatic_thread_count_is_logical_less_an_eighth_less_one() {
    // Probed with an interposed `sysctlbyname("hw.logicalcpu")`.
    let auto = |logical| {
        resolve_threads(
            0,
            Cores {
                logical,
                physical: 1,
            },
        )
    };
    for (logical, want) in [
        (1, 1),
        (2, 1),
        (3, 2),
        (4, 3),
        (5, 4),
        (6, 5),
        (7, 6),
        (8, 6),
        (9, 7),
        (10, 8),
        (11, 9),
        (12, 10),
        (13, 11),
        (16, 13),
        (20, 17),
        (24, 20),
        (32, 27),
        (64, 55),
        (100, 87),
        (128, 111),
        (200, 174),
    ] {
        assert_eq!(auto(logical), (want, None), "{logical} logical cores");
    }
    for (logical, asked) in [(250, 218), (256, 223), (300, 262), (1000, 874)] {
        assert_eq!(auto(logical), (200, Some(asked)), "{logical} logical cores");
    }
    let c = Cores::SANDBOX;
    assert_eq!(resolve_threads(0, c), (6, None));
    assert_eq!(resolve_threads(1, c), (1, None));
    assert_eq!(resolve_threads(200, c), (200, None));
    assert_eq!(resolve_threads(201, c), (200, Some(201)));
}

#[test]
fn threads_come_from_t_threads_and_lz4_nbworkers() {
    assert_eq!(ok(&[]).threads, 6, "automatic on the sandbox's 8 cores");
    assert_eq!(ok(&["-T4"]).threads, 4);
    assert_eq!(ok(&["-T"]).threads, 6);
    assert_eq!(ok(&["-TK"]).threads, 6);
    assert_eq!(ok(&["--threads=5"]).threads, 5);
    assert_eq!(ok(&["--threads", "5"]).threads, 5);
    assert_eq!(ok(&["--threads="]).threads, 6);
    assert_eq!(ok(&["--threads=4294967297"]).threads, 1);
    let c = ok(&["-T1K"]);
    assert_eq!((c.threads, c.threads_reduced_from), (200, Some(1024)));
    let env = |v: &str, args: &[&str]| {
        let (r, _, err) = run("lz4", args, &[("LZ4_NBWORKERS", v)]);
        (r.unwrap().threads, err)
    };
    assert_eq!(env("3", &[]), (3, String::new()));
    assert_eq!(env("3x", &[]), (3, String::new()));
    assert_eq!(env("3", &["-T0"]), (6, String::new()));
    assert_eq!(env("1", &["-T3"]), (3, String::new()));
    assert_eq!(
        env("x", &[]),
        (
            6,
            "Ignore environment variable setting LZ4_NBWORKERS=x: not a valid unsigned value \n"
                .to_string()
        )
    );
}

// ---- levels ----

#[test]
fn levels_come_from_digits_fast_best_and_lz4_clevel() {
    let level = |args: &[&str]| ok(args).opts.level;
    assert_eq!(level(&[]), 1);
    assert_eq!(level(&["-9"]), 9);
    assert_eq!(level(&["-12"]), 12);
    assert_eq!(level(&["-0"]), 0);
    // liblz4 clamps above 12, not the command line.
    assert_eq!(level(&["-99"]), 99);
    assert_eq!(level(&["-1K"]), 1024);
    assert_eq!(level(&["-4294967295"]), -1);
    assert_eq!(level(&["-4294967297"]), 1);
    assert_eq!(level(&["--best"]), 12);
    assert_eq!(level(&["--fast"]), -1);
    assert_eq!(level(&["--fast=3"]), -3);
    assert_eq!(level(&["--fast=1x"]), -1);
    assert_eq!(level(&["--fast=1K"]), -1024);
    assert_eq!(level(&["--fast=4294967295"]), 1);
    assert_eq!(level(&["--fast=2147483648"]), i32::MIN);
    // The last one given wins (lz4.1, "--fast[=#]").
    assert_eq!(level(&["--fast=2", "-3"]), 3);
    assert_eq!(level(&["-3", "--fast"]), -1);
    let env = |v: &str, args: &[&str]| run("lz4", args, &[("LZ4_CLEVEL", v)]).0.unwrap().opts.level;
    assert_eq!(env("9", &[]), 9);
    assert_eq!(env("9", &["-1"]), 1);
    assert_eq!(env("9", &["--fast=2"]), -2);
    assert_eq!(env("4294967295", &[]), -1);
    assert_eq!(env("1K", &[]), 1024);
    assert_eq!(env("-1", &[]), 1);
}

#[test]
fn an_invalid_environment_value_is_warned_about_before_any_argument() {
    // Both, in this order, and before a usage error; `-qq` cannot silence it.
    let (r, _, err) = run(
        "lz4cat",
        &["-qq", "--bogus"],
        &[("LZ4_NBWORKERS", " 4"), ("LZ4_CLEVEL", "")],
    );
    assert_eq!(r.unwrap_err(), USAGE_ERROR);
    assert_eq!(
        err,
        "Ignore environment variable setting LZ4_CLEVEL=: not a valid unsigned value \n\
         Ignore environment variable setting LZ4_NBWORKERS= 4: not a valid unsigned value \n"
    );
}

#[test]
fn lz4c_reads_the_legacy_arguments_from_the_rest_of_an_argument() {
    let c = |args: &[&str]| ok_as("lz4c", args);
    for (args, level, stdout, force) in [
        (&["-c0"][..], 0, false, false),
        (&["-c1"], 9, false, false),
        (&["-c2"], 12, false, false),
        (&["-hc"], 12, false, false),
        (&["-y"], 1, false, true),
        (&["-fy"], 1, false, true),
        (&["-cy"], 1, true, true),
        (&["-fc0"], 0, false, true),
        (&["-9c1"], 9, false, false),
        (&["-c0c"], 0, true, false),
        (&["-c3"], 3, true, false),
        (&["-c"], 1, true, false),
        (&["-Bc0"], 0, false, false),
    ] {
        let cmd = c(args);
        assert_eq!(
            (cmd.opts.level, cmd.force_stdout, cmd.force),
            (level, stdout, force),
            "lz4c {args:?}"
        );
    }
    // `-c0d` is not `-c0` then `-d`.
    let cmd = c(&["-c0d"]);
    assert_eq!(
        (cmd.opts.level, cmd.force_stdout, cmd.mode),
        (0, true, Mode::Decompress)
    );
    // `-Dc0` names a dictionary.
    assert_eq!(c(&["-Dc0"]).dict_file.as_deref(), Some(&b"c0"[..]));
    // Help where the rest is not exactly a legacy argument.
    for args in [&["-hc9"][..], &["-hcd"], &["-h"]] {
        let (r, out, err) = run("lz4c", args, &[]);
        assert_eq!(r.unwrap_err().code, 0, "{args:?}");
        assert!(
            out.is_empty() && err.contains("Legacy arguments : \n"),
            "{err}"
        );
    }
    let (r, _, _) = run("lz4c", &["-yf"], &[]);
    assert_eq!(r.unwrap_err(), USAGE_ERROR);
    // Under `lz4`, `-c0` is `-c -0` and `-y` an error.
    let cmd = ok(&["-c0"]);
    assert_eq!((cmd.opts.level, cmd.force_stdout), (0, true));
    assert_eq!(stop(&["-y"]).0, USAGE_ERROR);
}

// ---- -B and the frame flags ----

#[test]
fn block_sizes_flags_and_their_lines() {
    let (r, _, err) = run("lz4", &["-B4"], &[]);
    let c = r.unwrap();
    assert_eq!(
        (c.opts.block_size, c.opts.block_bytes),
        (BlockSizeId::Max64Kb, None)
    );
    assert_eq!(err, "using blocks of size 64 KB \n");
    let (r, _, err) = run("lz4", &["-B32", "-B5"], &[]);
    let c = r.unwrap();
    assert_eq!(
        (c.opts.block_size, c.opts.block_bytes),
        (BlockSizeId::Max256Kb, None)
    );
    assert_eq!(
        err,
        "using blocks of size 32 bytes \nusing blocks of size 256 KB \n"
    );
    for (arg, bytes, line) in [
        ("-B33", 33, "33 bytes"),
        ("-B1023", 1023, "1023 bytes"),
        ("-B1024", 1024, "1 KB"),
        ("-B65537", 65537, "64 KB"),
        ("-B4194305", 4 << 20, "4096 KB"),
        ("-B99999999999", 4 << 20, "4096 KB"),
        ("-B4194305K", 1024, "1 KB"),
    ] {
        let (r, _, err) = run("lz4", &[arg], &[]);
        assert_eq!(r.unwrap().opts.block_bytes, Some(bytes), "{arg}");
        assert_eq!(err, format!("using blocks of size {line} \n"), "{arg}");
    }
    for bad in ["-B0", "-B3", "-B8", "-B31", "-B1x", "-BK", "-B4-"] {
        assert_eq!(stop(&[bad]).0, USAGE_ERROR, "{bad}");
    }
    // No line below display level 2 at the time.
    let (r, _, err) = run("lz4", &["-q", "-B4"], &[]);
    assert!(r.is_ok() && err.is_empty());
    let c = ok(&["-BDX"]);
    assert!(c.opts.block_linked && c.opts.block_checksum);
    assert!(!ok(&["-BD", "-BI"]).opts.block_linked);
    assert!(ok(&["-B"]).opts == EncodeOptions::default());
    // Back in the outer loop after -B's letters.
    assert_eq!(ok(&["-BDd"]).mode, Mode::Decompress);
    // Checksums, last one wins.
    let c = ok(&["--no-crc", "-BX"]);
    assert!(!c.opts.content_checksum && c.opts.block_checksum);
    let c = ok(&["-BX", "--no-crc"]);
    assert!(!c.opts.content_checksum && !c.opts.block_checksum);
    assert!(ok(&["--no-frame-crc", "--frame-crc"]).opts.content_checksum);
    assert!(ok(&["--content-size"]).content_size);
    assert!(!ok(&["--content-size", "--no-content-size"]).content_size);
    assert_eq!(ok(&["--no-sparse"]).sparse, Some(false));
    assert_eq!(ok(&[]).sparse, None);
    assert!(ok(&["--favor-decSpeed"]).opts.favor_dec_speed);
    assert!(ok(&["-l"]).opts.legacy);
}

// ---- operands ----

#[test]
fn operands_fill_input_then_output() {
    let io = |args: &[&str]| {
        let c = ok(args);
        (c.inputs, c.output, c.from_list)
    };
    assert_eq!(io(&[]), (names(&["stdin"]), Output::Auto, false));
    assert_eq!(io(&["a"]), (names(&["a"]), Output::Auto, false));
    assert_eq!(io(&["a", "b"]), (names(&["a"]), file("b"), false));
    assert_eq!(io(&["a", "stdout"]), (names(&["a"]), Output::Stdout, false));
    assert_eq!(io(&["a", "null"]), (names(&["a"]), Output::Null, false));
    assert_eq!(io(&["a", "STDOUT"]), (names(&["a"]), file("STDOUT"), false));
    assert_eq!(io(&["a", "stdin"]), (names(&["a"]), file("stdin"), false));
    assert_eq!(io(&["-", "a"]), (names(&["stdin"]), file("a"), false));
    assert_eq!(io(&["a", "b", "-"]), (names(&["a"]), Output::Stdout, false));
    assert_eq!(
        io(&["-", "-", "-"]),
        (names(&["stdin"]), Output::Stdout, false)
    );
    assert_eq!(
        io(&["a", "b", "-c"]),
        (names(&["a"]), Output::Stdout, false)
    );
    assert_eq!(
        io(&["a", "null", "-c"]),
        (names(&["a"]), Output::Stdout, false)
    );
    assert_eq!(io(&["--", "-c"]), (names(&["-c"]), Output::Auto, false));
    assert_eq!(io(&["--", "a", "-"]), (names(&["a"]), file("-"), false));
    assert_eq!(io(&["", "a"]), (names(&[""]), file("a"), false));
    // -m: only the operands after it.
    assert_eq!(
        io(&["-m", "a", "b"]),
        (names(&["a", "b"]), Output::Auto, true)
    );
    assert_eq!(io(&["a", "-m", "b"]), (names(&["b"]), Output::Auto, true));
    assert_eq!(io(&["a", "b", "-m"]), (names(&["stdin"]), file("b"), false));
    assert_eq!(io(&["a", "-m"]), (names(&["stdin"]), Output::Auto, false));
    assert_eq!(io(&["-m", "a", "-"]), (names(&["a"]), Output::Auto, true));
    assert_eq!(
        io(&["-m", "a", "stdout"]),
        (names(&["a", "stdout"]), Output::Auto, true)
    );
    assert_eq!(
        io(&["-m", "-c", "a", "b"]),
        (names(&["a", "b"]), Output::Stdout, true)
    );
    assert_eq!(
        io(&["a", "-", "-m", "c"]),
        (names(&["c"]), Output::Stdout, true)
    );
    assert_eq!(
        io(&["a", "null", "-m", "c"]),
        (names(&["c"]), Output::Null, true)
    );
    assert_eq!(
        io(&["a", "b", "-m", "c"]),
        (names(&["c"]), Output::Auto, true)
    );
    assert_eq!(io(&["-r", "a"]), (names(&["a"]), Output::Auto, true));
    assert!(ok(&["-r"]).recursive);
    let c = ok(&["--list", "b.lz4"]);
    assert_eq!((c.mode, c.from_list), (Mode::List, true));
    assert_eq!(
        io(&["b.lz4", "--list"]),
        (names(&["stdin"]), Output::Auto, false)
    );
    // lz4cat's operands are all inputs.
    let c = ok_as("lz4cat", &["a", "b"]);
    assert_eq!((c.inputs, c.output), (names(&["a", "b"]), Output::Stdout));
}

#[test]
fn a_surplus_operand_ends_the_parse_when_it_is_read() {
    let msg =
        |n: &str| format!("Error : {n} won't be used ! Do you want multiple input files (-m) ? \n");
    assert_eq!(stop(&["a", "b", "c", "-h"]), (USAGE_ERROR, msg("c")));
    assert_eq!(stop(&["-c", "a", "b"]), (USAGE_ERROR, msg("b")));
    assert_eq!(stop(&["-c", "a", "stdout"]), (USAGE_ERROR, msg("stdout")));
    assert_eq!(stop(&["a", "-", "b"]), (USAGE_ERROR, msg("b")));
    assert_eq!(stop(&["-T", "2", "-c", "a"]), (USAGE_ERROR, msg("a")));
    assert_eq!(stop(&["-qq", "a", "b", "c"]), (USAGE_ERROR, String::new()));
    assert_eq!(stop(&["-p", "a", "b", "c"]).0, USAGE_ERROR);
}

#[test]
fn modes_and_switches_last_one_wins() {
    assert_eq!(ok(&["-z", "-d"]).mode, Mode::Decompress);
    assert_eq!(ok(&["-d", "-z"]).mode, Mode::Compress);
    assert_eq!(ok(&["-t", "-d"]).mode, Mode::Decompress);
    assert_eq!(ok(&["-d", "-t"]).mode, Mode::Test);
    assert_eq!(ok(&["--list", "-d"]).mode, Mode::Decompress);
    assert_eq!(ok(&["-d", "--list"]).mode, Mode::List);
    assert_eq!(ok(&["--uncompress"]).mode, Mode::Decompress);
    assert_eq!(ok(&["--compress"]).mode, Mode::Compress);
    assert_eq!(ok(&["--test"]).mode, Mode::Test);
    let c = ok(&["--rm", "-k"]);
    assert!(c.keep && !c.remove);
    let c = ok(&["-k", "--rm"]);
    assert!(!c.keep && c.remove);
    assert!(!ok(&["-f", "--no-force"]).force);
    assert!(ok(&["--no-force", "--force"]).force);
    assert_eq!(ok(&["-vvq"]).display_level, 3);
    assert_eq!(ok(&["--verbose", "--quiet", "--quiet"]).display_level, 1);
    assert!(ok(&["-p"]).pause);
    assert!(ok(&["-S"]).dict_file.is_none());
}

#[test]
fn d_takes_the_rest_of_its_argument_or_the_next() {
    assert_eq!(ok(&["-Dx"]).dict_file.as_deref(), Some(&b"x"[..]));
    assert_eq!(ok(&["-D", "x"]).dict_file.as_deref(), Some(&b"x"[..]));
    assert_eq!(ok(&["-D", "-h"]).dict_file.as_deref(), Some(&b"-h"[..]));
    assert_eq!(ok(&["-dD", "x", "a"]).inputs, names(&["a"]));
    assert_eq!(stop(&["-D"]).0, USAGE_ERROR);
    assert_eq!(stop(&["a", "-dD"]).0, USAGE_ERROR);
}

#[test]
fn threads_errors_name_their_cause() {
    let numeric =
        "error: only numeric values with optional suffixes K, KB, KiB, M, MB, MiB are allowed \n";
    assert_eq!(stop(&["--threads=x"]), (USAGE_ERROR, numeric.into()));
    assert_eq!(stop(&["--threads=4x"]), (USAGE_ERROR, numeric.into()));
    assert_eq!(stop(&["--threads4", "a"]), (USAGE_ERROR, numeric.into()));
    assert_eq!(
        stop(&["a", "--threads"]),
        (USAGE_ERROR, "error: missing command argument \n".into())
    );
    let separated = "error: command cannot be separated from its argument by another command \n";
    assert_eq!(stop(&["--threads", "-c"]), (USAGE_ERROR, separated.into()));
    assert_eq!(stop(&["--threads", "-"]), (USAGE_ERROR, separated.into()));
    assert_eq!(stop(&["-qq", "--threads=x"]), (USAGE_ERROR, String::new()));
    assert_eq!(ok(&["--threadsx", "4"]).threads, 4);
}

#[test]
fn usage_errors_print_at_display_level_1() {
    let usage = |name: &str| {
        let mut v = Vec::new();
        printf(&mut v, m::INCORRECT_PARAMETERS, &[]);
        printf(&mut v, m::USAGE, &[name.as_bytes()]);
        String::from_utf8(v).unwrap()
    };
    for bad in [
        &["--bogus"][..],
        &["-x"],
        &["--fast=0"],
        &["--fast="],
        &["--fast3"],
        &["--fast=4294967296"],
        &["--best=1"],
        &["--decomp"],
        &["-d-c"],
        &["-Tx"],
        &["-T4x"],
        &["-bK"],
        &["-e3x"],
        &["-y"],
    ] {
        assert_eq!(stop(bad), (USAGE_ERROR, usage("lz4")), "{bad:?}");
    }
    assert_eq!(stop(&["-qq", "--bogus"]), (USAGE_ERROR, String::new()));
    assert_eq!(stop(&["--bogus", "-qq"]), (USAGE_ERROR, usage("lz4")));
    let (r, _, err) = run("unlz4", &["--bogus"], &[]);
    assert_eq!((r.unwrap_err(), err), (USAGE_ERROR, usage("unlz4")));
}

// ---- help, version, the benchmark, -p ----

#[test]
fn help_and_version_print_at_once_whatever_the_level() {
    let banner = format!(
        "*** lz4 v1.10.0 64-bit multithread (stuffr {}), by Yann Collet ***\n",
        env!("CARGO_PKG_VERSION")
    );
    for args in [
        &["-V"][..],
        &["-qq", "-V"],
        &["-V", "--bogus"],
        &["-Vh"],
        &["--version"],
    ] {
        let (r, out, err) = run("lz4", args, &[]);
        assert_eq!(
            (r.unwrap_err(), out.as_str(), err.as_str()),
            (
                Stop {
                    code: 0,
                    pause: false
                },
                banner.as_str(),
                ""
            ),
            "{args:?}"
        );
    }
    let (r, out, short) = run("lz4", &["-qq", "-h"], &[]);
    assert_eq!((r.unwrap_err().code, out.as_str()), (0, ""));
    assert!(short.starts_with(&banner));
    // (The help's columns are built with `repeat`: a literal run of blanks
    // trips `no_message_literal_in_the_workspace_carries_a_run_of_collapsed_indentation`.)
    let blanks = |n: usize| " ".repeat(n);
    assert!(short.ends_with(&format!(
        " -i#{}: minimum evaluation time in seconds (default : 3s) \n",
        blanks(4)
    )));
    assert_eq!(run("lz4", &["--help"], &[]).2, short);
    assert_eq!(run("lz4", &["-hV"], &[]).2, short);
    let long = run("lz4", &["-H"], &[]).2;
    assert!(long.starts_with(&short));
    assert!(long.ends_with(&format!("{}generator | lz4 | consumer \n", blanks(10))));
    let long_c = run("lz4c", &["-H"], &[]).2;
    assert!(long_c.contains(&format!(
        " -y{}: overwrite output without prompting \n\n****",
        blanks(5)
    )));
    assert!(long_c.ends_with(&format!(
        "{}lz4c -h -c filename \nwhich displays help text and exits \n",
        blanks(10)
    )));
    // `-p` pauses after either.
    assert_eq!(
        run("lz4", &["-p", "-V"], &[]).0.unwrap_err(),
        Stop {
            code: 0,
            pause: true
        }
    );
    assert_eq!(
        run("lz4", &["-V", "-p"], &[]).0.unwrap_err(),
        Stop {
            code: 0,
            pause: false
        }
    );
}

#[test]
fn the_benchmark_is_refused_once_the_line_parses() {
    let refused = (USAGE_ERROR, m::BENCH_REFUSED.to_string());
    assert_eq!(stop(&["-b"]), refused);
    assert_eq!(stop(&["-b3", "a"]), refused);
    assert_eq!(stop(&["-b1", "-e3", "a"]), refused);
    assert_eq!(stop(&["-b", "-d"]), refused);
    // probe: `-e#`/`-i#` without `-b` are ignored (lz4 -e3 -c a compresses).
    for args in [&["-e3"][..], &["-i1"], &["-eK"], &["-T1i"], &["-9e3", "a"]] {
        assert!(run("lz4", args, &[]).0.is_ok(), "{args:?}");
    }
    assert_eq!(stop(&["-qq", "-b"]), (USAGE_ERROR, String::new()));
    // Help and usage errors answer first.
    assert_eq!(run("lz4", &["-b", "-h"], &[]).0.unwrap_err().code, 0);
    assert_eq!(
        stop(&["-b", "--bogus"]).1.lines().next(),
        Some("Incorrect parameters")
    );
}

// ---- the decision table ----

fn plan_of(
    program: &str,
    args: &[&str],
    stdin_tty: bool,
    stdout_tty: bool,
) -> Result<Plan, Refusal> {
    plan(&ok_as(program, args), stdin_tty, stdout_tty)
}

fn planned(op: Op, target: Target, derived: bool) -> Result<Plan, Refusal> {
    Ok(Plan {
        op,
        target,
        derived,
    })
}

fn tf(n: &str) -> Target {
    Target::File(n.as_bytes().to_vec())
}

#[test]
fn where_a_single_input_goes() {
    use Op::*;
    let p = |args: &[&str]| plan_of("lz4", args, false, false);
    assert_eq!(p(&["f"]), planned(Compress, tf("f.lz4"), true));
    assert_eq!(p(&["f", "-"]), planned(Compress, Target::Stdout, false));
    assert_eq!(
        p(&["f", "stdout"]),
        planned(Compress, Target::Stdout, false)
    );
    assert_eq!(p(&["-c", "f"]), planned(Compress, Target::Stdout, false));
    assert_eq!(p(&["f", "null"]), planned(Compress, Target::Null, false));
    assert_eq!(p(&["f", "out"]), planned(Compress, tf("out"), false));
    assert_eq!(p(&[]), planned(Compress, Target::Stdout, false));
    assert_eq!(p(&["-"]), planned(Compress, Target::Stdout, false));
    assert_eq!(p(&["stdin"]), planned(Compress, Target::Stdout, false));
    assert_eq!(p(&["-", "out"]), planned(Compress, tf("out"), false));
    assert_eq!(p(&["x.LZ4"]), planned(Compress, tf("x.LZ4.lz4"), true));
    assert_eq!(
        p(&["-z", "f.lz4"]),
        planned(Compress, tf("f.lz4.lz4"), true)
    );
    assert_eq!(p(&["f.lz4"]), planned(Decompress, tf("f"), true));
    assert_eq!(p(&["-d", "f.lz4"]), planned(Decompress, tf("f"), true));
    assert_eq!(p(&["y.lz4.lz4"]), planned(Decompress, tf("y.lz4"), true));
    assert_eq!(p(&["f.lz4", "out"]), planned(Decompress, tf("out"), false));
    assert_eq!(
        p(&["-dc", "f.lz4"]),
        planned(Decompress, Target::Stdout, false)
    );
    assert_eq!(p(&["-d"]), planned(Decompress, Target::Stdout, false));
    assert_eq!(p(&["-d", "f"]), Err(Refusal::NoOutputName));
    assert_eq!(p(&[".lz4"]), Err(Refusal::NoOutputName));
    assert_eq!(
        plan_of("unlz4", &["f"], false, false),
        Err(Refusal::NoOutputName)
    );
    assert_eq!(
        plan_of("unlz4", &["f.lz4"], false, false),
        planned(Decompress, tf("f"), true)
    );
    assert_eq!(p(&["-t", "f.lz4"]), planned(Test, Target::Null, false));
    assert_eq!(
        p(&["-t", "f.lz4", "out"]),
        planned(Test, Target::Null, false)
    );
    assert_eq!(
        p(&["-t", "-c", "f.lz4"]),
        planned(Test, Target::Null, false)
    );
    assert_eq!(
        p(&["-t", "-dc", "f.lz4"]),
        planned(Decompress, Target::Stdout, false)
    );
    assert_eq!(p(&["a", "b", "-m"]), planned(Compress, tf("b"), false));
    assert_eq!(p(&["a", "-m"]), planned(Compress, Target::Stdout, false));
}

#[test]
fn terminals_are_refused_where_lz4_refuses_them() {
    use Op::*;
    let tty_in = |name: &str, args: &[&str]| plan_of(name, args, true, false);
    let tty_out = |name: &str, args: &[&str]| plan_of(name, args, false, true);
    for (name, args) in [
        ("lz4", &[][..]),
        ("lz4", &["-c"]),
        ("lz4", &["-d"]),
        ("lz4", &["-dc"]),
        ("lz4", &["-", "out"]),
        ("lz4", &["-m"]),
        ("lz4", &["-m", "stdin"]),
        ("lz4", &["-t"]),
        ("lz4", &["--list"]),
        ("lz4", &["-f"]),
        ("lz4", &["stdin", "x"]),
        ("lz4cat", &[]),
        ("unlz4", &[]),
    ] {
        assert_eq!(
            tty_in(name, args),
            Err(Refusal::StdinConsole),
            "{name} {args:?}"
        );
    }
    assert_eq!(tty_in("lz4", &["a"]), planned(Compress, tf("a.lz4"), true));
    assert_eq!(
        tty_in("lz4", &["a", "-"]),
        planned(Compress, Target::Stdout, false)
    );
    assert!(tty_in("lz4", &["-m", "a", "stdin"]).is_ok());
    for (name, args) in [
        ("lz4", &[][..]),
        ("lz4", &["a", "-"]),
        ("lz4", &["a", "stdout"]),
        ("lz4", &["-d"]),
        ("lz4", &["-m"]),
        ("lz4", &["-m", "stdin"]),
        ("unlz4", &[]),
        ("unlz4", &["b.lz4", "-"]),
    ] {
        assert_eq!(
            tty_out(name, args),
            Err(Refusal::StdoutConsole),
            "{name} {args:?}"
        );
    }
    assert_eq!(tty_out("lz4", &["a"]), planned(Compress, tf("a.lz4"), true));
    assert_eq!(
        tty_out("lz4", &["-c", "a"]),
        planned(Compress, Target::Stdout, false)
    );
    assert_eq!(
        tty_out("lz4", &["-dc"]),
        planned(Decompress, Target::Stdout, false)
    );
    assert_eq!(tty_out("lz4cat", &["b.lz4"]).map(|p| p.op), Ok(Decompress));
    assert_eq!(tty_out("lz4", &["-t"]), planned(Test, Target::Null, false));
    assert_eq!(tty_out("lz4", &["-m", "a"]).map(|p| p.op), Ok(Compress));
    assert_eq!(
        tty_out("lz4", &["-m", "-t", "b.lz4"]).map(|p| p.op),
        Ok(Test)
    );
    assert_eq!(tty_out("lz4", &["--list", "b.lz4"]).map(|p| p.op), Ok(List));
    // Standard input's check comes first.
    assert_eq!(plan_of("lz4", &[], true, true), Err(Refusal::StdinConsole));
}

#[test]
fn where_each_input_of_a_list_goes() {
    let t = |args: &[&str], name: &str| {
        let cmd = ok(args);
        let op = op_for(cmd.mode, &cmd.inputs[0]);
        list_target(&cmd, op, name.as_bytes())
    };
    assert_eq!(t(&["-m", "a", "c"], "c"), Some(tf("c.lz4")));
    assert_eq!(t(&["-m", "a", "stdin"], "stdin"), Some(tf("stdin.lz4")));
    assert_eq!(t(&["-m", "a", "b.lz4"], "b.lz4"), Some(tf("b.lz4.lz4")));
    assert_eq!(t(&["-m", "-c", "a", "c"], "c"), Some(Target::Stdout));
    assert_eq!(t(&["a", "-", "-m", "c"], "c"), Some(Target::Stdout));
    assert_eq!(t(&["a", "null", "-m", "c"], "c"), Some(tf("c.lz4")));
    assert_eq!(t(&["-m", "b.lz4", "a"], "a"), None);
    assert_eq!(t(&["-m", "b.lz4", "x.lz4"], "x.lz4"), Some(tf("x")));
    assert_eq!(t(&["-m", "-d", ".lz4"], ".lz4"), None);
    assert_eq!(t(&["-m", "-c", "-d", "a"], "a"), Some(Target::Stdout));
    assert_eq!(
        t(&["a", "null", "-m", "-d", "b.lz4"], "b.lz4"),
        Some(Target::Stdout)
    );
    assert_eq!(t(&["-m", "-t", "b.lz4"], "b.lz4"), Some(Target::Stdout));
    assert_eq!(t(&["-m", "-z", "-t", "a"], "a"), Some(Target::Stdout));
    let cat = ok_as("lz4cat", &["-t", "b.lz4"]);
    assert_eq!(list_target(&cat, Op::Test, b"b.lz4"), Some(Target::Stdout));
}

#[test]
fn refusals_print_their_line_and_exit_1() {
    let r = |args: &[&str], refusal| {
        let mut err = Vec::new();
        let code = refuse(&mut err, &ok(args), refusal);
        (code, String::from_utf8(err).unwrap())
    };
    assert_eq!(
        r(&[], Refusal::StdinConsole),
        (1, "refusing to read from a console\n".into())
    );
    assert_eq!(
        r(&[], Refusal::StdoutConsole),
        (1, "refusing to write to console without -c \n".into())
    );
    let (code, err) = r(&["-d", "a"], Refusal::NoOutputName);
    assert_eq!(code, 1);
    assert!(
        err.starts_with("Cannot determine an output filename \nIncorrect parameters\nUsage : \n")
    );
    assert_eq!(r(&["-qq"], Refusal::NoOutputName), (1, String::new()));
    assert_eq!(r(&["-qq"], Refusal::StdinConsole), (1, String::new()));
}
