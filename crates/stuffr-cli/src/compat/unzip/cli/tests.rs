//! The command line, ported from `uz_opts()`, `zi_opts()`, `unzip()`'s
//! operand loop and `envargs()`; each case's expectation is the C's
//! behaviour, checked against Apple's `/usr/bin/unzip` where it prints
//! something (`compat_unzip_common.rs` compares those rows whole).

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::super::{Flavour, Uz};
use super::*;
use crate::compat::host::{Host, SANDBOX_OUTPUT_CAP, Sandbox};

/// What one parse did: its result, the options, and the two streams.
struct Run {
    parsed: Result<Parsed, i32>,
    o: Options,
    extract_flag: bool,
    noargs: bool,
    out: String,
    err: String,
}

/// Parse `args` in UnZip mode (`zipinfo` false) or ZipInfo mode, as Apple's
/// flavour, with `env` the whole environment.
fn parse(zipinfo: bool, args: &[&str], env: &[(&str, &str)]) -> Run {
    parse_as(Flavour::Apple, zipinfo, args, env)
}

/// [`parse`] as flavour `f`.
fn parse_as(f: Flavour, zipinfo: bool, args: &[&str], env: &[(&str, &str)]) -> Run {
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let host = Host::Sandbox(Sandbox {
        dir: std::env::temp_dir(),
        stdin: Some(Vec::new()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
        reads: Arc::new(Mutex::new(BTreeMap::new())),
    });
    let env: Vec<(String, OsString)> = env
        .iter()
        .map(|(k, v)| (k.to_string(), OsString::from(v)))
        .collect();
    let lookup = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let mut err = Vec::new();
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (parsed, o, extract_flag, noargs) = {
        let mut uz = Uz::new(host, f, &lookup, &mut err);
        let parsed = if zipinfo {
            parse_zipinfo(&mut uz, &args)
        } else {
            parse_unzip(&mut uz, &args)
        };
        (parsed, uz.o.clone(), uz.extract_flag, uz.noargs)
    };
    let out = std::mem::take(&mut *stdout.lock().unwrap());
    Run {
        parsed,
        o,
        extract_flag,
        noargs,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

fn unzip(args: &[&str]) -> Run {
    parse(false, args, &[])
}

fn ok(r: &Run) -> &Parsed {
    match &r.parsed {
        Ok(p) => p,
        Err(code) => panic!("exit {code}: {}{}", r.out, r.err),
    }
}

fn names(v: &[OsString]) -> Vec<&str> {
    v.iter().map(|a| a.to_str().unwrap()).collect()
}

#[test]
fn options_cluster_and_count() {
    let r = unzip(&["-jo", "-qq", "-aaa", "-LL", "a.zip"]);
    let p = ok(&r);
    assert_eq!(p.archive, "a.zip");
    assert!(r.o.jflag);
    assert_eq!(
        (r.o.overwrite_all, r.o.qflag, r.o.aflag, r.o.l_flag),
        (1, 2, 2, 2)
    );
    assert!(r.extract_flag);
    // `-b` clears `-a`; `-p` is `-c` and 999 `-q`s.
    let r = unzip(&["-aab", "-p", "a.zip"]);
    ok(&r);
    assert_eq!((r.o.aflag, r.o.cflag, r.o.qflag), (0, true, 999));
    assert!(!r.extract_flag);
    // A first `-v` is 2, then each counts; `-l` counts from 0.
    let r = unzip(&["-vv", "a.zip"]);
    ok(&r);
    assert_eq!(r.o.vflag, 3);
    let r = unzip(&["-ll", "a.zip"]);
    ok(&r);
    assert_eq!(r.o.vflag, 2);
}

/// A `-` negates the next option letter; the count carries across
/// arguments, and `-e`, `-x` and `-h` leave it pending.
#[test]
fn a_dash_negates_the_next_option() {
    // `--q`: the first `-` starts the option, the second negates.
    let r = unzip(&["-qqq", "--q", "a.zip"]);
    ok(&r);
    assert_eq!(r.o.qflag, 2);
    let r = unzip(&["-qqq", "---q", "a.zip"]);
    ok(&r);
    assert_eq!(r.o.qflag, 1, "two dashes take two");
    let r = unzip(&["-qq", "-x-q", "a.zip"]);
    ok(&r);
    assert_eq!(r.o.qflag, 1, "-x-q: -x is a no-op, -q negated");
    let r = unzip(&["-qq", "--", "-q", "a.zip"]);
    ok(&r);
    assert_eq!(r.o.qflag, 1, "the negation carries into the next argument");
    let r = unzip(&["-j", "-j-", "-ej", "a.zip"]);
    ok(&r);
    assert!(!r.o.jflag, "-e leaves the pending negation for -j");
    let r = unzip(&["-n-n", "-o-o", "a.zip"]);
    ok(&r);
    assert!(!r.o.overwrite_none);
    assert_eq!(r.o.overwrite_all, 0);
    // `-f` sets `-u` too, and `-f-f` clears both.
    let r = unzip(&["-f-f", "a.zip"]);
    ok(&r);
    assert!(!r.o.fflag && !r.o.uflag);
}

#[test]
fn d_takes_its_value_attached_or_next() {
    for args in [
        &["-dout", "a.zip"][..],
        &["-d", "out", "a.zip"],
        &["a.zip", "-d", "out"],
        &["a.zip", "-dout"],
    ] {
        let r = unzip(args);
        let p = ok(&r);
        assert_eq!(p.exdir.as_deref(), Some(OsStr::new("out")), "{args:?}");
        assert_eq!(r.o.exdir.as_deref(), Some(&b"out"[..]), "{args:?}");
        assert!(p.include.is_empty() && p.exclude.is_empty(), "{args:?}");
    }
    // The rest of `-dout` is the directory, not more options.
    let r = unzip(&["-dqq", "a.zip"]);
    assert_eq!(ok(&r).exdir.as_deref(), Some(OsStr::new("qq")));
    assert_eq!(r.o.qflag, 0);
    // A value starting with `-`, a missing one, and a second `-d`.
    for args in [&["-d", "-x", "a.zip"][..], &["-d"], &["a.zip", "-d"]] {
        let r = unzip(args);
        assert_eq!(r.parsed, Err(10), "{args:?}");
        assert_eq!(r.err, m::MUST_GIVE_EXDIR, "{args:?}");
    }
    let r = unzip(&["-d", "x", "-d", "y", "a.zip"]);
    assert_eq!((r.parsed, r.err.as_str()), (Err(10), m::ONLY_ONE_EXDIR));
    let r = unzip(&["-q-d", "x", "a.zip"]);
    assert_eq!((r.parsed, r.err.as_str()), (Err(10), m::MUST_GIVE_EXDIR));
    // After the archive with one before it, `-d` is just a name.
    let r = unzip(&["-dx", "a.zip", "-dy", "f"]);
    let p = ok(&r);
    assert_eq!(p.exdir.as_deref(), Some(OsStr::new("x")));
    assert_eq!(names(&p.include), ["-dy", "f"]);
    // `-l` does not extract: "-d ignored".
    let r = unzip(&["-l", "a.zip", "-d", "x"]);
    ok(&r);
    assert_eq!(r.err, m::NOT_EXTRACTING);
}

#[test]
fn p_takes_a_password_and_a_second_is_read_as_options() {
    let r = unzip(&["-P", "secret", "a.zip"]);
    ok(&r);
    assert_eq!(r.o.pwdarg.as_deref(), Some(&b"secret"[..]));
    let r = unzip(&["-Pone", "-Pq", "a.zip"]);
    ok(&r);
    assert_eq!(r.o.pwdarg.as_deref(), Some(&b"one"[..]));
    assert_eq!(r.o.qflag, 1, "the second -P is ignored, its q read");
    for args in [&["-P"][..], &["-P", "-q", "a.zip"], &["--P", "x", "a.zip"]] {
        let r = unzip(args);
        assert_eq!(r.parsed, Err(10), "{args:?}");
        assert_eq!(r.err, m::MUST_GIVE_PASSWD, "{args:?}");
    }
}

/// unzip.c's operand loop: names to include, `-x` and the names to exclude,
/// a `-d` among them.
#[test]
fn x_lists_and_operands() {
    let r = unzip(&["a.zip", "f1", "f2", "-x", "e1", "e2"]);
    let p = ok(&r);
    assert_eq!(names(&p.include), ["f1", "f2"]);
    assert_eq!(names(&p.exclude), ["e1", "e2"]);
    let r = unzip(&["a.zip", "-x", "e1"]);
    let p = ok(&r);
    assert!(p.include.is_empty());
    assert_eq!(names(&p.exclude), ["e1"]);
    // `-d` ends the include list; what follows is left out.
    let r = unzip(&["a.zip", "f1", "-d", "dir", "f2"]);
    let p = ok(&r);
    assert_eq!(names(&p.include), ["f1"]);
    assert_eq!(p.exdir.as_deref(), Some(OsStr::new("dir")));
    // `-d` ends the exclude list, and later names (and `-x`) are ignored.
    let r = unzip(&["a.zip", "f1", "-x", "e1", "-d", "dir", "e2", "-x", "e3"]);
    let p = ok(&r);
    assert_eq!(names(&p.include), ["f1"]);
    assert_eq!(names(&p.exclude), ["e1"]);
    // `-d` first, then names: they are the include list.
    let r = unzip(&["a.zip", "-d", "dir", "f1", "-x", "e1"]);
    let p = ok(&r);
    assert_eq!(names(&p.include), ["f1"]);
    assert_eq!(names(&p.exclude), ["e1"]);
    // ruling: P20: `-d` cuts the include list at `f1`, `f2` restarts it
    // and `-x` recounts it over the hole (C: `[f1, NULL, dir, f2]`, upstream
    // undefined behaviour, Apple crashes after `f1`); stuffr ends the list
    // at the hole, keeps `dir` and the exclude list.
    let r = unzip(&["a.zip", "f1", "-d", "dir", "f2", "-x", "e"]);
    let p = ok(&r);
    assert_eq!(names(&p.include), ["f1"]);
    assert_eq!(names(&p.exclude), ["e"]);
    assert_eq!(p.exdir.as_deref(), Some(OsStr::new("dir")));
    // Only the operand `-x` exactly starts the exclude list.
    let r = unzip(&["a.zip", "-xf", "f"]);
    assert_eq!(names(&ok(&r).include), ["-xf", "f"]);
    // `-x` with nothing after it.
    let r = unzip(&["a.zip", "f1", "-x"]);
    let p = ok(&r);
    assert_eq!(names(&p.include), ["f1"]);
    assert!(p.exclude.is_empty());
}

#[test]
fn usage_help_and_bad_options() {
    // `-h` prints the usage to standard output and ends the run, exit 0.
    let r = unzip(&["-h", "a.zip"]);
    assert_eq!(r.parsed, Err(0));
    assert!(r.out.contains(m::UNZIP_USAGE_LINE2), "{}", r.out);
    assert_eq!(r.err, "");
    // No arguments at all: the usage, exit 0; options but no archive: exit
    // 10, on standard error.
    let r = unzip(&[]);
    assert_eq!(r.parsed, Err(0));
    assert!(r.noargs);
    assert!(r.out.ends_with(m::UNZIP_USAGE_LINE5));
    let r = unzip(&["-l"]);
    assert_eq!(r.parsed, Err(10));
    assert_eq!(r.out, "");
    assert!(r.err.ends_with(m::UNZIP_USAGE_LINE5));
    // An unknown letter is an error, after the whole command line parsed.
    let r = unzip(&["-k", "-d", "x", "a.zip"]);
    assert_eq!(r.parsed, Err(10));
    assert!(r.err.contains(m::UNZIP_USAGE_LINE2));
    // Under `-t` every message goes to standard output.
    let r = unzip(&["-t", "-k", "a.zip"]);
    assert_eq!(r.parsed, Err(10));
    assert_eq!(r.err, "");
    assert!(r.out.contains(m::UNZIP_USAGE_LINE2));
    let r = unzip(&["-ct", "a.zip"]);
    assert_eq!(r.parsed, Err(10));
    assert!(r.out.starts_with(m::INVALID_OPTIONS), "{}", r.out);
    // `-hh` is the extended help.
    let r = unzip(&["-hh"]);
    assert_eq!(r.parsed, Err(0));
    assert!(r.out.starts_with("\nExtended Help for UnZip\n"));
    assert!(r.out.contains("(or %% or #, depending on OS)"));
    // `-Z` past the first argument is refused, then the usage.
    let r = unzip(&["-lZ", "a.zip"]);
    assert_eq!(r.parsed, Err(10));
    assert!(r.err.starts_with(m::Z_FIRST), "{}", r.err);
    // `-n` and `-o`: a caution, `-o` dropped.
    let r = unzip(&["-no", "a.zip"]);
    ok(&r);
    assert_eq!(r.err, m::IGNORE_O_OPTION);
    assert_eq!(r.o.overwrite_all, 0);
}

#[test]
fn v_alone_is_the_version_screen() {
    let r = unzip(&["-v"]);
    assert_eq!(r.parsed, Err(0));
    assert!(r.out.contains(m::APPLE_COMPILED_WITH), "{}", r.out);
    // EnvOptFormat, `%16s:  %.1024s`.
    let none: String = ["UNZIP", "UNZIPOPT", "ZIPINFO", "ZIPINFOOPT"]
        .iter()
        .map(|n| format!("{n:>16}:  [none]\n"))
        .collect();
    assert!(r.out.ends_with(&none), "{}", r.out);
    // Even with a bad option; `-vqqqq` is the number only.
    assert_eq!(unzip(&["-v", "-k"]).parsed, Err(0));
    let r = unzip(&["-vqqqq"]);
    assert_eq!((r.parsed, r.out.as_str()), (Err(0), "600\n"));
    // `-v` negated is no version screen: options without an archive.
    assert_eq!(unzip(&["-v-v"]).parsed, Err(10));
}

#[test]
fn unzip_and_unzipopt_come_before_the_command_line() {
    // UNZIP's `-o` meets the command line's `-n`.
    let r = parse(false, &["-n", "a.zip"], &[("UNZIP", "-o -q")]);
    ok(&r);
    assert_eq!(r.err, m::IGNORE_O_OPTION);
    assert_eq!(r.o.qflag, 1);
    // The command line negates what the environment set.
    let r = parse(false, &["--q", "a.zip"], &[("UNZIP", "-qq")]);
    ok(&r);
    assert_eq!(r.o.qflag, 1);
    let r = parse(false, &["-j-j", "a.zip"], &[("UNZIP", "-j")]);
    ok(&r);
    assert!(!r.o.jflag);
    // UNZIPOPT when UNZIP is unset, empty or blank only.
    for unzip_var in [None, Some(""), Some("  \t ")] {
        let mut env = vec![("UNZIPOPT", "-j")];
        if let Some(v) = unzip_var {
            env.push(("UNZIP", v));
        }
        let r = parse(false, &["a.zip"], &env);
        ok(&r);
        assert!(r.o.jflag, "{unzip_var:?}");
    }
    let r = parse(false, &["a.zip"], &[("UNZIP", "-q"), ("UNZIPOPT", "-j")]);
    ok(&r);
    assert!(!r.o.jflag);
    // ZipInfo's variables are not unzip's.
    let r = parse(false, &["a.zip"], &[("ZIPINFO", "-k")]);
    ok(&r);
    // An environment option alone still counts as no arguments.
    let r = parse(false, &[], &[("UNZIP", "-q")]);
    assert_eq!(r.parsed, Err(0));
    assert!(r.noargs);
    // The environment can name the archive and the `-d` directory.
    let r = parse(false, &["f"], &[("UNZIP", "-d x a.zip")]);
    let p = ok(&r);
    assert_eq!(p.archive, "a.zip");
    assert_eq!(p.exdir.as_deref(), Some(OsStr::new("x")));
    assert_eq!(names(&p.include), ["f"]);
    // `-v` lists the variables' values as given.
    let r = parse(false, &["-v"], &[("UNZIP", " -q  \"-x\" ")]);
    let line = format!("{:>16}:  {}\n", "UNZIP", " -q  \"-x\" ");
    assert!(r.out.contains(&line), "{}", r.out);
}

#[test]
fn zipinfo_reads_its_own_variables_and_options() {
    let r = parse(true, &["a.zip"], &[("ZIPINFO", "-1"), ("UNZIP", "-k")]);
    ok(&r);
    assert_eq!(r.o.lflag, 1);
    assert!(r.o.zipinfo_mode);
    assert!(!r.extract_flag);
    let r = parse(true, &["a.zip"], &[("ZIPINFOOPT", "-m")]);
    ok(&r);
    assert_eq!(r.o.lflag, 4);
    // The default listing, with header and totals unless names are given.
    let r = parse(true, &["a.zip"], &[]);
    ok(&r);
    assert_eq!((r.o.lflag, r.o.hflag, r.o.tflag), (3, true, true));
    let r = parse(true, &["a.zip", "x"], &[]);
    ok(&r);
    assert_eq!((r.o.lflag, r.o.hflag, r.o.tflag), (3, false, false));
    let r = parse(true, &["-h", "a.zip", "x"], &[]);
    ok(&r);
    assert_eq!((r.o.lflag, r.o.hflag, r.o.tflag), (3, true, false));
    // `-h` alone (no format) with no names: format 0, header only.
    let r = parse(true, &["-h", "a.zip"], &[]);
    ok(&r);
    assert_eq!((r.o.lflag, r.o.hflag, r.o.tflag), (0, true, false));
    // `-1` never prints header, totals or comment; `-v` both flags as given.
    let r = parse(true, &["-1hz", "a.zip"], &[]);
    ok(&r);
    assert_eq!((r.o.hflag, r.o.tflag, r.o.zflag), (false, false, 0));
    let r = parse(true, &["-v", "a.zip"], &[]);
    ok(&r);
    assert_eq!((r.o.lflag, r.o.hflag, r.o.tflag), (10, true, false));
    // A negated format letter, `-Z` ignored, `-z` and `-T`.
    let r = parse(true, &["-Z", "-l-l", "-zT", "a.zip"], &[]);
    ok(&r);
    assert_eq!((r.o.lflag, r.o.zflag, r.o.t_flag), (LFLAG, 1, true));
    // No archive: the usage, exit 0 (zipinfo has no "options but no
    // archive" error); a bad letter: exit 10 on standard error.
    let r = parse(true, &["-l"], &[]);
    assert_eq!(r.parsed, Err(0));
    assert!(r.out.contains(m::ZIPINFO_USAGE_LINE2));
    let r = parse(true, &["-k", "a.zip"], &[]);
    assert_eq!(r.parsed, Err(10));
    assert!(r.err.contains(m::ZIPINFO_USAGE_LINE3));
    // unzip's own letters are not zipinfo's.
    assert_eq!(parse(true, &["-o", "a.zip"], &[]).parsed, Err(10));
    // zipinfo takes `-d` and `-x` among the names too.
    let r = parse(true, &["a.zip", "f", "-x", "e", "-d", "x"], &[]);
    let p = ok(&r);
    assert_eq!(
        (names(&p.include), names(&p.exclude)),
        (vec!["f"], vec!["e"])
    );
    assert_eq!(r.err, m::NOT_EXTRACTING);
}

#[test]
fn an_argument_longer_than_the_window_allows_is_refused() {
    let long = "a".repeat((WSIZE >> 2) - 160 + 1);
    let r = unzip(&["-q", &long]);
    assert_eq!(r.parsed, Err(10));
    assert_eq!(
        r.err,
        "error:  command line parameter #2 exceeds internal size limit\n"
    );
    let fits = "a".repeat((WSIZE >> 2) - 160);
    assert_eq!(ok(&unzip(&[&fits])).archive, fits.as_str());
    // An environment argument is counted too, before the command line's.
    let r = parse(false, &["a.zip"], &[("UNZIP", &format!("-q {long}"))]);
    assert_eq!(r.parsed, Err(10));
    assert!(r.err.contains("#2 "), "{}", r.err);
}

/// envargs.c: blanks split, a leading `"` quotes to the next unescaped `"`
/// with every backslash inside dropped, and backslashes elsewhere kept.
#[test]
fn envargs_splits_and_unquotes() {
    let split = |value: &str| -> Vec<String> {
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let host = Host::Sandbox(Sandbox {
            dir: std::env::temp_dir(),
            stdin: None,
            stdout,
            budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
            reads: Arc::new(Mutex::new(BTreeMap::new())),
        });
        let value = OsString::from(value);
        let lookup = |k: &str| (k == "V").then(|| value.clone());
        let mut err = Vec::new();
        let uz = Uz::new(host, Flavour::Apple, &lookup, &mut err);
        let argv = vec![b"prog".to_vec(), b"cmd".to_vec()];
        envargs(&uz, argv, "V", "W")
            .into_iter()
            .map(|a| String::from_utf8(a).unwrap())
            .collect()
    };
    assert_eq!(split("-a  -b\t-c"), ["prog", "-a", "-b", "-c", "cmd"]);
    assert_eq!(split("  -a  "), ["prog", "-a", "cmd"]);
    assert_eq!(split(r#""-d" x"#), ["prog", "-d", "x", "cmd"]);
    assert_eq!(split(r#""a b" c"#), ["prog", "a b", "c", "cmd"]);
    assert_eq!(split(r#""a\"b""#), ["prog", "a\"b", "cmd"]);
    assert_eq!(split(r#""a\\b""#), ["prog", r"a\b", "cmd"]);
    assert_eq!(split(r"a\b"), ["prog", r"a\b", "cmd"]);
    assert_eq!(split(r#""ab"#), ["prog", "ab", "cmd"]);
    assert_eq!(split(r#""ab\"#), ["prog", "ab", "cmd"]);
    assert_eq!(split(r#""a"b"#), ["prog", "a", "b", "cmd"]);
    assert_eq!(split(r#""""#), ["prog", "", "cmd"]);
    assert_eq!(split(""), ["prog", "cmd"]);
}

#[test]
fn funzip_takes_a_password_then_a_file() {
    let a = |args: &[&str]| parse_funzip(&args.iter().map(OsString::from).collect::<Vec<_>>());
    assert_eq!(a(&[]), FunzipArgs::default());
    let got = a(&["-pw", "in.zip", "more"]);
    assert_eq!(got.password.as_deref(), Some(&b"pw"[..]));
    assert_eq!(got.input.as_deref(), Some(OsStr::new("in.zip")));
    let got = a(&["in.zip"]);
    assert_eq!(
        (got.password, got.input.as_deref()),
        (None, Some(OsStr::new("in.zip")))
    );
    let got = a(&["-"]);
    assert_eq!((got.password.as_deref(), got.input), (Some(&b""[..]), None));
}

/// ubuntu: 20-unzip60-alt-iconv-utf8.patch's `-I`/`-O`, attached or as the
/// next argument, kept to 25 bytes, the rest of the argument used up.
/// ruling: T14-7. `-I ''` is an empty `ISO_CP` and the next argument is an
/// option again (the C's `while(*(++s));` past the empty string's NUL is
/// not reproduced). Apple has no such options.
#[test]
fn charsets_are_taken_as_ubuntu_takes_them() {
    let ubuntu = |zipinfo: bool, args: &[&str]| parse_as(Flavour::Ubuntu, zipinfo, args, &[]);
    let r = ubuntu(false, &["-I", "", "-l", "a.zip"]);
    assert_eq!(ok(&r).archive, "a.zip");
    assert_eq!((r.o.iso_cp.as_slice(), r.o.vflag), (&b""[..], 1));
    let r = ubuntu(false, &["-OCP866q", "-I", "ISO-8859-5", "-l", "a.zip"]);
    assert_eq!(ok(&r).archive, "a.zip");
    assert_eq!(r.o.oem_cp, b"CP866q");
    assert_eq!(r.o.iso_cp, b"ISO-8859-5");
    let long = "x".repeat(30);
    let r = ubuntu(true, &["-1O", &long, "a.zip"]);
    assert_eq!(ok(&r).archive, "a.zip");
    assert_eq!(r.o.oem_cp, vec![b'x'; 25]);
    for (args, msg) in [
        (
            &["-O"][..],
            "error:  a valid character encoding should follow the -O argument",
        ),
        (
            &["-O-l", "a.zip"],
            "error:  a valid character encoding should follow the -I argument",
        ),
        (&["--I", "x", "a.zip"], "error:  encodings can't be negated"),
    ] {
        let r = ubuntu(false, args);
        assert_eq!(
            (&r.parsed.as_ref().err(), r.err.as_str()),
            (&Some(&10), msg),
            "{args:?}"
        );
    }
    let r = unzip(&["-I", "x", "a.zip"]);
    assert_eq!(r.parsed.as_ref().err(), Some(&10));
}
