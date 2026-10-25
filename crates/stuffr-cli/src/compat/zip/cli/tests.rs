//! Unit tests for the zip family's command line: `get_option()`'s grammar
//! (short clusters, two-character options, values attached, separate and
//! with `=`, value lists to `@`, long options and their abbreviations,
//! `--`, negation), `envargs`, the number, date and name readers, and
//! `main()`'s own checks. Every expectation of the grammar was read off the
//! reference (`zip -sc` shows the permuted command line, `-so` the table):
//! the rows in `tests/compat_zip_common.rs` run the same commands against
//! it.

use std::ffi::OsString;
use std::path::PathBuf;

use super::super::{Flavour, run_in};
use super::*;

fn args_of(a: &[&str]) -> Vec<Vec<u8>> {
    a.iter().map(|s| s.as_bytes().to_vec()).collect()
}

/// Every `get_option` result for `argv` (with `zip` as `argv[0]`): the ID
/// as a character or `o::` constant, the value and the negation; and the
/// arguments as left, permuted.
type Seen = Vec<(u32, Option<String>, bool)>;

fn walk(f: Flavour, argv: &[&str]) -> Result<(Seen, Vec<String>), String> {
    let table = table(f);
    let mut args = args_of(&[&["zip"], argv].concat());
    let mut st = GetOpt::new();
    let mut seen = Vec::new();
    loop {
        let g = get_option(&table, &mut args, &mut st)
            .map_err(|e| String::from_utf8_lossy(&e).into_owned())?;
        if g.id == 0 {
            break;
        }
        seen.push((
            g.id,
            g.value.map(|v| String::from_utf8_lossy(&v).into_owned()),
            g.negated,
        ));
        assert!(seen.len() < 100, "no end: {seen:?}");
    }
    let left = args
        .iter()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    Ok((seen, left))
}

fn c(ch: char) -> u32 {
    ch as u32
}

fn val(v: &str) -> Option<String> {
    Some(v.to_string())
}

#[test]
fn a_short_cluster_is_split_into_its_options() {
    let (seen, left) = walk(Flavour::Apple, &["-jlv", "t.zip", "a"]).unwrap();
    assert_eq!(
        seen,
        [
            (c('j'), None, false),
            (c('l'), None, false),
            (c('v'), None, false),
            (o::NON_OPTION_ARG, val("t.zip"), false),
            (o::NON_OPTION_ARG, val("a"), false),
        ]
    );
    assert_eq!(left, ["zip", "-jlv", "t.zip", "a"]);
}

#[test]
fn a_two_character_option_wins_over_its_first_letter() {
    let (seen, _) = walk(Flavour::Apple, &["-dd", "-d", "-ll", "-l", "-lf", "x"]).unwrap();
    assert_eq!(
        seen,
        [
            (o::DD, None, false),
            (c('d'), None, false),
            (o::LL, None, false),
            (c('l'), None, false),
            (o::LF, val("x"), false),
        ]
    );
    // `-fd` is force-descriptors, not `-f` and `-d`
    let (seen, _) = walk(Flavour::Apple, &["-fd"]).unwrap();
    assert_eq!(seen, [(o::DES, None, false)]);
    // an unlisted pair is two options
    let (seen, _) = walk(Flavour::Apple, &["-dj"]).unwrap();
    assert_eq!(seen, [(c('d'), None, false), (c('j'), None, false)]);
    // `-h2x` is `-h2` first (the caller stops there: `main()` leaves)
    let table = table(Flavour::Apple);
    let mut args = args_of(&["zip", "-h2x"]);
    let got = get_option(&table, &mut args, &mut GetOpt::new()).unwrap();
    assert_eq!(got.id, o::H2);
}

#[test]
fn a_value_follows_attached_with_equals_or_as_the_next_argument() {
    for argv in [
        &["-b", "dir"][..],
        &["-bdir"][..],
        &["-b=dir"][..],
        &["--temp-path", "dir"][..],
        &["--temp-path=dir"][..],
        &["--temp", "dir"][..],
    ] {
        let (seen, _) = walk(Flavour::Apple, argv).unwrap();
        assert_eq!(seen, [(c('b'), val("dir"), false)], "{argv:?}");
    }
    // a cluster ends at a value option
    let (seen, _) = walk(Flavour::Apple, &["-rbdir", "t.zip"]).unwrap();
    assert_eq!(
        seen,
        [
            (c('r'), None, false),
            (c('b'), val("dir"), false),
            (o::NON_OPTION_ARG, val("t.zip"), false),
        ]
    );
    // an empty value after `=` is a value
    let (seen, _) = walk(Flavour::Apple, &["-b="]).unwrap();
    assert_eq!(seen, [(c('b'), val(""), false)]);
}

#[test]
fn non_options_are_permuted_after_the_options() {
    let (seen, left) = walk(Flavour::Apple, &["t.zip", "a", "-b", "d", "-r", "f"]).unwrap();
    assert_eq!(
        seen.iter().map(|s| s.0).collect::<Vec<_>>(),
        [
            c('b'),
            c('r'),
            o::NON_OPTION_ARG,
            o::NON_OPTION_ARG,
            o::NON_OPTION_ARG
        ]
    );
    assert_eq!(left, ["zip", "-b", "d", "-r", "t.zip", "a", "f"]);
}

#[test]
fn value_lists_run_to_the_next_option_and_get_an_at_sign() {
    // zip -sc t.zip a b -x c d -i e
    let (seen, left) = walk(
        Flavour::Apple,
        &["t.zip", "a", "b", "-x", "c", "d", "-i", "e"],
    )
    .unwrap();
    assert_eq!(
        seen,
        [
            (c('x'), val("c"), false),
            (c('x'), val("d"), false),
            (c('i'), val("e"), false),
            (o::NON_OPTION_ARG, val("t.zip"), false),
            (o::NON_OPTION_ARG, val("a"), false),
            (o::NON_OPTION_ARG, val("b"), false),
        ]
    );
    assert_eq!(
        left,
        ["zip", "-x", "c", "d", "-i", "e", "@", "t.zip", "a", "b"]
    );
    // a list ended by an option needs no `@`
    let (_, left) = walk(Flavour::Apple, &["-x", "c", "d", "-r", "t.zip"]).unwrap();
    assert_eq!(left, ["zip", "-x", "c", "d", "-r", "t.zip"]);
}

#[test]
fn double_dash_reads_the_rest_verbatim() {
    // zip -sc t.zip a -- -b
    let (seen, left) = walk(Flavour::Apple, &["t.zip", "a", "--", "-b"]).unwrap();
    assert_eq!(
        seen,
        [
            (o::NON_OPTION_ARG, val("t.zip"), false),
            (o::NON_OPTION_ARG, val("a"), false),
            (o::NON_OPTION_ARG, val("--"), false),
            (o::NON_OPTION_ARG, val("-b"), false),
        ]
    );
    assert_eq!(left, ["zip", "t.zip", "a", "--", "-b"]);
    // as the first non-option, the `--` itself comes back first
    let (seen, _) = walk(Flavour::Apple, &["--", "t.zip"]).unwrap();
    assert_eq!(seen[0], (o::NON_OPTION_ARG, val("--"), false));
}

#[test]
fn a_trailing_dash_negates_what_can_be_negated() {
    let (seen, _) = walk(Flavour::Apple, &["-X-", "-dd-", "--fifo-"]).unwrap();
    assert_eq!(
        seen,
        [
            (c('X'), None, true),
            (o::DD, None, true),
            (o::FI, None, true)
        ]
    );
    assert_eq!(
        walk(Flavour::Apple, &["-r-"]).unwrap_err(),
        "option 'r' (recurse down listed paths) not negatable"
    );
    assert_eq!(
        walk(Flavour::Apple, &["--recurse-paths-"]).unwrap_err(),
        "option 'recurse-paths' (recurse down listed paths) not negatable"
    );
    // `-x-` is `-x` with the value `-`... no: a list option cannot be
    // negated, so the dash begins its value
    let (seen, _) = walk(Flavour::Apple, &["-x-", "t.zip"]).unwrap();
    assert_eq!(seen[0], (c('x'), val("-"), false));
}

#[test]
fn long_options_are_abbreviated_and_checked() {
    let (seen, _) = walk(Flavour::Apple, &["--exc", "a"]).unwrap();
    assert_eq!(seen, [(c('x'), val("a"), false)]);
    // an exact name beats a longer one it begins
    let (seen, _) = walk(Flavour::Apple, &["--fix"]).unwrap();
    assert_eq!(seen, [(c('F'), None, false)]);
    assert_eq!(
        walk(Flavour::Apple, &["--s"]).unwrap_err(),
        "long option 's' ambiguous"
    );
    assert_eq!(
        walk(Flavour::Apple, &["--fifo-", "--no"]).unwrap_err(),
        "long option 'no' ambiguous"
    );
    assert_eq!(
        walk(Flavour::Apple, &["--nosuch"]).unwrap_err(),
        "long option 'nosuch' not supported"
    );
    assert_eq!(
        walk(Flavour::Apple, &["---x"]).unwrap_err(),
        "long option '-x' not supported"
    );
    assert_eq!(
        walk(Flavour::Apple, &["--=x"]).unwrap_err(),
        "long option '' ambiguous"
    );
    assert_eq!(
        walk(Flavour::Apple, &["--store=3"]).unwrap_err(),
        "option 'store' (store) does not allow a value"
    );
}

#[test]
fn short_option_errors_name_the_byte() {
    assert_eq!(
        walk(Flavour::Apple, &["-%"]).unwrap_err(),
        "short option '%' not supported"
    );
    assert_eq!(
        walk(Flavour::Apple, &["t.zip", "-b"]).unwrap_err(),
        "option 'b' (dir to use for temp archive) requires a value"
    );
    assert_eq!(
        walk(Flavour::Apple, &["-x"]).unwrap_err(),
        "option 'x' (exclude files matching patterns) requires a value"
    );
}

#[test]
fn the_flavours_have_their_own_tables() {
    let a = table(Flavour::Apple);
    let u = table(Flavour::Ubuntu);
    assert_eq!(u.len(), a.len() + 3);
    let shorts = |t: &[OptionSpec]| t.iter().map(|s| s.short).collect::<Vec<_>>();
    for extra in ["su", "sU", "UN"] {
        assert!(!shorts(&a).contains(&extra));
        assert!(shorts(&u).contains(&extra));
    }
    // -su is `-s u` for Apple (a bad size), the show option for Ubuntu
    let (seen, _) = walk(Flavour::Apple, &["-su", "x"]).unwrap();
    assert_eq!(seen[0], (c('s'), val("u"), false));
    let (seen, _) = walk(Flavour::Ubuntu, &["-su"]).unwrap();
    assert_eq!(seen[0], (o::SU, None, false));
    assert_eq!(
        walk(Flavour::Apple, &["--show-unicode"]).unwrap_err(),
        "long option 'show-unicode' not supported"
    );
    // every ID answers one entry, up to the aliases the C has (-h -H -?)
    let ids: std::collections::BTreeMap<u32, Vec<&str>> =
        a.iter().fold(Default::default(), |mut m, s| {
            m.entry(s.id).or_default().push(s.short);
            m
        });
    for (id, names) in &ids {
        if names.len() > 1 {
            assert_eq!(*id, c('h'), "{names:?}");
        }
    }
}

#[test]
fn envargs_puts_the_environment_before_the_command_line() {
    let env = |k: &str| -> Option<OsString> {
        match k {
            "ZIP" => Some(" \x20-q \x20\x20-j ".into()),
            "ZIPOPT" => Some("".into()),
            _ => None,
        }
    };
    let got = envargs(args_of(&["zip", "t.zip", "a"]), &env, "ZIPOPT", "ZIP");
    assert_eq!(got, args_of(&["zip", "-q", "-j", "t.zip", "a"]));
    // ZIPOPT wins over ZIP when it has words
    let env = |k: &str| -> Option<OsString> {
        match k {
            "ZIP" => Some("-q".into()),
            "ZIPOPT" => Some("-v".into()),
            _ => None,
        }
    };
    let got = envargs(args_of(&["zip", "t.zip"]), &env, "ZIPOPT", "ZIP");
    assert_eq!(got, args_of(&["zip", "-v", "t.zip"]));
    // quotes protect blanks and lose their backslashes
    let env = |k: &str| -> Option<OsString> {
        (k == "ZIP").then(|| r#""a b" "c\"d" "e\\f" g"h""#.into())
    };
    let got = envargs(args_of(&["zip"]), &env, "ZIPOPT", "ZIP");
    assert_eq!(got, args_of(&["zip", "a b", "c\"d", "e\\f", "g\"h\""]));
    // all blanks, or unset: nothing added
    let env = |k: &str| -> Option<OsString> { (k == "ZIP").then(|| " \x20\x20".into()) };
    assert_eq!(
        envargs(args_of(&["zip", "x"]), &env, "ZIPOPT", "ZIP"),
        args_of(&["zip", "x"])
    );
}

#[test]
fn numbers_take_a_multiplier() {
    assert_eq!(read_num_string(b"64k"), (65536, None));
    assert_eq!(read_num_string(b"1m"), (1 << 20, None));
    assert_eq!(read_num_string(b"2G"), (2 << 30, None));
    assert_eq!(read_num_string(b"1t"), (1 << 40, None));
    assert_eq!(read_num_string(b"10"), (10, None));
    assert_eq!(read_num_string(b"1q"), (u64::MAX, None));
    assert_eq!(read_num_string(b"1kk"), (u64::MAX, None));
    assert_eq!(read_num_string(b"u"), (u64::MAX, Some(m::NUM_NOT_DIGIT)));
    assert_eq!(
        read_num_string(b"123456789"),
        (u64::MAX, Some(m::NUM_TOO_LONG))
    );
    assert_eq!(read_num_string(b""), (u64::MAX, Some(m::NUM_NOT_DIGIT)));
}

#[test]
fn dates_are_iso_or_american() {
    let d = |y, m, d| dostime(y, m, d, 0, 0, 0);
    assert_eq!(read_date(b"01012000"), Some(d(2000, 1, 1)));
    assert_eq!(read_date(b"2002-01-01"), Some(d(2002, 1, 1)));
    assert_eq!(read_date(b"12312030"), Some(d(2030, 12, 31)));
    // month 13, day 45
    assert_eq!(read_date(b"13452002"), None);
    assert_eq!(read_date(b"2002-13-01"), None);
    assert_eq!(read_date(b"x"), None);
    assert_eq!(read_date(b""), None);
    // before 1980 is the DOS minimum
    assert_eq!(read_date(b"01011970"), Some(0x0021_0000));
    // sscanf's %d skips blanks and takes a sign
    assert_eq!(read_date(b" 1 1 2000"), Some(d(2000, 1, 1)));
    assert_eq!(read_date(b"2002-01-01xyz"), Some(d(2002, 1, 1)));
}

#[test]
fn zip_names_get_a_zip_extension_unless_they_have_a_dot() {
    assert_eq!(ziptyp(b"t", false), b"t.zip");
    assert_eq!(ziptyp(b"t.zip", false), b"t.zip");
    assert_eq!(ziptyp(b"d.x/t", false), b"d.x/t.zip");
    assert_eq!(ziptyp(b"d/t.x", false), b"d/t.x");
    assert_eq!(ziptyp(b".t", false), b".t");
    assert_eq!(ziptyp(b"t", true), b"t");
}

#[test]
fn abbreviations_match_as_in_util_c() {
    assert!(abbrevmatch(b"deflate", b"d", false, 1));
    assert!(abbrevmatch(b"deflate", b"DEFL", false, 1));
    assert!(abbrevmatch(b"deflate", b"deflate", false, 1));
    assert!(!abbrevmatch(b"deflate", b"deflatex", false, 1));
    assert!(!abbrevmatch(b"deflate", b"", false, 1));
    assert!(!abbrevmatch(b"deflate", b"x", false, 1));
    assert!(!abbrevmatch(b"deflate", b"D", true, 1));
}

#[test]
fn names_are_read_up_to_a_newline_or_return() {
    let mut r = std::io::Cursor::new(b"\n\na b\rc\r\n\nd".to_vec());
    assert_eq!(getnam(&mut r), Some(b"a b".to_vec()));
    assert_eq!(getnam(&mut r), Some(b"c".to_vec()));
    assert_eq!(getnam(&mut r), Some(b"d".to_vec()));
    assert_eq!(getnam(&mut r), None);
    // a name of 9001 bytes ends the reading, 9000 is the longest
    let mut long = vec![b'x'; 9001];
    long.push(b'\n');
    assert_eq!(getnam(&mut std::io::Cursor::new(long)), None);
    let mut ok = vec![b'x'; 9000];
    ok.push(b'\n');
    assert_eq!(
        getnam(&mut std::io::Cursor::new(ok)).map(|n| n.len()),
        Some(9000)
    );
}

// ---- main()'s own checks, through the sandbox ----

/// A scratch directory, removed on drop.
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Scratch {
        let d = std::env::temp_dir().join(format!("stuffr-zipcli-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Scratch(d)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn go(f: Flavour, name: &str, args: &[&str]) -> (i32, String, String) {
    let s = Scratch::new("go");
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err) = run_in(&s.0, name, args, b"", f);
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

#[test]
fn the_show_command_screen_lists_the_permuted_arguments() {
    for (argv, want) in [
        (
            &["-sc", "t.zip", "a", "b", "-x", "c", "d", "-i", "e"][..],
            "'zip' \x20'-sc' \x20'-x' \x20'c' \x20'd' \x20'-i' \x20'e' \x20'@' \x20't.zip' \x20'a' \x20'b' \x20",
        ),
        (
            &["-sc", "t.zip", "-x", "c", "d", "--", "e", "f"][..],
            "'zip' \x20'-sc' \x20'-x' \x20'c' \x20'd' \x20't.zip' \x20'--' \x20'e' \x20'f' \x20",
        ),
        (
            &["-sc", "t.zip", "a", "-b", "d", "-r", "f"][..],
            "'zip' \x20'-sc' \x20'-b' \x20'd' \x20'-r' \x20't.zip' \x20'a' \x20'f' \x20",
        ),
        (
            &["-sc", "--exclude=a", "--exclude", "b", "c", "t.zip", "d"][..],
            "'zip' \x20'-sc' \x20'--exclude=a' \x20'--exclude' \x20'b' \x20'c' \x20't.zip' \x20'd' \x20",
        ),
    ] {
        let (code, out, err) = go(Flavour::Apple, "zip", argv);
        assert_eq!((code, err.as_str()), (9, ""), "{argv:?}: {out}");
        assert_eq!(
            out,
            format!("command line:\n{want}\n\nzip error: Interrupted (show command line)\n"),
            "{argv:?}"
        );
    }
}

#[test]
fn a_double_dash_before_the_archive_name_is_refused() {
    let (code, out, _) = go(Flavour::Apple, "zip", &["-sc", "--", "t.zip", "a"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "\nzip error: Invalid command arguments (can't use -- before archive name)\n"
    );
}

#[test]
fn the_checks_of_main_answer_in_order() {
    let a = Flavour::Apple;
    let parms = |t: &str| format!("\nzip error: Invalid command arguments ({t})\n");
    for (argv, text) in [
        (&["-d", "-u", "t.zip", "a"][..], "specify just one action"),
        (&["-r", "-R", "t.zip"][..], "do not specify both -r and -R"),
        (&["-d", "-f", "t.zip", "a"][..], "specify just one action"),
        (&["-sf", "-U", "-d", "t.zip"][..], "specify just one action"),
        (&["-U", "t.zip", "a"][..], "-U (--copy) requires -O (--out)"),
        (
            &["-DF", "-F", "-O", "o.zip", "t.zip"][..],
            "can't use --diff (-DF) with fix (-F or -FF)",
        ),
        (
            &["-O", "t.zip", "t.zip", "a"][..],
            "--out path must be different than in path: t.zip",
        ),
        (
            &["-DF", "-d", "-O", "o.zip", "t.zip", "a"][..],
            "can't use --diff (-DF) with -d or -U",
        ),
        (
            &["-s", "64k", "t.dat", "a"][..],
            "archive name must end in .zip for splits",
        ),
        (
            &["-s", "64k", "-F", "-O", "o.zip", "t.zip", "a"][..],
            "no other actions allowed when fixing archive (-F or -FF)",
        ),
        (
            &["-s", "64k", "-g", "t.zip", "a"][..],
            "can't create split archive with -d or -g or on stdout\n",
        ),
        (
            &["-FS", "-u", "t.zip", "a"][..],
            "can't use -d, -f, -u, -U, or -g with filesync -FS\n",
        ),
        (&["-R", "t.zip"][..], "nothing to select from"),
        (&["-x", "a", "t.zip"][..], "nothing to select from"),
        (
            &["-P", "", "t.zip", "a"][..],
            "zero length password not allowed",
        ),
    ] {
        let (code, out, err) = go(a, "zip", argv);
        assert_eq!(code, 16, "{argv:?}: {out}{err}");
        // the message is on standard output, as zip's `mesg` is
        assert_eq!(out, parms(text), "{argv:?}");
    }
}

#[test]
fn the_name_dash_sends_messages_to_standard_error() {
    let (code, out, err) = go(Flavour::Apple, "zip", &["-d", "-", "a"]);
    assert_eq!(code, 16);
    assert_eq!(out, "");
    assert_eq!(
        err,
        "\nzip error: Invalid command arguments (can't use -d, -f, -u, -U, or -g on stdout\n)\n"
    );
    let (code, out, err) = go(Flavour::Apple, "zip", &["-s", "64k", "-", "a"]);
    assert_eq!((code, out.as_str()), (16, ""));
    assert_eq!(
        err,
        "\nzip error: Invalid command arguments (archive name must end in .zip for splits)\n"
    );
}

/// The scan's answer when `a` is not there and nothing else is named.
const NOT_MATCHED_A: &str =
    "\tzip warning: name not matched: a\n\nzip error: Nothing to do! (t.zip)\n";

#[test]
fn compression_methods_follow_the_build() {
    let (code, out, _) = go(Flavour::Apple, "zip", &["-Z", "bzip2", "t.zip", "a"]);
    assert_eq!(code, 19);
    assert_eq!(
        out,
        "\nzip error: Not supported (Compression method bzip2 not enabled)\n"
    );
    // Ubuntu accepts it and goes on (to the scan: `a` is not there)
    let (code, out, _) = go(Flavour::Ubuntu, "zip", &["-Z", "b", "t.zip", "a"]);
    assert_eq!((code, out.as_str()), (12, NOT_MATCHED_A));
    let (code, out, _) = go(Flavour::Ubuntu, "zip", &["-Z", "foo", "t.zip", "a"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "\tzip warning: valid compression methods are:  store, deflate, bzip2\n\
         \tzip warning: unknown compression method found:  foo\n\n\
         zip error: Invalid command arguments (Option -Z (--compression-method):  unknown method)\n"
    );
}

#[test]
fn quiet_silences_warnings_but_not_errors() {
    let (code, out, _) = go(Flavour::Apple, "zip", &["-q", "-s", "u", "t.zip", "a"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "\nzip error: Invalid command arguments (bad split size: \x20'u')\n"
    );
}

#[test]
fn the_unicode_option_takes_its_words() {
    for w in [
        "q", "quit", "w", "Warn", "i", "n", "no", "e", "escape", "u", "UTF8",
    ] {
        let (code, out, err) = go(Flavour::Ubuntu, "zip", &["-UN", w, "t.zip", "a"]);
        assert_eq!((code, out.as_str()), (12, NOT_MATCHED_A), "{w}: {err}");
    }
    let (code, out, _) = go(Flavour::Ubuntu, "zip", &["-UN", "x", "t.zip", "a"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "\tzip warning: -UN must be Quit, Warn, Ignore, No, Escape, or UTF8: x\n\n\
         zip error: Invalid command arguments (-UN (unicode) bad value)\n"
    );
}

#[test]
fn the_screens_name_stuffr_and_the_build() {
    let v = env!("CARGO_PKG_VERSION");
    let (code, out, err) = go(Flavour::Apple, "zip", &["-h"]);
    assert_eq!((code, err.as_str()), (0, ""));
    let want = format!(
        "Copyright (c) 1990-2008 Info-ZIP - Type 'zip \"-L\"' for software license.\n\
         Zip 3.0 (July 5th 2008), by stuffr {v} (altered; original by Info-ZIP, with \
         modifications by Apple Inc.). Usage:\n\
         zip [-options] [-b path] [-t mmddyyyy] [-n suffixes] [zipfile list] [-xi list]\n"
    );
    assert!(out.starts_with(&want), "{out}");
    let (_, out, _) = go(Flavour::Ubuntu, "zip", &["--version"]);
    assert!(
        out.contains(&format!(
            "This is Zip 3.0 (July 5th 2008), by stuffr {v} (altered; Debian's build, \
             original by Info-ZIP).\nCurrently maintained by E. Gordon."
        )),
        "{out}"
    );
    assert!(out.contains("BZIP2_SUPPORT"), "{out}");
    assert!(
        out.ends_with(" \x20\x20\x20\x20\x20\x20\x20\x20\x20ZIPOPT: \x20[none]\n"),
        "{out}"
    );
    let (_, out, _) = go(Flavour::Apple, "zip", &["-v"]);
    assert!(out.contains("UIDGID_16BIT"), "{out}");
    assert!(out.contains("Please report bugs to Apple.\n"), "{out}");
    for (name, head) in [
        ("zipcloak", "\nZipCloak 3.0 (July 5th 2008), by stuffr "),
        ("zipnote", "\nZipNote 3.0 (July 5th 2008), by stuffr "),
        ("zipsplit", "\nZipSplit 3.0 (July 5th 2008), by stuffr "),
    ] {
        let (code, out, _) = go(Flavour::Ubuntu, name, &["-h"]);
        assert_eq!(code, 0, "{name}");
        assert!(
            out.contains(&format!(
                "{head}{v} (altered; Debian's build, original by Info-ZIP)\n"
            )),
            "{name}: {out}"
        );
    }
}

#[test]
fn the_extended_help_differs_by_one_line() {
    let (_, a, _) = go(Flavour::Apple, "zip", &["-h2"]);
    let (_, u, _) = go(Flavour::Ubuntu, "zip", &["-h2"]);
    let brace = " \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20In cmd, {} replaced by temp archive path, else temp appended.\n";
    assert!(!a.contains(brace));
    assert!(u.contains(brace));
    assert_eq!(u.replace(brace, ""), a);
}

#[test]
fn show_options_lists_the_table_with_its_columns() {
    let (code, out, _) = go(Flavour::Apple, "zip", &["-so"]);
    assert_eq!(code, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "available options:");
    assert_eq!(
        lines[1],
        " sh \x20long \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20val \x20neg description \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    );
    assert_eq!(
        lines[2],
        " -- \x20---- \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20--- \x20--- ----------- \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    );
    assert_eq!(
        lines[3],
        " 0 \x20\x20store \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20store \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
    );
    assert!(
        lines.contains(&" b \x20\x20temp-path \x20\x20\x20\x20\x20\x20\x20\x20\x20req \x20\x20\x20\x20\x20dir to use for temp archive \x20\x20"),
        "{out}"
    );
    assert!(
        lines.contains(&" db \x20display-bytes \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20neg display running bytes \x20\x20\x20\x20\x20\x20\x20\x20"),
        "{out}"
    );
    assert!(
        lines.contains(&" i \x20\x20include \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20list \x20\x20\x20\x20include only files matching patterns"),
        "{out}"
    );
    let (_, out, _) = go(Flavour::Ubuntu, "zip", &["-so"]);
    assert!(
        out.contains(" UN \x20unicode \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20req \x20\x20\x20\x20\x20UN=quit, warn, ignore, no, escape\n"),
        "{out}"
    );
    assert_eq!(lines.len() - 3, table(Flavour::Apple).len());
}

#[test]
fn a_log_file_gets_its_header_and_the_log_extension() {
    let s = Scratch::new("log");
    let args: Vec<OsString> = ["-lf", "run", "-sd", "t.zip", "a"]
        .iter()
        .map(OsString::from)
        .collect();
    let (code, _, err) = run_in(&s.0, "zip", args, b"", Flavour::Apple);
    // the command line is accepted; `a` is not there (nothing to do)
    assert_eq!(code, 12, "{}", String::from_utf8_lossy(&err));
    let log = std::fs::read_to_string(s.0.join("run.log")).unwrap();
    assert!(log.starts_with("---------\nZip log opened "), "{log}");
    assert!(
        log.contains("command line arguments:\n -lf run -sd t.zip a \n\n"),
        "{log:?}"
    );
    // the scan's warning and the error end are in the log too
    assert!(
        log.ends_with("\tzip warning: name not matched: a\n\nzip error: Nothing to do! (t.zip)\n"),
        "{log:?}"
    );
    // an unwritable log is a usage error naming the path with its extension
    let args: Vec<OsString> = ["-lf", "nodir/x", "t.zip", "a"]
        .iter()
        .map(OsString::from)
        .collect();
    let (code, out, _) = run_in(&s.0, "zip", args, b"", Flavour::Apple);
    assert_eq!(code, 16);
    assert_eq!(
        String::from_utf8_lossy(&out),
        "\nzip error: Invalid command arguments (could not open logfile 'nodir/x.log')\n"
    );
}

#[test]
fn names_from_stdin_are_read_when_the_archive_name_is_known() {
    let s = Scratch::new("stdin");
    let args: Vec<OsString> = ["-@", "-sc", "t.zip"].iter().map(OsString::from).collect();
    let (code, out, _) = run_in(&s.0, "zip", args, b"a\nb c\n", Flavour::Apple);
    assert_eq!(code, 9);
    assert!(out.starts_with(b"command line:\n'zip' \x20'-@' \x20'-sc' \x20't.zip' \x20\n"));
    // `s` is cleared once the archive name has read them, so a `-` among
    // the names is accepted here (the C's check is for `-@` before the
    // name is known, which the permutation never gives)
    let args: Vec<OsString> = ["-@", "t.zip", "-"].iter().map(OsString::from).collect();
    let (code, out, err) = run_in(&s.0, "zip", args, b"a\n", Flavour::Apple);
    // `a` is not there; `-` is standard input, which goes on to the archive
    assert_eq!(
        (code, out.as_slice()),
        (1, &b"\tzip warning: name not matched: a\n"[..])
    );
    assert!(String::from_utf8_lossy(&err).contains("not built yet"));
}

#[test]
fn the_helpers_parse_as_their_sources_do() {
    let a = Flavour::Apple;
    // zipcloak: get_option with its own table; the error is on stdout
    let (code, out, _) = go(a, "zipcloak", &["-x", "t.zip"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "zipcloak error: Invalid command arguments (short option 'x' not supported)\n"
    );
    // -q is in the help but not in the table
    let (code, out, _) = go(a, "zipcloak", &["-q", "t.zip"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "zipcloak error: Invalid command arguments (short option 'q' not supported)\n"
    );
    let (code, out, _) = go(a, "zipcloak", &["t.zip", "u.zip"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "zipcloak error: Invalid command arguments (can only specify one zip file)\n"
    );
    let (code, out, _) = go(a, "zipcloak", &["-d"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "zipcloak error: Invalid command arguments (need to specify zip file)\n"
    );
    let (code, out, _) = go(a, "zipcloak", &["-b", "x", "-b", "y", "t.zip"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "zipcloak error: Invalid command arguments (more than one temp_path)\n"
    );
    let (code, out, _) = go(a, "zipcloak", &["-"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "zipcloak error: Invalid command arguments (zip file cannot be stdin)\n"
    );
    // zipnote: its own loop; errors on standard error
    let (code, out, err) = go(a, "zipnote", &["-x", "t.zip"]);
    assert_eq!((code, out.as_str()), (16, ""));
    assert_eq!(
        err,
        "zipnote error: Invalid command arguments (unknown option)\n"
    );
    let (code, _, err) = go(a, "zipnote", &["-b", "-b"]);
    assert_eq!(code, 16);
    assert_eq!(
        err,
        "zipnote error: Invalid command arguments (use -b before zip file name)\n"
    );
    let (code, _, err) = go(a, "zipnote", &["-b"]);
    assert_eq!(code, 16);
    assert_eq!(
        err,
        "zipnote error: Invalid command arguments (need to specify zip file)\n"
    );
    // zipsplit: its own loop; errors on standard output
    let (code, out, _) = go(a, "zipsplit", &["-x", "t.zip"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "zipsplit error: Invalid command arguments (Use option -h for help.)\n"
    );
    let (code, out, _) = go(a, "zipsplit", &["-n", "50", "t.zip"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "zipsplit error: Invalid command arguments (invalid size given. Use option -h for help.)\n"
    );
    let (code, out, _) = go(a, "zipsplit", &["-nb", "t.zip"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "zipsplit error: Invalid command arguments (options are separate and precede zip file)\n"
    );
    // a good command line is accepted (and answers the not-built text)
    for (name, argv) in [
        ("zipcloak", &["-d", "-b", "d", "-O", "o", "t"][..]),
        ("zipnote", &["-w", "-q", "-b", "d", "t"][..]),
        (
            "zipsplit",
            &["-tips", "-n", "1000", "-r", "5", "-b", "d", "t"][..],
        ),
    ] {
        let (code, _, err) = go(a, name, argv);
        assert_eq!(code, 1, "{name}: {err}");
        assert!(err.contains("not built yet"), "{name}: {err}");
    }
}

#[test]
fn the_helpers_options_are_read_into_their_structs() {
    let s = Scratch::new("helpers");
    let host = || {
        crate::compat::host::Host::Sandbox(crate::compat::host::Sandbox {
            dir: s.0.clone(),
            stdin: None,
            stdout: Default::default(),
            budget: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1 << 20)),
            reads: Default::default(),
        })
    };
    let env = |_: &str| None;
    let mut err = Vec::new();
    let mut z = Zr::new(host(), Flavour::Apple, "zipcloak", &env, &mut err);
    let o = parse_cloak(
        &mut z,
        b"zipcloak",
        &args_of(&["-d", "-b", "d", "-O", "o", "t"]),
    )
    .unwrap();
    assert_eq!(o.zipfile, b"t.zip");
    assert_eq!(o.out_path.as_deref(), Some(&b"o.zip"[..]));
    assert_eq!(o.tempath.as_deref(), Some(&b"d"[..]));
    assert!(o.decrypt);
    let mut z = Zr::new(host(), Flavour::Apple, "zipsplit", &env, &mut err);
    let o = parse_split(
        &mut z,
        &args_of(&["-tips", "-n", "1000", "-r", "5", "-b", "d", "t"]),
    )
    .unwrap();
    assert_eq!(
        (
            o.capacity,
            o.room,
            o.report_only,
            o.index,
            o.pause,
            o.simple
        ),
        (1000, 5, true, true, true, true)
    );
    assert_eq!(o.tempath.as_deref(), Some(&b"d"[..]));
    let mut z = Zr::new(host(), Flavour::Apple, "zipsplit", &env, &mut err);
    let o = parse_split(&mut z, &args_of(&["t"])).unwrap();
    assert_eq!(o.capacity, 36000);
    let mut z = Zr::new(host(), Flavour::Apple, "zipnote", &env, &mut err);
    let o = parse_note(&mut z, &args_of(&["-wq", "x.zip"])).unwrap();
    assert!(o.write);
    assert!(!z.o.noisy);
    assert_eq!(o.zipfile, b"x.zip");
}

#[test]
fn options_are_recorded_for_the_later_tasks() {
    let s = Scratch::new("opts");
    let env = |_: &str| None;
    let mut err = Vec::new();
    let host = crate::compat::host::Host::Sandbox(crate::compat::host::Sandbox {
        dir: s.0.clone(),
        stdin: None,
        stdout: Default::default(),
        budget: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1 << 20)),
        reads: Default::default(),
    });
    let mut z = Zr::new(host, Flavour::Ubuntu, "zip", &env, &mut err);
    parse_zip(
        &mut z,
        b"zip",
        &args_of(&[
            "-r",
            "-9",
            "-j",
            "-q",
            "-X-",
            "-fz",
            "-dd",
            "-ds",
            "40k",
            "-s",
            "1m",
            "-t",
            "2001-02-03",
            "-Z",
            "store",
            "-x",
            "*.o",
            "*.a",
            "-i",
            "*.c",
            "-y",
            "t",
            "a",
            "b",
        ]),
    )
    .unwrap();
    let o = &z.o;
    assert_eq!(o.recurse, 1);
    assert_eq!(o.level, 9);
    assert_eq!(o.method, Method::Store);
    assert!(!o.pathput);
    assert!(!o.noisy);
    assert_eq!(o.extra_fields, 2);
    assert_eq!(o.force_zip64, 1);
    assert_eq!((o.dot_size, o.dot_count), (40 * 1024, -1));
    assert_eq!((o.split_method, o.split_size), (1, 1 << 20));
    assert_eq!(o.before, dostime(2001, 2, 3, 0, 0, 0));
    assert_eq!(o.zipfile.as_deref(), Some(&b"t.zip"[..]));
    assert_eq!(o.names, args_of(&["a", "b"]));
    assert_eq!(
        o.filters
            .iter()
            .map(|f| (f.flag, f.pattern.clone()))
            .collect::<Vec<_>>(),
        [
            (b'x', b"*.o".to_vec()),
            (b'x', b"*.a".to_vec()),
            (b'i', b"*.c".to_vec())
        ]
    );
    // level 9 compresses everything: no special suffixes
    assert_eq!(o.special, None);
    assert!(o.allow_empty_archive);
}

/// The bytes `optionerr` formats an option's name into, as the C counts
/// them: `'name' (description)`.
fn optname_len(s: &OptionSpec, islong: bool) -> usize {
    let nm = if islong { s.long } else { s.short };
    nm.len()
        + 2
        + if s.name.is_empty() {
            0
        } else {
            s.name.len() + 3
        }
}

/// Every error `get_option` raises about an option, as (`-x` or `--long`
/// form, the message), for the options whose name text needs 50 bytes or
/// more: the C formats it into `char optname[50]` with `sprintf`, so
/// both references abort there (Apple: SIGTRAP from `__sprintf_chk`;
/// Ubuntu: glibc's "buffer overflow detected", then zip's SIGABRT handler,
/// exit 9). Deviation 5: stuffr prints the whole message, exit 16. This
/// stuffr-only test pins which commands that is, and what they print.
#[test]
fn an_option_name_too_long_for_the_c_buffer_is_still_answered_whole() {
    let mut found: Vec<(Flavour, String)> = Vec::new();
    for f in [Flavour::Apple, Flavour::Ubuntu] {
        for s in table(f) {
            let nolist = |t: ValueType| matches!(t, ValueType::Required | ValueType::List);
            // short forms: `-r-`, and a value option at the end
            if !s.short.is_empty() && optname_len(&s, false) >= 50 {
                if s.value == ValueType::No && !s.negatable {
                    found.push((f, format!("-{}-", s.short)));
                }
                if nolist(s.value) {
                    found.push((f, format!("-{}", s.short)));
                }
            }
            // long forms: `--long-`, `--long` at the end, `--long=value`
            if !s.long.is_empty() && optname_len(&s, true) >= 50 {
                if !s.negatable {
                    found.push((f, format!("--{}-", s.long)));
                }
                if nolist(s.value) {
                    found.push((f, format!("--{}", s.long)));
                }
                if s.value == ValueType::No {
                    found.push((f, format!("--{}=v", s.long)));
                }
            }
        }
    }
    let of = |want: Flavour| -> Vec<&str> {
        found
            .iter()
            .filter(|(f, _)| *f == want)
            .map(|(_, a)| a.as_str())
            .collect()
    };
    assert_eq!(of(Flavour::Apple), PINNED_OVERFLOWS);
    let mut ubuntu = of(Flavour::Ubuntu);
    ubuntu.retain(|a| !PINNED_OVERFLOWS_UBUNTU.contains(a));
    assert_eq!(ubuntu, PINNED_OVERFLOWS);
    assert_eq!(
        of(Flavour::Ubuntu).len(),
        PINNED_OVERFLOWS.len() + PINNED_OVERFLOWS_UBUNTU.len()
    );
    // each of them answers the whole message with exit 16, as the C
    // would have had the buffer been large enough
    for (f, arg) in &found {
        let (code, out, err) = go(*f, "zip", &[arg.as_str()]);
        assert_eq!((code, err.as_str()), (16, ""), "{arg}: {out}");
        assert!(
            out.starts_with("\nzip error: Invalid command arguments (option '")
                || out.starts_with("\nzip error: Invalid command arguments (long option '"),
            "{arg}: {out}"
        );
        assert!(out.ends_with(")\n"), "{arg}: {out}");
    }
    let (code, out, _) = go(Flavour::Apple, "zip", &["-lf"]);
    assert_eq!(code, 16);
    assert_eq!(
        out,
        "\nzip error: Invalid command arguments (option 'lf' (log to log file at path (default overwrite)) requires a value)\n"
    );
    let (_, out, _) = go(Flavour::Apple, "zip", &["--output-file"]);
    assert_eq!(
        out,
        "\nzip error: Invalid command arguments (option 'output-file' (set out zipfile different than in zipfile) requires a value)\n"
    );
}

/// `-O` with no archive name: the C compares a NULL `in_path` and dies of
/// SIGSEGV, which zip's handler answers (in both builds, as measured) with
/// a blank line and `zip error: Interrupted (aborting)`, exit 9. Deviation
/// 5: stuffr gives that answer without the dereference.
#[test]
fn an_out_name_without_an_archive_name_answers_as_the_references_crash_does() {
    for f in [Flavour::Apple, Flavour::Ubuntu] {
        for argv in [&["-O", "o.zip"][..], &["-s-", "--output-file", "1k"][..]] {
            let (code, out, err) = go(f, "zip", argv);
            assert_eq!((code, err.as_str()), (9, ""), "{argv:?}");
            assert_eq!(
                out, "\n\nzip error: Interrupted (aborting)\n",
                "{f:?} {argv:?}"
            );
        }
    }
    // with an archive name the usual check answers
    let (code, out, _) = go(Flavour::Apple, "zip", &["-O", "t.zip", "t.zip", "a"]);
    assert_eq!(code, 16);
    assert!(out.contains("--out path must be different than in path: t.zip"));
}

/// The forms that overflow, in Apple's table order (the same under
/// Ubuntu's, which adds the two of [`PINNED_OVERFLOWS_UBUNTU`]; measured
/// on Apple's reference for every form of every option: it dies exactly
/// when the formatted name needs 50 bytes or more).
const PINNED_OVERFLOWS: &[&str] = &[
    "--display-dots=v",
    "--display-globaldots=v",
    "--dot-size-",
    "--dot-size",
    "--display-usize=v",
    "--no-dir-entries-",
    "--no-dir-entries=v",
    "--difference-archive-",
    "--difference-archive=v",
    "-FF-",
    "--fixfix-",
    "--fixfix=v",
    "--fifo=v",
    "-FS-",
    "--filesync-",
    "--filesync=v",
    "--force-descriptors-",
    "--force-descriptors=v",
    "--force-zip64=v",
    "--junk-paths-",
    "--junk-paths=v",
    "--to-crlf-",
    "--to-crlf=v",
    "--from-crlf-",
    "--from-crlf=v",
    "-lf",
    "--logfile-path-",
    "--logfile-path",
    "--log-info=v",
    "--must-match-",
    "--must-match=v",
    "--latest-time-",
    "--latest-time=v",
    "--output-file-",
    "--output-file",
    "--password-",
    "--password",
    "--recurse-patterns-",
    "--recurse-patterns=v",
    "--split-size-",
    "--split-size",
    "-sp-",
    "--split-pause-",
    "--split-pause=v",
    "--split-verbose-",
    "--split-verbose=v",
    "--split-bell-",
    "--split-bell=v",
    "--unzip-command-",
    "--unzip-command",
    "--copy-entries-",
    "--copy-entries=v",
    "--version-",
    "--version=v",
    "--wild-stop-dirs-",
    "--wild-stop-dirs=v",
    "--strip-extra=v",
    "--names-stdin-",
    "--names-stdin=v",
];

/// What Ubuntu's table adds (its `-su` and `-sU`).
const PINNED_OVERFLOWS_UBUNTU: &[&str] = &["--show-unicode=v", "--show-just-unicode=v"];

/// Every row of both tables has an arm in `main()`'s loop: no option ever
/// reaches the "no such option ID" answer.
#[test]
fn every_table_row_has_an_arm() {
    for f in [Flavour::Apple, Flavour::Ubuntu] {
        for s in table(f) {
            let arg = if !s.long.is_empty() {
                match s.value {
                    ValueType::No => format!("--{}", s.long),
                    _ => format!("--{}=1", s.long),
                }
            } else {
                match s.value {
                    ValueType::No => format!("-{}", s.short),
                    _ => format!("-{}1", s.short),
                }
            };
            let (_, out, err) = go(f, "zip", &[arg.as_str()]);
            assert!(
                !out.contains("no such option ID") && !err.contains("no such option ID"),
                "{f:?} {arg}: {out}{err}"
            );
        }
    }
}
