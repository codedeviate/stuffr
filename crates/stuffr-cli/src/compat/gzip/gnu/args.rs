//! GNU gzip 1.15's argument handling, established by running the binary:
//! the words of `$GZIP` first, then argv, both through GNU `getopt_long`.
//!
//! - **getopt_long, observed:** options and operands interleave (operands
//!   are collected in order) unless `POSIXLY_CORRECT` is set, when the
//!   first operand ends the options; `--` ends them too; `-` is an operand.
//!   A short option taking an argument takes the rest of its cluster or the
//!   next word, whatever it is (`-S -1`). A long option is matched exactly
//!   or by any unique prefix (`--std` is `--stdout`, `--s` is ambiguous);
//!   `--name=value` gives the argument inline. Errors name the full
//!   `argv[0]` and are followed by ``Try `gzip --help'``, exit 1.
//! - **The tables,** from `gzip --=x`, whose "ambiguous" message lists every
//!   long option in table order (`---presume-input-tty` among them), and
//!   from trying every short letter: `-a -b N -m -M -H -Z` are accepted
//!   though `--help` does not list them.
//! - **Immediate stops,** in argv order: `-h`/`-H` (help), `-V` (version)
//!   and `-L` (licence) print and exit 0; `-Z`, a non-integer `-b` and a
//!   `-S` holding `/` exit 1 at that option. After parsing: `--ascii`'s
//!   note (unless quiet), then the suffix check (empty or over 30 bytes).
//! - **`$GZIP` (1.14 and later):** split on spaces and tabs only, parsed the
//!   same way with every error silent, and only `-1`..`-9`, `--fast`,
//!   `--best`, `--rsyncable` and `--synchronous` take effect (`GZIP=-k9`
//!   sets level 9 and nothing else; `GZIP="-- -1"` sets nothing).

use std::ffi::OsString;
use std::io::Write;

use super::messages::{self as m, PROGRAM, printf, quote};

/// What a parsed option does, by its short letter or a long-only key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Ch(u8),
    Rsyncable,
    Synchronous,
    PresumeTty,
}

struct LongOpt {
    name: &'static str,
    takes_arg: bool,
    key: Key,
}

const fn opt(name: &'static str, takes_arg: bool, key: Key) -> LongOpt {
    LongOpt {
        name,
        takes_arg,
        key,
    }
}

/// The long options in GNU's table order (observed: `gzip --=x`).
const LONG: &[LongOpt] = &[
    opt("ascii", false, Key::Ch(b'a')),
    opt("to-stdout", false, Key::Ch(b'c')),
    opt("stdout", false, Key::Ch(b'c')),
    opt("decompress", false, Key::Ch(b'd')),
    opt("uncompress", false, Key::Ch(b'd')),
    opt("force", false, Key::Ch(b'f')),
    opt("help", false, Key::Ch(b'h')),
    opt("keep", false, Key::Ch(b'k')),
    opt("list", false, Key::Ch(b'l')),
    opt("license", false, Key::Ch(b'L')),
    opt("no-name", false, Key::Ch(b'n')),
    opt("name", false, Key::Ch(b'N')),
    opt("-presume-input-tty", false, Key::PresumeTty),
    opt("quiet", false, Key::Ch(b'q')),
    opt("silent", false, Key::Ch(b'q')),
    opt("synchronous", false, Key::Synchronous),
    opt("recursive", false, Key::Ch(b'r')),
    opt("suffix", true, Key::Ch(b'S')),
    opt("test", false, Key::Ch(b't')),
    opt("verbose", false, Key::Ch(b'v')),
    opt("version", false, Key::Ch(b'V')),
    opt("fast", false, Key::Ch(b'1')),
    opt("best", false, Key::Ch(b'9')),
    opt("lzw", false, Key::Ch(b'Z')),
    opt("bits", true, Key::Ch(b'b')),
    opt("rsyncable", false, Key::Rsyncable),
];

/// The short options that take no argument (`-?` is accepted by getopt and
/// then rejected by gzip with only ``Try `gzip --help'``).
const SHORT: &[u8] = b"123456789acdfhHklLmMnNqrtvVZ?";
/// The short options that take one.
const SHORT_ARG: &[u8] = b"bS";

/// The longest suffix gzip accepts (observed: 30 bytes pass, 31 do not).
const MAX_SUFFIX: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Compress,
    Decompress,
    Test,
    List,
}

#[derive(Debug)]
pub(super) struct Settings {
    pub(super) mode: Mode,
    pub(super) to_stdout: bool,
    pub(super) force: bool,
    pub(super) keep: bool,
    pub(super) recursive: bool,
    pub(super) quiet: bool,
    pub(super) verbose: u32,
    /// `-n`/`-N`: the name is not stored.
    pub(super) no_name: bool,
    /// `-n`/`-N`/`-m`/`-M`: the modification time is not stored.
    pub(super) no_time: bool,
    /// Decompressing: `-N` was the last of `-n`/`-N`, so the stored name
    /// and time are restored (`-n` is the default when decompressing).
    pub(super) restore: bool,
    pub(super) level: u32,
    pub(super) suffix: Vec<u8>,
    /// `---presume-input-tty`: standard input counts as a terminal.
    pub(super) presume_tty: bool,
    /// The operands, in order.
    pub(super) files: Vec<Vec<u8>>,
}

/// Either settings to run with, or the exit code to stop with, the
/// messages already printed.
pub(super) enum Parsed {
    Run(Settings),
    Exit(u8),
}

/// One getopt error, reported by the caller (or not, for `$GZIP`).
enum OptError {
    Invalid(u8),
    NeedsArgShort(u8),
    Unrecognized(Vec<u8>),
    Ambiguous(Vec<u8>, Vec<&'static str>),
    NeedsArgLong(&'static str),
    NoArgLong(&'static str),
    /// `-?`: gzip prints only the hint.
    Question,
}

/// One step of a parse, in order.
enum Event {
    Opt(Key, Option<Vec<u8>>),
    Err(OptError),
}

/// GNU `getopt_long` over `words`: every option and error in order, and the
/// operands. It has no effects of its own, so the caller acts on the events
/// in order and stops where gzip would.
fn getopt(words: &[Vec<u8>], posix: bool) -> (Vec<Event>, Vec<Vec<u8>>) {
    let mut events = Vec::new();
    let mut operands = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let w = &words[i];
        i += 1;
        if w == b"--" {
            operands.extend(words[i..].iter().cloned());
            break;
        }
        if w.len() < 2 || w[0] != b'-' {
            operands.push(w.clone());
            if posix {
                operands.extend(words[i..].iter().cloned());
                break;
            }
            continue;
        }
        if let Some(body) = w.strip_prefix(b"--") {
            events.push(long_option(w, body, words, &mut i));
            continue;
        }
        // A cluster of short options.
        let mut j = 1;
        while j < w.len() {
            let c = w[j];
            j += 1;
            if c == b'?' {
                events.push(Event::Err(OptError::Question));
            } else if SHORT_ARG.contains(&c) {
                let arg = if j < w.len() {
                    let a = w[j..].to_vec();
                    j = w.len();
                    a
                } else if let Some(v) = words.get(i) {
                    i += 1;
                    v.clone()
                } else {
                    events.push(Event::Err(OptError::NeedsArgShort(c)));
                    break;
                };
                events.push(Event::Opt(Key::Ch(c), Some(arg)));
            } else if SHORT.contains(&c) {
                events.push(Event::Opt(Key::Ch(c), None));
            } else {
                events.push(Event::Err(OptError::Invalid(c)));
            }
        }
    }
    (events, operands)
}

/// `--body` (the word `w`), taking its argument from `words[*i]` when it
/// needs one and has none inline.
fn long_option(w: &[u8], body: &[u8], words: &[Vec<u8>], i: &mut usize) -> Event {
    let (name, inline) = match body.iter().position(|&b| b == b'=') {
        Some(p) => (&body[..p], Some(&body[p + 1..])),
        None => (body, None),
    };
    let found: &'static LongOpt = match LONG.iter().find(|o| o.name.as_bytes() == name) {
        Some(o) => o,
        None => {
            let hits: Vec<&LongOpt> = LONG
                .iter()
                .filter(|o| o.name.as_bytes().starts_with(name))
                .collect();
            match hits.as_slice() {
                [] => return Event::Err(OptError::Unrecognized(w.to_vec())),
                [o] => o,
                // Candidates that all mean the same thing are not
                // ambiguous; getopt takes the first.
                [first, rest @ ..]
                    if rest
                        .iter()
                        .all(|o| o.takes_arg == first.takes_arg && o.key == first.key) =>
                {
                    first
                }
                _ => {
                    let names = hits.iter().map(|o| o.name).collect();
                    return Event::Err(OptError::Ambiguous(w.to_vec(), names));
                }
            }
        }
    };
    match (found.takes_arg, inline) {
        (false, Some(_)) => Event::Err(OptError::NoArgLong(found.name)),
        (false, None) => Event::Opt(found.key, None),
        (true, Some(v)) => Event::Opt(found.key, Some(v.to_vec())),
        (true, None) => match words.get(*i) {
            Some(v) => {
                *i += 1;
                Event::Opt(found.key, Some(v.clone()))
            }
            None => Event::Err(OptError::NeedsArgLong(found.name)),
        },
    }
}

/// `$GZIP`'s words: split on spaces and tabs only (observed: a newline,
/// vertical tab, form feed or carriage return joins its neighbours into
/// one word).
fn env_words(value: &[u8]) -> Vec<Vec<u8>> {
    value
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|w| !w.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// The bytes of an argument. On unix these are exactly argv's bytes.
fn os_bytes(s: &OsString) -> Vec<u8> {
    s.as_encoded_bytes().to_vec()
}

/// Whether `-b`'s operand is an integer as gzip judges it: ASCII digits
/// only, the empty string included (observed: `-b ''` passes, `-b +3`,
/// `-b ' 3'` and `-b 0x10` do not).
fn is_integer(s: &[u8]) -> bool {
    s.iter().all(u8::is_ascii_digit)
}

/// Parse `args` (with `$GZIP` from `env`). `getopt_name` prefixes getopt's
/// own errors (the full `argv[0]`); `out` takes `--help` and `--version`.
pub(super) fn parse(
    getopt_name: &[u8],
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Parsed {
    let posix = env("POSIXLY_CORRECT").is_some();
    let mut s = Settings {
        mode: Mode::Compress,
        to_stdout: false,
        force: false,
        keep: false,
        recursive: false,
        quiet: false,
        verbose: 0,
        no_name: false,
        no_time: false,
        restore: false,
        level: 6,
        suffix: b".gz".to_vec(),
        presume_tty: false,
        files: Vec::new(),
    };
    let mut ascii = false;

    // `$GZIP`: levels only, every error silent.
    if let Some(v) = env("GZIP") {
        let (events, _) = getopt(&env_words(&os_bytes(&v)), posix);
        for e in events {
            if let Event::Opt(Key::Ch(c @ b'1'..=b'9'), _) = e {
                s.level = u32::from(c - b'0');
            }
        }
    }

    let words: Vec<Vec<u8>> = args.iter().map(os_bytes).collect();
    let (events, operands) = getopt(&words, posix);
    for e in events {
        let stop = match e {
            Event::Opt(k, arg) => apply(&mut s, &mut ascii, k, arg.as_deref(), out, err),
            Event::Err(e) => {
                report(getopt_name, e, err);
                Some(1)
            }
        };
        if let Some(code) = stop {
            return Parsed::Exit(code);
        }
    }
    s.files = operands;
    let p = PROGRAM;
    if ascii && !s.quiet {
        printf(err, m::ASCII_IGNORED, &[p]);
    }
    if s.suffix.is_empty() || s.suffix.len() > MAX_SUFFIX {
        printf(err, m::INVALID_SUFFIX, &[p, &quote(&s.suffix)]);
        return Parsed::Exit(1);
    }
    Parsed::Run(s)
}

/// Act on one option from argv; `Some(code)` stops the run there.
fn apply(
    s: &mut Settings,
    ascii: &mut bool,
    k: Key,
    arg: Option<&[u8]>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Option<u8> {
    let p = PROGRAM;
    match k {
        Key::Ch(c @ b'1'..=b'9') => s.level = u32::from(c - b'0'),
        Key::Ch(b'a') => *ascii = true,
        Key::Ch(b'b') => {
            if !is_integer(arg.unwrap_or_default()) {
                printf(err, m::BITS_NOT_INTEGER, &[p]);
                printf(err, m::TRY_HELP, &[p]);
                return Some(1);
            }
        }
        Key::Ch(b'c') => s.to_stdout = true,
        Key::Ch(b'd') => s.mode = Mode::Decompress,
        Key::Ch(b'f') => s.force = true,
        Key::Ch(b'h' | b'H') => {
            printf(out, m::HELP, &[p]);
            return Some(0);
        }
        Key::Ch(b'k') => s.keep = true,
        Key::Ch(b'l') => s.mode = Mode::List,
        Key::Ch(b'L') => {
            let _ = out.write_all(m::VERSION_FIRST_LINE.as_bytes());
            let _ = out.write_all(m::LICENSE_REST.as_bytes());
            return Some(0);
        }
        Key::Ch(b'm') => s.no_time = true,
        Key::Ch(b'M') => s.no_time = false,
        Key::Ch(b'n') => {
            s.no_name = true;
            s.no_time = true;
            s.restore = false;
        }
        Key::Ch(b'N') => {
            s.no_name = false;
            s.no_time = false;
            s.restore = true;
        }
        Key::Ch(b'q') => {
            s.quiet = true;
            s.verbose = 0;
        }
        Key::Ch(b'r') => s.recursive = true,
        Key::Ch(b'S') => {
            let v = arg.unwrap_or_default();
            if v.contains(&b'/') {
                printf(err, m::SUFFIX_SLASH, &[p]);
                return Some(1);
            }
            s.suffix = v.to_vec();
        }
        Key::Ch(b't') => s.mode = Mode::Test,
        Key::Ch(b'v') => {
            s.verbose += 1;
            s.quiet = false;
        }
        Key::Ch(b'V') => {
            let _ = out.write_all(m::VERSION_FIRST_LINE.as_bytes());
            let _ = out.write_all(m::LICENSE_REST.as_bytes());
            let _ = out.write_all(m::WRITTEN_BY.as_bytes());
            return Some(0);
        }
        Key::Ch(b'Z') => {
            printf(err, m::LZW, &[p]);
            printf(err, m::TRY_HELP, &[p]);
            return Some(1);
        }
        Key::PresumeTty => s.presume_tty = true,
        // Accepted; neither changes what is written (the output is
        // compatible either way).
        Key::Rsyncable | Key::Synchronous => {}
        // Every short letter in `SHORT` and `SHORT_ARG` is handled above.
        Key::Ch(_) => {}
    }
    None
}

/// getopt's own message for `e`, then the hint.
fn report(getopt_name: &[u8], e: OptError, err: &mut dyn Write) {
    let n = getopt_name;
    match e {
        OptError::Invalid(c) => printf(err, m::INVALID_OPTION, &[n, &[c]]),
        OptError::NeedsArgShort(c) => printf(err, m::NEEDS_ARGUMENT_SHORT, &[n, &[c]]),
        OptError::Unrecognized(w) => printf(err, m::UNRECOGNIZED, &[n, &w]),
        OptError::Ambiguous(w, names) => {
            printf(err, m::AMBIGUOUS, &[n, &w]);
            for name in names {
                printf(err, m::CANDIDATE, &[name.as_bytes()]);
            }
            let _ = err.write_all(b"\n");
        }
        OptError::NeedsArgLong(o) => printf(err, m::NEEDS_ARGUMENT_LONG, &[n, o.as_bytes()]),
        OptError::NoArgLong(o) => printf(err, m::NO_ARGUMENT_LONG, &[n, o.as_bytes()]),
        OptError::Question => {}
    }
    printf(err, m::TRY_HELP, &[PROGRAM]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str], env: &[(&str, &str)]) -> (Option<Settings>, u8, String, String) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let lookup = move |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| OsString::from(v))
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let r = parse(b"/x/gzip", &args, &lookup, &mut out, &mut err);
        let (out, err) = (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        );
        match r {
            Parsed::Run(s) => (Some(s), 0, out, err),
            Parsed::Exit(c) => (None, c, out, err),
        }
    }

    #[test]
    fn options_and_operands_interleave_until_double_dash() {
        let s = run(&["a", "-k", "--", "-c"], &[]).0.unwrap();
        assert!(s.keep && !s.to_stdout);
        assert_eq!(s.files, vec![b"a".to_vec(), b"-c".to_vec()]);
        let s = run(&["-", "-c"], &[]).0.unwrap();
        assert!(s.to_stdout);
        assert_eq!(s.files, vec![b"-".to_vec()]);
    }

    #[test]
    fn posixly_correct_stops_at_the_first_operand() {
        let s = run(&["-c", "a", "-v"], &[("POSIXLY_CORRECT", "1")])
            .0
            .unwrap();
        assert_eq!(s.verbose, 0);
        assert_eq!(s.files, vec![b"a".to_vec(), b"-v".to_vec()]);
    }

    #[test]
    fn long_options_take_unique_prefixes() {
        let s = run(&["--std", "--fa", "--su=.x", "a"], &[]).0.unwrap();
        assert!(s.to_stdout);
        assert_eq!(s.level, 1);
        assert_eq!(s.suffix, b".x");
        let (_, code, _, err) = run(&["--s"], &[]);
        assert_eq!(code, 1);
        assert_eq!(
            err,
            "/x/gzip: option '--s' is ambiguous; possibilities: '--stdout' \
             '--silent' '--synchronous' '--suffix'\nTry `gzip --help' for more information.\n"
        );
        let (_, _, _, err) = run(&["--he=x"], &[]);
        assert!(err.starts_with("/x/gzip: option '--help' doesn't allow an argument\n"));
        let (_, _, _, err) = run(&["--su"], &[]);
        assert!(err.starts_with("/x/gzip: option '--suffix' requires an argument\n"));
    }

    #[test]
    fn short_arguments_take_the_rest_or_the_next_word() {
        assert_eq!(run(&["-kS.y", "a"], &[]).0.unwrap().suffix, b".y");
        let s = run(&["-kS", "-1", "a"], &[]).0.unwrap();
        assert_eq!((s.suffix.as_slice(), s.level), (&b"-1"[..], 6));
        let (_, code, _, err) = run(&["-kS"], &[]);
        assert_eq!(code, 1);
        assert!(err.starts_with("/x/gzip: option requires an argument -- 'S'\n"));
    }

    #[test]
    fn stops_happen_in_argv_order() {
        let (_, code, out, err) = run(&["-h", "-x"], &[]);
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(out.starts_with("Usage: gzip [OPTION]... [FILE]...\n"));
        let (_, code, out, err) = run(&["-x", "-h"], &[]);
        assert_eq!((code, out.as_str()), (1, ""));
        assert_eq!(
            err,
            "/x/gzip: invalid option -- 'x'\nTry `gzip --help' for more information.\n"
        );
        let (_, code, _, err) = run(&["-?"], &[]);
        assert_eq!(
            (code, err.as_str()),
            (1, "Try `gzip --help' for more information.\n")
        );
        let (_, code, _, err) = run(&["-S", "x/y", "-S", ".z"], &[]);
        assert_eq!((code, err.as_str()), (1, "gzip: suffix contains '/'\n"));
        let (_, code, _, err) = run(&["-S", "", "-x"], &[]);
        assert_eq!(code, 1);
        assert!(err.contains("invalid option"), "{err}");
        let (_, code, _, err) = run(&["-a", "-S", "", "a"], &[]);
        assert_eq!(code, 1);
        assert_eq!(
            err,
            "gzip: option --ascii ignored on this system\ngzip: '': invalid suffix\n"
        );
    }

    #[test]
    fn name_and_time_flags_are_separate() {
        let s = run(&["-nM"], &[]).0.unwrap();
        assert!(s.no_name && !s.no_time);
        let s = run(&["-Nm"], &[]).0.unwrap();
        assert!(!s.no_name && s.no_time);
        let s = run(&["-n", "-N"], &[]).0.unwrap();
        assert!(!s.no_name && !s.no_time && s.restore);
        assert!(!run(&["-N", "-n"], &[]).0.unwrap().restore);
        assert!(!run(&[], &[]).0.unwrap().restore);
    }

    #[test]
    fn quiet_and_verbose_undo_each_other() {
        let s = run(&["-vq"], &[]).0.unwrap();
        assert!(s.quiet && s.verbose == 0);
        let s = run(&["-qv"], &[]).0.unwrap();
        assert!(!s.quiet && s.verbose == 1);
    }

    #[test]
    fn gzip_env_sets_only_the_level() {
        for (v, level) in [
            ("-9", 9),
            ("-k9", 9),
            ("-1x9", 9),
            ("--fa", 1),
            ("-x -1", 1),
            ("-- -1", 6),
            ("a -1", 1),
            ("-S -1", 6),
            ("x\n-1", 6),
            ("  -1\t", 1),
            ("-9 -c -v -k -d -h -V", 9),
        ] {
            let (s, code, out, err) = run(&["-q"], &[("GZIP", v)]);
            let s = s.unwrap_or_else(|| panic!("{v:?} stopped the run"));
            assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""), "{v:?}");
            assert_eq!(s.level, level, "{v:?}");
            assert!(!s.to_stdout && !s.keep && s.mode == Mode::Compress, "{v:?}");
            assert!(s.files.is_empty(), "{v:?}");
        }
        assert_eq!(run(&["-1"], &[("GZIP", "-9")]).0.unwrap().level, 1);
    }
}
