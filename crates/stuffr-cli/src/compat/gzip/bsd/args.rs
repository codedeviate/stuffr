//! Apple gzip's arguments: `prepend_gzip` (the words of `$GZIP` go first),
//! then `main`'s option loop over Apple libc's `getopt_long`.
//!
//! **`getopt_long`** (Apple libc, OpenBSD lineage, built `GNU_COMPATIBLE`),
//! as it behaves for gzip's `OPT_LIST` `123456789acdfhklLNnqrS:tVv` and
//! `longopts`, each point confirmed against `/usr/bin/gzip`:
//!
//! - Operands and options interleave: every operand is kept, in order,
//!   and processed after all options (`gzip a -x` prints usage first).
//!   With `POSIXLY_CORRECT` in the environment (any value, empty too) the
//!   first operand ends the options, and a bad letter is "illegal", not
//!   "invalid". `--` ends the options; `-` is an operand.
//! - A short option taking an argument (`S`) takes the rest of its cluster
//!   or the next word, whatever it is.
//! - A `-` inside a cluster starts a long option there: `-c-` is a silent
//!   error (usage, no message), `-c-stdout` is `-c --stdout`, `-c-x` is
//!   "unrecognized option `--x'".
//! - A long option matches exactly, or by a prefix that only options with
//!   the same meaning share (`--st` is `--stdout`; `--s` is ambiguous);
//!   `--name=value` gives the argument inline, `--name value` the next
//!   word. The messages name the option as typed (see `messages.rs`).
//! - Every error is followed by `usage()`, which exits 0.
//!
//! **`main`** acts on each option as it is returned: `-V` and `-L` print
//! and exit 0 there, `-a` prints its note there, and `-S` longer than 30
//! bytes is `errx(1)` there. `-S ''` empties the last suffix of the table
//! instead of the first, so it changes nothing when compressing.

use std::ffi::OsString;
use std::io::Write;

use super::messages::{self as m, printf};

/// `SUFFIX_MAXLEN`.
const SUFFIX_MAXLEN: usize = 30;

/// `OPT_LIST` (not `SMALL`).
const OPT_LIST: &[u8] = b"123456789acdfhklLNnqrS:tVv";

/// `longopts`, in table order: name, takes an argument, the letter.
const LONGOPTS: &[(&str, bool, u8)] = &[
    ("stdout", false, b'c'),
    ("to-stdout", false, b'c'),
    ("decompress", false, b'd'),
    ("uncompress", false, b'd'),
    ("force", false, b'f'),
    ("help", false, b'h'),
    ("keep", false, b'k'),
    ("list", false, b'l'),
    ("no-name", false, b'n'),
    ("name", false, b'N'),
    ("quiet", false, b'q'),
    ("recursive", false, b'r'),
    ("suffix", true, b'S'),
    ("test", false, b't'),
    ("verbose", false, b'v'),
    ("version", false, b'V'),
    ("fast", false, b'1'),
    ("best", false, b'9'),
    ("ascii", false, b'a'),
    ("license", false, b'L'),
];

/// gzip's flags after the option loop.
#[derive(Debug, Clone)]
pub(super) struct Settings {
    /// `cflag`: to standard output.
    pub(super) to_stdout: bool,
    /// `dflag`: decompress (also `-l`, `-t`, and the names `gunzip`,
    /// `zcat`, `gzcat`).
    pub(super) decompress: bool,
    pub(super) list: bool,
    pub(super) test: bool,
    pub(super) force: bool,
    pub(super) keep: bool,
    /// `nflag`: store neither name nor time.
    pub(super) no_name: bool,
    /// `Nflag`: restore the stored name and time (decompressing).
    pub(super) restore_name: bool,
    pub(super) quiet: bool,
    pub(super) recursive: bool,
    pub(super) verbose: bool,
    /// `numflag`.
    pub(super) level: u32,
    /// `suffixes[0].zipped`: `.gz`, or `-S`'s.
    pub(super) suffix: Vec<u8>,
    /// `-S ''`: the table's last suffix is empty (decompressing).
    pub(super) empty_last_suffix: bool,
    /// The operands, in order.
    pub(super) files: Vec<Vec<u8>>,
}

pub(super) enum Parsed {
    Run(Settings),
    /// Stop with this code; everything is printed.
    Exit(u8),
}

/// What one `getopt_long` call returned.
#[derive(Debug, PartialEq, Eq)]
enum Got {
    /// An option letter (a long option returns its letter) and its
    /// argument.
    Opt(u8, Option<Vec<u8>>),
    /// `BADCH`/`BADARG`: an error, its message (if any) already printed.
    Bad,
    /// No more options.
    End,
}

/// Apple libc's `getopt_long` over `words` (no `argv[0]`): the state of
/// its scan, operands collected as they are skipped.
struct Getopt<'w> {
    words: &'w [Vec<u8>],
    /// `optind`.
    ind: usize,
    /// Within a cluster: the offset of the next letter in `words[ind]`.
    place: usize,
    posix: bool,
    operands: Vec<Vec<u8>>,
}

impl<'w> Getopt<'w> {
    fn new(words: &'w [Vec<u8>], posix: bool) -> Self {
        Getopt {
            words,
            ind: 0,
            place: 0,
            posix,
            operands: Vec::new(),
        }
    }

    /// Everything from `from` on is an operand.
    fn rest_are_operands(&mut self, from: usize) {
        self.operands.extend(self.words[from..].iter().cloned());
        self.ind = self.words.len();
    }

    fn next(&mut self, name: &str, err: &mut dyn Write) -> Got {
        if self.place == 0 {
            // A fresh word.
            loop {
                let Some(w) = self.words.get(self.ind) else {
                    return Got::End;
                };
                if w.first() != Some(&b'-') || w.len() == 1 {
                    if self.posix {
                        self.rest_are_operands(self.ind);
                        return Got::End;
                    }
                    self.operands.push(w.clone());
                    self.ind += 1;
                    continue;
                }
                if w.as_slice() == b"--" {
                    self.rest_are_operands(self.ind + 1);
                    return Got::End;
                }
                break;
            }
            self.place = 1;
        }
        let w = &self.words[self.ind];
        if w[self.place] == b'-' {
            // `--name`, or a `-` inside a cluster: a long option.
            self.place += 1;
            if self.place == w.len() {
                // `-c-`: "malformed option", no message.
                self.place = 0;
                self.ind += 1;
                return Got::Bad;
            }
            let body = w[self.place..].to_vec();
            self.place = 0;
            return self.long(&body, name, err);
        }
        let c = w[self.place];
        self.place += 1;
        let at_end = self.place == w.len();
        let known = c != b':' && OPT_LIST.contains(&c);
        if !known {
            if at_end {
                self.ind += 1;
                self.place = 0;
            }
            let fmt = if self.posix {
                m::ILLEGAL_OPTION
            } else {
                m::INVALID_OPTION
            };
            say(err, name, fmt, &[&[c]]);
            return Got::Bad;
        }
        let takes_arg = OPT_LIST
            .iter()
            .position(|&o| o == c)
            .is_some_and(|i| OPT_LIST.get(i + 1) == Some(&b':'));
        if !takes_arg {
            if at_end {
                self.ind += 1;
                self.place = 0;
            }
            return Got::Opt(c, None);
        }
        let arg = if !at_end {
            Some(w[self.place..].to_vec())
        } else {
            self.ind += 1;
            match self.words.get(self.ind) {
                Some(a) => Some(a.clone()),
                None => {
                    self.place = 0;
                    say(err, name, m::NEEDS_ARGUMENT_SHORT, &[&[c]]);
                    return Got::Bad;
                }
            }
        };
        self.ind += 1;
        self.place = 0;
        Got::Opt(c, arg)
    }

    /// `parse_long_options` for the word body after `--`.
    fn long(&mut self, body: &[u8], name: &str, err: &mut dyn Write) -> Got {
        self.ind += 1;
        let (typed, inline) = match body.iter().position(|&b| b == b'=') {
            Some(i) => (&body[..i], Some(body[i + 1..].to_vec())),
            None => (body, None),
        };
        let mut found: Option<usize> = None;
        let mut ambiguous = false;
        for (i, &(opt, has_arg, val)) in LONGOPTS.iter().enumerate() {
            if !opt.as_bytes().starts_with(typed) {
                continue;
            }
            if opt.len() == typed.len() {
                found = Some(i);
                ambiguous = false;
                break;
            }
            match found {
                None => found = Some(i),
                Some(j) => {
                    let (_, ha, va) = LONGOPTS[j];
                    if ha != has_arg || va != val {
                        ambiguous = true;
                    }
                }
            }
        }
        if ambiguous {
            say(err, name, m::AMBIGUOUS, &[typed]);
            return Got::Bad;
        }
        let Some(i) = found else {
            say(err, name, m::UNRECOGNIZED, &[body]);
            return Got::Bad;
        };
        let (_, has_arg, val) = LONGOPTS[i];
        if !has_arg {
            if inline.is_some() {
                say(err, name, m::NO_ARGUMENT, &[typed]);
                return Got::Bad;
            }
            return Got::Opt(val, None);
        }
        let arg = match inline {
            Some(a) => Some(a),
            None => {
                let a = self.words.get(self.ind).cloned();
                self.ind += 1;
                a
            }
        };
        match arg {
            Some(a) => Got::Opt(val, Some(a)),
            None => {
                self.ind -= 1;
                say(err, name, m::NEEDS_ARGUMENT_LONG, &[body]);
                Got::Bad
            }
        }
    }
}

/// `getopt`'s and `errx`'s messages: the program name, then the text.
fn say(err: &mut dyn Write, name: &str, fmt: &str, args: &[&[u8]]) {
    printf(err, m::PREFIX, &[name.as_bytes()]);
    printf(err, fmt, args);
}

/// `prepend_gzip`: `$GZIP` split on spaces and tabs, empty words dropped.
fn env_words(value: &[u8]) -> Vec<Vec<u8>> {
    value
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|w| !w.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn os_bytes(s: &OsString) -> Vec<u8> {
    s.as_encoded_bytes().to_vec()
}

/// `usage()`: the version line and the usage text, on standard error;
/// gzip then exits 0.
pub(super) fn usage(name: &str, err: &mut dyn Write) -> Parsed {
    let _ = err.write_all(m::GZIP_VERSION.as_bytes());
    printf(err, m::USAGE, &[name.as_bytes()]);
    Parsed::Exit(0)
}

/// `main` up to the end of its option loop, for the invoked `name`.
pub(super) fn parse(
    name: &str,
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    err: &mut dyn Write,
) -> Parsed {
    let mut words: Vec<Vec<u8>> = env("GZIP").map_or_else(Vec::new, |v| env_words(&os_bytes(&v)));
    words.extend(args.iter().map(os_bytes));
    let posix = env("POSIXLY_CORRECT").is_some();
    let mut s = Settings {
        to_stdout: false,
        decompress: false,
        list: false,
        test: false,
        force: false,
        keep: false,
        no_name: false,
        restore_name: false,
        quiet: false,
        recursive: false,
        verbose: false,
        level: 6,
        suffix: b".gz".to_vec(),
        empty_last_suffix: false,
        files: Vec::new(),
    };
    // The names `gunzip`, `zcat` and `gzcat`.
    match name {
        "gunzip" => s.decompress = true,
        "zcat" | "gzcat" => {
            s.decompress = true;
            s.to_stdout = true;
        }
        _ => {}
    }
    let mut g = Getopt::new(&words, posix);
    loop {
        let (c, arg) = match g.next(name, err) {
            Got::End => break,
            Got::Bad => return usage(name, err),
            Got::Opt(c, arg) => (c, arg),
        };
        match c {
            b'1'..=b'9' => s.level = u32::from(c - b'0'),
            b'c' => s.to_stdout = true,
            b'd' => s.decompress = true,
            b'l' => {
                s.list = true;
                s.decompress = true;
            }
            b'V' => {
                let _ = err.write_all(m::VERSION_FIRST_LINE.as_bytes());
                return Parsed::Exit(0);
            }
            b'a' => printf(err, m::ASCII_IGNORED, &[name.as_bytes()]),
            b'f' => s.force = true,
            b'k' => s.keep = true,
            b'L' => {
                let _ = err.write_all(m::LICENSE_FIRST_LINE.as_bytes());
                let _ = err.write_all(m::LICENSE_REST.as_bytes());
                return Parsed::Exit(0);
            }
            b'N' => {
                s.no_name = false;
                s.restore_name = true;
            }
            b'n' => {
                s.no_name = true;
                s.restore_name = false;
            }
            b'q' => s.quiet = true,
            b'r' => s.recursive = true,
            b'S' => {
                let a = arg.unwrap_or_default();
                if a.is_empty() {
                    s.empty_last_suffix = true;
                } else if a.len() > SUFFIX_MAXLEN {
                    say(err, name, m::SUFFIX_TOO_LONG, &[&a]);
                    return Parsed::Exit(1);
                } else {
                    s.suffix = a;
                }
            }
            b't' => {
                s.to_stdout = true;
                s.test = true;
                s.decompress = true;
            }
            b'v' => s.verbose = true,
            // `-h`, and anything else `getopt_long` returned.
            _ => return usage(name, err),
        }
    }
    s.files = g.operands;
    Parsed::Run(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str], env: &[(&str, &str)]) -> (Option<Settings>, u8, String) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let get = move |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| OsString::from(v))
        };
        let mut err = Vec::new();
        let (s, code) = match parse("gzip", &args, &get, &mut err) {
            Parsed::Run(s) => (Some(s), 0),
            Parsed::Exit(c) => (None, c),
        };
        (s, code, String::from_utf8(err).unwrap())
    }

    fn first_line(e: &str) -> &str {
        e.lines().next().unwrap_or("")
    }

    /// Each expectation is what `/usr/bin/gzip` 487.0.1 printed.
    #[test]
    fn getopt_errors_match_the_binary() {
        for (args, want) in [
            (&["-x"][..], "gzip: invalid option -- x"),
            (&["--bogus=1"], "gzip: unrecognized option `--bogus=1'"),
            (&["--s=x"], "gzip: option `--s' is ambiguous"),
            (&["--=x"], "gzip: option `--' is ambiguous"),
            (&["---"], "gzip: unrecognized option `---'"),
            (&["--fa=1"], "gzip: option `--fa' doesn't allow an argument"),
            (&["--su"], "gzip: option `--su' requires an argument"),
            (&["-S"], "gzip: option requires an argument -- S"),
            (&["-c-x"], "gzip: unrecognized option `--x'"),
            (&["-c-"], "Apple gzip 487.0.1"),
        ] {
            let (s, code, e) = run(args, &[]);
            assert!(s.is_none() && code == 0, "{args:?}");
            assert_eq!(first_line(&e), want, "{args:?}");
            assert!(e.contains("usage: gzip ["), "{args:?}");
        }
        let (_, _, e) = run(&["-x"], &[("POSIXLY_CORRECT", "")]);
        assert_eq!(first_line(&e), "gzip: illegal option -- x");
    }

    #[test]
    fn operands_interleave_and_dashes_end_options() {
        let (s, ..) = run(&["a", "-c", "b", "--", "-k", "-"], &[]);
        let s = s.unwrap();
        assert!(s.to_stdout && !s.keep);
        assert_eq!(s.files, [&b"a"[..], b"b", b"-k", b"-"]);
        let (s, ..) = run(&["-c", "a", "-v"], &[("POSIXLY_CORRECT", "1")]);
        let s = s.unwrap();
        assert!(!s.verbose);
        assert_eq!(s.files, [&b"a"[..], b"-v"]);
        let (s, ..) = run(&["-c-stdout", "-k-fast", "-c-suffix", ".z", "a"], &[]);
        let s = s.unwrap();
        assert_eq!(
            (s.level, s.keep, s.suffix.as_slice()),
            (1, true, &b".z"[..])
        );
    }

    #[test]
    fn long_options_abbreviate_when_unambiguous() {
        for (arg, check) in [
            (
                "--std",
                (|s: &Settings| s.to_stdout) as fn(&Settings) -> bool,
            ),
            ("--to", |s| s.to_stdout),
            ("--fo", |s| s.force),
            ("--na", |s| s.restore_name),
            ("--no", |s| s.no_name),
            ("--b", |s| s.level == 9),
            ("--verb", |s| s.verbose),
        ] {
            let (s, ..) = run(&[arg], &[]);
            assert!(check(&s.unwrap()), "{arg}");
        }
        for arg in ["--s", "--n", "--l", "--f", "--t", "--v"] {
            let (s, _, e) = run(&[arg], &[]);
            assert!(s.is_none(), "{arg}");
            assert!(e.contains("is ambiguous"), "{arg}: {e}");
        }
    }

    #[test]
    fn gzip_env_words_go_first() {
        let (s, ..) = run(&["a"], &[("GZIP", "  -1  \t -n\t-c ")]);
        let s = s.unwrap();
        assert!(s.no_name && s.to_stdout && s.level == 1);
        let (s, ..) = run(&["a"], &[("GZIP", "-- -c")]);
        assert_eq!(s.unwrap().files, [&b"-c"[..], b"a"]);
    }

    #[test]
    fn stops_happen_in_order() {
        let (_, code, e) = run(&["-a", "-V", "-x"], &[]);
        assert_eq!(code, 0);
        assert!(e.starts_with("gzip: option --ascii ignored on this system\nApple gzip (stuffr "));
        let long = "abcdefghijklmnopqrstuvwxyzabcde";
        let (_, code, e) = run(&["-q", "-S", long, "-x"], &[]);
        assert_eq!(code, 1);
        assert_eq!(e, format!("gzip: incorrect suffix: '{long}': too long\n"));
        let (s, ..) = run(&["-S", "", "a"], &[]);
        let s = s.unwrap();
        assert!(s.empty_last_suffix && s.suffix == b".gz");
    }
}
