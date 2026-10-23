//! `main`'s option loop, from ncompress 5.0's `compress.c` (the Unlicense,
//! `LICENSE-ncompress`): not getopt but a hand-rolled walk over `argv`.
//!
//! Every argument is looked at: `--` (each one) is dropped and ends the
//! options for good; before that, an argument starting with `-` is a
//! cluster of flags, each byte after the dash one flag (so a lone `-` is
//! nothing at all); anything else is an operand, wherever it is. `-b` takes
//! the rest of its cluster, or the next argument whatever it is, through
//! `atoi`; the value is clamped to 9..=16 once the walk is over. `-V` and
//! `-h` print and exit as soon as they are met; an unknown flag ends the
//! walk with its message and the usage.

use std::ffi::OsString;

/// `BITS`: the most bits a code may have, and `-b`'s default.
const BITS: i32 = 16;
/// `INIT_BITS`: the fewest `-b` gives.
const INIT_BITS: i32 = 9;

/// The parsed command line: `main`'s globals.
#[derive(Debug)]
pub(super) struct Settings {
    /// `do_decomp`: `uncompress`, or `-d`.
    pub(super) decomp: bool,
    /// `quiet`: no `-v` (`-q` and `-s` set it again).
    pub(super) quiet: bool,
    /// `force`: `-f` or `-F`.
    pub(super) force: bool,
    /// `keep`: `-k`.
    pub(super) keep: bool,
    /// `zcat_flg`: `-c`.
    pub(super) zcat: bool,
    /// `recursive`: `-r` or `-R`.
    pub(super) recursive: bool,
    /// `maxbits`, clamped to 9..=16.
    pub(super) maxbits: i32,
    /// The operands, in order.
    pub(super) files: Vec<Vec<u8>>,
}

/// What the walk ended in.
#[derive(Debug)]
pub(super) enum Parsed {
    Run(Settings),
    /// `-V`: `about()`, exit 0.
    Version,
    /// `-h`: `Usage(0)`.
    Help,
    /// A flag not in the switch: `Unknown flag: '%c'; ` and `Usage(1)`.
    Unknown(u8),
    /// `-b` with nothing after it: `Missing maxbits` and `Usage(1)`.
    MissingMaxbits,
}

/// The walk, for the invoked `name` (`uncompress` decompresses).
pub(super) fn parse(name: &str, args: &[OsString]) -> Parsed {
    let args: Vec<&[u8]> = args.iter().map(|a| a.as_encoded_bytes()).collect();
    let mut s = Settings {
        decomp: name == "uncompress",
        quiet: true,
        force: false,
        keep: false,
        zcat: false,
        recursive: false,
        maxbits: BITS,
        files: Vec::new(),
    };
    let mut seen_double_dash = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if a == b"--" {
            seen_double_dash = true;
        } else if !seen_double_dash && a.first() == Some(&b'-') {
            let mut k = 1;
            while k < a.len() {
                match a[k] {
                    b'V' => return Parsed::Version,
                    // `silent` is set too, and never read.
                    b's' | b'q' => s.quiet = true,
                    b'v' => s.quiet = false,
                    b'd' => s.decomp = true,
                    b'k' => s.keep = true,
                    b'f' | b'F' => s.force = true,
                    // `nomagic`, which nothing reads in 5.0.
                    b'n' => {}
                    b'b' => {
                        // ARGVAL(): the rest of the cluster, or the next
                        // argument.
                        let value = if k + 1 < a.len() {
                            &a[k + 1..]
                        } else if i + 1 < args.len() {
                            i += 1;
                            args[i]
                        } else {
                            return Parsed::MissingMaxbits;
                        };
                        s.maxbits = atoi(value);
                        break;
                    }
                    b'c' => s.zcat = true,
                    b'r' | b'R' => s.recursive = true,
                    b'h' => return Parsed::Help,
                    other => return Parsed::Unknown(other),
                }
                k += 1;
            }
        } else {
            s.files.push(a.to_vec());
        }
        i += 1;
    }
    s.maxbits = s.maxbits.clamp(INIT_BITS, BITS);
    Parsed::Run(s)
}

/// glibc's `atoi`: `(int)strtol(s, NULL, 10)` on LP64, trailing junk
/// ignored, no digits 0.
fn atoi(s: &[u8]) -> i32 {
    super::super::apple::args::strtol(s).0 as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(name: &str, args: &[&str]) -> Parsed {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        parse(name, &args)
    }

    fn settings(name: &str, args: &[&str]) -> Settings {
        match run(name, args) {
            Parsed::Run(s) => s,
            other => panic!("{args:?}: {other:?}"),
        }
    }

    #[test]
    fn flags_go_anywhere_and_double_dash_ends_them() {
        let s = settings("compress", &["f", "-c", "--", "-d", "--", "g"]);
        assert!(s.zcat && !s.decomp);
        assert_eq!(s.files, [b"f".to_vec(), b"-d".to_vec(), b"g".to_vec()]);
        // A lone `-` is no flag and no operand.
        let s = settings("compress", &["-"]);
        assert!(s.files.is_empty());
        let s = settings("uncompress", &["-vq"]);
        assert!(s.decomp && s.quiet);
        let s = settings("compress", &["-qv"]);
        assert!(!s.quiet);
    }

    #[test]
    fn maxbits_is_atoi_then_clamped() {
        for (args, want) in [
            (&["-b", "12"][..], 12),
            (&["-b12x"], 12),
            (&["-b", " +12"], 12),
            (&["-b", "-1"], 9),
            (&["-b", ""], 9),
            (&["-b", "abc"], 9),
            (&["-b", "17"], 16),
            (&["-bv"], 9),
            (&["-b", "-v"], 9),
            (&["-b", "4294967308"], 12),
            (&["-b", "99999999999999999999"], 9),
            (&["-b", "9", "-b", "12"], 12),
            (&[], 16),
        ] {
            assert_eq!(settings("compress", args).maxbits, want, "{args:?}");
        }
        // The value is taken whatever it is: `-b -v` sets no flag.
        assert!(settings("compress", &["-b", "-v"]).quiet);
        assert!(matches!(run("compress", &["-b"]), Parsed::MissingMaxbits));
        assert!(matches!(
            run("compress", &["f", "-b"]),
            Parsed::MissingMaxbits
        ));
    }

    #[test]
    fn version_help_and_unknown_end_the_walk_where_met() {
        assert!(matches!(run("compress", &["-Vx"]), Parsed::Version));
        assert!(matches!(run("compress", &["-xV"]), Parsed::Unknown(b'x')));
        assert!(matches!(run("compress", &["-hx"]), Parsed::Help));
        assert!(matches!(
            run("compress", &["--help"]),
            Parsed::Unknown(b'-')
        ));
        assert!(matches!(run("compress", &["-C"]), Parsed::Unknown(b'C')));
    }
}
