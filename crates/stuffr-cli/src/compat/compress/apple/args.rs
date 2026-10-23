//! `main`'s option loop: Apple libc's `getopt(argc, argv, "b:cdfv")` and
//! the `-b` value's `strtol`.
//!
//! getopt (FreeBSD's) does not permute: the first argument that is not an
//! option ends the options, `--` is consumed, and a lone `-` is an operand.
//! An option it does not know, or `-b` without a value, prints its message
//! with the full `argv[0]` and `main` prints the usage of the mode chosen so
//! far (`-d` first makes it `uncompress`'s), exit 1.

use std::ffi::OsString;
use std::io::Write;

use super::messages as m;

/// What `main` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Style {
    Compress,
    Decompress,
}

/// The parsed command line.
#[derive(Debug)]
pub(super) struct Settings {
    pub(super) style: Style,
    /// `-c`.
    pub(super) cat: bool,
    /// `-f`.
    pub(super) force: bool,
    /// `-v`.
    pub(super) verbose: bool,
    /// `-b`'s value as `strtol` gave it, cut to an `int`; 0 when absent.
    pub(super) bits: i32,
    /// The operands, as bytes.
    pub(super) operands: Vec<Vec<u8>>,
}

pub(super) enum Parsed {
    Run(Settings),
    Exit(u8),
}

/// `getopt` and `main`'s switch over it, for the invoked `name`.
pub(super) fn parse(name: &str, argv0: &[u8], args: &[OsString], err: &mut dyn Write) -> Parsed {
    let args: Vec<&[u8]> = args.iter().map(|a| a.as_encoded_bytes()).collect();
    let mut s = Settings {
        style: if name == "uncompress" {
            Style::Decompress
        } else {
            Style::Compress
        },
        cat: false,
        force: false,
        verbose: false,
        bits: 0,
        operands: Vec::new(),
    };
    let usage = |s: &Settings, err: &mut dyn Write| {
        let _ = err.write_all(match s.style {
            Style::Compress => m::USAGE_COMPRESS.as_bytes(),
            Style::Decompress => m::USAGE_UNCOMPRESS.as_bytes(),
        });
        Parsed::Exit(1)
    };
    // `optind` and `place`: the argument being scanned and the byte in it.
    let mut optind = 0;
    let mut place = 0;
    loop {
        if place == 0 {
            let Some(a) = args.get(optind) else { break };
            if a.first() != Some(&b'-') || a.len() == 1 {
                // Not an option, or a lone `-` ("-" is not in the list).
                break;
            }
            if *a == b"--" {
                optind += 1;
                break;
            }
            place = 1;
        }
        let a = args[optind];
        let opt = a[place];
        place += 1;
        let at_end = place >= a.len();
        match opt {
            b'b' => {
                let optarg: &[u8] = if !at_end {
                    &a[place..]
                } else if optind + 1 < args.len() {
                    optind += 1;
                    args[optind]
                } else {
                    m::printf(err, m::OPTION_NEEDS_ARGUMENT, &[argv0, b"b"]);
                    return usage(&s, err);
                };
                optind += 1;
                place = 0;
                let (value, end) = strtol(optarg);
                if end < optarg.len() {
                    m::printf(err, m::PREFIX, &[name.as_bytes()]);
                    m::printf(err, m::ILLEGAL_BIT_COUNT, &[optarg]);
                    let _ = err.write_all(m::NEWLINE.as_bytes());
                    return Parsed::Exit(1);
                }
                // `bits = strtol(...)`: a `long` cut to an `int`.
                s.bits = value as i32;
                continue;
            }
            b'c' => s.cat = true,
            b'd' => s.style = Style::Decompress,
            b'f' => s.force = true,
            b'v' => s.verbose = true,
            other => {
                m::printf(err, m::ILLEGAL_OPTION, &[argv0, &[other]]);
                return usage(&s, err);
            }
        }
        if at_end {
            optind += 1;
            place = 0;
        }
    }
    s.operands = args[optind.min(args.len())..]
        .iter()
        .map(|a| a.to_vec())
        .collect();
    Parsed::Run(s)
}

/// `strtol(s, &end, 10)` on LP64: leading white space, an optional sign,
/// decimal digits; the value saturates at the `long` limits. Returns the
/// value and the offset of `end`, which is 0 when no digit was read.
fn strtol(s: &[u8]) -> (i64, usize) {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        i += 1;
    }
    let negative = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let digits = i;
    // Accumulated negatively, as the C does, so `LONG_MIN` fits.
    let mut acc: i64 = 0;
    let mut overflow = false;
    while let Some(d) = s.get(i).filter(|b| b.is_ascii_digit()) {
        let d = i64::from(d - b'0');
        match acc.checked_mul(10).and_then(|v| v.checked_sub(d)) {
            Some(v) => acc = v,
            None => overflow = true,
        }
        i += 1;
    }
    if i == digits {
        return (0, 0);
    }
    let value = match (overflow, negative) {
        (true, true) => i64::MIN,
        (true, false) => i64::MAX,
        (false, true) => acc,
        (false, false) => acc.checked_neg().unwrap_or(i64::MAX),
    };
    (value, i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> (Option<Settings>, u8, String) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let mut err = Vec::new();
        match parse("compress", b"/bin/compress", &args, &mut err) {
            Parsed::Run(s) => (Some(s), 0, String::from_utf8(err).unwrap()),
            Parsed::Exit(c) => (None, c, String::from_utf8(err).unwrap()),
        }
    }

    #[test]
    fn strtol_reads_as_c_does() {
        assert_eq!(strtol(b"12"), (12, 2));
        assert_eq!(strtol(b" +12"), (12, 4));
        assert_eq!(strtol(b"-1"), (-1, 2));
        assert_eq!(strtol(b"12x"), (12, 2));
        assert_eq!(strtol(b""), (0, 0));
        assert_eq!(strtol(b" "), (0, 0));
        assert_eq!(strtol(b"+"), (0, 0));
        assert_eq!(strtol(b"abc"), (0, 0));
        assert_eq!(strtol(b"99999999999999999999"), (i64::MAX, 20));
        assert_eq!(strtol(b"-99999999999999999999"), (i64::MIN, 21));
        assert_eq!(strtol(b"-9223372036854775808"), (i64::MIN, 20));
        // `int` truncation: 2^32 + 16 is 16.
        assert_eq!(strtol(b"4294967312").0 as i32, 16);
    }

    #[test]
    fn getopt_stops_at_the_first_operand() {
        let (s, _, _) = run(&["-cv", "f", "-d"]);
        let s = s.unwrap();
        assert!(s.cat && s.verbose && s.style == Style::Compress);
        assert_eq!(s.operands, [b"f".to_vec(), b"-d".to_vec()]);
        let (s, _, _) = run(&["--", "-f"]);
        assert_eq!(s.unwrap().operands, [b"-f".to_vec()]);
        let (s, _, _) = run(&["-", "-c"]);
        let s = s.unwrap();
        assert!(!s.cat);
        assert_eq!(s.operands, [b"-".to_vec(), b"-c".to_vec()]);
        let (s, _, _) = run(&["-cb12", "-b", "9"]);
        assert_eq!(s.unwrap().bits, 9);
    }

    #[test]
    fn errors_print_getopt_s_text_then_the_usage() {
        let (_, code, err) = run(&["-dx"]);
        assert_eq!(code, 1);
        assert_eq!(
            err,
            "/bin/compress: illegal option -- x\nusage: uncompress [-cfv] [-b bits] [file ...]\n"
        );
        let (_, code, err) = run(&["-b"]);
        assert_eq!(code, 1);
        assert_eq!(
            err,
            "/bin/compress: option requires an argument -- b\nusage: compress [-cfv] [-b bits] [file ...]\n"
        );
        let (_, code, err) = run(&["-b", "12x"]);
        assert_eq!(
            (code, err.as_str()),
            (1, "compress: illegal bit count -- 12x\n")
        );
    }
}
