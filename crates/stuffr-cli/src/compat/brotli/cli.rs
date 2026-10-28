//! The brotli command line: a port of `ParseParams` and `CheckAlias` from
//! `c/tools/brotli.c` of brotli 1.2.1 (MIT), message for message.

use std::ffi::OsString;
use std::io::Write;

use stuffr::brotli_opts::{LARGE_MAX_WINDOW_BITS, MAX_WINDOW_BITS, MIN_WINDOW_BITS};

use super::messages as m;

/// `Command` of `brotli.c`; `Noop` never comes out of parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Compress,
    Decompress,
    Help,
    Invalid,
    TestIntegrity,
    Version,
}

/// `MAX_OPTIONS`: the reference keeps at most this many option indices.
const MAX_OPTIONS: usize = 24;

/// The fields of `Context` that parsing fills.
#[derive(Debug, Clone)]
#[allow(dead_code)] // `large_window` is dead, as in the reference.
pub(crate) struct Params {
    pub command: Command,
    pub quality: u32,
    /// -1 when `-w` was not given.
    pub lgwin: i32,
    pub verbosity: u32,
    pub force_overwrite: bool,
    pub junk_source: bool,
    pub reject_uncompressible: bool,
    pub copy_stat: bool,
    pub write_to_stdout: bool,
    pub test_integrity: bool,
    pub decompress: bool,
    /// Never set by the reference's parser (the field is dead there too);
    /// a window over 24 is what asks for the large-window stream.
    pub large_window: bool,
    pub allow_concatenated: bool,
    pub output_path: Option<OsString>,
    pub suffix: OsString,
    pub dictionary_path: Option<OsString>,
    pub comment: Vec<u8>,
    pub inputs: Vec<OsString>,
}

impl Params {
    fn new() -> Self {
        Params {
            command: Command::Compress,
            quality: 11,
            lgwin: -1,
            verbosity: 0,
            force_overwrite: false,
            junk_source: false,
            reject_uncompressible: false,
            copy_stat: true,
            write_to_stdout: false,
            test_integrity: false,
            decompress: false,
            large_window: false,
            allow_concatenated: false,
            output_path: None,
            suffix: OsString::from(".br"),
            dictionary_path: None,
            comment: Vec::new(),
            inputs: Vec::new(),
        }
    }
}

/// `FileName`: the tail after the last `/` and then the last `\`.
pub(crate) fn file_name(path: &[u8]) -> &[u8] {
    let mut path = path;
    if let Some(i) = path.iter().rposition(|&b| b == b'/') {
        path = &path[i + 1..];
    }
    if let Some(i) = path.iter().rposition(|&b| b == b'\\') {
        path = &path[i + 1..];
    }
    path
}

/// `CheckAlias`: the invoked name is `alias`, or `alias` and a `.`.
fn check_alias(name: &[u8], alias: &[u8]) -> bool {
    let name = file_name(name);
    name.starts_with(alias) && matches!(name.get(alias.len()), None | Some(b'.'))
}

/// `ParseInt`: up to five decimal digits, no leading zero, in `low..=high`.
fn parse_int(s: &[u8], low: i32, high: i32) -> Option<i32> {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut value = 0i32;
    let mut i = 0;
    while i < 5 {
        let c = at(i);
        if c == 0 {
            break;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        value = 10 * value + i32::from(c - b'0');
        i += 1;
    }
    if i == 0 || (i > 1 && s[0] == b'0') || at(i) != 0 || value < low || value > high {
        return None;
    }
    Some(value)
}

/// `ParseBase64`: relaxed base 64 into at most `max` bytes.
fn parse_base64(s: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut bits, mut bit_count, mut padding) = (0u32, 0usize, 0usize);
    for &c in s {
        if matches!(c, 9 | 10 | 13 | b' ') {
            continue;
        }
        if c == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            return None;
        }
        let sextet = match c {
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(sextet);
        bit_count += 6;
        if bit_count >= 8 {
            if out.len() == max {
                return None;
            }
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }
    if padding > 2 {
        return None;
    }
    Some(out)
}

#[cfg(unix)]
pub(super) fn bytes(s: &std::ffi::OsStr) -> &[u8] {
    std::os::unix::ffi::OsStrExt::as_bytes(s)
}

#[cfg(not(unix))]
pub(super) fn bytes(s: &std::ffi::OsStr) -> &[u8] {
    s.as_encoded_bytes()
}

#[cfg(unix)]
pub(super) fn os(b: &[u8]) -> OsString {
    std::os::unix::ffi::OsStringExt::from_vec(b.to_vec())
}

#[cfg(not(unix))]
pub(super) fn os(b: &[u8]) -> OsString {
    String::from_utf8_lossy(b).into_owned().into()
}

/// Write a message and give the `Invalid` outcome.
fn bad(err: &mut dyn Write, msg: impl AsRef<[u8]>) -> Result<Params, Command> {
    let _ = err.write_all(msg.as_ref());
    Err(Command::Invalid)
}

/// What a `--name=value` or `-q value` sets: shared between the short and
/// the long spelling, as the reference duplicates it.
struct Seen {
    command_set: bool,
    quality_set: bool,
    output_set: bool,
    keep_set: bool,
    squash_set: bool,
    lgwin_set: bool,
    suffix_set: bool,
    comment_set: bool,
    concatenated_set: bool,
}

/// `ParseParams`. `Ok` carries the parsed parameters (their `command` is
/// `Compress`, `Decompress` or `TestIntegrity`); `Err` is `Help`, `Version`
/// or `Invalid`, the last after the message (if any) went to `err`.
pub(crate) fn parse(
    argv0: &[u8],
    args: &[OsString],
    err: &mut dyn Write,
) -> Result<Params, Command> {
    let mut p = Params::new();
    let mut s = Seen {
        command_set: false,
        quality_set: false,
        output_set: false,
        keep_set: false,
        squash_set: false,
        lgwin_set: false,
        suffix_set: false,
        comment_set: false,
        concatenated_set: false,
    };
    let mut command = Command::Compress;
    let mut next_option_index = 0usize;
    let mut after_dash_dash = false;

    if check_alias(argv0, b"brcat") {
        s.command_set = true;
        command = Command::Decompress;
        s.concatenated_set = true;
        p.allow_concatenated = true;
        s.output_set = true;
        p.write_to_stdout = true;
    } else if check_alias(argv0, b"unbrotli") {
        s.command_set = true;
        command = Command::Decompress;
    }

    let mut i = 0;
    while i < args.len() {
        let arg = bytes(&args[i]);
        let arg_len = arg.len();
        if arg_len == 0 {
            next_option_index += 1;
            i += 1;
            continue;
        }
        if next_option_index > MAX_OPTIONS - 2 {
            return bad(err, m::TOO_MANY_OPTIONS);
        }
        if after_dash_dash || arg[0] != b'-' || arg_len == 1 {
            p.inputs.push(args[i].clone());
            i += 1;
            continue;
        }
        next_option_index += 1;
        if arg == b"--" {
            after_dash_dash = true;
            i += 1;
            continue;
        }
        if arg[1] != b'-' {
            // Simple and coalesced options.
            for (j, &c) in arg.iter().enumerate().skip(1) {
                match c {
                    b'0'..=b'9' => {
                        if s.quality_set {
                            return bad(err, m::QUALITY_SET);
                        }
                        s.quality_set = true;
                        p.quality = u32::from(c - b'0');
                        continue;
                    }
                    b'c' => {
                        if s.output_set {
                            return bad(err, m::STDOUT_SET);
                        }
                        s.output_set = true;
                        p.write_to_stdout = true;
                        continue;
                    }
                    b'd' => {
                        if s.command_set {
                            return bad(err, m::command_set("-d"));
                        }
                        s.command_set = true;
                        command = Command::Decompress;
                        continue;
                    }
                    b'f' => {
                        if p.force_overwrite {
                            return bad(err, m::FORCE_SET);
                        }
                        p.force_overwrite = true;
                        continue;
                    }
                    b'h' => return Err(Command::Help),
                    b'j' | b'k' => {
                        if s.keep_set {
                            return bad(err, m::KEEP_SET);
                        }
                        s.keep_set = true;
                        p.junk_source = c == b'j';
                        continue;
                    }
                    b'n' => {
                        if !p.copy_stat {
                            return bad(err, m::NO_COPY_STAT_SET);
                        }
                        p.copy_stat = false;
                        continue;
                    }
                    b's' => {
                        if s.squash_set {
                            return bad(err, m::SQUASH_SET);
                        }
                        s.squash_set = true;
                        p.reject_uncompressible = true;
                        continue;
                    }
                    b't' => {
                        if s.command_set {
                            return bad(err, m::command_set("-t"));
                        }
                        s.command_set = true;
                        command = Command::TestIntegrity;
                        continue;
                    }
                    b'v' => {
                        if p.verbosity > 0 {
                            return bad(err, m::VERBOSE_SET);
                        }
                        p.verbosity = 1;
                        continue;
                    }
                    b'K' => {
                        if s.concatenated_set {
                            return bad(err, m::CONCATENATED_SET);
                        }
                        s.concatenated_set = true;
                        p.allow_concatenated = true;
                        continue;
                    }
                    b'V' => return Err(Command::Version),
                    b'Z' => {
                        if s.quality_set {
                            return bad(err, m::QUALITY_SET);
                        }
                        s.quality_set = true;
                        p.quality = 11;
                        continue;
                    }
                    _ => {}
                }
                // o/q/w/C/D/S take a parameter.
                if !matches!(c, b'o' | b'q' | b'w' | b'C' | b'D' | b'S') {
                    return bad(err, m::invalid_argument(c));
                }
                if j + 1 != arg_len {
                    return bad(err, m::expected_parameter(c));
                }
                i += 1;
                let Some(value) = args.get(i).map(|v| bytes(v)).filter(|v| !v.is_empty()) else {
                    return bad(err, m::expected_parameter(c));
                };
                next_option_index += 1;
                match c {
                    b'o' => {
                        if s.output_set {
                            return bad(err, m::STDOUT_SET_O);
                        }
                        p.output_path = Some(args[i].clone());
                    }
                    b'q' => {
                        if s.quality_set {
                            return bad(err, m::QUALITY_SET);
                        }
                        match parse_int(value, MIN_Q, MAX_Q) {
                            Some(q) => p.quality = q as u32,
                            None => return bad(err, m::bad_quality(value)),
                        }
                        s.quality_set = true;
                    }
                    b'w' => {
                        if s.lgwin_set {
                            return bad(err, m::LGWIN_SET);
                        }
                        set_lgwin(&mut p, &mut s, value, MAX_WINDOW_BITS, err)?;
                    }
                    b'C' => {
                        if s.comment_set {
                            return bad(err, m::COMMENT_SET);
                        }
                        let Some(c) = parse_base64(value, m::MAX_COMMENT_LEN) else {
                            return bad(err, m::BAD_COMMENT);
                        };
                        p.comment = c;
                        s.comment_set = true;
                    }
                    b'D' => {
                        if p.dictionary_path.is_some() {
                            return bad(err, m::DICTIONARY_SET);
                        }
                        p.dictionary_path = Some(args[i].clone());
                    }
                    _ => {
                        // b'S'
                        if s.suffix_set {
                            return bad(err, m::SUFFIX_SET);
                        }
                        s.suffix_set = true;
                        p.suffix = args[i].clone();
                    }
                }
            }
        } else {
            // Double dash.
            let arg = &arg[2..];
            match arg {
                b"best" => {
                    if s.quality_set {
                        return bad(err, m::QUALITY_SET);
                    }
                    s.quality_set = true;
                    p.quality = 11;
                }
                b"concatenated" => {
                    if s.concatenated_set {
                        return bad(err, m::CONCATENATED_SET);
                    }
                    s.concatenated_set = true;
                    p.allow_concatenated = true;
                }
                b"decompress" => {
                    if s.command_set {
                        return bad(err, m::command_set("--decompress"));
                    }
                    s.command_set = true;
                    command = Command::Decompress;
                }
                b"force" => {
                    if p.force_overwrite {
                        return bad(err, m::FORCE_SET);
                    }
                    p.force_overwrite = true;
                }
                b"help" => return Err(Command::Help),
                b"keep" | b"rm" => {
                    if s.keep_set {
                        return bad(err, m::KEEP_SET);
                    }
                    s.keep_set = true;
                    p.junk_source = arg == b"rm";
                }
                b"no-copy-stat" => {
                    if !p.copy_stat {
                        return bad(err, m::NO_COPY_STAT_SET);
                    }
                    p.copy_stat = false;
                }
                b"squash" => {
                    if s.squash_set {
                        return bad(err, m::SQUASH_SET);
                    }
                    s.squash_set = true;
                    p.reject_uncompressible = true;
                }
                b"stdout" => {
                    if s.output_set {
                        return bad(err, m::STDOUT_SET);
                    }
                    s.output_set = true;
                    p.write_to_stdout = true;
                }
                b"test" => {
                    if s.command_set {
                        return bad(err, m::command_set("--test"));
                    }
                    s.command_set = true;
                    command = Command::TestIntegrity;
                }
                b"verbose" => {
                    if p.verbosity > 0 {
                        return bad(err, m::VERBOSE_SET);
                    }
                    p.verbosity = 1;
                }
                b"version" => return Err(Command::Version),
                _ => {
                    // key=value
                    let eq = arg.iter().position(|&b| b == b'=');
                    let Some(eq) = eq.filter(|&e| e + 1 < arg.len()) else {
                        return bad(err, m::must_pass_value(arg));
                    };
                    let (key, value) = (&arg[..eq], &arg[eq + 1..]);
                    // strncmp(NAME, arg, key_len) == 0: the key is a prefix
                    // of the name (an empty key matches the first).
                    let is = |name: &[u8]| name.starts_with(key);
                    if is(b"comment") {
                        if s.comment_set {
                            return bad(err, m::COMMENT_SET);
                        }
                        let Some(c) = parse_base64(value, m::MAX_COMMENT_LEN) else {
                            return bad(err, m::BAD_COMMENT);
                        };
                        p.comment = c;
                        s.comment_set = true;
                    } else if is(b"dictionary") {
                        if p.dictionary_path.is_some() {
                            return bad(err, m::DICTIONARY_SET);
                        }
                        p.dictionary_path = Some(os(value));
                    } else if is(b"lgwin") || is(b"large_window") {
                        if s.lgwin_set {
                            return bad(err, m::LGWIN_SET);
                        }
                        let high = if is(b"lgwin") {
                            MAX_WINDOW_BITS
                        } else {
                            LARGE_MAX_WINDOW_BITS
                        };
                        set_lgwin(&mut p, &mut s, value, high, err)?;
                    } else if is(b"output") {
                        if s.output_set {
                            return bad(err, m::STDOUT_SET_OUTPUT);
                        }
                        p.output_path = Some(os(value));
                    } else if is(b"quality") {
                        if s.quality_set {
                            return bad(err, m::QUALITY_SET);
                        }
                        match parse_int(value, MIN_Q, MAX_Q) {
                            Some(q) => p.quality = q as u32,
                            None => return bad(err, m::bad_quality(value)),
                        }
                        s.quality_set = true;
                    } else if is(b"suffix") {
                        if s.suffix_set {
                            return bad(err, m::SUFFIX_SET);
                        }
                        s.suffix_set = true;
                        p.suffix = os(value);
                    } else {
                        return bad(err, m::invalid_parameter(arg));
                    }
                }
            }
        }
        i += 1;
    }

    p.decompress = command == Command::Decompress;
    p.test_integrity = command == Command::TestIntegrity;
    p.command = command;

    let suffix = bytes(&p.suffix);
    if (p.inputs.len() > 1 && s.output_set)
        || (p.test_integrity && (p.output_path.is_some() || p.write_to_stdout))
        || (p.reject_uncompressible && p.write_to_stdout)
        || suffix.iter().any(|&b| b == b'/' || b == b'\\')
        || (!p.decompress && p.allow_concatenated)
        || (p.allow_concatenated && !p.comment.is_empty())
    {
        return Err(Command::Invalid);
    }
    Ok(p)
}

const MIN_Q: i32 = m::MIN_QUALITY as i32;
const MAX_Q: i32 = m::MAX_QUALITY as i32;

/// The `-w`, `--lgwin` and `--large_window` tail: parse, then the minimum.
fn set_lgwin(
    p: &mut Params,
    s: &mut Seen,
    value: &[u8],
    high: u32,
    err: &mut dyn Write,
) -> Result<(), Command> {
    let Some(v) = parse_int(value, 0, high as i32) else {
        let _ = err.write_all(&m::bad_lgwin(value));
        return Err(Command::Invalid);
    };
    s.lgwin_set = true;
    p.lgwin = v;
    if v != 0 && (v as u32) < MIN_WINDOW_BITS {
        let _ = err.write_all(m::lgwin_too_small(v).as_bytes());
        return Err(Command::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(argv0: &str, args: &[&str]) -> (Result<Params, Command>, String) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let mut err = Vec::new();
        let r = parse(argv0.as_bytes(), &args, &mut err);
        (r, String::from_utf8(err).unwrap())
    }

    #[test]
    fn aliases_pick_the_command() {
        let p = run("brcat", &["a.br"]).0.unwrap();
        assert_eq!(p.command, Command::Decompress);
        assert!(p.write_to_stdout && p.allow_concatenated);
        let p = run("/usr/bin/unbrotli", &["a.br"]).0.unwrap();
        assert_eq!(p.command, Command::Decompress);
        assert!(!p.write_to_stdout);
        // `.exe`-style suffixes count, other names do not.
        assert_eq!(run("brcat.1", &[]).0.unwrap().command, Command::Decompress);
        assert_eq!(run("xbrcat", &[]).0.unwrap().command, Command::Compress);
        assert_eq!(run("brcat2", &[]).0.unwrap().command, Command::Compress);
        assert!(run("brcat", &["-c"]).1.contains("already set"));
    }

    #[test]
    fn coalesced_and_long_options() {
        let p = run(
            "brotli",
            &["-9kf", "-w", "12", "--suffix=.x", "a", "--", "-b"],
        )
        .0
        .unwrap();
        assert_eq!((p.quality, p.lgwin, p.junk_source), (9, 12, false));
        assert!(p.force_overwrite);
        assert_eq!(p.suffix, ".x");
        assert_eq!(p.inputs, ["a", "-b"]);
        // A prefix names the first option it prefixes.
        assert_eq!(run("brotli", &["--l=10"]).0.unwrap().lgwin, 10);
        assert_eq!(run("brotli", &["--la=25"]).0.unwrap().lgwin, 25);
        assert_eq!(run("brotli", &["--=Zm9v"]).0.unwrap().comment, b"foo");
    }

    #[test]
    fn help_version_and_invalid() {
        assert_eq!(run("brotli", &["-kh"]).0.unwrap_err(), Command::Help);
        assert_eq!(
            run("brotli", &["--version"]).0.unwrap_err(),
            Command::Version
        );
        let (r, e) = run("brotli", &["-x"]);
        assert_eq!(
            (r.unwrap_err(), e.as_str()),
            (Command::Invalid, "invalid argument -x\n")
        );
        let (r, e) = run("brotli", &["-K"]);
        assert_eq!((r.unwrap_err(), e.as_str()), (Command::Invalid, ""));
    }

    #[test]
    fn numbers_and_comments() {
        assert_eq!(parse_int(b"11", 0, 11), Some(11));
        assert_eq!(parse_int(b"011", 0, 99), None);
        assert_eq!(parse_int(b"123456", 0, 999_999), None);
        assert_eq!(parse_int(b"", 0, 9), None);
        assert_eq!(parse_base64(b"Zm9v=", 80), Some(b"foo".to_vec()));
        assert_eq!(parse_base64(b"Zm9v=x", 80), None);
        assert_eq!(parse_base64(b"====", 80), None);
    }

    /// No argument list panics.
    #[test]
    fn hostile_arguments_do_not_panic() {
        for a in [
            &["-"][..],
            &["--"],
            &["-o"],
            &["--="],
            &["--=="],
            &["-q", "99999999999999999"],
            &["\u{ff}"],
            &["-w", "30"],
            &["--large_window=30"],
        ] {
            let _ = run("brotli", a);
        }
        let _ = run("", &[]);
    }
}
