//! Argument handling, in `main`'s order in bzip2.c: the words of `$BZIP2`,
//! then of `$BZIP`, then argv; the operation mode from the program name;
//! one pass over the short-flag clusters, then one over the long flags.

use std::ffi::OsString;
use std::io::Write;

use super::messages::{self as m, printf};

/// `FILE_NAME_LEN - 10` in bzip2.c: the longest name (and environment word)
/// bzip2 accepts.
pub(super) const MAX_NAME: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OpMode {
    Compress,
    Decompress,
    Test,
}

/// bzip2.c's source modes: stdin to stdout, file to stdout, file to file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SrcMode {
    I2O,
    F2O,
    F2F,
}

#[derive(Debug)]
pub(super) struct Settings {
    pub(super) op: OpMode,
    pub(super) src: SrcMode,
    /// Capped at 4, as bzip2 does.
    pub(super) verbosity: u32,
    pub(super) keep: bool,
    pub(super) small: bool,
    pub(super) force: bool,
    pub(super) noisy: bool,
    /// The compression level, `blockSize100k`.
    pub(super) level: u32,
    /// `longestFileName`, for `pad`.
    pub(super) longest: usize,
    /// The operands, in order.
    pub(super) files: Vec<Vec<u8>>,
}

/// Either settings to run with, or the exit code to stop with (after `-h`,
/// a bad flag, or `-c` with `-t`), the messages already printed.
pub(super) enum Parsed {
    Run(Settings),
    Exit(u8),
}

/// The bytes of an argument. On unix these are exactly argv's bytes.
pub(super) fn os_bytes(s: &OsString) -> Vec<u8> {
    s.as_encoded_bytes().to_vec()
}

/// `addFlagsFromEnvVar`: split on C `isspace`, each word cut to `MAX_NAME`.
fn env_words(value: &[u8], out: &mut Vec<Vec<u8>>) {
    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    for word in value.split(space).filter(|w| !w.is_empty()) {
        out.push(word[..word.len().min(MAX_NAME)].to_vec());
    }
}

/// `main`'s flag handling. `env` looks up an environment variable.
pub(super) fn parse(
    prog: &str,
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    err: &mut dyn Write,
) -> Parsed {
    let mut list: Vec<Vec<u8>> = Vec::new();
    for var in ["BZIP2", "BZIP"] {
        if let Some(v) = env(var) {
            env_words(&os_bytes(&v), &mut list);
        }
    }
    list.extend(args.iter().map(os_bytes));

    // Operands and the longest name.
    let mut files = Vec::new();
    let mut longest = 7;
    let mut decode = true;
    for a in &list {
        if a == b"--" {
            decode = false;
            continue;
        }
        if a.first() == Some(&b'-') && decode {
            continue;
        }
        longest = longest.max(a.len());
        files.push(a.clone());
    }

    let mut s = Settings {
        op: OpMode::Compress,
        src: if files.is_empty() {
            SrcMode::I2O
        } else {
            SrcMode::F2F
        },
        verbosity: 0,
        keep: false,
        small: false,
        force: false,
        noisy: true,
        level: 9,
        longest,
        files,
    };

    // bzip2.c tests `strstr(progName, "unzip")` and `"z2cat"`/`"zcat"`;
    // of the names that reach here, `bunzip2` and `bzcat` match.
    match prog {
        "bunzip2" => s.op = OpMode::Decompress,
        "bzcat" => {
            s.op = OpMode::Decompress;
            s.src = if s.files.is_empty() {
                SrcMode::I2O
            } else {
                SrcMode::F2O
            };
        }
        _ => {}
    }

    let p = prog.as_bytes();
    let usage = |err: &mut dyn Write| printf(err, m::USAGE, &[m::BZLIB_VERSION.as_bytes(), p]);
    let license = |err: &mut dyn Write| {
        let _ = err.write_all(m::LICENSE_FIRST_LINE.as_bytes());
        let _ = err.write_all(m::LICENSE_REST.as_bytes());
    };

    // Short flags, every cluster in order.
    for a in &list {
        if a == b"--" {
            break;
        }
        if a.first() != Some(&b'-') || a.get(1) == Some(&b'-') {
            continue;
        }
        for &c in &a[1..] {
            match c {
                b'c' => s.src = SrcMode::F2O,
                b'd' => s.op = OpMode::Decompress,
                b'z' => s.op = OpMode::Compress,
                b'f' => s.force = true,
                b't' => s.op = OpMode::Test,
                b'k' => s.keep = true,
                b's' => s.small = true,
                b'q' => s.noisy = false,
                b'1'..=b'9' => s.level = u32::from(c - b'0'),
                b'V' | b'L' => license(err),
                b'v' => s.verbosity += 1,
                b'h' => {
                    usage(err);
                    return Parsed::Exit(0);
                }
                _ => {
                    printf(err, m::BAD_FLAG, &[p, a]);
                    usage(err);
                    return Parsed::Exit(1);
                }
            }
        }
    }

    // Long flags.
    for a in &list {
        match a.as_slice() {
            b"--" => break,
            b"--stdout" => s.src = SrcMode::F2O,
            b"--decompress" => s.op = OpMode::Decompress,
            b"--compress" => s.op = OpMode::Compress,
            b"--force" => s.force = true,
            b"--test" => s.op = OpMode::Test,
            b"--keep" => s.keep = true,
            b"--small" => s.small = true,
            b"--quiet" => s.noisy = false,
            b"--version" | b"--license" => license(err),
            // `workFactor = 1`: it changes only how the block sorter
            // reaches its result, never the output.
            b"--exponential" => {}
            b"--repetitive-best" | b"--repetitive-fast" => printf(err, m::REDUNDANT, &[p, a]),
            b"--fast" => s.level = 1,
            b"--best" => s.level = 9,
            b"--verbose" => s.verbosity += 1,
            b"--help" => {
                usage(err);
                return Parsed::Exit(0);
            }
            x if x.starts_with(b"--") => {
                printf(err, m::BAD_FLAG, &[p, a]);
                usage(err);
                return Parsed::Exit(1);
            }
            _ => {}
        }
    }

    s.verbosity = s.verbosity.min(4);
    // bzip2.c: `-s` caps the block size when compressing, so unlike its
    // effect on decompression this one does change the output.
    if s.op == OpMode::Compress && s.small && s.level > 2 {
        s.level = 2;
    }
    if s.op == OpMode::Test && s.src == SrcMode::F2O {
        printf(err, m::C_AND_T, &[p]);
        return Parsed::Exit(1);
    }
    if s.src == SrcMode::F2O && s.files.is_empty() {
        s.src = SrcMode::I2O;
    }
    Parsed::Run(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(prog: &str, args: &[&str], env: &[(&str, &str)]) -> (Option<Settings>, u8, String) {
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
        let mut err = Vec::new();
        match parse(prog, &args, &lookup, &mut err) {
            Parsed::Run(s) => (Some(s), 0, String::from_utf8(err).unwrap()),
            Parsed::Exit(c) => (None, c, String::from_utf8(err).unwrap()),
        }
    }

    #[test]
    fn modes_follow_the_name_then_the_flags() {
        let (s, ..) = run("bzip2", &["a"], &[]);
        let s = s.unwrap();
        assert_eq!((s.op, s.src, s.level), (OpMode::Compress, SrcMode::F2F, 9));
        let s = run("bunzip2", &[], &[]).0.unwrap();
        assert_eq!((s.op, s.src), (OpMode::Decompress, SrcMode::I2O));
        let s = run("bzcat", &["a", "b"], &[]).0.unwrap();
        assert_eq!((s.op, s.src), (OpMode::Decompress, SrcMode::F2O));
        let s = run("bzcat", &["-z", "a"], &[]).0.unwrap();
        assert_eq!((s.op, s.src), (OpMode::Compress, SrcMode::F2O));
    }

    #[test]
    fn clusters_double_dash_and_the_bare_dash() {
        let s = run("bzip2", &["-dkv4", "-", "--", "-x"], &[]).0.unwrap();
        assert_eq!(s.op, OpMode::Decompress);
        assert!(s.keep);
        assert_eq!(s.verbosity, 1);
        assert_eq!(s.files, vec![b"-x".to_vec()]);
    }

    #[test]
    fn small_caps_the_compression_level() {
        assert_eq!(run("bzip2", &["-s9", "a"], &[]).0.unwrap().level, 2);
        assert_eq!(run("bzip2", &["-s1", "a"], &[]).0.unwrap().level, 1);
    }

    #[test]
    fn environment_words_come_first_and_may_be_operands() {
        let s = run("bzip2", &["-1"], &[("BZIP2", " -9\t-v x "), ("BZIP", "-k")])
            .0
            .unwrap();
        assert_eq!(s.level, 1);
        assert!(s.keep);
        assert_eq!(s.verbosity, 1);
        assert_eq!(s.files, vec![b"x".to_vec()]);
    }

    #[test]
    fn help_bad_flags_and_c_with_t_stop() {
        let (s, code, err) = run("bzip2", &["-h"], &[]);
        assert!(s.is_none());
        assert_eq!(code, 0);
        assert!(err.contains("usage: bzip2 [flags"));
        let (_, code, err) = run("bzip2", &["-x"], &[]);
        assert_eq!(code, 1);
        assert!(err.starts_with("bzip2: Bad flag `-x'\n"));
        let (_, code, err) = run("bzip2", &["--nope"], &[]);
        assert_eq!(code, 1);
        assert!(err.starts_with("bzip2: Bad flag `--nope'\n"));
        let (_, code, err) = run("bzcat", &["-t", "a"], &[]);
        assert_eq!(code, 1);
        assert_eq!(
            err,
            "bzip2: -c and -t cannot be used together.\n".replace("bzip2", "bzcat")
        );
    }

    #[test]
    fn verbosity_is_capped_at_four() {
        assert_eq!(run("bzip2", &["-vvvvvvv"], &[]).0.unwrap().verbosity, 4);
    }
}
