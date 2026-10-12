//! The xz family (`xz`, `unxz`, `xzcat`, `lzma`, `unlzma`, `lzcat`):
//! stuffr behaving as XZ Utils 5.8.4's `xz`.
//!
//! Ported from XZ Utils 5.8.4 `src/xz/` by Lasse Collin and contributors
//! (0BSD; the licence ships as `LICENSE-xz`), one module per C file:
//! `args.rs` (args.c, with the parts of coder.c and util.c the options
//! reach), `options.rs` (options.c, and liblzma's string_conversion.c for
//! `--filters`), `suffix.rs` (suffix.c), `hardware.rs` (hardware.c, with
//! tuklib_physmem/tuklib_cpucores), `message.rs` (message.c, main.c's exit
//! status, tuklib_exit.c) and this module (main.c). Every string is in
//! `messages.rs`.
//!
//! **Names** (R2): all six map to this family, and the mode comes from the
//! invoked name by args.c's substring rule, so `unxz` decompresses,
//! `xzcat` and `lzcat` decompress to standard output, and the `lzma` names
//! use the `.lzma` format.
//!
//! **Hardware** (R3): the real process reads the machine (physical memory,
//! processor threads, resource limits); a sandboxed run ([`run_in_counted`])
//! sees two threads and 4 GiB, so fuzzing is deterministic, and its decoder
//! is limited to 256 MiB (Ruling P7).
//!
//! Known deviations:
//!
//! - `--version`'s first line names stuffr (`xz (stuffr X.Y.Z; XZ Utils
//!   5.8.4 compatible)`); its second line and `--robot --version` are the
//!   reference's, on both tiers.
//! - `--list` arrives with list.c (0.13.0 Task 7); until then every input
//!   is refused there with stuffr's own error, exit 1.
//! - The output is written to a temporary file beside it and published
//!   when complete (`file_io.rs`); an input that is also the output is
//!   never lost, even where xz would lose it (spec deviation 4).
//! - `coder_init`'s header probe is approximated (`coder.rs`): corruption
//!   in the first LZMA2 chunk header, before any output, is said before
//!   the output is opened rather than after.
//! - A parent that ignores SIGPIPE is not seen (the Rust runtime ignores
//!   it before `main`): writing to a closed pipe still kills stuffr, where
//!   xz would say nothing and exit 0.
//! - Pure tier: before a corrupt or cut-short spot, less of the partial
//!   output is written than xz writes (`lzma-rust2` drops what its failing
//!   call had decoded); the messages and exit code are xz's. Near the end
//!   of a raw, `.lzma` or `.lz` stream, corruption can be reported as
//!   truncation (Ruling P6).

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::CountedRun;
use super::host::{Host, SANDBOX_OUTPUT_CAP, Sandbox, reset_sigpipe, strerror};

pub(crate) mod args;
mod coder;
mod file_io;
pub(crate) mod hardware;
pub(crate) mod message;
mod messages;
pub(crate) mod options;
pub(crate) mod suffix;

use args::{Args, OpMode};
use hardware::Hardware;
use message::{Messages, Status, Verbosity, mask_nonprint};

/// Entry point for the six names; `name` is the canonical invoked name,
/// `argv0` the program as invoked (every message's name, as xz's
/// `progname`) and `args` the arguments after it.
pub fn run(name: &'static str, argv0: &OsStr, args: Vec<OsString>) -> ExitCode {
    // xz dies of SIGPIPE writing to a closed pipe (observed: `xz -dc big.xz
    // | head -c1` exits 141 in bash). Before any interrupt cleanup is armed
    // (Ruling P8).
    reset_sigpipe();
    let argv0 = if argv0.is_empty() {
        name.as_bytes()
    } else {
        argv0.as_encoded_bytes()
    };
    let env = |k: &str| std::env::var_os(k);
    let mut err = io::stderr();
    let code = main(
        name,
        argv0,
        &args,
        &env,
        &mut Host::Real,
        Hardware::detect(),
        &mut err,
    );
    ExitCode::from(code)
}

/// [`run`] without the process: operands resolve against `dir`, standard
/// input is `stdin` (a pipe), standard output and error are captured and
/// returned with the exit code, neither is a terminal, `env` stands in for
/// the environment (`XZ_DEFAULTS`, `XZ_OPT`, `POSIXLY_CORRECT`) and
/// `SIGPIPE` is left alone. The machine is R3's fixed two threads and
/// 4 GiB, and the decoder's memory limit is at most 256 MiB whatever the
/// arguments say (Ruling P7: the pure tier zero-fills a dictionary as it
/// allocates it, so a fuzzed header must not reach gigabytes). Standard
/// output and output files share the [`SANDBOX_OUTPUT_CAP`] budget. For
/// the fuzz target; not a stable interface.
#[doc(hidden)]
pub fn run_in_counted(
    dir: &Path,
    name: &'static str,
    args: &[OsString],
    stdin: &[u8],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> CountedRun {
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let mut host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(stdin.to_vec()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
        reads: reads.clone(),
    });
    let mut err = Vec::new();
    let code = main(
        name,
        name.as_bytes(),
        args,
        env,
        &mut host,
        Hardware::SANDBOX,
        &mut err,
    );
    drop(host);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    let reads = std::mem::take(&mut *reads.lock().unwrap_or_else(|p| p.into_inner()));
    (i32::from(code), out, err, reads)
}

/// main.c: main, below the process boundary.
fn main(
    name: &str,
    argv0: &[u8],
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: &mut Host,
    hw: Hardware,
    err: &mut dyn Write,
) -> u8 {
    let mut out = host.out_writer(None);
    let (mut a, mut msg) = match args::parse(name, argv0, env, args, host, hw, &mut out, err) {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    if a.op != OpMode::List && a.robot {
        return msg.fatal(err, messages::ROBOT_CODING, &[]);
    }
    // Refuse to write compressed data to a terminal.
    if a.op == OpMode::Compress
        && (a.to_stdout || a.files == [b"-".to_vec()])
        && is_tty_stdout(host, &mut msg, err)
    {
        msg.try_help(err);
        return Status::Error as u8;
    }
    // signals_init(): the cleanup handlers are installed when an output
    // file is armed (host.rs), the only time they act.
    let names = std::mem::take(&mut a.files);
    for n in &names {
        let mut file = Some(n.as_slice());
        if n == b"-" {
            if a.op == OpMode::Compress {
                if is_tty_stdout(host, &mut msg, err) {
                    continue;
                }
            } else if host.stdin_is_tty() {
                msg.error(err, messages::TTY_STDIN, &[]);
                continue;
            }
            if a.files_from.as_ref().is_some_and(|f| f.name.is_none()) {
                msg.error(err, messages::STDIN_BOTH, &[]);
                continue;
            }
            file = None;
        }
        run_one(&a, file, host, &mut msg, err);
    }
    if let Some(from) = a.files_from.take() {
        let delim = from.delim;
        let display = from.display_name().to_vec();
        let source: Box<dyn Read + '_> = match from.file {
            Some(f) => Box::new(f),
            None => Box::new(host.stdin()),
        };
        let mut reader = BufReader::new(source);
        while let Some(name) = read_name(&mut reader, delim, &display, &mut msg, err) {
            run_one(&a, Some(&name), host, &mut msg, err);
        }
    }
    // list_totals() for --list comes with list.c (Task 7).
    let status = msg.final_status();
    message::exit(
        status,
        &msg.progname,
        &mut out,
        err,
        msg.verbosity != Verbosity::Silent,
    )
}

/// util.c: is_tty_stdout, which reports a terminal as an error.
fn is_tty_stdout(host: &Host, msg: &mut Messages, err: &mut dyn Write) -> bool {
    let tty = host.stdout_is_tty();
    if tty {
        msg.error(err, messages::TTY_STDOUT, &[]);
    }
    tty
}

/// coder.c: coder_run, or list.c: list_file under `--list`, for one input
/// (`None`: standard input). `--list` arrives with list.c (Task 7); until
/// then every input is refused there.
fn run_one(
    a: &Args,
    name: Option<&[u8]>,
    host: &mut Host,
    msg: &mut Messages,
    err: &mut dyn Write,
) {
    if a.op == OpMode::List {
        let shown = mask_nonprint(name.unwrap_or(messages::STDIN_NAME));
        msg.error(err, messages::NOT_YET, &[&shown]);
        return;
    }
    coder::run(a, name, host, msg, err);
}

/// main.c: read_name: the next name from `--files`/`--files0`'s source,
/// skipping empty ones; `None` at the end or after an error (said).
fn read_name(
    r: &mut dyn BufRead,
    delim: u8,
    display: &[u8],
    msg: &mut Messages,
    err: &mut dyn Write,
) -> Option<Vec<u8>> {
    let mut name = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match r.read(&mut byte) {
            Ok(0) => {
                if !name.is_empty() {
                    msg.error(
                        err,
                        messages::NAMES_UNEXPECTED_END,
                        &[&mask_nonprint(display)],
                    );
                }
                return None;
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                msg.error(
                    err,
                    messages::READ_NAMES_FAILED,
                    &[&mask_nonprint(display), &strerror(&e)],
                );
                return None;
            }
        }
        let c = byte[0];
        if c == delim {
            if name.is_empty() {
                continue;
            }
            return Some(name);
        }
        if c == 0 {
            msg.error(err, messages::NAMES_NUL, &[&mask_nonprint(display)]);
            return None;
        }
        name.push(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(data: &[u8], delim: u8) -> (Vec<String>, String, Status) {
        let mut msg = Messages::new(b"xz");
        let mut err = Vec::new();
        let mut r = data;
        let mut got = Vec::new();
        while let Some(n) = read_name(&mut r, delim, b"(stdin)", &mut msg, &mut err) {
            got.push(String::from_utf8(n).unwrap());
        }
        (got, String::from_utf8(err).unwrap(), msg.status)
    }

    #[test]
    fn read_name_splits_and_skips_empty_names() {
        assert_eq!(
            names(b"a\n\nb\n", b'\n'),
            (vec!["a".into(), "b".into()], String::new(), Status::Success)
        );
        assert_eq!(names(b"a\0b\0", 0).0, ["a", "b"]);
        let (got, err, st) = names(b"a\nb", b'\n');
        assert_eq!(got, ["a"]);
        assert_eq!(
            (err.as_str(), st),
            (
                "xz: (stdin): Unexpected end of input when reading filenames\n",
                Status::Error
            )
        );
        let (got, err, _) = names(b"a\0b\n", b'\n');
        assert!(got.is_empty());
        assert!(err.contains("Null character found"), "{err}");
    }

    /// The coder under `Host::Sandbox`: standard input to standard output
    /// and back, a file to its `.xz` (the input removed), a test, and
    /// output past the sandbox's budget failing as a full disk does.
    #[test]
    fn run_in_counted_codes_in_the_sandbox() {
        let dir = std::env::temp_dir().join(format!("stuffr-xz-sandbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let plain = b"sandboxed\n".repeat(100);
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        let (code, packed, err, _) = run_in_counted(&dir, "xz", &args(&["-T1"]), &plain, &|_| None);
        assert_eq!((code, err.as_slice()), (0, &b""[..]));
        assert!(packed.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0]));
        let (code, out, err, _) = run_in_counted(&dir, "xzcat", &[], &packed, &|_| None);
        assert_eq!((code, out, err), (0, plain.clone(), Vec::new()));

        std::fs::write(dir.join("a"), &plain).unwrap();
        let (code, _, err, reads) = run_in_counted(&dir, "xz", &args(&["a"]), b"", &|_| None);
        assert_eq!((code, err), (0, Vec::new()));
        assert!(!dir.join("a").exists());
        assert_eq!(
            reads.get(&dir.join("a")).map(|r| r.bytes),
            Some(plain.len() as u64)
        );
        let (code, out, err, _) =
            run_in_counted(&dir, "xz", &args(&["-t", "a.xz"]), b"", &|_| None);
        assert_eq!((code, out, err), (0, Vec::new(), Vec::new()));
        let (code, _, err, _) = run_in_counted(&dir, "unxz", &args(&["a.xz"]), b"", &|_| None);
        assert_eq!((code, err), (0, Vec::new()));
        assert_eq!(std::fs::read(dir.join("a")).unwrap(), plain);

        // 9 MiB of zeros decode past the 8 MiB budget.
        let zeros = vec![0u8; 9 << 20];
        let (_, bomb, _, _) = run_in_counted(&dir, "xz", &args(&["-T1"]), &zeros, &|_| None);
        let (code, _, err, _) = run_in_counted(&dir, "xzcat", &[], &bomb, &|_| None);
        assert_eq!(code, 1);
        assert!(
            String::from_utf8_lossy(&err).starts_with("xzcat: (stdout): Write error: "),
            "{}",
            String::from_utf8_lossy(&err)
        );
        // A test counts what it decodes against the same budget.
        let (code, _, err, _) = run_in_counted(&dir, "xz", &args(&["-t"]), &bomb, &|_| None);
        assert_eq!(code, 1);
        assert!(
            String::from_utf8_lossy(&err).starts_with("xz: (stdout): Write error: "),
            "{}",
            String::from_utf8_lossy(&err)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_in_counted_parses_in_the_sandbox() {
        let dir = std::env::temp_dir();
        let (code, out, err, reads) = run_in_counted(&dir, "xz", &["-h".into()], b"", &|_| None);
        assert_eq!((code, err.len(), reads.len()), (0, 0, 0));
        assert!(out.starts_with(b"Usage: xz [OPTION]... [FILE]...\n"));
        // R3: the sandbox's machine.
        let (code, out, _, _) = run_in_counted(
            &dir,
            "xz",
            &["--robot".into(), "--info-memory".into()],
            b"",
            &|_| None,
        );
        assert_eq!(code, 0);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "4294967296\t0\t0\t268435456\t1073741824\t2\n"
        );
        let (code, _, err, _) = run_in_counted(&dir, "xz", &["--robot".into()], b"", &|_| None);
        assert_eq!(code, 1);
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "xz: Compression and decompression with --robot are not supported yet.\n"
        );
    }
}
