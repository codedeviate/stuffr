//! The xz family (`xz`, `unxz`, `xzcat`, `lzma`, `unlzma`, `lzcat`):
//! stuffr behaving as XZ Utils 5.8.4's `xz`.
//!
//! Ported from XZ Utils 5.8.4 `src/xz/` by Lasse Collin and contributors
//! (0BSD; the licence ships as `LICENSE-xz`), one module per C file:
//! `args.rs` (args.c, with the parts of coder.c and util.c the options
//! reach), `options.rs` (options.c, and liblzma's string_conversion.c for
//! `--filters`), `suffix.rs` (suffix.c), `hardware.rs` (hardware.c, with
//! tuklib_physmem/tuklib_cpucores), `message.rs` (message.c, mytime.c,
//! main.c's exit status, tuklib_exit.c; signals.c's handlers are in
//! `compat/host.rs`), `coder.rs` (coder.c), `file_io.rs` (file_io.c),
//! `list.rs` (list.c, util.c's number formatting), `index.rs` (liblzma's
//! file_info.c, index_decoder.c and block_header_decoder.c, in pure Rust
//! so that `--list` is the same on both tiers) and this module (main.c).
//! Every string is in `messages.rs`.
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
//! Known deviations (the source of truth: the README's "The xz family"
//! and the spec mirror this list):
//!
//! - `--version`'s first line names stuffr (`xz (stuffr X.Y.Z; XZ Utils
//!   5.8.4 compatible)`); its second line and `--robot --version` are the
//!   reference's, on both tiers.
//! - The `-v` line's speed and elapsed fields vary from run to run, as they
//!   do between two runs of xz.
//! - The output is written to a temporary file beside it and published
//!   when complete (`file_io.rs`); an input that is also the output is
//!   never lost, even where xz would lose it (spec deviation 4).
//! - The header probe (`coder.rs`): corruption in the first LZMA chunk's
//!   properties byte or its range-coder start (`.xz`), or in the
//!   range-coder start (`.lzma`), is said before the output is opened,
//!   where xz finds it after opening it. Without `-f` the corruption is
//!   reported where xz reports that the output exists. With `-f` an
//!   existing output survives where xz removes it.
//! - Closed standard streams: run with standard input or output closed
//!   (`xz <&-`, or `xz -c a >&-`), xz says "(stdin): Read error: Bad file
//!   descriptor" or "(stdout): Write error: Bad file descriptor" and exits
//!   1; the Rust runtime reopens a closed standard descriptor on
//!   `/dev/null` before `main`, so stuffr reads an empty input (compressing
//!   it and exiting 0, or, decompressing, saying "File format not
//!   recognized"), or writes to nowhere and exits 0.
//! - A parent that ignores SIGPIPE is not seen (the Rust runtime ignores
//!   it before `main`): writing to a closed pipe still kills stuffr, where
//!   xz says nothing and exits 0.
//! - The `-v` indicator's one-second timer is polled against the clock
//!   after each coder call rather than set with `alarm(2)` (message.c's
//!   own way where there is no SIGALRM). The lines and when they appear
//!   are xz's; SIGALRM, SIGINFO (where the system has it) and SIGUSR1
//!   still each ask for a line.
//! - No sandbox: xz's capsicum, pledge and Landlock confinement
//!   (`sandbox.c`) is not ported. xz 5.8.4 on macOS has none either, and
//!   nothing it changes elsewhere is observable.
//! - The memory figures xz prints (`-vv`, `--list`, the memory-limit
//!   messages) and every decision against a limit come from liblzma's
//!   formulas modelled on a configure-built xz 5.8.4 for the host (Ruling
//!   P5), on both tiers.
//! - Pure tier: a stream that declares a dictionary larger than its data
//!   needs commits that memory, where xz only reserves it; `-M` bounds it.
//!   Where the size is declared (`.lzma` with a known size, a `.xz` Block's
//!   uncompressed size) the window is capped at that size. A sandboxed run
//!   caps the decoder at 256 MiB (Ruling P7).
//! - Pure tier: a `.lzma` whose header gives a known size and that also
//!   carries an end-of-payload marker is refused (liblzma accepts it; no xz
//!   encoder writes one).
//! - Pure tier: with threads and a `--block-size` smaller than the
//!   dictionary, the Block boundaries differ from xz's (for a lone LZMA2
//!   chain and no `--block-list`, the threaded encoder's Blocks are at
//!   least the dictionary size).
//! - Pure tier: the `-v` line's compressed size and ratio are those of
//!   the pure encoder's output, which is compatible with xz's, not equal
//!   to it.
//! - Pure tier: output written before a decode error may be a strict
//!   prefix of xz's (Ruling P9: `lzma-rust2` drops what its failing call
//!   had decoded), and `-v`'s figures at that point differ with it; the
//!   messages, exit code and file tree are xz's. Near the end of a raw,
//!   `.lzma` or `.lz` stream, corruption can be reported as truncation
//!   (Ruling P6).

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::CountedRun;
use super::host::{self, Host, SANDBOX_OUTPUT_CAP, Sandbox, reset_sigpipe, strerror};

pub(crate) mod args;
mod coder;
mod file_io;
pub(crate) mod hardware;
mod index;
mod list;
pub(crate) mod message;
mod messages;
pub(crate) mod options;
pub(crate) mod suffix;

use args::{Args, OpMode};
use hardware::Hardware;
use list::ListTotals;
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
/// output and output files share the [`SANDBOX_OUTPUT_CAP`] budget. No
/// signal handler is installed and the progress clock is frozen, so a
/// `-v` line never carries a speed or an elapsed time. For the fuzz
/// target; not a stable interface.
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
    // message_init: the progress signals' handlers (the real process only).
    host::install_progress_signals(host);
    let mut out = host.out_writer(None);
    let (mut a, mut msg) = match args::parse(name, argv0, env, args, host, hw, &mut out, err) {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    // message_init's progress_automatic, and what message.c reads of the
    // options.
    msg.automatic = host.stderr_is_tty();
    msg.robot = a.robot;
    msg.list = a.op == OpMode::List;
    if matches!(host, Host::Sandbox(_)) {
        msg.clock = message::frozen_clock;
    }
    if a.op != OpMode::List && a.robot {
        return msg.fatal(err, messages::ROBOT_CODING, &[]);
    }
    // message_set_files: unknown with --files/--files0.
    msg.files_total = if a.files_from.is_some() {
        0
    } else {
        a.files.len() as u32
    };
    // Refuse to write compressed data to a terminal.
    if a.op == OpMode::Compress
        && (a.to_stdout || a.files == [b"-".to_vec()])
        && is_tty_stdout(host, &mut msg, err)
    {
        msg.try_help(err);
        return Status::Error as u8;
    }
    // signals_init(), not under --list: the SIGTSTP handler now; the
    // cleanup handlers when an output file is armed (host.rs), the only
    // time they act.
    if a.op != OpMode::List {
        host::install_stop_handler(host);
    }
    let names = std::mem::take(&mut a.files);
    let mut totals = ListTotals::default();
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
        if let Err(code) = run_one(&a, file, host, &mut msg, &mut out, err, &mut totals) {
            return code;
        }
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
            if let Err(code) = run_one(&a, Some(&name), host, &mut msg, &mut out, err, &mut totals)
            {
                return code;
            }
        }
    }
    if a.op == OpMode::List {
        list::list_totals(&a, &msg, &totals, &mut out);
    }
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
/// (`None`: standard input). `Err` is the exit code of a run list_file
/// ends (message_fatal).
fn run_one(
    a: &Args,
    name: Option<&[u8]>,
    host: &mut Host,
    msg: &mut Messages,
    out: &mut dyn Write,
    err: &mut dyn Write,
    totals: &mut ListTotals,
) -> Result<(), u8> {
    if a.op == OpMode::List {
        return list::list_file(a, name, host, msg, out, err, totals);
    }
    coder::run(a, name, host, msg, err);
    Ok(())
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

    /// `-v` under `Host::Sandbox`: standard error is no terminal and the
    /// clock is frozen, so each file gets its one line, with no speed or
    /// elapsed time however long the run takes.
    #[test]
    fn run_in_counted_verbose_is_deterministic() {
        let dir = std::env::temp_dir();
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        let plain = vec![b'x'; 300_000];
        let (code, packed, err, _) =
            run_in_counted(&dir, "xz", &args(&["-v", "-T1", "-0"]), &plain, &|_| None);
        assert_eq!(code, 0);
        let ratio = packed.len() as f64 / plain.len() as f64;
        let want = format!("(stdin): {} B / 293.0 KiB = {ratio:.3}\n", packed.len());
        assert_eq!(String::from_utf8(err).unwrap(), want);
        let (code, _, err, _) = run_in_counted(&dir, "xz", &args(&["-tv"]), &packed, &|_| None);
        assert_eq!((code, String::from_utf8(err).unwrap()), (0, want));
    }

    /// `--list` under `Host::Sandbox`: a file is listed and its reads
    /// counted, standard input is refused, and arbitrary bytes end in
    /// xz's own exit codes.
    #[test]
    fn run_in_counted_lists_in_the_sandbox() {
        let dir = std::env::temp_dir().join(format!("stuffr-xz-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        let (_, packed, _, _) = run_in_counted(&dir, "xz", &args(&["-T1"]), b"listed\n", &|_| None);
        std::fs::write(dir.join("a.xz"), &packed).unwrap();
        let (code, out, err, reads) = run_in_counted(
            &dir,
            "xz",
            &args(&["--robot", "-lvv", "a.xz"]),
            b"",
            &|_| None,
        );
        assert_eq!((code, String::from_utf8(err).unwrap()), (0, String::new()));
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("name\ta.xz\nfile\t1\t1\t"), "{out}");
        assert!(
            out.ends_with("\tCRC64\t0\t1\t8454776\tno\t50000002\n"),
            "{out}"
        );
        let read = reads.get(&dir.join("a.xz")).map_or(0, |r| r.bytes);
        assert!(read > 0 && read <= 4 * packed.len() as u64, "read {read}");
        let (code, _, err, _) = run_in_counted(&dir, "xz", &args(&["-l"]), &packed, &|_| None);
        assert_eq!(code, 1);
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "xz: --list does not support reading from standard input\n"
        );
        let short = short_block(4, 5);
        assert_eq!(short.len(), 44);
        for (i, junk) in [
            &b""[..],
            b"\xfd7zXZ\0\0\x01",
            &[0u8; 64],
            &packed[..packed.len() - 4],
            &short,
        ]
        .iter()
        .enumerate()
        {
            let name = format!("j{i}.xz");
            std::fs::write(dir.join(&name), junk).unwrap();
            let (code, _, _, _) =
                run_in_counted(&dir, "xz", &args(&["-lvv", &name]), b"", &|_| None);
            assert_eq!(code, 1, "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A CRC32 of `data`.
    fn crc32(data: &[u8]) -> [u8; 4] {
        let mut c = flate2::Crc::new();
        c.update(data);
        c.sum().to_le_bytes()
    }

    /// A Stream with check `check` of one Block of filler whose Index
    /// record is (`unpadded`, 1000): a Block as short as its Check (or
    /// shorter, or a few bytes longer) for `-vv` to read the header of.
    fn short_block(check: u8, unpadded: u64) -> Vec<u8> {
        let mut s = vec![0xFD, b'7', b'z', b'X', b'Z', 0, 0, check];
        s.extend(crc32(&[0, check]));
        s.extend(std::iter::repeat_n(0x55, ((unpadded + 3) & !3) as usize));
        let mut index = vec![0, 1];
        let mut v = unpadded;
        while v >= 0x80 {
            index.push(v as u8 | 0x80);
            v >>= 7;
        }
        index.extend([v as u8, 0xE8, 0x07]);
        while !index.len().is_multiple_of(4) {
            index.push(0);
        }
        let crc = crc32(&index);
        index.extend(crc);
        s.extend(&index);
        let mut tail = ((index.len() / 4 - 1) as u32).to_le_bytes().to_vec();
        tail.extend([0, check]);
        s.extend(crc32(&tail));
        s.extend(tail);
        s.extend(b"YZ");
        s
    }

    /// list.rs's `-vv` paths (Block Headers, Check values) on hostile
    /// files, not only index.rs's walk: every check ID with Blocks from
    /// shorter than their Check to a little past it, and every byte of a
    /// multi-Block file flipped three ways. Never a panic; only xz's exit
    /// codes.
    #[test]
    fn list_vv_on_hostile_input_never_panics() {
        let dir = std::env::temp_dir().join(format!("stuffr-xz-listvv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        let plain = b"hostile listing\n".repeat(40);
        let (_, packed, _, _) = run_in_counted(
            &dir,
            "xz",
            &args(&["-T1", "-C", "sha256", "--block-size=100"]),
            &plain,
            &|_| None,
        );
        let mut inputs = Vec::new();
        for check in 0..16u8 {
            for unpadded in 5..=72 {
                inputs.push(short_block(check, unpadded));
            }
        }
        for i in 0..packed.len() {
            for mask in [0x01, 0x80, 0xFF] {
                let mut b = packed.clone();
                b[i] ^= mask;
                inputs.push(b);
            }
        }
        for (i, data) in inputs.iter().enumerate() {
            let name = format!("h{i}.xz");
            std::fs::write(dir.join(&name), data).unwrap();
            for form in [&["-lvv"][..], &["--robot", "-lvv"]] {
                let mut a = form.to_vec();
                a.push(&name);
                let (code, _, _, _) = run_in_counted(&dir, "xz", &args(&a), b"", &|_| None);
                assert!(matches!(code, 0 | 1), "{name} {form:?}: exit {code}");
            }
            std::fs::remove_file(dir.join(&name)).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--files=FILE` opens its list through `Host::track`, so the fuzz
    /// target's read bound sees the list as well as the names in it.
    #[test]
    fn files_from_a_file_are_counted() {
        let dir = std::env::temp_dir().join(format!("stuffr-xz-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("list"), b"a\n").unwrap();
        std::fs::write(dir.join("a"), b"listed by name\n").unwrap();
        let args = ["-k".into(), "--files=list".into()];
        let (code, _, err, reads) = run_in_counted(&dir, "xz", &args, b"", &|_| None);
        assert_eq!((code, String::from_utf8(err).unwrap()), (0, String::new()));
        let got = |n: &str| reads.get(&dir.join(n)).copied().unwrap_or_default();
        assert_eq!(
            (got("list").opens, got("list").bytes, got("list").len),
            (1, 2, 2)
        );
        assert_eq!((got("a").opens, got("a").bytes), (1, 15));
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
