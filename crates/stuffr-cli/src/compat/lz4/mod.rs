//! The lz4 family (`lz4`, `unlz4`, `lz4cat`, `lz4c`): stuffr behaving as
//! the LZ4 command line interface v1.10.0.
//!
//! **A clean-room implementation** (spec decision 3): lz4's `programs/` is
//! GPL-2.0-or-later and was never read. Every rule comes from the man page
//! (`lz4.1`), `NEWS`, `README.md`, `lz4 -h`/`-H` and probes of the 1.10.0
//! binary, and carries its source in a comment; every string is in
//! `messages.rs`. liblz4 itself (BSD-2-Clause, `LICENSE-lz4`) is reached
//! through `stuffr::lz4_opts`. `cli.rs` holds the command line and the
//! decision table for where output goes.
//!
//! **Names** (spec section 1, R12): dispatch registers the four exact
//! names. The presets come from the invoked name's last path component
//! (after `/` or `\`), matched as lz4 1.10.0 matches it, probed through
//! `exec -a`: the name itself, or the name followed by `.` and anything
//! (`unlz4.exe`, `lz4cat.1`), case-sensitively; `unlz4-1`, `xunlz4` and
//! `UNLZ4` match nothing. `unlz4` decompresses; `lz4cat` is `-dcfm` at
//! display level 1; `lz4c` reads the legacy arguments (`-c0`, `-c1`,
//! `-c2`, `-hc`, `-y`) and lists them in its help.
//!
//! **The machine** (R4): the automatic thread count is the logical cores
//! less an eighth, less one (`cli::resolve_threads`); the real process
//! counts its cores (`host::cores`), a sandboxed run
//! ([`run_in_counted`]) sees 8 logical and 4 physical.
//!
//! **Signals** (ruling T2-a): lz4 installs no handler; SIGINT, SIGTERM and
//! SIGHUP kill it and the partial output stays under its name (probed).
//! So nothing is armed here, and outputs are written directly to their
//! names (`io.rs`), never to a temporary file: an interrupt leaves what lz4
//! leaves. `run` restores SIGPIPE's default action, as the earlier families
//! do (deviation 4).
//!
//! **Files** (`io.rs`, `decode.rs`): compression, decompression and test
//! over files and streams, with lz4's order of opening, its overwrite
//! question, `-m`/`-r`, `--rm`, sparse output and its display level 2
//! (ruling P3).
//!
//! Known deviations (the source of truth; the README and the spec mirror
//! this list):
//!
//! 1. The banner names stuffr wherever lz4 prints it (`-V`, the first line
//!    of `-h`/`-H`, `-v`): `*** lz4 v1.10.0 64-bit multithread (stuffr
//!    X.Y.Z), by Yann Collet ***`. The prefix `*** lz4 v1.10.0 ` is
//!    unchanged.
//! 2. Timing and host fields vary, as between two runs of lz4: the `Done
//!    in` line's seconds, speed and cpu load, the progress refreshes, and
//!    the `Using N threads` count where two programs count the host's
//!    cores differently. Refreshes are drawn at most every 200 ms (the
//!    first one always; at display level 4 every chunk), which `display.rs`
//!    pins from recordings (a decode offers one per MiB where lz4 offers
//!    one per 4 MiB chunk); under a sandbox the clock is frozen at zero.
//!    The figures in the `\r` refresh line also differ from lz4's, not
//!    only their timing: for a file under 4 MiB lz4 shows `==> 24.69%`
//!    (the final ratio) where stuffr shows `==> 0.00%`, because the
//!    one-shot frame is not written yet when stuffr draws it; `-l` and
//!    large inputs differ too.
//! 3. An input that is also the output is never lost. Where the output
//!    named is the input file itself (the same device and inode: `lz4 -f a
//!    a`, `lz4 -df s.lz4 s.lz4`, a hard link, standard input redirected
//!    from it), lz4 truncates it before reading it, and the data is gone;
//!    stuffr opens nothing, prints `NAME is the input file; not overwritten
//!    (stuffr)` and counts that input as failed (exit 1, or one more in
//!    `-m`'s count), whatever `-f` says.
//! 4. Closed standard streams and a parent that ignores SIGPIPE behave as
//!    in the earlier families: a closed pipe kills stuffr by SIGPIPE, as it
//!    kills lz4 under the default disposition; where the parent ignores
//!    SIGPIPE, lz4 answers `Error 70` (decoding) or `Error 38` (compressing)
//!    and stuffr still dies of the signal (the Rust runtime ignores SIGPIPE
//!    before `main`, so the inherited disposition cannot be told apart).
//!    A closed standard input or output is reopened on `/dev/null` by the
//!    runtime before `main`, so `lz4 -c <&-` (lz4: `Error 40`) compresses
//!    an empty input.
//! 5. Out of scope and refused: `-b#`, `-e#` and `-i#` print `Benchmark
//!    mode is not available in this build (stuffr)` and exit 1, once the
//!    whole command line has parsed (a usage error, `-h` or `-V` still
//!    answers first). `-h` and `-H` still list them (R8). The hidden `-S`
//!    (a benchmark switch with no effect elsewhere) is accepted and has no
//!    effect, as in lz4.
//! 6. The pure tier (`lz4_flex`): levels 3 to 12, `--best` and
//!    `--favor-decSpeed` compress with its single level; a corrupt frame's
//!    `Error N` text may differ, and output written before it may be a
//!    strict prefix of lz4's. The summary's compressed size and ratio are
//!    those of its own bytes.
//! 7. A decode that fails keeps everything decoded before the fault in its
//!    output (a file or standard output). lz4 writes on another thread and
//!    exits from the failing one, so it leaves nothing or all of that, run
//!    to run (probed: 0 or 8800 bytes of 8800 for the same input).
//! 8. `--list` of a file that ends inside a block-size word: lz4
//!    completes the word from an uninitialised buffer, which only the `-v`
//!    size of that last frame shows. On macOS that is garbage once a frame
//!    or skippable frame came before (probed: the same run to run, about
//!    4.4 million, for a given shape) and zero before; on Linux it is
//!    garbage even in the first frame, different on every run (probed: the
//!    tarball build, `lz4 --list -v` of a header and one byte gave sizes
//!    from 1.0 to 2.1 billion; CI run 39166896170). stuffr completes it from
//!    the frame's previous block-size word, as lz4 does for a second block
//!    (zero for the first).
//! 9. `--list` of a regular file that cannot be opened (mode 000): lz4
//!    aborts on an assertion (exit 134); stuffr names the error
//!    (`NAME: Permission denied`) and exits 1.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::CountedRun;
use super::host::{self, Host, SANDBOX_OUTPUT_CAP, Sandbox};

pub(crate) mod cli;
mod decode;
mod display;
mod io;
mod list;
mod messages;

use cli::{Command, Op, Stop};
use messages::{self as m, printf};

/// Entry point for the four names; `name` is the canonical invoked name,
/// `argv0` the program as invoked (its last component is the program name
/// the usage texts print, and picks the presets) and `args` the arguments
/// after it.
pub fn run(name: &'static str, argv0: &OsStr, args: Vec<OsString>) -> ExitCode {
    // Ruling T3-c, deviation 4: as `gzip::run` and `xz::run`.
    host::reset_sigpipe();
    let argv0 = if argv0.is_empty() {
        name.as_bytes()
    } else {
        argv0.as_encoded_bytes()
    };
    let env = |k: &str| std::env::var_os(k);
    let code = main(argv0, &args, &env, &mut Host::Real, &mut std::io::stderr());
    // The process's exit status is the code's low byte, as `exit()` makes
    // it.
    ExitCode::from(code as u8)
}

/// The exit codes the reference produced over every row of the differential
/// suite and its mutation fuzz: the set the `compat` fuzz target accepts
/// under the lz4 names (with 0 and 1 always allowed there).
///
/// Probed 2026-10-16 over the rows and over ~3000 corruptions and cuts
/// of ten frames (`-t`, `-dc`, `--list`).
///
/// Task 3 added 50: `lz4 -c --rm` on standard input is `Error 50 :
/// Remove error : stdin: No such file or directory` (probed 2026-10-16).
///
/// Task 4 added 69, 72 and 74: `--sparse` decoding into a pipe (`lz4
/// --sparse -dc X | cat`: `Error 69 : Final skip error (sparse file)`,
/// `Error 72 : Sparse skip error(29): Illegal seek ; try --no-sparse`,
/// `Error 74 : Sparse skip error ; try --no-sparse`; probed 2026-10-16,
/// pinned by `sparse_output_matches_the_reference`).
///
/// Task 5 added 71 (and met 72 again): `--list` of a file that is only a
/// frame's magic number is `Error 71 : Error reading NAME`, of one cut
/// inside a header that promises a content size `Error 72 : Error
/// reading NAME` (probed 2026-10-16, pinned by the `--list` rows).
#[doc(hidden)]
pub const EXIT_CODES: [i32; 19] = [
    0, 1, 26, 27, 34, 38, 40, 42, 43, 44, 50, 61, 63, 64, 69, 70, 71, 72, 74,
];

/// [`run`] without the process: operands resolve against `dir`, standard
/// input is `stdin` (a pipe), standard output and error are captured and
/// returned with the exit code, neither is a terminal, `env` stands in for
/// the environment (`LZ4_CLEVEL`, `LZ4_NBWORKERS`) and `SIGPIPE` is left
/// alone. The machine is 8 logical and 4 physical cores (R4).
///
/// R9: nothing needs a cap beyond the shared output budget
/// ([`SANDBOX_OUTPUT_CAP`], standard output and output files together):
/// compression always runs on one thread, a frame's blocks are at most
/// 4 MiB and a legacy block at most 8 MiB by format, and dictionary files
/// are read through [`Host::track`] like every input. No signal handler is
/// installed. For the fuzz target; not a stable interface.
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
    let code = main(name.as_bytes(), args, env, &mut host, &mut err);
    drop(host);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    let reads = std::mem::take(&mut *reads.lock().unwrap_or_else(|p| p.into_inner()));
    (code, out, err, reads)
}

/// The run below the process boundary. Returns the exit code.
fn main(
    argv0: &[u8],
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: &mut Host,
    err: &mut dyn Write,
) -> i32 {
    let program = cli::program_name(argv0);
    let mut out = host.out_writer(None);
    let stop = match cli::parse(program, env, args, host::cores(host), &mut out, err) {
        Ok(cmd) => execute(&cmd, host, &mut out, err),
        Err(stop) => stop,
    };
    let _ = out.flush();
    drop(out);
    if stop.pause {
        // probe: `lz4 -p -V < /dev/null`: the prompt, then a read of
        // standard input.
        printf(err, m::PRESS_ENTER, &[]);
        let mut byte = [0u8; 1];
        let _ = host.stdin().read(&mut byte);
    }
    stop.code
}

/// Everything after a successful parse.
fn execute(cmd: &Command, host: &mut Host, out: &mut dyn Write, err: &mut dyn Write) -> Stop {
    announce(cmd, err);
    let plan = match cli::plan(cmd, host.stdin_is_tty(), host.stdout_is_tty()) {
        Ok(plan) => plan,
        Err(refusal) => {
            return Stop {
                code: cli::refuse(err, cmd, refusal),
                pause: false,
            };
        }
    };
    let ended = match plan.op {
        Op::Compress => io::compress_files(cmd, &plan, host, out, err),
        Op::Decompress | Op::Test => io::decompress_files(cmd, &plan, host, out, err),
        Op::List => list::list_files(cmd, host, out, err),
    };
    Stop {
        code: ended.code,
        pause: ended.pause,
    }
}

/// What lz4 prints once the command line has parsed, before anything else
/// (probe: `lz4 -v -d nosuch`, `lz4 -vv -t a`, `lz4 -vv --list b.lz4`; the
/// same under every operation, and before a refusal or a usage error that
/// the arguments did not raise): the banner at display level 3 and up,
/// and at level 4 and up the two `_POSIX_VERSION` lines, after a
/// `_POSIX_C_SOURCE` line on Linux.
fn announce(cmd: &Command, err: &mut dyn Write) {
    if cmd.display_level >= 3 {
        cli::print_banner(err);
    }
    if cmd.display_level >= 4 {
        // probe: `lz4 -vv -c f` on Linux, glibc and musl (CI run
        // 39166896170; see `m::POSIX_C_SOURCE`); none on macOS.
        #[cfg(target_os = "linux")]
        printf(err, m::POSIX_C_SOURCE, &[]);
        let v = posix_version();
        printf(err, m::POSIX_VERSION, &[v.as_bytes(), v.as_bytes()]);
    }
}

/// `_POSIX_VERSION` as the system says it (200112 on macOS, probed with
/// lz4: `_POSIX_VERSION defined: 200112L`; 200809 on Linux, probed with the
/// tarball build on glibc and musl and on CI run 39166896170);
/// `sysconf(_SC_VERSION)` is the run-time spelling of the same fact.
fn posix_version() -> String {
    #[cfg(unix)]
    {
        // SAFETY: `sysconf` reads no memory of ours and has no
        // preconditions; `_SC_VERSION` is a valid name on every unix.
        let v = unsafe { libc::sysconf(libc::_SC_VERSION) };
        if v > 0 {
            return v.to_string();
        }
    }
    // Where the system cannot say: the value lz4 prints on macOS.
    "200112".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(name: &'static str, args: &[&str], stdin: &[u8]) -> (i32, String, String) {
        let dir = std::env::temp_dir().join(format!("stuffr-lz4-mod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a"), b"hello\n").unwrap();
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let (code, out, err, _) = run_in_counted(&dir, name, &args, stdin, &|_| None);
        let _ = std::fs::remove_dir_all(&dir);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    /// The sandbox runs the parse and the decision table: `-V` reaches its
    /// captured standard output, `-p` reads its standard input, and a
    /// refusal answers before anything is opened.
    #[test]
    fn a_sandboxed_run_parses_and_plans() {
        let banner = format!(
            "*** lz4 v1.10.0 64-bit multithread (stuffr {}), by Yann Collet ***\n",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(run("lz4", &["-V"], b""), (0, banner.clone(), String::new()));
        assert_eq!(
            run("lz4", &["-p", "-V"], b"\n"),
            (0, banner, "Press enter to continue...\n".into())
        );
        let (code, out, err) = run("unlz4", &["a"], b"");
        assert_eq!((code, out.as_str()), (1, ""));
        assert!(
            err.starts_with("Cannot determine an output filename \n"),
            "{err}"
        );
        let (code, _, err) = run("lz4", &["--bogus"], b"");
        assert_eq!(code, 1);
        assert!(err.starts_with("Incorrect parameters\n"), "{err}");
    }

    /// A scratch directory for one sandboxed run, unique in the process.
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new(files: &[(&str, &[u8])]) -> Scratch {
            static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("stuffr-lz4-io-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            for (name, data) in files {
                std::fs::write(dir.join(name), data).unwrap();
            }
            Scratch(dir)
        }
        fn run(&self, name: &'static str, args: &[&str], stdin: &[u8]) -> CountedRun {
            let args: Vec<OsString> = args.iter().map(OsString::from).collect();
            run_in_counted(&self.0, name, &args, stdin, &|_| None)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A sandboxed run compresses into a file, decodes to its captured
    /// standard output, tests, and counts what it read through
    /// `Host::track` (R9).
    #[test]
    fn a_sandboxed_run_compresses_decodes_and_tests() {
        let plain = b"hello hello hello hello\n".repeat(50);
        let d = Scratch::new(&[("a", &plain)]);
        let (code, out, err, reads) = d.run("lz4", &["-q", "a"], b"");
        assert_eq!((code, out.len(), err.len()), (0, 0, 0));
        let read = reads.get(&d.0.join("a")).copied().unwrap_or_default();
        assert_eq!((read.opens, read.bytes), (1, plain.len() as u64));
        let (code, out, err, _) = d.run("lz4cat", &["a.lz4"], b"");
        assert_eq!((code, out, err.len()), (0, plain.clone(), 0));
        let (code, _, err, _) = d.run("lz4", &["-t", "a.lz4"], b"");
        assert_eq!(code, 0);
        let err = String::from_utf8(err).unwrap();
        let summary = format!("a.lz4{}: decoded 1200 bytes \n", " ".repeat(26));
        assert!(err.ends_with(&summary), "{err:?}");
    }

    /// R11 in the sandbox: the overwrite question reads the run's standard
    /// input, and the data after the answer is the input compressed.
    #[test]
    fn the_overwrite_question_reads_standard_input() {
        let d = Scratch::new(&[("e", b"old")]);
        let (code, _, err, _) = d.run("lz4", &["-", "e"], b"y\nhello");
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        let (code, out, _, _) = d.run("lz4", &["-dc", "e"], b"");
        assert_eq!((code, out.as_slice()), (0, &b"hello"[..]));
        let (code, _, err, _) = d.run("lz4", &["-", "e"], b"n\nhello");
        assert_eq!(code, 1);
        let refused = format!("?{}not overwritten  \n", " ".repeat(5));
        assert!(String::from_utf8(err).unwrap().ends_with(&refused));
    }

    /// `--sparse` to standard output: a sandbox's is a pipe, which refuses
    /// the first seek, as lz4's does (`Error 72` for data, `Error 69` for
    /// an output of zeros only).
    #[test]
    fn sparse_standard_output_is_a_pipe_in_the_sandbox() {
        let d = Scratch::new(&[("a", b"AAAAAAAA"), ("z", &[0u8; 100])]);
        assert_eq!(d.run("lz4", &["-q", "-m", "a", "z"], b"").0, 0);
        let (code, out, err, _) = d.run("lz4", &["--sparse", "-dc", "z.lz4"], b"");
        assert_eq!((code, out.len()), (69, 0));
        assert_eq!(err, b"Error 69 : Final skip error (sparse file)\n \n");
        let (code, out, err, _) = d.run("lz4", &["--sparse", "-dc", "a.lz4"], b"");
        assert_eq!((code, out.len()), (72, 0));
        let err = String::from_utf8(err).unwrap();
        assert!(err.starts_with("Error 72 : Sparse skip error("), "{err:?}");
        assert!(err.ends_with(" ; try --no-sparse \n"), "{err:?}");
        // Without `--sparse`, standard output is written plainly.
        let (code, out, _, _) = d.run("lz4", &["-dc", "a.lz4"], b"");
        assert_eq!((code, out.as_slice()), (0, &b"AAAAAAAA"[..]));
    }

    /// Spec deviation 3 in the sandbox: an output that is the input is
    /// refused and the input kept.
    #[test]
    fn an_output_that_is_the_input_is_refused() {
        let d = Scratch::new(&[("a", b"keep me")]);
        let (code, _, err, _) = d.run("lz4", &["-f", "a", "a"], b"");
        assert_eq!(code, 1);
        assert_eq!(err, b"a is the input file; not overwritten (stuffr)  \n");
        assert_eq!(std::fs::read(d.0.join("a")).unwrap(), b"keep me");
    }
}
