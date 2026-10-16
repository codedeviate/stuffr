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
//! **Signals** (ruling T2-a): lz4 installs no handler; an interrupt kills
//! the process and leaves the partial output. Nothing is armed here.
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
//!    cores differently.
//! 3. An input that is also the output is never lost.
//! 4. Closed standard streams and a parent that ignores SIGPIPE behave as
//!    in the earlier families.
//! 5. Out of scope and refused: `-b#`, `-e#` and `-i#` print `Benchmark
//!    mode is not available in this build (stuffr)` and exit 1, once the
//!    whole command line has parsed (a usage error, `-h` or `-V` still
//!    answers first). `-h` and `-H` still list them (R8). The hidden `-S`
//!    (a benchmark switch with no effect elsewhere) is accepted and has no
//!    effect, as in lz4.
//! 6. The pure tier (`lz4_flex`): levels 3 to 12, `--best` and
//!    `--favor-decSpeed` compress with its single level; a corrupt frame's
//!    `Error N` text may differ, and output written before it may be a
//!    strict prefix of lz4's.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::CountedRun;
use super::host::{self, Host, SANDBOX_OUTPUT_CAP, Sandbox};

pub(crate) mod cli;
mod messages;

use cli::{Command, Op, Stop};
use messages::{self as m, printf};

/// Entry point for the four names; `name` is the canonical invoked name,
/// `argv0` the program as invoked (its last component is the program name
/// the usage texts print, and picks the presets) and `args` the arguments
/// after it.
pub fn run(name: &'static str, argv0: &OsStr, args: Vec<OsString>) -> ExitCode {
    let argv0 = if argv0.is_empty() {
        name.as_bytes()
    } else {
        argv0.as_encoded_bytes()
    };
    let env = |k: &str| std::env::var_os(k);
    let code = main(argv0, &args, &env, &mut Host::Real, &mut io::stderr());
    // The process's exit status is the code's low byte, as `exit()` makes
    // it.
    ExitCode::from(code as u8)
}

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
    let plan = match cli::plan(cmd, host.stdin_is_tty(), host.stdout_is_tty()) {
        Ok(plan) => plan,
        Err(refusal) => {
            return Stop {
                code: cli::refuse(err, cmd, refusal),
                pause: false,
            };
        }
    };
    let _ = out;
    let (what, task) = match plan.op {
        Op::Compress => ("compress", "Task 4"),
        Op::Decompress => ("decompress", "Task 4"),
        Op::Test => ("test", "Task 4"),
        Op::List => ("--list", "Task 5"),
    };
    Stop {
        code: not_yet(err, what, task),
        pause: cmd.pause,
    }
}

/// An operation a later task of 0.15.0 implements: exit 1, with a note in
/// debug builds only.
fn not_yet(err: &mut dyn Write, what: &str, task: &str) -> i32 {
    #[cfg(debug_assertions)]
    printf(
        err,
        m::TODO_NOT_IMPLEMENTED,
        &[what.as_bytes(), task.as_bytes()],
    );
    let _ = (err, what, task);
    1
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
}
