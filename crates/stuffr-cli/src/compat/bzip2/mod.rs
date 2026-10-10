//! The `bzip2` / `bunzip2` / `bzcat` family: stuffr behaving as bzip2 1.0.8.
//!
//! Ported from bzip2 1.0.8's `bzip2.c`, copyright (C) 1996-2019 Julian R
//! Seward, under the bzip2 licence reproduced in `LICENSE-bzip2`. Its flag
//! handling, checks, messages and exit codes are followed line by line; the
//! compression itself is stuffr's bzip2 codec, whose output is byte-identical
//! to bzip2's at every level.
//!
//! Known deviations from bzip2 1.0.8:
//!
//! - `--version`/`-V`/`-L`/`--license` name stuffr and its version on the
//!   licence's first line (the rest is verbatim).
//! - Verbosity 2 and above (`-vv`) behaves as `-v`: libbzip2's internal
//!   trace (block CRCs, sorting statistics) is not reachable through stuffr's
//!   codec API, and bzip2.c's own extra blank lines at that level only frame
//!   that trace, so they are left out with it.
//! - Output is written under a temporary name and renamed into place, so an
//!   interrupted run leaves a `.stuffr-bzip2-*.tmp` file where bzip2's signal
//!   handler would have deleted its partial output.
//! - When the parent ignores `SIGPIPE` (`SIG_IGN` inherited across exec),
//!   bzip2 reports a Broken pipe I/O error and exits 1; stuffr dies of
//!   `SIGPIPE`, because the Rust runtime sets `SIG_IGN` before `main` and the
//!   inherited disposition cannot be read on stable Rust.
//! - The `perror` text after a cut-short stream reproduces the `errno` that
//!   bzip2 happens to leave behind as measured on macOS; elsewhere it prints
//!   `strerror(0)`.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use streams::{Host, Sandbox};

mod args;
mod messages;
mod run;
mod streams;

/// Entry point for `bzip2`, `bunzip2` and `bzcat`; `name` is the canonical
/// invoked name and `args` the arguments after `argv[0]`.
pub fn run(name: &'static str, args: Vec<OsString>) -> ExitCode {
    // bzip2 dies of SIGPIPE writing to a closed pipe; Rust ignores the
    // signal by default, so restore its default action, on this path only.
    #[cfg(unix)]
    // SAFETY: setting a signal's disposition to SIG_DFL installs no handler
    // and touches no Rust state; it is done before any other thread or I/O.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let env = |k: &str| std::env::var_os(k);
    ExitCode::from(main(name, &args, &env, &mut Host::Real, &mut io::stderr()))
}

/// bzip2.c's `main` after the program name: the flags, then the run.
fn main(
    name: &'static str,
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: &mut Host,
    err: &mut dyn Write,
) -> u8 {
    match args::parse(name, args, env, err) {
        args::Parsed::Exit(c) => c,
        args::Parsed::Run(s) => run::execute(name, s, host, err),
    }
}

/// The most a [`run_in`] run may write, to standard output and files
/// together. Past it a write fails with `ENOSPC`, which bzip2 reports as an
/// I/O error and exit 1, the code it gives a full disk. A bzip2 stream of a
/// few dozen bytes can expand to tens of MiB, so without a cap a fuzzer's
/// short input could fill memory or disk; 8 MiB is past any block's
/// ordinary output (a 900k block of text) and bounds what a bomb can cost.
const SANDBOX_OUTPUT_CAP: u64 = 8 * 1024 * 1024;

/// [`run`] without the process: operands resolve against `dir`, standard
/// input is `stdin` (read as a pipe), standard output and error are
/// captured and returned with the exit code, neither is a terminal, `$BZIP2`
/// and `$BZIP` are unset, and `SIGPIPE` is left alone. Output is capped at
/// [`SANDBOX_OUTPUT_CAP`]. For the fuzz target; not a stable interface.
#[doc(hidden)]
pub fn run_in(
    dir: &Path,
    name: &'static str,
    args: &[OsString],
    stdin: &[u8],
) -> (i32, Vec<u8>, Vec<u8>) {
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let mut host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(stdin.to_vec()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
    });
    let mut err = Vec::new();
    let code = main(name, args, &|_| None, &mut host, &mut err);
    drop(host);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    (i32::from(code), out, err)
}
