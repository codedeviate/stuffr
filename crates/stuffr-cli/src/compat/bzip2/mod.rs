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
use std::io;
use std::process::ExitCode;

use super::Prog;

mod args;
mod messages;
mod run;
mod streams;

/// Entry point for the bzip2 family; `name` is the canonical invoked name and
/// `args` the arguments after `argv[0]`.
pub fn run(name: &'static str, args: Vec<OsString>) -> ExitCode {
    if name == "bzip2recover" {
        Prog { name }.err(format_args!("not yet implemented"));
        return ExitCode::from(3);
    }
    // bzip2 dies of SIGPIPE writing to a closed pipe; Rust ignores the
    // signal by default, so restore its default action, on this path only.
    #[cfg(unix)]
    // SAFETY: setting a signal's disposition to SIG_DFL installs no handler
    // and touches no Rust state; it is done before any other thread or I/O.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let mut err = io::stderr();
    let code = match args::parse(name, &args, &|k| std::env::var_os(k), &mut err) {
        args::Parsed::Exit(c) => c,
        args::Parsed::Run(s) => run::execute(name, s, &mut err),
    };
    ExitCode::from(code)
}
