//! The compress family (`compress`, `uncompress`): stuffr behaving as the
//! platform's own `.Z` compressor.
//!
//! Two personalities, as the gzip and unzip families have:
//!
//! - **Apple** (`apple/`): Apple's `compress` from `file_cmds-487.0.1`,
//!   ported from its `compress.c` and `zopen.c` (BSD-3-Clause,
//!   `LICENSE-compress-bsd`). The module doc of `apple/mod.rs` lists the
//!   behaviours reproduced and the deviations.
//! - **ncompress** (`ncompress/`): ncompress 5.0 as Ubuntu's `5.0-1`
//!   builds it, on every platform, ported from its `compress.c` (the
//!   Unlicense, `LICENSE-ncompress`). The module doc of `ncompress/mod.rs`
//!   lists the behaviours reproduced and the deviations.
//!
//! The flavour is [`default_flavour`] unless `STUFFR_COMPRESS_FLAVOR` says
//! `apple` or `ncompress`; [`run`] reads the variable once, before any
//! argument. Anything else in it is refused, exit 1, in stuffr's own words
//! (neither reference has the variable). `uncompress` decompresses in both
//! flavours, on every platform (Ubuntu's own `uncompress` is gzip's script,
//! and its ncompress binary decompresses only as `uncompress.real`).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::CountedRun;
use super::host::{Host, SANDBOX_OUTPUT_CAP, Sandbox, reset_sigpipe};

mod apple;
mod flavour;
mod ncompress;

pub(crate) use flavour::flavour_from;
pub use flavour::{Flavour, default_flavour};

/// The environment variable that overrides [`default_flavour`].
const FLAVOR_VAR: &str = "STUFFR_COMPRESS_FLAVOR";

/// Entry point for `compress` and `uncompress`; `name` is the canonical
/// invoked name and `args` the arguments after `argv[0]`.
pub fn run(name: &'static str, args: Vec<OsString>) -> ExitCode {
    // Both references die of SIGPIPE writing to a closed pipe.
    reset_sigpipe();
    let mut err = io::stderr();
    let flavour = match flavour_from(std::env::var_os(FLAVOR_VAR)) {
        Ok(f) => f,
        Err(v) => {
            let _ = writeln!(
                err,
                "{name}: {FLAVOR_VAR} must be apple or ncompress, not '{}'",
                v.to_string_lossy()
            );
            return ExitCode::from(1);
        }
    };
    // getopt names the program by its full `argv[0]`.
    let argv0 = std::env::args_os()
        .next()
        .map(|a| a.as_encoded_bytes().to_vec())
        .unwrap_or_else(|| name.as_bytes().to_vec());
    let code = main(flavour, name, &argv0, &args, &mut Host::Real, &mut err);
    ExitCode::from(code)
}

/// The flavour's `main`, below the process boundary.
fn main(
    flavour: Flavour,
    name: &'static str,
    argv0: &[u8],
    args: &[OsString],
    host: &mut Host,
    err: &mut dyn Write,
) -> u8 {
    match flavour {
        Flavour::Apple => apple::main(name, argv0, args, host, err),
        Flavour::Ncompress => ncompress::main(name, args, host, err),
    }
}

/// [`run`] without the process, as `flavour`: operands resolve against
/// `dir`, standard input is `stdin` (read as a pipe), standard output and
/// error are captured and returned with the exit code and what each input
/// opened read, neither is a terminal, and `SIGPIPE` is left alone.
/// Standard output and output files share the [`SANDBOX_OUTPUT_CAP`]
/// budget. `env` stands in for the environment; neither reference reads a
/// variable, so it is never asked (`STUFFR_COMPRESS_FLAVOR` is not
/// consulted either). For the fuzz target; not a stable interface.
#[doc(hidden)]
pub fn run_in_counted(
    flavour: Flavour,
    dir: &Path,
    name: &'static str,
    args: &[OsString],
    stdin: &[u8],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> CountedRun {
    let _ = env;
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
    let code = main(flavour, name, name.as_bytes(), args, &mut host, &mut err);
    drop(host);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    let reads = std::mem::take(&mut *reads.lock().unwrap_or_else(|p| p.into_inner()));
    (i32::from(code), out, err, reads)
}
