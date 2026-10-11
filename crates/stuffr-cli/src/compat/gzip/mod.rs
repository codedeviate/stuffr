//! The gzip family (`gzip`, `gunzip`, `zcat`, `gzcat`): stuffr behaving as
//! the platform's own gzip.
//!
//! Two personalities share the member layer (`member`) and the format
//! sniffer (`sniff`):
//!
//! - **GNU** (`gnu/`): GNU gzip 1.15, written from its manual, `--help` and
//!   black-box observation of the binary only. GNU gzip is GPLv3 and its
//!   source is never read. Its `gunzip` and `zcat` are shell scripts that
//!   run `gzip -d` and `gzip -dc`, so every message says `gzip:`; `gzcat`
//!   behaves as `zcat`. The module doc of `gnu/mod.rs` lists the behaviours
//!   reproduced and the deviations.
//! - **BSD** (`bsd/`): Apple's gzip 487, ported from `file_cmds`
//!   (BSD-2-Clause, `LICENSE-gzip-bsd`); its compressed bytes are Apple's
//!   on the C tier. The module doc of `bsd/mod.rs` lists the behaviours
//!   reproduced and the deviations.
//!
//! The flavour is [`default_flavour`] unless `STUFFR_GZIP_FLAVOR` says `gnu`
//! or `bsd`; [`run`] reads the variable once, before any argument.
//! Anything else in it is refused, exit 1, in stuffr's own words (neither
//! reference has the variable).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::CountedRun;
use super::host::{Host, SANDBOX_OUTPUT_CAP, Sandbox, reset_sigpipe};

mod bsd;
mod gnu;
// Some of the member layer and the sniffer is used by neither personality
// outside tests: `read_header`, `after_member` and `MemberInfo`'s sizes
// (GNU reads with `read_header_with`; Apple's `gz_uncompress` is a
// byte-at-a-time state machine of its own, `bsd/run/decompress.rs`),
// `ZipEntry::data` and `Detected::Lzh` (GNU's zip and LZH paths).
#[allow(dead_code)]
pub(crate) mod member;
#[allow(dead_code)]
pub(crate) mod sniff;

pub use sniff::Flavour;

/// The environment variable that overrides [`default_flavour`].
const FLAVOR_VAR: &str = "STUFFR_GZIP_FLAVOR";

/// The flavour a build uses when `STUFFR_GZIP_FLAVOR` is unset or empty:
/// BSD on Apple platforms and the BSDs, whose gzip is the FreeBSD/NetBSD
/// one; GNU everywhere else, Windows included.
pub fn default_flavour() -> Flavour {
    if cfg!(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )) {
        Flavour::Bsd
    } else {
        Flavour::Gnu
    }
}

/// The flavour `STUFFR_GZIP_FLAVOR`'s value selects: `gnu` or `bsd`, the
/// default when unset or empty, and `Err(value)` for anything else.
fn flavour_from(value: Option<OsString>) -> Result<Flavour, OsString> {
    match value {
        None => Ok(default_flavour()),
        Some(v) if v.is_empty() => Ok(default_flavour()),
        Some(v) if v == "gnu" => Ok(Flavour::Gnu),
        Some(v) if v == "bsd" => Ok(Flavour::Bsd),
        Some(v) => Err(v),
    }
}

/// Entry point for `gzip`, `gunzip`, `zcat` and `gzcat`; `name` is the
/// canonical invoked name and `args` the arguments after `argv[0]`.
pub fn run(name: &'static str, args: Vec<OsString>) -> ExitCode {
    // gzip dies of SIGPIPE writing to a closed pipe.
    reset_sigpipe();
    let env = |k: &str| std::env::var_os(k);
    let mut err = io::stderr();
    let flavour = match flavour_from(env(FLAVOR_VAR)) {
        Ok(f) => f,
        Err(v) => {
            let _ = writeln!(
                err,
                "{name}: {FLAVOR_VAR} must be gnu or bsd, not '{}'",
                v.to_string_lossy()
            );
            return ExitCode::from(1);
        }
    };
    // GNU's getopt names the program by its full `argv[0]` (only `gzip`
    // itself is ever exec'd under its own name; the scripts exec `gzip`).
    let argv0 = std::env::args_os()
        .next()
        .map(|a| a.as_encoded_bytes().to_vec())
        .unwrap_or_else(|| name.as_bytes().to_vec());
    let code = main(
        flavour,
        name,
        &argv0,
        &args,
        &env,
        &mut Host::Real,
        &mut err,
    );
    ExitCode::from(code)
}

/// The flavour's `main`, below the process boundary.
fn main(
    flavour: Flavour,
    name: &'static str,
    argv0: &[u8],
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: &mut Host,
    err: &mut dyn Write,
) -> u8 {
    match flavour {
        Flavour::Gnu => gnu::main(name, argv0, args, env, host, err),
        Flavour::Bsd => bsd::main(name, args, env, host, err),
    }
}

/// [`run`] without the process, as `flavour`: operands resolve against
/// `dir`, standard input is `stdin` (read as a pipe), standard output and
/// error are captured and returned with the exit code, neither is a
/// terminal, `env` stands in for the environment (`GZIP`,
/// `POSIXLY_CORRECT`; `STUFFR_GZIP_FLAVOR` is not consulted) and `SIGPIPE`
/// is left alone. Standard output and output files share the
/// [`SANDBOX_OUTPUT_CAP`] budget. For the fuzz target; not a stable
/// interface.
#[doc(hidden)]
pub fn run_in(
    flavour: Flavour,
    dir: &Path,
    name: &'static str,
    args: &[OsString],
    stdin: &[u8],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> (i32, Vec<u8>, Vec<u8>) {
    let (code, out, err, _) = run_in_counted(flavour, dir, name, args, stdin, env);
    (code, out, err)
}

/// [`run_in`], also returning what the run opened and read, by path.
#[doc(hidden)]
pub fn run_in_counted(
    flavour: Flavour,
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
        flavour,
        name,
        name.as_bytes(),
        args,
        env,
        &mut host,
        &mut err,
    );
    drop(host);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    let reads = std::mem::take(&mut *reads.lock().unwrap_or_else(|p| p.into_inner()));
    (i32::from(code), out, err, reads)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flavour_variable_selects_or_is_refused() {
        assert_eq!(flavour_from(None), Ok(default_flavour()));
        assert_eq!(flavour_from(Some("".into())), Ok(default_flavour()));
        assert_eq!(flavour_from(Some("gnu".into())), Ok(Flavour::Gnu));
        assert_eq!(flavour_from(Some("bsd".into())), Ok(Flavour::Bsd));
        assert_eq!(flavour_from(Some("GNU".into())), Err("GNU".into()));
        assert_eq!(flavour_from(Some(" gnu".into())), Err(" gnu".into()));
    }

    #[test]
    fn the_default_flavour_follows_the_platform() {
        let bsd = cfg!(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ));
        assert_eq!(
            default_flavour(),
            if bsd { Flavour::Bsd } else { Flavour::Gnu }
        );
    }
}
