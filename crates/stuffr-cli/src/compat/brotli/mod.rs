//! The brotli family (`brotli`, `unbrotli`, `brcat`): stuffr behaving as the
//! brotli 1.2.1 command line tool.
//!
//! A port of `c/tools/brotli.c` of the 1.2.1 tag (MIT; `LICENSE-brotli`)
//! over the doc-hidden `stuffr::brotli_opts` seam. `cli.rs` is
//! `ParseParams`, `messages.rs` holds every string byte for byte. The
//! reference reads no environment variable and installs no signal handler.
//!
//! **Streams** (probed, ruling T1-a): `-h` writes the help text to standard
//! error and exits 0; a usage error writes its message (if any) to standard
//! error, the help text to standard output and exits 1; `-V` writes
//! `brotli 1.2.1` to standard output. Exit codes are 0 and 1 only.
//!
//! Compressing, decompressing and testing are not here yet: they end with
//! exit 1 and no output until the tasks that port them land.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use super::CountedRun;
use super::host::{self, Host, SANDBOX_OUTPUT_CAP, Sandbox};

pub(crate) mod cli;
mod messages;

use cli::Command;

/// Entry point for the three names; `name` is the canonical invoked name,
/// `argv0` the program as invoked (its last component is the name the help
/// text prints) and `args` the arguments after it.
pub fn run(name: &'static str, argv0: &OsStr, args: Vec<OsString>) -> ExitCode {
    host::reset_sigpipe();
    let argv0 = if argv0.is_empty() {
        name.as_bytes()
    } else {
        argv0.as_encoded_bytes()
    };
    let code = main(argv0, &args, &mut Host::Real, &mut std::io::stderr());
    ExitCode::from(code as u8)
}

/// [`run`] without the process: operands resolve against `dir`, standard
/// input is `stdin`, standard output and error are captured and returned
/// with the exit code. For the fuzz target; not a stable interface.
#[doc(hidden)]
pub fn run_in_counted(
    dir: &Path,
    name: &'static str,
    args: &[OsString],
    stdin: &[u8],
) -> CountedRun {
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};

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
    let code = main(name.as_bytes(), args, &mut host, &mut err);
    drop(host);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    let reads = std::mem::take(&mut *reads.lock().unwrap_or_else(|p| p.into_inner()));
    (code, out, err, reads)
}

/// The run below the process boundary. Returns the exit code.
fn main(argv0: &[u8], args: &[OsString], host: &mut Host, err: &mut dyn Write) -> i32 {
    let mut out = host.out_writer(None);
    let name = cli::file_name(argv0);
    let code = match cli::parse(argv0, args, err) {
        Err(Command::Help) => {
            let _ = err.write_all(&messages::help_text(name));
            0
        }
        Err(Command::Version) => {
            let _ = out.write_all(messages::version_line().as_bytes());
            0
        }
        // `Command::Invalid`: the message is out; the help text goes to
        // standard output, the reference's `PrintHelp(name, is_ok)`.
        Err(_) => {
            let _ = out.write_all(&messages::help_text(name));
            1
        }
        // Compress, decompress and test: a later task.
        Ok(_) => 1,
    };
    let _ = out.flush();
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(name: &'static str, args: &[&str]) -> (i32, String, String) {
        let dir = std::env::temp_dir();
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let (code, out, err, _) = run_in_counted(&dir, name, &args, b"");
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn help_goes_to_standard_error_and_usage_errors_to_standard_output() {
        let (code, out, err) = run("brcat", &["-h"]);
        assert_eq!((code, out.as_str()), (0, ""));
        assert!(
            err.starts_with("Usage: brcat [OPTION]... [FILE]...\n"),
            "{err}"
        );
        let (code, out, err) = run("brotli", &["-x"]);
        assert_eq!((code, err.as_str()), (1, "invalid argument -x\n"));
        assert!(out.starts_with("Usage: brotli ["), "{out}");
    }

    #[test]
    fn version_goes_to_standard_output() {
        assert_eq!(
            run("unbrotli", &["-V"]),
            (0, "brotli 1.2.1\n".into(), String::new())
        );
    }
}
