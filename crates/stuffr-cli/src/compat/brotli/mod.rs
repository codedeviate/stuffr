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
//! `files.rs` is the file handling (`NextFile`, `OpenFiles`, `CloseFiles`,
//! `CopyStat`, `ReadDictionary`), `codec.rs` compression and the
//! decompression loop. Decoding a stream is not here yet (Task 5): a
//! decompression or test that gets that far fails silently, exit 1.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use super::CountedRun;
use super::host::{self, Host, SANDBOX_OUTPUT_CAP, Sandbox};

pub(crate) mod cli;
mod codec;
mod files;
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
        Ok(params) => {
            // `main`: the dictionary first, then the buffers and the files.
            let mut ctx = files::Ctx::new(&params, host, err);
            let mut is_ok = files::read_dictionary(&mut ctx, params.command);
            if is_ok {
                let mut bufs = codec::Buffers::new();
                is_ok = match params.command {
                    Command::Compress => codec::compress_files(&mut ctx, &mut bufs),
                    _ => codec::decompress_files(&mut ctx, &mut bufs),
                };
            }
            if ctx.iterator_error {
                is_ok = false;
            }
            i32::from(!is_ok)
        }
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

    /// A scratch directory `stuffr-brotli-<pid>-<n>`, removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static N: AtomicUsize = AtomicUsize::new(0);
            let d = std::env::temp_dir().join(format!(
                "stuffr-brotli-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Scratch(d)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn run_at(dir: &Path, args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>, String) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let (code, out, err, _) = run_in_counted(dir, "brotli", &args, stdin);
        (code, out, String::from_utf8(err).unwrap())
    }

    /// `brotli -c a` of `hello\n`, as the reference writes it (lgwin 16).
    const BR: &[u8] = b"\x21\x14\x00\x04hello\n\x03";

    #[test]
    fn compresses_a_file_and_standard_input_in_the_sandbox() {
        let s = Scratch::new();
        std::fs::write(s.0.join("a"), b"hello\n").unwrap();
        assert_eq!(run_at(&s.0, &["a"], b""), (0, Vec::new(), String::new()));
        let written = std::fs::read(s.0.join("a.br")).unwrap();
        let (code, out, err) = run_at(&s.0, &["-c"], b"hello\n");
        assert_eq!((code, err.as_str()), (0, ""));
        if cfg!(feature = "brotli-c") {
            assert_eq!(written, BR);
            // Standard input: window 24, so another header.
            assert_ne!(out, BR);
        }
        // `-j` removes the input once its output is complete.
        assert_eq!(run_at(&s.0, &["-jf", "a"], b"").0, 0);
        assert!(!s.0.join("a").exists() && s.0.join("a.br").exists());
    }

    #[test]
    fn an_output_that_is_the_input_is_refused() {
        let s = Scratch::new();
        std::fs::write(s.0.join("a"), b"hello\n").unwrap();
        for args in [&["-f", "-o", "a", "a"][..], &["-df", "-o", "a", "a"]] {
            let (code, out, err) = run_at(&s.0, args, b"");
            assert_eq!(
                (code, out.as_slice(), err.as_str()),
                (
                    1,
                    &b""[..],
                    "input file [a] is the same as the output file\n"
                ),
                "{args:?}"
            );
            assert_eq!(std::fs::read(s.0.join("a")).unwrap(), b"hello\n");
        }
        // Without `-f`: the reference's own refusal.
        let (code, _, err) = run_at(&s.0, &["-o", "a", "a"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "failed to open output file [a]: File exists\n")
        );
    }

    #[test]
    fn names_map_as_next_file_maps_them() {
        let s = Scratch::new();
        std::fs::write(s.0.join("x"), BR).unwrap();
        let (code, _, err) = run_at(&s.0, &["-d", "x"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "empty output file name for [x] input file\n")
        );
        std::fs::write(s.0.join("abcd"), BR).unwrap();
        let (code, _, err) = run_at(&s.0, &["-d", "abcd"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "input file [abcd] suffix mismatch\n")
        );
        let (code, _, err) = run_at(&s.0, &["-S", ".x", "nosuch"], b"");
        assert_eq!(
            (code, err.as_str()),
            (
                1,
                "failed to open input file [nosuch]: No such file or directory\n"
            )
        );
    }

    #[test]
    fn verbose_and_squash_lines() {
        let s = Scratch::new();
        std::fs::write(s.0.join("a"), b"hello\n").unwrap();
        let (code, _, err) = run_at(&s.0, &["-v", "-s", "a"], b"");
        assert_eq!(code, 0);
        // The sandbox's clock is frozen.
        let size = if cfg!(feature = "brotli-c") {
            "11 B"
        } else {
            ""
        };
        assert!(err.starts_with("Compressed [a]: 6 B -> "), "{err}");
        assert!(err.contains(size));
        assert!(
            err.ends_with(" in 0.00 sec\nOutput is larger than input\n"),
            "{err}"
        );
        assert!(!s.0.join("a.br").exists());
    }
}
