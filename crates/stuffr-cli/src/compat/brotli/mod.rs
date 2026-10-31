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
//! **The promise.** Stdout, stderr and exit codes (0 and 1) are those of
//! brotli 1.2.1 on both build tiers, and the `.br` bytes are identical on
//! the C tier (`brotli-c`, libbrotli 1.2.1 vendored; also in `c-backed`).
//! `-V` prints `brotli 1.2.1`; there is no stuffr banner.
//!
//! Known deviations (the source of truth; the README mirrors it with the
//! same numbers and words):
//!
//! 1. Pure tier: the `.br` bytes are compatible, not identical. brotli 1.2.1
//!    decodes them to the input; the C tier's are the reference's.
//! 2. Pure tier: `-D` is refused in both directions (`-D is not supported
//!    by this build (pure tier); build with --features brotli-c`, exit 1,
//!    once the dictionary file has been read), and so is a one-byte `-C`
//!    comment when compressing (`failed to emit metadata [NAME]`, exit 1;
//!    the pure encoder writes a corrupt stream for it). Every other `-C`
//!    length, and `--large_window`, work.
//! 3. Pure tier: a corrupt stream's `reason:` line can differ. The decoder
//!    cannot tell `-10` (`BLOCK_LENGTH_2`) from `-9` (`BLOCK_LENGTH_1`) and
//!    reports `-9`, and it accepts some streams libbrotli rejects with `-9`.
//!    `-15` is reported as `-14` where the decoder is at a metablock
//!    header.
//! 4. An input that is also the output is refused, where the reference
//!    truncates it, and with `-d` deletes it: `brotli -f -o a a`, a hard
//!    link or a symlink to the input as the output. stuffr prints `input file
//!    [NAME] is the same as the output file` and exits 1 before opening the
//!    output.
//! 5. A later input operand that an earlier output would overwrite is
//!    refused before the output is opened (`brotli -f a a.br`, `-df a.br
//!    a`; `input file [NAME] would be overwritten by the output of
//!    [NAME]`, exit 1), where the reference overwrites that input before
//!    reading it.
//! 6. `-j` removes the source only after the output closed without error;
//!    the reference removes it even when `fclose` failed (ENOSPC, EIO),
//!    leaving a truncated output and no input. stuffr buffers its output
//!    in 64 KiB, the reference in stdio's buffer, so on a full disk the
//!    failure may be reported as `fclose failed [x]` where the reference
//!    says `failed to write output [x]`. The output is removed either way.
//! 7. `brotli - -` (standard input named twice) writes both streams; the
//!    reference closes standard output after the first file and crashes on
//!    the second.
//! 8. `could not read dictionary: out of memory` is never printed. The
//!    dictionary buffer (at most `MAX_DICTIONARY_SIZE`, 50331660 bytes,
//!    about 48 MiB, the reference's own limit) is a plain allocation; when the allocator
//!    cannot give it, Rust aborts the process (SIGABRT, status 134) where
//!    the reference prints that line and exits 1.
//! 9. No signal handler, as the reference: an interrupt leaves the partial
//!    output where it was written (outputs are created directly under their
//!    names, never through a temporary).
//! 10. A closed pipe kills stuffr by SIGPIPE, as it kills brotli under the
//!     default disposition. Where the parent ignores SIGPIPE brotli answers
//!     `failed to write output [NAME]: Broken pipe` and exits 1; stuffr still dies of the
//!     signal, because the Rust runtime ignores SIGPIPE before `main` and
//!     the inherited setting cannot be told apart. A permanent deviation,
//!     as in every family.
//! 11. Hardening (ruling T5 of the 2026-10-31 security audit): `-f` never
//!     writes through a symlink at the output name. The reference opens a
//!     forced output `O_CREAT | O_TRUNC` without `O_EXCL`, so a symlink
//!     there, dangling or not, is followed and the file it names is
//!     created or truncated. stuffr unlinks the link and creates a fresh
//!     file (`O_NOFOLLOW`), its target untouched; without `-f` both refuse
//!     it (`O_EXCL`), as before. The attributes `CopyStat` copies are still
//!     set by name after the close, as the reference sets them, but only
//!     onto the file this run opened (same device and inode, not a
//!     symlink): if the name was swapped meanwhile they are not copied.
//!     Why: a planted link must not redirect a write.
//!
//! `files.rs` is the file handling (`NextFile`, `OpenFiles`, `CloseFiles`,
//! `CopyStat`, `ReadDictionary`), `codec.rs` compression and the
//! decompression loop, decoding (with `-t`, `-K` and the comment check).

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

    /// `main` in a sandbox whose output budget is `budget` bytes.
    fn run_capped(dir: &Path, args: &[&str], budget: u64) -> (i32, String) {
        use std::collections::BTreeMap;
        use std::sync::atomic::AtomicU64;
        use std::sync::{Arc, Mutex};
        let mut host = Host::Sandbox(Sandbox {
            dir: dir.to_path_buf(),
            stdin: Some(Vec::new()),
            stdout: Arc::new(Mutex::new(Vec::new())),
            budget: Arc::new(AtomicU64::new(budget)),
            reads: Arc::new(Mutex::new(BTreeMap::new())),
        });
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let mut err = Vec::new();
        let code = main(b"brotli", &args, &mut host, &mut err);
        (code, String::from_utf8(err).unwrap())
    }

    /// Ruling T4-g: the output fits the buffer, so the full disk shows only
    /// at the close; `-j` must keep the input then (the reference unlinks
    /// it), compressing and decompressing.
    #[test]
    fn rm_keeps_the_input_when_the_close_fails() {
        let s = Scratch::new();
        std::fs::write(s.0.join("a"), b"hello\n").unwrap();
        let (code, err) = run_capped(&s.0, &["-j", "a"], 5);
        assert_eq!(code, 1);
        assert!(err.starts_with("fclose failed [a.br]: "), "{err}");
        assert_eq!(std::fs::read(s.0.join("a")).unwrap(), b"hello\n");
        std::fs::write(s.0.join("b.br"), BR).unwrap();
        let (code, _) = run_capped(&s.0, &["-dj", "b.br"], 3);
        assert_eq!(code, 1);
        assert_eq!(std::fs::read(s.0.join("b.br")).unwrap(), BR);
        // With room, `-j` removes it.
        assert_eq!(run_capped(&s.0, &["-jf", "a"], 1 << 20).0, 0);
        assert!(!s.0.join("a").exists());
    }

    /// Ruling T4-f: an output that is a later input operand is refused.
    #[test]
    fn a_later_input_operand_is_never_overwritten() {
        let s = Scratch::new();
        std::fs::write(s.0.join("a"), b"hello\n").unwrap();
        std::fs::write(s.0.join("a.br"), b"keep").unwrap();
        let (code, _, err) = run_at(&s.0, &["-f", "a", "a.br"], b"");
        assert_eq!(
            (code, err.as_str()),
            (
                1,
                "input file [a.br] would be overwritten by the output of [a]\n"
            )
        );
        assert_eq!(std::fs::read(s.0.join("a.br")).unwrap(), b"keep");
        // An earlier operand is not protected (it has been read), nor is
        // `-` (standard input is no file name).
        let (code, _, _) = run_at(&s.0, &["-f", "a", "-"], b"");
        assert_eq!(code, 0);
    }

    /// `DecompressFile` in the sandbox: a stream, `-K`, the comment check
    /// and the reason lines (the clock is frozen).
    #[test]
    fn decodes_tests_and_checks_comments() {
        let s = Scratch::new();
        let mut two = BR.to_vec();
        two.extend_from_slice(BR);
        std::fs::write(s.0.join("two.br"), &two).unwrap();
        assert_eq!(
            run_at(&s.0, &["-vdcK", "two.br"], b""),
            (
                0,
                b"hello\nhello\n".to_vec(),
                "extra input\nDecompressed [two.br]: 22 B -> 12 B in 0.00 sec\n".into()
            )
        );
        let (code, out, err) = run_at(&s.0, &["-vdc", "two.br"], b"");
        assert_eq!(
            (code, out.as_slice(), err.as_str()),
            (
                1,
                &b"hello\n"[..],
                "corrupt input [two.br]\nreason: extra input\n"
            )
        );
        // Truncation is the end of input inside a stream.
        let (code, _, err) = run_at(&s.0, &["-vt"], &BR[..8]);
        assert_eq!(
            (code, err.as_str()),
            (1, "corrupt input [con]\nreason: truncated input\n")
        );
        // A decoder error, its name without the `_ERROR_` prefix.
        let (code, _, err) = run_at(&s.0, &["-vt"], b"\x1c");
        assert_eq!(
            (code, err.as_str()),
            (1, "corrupt input [con]\nreason: FORMAT_RESERVED (-2)\n")
        );
        // The comment `foo`: right, wrong, and absent (printed, exit 0).
        let foo = b"\x21\x4b\x00foo\x28\x00\x08hello\n\x03";
        assert_eq!(run_at(&s.0, &["-t", "-C", "Zm9v"], foo).0, 0);
        let (code, _, err) = run_at(&s.0, &["-vt", "-C", "Zm9x"], foo);
        assert_eq!(
            (code, err.as_str()),
            (1, "corrupt input [con]\nreason: comment mismatch\n")
        );
        let (code, _, err) = run_at(&s.0, &["-t", "-C", "Zm9v"], BR);
        assert_eq!((code, err.as_str()), (0, "corrupt input [con]\n"));
    }

    /// `-t` writes nothing, but in a sandbox what it decodes counts against
    /// the output budget: a small bomb cannot decode without bound.
    #[test]
    fn test_mode_is_charged_in_the_sandbox() {
        let s = Scratch::new();
        // 2 MiB of zeros, compressed.
        let mut enc = stuffr::brotli_opts::Encoder::new(
            &stuffr::brotli_opts::EncoderParams {
                quality: 5,
                lgwin: 22,
                large_window: false,
                size_hint: None,
            },
            None,
        )
        .unwrap();
        let zeros = vec![0u8; 2 << 20];
        let mut input = &zeros[..];
        let mut buf = vec![0u8; 1 << 16];
        let mut outv = Vec::new();
        while !enc.is_finished() {
            let mut out = &mut buf[..];
            let room = out.len();
            assert!(enc.compress_stream(
                stuffr::brotli_opts::Operation::Finish,
                &mut input,
                &mut out
            ));
            let n = room - out.len();
            outv.extend_from_slice(&buf[..n]);
        }
        std::fs::write(s.0.join("z.br"), &outv).unwrap();
        assert_eq!(run_capped(&s.0, &["-t", "z.br"], 4 << 20).0, 0);
        let (code, err) = run_capped(&s.0, &["-t", "z.br"], 1 << 20);
        assert_eq!(code, 1);
        // `current_output_path` under `-t` is the name compression would
        // give (`NextFile` appends the suffix): never opened, only named.
        assert!(
            err.starts_with("failed to write output [z.br.br]: "),
            "{err}"
        );
        assert!(!s.0.join("z.br.br").exists());
    }
}
