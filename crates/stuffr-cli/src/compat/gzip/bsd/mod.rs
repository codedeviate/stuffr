//! The BSD personality: stuffr behaving as Apple's gzip 487.0.1.
//!
//! **Ported from source.** Apple's gzip is `gzip.c` from Apple's
//! `file_cmds` (tag file_cmds-479), itself FreeBSD's gzip (20190107), which
//! is NetBSD's gzip (20150113) by Matthew R. Green: "GPL free gzip using
//! zlib". It is BSD-licensed (`SPDX-License-Identifier:
//! BSD-2-Clause-NetBSD`, Copyright (c) 1997-2017 Matthew R. Green), and its
//! notice ships with stuffr-cli as `LICENSE-gzip-bsd`, beside the notice of
//! FreeBSD's `unpack.c` (Xin LI), whose pack decoder stuffr also ports.
//! The functions ported are named in each module; where `/usr/bin/gzip`
//! and the source could differ, the binary was run and decided.
//!
//! **Names.** `gzip`, `gunzip`, `zcat` and `gzcat` are one program;
//! `gunzip` decompresses, `zcat` and `gzcat` decompress to standard
//! output, and every message carries the invoked name (`getprogname()`),
//! the usage line too.
//!
//! **Bytes.** On the C tier (`zlib-c`) the deflate stream is C zlib's, at
//! gzip's level with a raw window of 15 bits and `memLevel` 8, as Apple's
//! `deflateInit2` asks, so the output is Apple's byte for byte; elsewhere
//! it is miniz's (valid, and the header through FNAME is Apple's).
//!
//! Behaviours reproduced (each pinned by `tests/compat_gzip_bsd.rs`):
//!
//! - an unknown or malformed option prints the usage text and exits **0**;
//!   so does `-h`; `-V`, `-L` and usage go to standard error;
//! - every warning is exit 1 (never 2), `-q` silences it but not the code;
//!   an existing output declined at the terminal leaves the code alone;
//! - a symbolic link is "not a regular file" unless `-f` or `-c`, which
//!   follow it; `-f` then removes the link and keeps its target;
//! - a hard-linked input says "has 1 other links" (always plural);
//! - the suffix check is case-sensitive, against the whole operand (so
//!   `d/.gz` has the suffix and `.gz` has not), over `.gz .z -gz -z _z
//!   .taz .tgz .bz2 .tbz .tbz2 .Z .xz .lz` and `-S`'s;
//! - set-user-ID inputs are compressed and keep the bit on the output; the
//!   sticky bit is dropped; ACLs, extended attributes and file flags are
//!   copied, the Finder type and creator cleared;
//! - standard input that is not a regular file stores the **current time**
//!   (a regular file its own), and never a name;
//! - no MTIME range check: a time before 1970 is stored wrapped to 32 bits;
//! - `-f` unlinks an existing output, ignoring failure, so a directory
//!   there is then "could not create output: ...: File exists", as is a
//!   dangling symbolic link even without `-f`;
//! - a failed output creation closes standard input, so a later `-` is
//!   "Can't stat stdin: Bad file descriptor" and no question is asked;
//! - the overwrite question reads at most 8 bytes of the answer (`fgets`),
//!   so the rest of a long line answers the next question;
//! - `-r` names children `ROOT/NAME` with the root as given (`d/` gives
//!   `d//x`), in the directory's own order, and skips symbolic links
//!   (the root's too) and non-regular files silently;
//! - the output name is cut to `PATH_MAX - 1` bytes, the suffix kept;
//! - `-v`'s ratio is `print_ratio`'s integer arithmetic (`-99.9%` for an
//!   output more than twice the input).
//!
//! Decompressing (`run/decompress.rs`, Task 10):
//!
//! - gzip, `.Z`, `.bz2`, `.xz`, pack and lzip are read (`file_gettype`;
//!   lzip's first member only), anything else is "not in gzip format" (or
//!   with `-f` copied to standard output, even when the output is a file,
//!   which then has the wrong size and is removed);
//! - a gzip member is read byte by byte as Apple's state machine reads it:
//!   the old `1f 9e` magic in any member, reserved flags ignored, FHCRC
//!   skipped unchecked; any byte other than `1f` after a member, NULs too,
//!   is "trailing garbage ignored", exit 2;
//! - only whole 64 KiB buffers of a member reach the output before a
//!   failure (so nothing of a short one); a CRC error comes after the data
//!   and adds "uncompress failed";
//! - a gzip failure is a warning (exit 1, the output removed, the run goes
//!   on); a failure in `.bz2`, `.xz` or pack data, and a `.bz2` cut short,
//!   ends the run with exit 2 (`maybe_errx`), keeping what was written in
//!   a 0600 output file; `.Z` and lzip failures say "failed infile" or
//!   "uncompress failed";
//! - `-t` writes the decoded data of `.xz`, pack and lzip to standard
//!   output (their decoders do not look at `-t`);
//! - `zcat` (not `gzcat`) adds `.Z` to an operand not ending in it, unless
//!   `-f` or `COMMAND_MODE=legacy`;
//! - a missing operand is retried with `.gz` (or `-S`'s) added, nothing
//!   else;
//! - `-N` reads the stored time at offset 4 and the name at offset 10
//!   whatever FEXTRA says, keeps its last component in the input's
//!   directory, and sets only the seconds of the output's time;
//! - `-l` reads the last eight bytes of a gzip file (so the last member's
//!   size and CRC, and 0 for a pipe), decodes nothing, and refuses every
//!   other format but `.xz`, whose line has no header and no part in the
//!   totals; `-lt` lists, then tests from where the list left the file
//!   (its end), so it always passes;
//! - "File appears to be truncated" (pack) carries whatever `errno` the
//!   last failed call left: `ENOENT` from the output's `stat`, `ENOTTY`
//!   from standard input's `isatty`, 0 otherwise.
//!
//! Known deviations:
//!
//! - `-V` and `-L` name stuffr on their first line (Ruling T9-1).
//! - Output is written under a temporary name and linked into place, so an
//!   interrupted run leaves a `.stuffr-gzip-*.tmp` file where gzip's
//!   `SIGINT` handler removes its partial output. `SIGINFO` (^T) prints no
//!   progress.
//! - Implementer ruling: after a read error part-way through an input (or
//!   a failed trailer write) gzip keeps the cut-short output and removes
//!   the input; stuffr prints the same and exits the same but keeps the
//!   input and removes the output.
//! - When the existing output is the input itself (`gzip -f a.txt` with
//!   `a.txt` a symbolic link to `a.txt.gz`, or a name `PATH_MAX` cuts
//!   back to itself), gzip unlinks it before compressing, so a failure
//!   part-way loses the data. stuffr leaves it in place and replaces it
//!   only with the finished output (Ruling T8-4/T8-5, carried over): the
//!   same messages and exit code, and on failure the input survives.
//! - A write that fails part-way is reported with the bytes stuffr's
//!   buffered writer had passed on, which can differ from what the disk
//!   took.
//! - Run with standard input or output closed (`gzip <&-`, or
//!   `gzip -c a` with standard output closed), gzip says "Can't stat
//!   stdin" or "write: Bad file descriptor"; the Rust runtime reopens a
//!   closed standard descriptor on `/dev/null` before `main`, so stuffr
//!   compresses an empty input, or writes to nowhere, and exits 0.
//! - Implementer ruling: a stored name or `-S ''` naming the input itself
//!   (Rulings T8-4/T8-5, carried over): gzip unlinks the input under `-f`
//!   and decodes from the open file, so a failure loses it; stuffr prints
//!   and exits the same and replaces the input only with a finished output.
//!   A failure that ends the run (exit 2) leaves its partial output, as
//!   gzip does, except over the input itself.
//! - Implementer ruling, undefined behaviour not reproduced: a pack EOB
//!   before the header's length (unpack.c outputs the byte past its
//!   symbol table and goes on) stops with "Premature EOF", exit 2; a pack
//!   header shorter than seven bytes (unpack.c reads bytes it never set)
//!   is "Huffman tree has insane levels", what the binary was seen to say;
//!   `-N` on a 10-byte file (an unset name) restores no name; `-v` on a
//!   piped pack (an uninitialised byte count) counts from 0.
//! - `.Z` from standard input goes through stdio's `stdout` in gzip, so it
//!   reaches the output only at exit, after later operands' output; stuffr
//!   writes it in order. The failed `fflush(stdout)` check at exit is not
//!   made.
//! - Off the C tier (`xz-c`), `.xz` is decoded by stuffr's pure decoder:
//!   the stream header is judged as liblzma judges it, but what a failing
//!   stream outputs first, and whether a failure is "Unexpected end of
//!   input" (taken as: met at the end of the input) or "File is corrupt",
//!   can differ from liblzma's.
//! - A sandboxed run (`run_in`) bounds what a decoder may hold: lzip's
//!   dictionary buffer to the output budget, liblzma to 128 MiB.

use std::ffi::OsString;
use std::io::Write;

use crate::compat::host::Host;

mod args;
mod list;
mod messages;
mod run;
mod unlz;
mod zread;

/// Apple gzip's `main`, for the invoked `name`.
pub(super) fn main(
    name: &'static str,
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: &mut Host,
    err: &mut dyn Write,
) -> u8 {
    let s = match args::parse(name, args, env, err) {
        args::Parsed::Exit(code) => return code,
        args::Parsed::Run(s) => s,
    };
    // `zcat` (not `gzcat`) in Unix 2003 mode, which libc's `compat_mode`
    // takes unless `COMMAND_MODE` is `legacy` in any case.
    let legacy = env("COMMAND_MODE").is_some_and(|v| v.eq_ignore_ascii_case("legacy"));
    run::execute(name, s, name == "zcat" && !legacy, host, err)
}

#[cfg(test)]
mod tests {
    use crate::compat::gzip::{Flavour, run_in};
    use std::ffi::OsString;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("stuffr-bsd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn args(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    /// Random bytes past the sandbox's 8 MiB output budget.
    fn incompressible() -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        (0..9 << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// A write that fails part-way (the sandbox's budget, as a full disk):
    /// to standard output, `gzip: write: ...`, exit 1, and the run goes on;
    /// to a file, gzip's size check then deletes the output and keeps the
    /// input (`file_compress`'s `bad_outfile`).
    #[test]
    fn a_failed_write_is_reported_as_gzip_reports_it() {
        let d = scratch("write");
        std::fs::write(d.join("big"), incompressible()).unwrap();
        std::fs::write(d.join("small"), b"small").unwrap();
        let none = |_: &str| None;
        let (code, out, err) = run_in(
            Flavour::Bsd,
            &d,
            "gzip",
            &args(&["-c", "big", "small"]),
            b"",
            &none,
        );
        let err = String::from_utf8(err).unwrap();
        assert_eq!(code, 1);
        // `small` meets the spent budget too, and says so on its own.
        assert_eq!(err, "gzip: write: No space left on device\n".repeat(2));
        // Whole 64 KiB buffers reached standard output before the failure.
        assert_eq!(out.len() % (64 * 1024), 0, "{}", out.len());
        let (code, _, err) = run_in(Flavour::Bsd, &d, "gzip", &args(&["big"]), b"", &none);
        let err = String::from_utf8(err).unwrap();
        assert_eq!(code, 1);
        let lines: Vec<&str> = err.lines().collect();
        assert_eq!(lines[0], "gzip: write: No space left on device");
        assert!(
            lines[1].starts_with("gzip: output file: big.gz wrong size (")
                && lines[1].ends_with(" != 18446744073709551615), deleting"),
            "{err}"
        );
        assert_eq!(lines[2], "gzip: leaving original big");
        assert!(d.join("big").exists());
        let left: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 2, "{left:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ruling T8-4/T8-5, carried over: when the existing output is the
    /// input itself (`a.txt` a symlink to `a.txt.gz`, `gzip -f a.txt`),
    /// gzip unlinks it before compressing, so a failure part-way loses the
    /// data. stuffr leaves it in place until the new output is complete:
    /// a write failure (the sandbox budget, as a full disk) says what gzip
    /// says and the input survives.
    #[cfg(unix)]
    #[test]
    fn an_output_that_is_the_input_survives_a_failure() {
        let d = scratch("self");
        let data = incompressible();
        std::fs::write(d.join("a.txt.gz"), &data).unwrap();
        std::os::unix::fs::symlink("a.txt.gz", d.join("a.txt")).unwrap();
        let none = |_: &str| None;
        let (code, _, err) = run_in(
            Flavour::Bsd,
            &d,
            "gzip",
            &args(&["-f", "a.txt"]),
            b"",
            &none,
        );
        let err = String::from_utf8(err).unwrap();
        assert_eq!(code, 1);
        assert!(
            err.starts_with("gzip: write: No space left on device\n")
                && err.ends_with("gzip: leaving original a.txt\n"),
            "{err}"
        );
        assert!(
            std::fs::read(d.join("a.txt.gz")).unwrap() == data,
            "the input was lost"
        );
        let left = std::fs::read_dir(&d).unwrap().count();
        assert_eq!(left, 2, "a temporary file was left");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `-t` in the sandbox charges what it decodes to the output budget,
    /// so a small bomb ends with the write error a full disk gives, and
    /// "uncompress failed".
    #[test]
    fn a_test_of_a_bomb_is_bounded() {
        use std::io::Write;
        let d = scratch("bomb");
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&vec![0u8; 20 << 20]).unwrap();
        std::fs::write(d.join("z.gz"), e.finish().unwrap()).unwrap();
        let none = |_: &str| None;
        let (code, out, err) = run_in(Flavour::Bsd, &d, "gzip", &args(&["-t", "z.gz"]), b"", &none);
        assert_eq!(code, 1);
        assert!(out.is_empty());
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "gzip: error writing to output: No space left on device\ngzip: z.gz: uncompress failed\n"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// lzip's dictionary buffer grows with what is decoded; in the sandbox
    /// it stops at the output budget whatever the header claims (here 512
    /// MiB), and the member fails.
    #[test]
    fn an_lzip_dictionary_is_bounded_in_the_sandbox() {
        let d = scratch("lzdict");
        let codec = stuffr::registry()
            .codec(stuffr::FormatId::new("lzip"))
            .unwrap();
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Shared {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = codec
            .encoder(
                Box::new(Shared(buf.clone())),
                &stuffr::EncodeOpts::default(),
            )
            .unwrap();
        sink.write_all(&vec![7u8; 12 << 20]).unwrap();
        sink.finish().unwrap();
        let mut lz = buf.lock().unwrap().clone();
        lz[5] = 29; // a 512 MiB dictionary
        std::fs::write(d.join("z.lz"), lz).unwrap();
        let none = |_: &str| None;
        let (code, out, err) = run_in(
            Flavour::Bsd,
            &d,
            "gzip",
            &args(&["-dc", "z.lz"]),
            b"",
            &none,
        );
        assert_eq!(code, 1);
        assert!(out.is_empty());
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "gzip: z.lz: uncompress failed\n"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Hostile headers and bodies never panic (this runs with overflow
    /// checks, as the fuzz target does): valid lzip, `.Z`, xz, bzip2,
    /// pack and gzip files with random bytes overwritten (the header twice
    /// as often), random truncations, and random header bytes after each
    /// magic, through `-dc`, `-t` and `-l`. Every run ends with one of
    /// Apple's codes. `STUFFR_BSD_SMOKE` raises the 150 rounds per format.
    #[test]
    fn hostile_inputs_never_panic() {
        let rounds: usize = std::env::var("STUFFR_BSD_SMOKE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(150);
        let d = scratch("smoke");
        let plain: Vec<u8> = (0..3000u32)
            .flat_map(|i| format!("{i} smoke ").into_bytes())
            .collect();
        let encode = |id: &'static str| {
            let codec = stuffr::registry().codec(stuffr::FormatId::new(id)).unwrap();
            let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
            impl std::io::Write for Shared {
                fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(b);
                    Ok(b.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut sink = codec
                .encoder(
                    Box::new(Shared(buf.clone())),
                    &stuffr::EncodeOpts::default(),
                )
                .unwrap();
            sink.write_all(&plain).unwrap();
            sink.finish().unwrap();
            buf.lock().unwrap().clone()
        };
        let gz = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&plain).unwrap();
            e.finish().unwrap()
        };
        let samples: Vec<(&str, Vec<u8>)> = vec![
            ("a.lz", encode("lzip")),
            ("a.Z", encode("compress")),
            ("a.xz", encode("xz")),
            ("a.bz2", encode("bzip2")),
            (
                "a.z",
                b"\x1f\x1e\x00\x00\x00\x08\x03\x01\x00\x00AB\x80".to_vec(),
            ),
            ("a.gz", gz),
        ];
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let none = |_: &str| None;
        let mut runs = 0;
        for (name, good) in &samples {
            for round in 0..rounds {
                let mut b = good.clone();
                match round % 3 {
                    // Bytes overwritten, mostly in the header.
                    0 | 1 => {
                        for _ in 0..1 + next() % 4 {
                            let span = if next() % 2 == 0 {
                                b.len().min(24)
                            } else {
                                b.len()
                            };
                            let at = (next() as usize) % span;
                            b[at] = next() as u8;
                        }
                    }
                    // Cut short.
                    _ => b.truncate((next() as usize) % b.len()),
                }
                // Now and then a whole random header after the magic.
                if round % 7 == 0 && b.len() > 12 {
                    for v in &mut b[4..12] {
                        *v = next() as u8;
                    }
                }
                std::fs::write(d.join(name), &b).unwrap();
                for flags in [&["-dc"][..], &["-t"], &["-l"], &["-lt"]] {
                    let mut a = flags.to_vec();
                    a.push(name);
                    let (code, _, _) = run_in(Flavour::Bsd, &d, "gzip", &args(&a), b"", &none);
                    assert!(matches!(code, 0..=2), "{name} {flags:?}: exit {code}");
                    runs += 1;
                }
                let (code, _, _) = run_in(Flavour::Bsd, &d, "gzcat", &[], &b, &none);
                assert!(matches!(code, 0..=2), "stdin {name}: exit {code}");
                runs += 1;
            }
        }
        assert_eq!(runs, samples.len() * rounds * 5);
        let _ = std::fs::remove_dir_all(&d);
    }
}
