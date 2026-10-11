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
//! - A write that fails part-way is reported with the bytes stuffr's
//!   buffered writer had passed on, which can differ from what the disk
//!   took.
//! - Run with standard input or output closed (`gzip <&-`, `gzip -c a
//!   >&-`), gzip says "Can't stat stdin" or "write: Bad file descriptor";
//!   the Rust runtime reopens a closed standard descriptor on `/dev/null`
//!   before `main`, so stuffr compresses an empty input, or writes to
//!   nowhere, and exits 0.
//! - Decompression, `-t` and `-l` are not built yet (a later task): any
//!   name or option that decompresses stops with a message, exit 1.

use std::ffi::OsString;
use std::io::Write;

use crate::compat::host::Host;

mod args;
mod messages;
mod run;

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
    if s.decompress || s.list || s.test {
        messages::printf(err, messages::DECOMPRESS_NOT_BUILT, &[name.as_bytes()]);
        return 1;
    }
    run::execute(name, s, host, err)
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

    /// Decompression is a later task's; until then it says so, exit 1,
    /// after the options are parsed (so `gunzip -h` is still usage).
    #[test]
    fn decompression_is_not_built_yet() {
        let d = scratch("dec");
        let none = |_: &str| None;
        let (code, _, err) = run_in(Flavour::Bsd, &d, "gunzip", &[], b"", &none);
        assert_eq!(code, 1);
        assert!(
            String::from_utf8(err)
                .unwrap()
                .starts_with("gunzip: decompression")
        );
        let (code, _, err) = run_in(Flavour::Bsd, &d, "gunzip", &args(&["-h"]), b"", &none);
        assert_eq!(code, 0);
        assert!(String::from_utf8(err).unwrap().contains("usage: gunzip ["));
        let _ = std::fs::remove_dir_all(&d);
    }
}
