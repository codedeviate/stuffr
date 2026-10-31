//! The Apple personality: stuffr behaving as Apple's `compress` 487.0.1.
//!
//! **Ported from source.** Apple's `compress` is `compress.c` and `zopen.c`
//! from Apple's `file_cmds` (`compress/`, unchanged from tag file_cmds-400
//! to file_cmds-479; 487.0.1 is not published, and the installed binary
//! matches this source in every string, import and measured behaviour),
//! itself 4.4BSD's: Copyright (c) 1985, 1986, 1992, 1993 The Regents of
//! the University of California, BSD-3-Clause, whose notice ships with
//! stuffr-cli as `LICENSE-compress-bsd`. The functions ported are named in
//! each module; the measurement record of 0.18.0 Task 1 checked every
//! behaviour against `/usr/bin/compress`.
//!
//! **Names.** `compress` and `uncompress` are one program; `uncompress`
//! decompresses, and so does `compress -d`. Messages carry the invoked name
//! (`getprogname()`); getopt's two carry the full `argv[0]`. (Apple's
//! program also answers to `zcat`, which in stuffr is the gzip family's.)
//!
//! **Bytes.** The LZW coder is `zopen.c`'s, so the compressed bytes are
//! Apple's at every bit count, `-b 1` to `-b 16`, on every tier.
//!
//! Behaviours reproduced (each pinned by `tests/compat_compress_apple.rs`):
//!
//! - options before the first operand only (no permutation); `--`; a lone
//!   `-` is standard input, and turns on `-c` for every later operand;
//!   `-c` with more than one file is refused when compressing only;
//! - `-b` is `strtol`'s: leading blanks and a sign accepted, trailing junk
//!   `illegal bit count`, an `int` truncation (`4294967312` is 16, an
//!   overflow is -1); 0 and the empty string mean 16; outside 0..=16 the
//!   output (decompressing: the input) is `Invalid argument`, after the
//!   input was opened when compressing, before when decompressing;
//!   `-b 1` to `-b 8` write a header of 1 to 8 bits and a stream of 9-bit
//!   literals and CLEARs (ruling E1);
//! - an operand ending in `.Z` is refused when compressing; decompressing,
//!   a name without `.Z` reads `name.Z`; names past `MAXPATHLEN` are "name
//!   too long";
//! - an existing regular output is refused (`already exists`, exit 1)
//!   unless `-f`, or unless standard error is a terminal and the answer to
//!   `overwrite NAME? ` (read from standard input) starts with `y`; a
//!   refusal at the prompt also prints the message; `-c` never asks;
//!   symbolic links are followed, both ways, and an existing output that is
//!   a link to another file is written through;
//! - no saving: an output not smaller than its input is removed, exit 2,
//!   `file would grow; left unmodified` only under `-v`; `-f` keeps it;
//!   standard output is never checked; an empty input writes no byte at
//!   all, not even the header (ruling E2), so `compress e` exits 2 and
//!   `compress -f e` leaves an empty `e.Z`;
//! - a successful file run copies the times, owner (if allowed), mode
//!   and file flags, then removes the input; `-v` prints Apple's
//!   percentages (`%.0f` of `float` ratios, `nan` for two empty files);
//! - decompressing reads the first 1024 bytes before creating the output,
//!   so a bad header leaves no output; later failures remove it, except on
//!   standard output, which keeps every whole 1024-byte piece decoded
//!   before the failure; a bad magic or more than 16 bits is
//!   `Inappropriate file type or format`, a bad code `Invalid argument`,
//!   exit 1; a stream cut short or with flipped bytes decodes silently; the
//!   first code is not checked (its low byte is written);
//! - neither tool refuses a terminal: compressed data goes to a terminal
//!   standard output, and a terminal standard input is read;
//! - every warning is exit 1, `no saving` 2, the last one set wins;
//! - no signal handler (ruling E3): INT, TERM, HUP and QUIT kill the run
//!   by their default action and leave the partial output beside the
//!   intact input, as Apple does; an INT ignored at start stays ignored.
//!
//! Known deviations:
//!
//! - **A1.** A stream whose header asks for fewer than 12 bits is decoded
//!   (any maxbits up to 16, as ncompress's decoder accepts: ruling E1),
//!   Apple's own `-b 1` to `-b 11` output included; Apple's `uncompress`
//!   refuses all of them, `Inappropriate file type or format`, exit 1.
//! - **A2.** When the output exists and is the input itself (`compress -f
//!   f` with `f.Z` a symbolic or hard link to `f`, `uncompress -f f.Z` with
//!   `f` a link to `f.Z`, or the same after a `y` at the prompt), Apple
//!   opens the output for writing over its own input: the data is lost
//!   (compress exits 0, uncompress says `Invalid argument`, exit 1).
//!   stuffr writes such an output under a temporary name
//!   (`.stuffr-compress-*.tmp`, removed on INT, TERM or HUP; QUIT, the
//!   "leave a core" signal, leaves it behind, as Apple leaves its partial
//!   output on QUIT, and nothing is lost: ruling E12) and renames it
//!   over the link when complete, then removes the input as usual: the
//!   data survives, compressed or decompressed, silently, exit 0 (spec
//!   anti-goal: an input is never lost; ruling E4). After a `y` at the
//!   prompt without `-f`, a compressed output not smaller than its input is
//!   still "no saving", exit 2 (with its `-v` line): stuffr drops its
//!   temporary and leaves the `f.Z` link and `f` as they were, where Apple
//!   unlinks `f.Z` after it has already emptied `f`.
//! - **A3.** A header and nothing else (`1f 9d 90`, what ncompress writes
//!   for an empty input) is a valid stream of no bytes: stuffr writes the
//!   empty output (exit 0, the input removed as after any success). Apple
//!   refuses it with whatever `errno` was left (`No such file or directory`
//!   from the output's `stat`, `Undefined error: 0` with `-c` or standard
//!   input), exit 1.
//! - **A4.** A read error part-way through a `.Z` input (`EIO`, say):
//!   Apple's `getcode` takes it for the end of the stream, so the cut-short
//!   output is published and the input removed, exit 0, and the data is
//!   lost. stuffr warns as Apple warns for a failed read
//!   (`uncompress: NAME: <strerror>`), exit 1, removes the output (standard
//!   output keeps what was written) and keeps the input (ruling E7). A read
//!   error inside the 3-byte header stays Apple's `Inappropriate file type
//!   or format`.
//! - **A5.** Hardening (ruling T5 of the 2026-10-31 security audit): a
//!   symlink at an output name is never written through. Apple checks for
//!   an existing output with `stat` and opens it `fopen(.., "w")`, so a
//!   dangling symlink looks absent and the write creates the file it
//!   names, a live one is truncated through, and `setfile` sets the
//!   times, owner, mode and flags by name. stuffr checks with `lstat`: a
//!   symlink, dangling or not, is an existing file (`already exists`, or
//!   the question); overwriting it (`-f`, or `y`) unlinks the link and
//!   creates a fresh file (`O_NOFOLLOW`), its target untouched. A file it
//!   creates is created 0600 and given the input's mode, owner, times and
//!   flags through its own descriptor at the end (a run that ends first
//!   gives it Apple's 0666 less the umask intersected with the input's
//!   permission bits: Apple's mode for an ordinary 0644 input, and a
//!   private input's partial output stays private), so a private input is
//!   never readable through its output while it is written, and a "no
//!   saving" or failed output removed is always the file this run created.
//!   Why: a planted link must not redirect a write.
//! - The overwrite question's answer is judged by the C locale's
//!   `rpmatch` (`y` or `Y`), whatever `LC_MESSAGES` says; Apple loads the
//!   user's locale first.
//! - Undefined behaviour, never reproduced: a table chain longer than
//!   65536 entries, reachable only through the unchecked first code, is
//!   `Invalid argument`, where Apple's decoder overruns its stack; after a
//!   failed write, Apple's `zclose` encodes the last code past its 16-byte
//!   buffer, stuffr's encoder writes nothing more.
//! - Run with standard input or output closed, Apple fails to open
//!   `/dev/stdin` or `/dev/stdout`; the Rust runtime reopens a closed
//!   standard descriptor on `/dev/null` before `main`, so stuffr reads
//!   nothing or writes nowhere.
//! - A write that fails part-way is reported where stuffr's buffered
//!   writer (64 KiB) meets it, not where Apple's stdio would; the message
//!   and exit code are the same.
//! - Off macOS (where Apple's compress does not exist) file flags are not
//!   copied, and `Inappropriate file type or format` is still the text of
//!   a refused header.

use std::ffi::OsString;
use std::io::Write;

use crate::compat::host::Host;

pub(super) mod args;
mod lzw;
mod messages;
mod run;

/// Apple compress's `main`, for the invoked `name` (`compress` or
/// `uncompress`) and the full `argv0` getopt prints.
pub(super) fn main(
    name: &'static str,
    argv0: &[u8],
    args: &[OsString],
    host: &mut Host,
    err: &mut dyn Write,
) -> u8 {
    match args::parse(name, argv0, args, err) {
        args::Parsed::Exit(code) => code,
        args::Parsed::Run(s) => run::execute(name, s, host, err),
    }
}

#[cfg(test)]
mod tests {
    use crate::compat::compress::{Flavour, run_in_counted};
    use std::ffi::OsString;

    use crate::compat::compress::test_scratch::scratch;

    fn run(
        d: &std::path::Path,
        name: &'static str,
        a: &[&str],
        stdin: &[u8],
    ) -> (i32, Vec<u8>, String) {
        let args: Vec<OsString> = a.iter().map(OsString::from).collect();
        let (code, out, err, _) = run_in_counted(Flavour::Apple, d, name, &args, stdin, &|_| None);
        (code, out, String::from_utf8(err).unwrap())
    }

    fn text(n: usize) -> Vec<u8> {
        (0..n).map(|i| b"the quick brown fox "[i % 20]).collect()
    }

    /// A round trip through files: `compress f` writes `f.Z` and removes
    /// `f`; `uncompress f` reads it back; the input of each run is read
    /// once, whole, and counted.
    #[test]
    fn files_round_trip_in_the_sandbox() {
        let d = scratch("trip");
        let data = text(100_000);
        std::fs::write(d.join("f"), &data).unwrap();
        let args: Vec<OsString> = vec!["f".into()];
        let (code, _, err, reads) =
            run_in_counted(Flavour::Apple, &d, "compress", &args, b"", &|_| None);
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        let f = reads[&d.join("f")];
        assert_eq!((f.opens, f.bytes, f.len), (1, 100_000, 100_000));
        assert!(!d.join("f").exists());
        let (code, _, err) = run(&d, "uncompress", &["f"], b"");
        assert_eq!(code, 0, "{err}");
        assert_eq!(std::fs::read(d.join("f")).unwrap(), data);
        assert!(!d.join("f.Z").exists());
    }

    /// A write that fails part-way (the sandbox's budget, as a full disk)
    /// is `NAME: No space left on device`, exit 1, the output removed and
    /// the input kept; to standard output the run goes on.
    #[test]
    fn a_failed_write_keeps_the_input() {
        let d = scratch("full");
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let noise: Vec<u8> = (0..9 << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        std::fs::write(d.join("big"), &noise).unwrap();
        let (code, _, err) = run(&d, "compress", &["-f", "big"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "compress: big.Z: No space left on device\n")
        );
        assert_eq!(std::fs::read(d.join("big")).unwrap(), noise);
        assert!(!d.join("big.Z").exists());
        let (code, out, err) = run(&d, "compress", &["-c", "big"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "compress: /dev/stdout: No space left on device\n")
        );
        assert!(!out.is_empty());
    }

    /// The same when decompressing: 9 MiB of zeros decode past the
    /// sandbox's 8 MiB budget, so the write fails part-way: `NAME: No space
    /// left on device`, exit 1, the partial output removed and the `.Z`
    /// kept; to standard output, what was written stays.
    #[test]
    fn a_failed_decompressing_write_keeps_the_input() {
        let d = scratch("full-d");
        let (code, z, err) = run(&d, "compress", &[], &vec![0u8; 9 << 20]);
        assert_eq!(code, 0, "{err}");
        std::fs::write(d.join("z.Z"), &z).unwrap();
        let (code, _, err) = run(&d, "uncompress", &["z.Z"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "uncompress: z: No space left on device\n")
        );
        assert_eq!(std::fs::read(d.join("z.Z")).unwrap(), z);
        assert!(!d.join("z").exists());
        let (code, out, err) = run(&d, "uncompress", &["-c", "z.Z"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "uncompress: /dev/stdout: No space left on device\n")
        );
        assert!(!out.is_empty() && out.iter().all(|&b| b == 0));
        assert_eq!(std::fs::read_dir(&*d).unwrap().count(), 1);
    }

    /// Deviation A4 at run level: a read error part-way through the `.Z`
    /// (EIO injected after `n` bytes) is not the end of the stream. Apple's
    /// stdio would take it for EOF and lose the input; stuffr warns with
    /// the file name and `strerror`, exits 1, keeps the `.Z` and publishes
    /// no output. `-c` takes the same branch (the output is only standard
    /// output, which gets whatever was decoded before the error).
    #[test]
    fn a4_a_read_error_mid_file_keeps_the_input() {
        use crate::compat::host::{Host, InputReads, Sandbox};
        use std::sync::atomic::AtomicU64;
        use std::sync::{Arc, Mutex};

        let d = scratch("a4");
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let data: Vec<u8> = (0..200_000)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                b"abcdefgh"[(x >> 40) as usize % 8] ^ (i / 50_000) as u8
            })
            .collect();
        let (code, z, err) = run(&d, "compress", &[], &data);
        assert_eq!(code, 0, "{err}");
        assert!(z.len() >= 64 << 10, "fixture too small: {}", z.len());
        std::fs::write(d.join("a.Z"), &z).unwrap();
        for cat in [false, true] {
            for n in [0u64, 4096, 20_000] {
                let reads = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
                reads.lock().unwrap().insert(
                    d.join("a.Z"),
                    InputReads {
                        fail_after: Some(n),
                        ..Default::default()
                    },
                );
                let mut host = Host::Sandbox(Sandbox {
                    dir: d.to_path_buf(),
                    stdin: Some(Vec::new()),
                    stdout: Arc::new(Mutex::new(Vec::new())),
                    budget: Arc::new(AtomicU64::new(u64::MAX)),
                    reads,
                });
                let args: Vec<OsString> = if cat {
                    vec!["-c".into(), "a.Z".into()]
                } else {
                    vec!["a.Z".into()]
                };
                let mut err = Vec::new();
                let code = super::main("uncompress", b"uncompress", &args, &mut host, &mut err);
                let err = String::from_utf8(err).unwrap();
                let ctx = format!("cat={cat} n={n}: {err}");
                assert_eq!(code, 1, "{ctx}");
                // Before the header is whole, a failed read is Apple's own
                // short-header answer (EFTYPE), not the A4 branch.
                let text = if n == 0 {
                    "Inappropriate file type or format"
                } else {
                    "Input/output error"
                };
                assert!(err.contains("a.Z") && err.contains(text), "{ctx}");
                assert_eq!(std::fs::read(d.join("a.Z")).unwrap(), z, "{ctx}");
                assert!(!d.join("a").exists(), "{ctx}");
            }
        }
    }

    /// Deviation A2 in the sandbox: a hard link `f.Z` to `f` and `-f`.
    #[cfg(unix)]
    #[test]
    fn an_output_that_is_the_input_is_never_lost() {
        let d = scratch("same");
        let data = text(50_000);
        std::fs::write(d.join("f"), &data).unwrap();
        std::fs::hard_link(d.join("f"), d.join("f.Z")).unwrap();
        let (code, _, err) = run(&d, "compress", &["-f", "f"], b"");
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(!d.join("f").exists());
        let (code, out, _) = run(&d, "uncompress", &["-c", "f.Z"], b"");
        assert_eq!((code, out), (0, data.clone()));
        std::os::unix::fs::symlink("f.Z", d.join("f")).unwrap();
        let (code, _, err) = run(&d, "uncompress", &["-f", "f.Z"], b"");
        assert_eq!((code, err.as_str()), (0, ""));
        assert_eq!(std::fs::read(d.join("f")).unwrap(), data);
        assert!(!d.join("f.Z").exists());
        let left = std::fs::read_dir(&*d).unwrap().count();
        assert_eq!(left, 1, "a temporary was left");
    }

    /// Hostile streams never panic (overflow checks on, as the fuzz target
    /// runs): random bytes after every header byte, cut-short and
    /// byte-flipped valid streams, through `uncompress -c`. Every run ends
    /// 0 or 1.
    #[test]
    fn hostile_streams_never_panic() {
        let d = scratch("hostile");
        let data = text(20_000);
        let (_, good, _) = run(&d, "compress", &[], &data);
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..300 {
            let mut b = good.clone();
            match round % 3 {
                0 => {
                    for _ in 0..1 + next() % 4 {
                        let at = (next() as usize) % b.len();
                        b[at] = next() as u8;
                    }
                }
                1 => b.truncate((next() as usize) % b.len()),
                _ => {
                    b.truncate(3 + (next() as usize) % 64);
                    for v in &mut b[3..] {
                        *v = next() as u8;
                    }
                    b[2] = next() as u8;
                }
            }
            let (code, _, _) = run(&d, "uncompress", &["-c"], &b);
            assert!(matches!(code, 0 | 1), "round {round}: exit {code}");
        }
    }
}
