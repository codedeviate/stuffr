//! The ncompress personality: stuffr behaving as ncompress 5.0, built as
//! Ubuntu's `5.0-1` builds it, on every platform (ruling E6 of 0.18.0).
//!
//! **Ported from source.** ncompress 5.0's `compress.c` (github
//! `vapier/ncompress` tag `v5.0`, identical to Debian's
//! `ncompress_5.0.orig.tar.gz`), released into the public domain under the
//! Unlicense, whose text ships with stuffr-cli as `LICENSE-ncompress`. Of
//! Ubuntu's three patches, `uncompress-real.patch` and `fix-softlinks.patch`
//! change behaviour: the first is deviation N2 below, the second drops
//! `-DLSTAT`, so `lstat` is `stat` and symbolic links are followed. The
//! build's `-DUSERMEM=800000` makes the `FAST` hash, and glibc's `BUFSIZ`
//! makes `IBUFSIZ` and `OBUFSIZ` 8192, which shows in `-V` and in the
//! corrupt-input debug line. The measurement record of 0.18.0 Task 1
//! checked every behaviour against Ubuntu's and Homebrew's 5.0.
//!
//! **Names.** `uncompress` decompresses, and so does `compress -d`. The
//! usage names the invoked program (`progname`).
//!
//! **Bytes.** The LZW coder is `compress.c`'s, so the compressed bytes are
//! ncompress's at every bit count from 10 to 16, and at 9 up to the point
//! where its table fills (deviation N1).
//!
//! Behaviours reproduced (each pinned by `tests/compat_compress_ncompress.rs`):
//!
//! - flags anywhere on the line and in clusters; every `--` is dropped and
//!   ends the flags; a lone `-` is nothing (no operands: standard input);
//!   `-V` prints the version text and `-h` the usage, to standard output,
//!   exit 0, when met; an unknown flag is `Unknown flag: 'x'; ` and the
//!   usage on standard error, exit 1; `-n`, `-s`, `-q`, `-k`, `-F`, `-R`
//!   are accepted;
//! - `-b` takes the rest of its cluster or the next argument, whatever it
//!   is, through `atoi`, then is clamped to 9..=16; with nothing after it,
//!   `Missing maxbits` and the usage, exit 1, wherever it is;
//! - standard input to standard output when there is no operand; `-v`
//!   prints `Compression: x.xx%` (fixed-point `prratio`), and an output not
//!   smaller than its input is exit 2 even there, unless `-f`;
//! - an operand is `stat`ed (symbolic links followed); decompressing, a
//!   missing name is tried with `.Z`; a directory is skipped (`-v` says so)
//!   or, with `-r`, walked in `readdir` order (`-r` skips names without
//!   `.Z` when decompressing and with it when compressing, silently); a
//!   name that is neither is `ignored`, without changing the exit code;
//! - decompressing a regular file without `.Z` is a silent exit 1 (`-v`:
//!   `- no .Z suffix`), unless `-c`, which reads it as it is; compressing a
//!   name with `.Z` is `already has .Z suffix -- no change`, exit code
//!   untouched; an input with other hard links is refused without `-f`;
//! - an existing output is `NAME already exists.`, then, in the foreground
//!   with standard input a terminal, `Do you wish to overwrite NAME (y or
//!   n)? ` and one line read with `read(2)` (only `y` first overwrites),
//!   else `NAME not overwritten`, exit 1; `-f` (or `y`) removes the old
//!   output first, so a link in its place is replaced, never written
//!   through; `-c` never looks;
//! - the output is created `O_EXCL`, mode 0600, and an open failure names
//!   the input; `-v` prints `NAME: ` before the work and ` -- replaced
//!   with NAME` (and ` Compression: x.xx%`) after; a success copies the
//!   times (whole seconds), the mode (`& 07777`) and the owner, each
//!   failure reported and ignored, then removes the input unless `-k`;
//! - no saving: `No compression -- NAME unchanged` under `-v`, the output
//!   removed, exit 2, unless `-f`; an empty input is a 3-byte header;
//! - decompressing: fewer than 3 bytes or no magic is `NAME: not in
//!   compressed format` (exit 1, or 2 for a file, whose empty output is
//!   removed as "no compression"); more than 16 bits is `compressed with N
//!   bits, can only handle 16 bits` (exit 4, or 2 for a file); an empty
//!   input is silent (exit 2 for a file, 0 for standard input); a header
//!   and nothing else is an empty output; any header maxbits up to 16 is
//!   read (ruling E1); a cut-short stream or a flipped byte decodes
//!   silently; a bad code prints its debug line (`oldcode:-1 code:N`, or
//!   `insize:... posbits:... inbuf:...`) and `uncompress: corrupt input`,
//!   and ends the run: the partial output file is removed, standard output
//!   keeps the whole `OBUFSIZ` pieces written, exit 1;
//! - a read or write error is `\nread error on`/`\nwrite error on` and the
//!   name's `perror` (`stdin`, `stdout`, or after `-c` the name the output
//!   would have had), then the same end of the run: the output removed,
//!   the input kept (so a read error part-way loses nothing: ruling E7
//!   needs no deviation here);
//! - neither tool refuses a terminal;
//! - the exit code is the last one set (1 error, 2 no saving, 4 too many
//!   bits); nothing processed is exit 1, and `-r` then also says `no files
//!   processed after recursive search`;
//! - signals (ruling E3): SIGINT (unless ignored at start, which also
//!   silences the question), SIGTERM and SIGHUP remove the partial output
//!   and exit 1; SIGQUIT and the rest kill by their default action, leaving
//!   the partial output (mode 0600).
//!
//! Known deviations:
//!
//! - **N1.** At maxbits 9 (`-b 9`, and every value clamped to 9: 0,
//!   negative values, 1 to 8, non-numbers, the empty string) ncompress's
//!   encoder writes entry 512 in 9 bits and never widens: once the table
//!   fills its stream is undecodable, by its own `uncompress` too (where the
//!   first bad code falls depends on the input; about 21 500 bytes into the
//!   record's text). stuffr writes the valid compress 4.0 stream there: the
//!   table stops at entry 511, one more 9-bit code follows, and the codes
//!   after it are 10 bits, which ncompress's decoder reads. The bytes
//!   before the table fills are ncompress's, so a short input is unchanged;
//!   after it the ratio checks see the 10-bit sizes, so the CLEAR codes
//!   fall where ncompress's would not.
//! - **N2.** `uncompress` decompresses under that name on every platform
//!   (ruling E5). Ubuntu's binary decompresses only as `uncompress.real`
//!   (Debian's `uncompress-real.patch`; as `uncompress` it compresses), so
//!   where its usage says `uncompress.real`, stuffr's says `uncompress`.
//! - **N4.** `uncompress -f` on a file refused at its header (not in
//!   compressed format, or more than 16 bits): ncompress prints the refusal
//!   with its exit code (1 or 4), then takes the empty output for a
//!   success, removing the input. stuffr prints the same, exits the same,
//!   removes its empty output and keeps the input (ruling E4: an input is
//!   never lost). Under `-v` ncompress also prints `g.Z: g.Z: not in
//!   compressed format` and then ` -- replaced with g` on the next line,
//!   which is false (the input was refused, nothing replaced `g`): stuffr
//!   leaves that line out. An empty `.Z` with `-f` still becomes an empty
//!   output, as ncompress makes it (nothing is lost).
//! - **Ubuntu's build everywhere (ruling E6).** On macOS this personality
//!   is still Ubuntu's build, not Homebrew's: symbolic-link operands are
//!   followed (Homebrew's `-DLSTAT` refuses them, `NAME is not a directory
//!   or a regular file - ignored`), `-V` lists `FAST, ` and `IBUFSIZ=8192,
//!   OBUFSIZ=8192`, and the corrupt-input debug line and the output written
//!   before it follow 8192-byte buffers.
//! - Undefined behaviour, never reproduced: the corrupt-input debug line's
//!   first byte, read before the C's buffer when the bad code starts it, is
//!   printed as `00`; a table chain longer than the table (only a stale
//!   entry reused across inputs makes one, and the C's stack then runs
//!   through its hash table) is `uncompress: corrupt input`.
//! - The signal handler calls `_exit`, where the C's calls `exit()`: a
//!   pending `-r` `NAME unreadable` line (stdio, standard output) is not
//!   flushed.
//! - The answer `perror` prints after a question met by the end of the
//!   input is the platform's `strerror(0)`.
//! - Run with standard input or output closed, ncompress reads or writes a
//!   closed descriptor; the Rust runtime reopens a closed standard
//!   descriptor on `/dev/null` before `main`.
//! - Off unix there is no mode, owner or time to copy.

use std::ffi::OsString;
use std::io::Write;

use crate::compat::host::Host;

mod args;
mod lzw;
mod messages;
mod run;

/// ncompress's `main`, for the invoked `name` (`compress` or `uncompress`).
pub(super) fn main(
    name: &'static str,
    args: &[OsString],
    host: &mut Host,
    err: &mut dyn Write,
) -> u8 {
    use args::Parsed;
    let usage = |w: &mut dyn Write| messages::printf(w, messages::USAGE, &[name.as_bytes()]);
    let to_stdout = |host: &mut Host, text: &[u8]| {
        let mut w = host.out_writer(None);
        let _ = w.write_all(text);
        let _ = w.flush();
    };
    match args::parse(name, args) {
        Parsed::Run(s) => run::execute(s, host, err),
        Parsed::Version => {
            to_stdout(host, messages::ABOUT.as_bytes());
            0
        }
        Parsed::Help => {
            let mut text = Vec::new();
            usage(&mut text);
            to_stdout(host, &text);
            0
        }
        Parsed::Unknown(c) => {
            messages::printf(err, messages::UNKNOWN_FLAG, &[&[c]]);
            usage(err);
            1
        }
        Parsed::MissingMaxbits => {
            let _ = err.write_all(messages::MISSING_MAXBITS.as_bytes());
            usage(err);
            1
        }
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
        let (code, out, err, _) =
            run_in_counted(Flavour::Ncompress, d, name, &args, stdin, &|_| None);
        (code, out, String::from_utf8(err).unwrap())
    }

    fn text(n: usize) -> Vec<u8> {
        (0..n).map(|i| b"the quick brown fox "[i % 20]).collect()
    }

    fn noise(n: usize, mut x: u64) -> Vec<u8> {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// A round trip through files: `compress f` writes `f.Z` and removes
    /// `f`, reading it once, whole; `uncompress f` reads it back.
    #[test]
    fn files_round_trip_in_the_sandbox() {
        let d = scratch("trip");
        let data = text(100_000);
        std::fs::write(d.join("f"), &data).unwrap();
        let args: Vec<OsString> = vec!["-v".into(), "f".into()];
        let (code, _, err, reads) =
            run_in_counted(Flavour::Ncompress, &d, "compress", &args, b"", &|_| None);
        let err = String::from_utf8(err).unwrap();
        assert_eq!(code, 0, "{err}");
        assert!(
            err.starts_with("f:  -- replaced with f.Z Compression: "),
            "{err}"
        );
        let f = reads[&d.join("f")];
        assert_eq!((f.opens, f.bytes, f.len), (1, 100_000, 100_000));
        assert!(!d.join("f").exists());
        let (code, _, err) = run(&d, "uncompress", &["f"], b"");
        assert_eq!((code, err.as_str()), (0, ""));
        assert_eq!(std::fs::read(d.join("f")).unwrap(), data);
        assert!(!d.join("f.Z").exists());
    }

    /// The usage and the version text go to standard output for `-h` and
    /// `-V`, the usage to standard error after a bad flag.
    #[test]
    fn usage_and_version() {
        let d = scratch("usage");
        let (code, out, err) = run(&d, "uncompress", &["-h"], b"");
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(out.starts_with(b"Usage: uncompress [-dfhvcVr] [-b maxbits] [--] [path ...]\n"));
        let (code, out, _) = run(&d, "compress", &["-V"], b"");
        assert_eq!(code, 0);
        assert!(out.starts_with(b"Compress version: (N)compress 5.0\n"));
        let (code, out, err) = run(&d, "compress", &["-z"], b"");
        assert_eq!(code, 1);
        assert!(out.is_empty());
        assert!(
            err.starts_with("Unknown flag: 'z'; Usage: compress "),
            "{err}"
        );
    }

    /// A write that fails part-way (the sandbox's budget, as a full disk)
    /// is `\nwrite error onNAME: No space left on device`, exit 1, the
    /// output removed and the input kept; after `-c` the name is the one
    /// the output would have had.
    #[test]
    fn a_failed_write_keeps_the_input() {
        let d = scratch("full");
        let data = noise(9 << 20, 0x9e37_79b9_7f4a_7c15);
        std::fs::write(d.join("big"), &data).unwrap();
        let (code, _, err) = run(&d, "compress", &["-f", "big"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "\nwrite error onbig.Z: No space left on device\n")
        );
        assert_eq!(std::fs::read(d.join("big")).unwrap(), data);
        assert!(!d.join("big.Z").exists());
        let (code, out, err) = run(&d, "compress", &["-c", "big"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "\nwrite error onbig.Z: No space left on device\n")
        );
        assert!(!out.is_empty() && out.len() % super::lzw::OBUFSIZ == 0);
        let (code, _, err) = run(&d, "compress", &[], &data);
        assert_eq!(
            (code, err.as_str()),
            (1, "\nwrite error onstdout: No space left on device\n")
        );
    }

    /// The same decompressing: 9 MiB of zeros decode past the sandbox's
    /// 8 MiB budget; the partial output is removed and the `.Z` kept.
    #[test]
    fn a_failed_decompressing_write_keeps_the_input() {
        let d = scratch("full-d");
        let (code, z, err) = run(&d, "compress", &[], &vec![0u8; 9 << 20]);
        assert_eq!(code, 0, "{err}");
        std::fs::write(d.join("z.Z"), &z).unwrap();
        let (code, _, err) = run(&d, "uncompress", &["z.Z"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "\nwrite error onz: No space left on device\n")
        );
        assert_eq!(std::fs::read(d.join("z.Z")).unwrap(), z);
        assert!(!d.join("z").exists());
    }

    /// Deviation N1 in the sandbox: a `-b 9` stream of an input that fills
    /// the table many times reads back, every clamped value alike.
    #[test]
    fn maxbits_9_streams_read_back() {
        let d = scratch("n1");
        let data = [text(50_000), noise(50_000, 7), vec![0u8; 50_000]].concat();
        for v in ["9", "0", "-1", "8", "abc", ""] {
            let (code, z, err) = run(&d, "compress", &["-b", v], &data);
            assert_eq!((code, z[2]), (0, 0x89), "-b {v:?}: {err}");
            let (code, back, err) = run(&d, "uncompress", &[], &z);
            assert_eq!((code, err.as_str()), (0, ""), "-b {v:?}");
            assert!(back == data, "-b {v:?}");
        }
    }

    /// Deviation N4 in the sandbox: `uncompress -f` of a refused input
    /// keeps it and leaves no output.
    #[test]
    fn a_refused_input_is_kept_under_f() {
        let d = scratch("n4");
        std::fs::write(d.join("bad.Z"), b"plain text").unwrap();
        let (code, _, err) = run(&d, "uncompress", &["-f", "bad.Z"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "bad.Z: not in compressed format\n")
        );
        assert_eq!(std::fs::read(d.join("bad.Z")).unwrap(), b"plain text");
        assert!(!d.join("bad").exists());
        std::fs::write(d.join("e.Z"), b"").unwrap();
        let (code, _, err) = run(&d, "uncompress", &["-f", "e.Z"], b"");
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(!d.join("e.Z").exists());
        assert_eq!(std::fs::read(d.join("e")).unwrap(), b"");
    }

    /// A corrupt stream ends the run: the operands after it are never
    /// looked at, the partial output goes, exit 1.
    #[test]
    fn a_corrupt_input_ends_the_run() {
        let d = scratch("corrupt");
        std::fs::write(d.join("w.Z"), [0x1f, 0x9d, 0x90, 0xff, 0x03, 0x00]).unwrap();
        std::fs::write(d.join("x"), b"x").unwrap();
        let (code, _, err) = run(&d, "uncompress", &["w.Z", "x"], b"");
        assert_eq!(
            (code, err.as_str()),
            (1, "oldcode:-1 code:511\nuncompress: corrupt input\n")
        );
        assert!(d.join("w.Z").exists() && !d.join("w").exists());
    }

    /// `-r` meets a directory it cannot open: `printf`'s `NAME unreadable`
    /// on standard output, the run going on (exit code untouched).
    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_is_reported_on_standard_output() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("unreadable");
        std::fs::create_dir_all(d.join("dir/sub")).unwrap();
        std::fs::write(d.join("dir/a"), text(1000)).unwrap();
        let sub = d.join("dir/sub");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
        // The scratch's drop makes `dir/sub` writable again, whatever fails.
        let (code, out, err) = run(&d, "compress", &["-r", "dir"], b"");
        assert_eq!((code, err.as_str()), (0, ""));
        assert_eq!(out, b"dir/sub unreadable\n");
        assert!(d.join("dir/a.Z").exists());
    }

    /// Hostile streams never panic (overflow checks on, as the fuzz target
    /// runs): random bytes after every header byte, cut-short and
    /// byte-flipped valid streams, through `uncompress -c`. Every run ends
    /// 0, 1, 2 or 4.
    #[test]
    fn hostile_streams_never_panic() {
        let d = scratch("hostile");
        let data = text(20_000);
        let (_, good, _) = run(&d, "compress", &["-b", "12"], &data);
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
            assert!(matches!(code, 0 | 1 | 2 | 4), "round {round}: exit {code}");
        }
    }
}
