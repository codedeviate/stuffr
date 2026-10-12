//! The GNU personality: stuffr behaving as GNU gzip 1.15.
//!
//! **Written from the outside only.** GNU gzip is GPLv3 and stuffr is MIT,
//! so nothing here is ported: every flag, check, message and exit code was
//! established from `gzip --help`, the manual, the NEWS file, and running
//! the binary and watching its stdout, stderr, exit code and file tree.
//! `messages.rs` names the command behind each string.
//!
//! **Names.** GNU installs `gunzip` and `zcat` as shell scripts: when their
//! first argument is exactly `--help` or `--version` they print their own
//! text, and otherwise they exec `gzip -d "$@"` and `gzip -dc "$@"`, so
//! every later message says `gzip:`. `gzcat`, which GNU does not install,
//! behaves as `zcat`.
//!
//! Behaviours reproduced because the binary shows them (each pinned by the
//! differential suite `tests/compat_gzip_gnu.rs`):
//!
//! - output is written under a temporary name (`.stuffr-gzip-*.tmp`) and
//!   put in place when complete; on SIGINT, SIGTERM, SIGHUP, SIGPIPE,
//!   SIGXCPU or SIGXFSZ the temporary is removed and the process dies of
//!   the signal, as GNU's partial output is (SIGQUIT and SIGUSR1 leave it);
//!   a SIGINT ignored at start stays ignored;
//! - a set-user-ID input is refused even under `-f`, a sticky one unless
//!   `-f` (whose output then drops the sticky bit); `-c` takes both;
//! - an input that already has a gzip suffix is skipped with a note (under
//!   `-r` only with `-v`) and exit 0, not 2; the suffixes are `.gz .z -gz -z _z .tgz .taz` in any
//!   case, and `-S`'s is tried before them when it holds an uppercase
//!   letter and after them otherwise (which one the note names);
//! - standard input compressed after a file operand stores the name
//!   `stdin` (`gzip a -`); before any file it stores none;
//! - standard input that is a regular file stores its modification time;
//!   a pipe stores 0, and so does any input that is not a regular file;
//! - `-c` follows a symbolic link and compresses a hard-linked or
//!   non-regular file without complaint; without `-c` a link is refused
//!   (`O_NOFOLLOW`'s error) unless `-f`;
//! - a terminal on standard output refuses only standard input, and ends
//!   the run there (exit 1, later operands untouched);
//! - `-v` prints the name before compressing and the ratio after, so a
//!   timestamp warning lands between them.
//!
//! Decompression, `-t` and `-l` (`run/decompress.rs`, `decode.rs`,
//! `unpack.rs`, `list.rs`; each module doc lists what the binary showed):
//!
//! - gzip (and the old magic `1f 9e`), `.Z`, pack and a zip's first entry;
//!   members of any of the first three may follow one another;
//! - a missing operand is looked for with a suffix added; `-N` restores the
//!   stored name's last component only, beside the input, and the last
//!   stored time; a stored name that with the operand's directory part
//!   reaches 1024 bytes is "corrupted input -- file name too large" under
//!   `-N` to a file and `-lN` (the run ends), while `-dNc`, `-tN` and every
//!   mode without `-N` read a stored name or comment of any length;
//! - `-v` and `-l` subtract a first header longer than GNU's 256 KiB input
//!   buffer only modulo that buffer (`decode::counted_header`);
//! - which failures end the whole run (truncation, a corrupt body, a
//!   corrupt `.Z`, any pack failure, and CRC or length errors under `-d`)
//!   and which do not, and that standard input refused at its header ends
//!   it too;
//! - a later member whose header is refused keeps the output and removes
//!   the input, exit 1 (under `-k` the output goes instead); a run-ending
//!   failure in an input's header removes the previous `-k` output;
//! - `-f` copies what is not compressed when the output is standard
//!   output, and trailing data after the last member likewise;
//! - `-l` decodes every input in full, prints a totals line in place of an
//!   input that does not decode cleanly, quotes names, and dates a piped
//!   standard input with the previous input's time.
//!
//! Known deviations:
//!
//! - `--version`/`-V`/`-L` print stuffr's first line and its own MIT notice,
//!   not GNU's copyright and licence text (Ruling T7-2).
//! - The compressed bytes are stuffr's deflate, not GNU's (GNU's deflate is
//!   its own and GPL): the reference decodes them to the same bytes and the
//!   header through FNAME matches, but the size, and so `-v`'s ratio,
//!   differ.
//! - `--rsyncable` and `--synchronous` are accepted and change nothing.
//! - Diagnostics quote names as GNU does in the C locale; non-ASCII bytes
//!   are always escaped, whatever the locale.
//! - The `gunzip`/`zcat` scripts' `--help` names their own path (`$0`);
//!   stuffr prints the `argv[0]` it was given, which for a command found on
//!   `PATH` is the bare name, where the shell gives the script its full
//!   path.
//! - LZH (`1f a0`, `compress -H`) is not decoded: a first member is "not in
//!   gzip format", a later one trailing garbage (Ruling T5).
//! - An output name past the file system's `NAME_MAX` is not shortened:
//!   GNU compresses a 253-byte name to a cut-short `.gz` name ("NAME
//!   compressed to SHORTER", exit 0) and under `-dN` writes a too-long
//!   stored name cut short ("warning, name truncated", exit 2); stuffr
//!   says "File name too long", exit 1, and keeps the input (observed:
//!   `gzip -k` on 252- to 255-byte names; final review, item 3).
//! - A `.Z` header claiming fewer than 9 bits is "corrupt input." before
//!   any output; GNU writes a few bytes first.
//! - A zip refused as "not a valid zip file" with its data-descriptor flag
//!   set makes GNU check the *next* input's gzip trailer as a data
//!   descriptor ("crc/length error"); that leaked state is not reproduced.
//! - `gzip -dNf` on an input whose stored name is its own name (or, on a
//!   case-insensitive or normalising volume, any spelling of it: `X.GZ`
//!   for `x.gz`): GNU removes the input before decoding and the output
//!   after, losing both whether the body decodes or not; stuffr says and
//!   exits the same but keeps the decoded file on success and the
//!   untouched input on failure (Rulings T8-4, T8-5). "The same file" is
//!   judged by device and inode; off unix, by spelling only.
//! - Read and write failures say `gzip: NAME: strerror`, exit 1, and end
//!   the run: the shape every other file error has, not observed.

use std::ffi::OsString;
use std::io::Write;

use crate::compat::host::Host;

mod args;
mod decode;
mod list;
mod messages;
mod run;
mod unpack;

use messages::{self as m, PROGRAM, printf};

/// GNU gzip's `main`, for the invoked `name`; `argv0` is the full
/// `argv[0]`, which getopt's own errors name when `name` is `gzip`.
pub(super) fn main(
    name: &'static str,
    argv0: &[u8],
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: &mut Host,
    err: &mut dyn Write,
) -> u8 {
    let mut out = host.out_writer(None);
    // The scripts: their own `--help`/`--version` as the first argument,
    // otherwise `gzip -d`/`gzip -dc` with every argument after it.
    let script = match name {
        "gunzip" => Some((m::GUNZIP_HELP, "-d")),
        "zcat" | "gzcat" => Some((m::ZCAT_HELP, "-dc")),
        _ => None,
    };
    let mut argv: Vec<OsString> = Vec::with_capacity(args.len() + 1);
    if let Some((help, flag)) = script {
        match args.first().map(|a| a.as_encoded_bytes()) {
            Some(b"--help") => {
                printf(&mut out, help, &[argv0]);
                return flushed(out, 0);
            }
            Some(b"--version") => {
                printf(&mut out, m::SCRIPT_VERSION_FIRST_LINE, &[name.as_bytes()]);
                let _ = out.write_all(m::SCRIPT_VERSION_REST.as_bytes());
                return flushed(out, 0);
            }
            _ => argv.push(flag.into()),
        }
    }
    argv.extend(args.iter().cloned());
    // The scripts exec `gzip` by that name.
    let getopt_name = if script.is_some() { PROGRAM } else { argv0 };
    match args::parse(getopt_name, &argv, env, &mut out, err) {
        args::Parsed::Exit(code) => flushed(out, code),
        args::Parsed::Run(s) => {
            drop(out);
            run::execute(s, host, err)
        }
    }
}

/// Flush the help or version text, then stop with `code`.
fn flushed(mut out: impl Write, code: u8) -> u8 {
    let _ = out.flush();
    code
}
