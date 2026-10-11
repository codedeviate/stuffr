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
//! - an input that already has a gzip suffix is skipped with a note and
//!   exit 0, not 2; the suffixes are `.gz .z -gz -z _z .tgz .taz` in any
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
//! - Output is written under a temporary name and renamed into place, so an
//!   interrupted run leaves a `.stuffr-gzip-*.tmp` file.
//! - Decompression, `-t` and `-l` are not built yet (a later task).

use std::ffi::OsString;
use std::io::Write;

use crate::compat::host::Host;

mod args;
mod messages;
mod run;

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

/// What any name says under the BSD flavour until it is built.
pub(super) fn bsd_not_built(name: &str, err: &mut dyn Write) {
    printf(err, m::BSD_NOT_BUILT, &[name.as_bytes()]);
}
