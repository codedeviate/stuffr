//! Every message the BSD personality prints, copied from Apple's `gzip.c`
//! (file_cmds-479, BSD-2-Clause, see `LICENSE-gzip-bsd`) and Apple libc's
//! `getopt_long`, and checked against `/usr/bin/gzip` 487.0.1. Formats keep
//! C's `fprintf` layout (`%s` and `%d` take an argument in order, integers
//! formatted by the caller, `%%` is a literal percent sign) and print
//! through [`printf`]. The comment on each names the function it comes
//! from.
//!
//! `warn`/`warnx` (err(3)) put `getprogname()`, the invoked name, and `: `
//! in front ([`PREFIX`]); `warn` adds `: ` and `strerror(errno)`
//! ([`ERRNO_SUFFIX`]), `warnx` only the newline ([`NEWLINE`]).
//!
//! The deliberate changes: `-V` and `-L` name stuffr and its version on
//! their first line (Ruling T9-1, as bzip2's `--version` does); the rest of
//! `-L` is Apple's notice, which `LICENSE-gzip-bsd` carries. The usage
//! text, which `-h` and every option error print, keeps Apple's version
//! line byte for byte. [`DECOMPRESS_NOT_BUILT`] is stuffr's own, for the
//! part a later task builds.

pub(super) use crate::compat::host::printf;

// ---- err(3) ----

/// `warn`/`warnx`/`errx`: `getprogname()` and a colon.
pub(super) const PREFIX: &str = "%s: ";

/// `warn`: after the message, the error text.
pub(super) const ERRNO_SUFFIX: &str = ": %s\n";

/// `warnx`/`errx`: the message ends the line.
pub(super) const NEWLINE: &str = "\n";

// ---- version, usage, licence ----

/// `gzip_version` (`"Apple gzip " GZIP_APPLE_VERSION`), as the binary
/// prints it: the first line of `usage`.
pub(super) const GZIP_VERSION: &str = "Apple gzip 487.0.1\n";

/// `display_version`, changed to name stuffr (Ruling T9-1): Apple prints
/// [`GZIP_VERSION`].
pub(super) const VERSION_FIRST_LINE: &str = concat!(
    "Apple gzip (stuffr ",
    env!("CARGO_PKG_VERSION"),
    ") 487.0.1\n"
);

/// `display_license`'s first line under `__APPLE__`, changed to name
/// stuffr (Ruling T9-1).
pub(super) const LICENSE_FIRST_LINE: &str = concat!(
    "Apple gzip (stuffr ",
    env!("CARGO_PKG_VERSION"),
    ") 487.0.1 (based on FreeBSD gzip 20190107, NetBSD gzip 20150113)\n"
);

/// `display_license`: `gzip_copyright` and a newline, verbatim.
pub(super) const LICENSE_REST: &str = concat!(
    "   Copyright (c) 1997, 1998, 2003, 2004, 2006 Matthew R. Green\n",
    "   All rights reserved.\n",
    "\n",
    "   Redistribution and use in source and binary forms, with or without\n",
    "   modification, are permitted provided that the following conditions\n",
    "   are met:\n",
    "   1. Redistributions of source code must retain the above copyright\n",
    "      notice, this list of conditions and the following disclaimer.\n",
    "   2. Redistributions in binary form must reproduce the above copyright\n",
    "      notice, this list of conditions and the following disclaimer in the\n",
    "      documentation and/or other materials provided with the distribution.\n",
    "\n",
    "   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n",
    "   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n",
    "   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n",
    "   IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n",
    "   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,\n",
    "   BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;\n",
    "   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED\n",
    "   AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,\n",
    "   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY\n",
    "   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF\n",
    "   SUCH DAMAGE.\n",
);

/// `usage`, after [`GZIP_VERSION`]; `%s` is `getprogname()`.
pub(super) const USAGE: &str = concat!(
    "usage: %s [-123456789acdfhklLNnqrtVv] [-S .suffix] [<file> [<file> ...]]\n",
    " -1 --fast            fastest (worst) compression\n",
    " -2 .. -8             set compression level\n",
    " -9 --best            best (slowest) compression\n",
    " -c --stdout          write to stdout, keep original files\n",
    "    --to-stdout\n",
    " -d --decompress      uncompress files\n",
    "    --uncompress\n",
    " -f --force           force overwriting & compress links\n",
    " -h --help            display this help\n",
    " -k --keep            don't delete input files during operation\n",
    " -l --list            list compressed file contents\n",
    " -N --name            save or restore original file name and time stamp\n",
    " -n --no-name         don't save original file name or time stamp\n",
    " -q --quiet           output no warnings\n",
    " -r --recursive       recursively compress files in directories\n",
    " -S .suf              use suffix .suf instead of .gz\n",
    "    --suffix .suf\n",
    " -t --test            test compressed file\n",
    " -V --version         display program version\n",
    " -v --verbose         print extra statistics\n",
);

// ---- getopt_long (Apple libc, GNU_COMPATIBLE), each after [`PREFIX`] ----

/// `getopt_internal`: an option letter not in `OPT_LIST` (`gnuoptchar`).
pub(super) const INVALID_OPTION: &str = "invalid option -- %s\n";

/// `getopt_internal`: the same under `POSIXLY_CORRECT` (`illoptchar`).
pub(super) const ILLEGAL_OPTION: &str = "illegal option -- %s\n";

/// `getopt_internal`: `-S` last (`recargchar`).
pub(super) const NEEDS_ARGUMENT_SHORT: &str = "option requires an argument -- %s\n";

/// `parse_long_options` (`ambig`): the name as typed, up to any `=`.
pub(super) const AMBIGUOUS: &str = "option `--%s' is ambiguous\n";

/// `parse_long_options` (`noarg`): the name as typed, up to the `=`.
pub(super) const NO_ARGUMENT: &str = "option `--%s' doesn't allow an argument\n";

/// `parse_long_options` (`recargstring`): the name as typed.
pub(super) const NEEDS_ARGUMENT_LONG: &str = "option `--%s' requires an argument\n";

/// `parse_long_options` (`illoptstring`): the whole word after `--`,
/// `=value` included.
pub(super) const UNRECOGNIZED: &str = "unrecognized option `--%s'\n";

// ---- main ----

/// `main`, `case 'a'`: printed at the option, `-q` or not.
pub(super) const ASCII_IGNORED: &str = "%s: option --ascii ignored on this system\n";

/// `main`, `case 'S'` (`errx(1, ...)`), after [`PREFIX`].
pub(super) const SUFFIX_TOO_LONG: &str = "incorrect suffix: '%s': too long\n";

// ---- handle_pathname, handle_dir ----

/// `handle_pathname` (`__APPLE__`: the operand, then the path tried).
pub(super) const CANT_STAT: &str = "can't stat: %s (%s)";

/// `handle_pathname`, without `-r`.
pub(super) const IS_DIRECTORY: &str = "%s is a directory";

/// `handle_pathname`.
pub(super) const NOT_REGULAR: &str = "%s is not a regular file";

/// `handle_dir`: an entry `fts` could not read (`FTS_DNR`/`FTS_ERR`/
/// `FTS_NS`), as `warn("%s", path)`.
pub(super) const PATH_ONLY: &str = "%s";

// ---- file_compress, check_outfile, copymodes ----

/// `file_compress`: `open` of the input failed.
pub(super) const CANT_OPEN: &str = "can't open %s";

/// `file_compress`: `fstat` of the input failed.
pub(super) const COULDNT_STAT: &str = "couldn't stat: %s";

/// `file_compress`: more than one link without `-f`. The plural is
/// `st_nlink == 1 ? "" : "s"`, always `s` here.
pub(super) const HAS_LINKS: &str = "%s has %s other link%s -- skipping";

/// `file_compress`: the input already has a suffix of the table.
pub(super) const HAS_SUFFIX: &str = "%s already has %s suffix -- unchanged";

/// `check_outfile`: the output exists, standard input is not a terminal.
pub(super) const ALREADY_EXISTS: &str = "%s already exists -- skipping";

/// `check_outfile`: the output exists, standard input is a terminal.
pub(super) const ASK_OVERWRITE: &str = "%s already exists -- do you wish to overwrite (y or n)? ";

/// `check_outfile`: the answer was not yes.
pub(super) const NOT_OVERWRITING: &str = "\tnot overwriting\n";

/// `file_compress`: the exclusive create of the output failed.
pub(super) const COULD_NOT_CREATE: &str = "could not create output: %s";

/// `file_compress`: after a write failure, the output's size is not what
/// was counted (`(uintmax_t)-1`).
pub(super) const WRONG_SIZE: &str = "output file: %s wrong size (%s != %s), deleting";

/// `file_compress`, `bad_outfile`.
pub(super) const LEAVING_ORIGINAL: &str = "leaving original %s";

/// `copymodes`: `fchown` failed with other than `EPERM`.
pub(super) const COULDNT_FCHOWN: &str = "couldn't fchown: %s";

/// `copymodes`.
pub(super) const COULDNT_FCHMOD: &str = "couldn't fchmod: %s";

/// `copymodes`.
pub(super) const COULDNT_FUTIMENS: &str = "couldn't futimens: %s";

/// `copymodes`: the input had file flags and they could not be set
/// (macOS only: elsewhere stuffr copies no file flags).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) const COULDNT_FCHFLAGS: &str = "couldn't fchflags: %s";

// ---- gz_compress ----

/// `gz_compress`: `read` of the input failed.
pub(super) const READ: &str = "read";

/// `gz_compress`: `write` of the output failed.
pub(super) const WRITE: &str = "write";

/// `gz_compress`: zlib refused to go on.
pub(super) const DEFLATE_FAILED: &str = "deflate failed";

// ---- handle_stdout ----

/// `handle_stdout`, without `-f`.
pub(super) const STDOUT_IS_TERMINAL: &str = "standard output is a terminal -- ignoring";

/// `handle_stdout`: `fstat(STDIN_FILENO)` failed (after a failed output
/// creation has `fclose`d standard input).
pub(super) const CANT_STAT_STDIN: &str = "Can't stat stdin";

// ---- print_verbage, print_ratio ----

/// `print_verbage`: the input's name, then [`TABS_SHORT`] or [`TAB_LONG`]
/// and two spaces.
pub(super) const VERBOSE_NAME: &str = "%s:%s  ";

/// `print_verbage`: after a name shorter than 7 bytes.
pub(super) const TABS_SHORT: &str = "\t\t";

/// `print_verbage`: after a name of 7 bytes or more.
pub(super) const TAB_LONG: &str = "\t";

/// `print_ratio`: `"%5s%%"` of the formatted per-mille value.
pub(super) const RATIO: &str = "%s%%";

/// `print_verbage`: the output's name, when not `-c`.
pub(super) const REPLACED_WITH: &str = " -- replaced with %s";

// ---- stuffr's own ----

/// stuffr's own: the BSD personality's decompression, `-t` and `-l` are
/// built by a later task.
pub(super) const DECOMPRESS_NOT_BUILT: &str = concat!(
    "%s: decompression, -t and -l are not built yet ",
    "in stuffr's BSD personality\n"
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Ruling T9-1: only the first lines name stuffr; Apple's usage line
    /// stays Apple's.
    #[test]
    fn only_version_and_license_name_stuffr() {
        assert!(VERSION_FIRST_LINE.starts_with("Apple gzip (stuffr "));
        assert!(LICENSE_FIRST_LINE.starts_with("Apple gzip (stuffr "));
        assert!(!GZIP_VERSION.contains("stuffr"));
        assert!(!USAGE.contains("stuffr"));
        assert!(!LICENSE_REST.contains("stuffr"));
    }
}
