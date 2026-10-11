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
//! line byte for byte.

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

// ---- handle_pathname (decompressing), handle_stdin ----

/// `handle_stdin`, without `-f` or `-l`.
pub(super) const STDIN_IS_TERMINAL: &str = "standard input is a terminal -- ignoring";

/// `handle_stdin`: `fstat(STDIN_FILENO)` failed.
pub(super) const FSTAT: &str = "fstat";

/// `handle_stdin`: the first four bytes could not be read.
pub(super) const CANT_READ_STDIN: &str = "can't read stdin";

/// `handle_stdin`: fewer than four bytes.
pub(super) const STDIN_UNEXPECTED_EOF: &str = "(stdin): unexpected end of file";

/// `handle_stdin`: not a format `file_gettype` knows, without `-f`.
pub(super) const UNKNOWN_FORMAT: &str = "unknown compression format";

/// `handle_stdin`, `handle_stdin`'s `print_list` and `print_test`: the
/// name standard input goes by (`infile_set("(stdin)", ...)`).
pub(super) const STDIN_NAME: &str = "(stdin)";

// ---- file_uncompress ----

/// `file_uncompress`: `fstat` of the input failed.
pub(super) const CANT_STAT_FILE: &str = "can't stat %s";

/// `file_uncompress`: no suffix of the table, and neither `-c` nor `-l`.
pub(super) const UNKNOWN_SUFFIX: &str = "%s: unknown suffix -- ignored";

/// `file_uncompress`: reading the first four bytes failed.
pub(super) const CANT_READ: &str = "can't read %s";

/// `file_uncompress` (`unexpected_EOF`) and `gz_uncompress`.
pub(super) const UNEXPECTED_EOF: &str = "%s: unexpected end of file";

/// `file_uncompress`: not a format `file_gettype` knows, without `-f`.
pub(super) const NOT_IN_GZIP_FORMAT: &str = "%s: not in gzip format";

/// `file_uncompress`: more than one link without `-f` or `-l` (`%ju`,
/// never singular, unlike `file_compress`'s).
pub(super) const HAS_LINKS_UNCOMPRESS: &str = "%s has %s other links -- skipping";

/// `file_uncompress`: the exclusive create of the output failed.
pub(super) const CANT_OPEN_OUTPUT: &str = "can't open %s";

/// `file_uncompress`, under `-l`.
pub(super) const NO_L_BZIP2: &str = "no -l with bzip2 files";

/// `file_uncompress`, under `-l`.
pub(super) const NO_L_COMPRESS: &str = "no -l with Lempel-Ziv files";

/// `file_uncompress`, under `-l`.
pub(super) const NO_L_PACK: &str = "no -l with packed files";

/// `file_uncompress`, under `-l`.
pub(super) const NO_L_LZIP: &str = "no -l with lzip files";

/// `file_uncompress`, under `-l` with `-f`.
pub(super) const NO_L_UNKNOWN: &str = "no -l for unknown filetypes";

/// `file_uncompress`: the `.Z` decoder's stream reported an error
/// (`ferror(in)`; `errno` is `zread`'s `EFTYPE`).
pub(super) const FAILED_INFILE: &str = "failed infile";

/// `file_uncompress`: the decoder failed (`size == -1`).
pub(super) const UNCOMPRESS_FAILED: &str = "%s: uncompress failed";

/// `file_uncompress`: the output's size is not what was decoded.
pub(super) const DIFFERENT_SIZE: &str = "stat gave different size: %s != %s (leaving original)";

/// `file_uncompress`: the finished output could not be opened again.
pub(super) const COULDNT_OPEN_LEAVING: &str = "couldn't open (leaving original): %s";

// ---- gz_uncompress ----

/// `gz_uncompress`: `read` failed.
pub(super) const FAILED_TO_READ: &str = "failed to read stdin";

/// `gz_uncompress`: a byte other than `1f` where a member would start.
pub(super) const TRAILING_GARBAGE: &str = "%s: trailing garbage ignored";

/// `gz_uncompress`: `1f` and then neither `8b` nor `9e`.
pub(super) const NOT_GZIPED_MAGIC1: &str = "input not gziped (MAGIC1)";

/// `gz_uncompress`: CM is not 8.
pub(super) const UNKNOWN_METHOD: &str = "unknown compression method";

/// `gz_uncompress`: `inflate` returned `Z_DATA_ERROR`.
pub(super) const DATA_STREAM_ERROR: &str = "data stream error";

/// `gz_uncompress`: `write` of the output failed.
pub(super) const ERROR_WRITING: &str = "error writing to output";

/// `gz_uncompress`: the input ended inside CRC32 or ISIZE.
pub(super) const TRUNCATED_INPUT: &str = "truncated input";

/// `gz_uncompress`.
pub(super) const CRC_ERROR: &str = "invalid compressed data--crc error";

/// `gz_uncompress`.
pub(super) const LENGTH_ERROR: &str = "invalid compressed data--length error";

// ---- cat_fd ----

/// `cat_fd`: `write` to standard output failed.
pub(super) const WRITE_TO_STDOUT: &str = "write to stdout";

/// `cat_fd`: `read` failed; `%s` is the descriptor's number.
pub(super) const READ_FROM_FD: &str = "read from fd %s";

// ---- unbzip2 (each `maybe_errx`/`maybe_err` ends the run, exit 2) ----

/// `unbzip2`: the input ended inside a stream.
pub(super) const BZ_TRUNCATED: &str = "truncated file";

/// `unbzip2`: `read` failed (`maybe_err`).
pub(super) const BZ_READ: &str = "read";

/// `unbzip2`: `write` failed (`maybe_err`).
pub(super) const BZ_WRITE: &str = "write";

/// `unbzip2`: `BZ_DATA_ERROR` (a warning; the file fails).
pub(super) const BZ_DATA_ERROR: &str = "bzip2 data integrity error";

/// `unbzip2`: `BZ_DATA_ERROR_MAGIC` (a warning; the file fails).
pub(super) const BZ_MAGIC_ERROR: &str = "bzip2 magic number error";

/// `unbzip2`: `BZ_MEM_ERROR` (a warning; the file fails).
pub(super) const BZ_MEMORY: &str = "bzip2 out of memory";

/// `unbzip2`: any other result (a warning; the file fails).
pub(super) const BZ_UNKNOWN: &str = "unknown bzip2 error: %s";

// ---- unxz (`maybe_errx`/`maybe_err`: exit 2) ----

/// `unxz`: `read` failed (`maybe_err`).
pub(super) const XZ_READ_FAILED: &str = "read failed";

/// `unxz`: `lzma_stream_decoder` failed with the `lzma_ret` given.
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // liblzma's, the C tier
pub(super) const XZ_CANT_INITIALIZE: &str = "Can't initialize decoder (%s)";

/// `unxz`: `LZMA_FORMAT_ERROR`.
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // liblzma's, the C tier
pub(super) const XZ_FORMAT: &str = "File format not recognized";

/// `unxz`: any other `lzma_ret`.
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // liblzma's, the C tier
pub(super) const XZ_UNKNOWN: &str = "Unknown error (%s)";

/// `unxz`: the first `lzma_code`, on the stream header, failed with the
/// `lzma_ret` given.
pub(super) const XZ_CANT_READ_HEADERS: &str = "Can't read headers (%s)";

/// `unxz`: `write` failed (`maybe_err`).
pub(super) const XZ_WRITE_FAILED: &str = "write failed";

/// `unxz`: `LZMA_OPTIONS_ERROR`.
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // liblzma's, the C tier
pub(super) const XZ_OPTIONS: &str = "Unsupported compression options";

/// `unxz`: `LZMA_DATA_ERROR`, and bytes after the last stream.
pub(super) const XZ_CORRUPT: &str = "File is corrupt";

/// `unxz`: `LZMA_BUF_ERROR`.
pub(super) const XZ_UNEXPECTED_END: &str = "Unexpected end of input";

/// `unxz`: `LZMA_MEMLIMIT_ERROR`.
#[cfg_attr(not(feature = "xz-c"), allow(dead_code))] // liblzma's, the C tier
pub(super) const XZ_MEMLIMIT: &str = "Reached memory limit";

// ---- unpack (`maybe_errx`/`maybe_err`: exit 2) ----

/// `unpack_parse_header`: the level count is 0 or more than 24.
pub(super) const PACK_INSANE_LEVELS: &str = "Huffman tree has insane levels";

/// `unpack_parse_header`: the input ended in the level counts
/// (`maybe_err`: `errno` is whatever the last failed call left).
pub(super) const PACK_TRUNCATED: &str = "File appears to be truncated";

/// `unpack_parse_header`: more than 256 symbols.
pub(super) const PACK_BAD_TABLE: &str = "Bad symbol table";

/// `unpack_parse_header`: the input ended in the symbol table.
pub(super) const PACK_TABLE_TRUNCATED: &str = "Symbol table truncated";

/// `unpack_decode`: a code past the tree.
pub(super) const PACK_CORRUPT: &str = "File corrupt";

/// `unpack_decode`: the input ended before the length was reached.
pub(super) const PACK_PREMATURE_EOF: &str = "Premature EOF";

// ---- print_test ----

/// `print_test`: the name, [`TABS_SHORT`] or [`TAB_LONG`], two spaces and
/// the verdict.
pub(super) const TEST_LINE: &str = "%s:%s  %s\n";

/// `print_test`.
pub(super) const OK: &str = "OK";

/// `print_test`.
pub(super) const NOT_OK: &str = "NOT OK";

// ---- print_list, print_list_out (standard output) ----

/// `print_list`, first call, with `-v` (even under `-q`): no newline.
pub(super) const LIST_VERBOSE_HEADER: &str = "method  crc     date  time  ";

/// `print_list`, first call, unless `-q`.
pub(super) const LIST_HEADER: &str = "  compressed uncompressed  ratio uncompressed_name\n";

/// `print_list`: the last eight bytes could not be read.
pub(super) const READ_OF_SIZE: &str = "read of uncompressed size";

/// `print_list`, the totals line under `-v`.
pub(super) const LIST_VERBOSE_TOTALS: &str = "                            ";

/// `print_list` under `-v`: `"%5s %08x %11s "` of `"defla"`, the CRC and
/// `ctime`'s month, day and time.
pub(super) const LIST_VERBOSE_ROW: &str = "defla %s %s ";

/// `print_list_out`: `"%12llu %12llu "`, the ratio, the name.
pub(super) const LIST_ROW: &str = "%s %s ";

/// `print_list_out`, after the ratio.
pub(super) const LIST_NAME: &str = " %s\n";

/// `main`: the totals line's name.
pub(super) const TOTALS: &str = "(totals)";

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
