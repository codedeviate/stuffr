//! Every message the ncompress personality prints, copied from ncompress
//! 5.0's `compress.c` (the Unlicense, `LICENSE-ncompress`) as Ubuntu's
//! `5.0-1` builds it, and checked against Ubuntu's `/usr/bin/compress` and
//! Homebrew's 5.0. Formats keep C's `fprintf` layout and print through
//! [`printf`]: each conversion (`%s`, `%d`, `%i`, `%c`, `%jd`, `%02X`)
//! takes the next argument, which the caller has already formatted as C
//! would, and `%%` is a literal percent sign. The comment on each names the
//! function it comes from.
//!
//! The program name in the usage is `progname`, the base name of `argv[0]`
//! (`compress` or `uncompress`). `perror(s)` is [`PERROR`]: `s`, a colon
//! and `strerror(errno)`.
//!
//! One deliberate choice, ruling E6 of 0.18.0: [`ABOUT`]'s compile-option
//! lines are Ubuntu's build's (`FAST, ` and `IBUFSIZ=8192, OBUFSIZ=8192`)
//! on every platform, where Homebrew's read `FAST, LSTAT, ` and
//! `IBUFSIZ=1024, OBUFSIZ=1024`.

use std::io::Write;

/// Write `fmt` with each C conversion replaced by the next of `args`, and
/// `%%` by `%`. Write errors are ignored, as ncompress ignores
/// `fprintf`'s result.
pub(super) fn printf(w: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
    let mut out = Vec::with_capacity(fmt.len() + 64);
    let mut args = args.iter();
    let b = fmt.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        if b.get(i) == Some(&b'%') {
            out.push(b'%');
            i += 1;
            continue;
        }
        // Flags, width and length, then the conversion letter.
        while i < b.len() && !matches!(b[i], b's' | b'd' | b'i' | b'c' | b'X') {
            i += 1;
        }
        i += 1;
        out.extend_from_slice(args.next().copied().unwrap_or_default());
    }
    let _ = w.write_all(&out);
}

/// `perror(s)`: the subject, then `strerror(errno)`.
pub(super) const PERROR: &str = "%s: %s\n";

/// `perror("")`: an empty subject is left out with its colon.
pub(super) const PERROR_BARE: &str = "%s\n";

// ---- main ----

/// `main`, a flag not in the switch (then `Usage(1)`).
pub(super) const UNKNOWN_FLAG: &str = "Unknown flag: '%c'; ";

/// `main`, `-b` with nothing after it (then `Usage(1)`).
pub(super) const MISSING_MAXBITS: &str = "Missing maxbits\n";

/// `main`, standard input compressed under `-v` (then [`prratio`]'s
/// figure and a newline).
///
/// [`prratio`]: super::run
pub(super) const STDIN_COMPRESSION: &str = "Compression: ";

/// `main`, `-r` and nothing processed.
pub(super) const NO_FILES_RECURSIVE: &str = "no files processed after recursive search\n";

// ---- Usage ----

/// `Usage(status)`: to standard output for `-h` (exit 0), to standard
/// error after an error (exit 1); `progname`.
pub(super) const USAGE: &str = concat!(
    "Usage: %s [-dfhvcVr] [-b maxbits] [--] [path ...]\n",
    "  --   Halt option processing and treat all remaining args as paths.\n",
    "  -d   If given, decompression is done instead.\n",
    "  -c   Write output on stdout, don't remove original.\n",
    "  -k   Keep input files (do not automatically remove).\n",
    "  -b   Parameter limits the max number of bits/code.\n",
    "  -f   Forces output file to be generated, even if one already.\n",
    "       exists, and even if no space is saved by compressing.\n",
    "       If -f is not used, the user will be prompted if stdin is.\n",
    "       a tty, otherwise, the output file will not be overwritten.\n",
    "  -h   This help output.\n",
    "  -v   Write compression statistics.\n",
    "  -V   Output version and compile options.\n",
    "  -r   Recursive. If a path is a directory, compress everything in it.\n",
);

// ---- comprexx ----

/// `comprexx`, a name that does not exist with `.Z` added, found but not a
/// regular file.
pub(super) const NOT_REGULAR: &str = "%s: Not a regular file.\n";

/// `comprexx`, a directory without `-r`, under `-v`.
pub(super) const IS_DIRECTORY: &str = "%s is a directory -- ignored\n";

/// `comprexx`, decompressing a name without `.Z`, under `-v`.
pub(super) const NO_Z_SUFFIX: &str = "%s - no .Z suffix\n";

/// `comprexx`, compressing a name that has `.Z` (not under `-r`).
pub(super) const HAS_Z_SUFFIX: &str = "%s: already has .Z suffix -- no change\n";

/// `comprexx`, compressing an input with other hard links, without `-f`.
pub(super) const OTHER_LINKS: &str = "%s has %jd other links: unchanged\n";

/// `comprexx`, an existing output without `-f`.
pub(super) const ALREADY_EXISTS: &str = "%s already exists.\n";

/// `comprexx`, the question, when in the foreground and standard input is
/// a terminal.
pub(super) const OVERWRITE: &str = "Do you wish to overwrite %s (y or n)? ";

/// `comprexx`, any answer but `y`.
pub(super) const NOT_OVERWRITTEN: &str = "%s not overwritten\n";

/// `comprexx`, `unlink` of the existing output failed (then `perror`).
pub(super) const CANT_REMOVE: &str = "Can't remove old output file\n";

/// `comprexx`, `-v`: the input's name before the work.
pub(super) const NAME: &str = "%s: ";

/// `comprexx`, no saving (or nothing read), under `-v`.
pub(super) const NO_COMPRESSION: &str = "No compression -- %s unchanged\n";

/// `comprexx`, the empty output's `unlink` failed (then `perror`).
pub(super) const UNLINK_ERROR_NL: &str = "\nunlink error (ignored) ";

/// `comprexx`, the no-saving output's `unlink` failed (then `perror`).
pub(super) const UNLINK_ERROR: &str = "unlink error (ignored) ";

/// `comprexx`, success under `-v`.
pub(super) const REPLACED_WITH: &str = " -- replaced with %s";

/// `comprexx`, success under `-v` when compressing (then [`prratio`]'s
/// figure).
///
/// [`prratio`]: super::run
pub(super) const COMPRESSION: &str = " Compression: ";

/// `comprexx`, after the `-v` line.
pub(super) const NEWLINE: &str = "\n";

/// `comprexx`, `utime` failed (then `perror`).
pub(super) const UTIME_ERROR: &str = "\nutime error (ignored) ";

/// `comprexx`, `chmod` failed (then `perror`).
pub(super) const CHMOD_ERROR: &str = "\nchmod error (ignored) ";

/// `comprexx`, `chown` failed (then `perror`).
pub(super) const CHOWN_ERROR: &str = "\nchown error (ignored) ";

/// `comprexx`, neither a directory nor a regular file.
pub(super) const NOT_DIR_OR_REGULAR: &str = "%s is not a directory or a regular file - ignored\n";

// ---- compdir ----

/// `compdir`, `opendir` failed: `printf`, to standard output ("not
/// stderr!").
pub(super) const UNREADABLE: &str = "%s unreadable\n";

// ---- decompress ----

/// `decompress`, bytes that are not a `.Z` header (`stdin` for standard
/// input).
pub(super) const NOT_COMPRESSED: &str = "%s: not in compressed format\n";

/// `decompress`, a header asking for more than `BITS` bits.
pub(super) const TOO_MANY_BITS: &str = "%s: compressed with %d bits, can only handle %d bits\n";

/// `decompress`, a first code past 255.
pub(super) const FIRST_CODE: &str = "oldcode:-1 code:%i\n";

/// `decompress`, a code past the next free entry: the input buffer's state.
pub(super) const BAD_CODE: &str = "insize:%d posbits:%d inbuf:%02X %02X %02X %02X %02X (%d)\n";

/// `decompress`, after either of the two above (the name is fixed, even
/// as `compress -d` or Ubuntu's `uncompress.real`).
pub(super) const CORRUPT_INPUT: &str = "uncompress: corrupt input\n";

// ---- read_error, write_error ----

/// `read_error` (then `perror` of the input's name, or `stdin`).
pub(super) const READ_ERROR: &str = "\nread error on";

/// `write_error` (then `perror` of the output's name, or `stdout`).
pub(super) const WRITE_ERROR: &str = "\nwrite error on";

// ---- about ----

/// `about()`, `-V`, to standard output: `version_id` and Ubuntu's build's
/// compile options (ruling E6; see the module doc).
pub(super) const ABOUT: &str = concat!(
    "Compress version: (N)compress 5.0\n",
    "Compile options:\n",
    "        FAST, \n",
    "        IBUFSIZ=8192, OBUFSIZ=8192, BITS=16\n",
    "\n",
    "Author version 5.x (Modernization):\n",
    "Author version 4.2.4.x (Maintenance):\n",
    "     Mike Frysinger  (vapier@gmail.com)\n",
    "\n",
    "Author version 4.2 (Speed improvement & source cleanup):\n",
    "     Peter Jannesen  (peter@ncs.nl)\n",
    "\n",
    "Author version 4.1 (Added recursive directory compress):\n",
    "     Dave Mack  (csu@alembic.acs.com)\n",
    "\n",
    "Authors version 4.0 (World release in 1985):\n",
    "     Spencer W. Thomas, Jim McKie, Steve Davies,\n",
    "     Ken Turkowski, James A. Woods, Joe Orost\n",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printf_takes_any_conversion_in_order() {
        let mut out = Vec::new();
        printf(
            &mut out,
            BAD_CODE,
            &[b"9", b"42", b"06", b"00", b"FF", b"FF", b"FF", b"2"],
        );
        assert_eq!(out, b"insize:9 posbits:42 inbuf:06 00 FF FF FF (2)\n");
        let mut out = Vec::new();
        printf(&mut out, OTHER_LINKS, &[b"f", b"1"]);
        assert_eq!(out, b"f has 1 other links: unchanged\n");
        let mut out = Vec::new();
        printf(&mut out, "%c%%", &[b"x"]);
        assert_eq!(out, b"x%");
    }

    /// The `-V` text is Ubuntu's, byte for byte (the record's
    /// "ncompress `-V` stdout, Ubuntu 5.0-1").
    #[test]
    fn about_is_ubuntus() {
        assert_eq!(ABOUT.len(), 556);
        assert!(
            ABOUT.contains("\n        FAST, \n        IBUFSIZ=8192, OBUFSIZ=8192, BITS=16\n\n")
        );
    }
}
