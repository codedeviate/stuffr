//! Every message the bzip2 family prints, copied verbatim from bzip2 1.0.8's
//! `bzip2.c` (see `LICENSE-bzip2`). Each format string keeps the C
//! `fprintf` layout: `%s` and `%d` take an argument in order (integers are
//! formatted by the caller), `%%` is a literal percent sign. The comment on
//! each names the function in `bzip2.c` it comes from.
//!
//! The one deliberate change is [`LICENSE_FIRST_LINE`]: the licence text
//! names stuffr and its version on its first line, as `--version` must.

use std::io::Write;

/// `BZ2_bzlibVersion()` in bzip2 1.0.8, which `usage` and `license` print.
pub(super) const BZLIB_VERSION: &str = "1.0.8, 13-Jul-2019";

/// `license`: its first line, changed to name stuffr (the only change).
pub(super) const LICENSE_FIRST_LINE: &str = concat!(
    "bzip2 (stuffr ",
    env!("CARGO_PKG_VERSION"),
    "), a block-sorting file compressor.  ",
    "Version 1.0.8, 13-Jul-2019.\n"
);

/// `license`: everything after its first line, verbatim.
pub(super) const LICENSE_REST: &str = concat!(
    "   \n",
    "   Copyright (C) 1996-2019 by Julian Seward.\n",
    "   \n",
    "   This program is free software; you can redistribute it and/or modify\n",
    "   it under the terms set out in the LICENSE file, which is included\n",
    "   in the bzip2 source distribution.\n",
    "   \n",
    "   This program is distributed in the hope that it will be useful,\n",
    "   but WITHOUT ANY WARRANTY; without even the implied warranty of\n",
    "   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n",
    "   LICENSE file for more details.\n",
    "   \n",
);

/// `usage`: arguments are `BZ2_bzlibVersion()` and the program name.
pub(super) const USAGE: &str = concat!(
    "bzip2, a block-sorting file compressor.  ",
    "Version %s.\n",
    "\n   usage: %s [flags and input files in any order]\n",
    "\n",
    "   -h --help           print this message\n",
    "   -d --decompress     force decompression\n",
    "   -z --compress       force compression\n",
    "   -k --keep           keep (don't delete) input files\n",
    "   -f --force          overwrite existing output files\n",
    "   -t --test           test compressed file integrity\n",
    "   -c --stdout         output to standard out\n",
    "   -q --quiet          suppress noncritical error messages\n",
    "   -v --verbose        be verbose (a 2nd -v gives more)\n",
    "   -L --license        display software version & license\n",
    "   -V --version        display software version & license\n",
    "   -s --small          use less memory (at most 2500k)\n",
    "   -1 .. -9            set block size to 100k .. 900k\n",
    "   --fast              alias for -1\n",
    "   --best              alias for -9\n",
    "\n",
    "   If invoked as `bzip2', default action is to compress.\n",
    "              as `bunzip2',  default action is to decompress.\n",
    "              as `bzcat', default action is to decompress to stdout.\n",
    "\n",
    "   If no file names are given, bzip2 compresses or decompresses\n",
    "   from standard input to standard output.  You can combine\n",
    "   short flags, so `-v -4' means the same as -v4 or -4v, &c.\n",
    // `#if BZ_UNIX`
    "\n",
);

/// `redundant`.
pub(super) const REDUNDANT: &str = "%s: %s is redundant in versions 0.9.5 and above\n";

/// `main`: an unknown short or long flag (followed by `usage`).
pub(super) const BAD_FLAG: &str = "%s: Bad flag `%s'\n";

/// `main`.
pub(super) const C_AND_T: &str = "%s: -c and -t cannot be used together.\n";

/// `main`: after testing, when any file failed.
pub(super) const TEST_FAILS_ADVICE: &str = concat!(
    "\n",
    "You can use the `bzip2recover' program to attempt to recover\n",
    "data from undamaged sections of corrupted files.\n\n"
);

/// `copyFileName`: note the literal `bzip2`, not the program name.
pub(super) const NAME_TOO_LONG: &str = concat!(
    "bzip2: file name\n`%s'\n",
    "is suspiciously (more than %d chars) long.\n",
    "Try using a reasonable file name instead.  Sorry! :-)\n"
);

/// `compress`, `uncompress`: the existence check or opening the input.
pub(super) const CANT_OPEN_INPUT: &str = "%s: Can't open input file %s: %s.\n";

/// `uncompress`, `testf`: opening the input with `-c` or `-t` (no space
/// after the colon, as in bzip2.c).
pub(super) const CANT_OPEN_INPUT_NOSPACE: &str = "%s: Can't open input file %s:%s.\n";

/// `testf`: the existence check.
pub(super) const CANT_OPEN_INPUT_TEST: &str = "%s: Can't open input %s: %s.\n";

/// `compress`.
pub(super) const HAS_SUFFIX: &str = "%s: Input file %s already has %s suffix.\n";

/// `compress`, `uncompress`, `testf`.
pub(super) const IS_DIRECTORY: &str = "%s: Input file %s is a directory.\n";

/// `compress`, `uncompress`.
pub(super) const NOT_NORMAL_FILE: &str = "%s: Input file %s is not a normal file.\n";

/// `compress`, `uncompress`.
pub(super) const OUTPUT_EXISTS: &str = "%s: Output file %s already exists.\n";

/// `compress`, `uncompress`: the last argument is `"s"` or `""`.
pub(super) const HARD_LINKS: &str = "%s: Input file %s has %d other link%s.\n";

/// `compress`.
pub(super) const NO_TTY_OUTPUT: &str = "%s: I won't write compressed data to a terminal.\n";

/// `uncompress`, `testf`.
pub(super) const NO_TTY_INPUT: &str = "%s: I won't read compressed data from a terminal.\n";

/// `compress`, `uncompress`, `testf`: after a terminal refusal.
pub(super) const FOR_HELP: &str = "%s: For help, type: `%s --help'.\n";

/// `compress`, `uncompress`.
pub(super) const CANT_CREATE_OUTPUT: &str = "%s: Can't create output file %s: %s.\n";

/// `uncompress`.
pub(super) const CANT_GUESS: &str = "%s: Can't guess original name for %s -- using %s\n";

/// `compress`, `uncompress`, `testf`: the `-v` line prefix (then `pad`).
pub(super) const VERBOSE_PREFIX: &str = "  %s: ";

/// `compressStream`: `-v` with empty input.
pub(super) const NO_DATA: &str = " no data compressed.\n";

/// `uncompress`: `-v`, success.
pub(super) const DONE: &str = "done\n";

/// `uncompress`: `-v`, first stream not bzip2.
pub(super) const NOT_BZIP2_VERBOSE: &str = "not a bzip2 file.\n";

/// `uncompress`: first stream not bzip2.
pub(super) const NOT_BZIP2: &str = "%s: %s is not a bzip2 file.\n";

/// `testf`: `-v`, success.
pub(super) const OK: &str = "ok\n";

/// `uncompressStream`.
pub(super) const TRAILING_GARBAGE: &str = "\n%s: %s: trailing garbage after EOF ignored\n";

/// `testStream`: the prefix before a failure, at verbosity 0.
pub(super) const TEST_PREFIX: &str = "%s: %s: ";

/// `testStream`.
pub(super) const TEST_CRC: &str = "data integrity (CRC) error in data\n";

/// `testStream`.
pub(super) const TEST_EOF: &str = "file ends unexpectedly\n";

/// `testStream`.
pub(super) const TEST_MAGIC: &str = "bad magic number (file not created by bzip2)\n";

/// `testStream`.
pub(super) const TEST_TRAILING_GARBAGE: &str = "trailing garbage after EOF ignored\n";

/// `cadvise`.
pub(super) const CADVISE: &str = concat!(
    "\nIt is possible that the compressed file(s) have become corrupted.\n",
    "You can use the -tvv option to test integrity of such files.\n\n",
    "You can use the `bzip2recover' program to attempt to recover\n",
    "data from undamaged sections of corrupted files.\n\n"
);

/// `showFileNames`.
pub(super) const SHOW_FILE_NAMES: &str = "\tInput file = %s, output file = %s\n";

/// `cleanUpAndFail`.
pub(super) const DELETING_OUTPUT: &str = "%s: Deleting output file %s, if it exists.\n";

/// `cleanUpAndFail`.
pub(super) const DELETION_FAILED: &str =
    "%s: WARNING: deletion of output file (apparently) failed.\n";

/// `cleanUpAndFail`: the input has gone, so the output is kept.
pub(super) const DELETION_SUPPRESSED: &str = "%s: WARNING: deletion of output file suppressed\n";
/// `cleanUpAndFail`.
pub(super) const SINCE_INPUT_GONE: &str =
    "%s:    since input file no longer exists.  Output file\n";
/// `cleanUpAndFail`.
pub(super) const MAY_BE_INCOMPLETE: &str = "%s:    `%s' may be incomplete.\n";
/// `cleanUpAndFail`.
pub(super) const SUGGEST_TEST: &str =
    "%s:    I suggest doing an integrity test (bzip2 -tv) of it.\n";

/// `cleanUpAndFail`.
pub(super) const NOT_PROCESSED: &str = concat!(
    "%s: WARNING: some files have not been processed:\n",
    "%s:    %d specified on command line, %d not processed yet.\n\n"
);

/// `panic`.
pub(super) const PANIC: &str = concat!(
    "\n%s: PANIC -- internal consistency error:\n",
    "\t%s\n",
    "\tThis is a BUG.  Please report it to:\n",
    "\tbzip2-devel@sourceware.org\n"
);

/// `crcError`.
pub(super) const CRC_ERROR: &str = "\n%s: Data integrity error when decompressing.\n";

/// `compressedStreamEOF`.
pub(super) const STREAM_EOF: &str = concat!(
    "\n%s: Compressed file ends unexpectedly;\n\t",
    "perhaps it is corrupted?  *Possible* reason follows.\n"
);

/// `ioError`.
pub(super) const IO_ERROR: &str = concat!(
    "\n%s: I/O or other error, bailing out.  ",
    "Possible reason follows.\n"
);

/// `outOfMemory`.
pub(super) const OUT_OF_MEMORY: &str = "\n%s: couldn't allocate enough memory\n";

/// What C's `perror(s)` prints.
pub(super) const PERROR: &str = "%s: %s\n";

/// Write `fmt` with `%s`/`%d` replaced by `args` in order and `%%` by `%`,
/// as C's `fprintf` does for these formats. Write errors are ignored, as
/// bzip2 ignores `fprintf`'s result.
pub(super) fn printf(w: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
    let mut out = Vec::with_capacity(fmt.len() + 64);
    let mut args = args.iter();
    let mut bytes = fmt.as_bytes().iter().copied();
    while let Some(b) = bytes.next() {
        if b != b'%' {
            out.push(b);
            continue;
        }
        match bytes.next() {
            Some(b'%') => out.push(b'%'),
            Some(b's' | b'd') => out.extend_from_slice(args.next().copied().unwrap_or_default()),
            // Only `%s`, `%d` and `%%` occur in the strings above.
            Some(other) => out.extend_from_slice(&[b'%', other]),
            None => out.push(b'%'),
        }
    }
    let _ = w.write_all(&out);
}

/// `compressStream`: the `-v` statistics line, whose C format is
/// `"%6.3f:1, %6.3f bits/byte, %5.2f%% saved, %s in, %s out.\n"`, with the
/// same arithmetic. `%6.3f` and `%5.2f` are correctly rounded from the exact
/// binary value in both C and Rust, so the digits agree.
pub(super) fn stats(nbytes_in: u64, nbytes_out: u64) -> String {
    let (i, o) = (nbytes_in as f64, nbytes_out as f64);
    format!(
        "{:6.3}:1, {:6.3} bits/byte, {:5.2}% saved, {} in, {} out.\n",
        i / o,
        (8.0 * o) / i,
        100.0 * (1.0 - o / i),
        nbytes_in,
        nbytes_out
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(fmt: &str, args: &[&[u8]]) -> String {
        let mut v = Vec::new();
        printf(&mut v, fmt, args);
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn printf_substitutes_in_order() {
        assert_eq!(
            p(
                CANT_OPEN_INPUT,
                &[b"bzip2", b"f", b"No such file or directory"]
            ),
            "bzip2: Can't open input file f: No such file or directory.\n"
        );
        assert_eq!(
            p(HARD_LINKS, &[b"bzip2", b"a", b"2", b"s"]),
            "bzip2: Input file a has 2 other links.\n"
        );
        assert_eq!(p("100%% %s", &[b"x"]), "100% x");
    }

    #[test]
    fn stats_matches_bzip2s_layout() {
        assert_eq!(
            stats(100, 19),
            " 5.263:1,  1.520 bits/byte, 81.00% saved, 100 in, 19 out.\n"
        );
        // Expansion: a negative saving and a ratio under one.
        assert_eq!(
            stats(1, 40),
            " 0.025:1, 320.000 bits/byte, -3900.00% saved, 1 in, 40 out.\n"
        );
    }

    /// Ties on an exactly representable value: C's printf rounds half to
    /// even on the exact binary value, and so does Rust's formatter.
    #[test]
    fn float_ties_round_like_c() {
        assert_eq!(format!("{:5.2}", 0.125), " 0.12");
        assert_eq!(format!("{:5.2}", 0.375), " 0.38");
        assert_eq!(format!("{:6.3}", 2.0625), " 2.062");
    }

    #[test]
    fn usage_ends_with_the_unix_blank_line() {
        assert!(USAGE.ends_with("&c.\n\n"));
        assert_eq!(USAGE.matches("%s").count(), 2);
    }

    #[test]
    fn license_first_line_names_stuffr() {
        assert!(LICENSE_FIRST_LINE.starts_with("bzip2 (stuffr "));
        assert!(LICENSE_FIRST_LINE.ends_with("Version 1.0.8, 13-Jul-2019.\n"));
    }
}
