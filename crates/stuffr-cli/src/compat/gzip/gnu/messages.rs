//! Every message the GNU personality prints, as GNU gzip 1.15 prints it.
//!
//! GNU gzip is GPLv3 and its source is never read: each string here was
//! observed by running the binary (`/opt/homebrew/opt/gzip/bin/gzip` 1.15,
//! with `LANG=C`) or copied from its `--help` output, and the comment on
//! each names the command that shows it. Formats follow C's `fprintf`
//! (`%s` and `%d` take an argument in order, integers formatted by the
//! caller, `%%` is a literal percent sign) and print through
//! [`printf`].
//!
//! The deliberate changes: `--version`/`-V`/`-L` (and the `gunzip`/`zcat`
//! scripts' `--version`) name stuffr and its version on the first line and
//! print stuffr's own MIT notice after it, never GNU's (Ruling T7-2).
//! [`BSD_NOT_BUILT`] is stuffr's own, for the flavour a later task fills
//! in.

pub(super) use crate::compat::host::printf;

/// The program name every non-getopt message carries: GNU's `gunzip` and
/// `zcat` are scripts that exec `gzip`. Observed: `gunzip -S '' x`.
pub(super) const PROGRAM: &[u8] = b"gzip";

/// Observed: `gzip --help` (also `-h`, `-H`; standard output, exit 0).
pub(super) const HELP: &str = concat!(
    "Usage: %s [OPTION]... [FILE]...\n",
    "Compress or uncompress FILEs (by default, compress FILES in-place).\n",
    "\n",
    "Mandatory arguments to long options are mandatory for short options too.\n",
    "\n",
    "  -c, --stdout      write on standard output, keep original files unchanged\n",
    "  -d, --decompress  decompress\n",
    "  -f, --force       force overwrite of output file and compress links\n",
    "  -h, --help        give this help\n",
    "  -k, --keep        keep (don't delete) input files\n",
    "  -l, --list        list compressed file contents\n",
    "  -L, --license     display software license\n",
    "  -n, --no-name     do not save or restore the original name and timestamp\n",
    "  -N, --name        save or restore the original name and timestamp\n",
    "  -q, --quiet       suppress all warnings\n",
    "  -r, --recursive   operate recursively on directories\n",
    "      --rsyncable   make rsync-friendly archive\n",
    "  -S, --suffix=SUF  use suffix SUF on compressed files\n",
    "      --synchronous synchronous output (safer if system crashes, but slower)\n",
    "  -t, --test        test compressed file integrity\n",
    "  -v, --verbose     verbose mode\n",
    "  -V, --version     display version number\n",
    "  -1, --fast        compress faster\n",
    "  -9, --best        compress better\n",
    "\n",
    "With no FILE, or when FILE is -, read standard input.\n",
    "\n",
    "Report bugs to <bug-gzip@gnu.org>.\n",
);

/// `--version`/`-V`/`-L`: the first line, changed to name stuffr. GNU's
/// is `gzip 1.15`; the layout `PROGRAM (PACKAGE) VERSION` is the one its
/// own scripts print (`gunzip (gzip) 1.15`).
pub(super) const VERSION_FIRST_LINE: &str =
    concat!("gzip (stuffr ", env!("CARGO_PKG_VERSION"), ") 1.15\n");

/// Ruling T7-2: after the first line, `-L`/`--license` print stuffr's own
/// notice in the shape of GNU's block, never GNU's copyright or licence
/// text (stuffr is MIT and holds no GNU code). The holder is the
/// workspace `LICENSE`'s.
pub(super) const LICENSE_REST: &str = concat!(
    "Copyright (c) 2026 Thomas Bjork\n",
    "License MIT: <https://opensource.org/license/mit>.\n",
    "This is stuffr emulating GNU gzip's command-line interface; it contains no GNU code.\n",
    "It is provided as is, without warranty of any kind.\n",
);

/// Ruling T7-2: what `--version`/`-V` add after [`LICENSE_REST`].
pub(super) const WRITTEN_BY: &str = "\nWritten by Thomas Bjork, for stuffr.\n";

/// Observed: `gunzip --help`, the script's own text when `--help` is its
/// first argument; `%s` is the script's `$0`.
pub(super) const GUNZIP_HELP: &str = concat!(
    "Usage: %s [OPTION]... [FILE]...\n",
    "Uncompress FILEs (by default, in-place).\n",
    "\n",
    "Mandatory arguments to long options are mandatory for short options too.\n",
    "\n",
    "  -c, --stdout      write on standard output, keep original files unchanged\n",
    "  -f, --force       force overwrite of output file and compress links\n",
    "  -k, --keep        keep (don't delete) input files\n",
    "  -l, --list        list compressed file contents\n",
    "  -n, --no-name     do not save or restore the original name and timestamp\n",
    "  -N, --name        save or restore the original name and timestamp\n",
    "  -q, --quiet       suppress all warnings\n",
    "  -r, --recursive   operate recursively on directories\n",
    "  -S, --suffix=SUF  use suffix SUF on compressed files\n",
    "      --synchronous synchronous output (safer if system crashes, but slower)\n",
    "  -t, --test        test compressed file integrity\n",
    "  -v, --verbose     verbose mode\n",
    "      --help        display this help and exit\n",
    "      --version     display version information and exit\n",
    "\n",
    "With no FILE, or when FILE is -, read standard input.\n",
    "\n",
    "Report bugs to <bug-gzip@gnu.org>.\n",
);

/// Observed: `zcat --help`, the script's own text; `%s` is its `$0`.
pub(super) const ZCAT_HELP: &str = concat!(
    "Usage: %s [OPTION]... [FILE]...\n",
    "Uncompress FILEs to standard output.\n",
    "\n",
    "  -f, --force       force; read compressed data even from a terminal\n",
    "  -l, --list        list compressed file contents\n",
    "  -q, --quiet       suppress all warnings\n",
    "  -r, --recursive   operate recursively on directories\n",
    "  -S, --suffix=SUF  use suffix SUF on compressed files\n",
    "      --synchronous synchronous output (safer if system crashes, but slower)\n",
    "  -t, --test        test compressed file integrity\n",
    "  -v, --verbose     verbose mode\n",
    "      --help        display this help and exit\n",
    "      --version     display version information and exit\n",
    "\n",
    "With no FILE, or when FILE is -, read standard input.\n",
    "\n",
    "Report bugs to <bug-gzip@gnu.org>.\n",
);

/// The scripts' `--version` first line, changed to name stuffr: GNU's is
/// `gunzip (gzip) 1.15` / `zcat (gzip) 1.15`. `%s` is the invoked name.
pub(super) const SCRIPT_VERSION_FIRST_LINE: &str =
    concat!("%s (stuffr ", env!("CARGO_PKG_VERSION"), ") 1.15\n");

/// Ruling T7-2: the scripts' `--version` after the first line: stuffr's
/// notice, as [`LICENSE_REST`] and [`WRITTEN_BY`].
pub(super) const SCRIPT_VERSION_REST: &str = concat!(
    "Copyright (c) 2026 Thomas Bjork\n",
    "License MIT: <https://opensource.org/license/mit>.\n",
    "This is stuffr emulating GNU gzip's command-line interface; it contains no GNU code.\n",
    "It is provided as is, without warranty of any kind.\n",
    "\n",
    "Written by Thomas Bjork, for stuffr.\n",
);

// ---- getopt (prefixed by the full argv[0]) ----

/// Observed: `gzip -x`.
pub(super) const INVALID_OPTION: &str = "%s: invalid option -- '%s'\n";

/// Observed: `gzip --bogus=1` (the argument as typed).
pub(super) const UNRECOGNIZED: &str = "%s: unrecognized option '%s'\n";

/// Observed: `gzip --s=x`; each candidate follows as [`CANDIDATE`], then a
/// newline.
pub(super) const AMBIGUOUS: &str = "%s: option '%s' is ambiguous; possibilities:";

/// Observed: `gzip --s`, one per candidate in table order.
pub(super) const CANDIDATE: &str = " '--%s'";

/// Observed: `gzip -S`.
pub(super) const NEEDS_ARGUMENT_SHORT: &str = "%s: option requires an argument -- '%s'\n";

/// Observed: `gzip --su` (the full option name).
pub(super) const NEEDS_ARGUMENT_LONG: &str = "%s: option '--%s' requires an argument\n";

/// Observed: `gzip --he=x` (the full option name).
pub(super) const NO_ARGUMENT_LONG: &str = "%s: option '--%s' doesn't allow an argument\n";

/// Observed: `gzip -x`, after every option error (and alone for `-?`).
pub(super) const TRY_HELP: &str = "Try `%s --help' for more information.\n";

// ---- options ----

/// Observed: `gzip -Z` (then [`TRY_HELP`], exit 1).
pub(super) const LZW: &str = "%s: -Z not supported in this version\n";

/// Observed: `gzip -b x` (then [`TRY_HELP`], exit 1).
pub(super) const BITS_NOT_INTEGER: &str = "%s: -b operand is not an integer\n";

/// Observed: `gzip -S x/y a` (exit 1, no [`TRY_HELP`]).
pub(super) const SUFFIX_SLASH: &str = "%s: suffix contains '/'\n";

/// Observed: `gzip -S '' a`; the suffix is quoted as a file name is.
pub(super) const INVALID_SUFFIX: &str = "%s: %s: invalid suffix\n";

/// Observed: `gzip -a a` (after option parsing; not with `-q`).
pub(super) const ASCII_IGNORED: &str = "%s: option --ascii ignored on this system\n";

// ---- files ----

/// Observed: `gzip nonexist`, `gzip l` (a symlink), `chmod 0 a; gzip a`.
pub(super) const OPEN_FAILED: &str = "%s: %s: %s\n";

/// Observed: `gzip d`.
pub(super) const IS_DIRECTORY: &str = "%s: %s is a directory -- ignored\n";

/// Observed: `mkfifo f; gzip f`.
pub(super) const NOT_REGULAR: &str = "%s: %s is not a directory or a regular file - ignored\n";

/// Observed: `ln a h; gzip h`; the last argument is `"s"` or `""`.
pub(super) const HAS_LINKS: &str = "%s: %s has %d other link%s -- file ignored\n";

/// Observed: `chmod 4755 a; gzip a` (exit 2, also under `-f`; `-q`
/// silences it; `-c` compresses).
pub(super) const SET_USER_ID: &str = "%s: %s is set-user-ID on execution - ignored\n";

/// Observed: `chmod 1644 a; gzip a` (exit 2; `-f` compresses; `-c`
/// compresses).
pub(super) const STICKY: &str = "%s: %s has the sticky bit set - file ignored\n";

/// Observed: `gzip a.gz` (under `-r` only with `-v`: `gzip -r d`).
pub(super) const HAS_SUFFIX: &str = "%s: %s already has %s suffix -- unchanged\n";

/// Observed: `gzip a` with `a.gz` present: this, then [`ASK_OVERWRITE`]
/// when standard input is a terminal, then [`NOT_OVERWRITTEN`] unless the
/// answer is yes.
pub(super) const ALREADY_EXISTS: &str = "%s: %s already exists;";

/// Observed: `gzip a` with `a.gz` present, standard input a terminal.
pub(super) const ASK_OVERWRITE: &str = " do you wish to overwrite (y or n)? ";

/// Observed: `gzip a` with `a.gz` present.
pub(super) const NOT_OVERWRITTEN: &str = "\tnot overwritten\n";

/// Observed: `touch -t 196001010000 old; gzip -c old`.
pub(super) const TIMESTAMP_RANGE: &str =
    "%s: %s: warning: file timestamp out of range for gzip format\n";

/// Observed: `gzip < /dev/null` with a terminal on standard output.
pub(super) const NOT_TO_TERMINAL: &str = concat!(
    "%s: compressed data not written to a terminal. ",
    "Use -f to force compression.\n",
    "For help, type: %s -h\n"
);

/// Observed: `gzip -v a`: the name, before compressing.
pub(super) const VERBOSE_NAME: &str = "%s:\t";

/// Observed: `gzip -v a`: after the ratio, the output replaced the input.
pub(super) const REPLACED_WITH: &str = " -- replaced with %s\n";

/// Observed: `gzip -kv a`: after the ratio, the input kept.
pub(super) const CREATED: &str = " -- created %s\n";

/// Observed: `gzip -cv a`: the output name in [`REPLACED_WITH`] and
/// [`CREATED`].
pub(super) const STDOUT_NAME: &[u8] = b"stdout";

/// Observed: `gzip a b -`: what FNAME holds for standard input compressed
/// after a file.
pub(super) const STDIN_NAME: &[u8] = b"stdin";

/// The read or write error on a stream, in the shape of [`OPEN_FAILED`]:
/// `gzip: stdin: …` or `gzip: NAME: …`. Observed for the unlink `-f`
/// does first: `gzip -df a.gz` with a directory `a` says `gzip: a:
/// Operation not permitted`, no leading newline. A full disk was not
/// reproduced; read and write errors take the same shape.
pub(super) const IO_FAILED: &str = "%s: %s: %s\n";

// ---- decompression, -t and -l ----
//
// A leading `\n` is part of the text where the binary prints one: it does
// for every data error and for a failure to create the output, whether or
// not anything was written before it (observed: `gzip -dc empty.gz` prints
// `\ngzip: empty.gz: unexpected end of file`), and not for the refusals
// read from a header's fixed fields (method, flags) or a suffix.

/// Observed: `gzip -d < x.gz` with a terminal on standard input (also `-t`;
/// `-l` reads the terminal; exit 1, the run stops; `-q` silences it).
pub(super) const NOT_FROM_TERMINAL: &str = concat!(
    "%s: compressed data not read from a terminal. ",
    "Use -f to force decompression.\n",
    "For help, type: %s -h\n"
);

/// Observed: `gzip -d f.x` (exit 2; with `-q` silent and exit 0; under `-r`
/// only with `-v`).
pub(super) const UNKNOWN_SUFFIX: &str = "%s: %s: unknown suffix -- ignored\n";

/// Observed: `gzip -dc notgz` (exit 1, the run goes on).
pub(super) const NOT_GZIP: &str = "\n%s: %s: not in gzip format\n";

/// Observed: `gzip -dc` on an empty, a one-byte or a cut-short input (exit
/// 1, the run stops there).
pub(super) const UNEXPECTED_EOF: &str = "\n%s: %s: unexpected end of file\n";

/// Observed: `gzip -dc` on a member whose CRC32 trailer is wrong.
pub(super) const CRC_ERROR: &str = "\n%s: %s: invalid compressed data--crc error\n";

/// Observed: `gzip -dc` on a member whose ISIZE trailer is wrong, and on a
/// pack stream whose length field is.
pub(super) const LENGTH_ERROR: &str = "\n%s: %s: invalid compressed data--length error\n";

/// Observed: `gzip -dc` on a zip entry whose data descriptor is wrong or
/// cut short.
pub(super) const CRC_LENGTH_ERROR: &str = "\n%s: %s: invalid compressed data--crc/length error\n";

/// Observed: `gzip -dc` on a corrupt deflate body (the run stops there).
pub(super) const FORMAT_VIOLATED: &str = "\n%s: %s: invalid compressed data--format violated\n";

/// Observed: `gzip -dc` on a member whose method byte is 7.
pub(super) const UNKNOWN_METHOD: &str = "%s: %s: unknown method %d -- not supported\n";

/// Observed: `gzip -dc` on a member with flag bit 0x20 set (any others too).
pub(super) const ENCRYPTED: &str = "%s: %s is encrypted -- not supported\n";

/// Observed: `gzip -dc` on a member with flag 0x40 or 0x80 set and not
/// 0x20; the whole flag byte is printed (`0x48`).
pub(super) const HAS_FLAGS: &str = "%s: %s has flags 0x%s -- not supported\n";

/// Observed: `gzip -dc` on a member whose FHCRC is wrong: the stored and
/// the computed value, `%04x` (exit 1, the run goes on).
pub(super) const HEADER_CRC: &str = "%s: %s: header checksum 0x%s != computed checksum 0x%s\n";

/// Observed: `gzip -dcv` on a member with FEXTRA (only with `-v`).
pub(super) const EXTRA_FIELD: &str = "%s: %s: extra field of %d bytes ignored\n";

/// Observed: `gzip -dc` on a member followed by bytes not all zero (exit 2;
/// `-q` silences it).
pub(super) const TRAILING_GARBAGE: &str = "\n%s: %s: decompression OK, trailing garbage ignored\n";

/// Observed: `gzip -dcv` on a member followed by zero bytes (only with
/// `-v`, then exit 2; silent and exit 0 otherwise).
pub(super) const TRAILING_ZEROS: &str = "\n%s: %s: decompression OK, trailing zero bytes ignored\n";

/// Observed: `gzip -dc` on a zip whose first entry has flag bit 0 set.
pub(super) const ZIP_ENCRYPTED: &str = "\n%s: %s: encrypted file -- use unzip\n";

/// Observed: `gzip -dc` on a zip whose first entry is bzip2 (12) or LZMA.
pub(super) const ZIP_METHOD: &str = "\n%s: %s: first entry not deflated or stored -- use unzip\n";

/// Observed: `gzip -dc` on a zip entry whose uncompressed size field is
/// `ffffffff` (what `zip - -` writes).
pub(super) const ZIP64: &str = "\n%s: %s: Zip64 entry -- not supported, use unzip\n";

/// Observed: `gzip -dc` on `PK\3\4` alone, a cut-short local header, and a
/// stored entry with a data descriptor or unequal sizes.
pub(super) const ZIP_INVALID: &str = "\n%s: %s: not a valid zip file\n";

/// Observed: `gzip -dc two.zip` (exit 2; `-q` silences it; also `-t`, `-l`).
pub(super) const ZIP_MORE: &str = "%s: %s has more than one entry--rest ignored\n";

/// Observed: `gzip -d -S .zip two.zip` (exit 1, no output, the run stops).
pub(super) const ZIP_MORE_UNCHANGED: &str = "%s: %s has more than one entry -- unchanged\n";

/// Observed: `gzip -dc` on a `.Z` whose header says 17 bits.
pub(super) const Z_BITS: &str = "\n%s: %s: compressed with %d bits, can only handle %d bits\n";

/// Observed: `gzip -dc` on a `.Z` whose header byte has 0x60 set (exit 2,
/// then it decodes; `-q` silences it).
pub(super) const Z_FLAGS: &str = "\n%s: %s: warning, unknown flags 0x%s\n";

/// Observed: `gzip -dc` (and `-t`) on a `.Z` with a code past the table
/// (exit 1, the run stops).
pub(super) const Z_CORRUPT: &str = "\n%s: %s: corrupt input.\n";

/// Observed: `gzip -d` (to a file) on the same `.Z`.
pub(super) const Z_CORRUPT_FILE: &str = "\n%s: %s: corrupt input. Use zcat to recover some data.\n";

/// Observed: `gzip -dc` on a pack stream whose code lengths leave codes
/// unused (exit 1, the run stops).
pub(super) const PACK_FEW: &str = "\n%s: %s: too few leaves in Huffman tree\n";

/// Observed: `gzip -dc` on a pack stream whose code lengths oversubscribe
/// the tree, or that has more than 257 leaves.
pub(super) const PACK_MANY: &str = "\n%s: %s: too many leaves in Huffman tree\n";

/// Observed: `gzip -dc` on a pack stream claiming 0 or more than 25 levels.
pub(super) const PACK_BIT_LENGTH: &str =
    "\n%s: %s: invalid compressed data -- Huffman code bit length out of range\n";

/// Observed: `gzip -dN` on a member whose FNAME is empty: the output could
/// not be created (`%s` the OS's text).
pub(super) const CREATE_FAILED: &str = "\n%s: %s: %s\n";

/// Observed: `gzip -tv a.gz`, after the name.
pub(super) const TEST_OK: &str = " OK\n";

/// Observed: `gzip -l` on standard input: the name column.
pub(super) const LIST_STDIN_NAME: &[u8] = b"stdout";

/// Observed: `gzip -l a.gz`.
pub(super) const LIST_HEADER: &str =
    "         compressed        uncompressed  ratio uncompressed_name\n";

/// Observed: `gzip -lv a.gz`.
pub(super) const LIST_HEADER_VERBOSE: &str = concat!(
    "method  crc     date  time  ",
    "         compressed        uncompressed  ratio uncompressed_name\n"
);

/// Observed: `gzip -l a.gz b.gz`: the last line's name column.
pub(super) const LIST_TOTALS: &[u8] = b"(totals)";

/// Observed: `gzip -lv`'s method column, by the last member's format.
pub(super) const METHOD_DEFLATE: &str = "defla";
/// Observed: `gzip -lv` on a stored zip entry.
pub(super) const METHOD_STORED: &str = "store";
/// Observed: `gzip -lv a.Z`.
pub(super) const METHOD_COMPRESS: &str = "compr";
/// Observed: `gzip -lv a.z` (a pack stream).
pub(super) const METHOD_PACK: &str = "pack ";

/// Observed: `gzip -lv` on anything whose last member is not gzip: the CRC
/// column is `-1` printed as a 64-bit hex number.
pub(super) const NO_CRC: &str = "ffffffffffffffff";

/// Observed: `gzip -lv`'s date column: month, day and time of day, never
/// the year (`Jan  1 01:00` for time 0 in CET).
pub(super) const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

// ---- stuffr's own ----

/// stuffr's own: Apple's personality is built by a later task.
pub(super) const BSD_NOT_BUILT: &str = concat!(
    "%s: stuffr's BSD gzip personality is not built yet; ",
    "set STUFFR_GZIP_FLAVOR=gnu\n"
);

/// GNU's `-v` ratio, `%5.1f%%` of `100 * (in - out) / in`, where `out`
/// counts the deflate body only (header and trailer excluded); matched
/// against the binary on 431 inputs (`head -c N /bin/ls`, N up to 200001).
/// An empty input is `-Inf` (GNU 1.15; observed `gzip -v < /dev/null`).
pub(super) fn ratio(bytes_in: u64, body: u64) -> String {
    if bytes_in == 0 {
        // `-(body) / 0`: the body is never empty (two bytes at least).
        return " -Inf%".to_owned();
    }
    let r = 100.0 * (bytes_in as f64 - body as f64) / bytes_in as f64;
    format!("{r:5.1}%")
}

/// A file name as GNU 1.15's diagnostics show it (NEWS: "diagnostics now
/// quote file names"). Established by observation (`gzip -- NAME` on a
/// missing file, for every printable ASCII character and the control and
/// high bytes):
///
/// - unquoted unless it is empty, holds a byte outside printable ASCII, or
///   one of ``space ! " $ & ' ( ) * ; < = > ? [ \ ^ ` | :``, starts with `#`
///   or `~`, or is exactly `{` or `}`;
/// - in double quotes when it holds `'` and none of ``$ ` " \ !`` and no
///   byte to escape;
/// - otherwise in single quotes, `'` as `'\''`, and each run of control or
///   non-ASCII bytes as `$'…'` (`\a \b \t \n \v \f \r`, else three octal
///   digits) between closed quotes: `'a'$'\t''b'`, `''$'\n'`.
pub(super) fn quote(name: &[u8]) -> Vec<u8> {
    let escaped = |b: u8| !(0x20..0x7f).contains(&b);
    let special = |b: u8| b" !\"$&'()*;<=>?[\\^`|:".contains(&b) || escaped(b);
    let needs = name.is_empty()
        || name.iter().any(|&b| special(b))
        || matches!(name.first(), Some(b'#' | b'~'))
        || name == b"{"
        || name == b"}";
    if !needs {
        return name.to_vec();
    }
    if name.contains(&b'\'') && !name.iter().any(|&b| b"$`\"\\!".contains(&b) || escaped(b)) {
        let mut v = Vec::with_capacity(name.len() + 2);
        v.push(b'"');
        v.extend_from_slice(name);
        v.push(b'"');
        return v;
    }
    #[derive(PartialEq)]
    enum In {
        Single,
        Dollar,
    }
    let mut v = vec![b'\''];
    let mut state = In::Single;
    for &b in name {
        if escaped(b) {
            if state == In::Single {
                v.extend_from_slice(b"'$'");
                state = In::Dollar;
            }
            match b {
                0x07 => v.extend_from_slice(b"\\a"),
                0x08 => v.extend_from_slice(b"\\b"),
                b'\t' => v.extend_from_slice(b"\\t"),
                b'\n' => v.extend_from_slice(b"\\n"),
                0x0b => v.extend_from_slice(b"\\v"),
                0x0c => v.extend_from_slice(b"\\f"),
                b'\r' => v.extend_from_slice(b"\\r"),
                _ => v.extend_from_slice(format!("\\{b:03o}").as_bytes()),
            }
            continue;
        }
        if state == In::Dollar {
            v.extend_from_slice(b"''");
            state = In::Single;
        }
        if b == b'\'' {
            v.extend_from_slice(b"'\\''");
        } else {
            v.push(b);
        }
    }
    v.push(b'\'');
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(s: &[u8]) -> String {
        String::from_utf8(quote(s)).unwrap()
    }

    /// Every expectation below is the 1.15 binary's own output for that
    /// name (`gzip -- NAME`, the name missing).
    #[test]
    fn quoting_matches_the_observed_names() {
        assert_eq!(q(b"a.txt"), "a.txt");
        assert_eq!(q(b""), "''");
        assert_eq!(q(b"a b"), "'a b'");
        assert_eq!(q(b"it's"), "\"it's\"");
        assert_eq!(q(b"it's a"), "\"it's a\"");
        assert_eq!(q(b"'"), "\"'\"");
        assert_eq!(q(b"a'b$c"), "'a'\\''b$c'");
        assert_eq!(q(b"a\tb"), "'a'$'\\t''b'");
        assert_eq!(q(b"\n"), "''$'\\n'");
        assert_eq!(q(b"a\x01\x02"), "'a'$'\\001\\002'");
        assert_eq!(q(b"a\x01b\x02"), "'a'$'\\001''b'$'\\002'");
        assert_eq!(q(b"a'\x01"), "'a'\\'''$'\\001'");
        assert_eq!(q(b"x\xc3\xa9"), "'x'$'\\303\\251'");
        assert_eq!(q(b"a\x7fb"), "'a'$'\\177''b'");
        assert_eq!(q(b"~a"), "'~a'");
        assert_eq!(q(b"a~"), "a~");
        assert_eq!(q(b"#a"), "'#a'");
        assert_eq!(q(b"a#"), "a#");
        assert_eq!(q(b"{"), "'{'");
        assert_eq!(q(b"{}"), "{}");
        assert_eq!(q(b"a{b"), "a{b");
        assert_eq!(q(b"]"), "]");
        assert_eq!(q(b"a=b"), "'a=b'");
        assert_eq!(q(b"a:b"), "'a:b'");
        assert_eq!(q(b"a^"), "'a^'");
        assert_eq!(q(b"-a"), "-a");
        assert_eq!(q(b"a%b+c,d.e/f@g_h-i"), "a%b+c,d.e/f@g_h-i");
    }

    #[test]
    fn the_ratio_is_gnus_layout() {
        assert_eq!(ratio(6, 8), "-33.3%");
        assert_eq!(ratio(24, 11), " 54.2%");
        assert_eq!(ratio(1, 3), "-200.0%");
        assert_eq!(ratio(0, 2), " -Inf%");
    }

    #[test]
    fn the_version_line_names_stuffr_in_gnus_layout() {
        assert!(VERSION_FIRST_LINE.starts_with("gzip (stuffr "));
        assert!(VERSION_FIRST_LINE.ends_with(") 1.15\n"));
        // Ruling T7-2: no GNU licence or authorship claim.
        for text in [LICENSE_REST, WRITTEN_BY, SCRIPT_VERSION_REST] {
            for banned in [
                "Free Software Foundation",
                "GNU General Public",
                "Gailly",
                "Eggert",
            ] {
                assert!(!text.contains(banned), "{banned}");
            }
            assert!(text.contains("MIT") || text.contains("Bjork"));
        }
    }
}
