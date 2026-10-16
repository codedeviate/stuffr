//! Every string the lz4 family prints, as lz4 1.10.0 prints it (C locale;
//! lz4 has no NLS).
//!
//! **Clean room** (spec decision 3): lz4's `programs/` is GPL-2.0-or-later
//! and was never read. Each literal names where it was taken from: the
//! reference binary's own output (`// probe: <command>`, run as
//! `/opt/homebrew/opt/lz4/bin/lz4` 1.10.0 under `LC_ALL=C`), its `-h`/`-H`
//! (`// lz4 -H`), or the man page (`// lz4.1`). Formats follow C's `printf`
//! as [`printf`] renders them: `%s` and `%d` take the next argument (an
//! integer is formatted by the caller).
//!
//! The deliberate changes: the banner names stuffr ([`BANNER`], spec
//! deviation 1), and the benchmark refusal is stuffr's own
//! ([`BENCH_REFUSED`], deviation 5).

pub(super) use crate::compat::host::printf;

// ---- the banner and the help texts ----

/// probe: `lz4 -V` prints `*** lz4 v1.10.0 64-bit multithread, by Yann
/// Collet ***`; spec deviation 1 adds `(stuffr X.Y.Z)` (the argument)
/// after `multithread`, so the prefix `*** lz4 v1.10.0 ` a script reads is
/// unchanged. Printed by `-V` (standard output), first by `-h`/`-H`
/// (standard error), and at `-v`.
pub(super) const BANNER: &str =
    "*** lz4 v1.10.0 64-bit multithread (stuffr %s), by Yann Collet ***\n";

/// probe: `lz4 --bogus`: the line before the short usage on a usage error.
pub(super) const INCORRECT_PARAMETERS: &str = "Incorrect parameters\n";

/// lz4 -h (lines 2-15), also the usage `Incorrect parameters` is followed by
/// (probe: `lz4 --bogus`). `%s` is the program name: the invoked name's last
/// path component, after `/` or `\` (probe: `exec -a 'x\unlz4.exe' lz4 -y`).
pub(super) const USAGE: &str = concat!(
    "Usage : \n",
    "      %s [arg] [input] [output] \n",
    "\n",
    "input   : a filename \n",
    "          with no FILE, or when FILE is - or stdin, read standard input\n",
    "Arguments : \n",
    " -1     : fast compression (default) \n",
    " -12    : slowest compression level \n",
    " -T#    : use # threads for compression (default:0==auto) \n",
    " -d     : decompression (default for .lz4 extension)\n",
    " -f     : overwrite output without prompting \n",
    " -k     : preserve source files(s)  (default) \n",
    "--rm    : remove source file(s) after successful de/compression \n",
    " -h/-H  : display help/long help and exit \n",
);
/// lz4 -h: the rest of the short help, after the usage (lines 16-43), the
/// benchmark lines included (R8: printed though `-b`/`-e`/`-i` are refused).
pub(super) const HELP_REST: &str = concat!(
    "\n",
    "Advanced arguments :\n",
    " -V     : display Version number and exit \n",
    " -v     : verbose mode \n",
    " -q     : suppress warnings; specify twice to suppress errors too\n",
    " -c     : force write to standard output, even if it is the console\n",
    " -t     : test compressed file integrity\n",
    " -m     : multiple input files (implies automatic output filenames)\n",
    " -r     : operate recursively on directories (sets also -m) \n",
    " -l     : compress using Legacy format (Linux kernel compression)\n",
    " -z     : force compression \n",
    " -D FILE: use FILE as dictionary (compression & decompression)\n",
    " -B#    : cut file into blocks of size # bytes [32+] \n",
    "                     or predefined block size [4-7] (default: 7) \n",
    " -BI    : Block Independence (default) \n",
    " -BD    : Block dependency (improves compression ratio) \n",
    " -BX    : enable block checksum (default:disabled) \n",
    "--no-frame-crc : disable stream checksum (default:enabled) \n",
    "--content-size : compressed frame includes original size (default:not present)\n",
    "--list FILE : lists information about .lz4 files (useful for files compressed with --content-size flag)\n",
    "--[no-]sparse  : sparse mode (default:enabled on file, disabled on stdout)\n",
    "--favor-decSpeed: compressed files decompress faster, but are less compressed \n",
    "--fast[=#]: switch to ultra fast compression level (default: 1)\n",
    "--best  : same as -12\n",
    "Benchmark arguments : \n",
    " -b#    : benchmark file(s), using # compression level (default : 1) \n",
    " -e#    : test all compression levels from -bX to # (default : 1)\n",
    " -i#    : minimum evaluation time in seconds (default : 3s) \n",
);
/// lz4c -h, lz4c -H: the block a name matching `lz4c` adds after the
/// benchmark lines (probe: `lz4c -h`, `exec -a lz4c.exe lz4 -H`).
pub(super) const HELP_LEGACY: &str = concat!(
    "Legacy arguments : \n",
    " -c0    : fast compression \n",
    " -c1    : high compression \n",
    " -c2,-hc: very high compression \n",
    " -y     : overwrite output without prompting \n",
);
/// lz4 -H: what the long help adds after the short help; `%s` (six times)
/// is the program name.
pub(super) const LONG_HELP: &str = concat!(
    "\n",
    "****************************\n",
    "***** Advanced comment *****\n",
    "****************************\n",
    "\n",
    "Which values can [output] have ? \n",
    "---------------------------------\n",
    "[output] : a filename \n",
    "          'stdout', or '-' for standard output (pipe mode)\n",
    "          'null' to discard output (test mode) \n",
    "[output] can be left empty. In this case, it receives the following value :\n",
    "          - if stdout is not the console, then [output] = stdout \n",
    "          - if stdout is console : \n",
    "               + for compression, output to filename.lz4 \n",
    "               + for decompression, output to filename without '.lz4'\n",
    "                    > if input filename has no '.lz4' extension : error \n",
    "\n",
    "Compression levels : \n",
    "---------------------\n",
    "-0 ... -2  => Fast compression, all identical\n",
    "-3 ... -12 => High compression; higher number == more compression but slower\n",
    "\n",
    "stdin, stdout and the console : \n",
    "--------------------------------\n",
    "To protect the console from binary flooding (bad argument mistake)\n",
    "%s will refuse to read from console, or write to console \n",
    "except if '-c' command is specified, to force output to console \n",
    "\n",
    "Simple example :\n",
    "----------------\n",
    "1 : compress 'filename' fast, using default output name 'filename.lz4'\n",
    "          %s filename\n",
    "\n",
    "Short arguments can be aggregated. For example :\n",
    "----------------------------------\n",
    "2 : compress 'filename' in high compression mode, overwrite output if exists\n",
    "          %s -9 -f filename \n",
    "    is equivalent to :\n",
    "          %s -9f filename \n",
    "\n",
    "%s can be used in 'pure pipe mode'. For example :\n",
    "-------------------------------------\n",
    "3 : compress data stream from 'generator', send result to 'consumer'\n",
    "          generator | %s | consumer \n",
);
/// lz4c -H: the warning a name matching `lz4c` adds at the end of the long
/// help; `%s` (twice) is the program name.
pub(super) const LONG_HELP_LEGACY: &str = concat!(
    "\n",
    "***** Warning  ***** \n",
    "Legacy arguments take precedence. Therefore : \n",
    "--------------------------------- \n",
    "          %s -hc filename \n",
    "means 'compress filename in high compression mode' \n",
    "It is not equivalent to : \n",
    "          %s -h -c filename \n",
    "which displays help text and exits \n",
);

// ---- usage errors (exit 1, display level 1) ----

/// probe: `lz4 a x.lz4 y`, `lz4 -c a b c` (the first operand with no slot).
pub(super) const WONT_BE_USED: &str =
    "Error : %s won't be used ! Do you want multiple input files (-m) ? \n";

/// probe: `lz4 a --threads` (no argument follows).
pub(super) const MISSING_ARGUMENT: &str = "error: missing command argument \n";

/// probe: `lz4 --threads -c a`.
pub(super) const SEPARATED_ARGUMENT: &str =
    "error: command cannot be separated from its argument by another command \n";

/// probe: `lz4 --threads=x`, `lz4 --threads=4x`.
pub(super) const NUMERIC_ONLY: &str =
    "error: only numeric values with optional suffixes K, KB, KiB, M, MB, MiB are allowed \n";

/// probe: `LZ4_CLEVEL=x lz4 -qq -c` (printed before the arguments are
/// read, under every name): the variable's name, then its value.
pub(super) const ENV_IGNORED: &str =
    "Ignore environment variable setting %s=%s: not a valid unsigned value \n";

// ---- parsing notes ----

/// probe: `lz4 -B4 -c` (display level 2, while parsing): the block size
/// of an ID, or of a byte count of 1024 or more, in KiB.
pub(super) const BLOCKS_KB: &str = "using blocks of size %d KB \n";

/// probe: `lz4 -B32 -c`, `lz4 -B1023 -c`: a byte count under 1024.
pub(super) const BLOCKS_BYTES: &str = "using blocks of size %d bytes \n";

/// probe: `lz4 -v -T300 -c a` (display level 3, compression only; Task 6
/// prints it): the count asked for, then the cap.
#[allow(dead_code, reason = "0.15.0 Task 6 prints it")]
pub(super) const THREADS_REDUCED: &str =
    "Requested %d threads too large => automatically reduced to %d \n";

// ---- where the output goes (the decision table in `cli.rs`) ----

/// probe: `lz4 -d a`, `unlz4 a`, `lz4 .lz4`; followed by the usage error.
pub(super) const CANNOT_DETERMINE: &str = "Cannot determine an output filename \n";

/// probe: `script -q /dev/null lz4` (standard input a terminal).
pub(super) const STDIN_CONSOLE: &str = "refusing to read from a console\n";

/// probe: `lz4 a -` with standard output a terminal.
pub(super) const STDOUT_CONSOLE: &str = "refusing to write to console without -c \n";

/// probe: `lz4 -m -d b.lz4 a` (per file, the run continues; exit 1).
pub(super) const EXTENSION_MISMATCH: &str =
    "File extension doesn't match expected LZ4_EXTENSION (.lz4); will not process file: %s\n";

/// probe: `lz4 a` (display level 2): a compressed output name derived from
/// the input's.
pub(super) const COMPRESSED_FILENAME: &str = "Compressed filename will be : %s \n";

/// probe: `lz4 -d b.lz4` (display level 2): a decompressed output name
/// derived from the input's.
pub(super) const DECODING_FILE: &str = "Decoding file %s \n";

// ---- files (display level 1 unless noted) ----

/// probe: `lz4 nosuch`, `lz4 -d nosuch.lz4 o`, `lz4 -D nosuch a` (an
/// input or dictionary that cannot be opened): the name as given, then
/// `strerror` and a blank.
pub(super) const OPEN_INPUT_FAILED: &str = "%s: %s \n";

/// probe: `lz4 -f a ro/x`, `lz4 -d b.lz4 nodir/x`, `lz4 -f a d`: an output
/// that cannot be created; no blank before the newline.
pub(super) const OPEN_OUTPUT_FAILED: &str = "%s: %s\n";

/// probe: `lz4 d`, `lz4 -d d.lz4 o`, `lz4 -D d a` (the same text under
/// every name: `unlz4 d.lz4 o` prints `lz4:` too).
pub(super) const IS_A_DIRECTORY: &str = "lz4: %s is a directory -- ignored \n";

/// probe: `lz4 a` with `a.lz4` present (display level 2 and up; standard
/// input is read for the answer whether or not it is a terminal, R11).
pub(super) const OVERWRITE_PROMPT: &str = "%s already exists; do you want to overwrite (y/N) ? ";

/// probe: `lz4 a < /dev/null` with `a.lz4` present: a refused answer
/// (anything but `y` or `Y` first, or end of file).
pub(super) const NOT_OVERWRITTEN: &str = "    not overwritten  \n";

/// probe: `lz4 -q a`, `lz4 -m a`, `lz4 -qqqq a` with `a.lz4` present: below
/// display level 2 there is no question, and this line is printed at every
/// level.
pub(super) const ALREADY_EXISTS: &str = "%s already exists; not overwritten  \n";

/// Spec deviation 3 (stuffr's own text, in lz4's words): an output that is
/// the input file itself is refused, so the input is never lost (lz4
/// truncates it first: probe `lz4 -f a a` leaves an empty frame). Printed
/// at every level, as [`ALREADY_EXISTS`] is.
pub(super) const SAME_FILE: &str = "%s is the input file; not overwritten (stuffr)  \n";

// ---- progress and summaries (display level 2; stderr not a terminal) ----

/// probe: `lz4 a 2>err` (`\r`-refreshed while compressing): MiB read, then
/// the ratio so far as `%.2f` (deviation 2: the harness normalises both).
pub(super) const READ_PROGRESS: &str = "\rRead : %d MiB   ==> %s%%   ";

/// probe: `lz4 -d b.lz4 2>err`: MiB decoded so far.
pub(super) const DECODE_PROGRESS: &str = "\rDecompressed : %d MiB  ";

/// probe: `lz4 a 2>err`, `lz4 -t b.lz4 2>err`: the progress line is
/// cleared (79 blanks) before the summary, even when no refresh was drawn.
pub(super) const CLEAR_LINE: &str = concat!(
    "\r",
    "                                                                               ",
    "\r"
);

/// probe: `lz4 a` (a frame): bytes read, bytes written, the ratio (`%.2f`,
/// of at least one byte read: `lz4 e` says `1500.00%`).
pub(super) const COMPRESSED_SUMMARY: &str = "Compressed %d bytes into %d bytes ==> %s%%\n";

/// probe: `lz4 -l a`: the legacy format's summary has a blank before the
/// newline.
pub(super) const COMPRESSED_LEGACY_SUMMARY: &str = "Compressed %d bytes into %d bytes ==> %s%% \n";

/// probe: `lz4 -t b.lz4`, `lz4 -d sub/x.lz4`: the input name as given
/// (`stdin` for standard input), cut or padded to 30 bytes by the caller
/// (`a_very_long_file_name_more_tha`), then the bytes decoded.
pub(super) const DECODED_SUMMARY: &str = "%s : decoded %d bytes \n";

/// probe: `lz4 -d lg.lz4` (a legacy frame, then bytes that are no frame;
/// display level 2): the run decodes what came before, prints this and
/// the summary, and ends with exit 1. lz4 says where the bytes were only
/// when it can tell (`ftell` on a file: [`AT_POSITION`]); on a pipe the
/// line ends here.
pub(super) const UNDECODABLE: &str = "Stream followed by undecodable data ";

/// probe: `lz4 -d lg.lz4` on a file: the offset just past the four bytes
/// read as a magic number.
pub(super) const AT_POSITION: &str = "at position %d ";

/// The end of [`UNDECODABLE`]'s line.
pub(super) const NEWLINE: &str = "\n";

// ---- `Error N : ...` (display level 1; the run ends with exit N) ----

/// probe: `lz4 -t t_hdr.lz4`, `lz4 -dc g4.lz4` (a frame left unfinished at
/// end of input).
pub(super) const E26_INCOMPLETE: &str =
    "Error 26 : LZ4F frame decoding could not complete: invalid frame \n";

/// probe: `lz4 -D nosuch a`, `lz4 -D d a` (after the open's own line).
pub(super) const E27_DICTIONARY: &str =
    "Error 27 : Dictionary error : could not open dictionary file \n";

/// probe: `lz4 -t bad_hc.lz4`: liblz4's error name (`LZ4F_getErrorName`).
pub(super) const E34_DECOMPRESSION: &str = "Error 34 : Decompression error : %s \n";

/// probe: `lz4 -c big | head -c1` with SIGPIPE ignored.
pub(super) const E38_WRITE_COMPRESSED: &str =
    "Error 38 : Write error : cannot write compressed block \n";

/// probe: `lz4 -c <&-` (closed standard input): the first read of a frame's
/// input failed. Two blanks before the newline.
pub(super) const E40_FIRST_CHUNK: &str =
    "Error 40 : Error reading first chunk (%d bytes) of '%s'  \n";

/// probe: `lz4 -t t_magic.lz4`, a skippable frame then two bytes.
pub(super) const E40_MAGIC_UNREADABLE: &str =
    "Error 40 : Unrecognized header : Magic Number unreadable \n";

/// probe: `lz4 -t skip_hdr_trunc.lz4`.
pub(super) const E42_SKIPPABLE_SIZE: &str =
    "Error 42 : Stream error : skippable size unreadable \n";

/// probe: `cat skip_trunc.lz4 | lz4 -dc` (on a pipe the area is read, and it
/// ends early; a file is seeked past its end instead, silently).
pub(super) const E43_SKIP: &str = "Error 43 : Stream error : cannot skip skippable area \n";

/// probe: `lz4 -d unk_hdr.lz4`.
pub(super) const E44_UNRECOGNIZED: &str =
    "Error 44 : Unrecognized header : file cannot be decoded \n";

/// probe: `lz4 -c --rm < a` (the name removed is `stdin`): the name, then
/// `strerror`.
pub(super) const E50_REMOVE: &str = "Error 50 : Remove error : %s: %s \n";

/// probe: `lz4 -t leg_bsz_trunc.lz4`, `lz4 -t leg_garbage.lz4`.
pub(super) const E61_LEGACY_SIZE: &str =
    "Error 61 : Error: cannot read block size in Legacy format \n";

/// probe: `lz4 -t leg_blk_trunc.lz4`.
pub(super) const E63_LEGACY_BLOCK: &str =
    "Error 63 : Read error : cannot access compressed block ! \n";

/// probe: `lz4 -t leg_bad.lz4`, `lz4 -t legzero.lz4`.
pub(super) const E64_LEGACY_DECODE: &str =
    "Error 64 : Decoding Failed ! Corrupted input detected ! \n";

/// probe: `lz4 --sparse -dc z.lz4 | cat` (all zeros, so only the final
/// skip, which a pipe refuses). The blank line is lz4's.
pub(super) const E69_FINAL_SKIP: &str = "Error 69 : Final skip error (sparse file)\n \n";

/// probe: `lz4cat big.lz4 | head -c1` with SIGPIPE ignored.
pub(super) const E70_WRITE_DECODED: &str = "Error 70 : Write error : cannot write decoded block \n";

/// probe: `lz4 --sparse -dc a8.lz4 | cat` (data in whole words: the skip
/// before it is tried, even an empty one, and a pipe refuses): `errno`, then
/// `strerror`.
pub(super) const E72_SPARSE_SKIP: &str =
    "Error 72 : Sparse skip error(%d): %s ; try --no-sparse \n";

/// probe: `lz4 --sparse -dc z8a.lz4 | cat` (8 zero bytes then `A`: data in
/// the bytes after the last whole word).
pub(super) const E74_SPARSE_TAIL_SKIP: &str = "Error 74 : Sparse skip error ; try --no-sparse \n";

// ---- the end of a run ----

/// probe: `lz4 -p -V < /dev/null` (hidden `-p`): printed at a clean exit,
/// whatever the display level, then a byte of standard input is read.
pub(super) const PRESS_ENTER: &str = "Press enter to continue...\n";

/// Spec deviation 5 (stuffr's own text): `-b#`, `-e#` and `-i#`.
pub(super) const BENCH_REFUSED: &str = "Benchmark mode is not available in this build (stuffr)\n";

/// Not lz4's: what an operation a later task implements answers until then
/// (debug builds only; the 0.15.0 final review greps that none remains).
#[cfg(debug_assertions)]
pub(super) const TODO_NOT_IMPLEMENTED: &str = "stuffr: lz4 %s: todo (0.15.0 %s)\n";
