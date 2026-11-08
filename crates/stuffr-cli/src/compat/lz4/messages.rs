//! Every string the lz4 family prints, as lz4 1.11.0 prints it (C locale;
//! lz4 has no NLS).
//!
//! **Clean room** (spec decision 3): lz4's `programs/` is GPL-2.0-or-later
//! and was never read. Each literal names where it was taken from: the
//! reference binary's own output (`// probe: <command>`, run as
//! `/opt/homebrew/opt/lz4/bin/lz4` 1.10.0 under `LC_ALL=C`, and since 0.26.0
//! `/opt/homebrew/Cellar/lz4/1.11.0/bin/lz4`; every string was checked
//! against 1.11.0, and the ones it changed or added say so), its `-h`/`-H`
//! (`// lz4 -H`), or the man page (`// lz4.1`). Formats follow C's `printf`
//! as [`printf`] renders them: `%s` and `%d` take the next argument (an
//! integer is formatted by the caller).
//!
//! The deliberate changes: the banner names stuffr ([`BANNER`], spec
//! deviation 1), and the benchmark refusal is stuffr's own
//! ([`BENCH_REFUSED`], deviation 5).

pub(super) use crate::compat::host::printf;

// ---- the banner and the help texts ----

/// probe: `lz4 -V` (1.11.0) prints `*** lz4 v1.11.0 64-bit multithread, by
/// Yann Collet ***`; spec deviation 1 adds `(stuffr X.Y.Z)` (the argument)
/// after `multithread`, so the prefix `*** lz4 v1.11.0 ` a script reads is
/// unchanged. Printed by `-V` (standard output), first by `-h`/`-H`
/// (standard error), and at `-v`.
pub(super) const BANNER: &str =
    "*** lz4 v1.11.0 64-bit multithread (stuffr %s), by Yann Collet ***\n";

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
    // lz4 -h (1.11.0): "worker" is new.
    " -T#    : use # worker threads for compression (default:0==auto) \n",
    " -d     : decompression (default for .lz4 extension)\n",
    " -f     : overwrite output without prompting \n",
    " -k     : preserve source files(s)  (default) \n",
    "--rm    : remove source file(s) after successful de/compression \n",
    " -h/-H  : display help/long help and exit \n",
);
/// lz4 -h: the rest of the short help, after the usage (lines 16-48 in
/// 1.11.0), the benchmark lines included (R8: printed though `-b` is
/// refused). `%s` is the default memory budget in MB (4096; 1024 on a
/// 32-bit build, lz4.1 1.11.0, `--memory`).
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
    // lz4 -h (1.11.0): new.
    "                     (custom sizes : single-threaded compression) \n",
    " -BI    : Block Independence (default) \n",
    " -BD    : Block dependency (improves compression ratio) \n",
    " -BX    : enable block checksum (default:disabled) \n",
    "--no-frame-crc : disable stream checksum (default:enabled) \n",
    "--content-size : compressed frame includes original size (default:not present)\n",
    "--list FILE : lists information about .lz4 files (useful for files compressed with --content-size flag)\n",
    "--[no-]sparse  : sparse mode (default:enabled on file, disabled on stdout)\n",
    // lz4 -h (1.11.0): the next four lines are new (`--memory=#` and the
    // `note :` line end with a blank, the other two do not).
    "--memory=#     : memory budget of multi-threaded compression (default: %s MB) ; suffixes K, M, G \n",
    "--single-thread: compress frames with the main thread alone, not cut into jobs (output can differ from -T1 with -BD)\n",
    "--[no-]mmap    : memory-map files to compress (default:enabled when supported)\n",
    "                 note : compression fails if the file is truncated or rewritten meanwhile \n",
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
    // lz4 -H (1.11.0): these five lines replace 1.10.0's two.
    "-0  => Default level, identical to -1 \n",
    "-1  => Fast compression \n",
    "-2 .. -12 => High compression; higher number == more compression but slower\n",
    "--best    => Highest available compression level (-12) \n",
    "--fast=#  => Faster compression; higher number == faster but compress less\n",
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
/// read, under every name): the variable's name, then its value. 1.11.0
/// prints it for anything that is not a whole number (`LZ4_CLEVEL=3x`,
/// `=1G`, `=99999999999`, and `LZ4_CLEVEL=2147483648`).
pub(super) const ENV_IGNORED: &str =
    "Ignore environment variable setting %s=%s: not a valid unsigned value \n";

/// probe (1.11.0): `LZ4_MEMORY=x lz4 -qq -c`, `=0`, `=4T`, `=50Mx`
/// (after the two above, also at `-qq`).
pub(super) const ENV_MEMORY_IGNORED: &str =
    "Ignore environment variable setting %s=%s: not a valid size \n";

/// probe (1.11.0): `lz4 -T4294967296`, `-B4194304K`, `-99999999999`,
/// `--fast=4294967296`, `--threads=4294967296`, `-b4294967296` (display
/// level 1, exit 1, no usage).
pub(super) const NUMERIC_OVERFLOW: &str = "error: numeric value overflows 32-bit unsigned int \n";

/// probe (1.11.0): `lz4 -2147483648`, `-4294967295`, `-2097152K`,
/// `--fast=2147483648` (a level above `INT_MAX`).
pub(super) const NUMERIC_TOO_LARGE: &str = "error: numeric value is too large \n";

/// probe (1.11.0): `lz4 --memory=0`, `=x`, `=4T`, `=1g`, `=1Mx`, `=`,
/// `--memory a`.
pub(super) const MEMORY_SIZE_REQUIRED: &str =
    "error: --memory requires a size, with optional suffixes K, KB, KiB, M, MB, MiB, G, GB, GiB \n";

/// probe (1.11.0): `lz4 --memory=18446744073709551616`,
/// `--memory=17179869184G`.
pub(super) const MEMORY_OVERFLOW: &str = "error: --memory value overflows 64-bit unsigned int \n";

// ---- parsing notes ----

/// probe: `lz4 -B4 -c` (display level 2, while parsing): the block size
/// of an ID, or of a byte count of 1024 or more, in KiB.
pub(super) const BLOCKS_KB: &str = "using blocks of size %d KB \n";

/// probe: `lz4 -B32 -c`, `lz4 -B1023 -c`: a byte count under 1024.
pub(super) const BLOCKS_BYTES: &str = "using blocks of size %d bytes \n";

/// probe (1.11.0): `lz4 -T5000 a` (display level 2, compression only,
/// after `Compressed filename will be :`; also with `-l`, `--single-thread`
/// and a custom `-B#`): the count asked for, then the cap.
pub(super) const THREADS_REDUCED: &str =
    "Warning : requested %d threads too large => automatically reduced to %d \n";

/// probe (1.11.0): `lz4 -v --memory=40M a` (display level 3, an automatic
/// thread count lowered by the memory budget): the budget in MB, the
/// threads, the count it replaces.
pub(super) const MEMORY_BUDGET_AUTO: &str = "Memory budget (%d MB) : %d threads instead of %d \n";

/// probe (1.11.0): `lz4 --memory=40M -T8 a` (display level 2, a count asked
/// for, `-T#` or `LZ4_NBWORKERS`, lowered by the budget).
pub(super) const MEMORY_BUDGET_ASKED: &str =
    "Warning : memory budget (%d MB) : %d threads instead of %d (see --memory) \n";

/// probe (1.11.0): `lz4 --memory=1 a`, `--memory=30017171 a` (display level
/// 2, a budget below one worker's): the budget, then one worker's need in
/// MB (`~28` with 4 MB blocks, `~13` with smaller ones).
pub(super) const MEMORY_TOO_SMALL: &str =
    "Warning : memory budget (%d MB) too small : compression requires ~%d MB \n";

/// probe (1.11.0): `lz4 -v --single-thread a` (display level 3, instead of
/// [`USING_THREADS`]).
pub(super) const SINGLE_THREADED: &str =
    "Single-threaded compression (frames not cut into jobs) \n";

/// probe (1.11.0): `lz4 -v -B1024 a` (display level 3, a block size other
/// than 64 KB, 256 KB, 1 MB and 4 MB, instead of [`USING_THREADS`]): the
/// size in bytes.
pub(super) const CUSTOM_BLOCKS: &str =
    "Note : custom block size (%d bytes) : single-threaded compression (-T# ignored) \n";

/// probe (1.11.0): `lz4 --content-size < a`, `lz4 --content-size -d`, `lz4
/// --content-size -m stdin a` (display level 2 as parsed, before it is
/// lowered for standard output; after the banner and the `_POSIX` lines;
/// whenever the first input is standard input, whatever the operation).
/// Lower-case, no blank before the newline.
pub(super) const CONTENT_SIZE_STDIN: &str =
    "warning : --content-size cannot determine size when used with stdin\n";

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

/// probe (1.11.0): `lz4 -f a a`, `lz4 a a`, `lz4 -df b.lz4 b.lz4`, a hard
/// link or a symbolic link as the output (`lz4 -df b.lz4 h.lz4`, `lz4 -f a
/// sa`), `lz4 -d -m y.lz4` with `y` a link to `y.lz4`: the output's name as
/// given, display level 1 (`-q` shows it, `-qq` hides it), whatever `-f`
/// says, asked before the overwrite question; that input fails (exit 1).
/// 1.10.0 truncated the input instead (deviation 3, now only for standard
/// input redirected from the output file).
pub(super) const SAME_FILE: &str = "%s: input and output are the same file; not overwritten \n";

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

/// probe (1.11.0): `lz4 -l a`: the legacy format's summary is the frame's
/// (1.10.0 had a blank before the newline).
pub(super) const COMPRESSED_LEGACY_SUMMARY: &str = "Compressed %d bytes into %d bytes ==> %s%%\n";

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

/// probe (1.11.0): `lz4 -c big | head -c1` with SIGPIPE ignored (1.10.0
/// said `Error 38`).
pub(super) const E46_WRITE_COMPRESSED: &str =
    "Error 46 : Write error : cannot write compressed block \n";

/// probe (1.11.0): `lz4 -12 -T1 f` with `f` truncated, or (with
/// `--no-frame-crc`) changed in any way, while it is compressed (display
/// level 1, right after the last refresh; the output file is removed).
pub(super) const E54_SOURCE_MODIFIED: &str = "Error 54 : %s : file modified during compression (memory-mapped) : output removed ; see --no-mmap \n";

/// probe (1.11.0): `lz4 -12 -T1 f` with `f` appended to, rewritten,
/// touched or chmod-ed meanwhile (display level 2, after the last refresh):
/// the name, then [`SOURCE_KEPT`] or nothing.
pub(super) const SOURCE_MODIFIED: &str =
    "\rWarning : %s : file modified during processing : output holds the content read %s\n";

/// probe (1.11.0): `lz4 -12 -T1 f` with `f` renamed and another file put
/// in its place meanwhile.
pub(super) const SOURCE_REPLACED: &str = "\rWarning : %s : file renamed or replaced during processing : output holds the content read %s\n";

/// probe (1.11.0): `lz4 --rm -12 -T1 f`, `f` modified meanwhile: the end of
/// [`SOURCE_MODIFIED`] or [`SOURCE_REPLACED`], and `f` is kept.
pub(super) const SOURCE_KEPT: &str = "; source kept ";

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
/// ends early); lz4 1.11.0 also from a file whose skippable area runs past
/// its end (`lz4 -t skip_trunc.lz4`, `skip_4g.lz4`; 1.10.0 seeked past the
/// end silently), and `lz4 --list skip_trunc.lz4` (1.10.0 listed it).
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

/// probe: `lz4 -t leg_bad.lz4`; a mozlz4 block that does not decode within
/// its declared size (1.11.0: `lz4 -t small.mozlz4`, `cut100.mozlz4`,
/// `two.mozlz4`). (1.10.0 also said it for `legzero.lz4`, which 1.11.0
/// reads as an empty legacy frame.)
pub(super) const E64_LEGACY_DECODE: &str =
    "Error 64 : Decoding Failed ! Corrupted input detected ! \n";

/// probe (1.11.0): `lz4 -t hdr9.mozlz4`, the mozlz4 magic then fewer than four
/// bytes (`-dcf` too: no pass-through).
pub(super) const E62_MOZLZ4_SIZE: &str =
    "Error 62 : Error: cannot read decompressed size in mozlz4 format \n";

/// probe (1.11.0): `lz4 -t ffff.mozlz4`, `v7e000001.mozlz4`: a declared size
/// past `0x7E000000`, as `%u`.
pub(super) const E62_MOZLZ4_TOO_LARGE: &str =
    "Error 62 : Error: mozlz4 decompressed size too large (%d) \n";

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

// ---- `--list` (probed on lz4 1.10.0, unchanged in 1.11.0: 0.26.0 Task 6) ----

/// probe: `lz4 --list b.lz4` (standard output, once before the first file
/// and even when none is read: `lz4 --list` on standard input prints only
/// this; absent at display level 3).
pub(super) const LIST_HEADER: &str =
    "    Frames           Type Block  Compressed  Uncompressed    Ratio   Filename\n";

/// probe: `lz4 --list cs100.lz4` (a file whose frames all say how big their
/// content is): the cells `%10s %14s %5s %11s %13s %8s` as padded by the
/// caller, the ratio's `%`, two blanks, the file's base name, a blank.
pub(super) const LIST_ROW_KNOWN: &str = "%s %s %s %s %s %s%%  %s \n";

/// probe: `lz4 --list b.lz4` (a content size missing from a frame, or any
/// legacy or skippable frame): the same cells, three blanks, the base name,
/// no trailing blank.
pub(super) const LIST_ROW_UNKNOWN: &str = "%s %s %s %s %s %s   %s\n";

/// probe: `lz4 --list -v b.lz4` (display level 3): `name(i/n)` before each
/// file, the base name.
pub(super) const LIST_FILE_VERBOSE: &str = "%s(%s/%s)\n";

/// probe: `lz4 --list -v b.lz4`: the columns of the per-frame table.
pub(super) const LIST_HEADER_VERBOSE: &str = "     Frame           Type Block Checksum           Compressed         Uncompressed     Ratio\n";

/// probe: `lz4 --list -v cs100.lz4` (a modern frame with a content size):
/// the cells `%10s %14s %5s %8s %20s %20s %9s` as padded by the caller, then
/// the ratio's `%`.
pub(super) const LIST_FRAME_KNOWN: &str = "%s %s %s %s %s %s %s%%\n";

/// probe: `lz4 --list -v b.lz4` (a modern frame with no content size): the
/// same cells and a trailing blank.
pub(super) const LIST_FRAME_UNKNOWN: &str = "%s %s %s %s %s %s %s \n";

/// probe: `lz4 --list -v leg.lz4`, `skip.lz4` (legacy and skippable frames):
/// the same cells and nothing after them.
pub(super) const LIST_FRAME_OTHER: &str = "%s %s %s %s %s %s %s\n";

/// probe: `lz4 --list -v b.lz4`: the blank line after a file's frames (not
/// printed after a file that failed).
pub(super) const LIST_FILE_END: &str = "\n";

/// probe: `lz4 --list b.lz4`: a modern frame's type cell.
pub(super) const TYPE_FRAME: &str = "LZ4Frame";
/// probe: `lz4 --list leg.lz4`: a legacy frame's type cell.
pub(super) const TYPE_LEGACY: &str = "LegacyFrame";
/// probe: `lz4 --list skip.lz4`: a skippable frame's type cell.
pub(super) const TYPE_SKIPPABLE: &str = "SkippableFrame";
/// probe: `lz4 --list leg_then_good.lz4`: no cell, or frames that differ
/// (type, block size, block mode), or a frame with nothing to say.
pub(super) const CELL_NONE: &str = "-";
/// probe: `lz4 --list -v b.lz4`: the checksum cell of a frame with a
/// content checksum (`-` without).
pub(super) const CHECKSUM_XXH32: &str = "XXH32";
/// probe: `lz4 --list b.lz4`: the block cell is `B`, the size ID (4 to 7)
/// and `I` (independent blocks) or `D` (linked: `lz4 -BD`).
pub(super) const BLOCK_INDEPENDENT: &str = "I";
/// probe: `lz4 --list linked.lz4` (a frame header with block-independence
/// off).
pub(super) const BLOCK_LINKED: &str = "D";
/// probe: `lz4 --list b.lz4`: the block cell's `B` before the size ID.
pub(super) const BLOCK_PREFIX: &str = "B";

/// probe: `lz4 --list notlz4`, `lz4 --list badhc.lz4`, `lz4 --list e.lz4`
/// (display level 1 and up; the run ends with exit 1, without reading the
/// files after it).
pub(super) const LIST_NOT_RECOGNIZED: &str = "lz4: %s: File format not recognized \n";

/// probe: `lz4 --list nosuch`, `lz4 --list d`, `lz4 --list /dev/null`,
/// `lz4 --list stdin` (a file named `stdin`: only the operand `-` is
/// standard input in a list).
pub(super) const LIST_NOT_REGULAR: &str = "lz4: %s is not a regular file \n";

/// probe: `lz4 --list leg_huge.lz4` (a legacy block size above 8 MiB, or a
/// size word cut short): printed before [`LIST_NOT_RECOGNIZED`].
pub(super) const LIST_CORRUPTED_LEGACY: &str = "Corrupted legacy frame \n";

/// probe: `lz4 -vv --list b.lz4` (display level 4, after the banner):
/// `_POSIX_VERSION` as the system reports it (`sysconf(_SC_VERSION)`: on
/// macOS 200112L), twice.
pub(super) const POSIX_VERSION: &str =
    "_POSIX_VERSION defined: %sL\nPLATFORM_POSIX_VERSION defined: %sL\n";

/// probe: `lz4 -vv -c f` on Linux (the 1.10.0 tarball built with `make -C
/// programs lz4` on glibc, Debian `rust:1.95`, and on musl, Alpine 3.20;
/// CI run 39166896170 on ubuntu): a line before the two above, at display
/// level 4. The reference built on macOS prints no such line. The value is
/// the reference build's, 200809L under both C libraries.
#[cfg(target_os = "linux")]
pub(super) const POSIX_C_SOURCE: &str = "_POSIX_C_SOURCE defined: 200809L\n";

// ---- the end of a run ----

/// probe: `lz4 -p -V < /dev/null` (hidden `-p`): printed at a clean exit,
/// whatever the display level, then a byte of standard input is read.
pub(super) const PRESS_ENTER: &str = "Press enter to continue...\n";

/// Spec deviation 5 (stuffr's own text): `-b#` (`-e#` and `-i#` are accepted and ignored).
pub(super) const BENCH_REFUSED: &str = "Benchmark mode is not available in this build (stuffr)\n";

// ---- display levels 3 and 4 (Task 6) ----

/// probe (1.11.0): `lz4 -v -T3 a` (display level 3, compression only,
/// after `Compressed filename will be :` and before the first file): the
/// worker count, `-T1`'s too, after the cap and the memory budget. Not
/// for `-l`; [`SINGLE_THREADED`] or [`CUSTOM_BLOCKS`] instead where they
/// apply.
pub(super) const USING_THREADS: &str = "Using up to %d threads for compression \n";

/// probe: `lz4 -v -l a` (display level 3): after the thread line.
pub(super) const GENERATING_LEGACY: &str = "! Generating LZ4 Legacy format (deprecated) ! \n";

/// probe: `lz4 -v --content-size - o < pipe`, `lz4 -v --content-size
/// /dev/null o` (display level 3, compression of a frame, once the output
/// is open; a regular file, standard input redirected from one included,
/// does not say it).
pub(super) const CONTENT_SIZE_UNKNOWN: &str = "Warning : cannot determine input content size \n";

/// probe: `lz4 -vv - o` (display level 4): standard input is the input,
/// printed as it is opened (before the overwrite question when compressing,
/// after it when decoding).
pub(super) const USING_STDIN: &str = "Using stdin for input \n";

/// probe: `lz4 -vv -c a` (display level 4): standard output is the output.
/// Compressing says it for every file written there; decoding says it once
/// at the start of a run whose output is standard output or which has `-m`
/// operands (`lz4 -vv -d -m a.lz4` says it though it writes `a`).
pub(super) const USING_STDOUT: &str = "Using stdout for output \n";

/// probe: `lz4 -vv -c a`, after [`USING_STDOUT`] (display level 4): said
/// unless `--sparse` or `--no-sparse` was given.
pub(super) const SPARSE_DISABLED: &str = "Sparse File Support automatically disabled on stdout ; to force-enable it, add --sparse command \n";

/// probe: `lz4 -vv -r d` (display level 4, before everything else of the
/// run): each input of the list `-r` made, from 0.
pub(super) const LIST_ENTRY: &str = "%d %s\n";

/// probe: `lz4 -v a`, `lz4 -v -d -m b.lz4` (display level 3): after the
/// last input of a compression (always), of a decode that has `-m`
/// operands, or (1.11.0) of a single decode that succeeded (`lz4 -v -t
/// b.lz4`; not after `lz4 -v -d nosuch.lz4 o`, a declined overwrite, a
/// same-file refusal or undecodable trailing data; 1.10.0 said it exactly
/// there instead). The seconds
/// and the speed are `%.2f`, the load `%.0f` (deviation 2: the harness
/// normalises all three).
pub(super) const DONE_IN: &str = "Done in %s s ==> %s MiB/s  (cpu load : %s%%)\n";

/// probe: `lz4 -vv -t leg.lz4` (display level 4, decoding): a legacy frame's
/// magic number was read; said for each such frame, before its first
/// refresh (not by `--list`).
pub(super) const LEGACY_DETECTED: &str = "Detected : Legacy format \n";

/// probe (1.11.0): `lz4 -vv -t good.jsonlz4` (display level 4, decoding):
/// the mozlz4 magic was read whole, before the size word is.
pub(super) const MOZLZ4_DETECTED: &str = "Detected : mozlz4 format \n";

/// probe (1.11.0): `lz4 -qqq -r d`, `--list -r d`, `-d -r d` with `d/lnk` a
/// link to a directory: at every display level, as the walk meets it
/// (readdir order), before `-vvvv`'s list; no trailing blank. The link is
/// not followed (1.10.0 followed it); one named as an operand still is.
pub(super) const RECURSIVE_DIR_LINK: &str =
    "Warning : %s is a symbolic link to a directory, ignoring\n";

/// probe: `lz4 -vv -t skip_then_frame.lz4` (display level 4, decoding):
/// a skippable frame's magic number was read, before its size is.
pub(super) const SKIPPABLE_DETECTED: &str = "Skipping detected skippable area \n";
