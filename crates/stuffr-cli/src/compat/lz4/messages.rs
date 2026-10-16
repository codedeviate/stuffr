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
#[allow(dead_code, reason = "0.15.0 Task 4 prints it")]
pub(super) const EXTENSION_MISMATCH: &str =
    "File extension doesn't match expected LZ4_EXTENSION (.lz4); will not process file: %s\n";

/// probe: `lz4 a` (display level 2): a compressed output name derived from
/// the input's.
#[allow(dead_code, reason = "0.15.0 Task 4 prints it")]
pub(super) const COMPRESSED_FILENAME: &str = "Compressed filename will be : %s \n";

/// probe: `lz4 -d b.lz4` (display level 2): a decompressed output name
/// derived from the input's.
#[allow(dead_code, reason = "0.15.0 Task 4 prints it")]
pub(super) const DECODING_FILE: &str = "Decoding file %s \n";

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
