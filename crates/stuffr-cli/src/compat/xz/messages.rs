//! Every string the xz family prints, as XZ Utils 5.8.4's `xz` prints it
//! with NLS off (`LC_ALL=C`).
//!
//! Ported from XZ Utils 5.8.4 (`src/xz/`, `src/common/tuklib_exit.c`,
//! `src/liblzma/common/string_conversion.c`; 0BSD, `LICENSE-xz`). Each
//! constant names the file and function it comes from. Formats follow C's
//! `printf` as [`printf`] renders them: `%s` takes the next argument (an
//! integer is formatted by the caller), `%%` is a literal percent sign.
//! The help texts are `message_help`'s output verbatim, wrapped by
//! `tuklib_wrapf` exactly as the reference binary prints them.
//!
//! The getopt texts are the platform C library's, not xz's: BSD libc
//! (`getopt_long.c`, macOS and the BSDs) and glibc (`posix/getopt.c`,
//! elsewhere) word them differently, and `args.rs` picks one by `cfg`.
//!
//! The deliberate change: `--version`'s first line names stuffr
//! ([`VERSION_FIRST_LINE`]); the second line and `--robot --version` are
//! the reference's.

pub(super) use crate::compat::host::printf;

// ---- message.c ----

/// message.c: vmessage, the prefix of every message (the program name is
/// the full `argv[0]`, `tuklib_progname`).
pub(super) const PREFIX: &str = "%s: ";

/// message.c: message_try_help (printed at `V_WARNING`).
pub(super) const TRY_HELP: &str = "Try '%s --help' for more information.";

/// message.c: message_version, first line. stuffr's own: the reference
/// prints `xz (XZ Utils) 5.8.4`.
pub(super) const VERSION_FIRST_LINE: &str = "xz (stuffr %s; XZ Utils 5.8.4 compatible)\n";

/// message.c: message_version, second line (`lzma_version_string()`).
pub(super) const VERSION_LIBLZMA: &str = "liblzma 5.8.4\n";

/// message.c: message_version under `--robot` (`LZMA_VERSION` and
/// `lzma_version_number()` of 5.8.4).
pub(super) const VERSION_ROBOT: &str = "XZ_VERSION=50080042\nLIBLZMA_VERSION=50080042\n";

/// message.c: message_filters_help, the text before the list (not under
/// `--robot`).
pub(super) const FILTERS_HELP_INTRO: &str = concat!(
    "Filter chains are set using the --filters=FILTERS or --filters1=FILTERS ...\n",
    "--filters9=FILTERS options. Each filter in the chain can be separated by\n",
    "spaces or '--'. Alternatively a preset <0-9>[e] can be specified instead of\n",
    "a filter chain.\n",
    "\n",
    "The supported filters and their options are:\n",
);

/// string_conversion.c: lzma_str_list_filters(LZMA_VLI_UNKNOWN,
/// LZMA_STR_ENCODER), as message_filters_help `puts` it.
pub(super) const FILTERS_HELP_LIST: &str = concat!(
    "lzma2:preset=<0-9[e]>,dict=<4KiB-1536MiB>,lc=<0-4>,lp=<0-4>,pb=<0-4>,",
    "mode=<fast|normal>,nice=<2-273>,mf=<hc3|hc4|bt2|bt3|bt4>,depth=<0-4294967295>\n",
    "x86:start=<0-4294967295>\n",
    "arm:start=<0-4294967295>\n",
    "armthumb:start=<0-4294967295>\n",
    "arm64:start=<0-4294967295>\n",
    "riscv:start=<0-4294967295>\n",
    "powerpc:start=<0-4294967295>\n",
    "ia64:start=<0-4294967295>\n",
    "sparc:start=<0-4294967295>\n",
    "delta:dist=<1-256>\n",
);

/// message.c: message_help(false) (`-h`, `--help`), standard output.
pub(super) const HELP: &str = concat!(
    "Usage: %s [OPTION]... [FILE]...\n",
    "Compress or decompress FILEs in the .xz format.\n",
    "\n",
    "Mandatory arguments to long options are mandatory for short options too.\n",
    "\n",
    "  -z, --compress      force compression\n",
    "  -d, --decompress    force decompression\n",
    "  -t, --test          test compressed file integrity\n",
    "  -l, --list          list information about .xz files\n",
    "  -k, --keep          keep (don't delete) input files\n",
    "  -f, --force         force overwrite of output file and (de)compress links\n",
    "  -c, --stdout        write to standard output and don't delete input files\n",
    "  -0 ... -9           compression preset; default is 6; take compressor *and*\n",
    "                      decompressor memory usage into account before using 7-9!\n",
    "  -e, --extreme       try to improve compression ratio by using more CPU time;\n",
    "                      does not affect decompressor memory requirements\n",
    "  -T, --threads=NUM   use at most NUM threads; the default is 0 which uses as\n",
    "                      many threads as there are processor cores\n",
    "  -q, --quiet         suppress warnings; specify twice to suppress errors too\n",
    "  -v, --verbose       be verbose; specify twice for even more verbose\n",
    "  -h, --help          display this short help and exit\n",
    "  -H, --long-help     display the long help (lists also the advanced options)\n",
    "  -V, --version       display the version number and exit\n",
    "\n",
    "With no FILE, or when FILE is -, read standard input.\n",
    "\n",
    "Report bugs to <xz@tukaani.org> (in English or Finnish).\n",
    "XZ Utils home page: <https://tukaani.org/xz/>\n",
);

/// message.c: message_help(true) (`-H`, `--long-help`), standard output.
pub(super) const LONG_HELP: &str = concat!(
    "Usage: %s [OPTION]... [FILE]...\n",
    "Compress or decompress FILEs in the .xz format.\n",
    "\n",
    "Mandatory arguments to long options are mandatory for short options too.\n",
    "\n",
    " Operation mode:\n",
    "\n",
    "  -z, --compress      force compression\n",
    "  -d, --decompress    force decompression\n",
    "  -t, --test          test compressed file integrity\n",
    "  -l, --list          list information about .xz files\n",
    "\n",
    " Operation modifiers:\n",
    "\n",
    "  -k, --keep          keep (don't delete) input files\n",
    "  -f, --force         force overwrite of output file and (de)compress links\n",
    "  -c, --stdout        write to standard output and don't delete input files\n",
    "      --no-sync       don't synchronize the output file to the storage device\n",
    "                      before removing the input file\n",
    "      --single-stream decompress only the first stream, and silently ignore\n",
    "                      possible remaining input data\n",
    "      --no-sparse     do not create sparse files when decompressing\n",
    "  -S, --suffix=.SUF   use the suffix '.SUF' on compressed files\n",
    "      --files[=FILE]  read filenames to process from FILE; if FILE is omitted,\n",
    "                      filenames are read from the standard input; filenames\n",
    "                      must be terminated with the newline character\n",
    "      --files0[=FILE] like --files but use the null character as terminator\n",
    "\n",
    " Basic file format and compression options:\n",
    "\n",
    "  -F, --format=FORMAT file format to encode or decode; possible values are\n",
    "                      'auto' (default), 'xz', 'lzma', 'lzip', and 'raw'\n",
    "  -C, --check=NAME    integrity check type: 'none' (use with caution), 'crc32',\n",
    "                      'crc64' (default), or 'sha256'\n",
    "      --ignore-check  don't verify the integrity check when decompressing\n",
    "  -0 ... -9           compression preset; default is 6; take compressor *and*\n",
    "                      decompressor memory usage into account before using 7-9!\n",
    "  -e, --extreme       try to improve compression ratio by using more CPU time;\n",
    "                      does not affect decompressor memory requirements\n",
    "  -T, --threads=NUM   use at most NUM threads; the default is 0 which uses as\n",
    "                      many threads as there are processor cores\n",
    "      --block-size=SIZE\n",
    "                      start a new .xz block after every SIZE bytes of input;\n",
    "                      use this to set the block size for threaded compression\n",
    "      --block-list=BLOCKS\n",
    "                      start a new .xz block after the given comma-separated\n",
    "                      intervals of uncompressed data; optionally, specify a\n",
    "                      filter chain number (0-9) followed by a ':' before the\n",
    "                      uncompressed data size\n",
    "      --flush-timeout=NUM\n",
    "                      when compressing, if more than NUM milliseconds has\n",
    "                      passed since the previous flush and reading more input\n",
    "                      would block, all pending data is flushed out\n",
    "      --memlimit-compress=LIMIT\n",
    "      --memlimit-decompress=LIMIT\n",
    "      --memlimit-mt-decompress=LIMIT\n",
    "  -M, --memlimit=LIMIT\n",
    "                      set memory usage limit for compression, decompression,\n",
    "                      threaded decompression, or all of these; LIMIT is in\n",
    "                      bytes, %% of RAM, or 0 for defaults\n",
    "      --no-adjust     if compression settings exceed the memory usage limit,\n",
    "                      give an error instead of adjusting the settings downwards\n",
    "\n",
    " Custom filter chain for compression (an alternative to using presets):\n",
    "\n",
    "  --filters=FILTERS   set the filter chain using the liblzma filter string\n",
    "                      syntax; use --filters-help for more information\n",
    "  --filters1=FILTERS ... --filters9=FILTERS\n",
    "                      set additional filter chains using the liblzma filter\n",
    "                      string syntax to use with --block-list\n",
    "  --filters-help      display more information about the liblzma filter string\n",
    "                      syntax and exit\n",
    "\n",
    "  --lzma1[=OPTS]\n",
    "  --lzma2[=OPTS]      LZMA1 or LZMA2; OPTS is a comma-separated list of zero or\n",
    "                      more of the following options (valid values; default):\n",
    "                        preset=PRE  reset options to a preset (0-9[e])\n",
    "                        dict=NUM    dictionary size (4KiB - 1536MiB; 8MiB)\n",
    "                        lc=NUM      number of literal context bits (0-4; 3)\n",
    "                        lp=NUM      number of literal position bits (0-4; 0)\n",
    "                        pb=NUM      number of position bits (0-4; 2)\n",
    "                        mode=MODE   compression mode (fast, normal; normal)\n",
    "                        nice=NUM    nice length of a match (2-273; 64)\n",
    "                        mf=NAME     match finder (hc3, hc4, bt2, bt3, bt4; bt4)\n",
    "                        depth=NUM   maximum search depth; 0=automatic (default)\n",
    "\n",
    "  --x86[=OPTS]        x86 BCJ filter (32-bit and 64-bit)\n",
    "  --arm[=OPTS]        ARM BCJ filter\n",
    "  --armthumb[=OPTS]   ARM-Thumb BCJ filter\n",
    "  --arm64[=OPTS]      ARM64 BCJ filter\n",
    "  --powerpc[=OPTS]    PowerPC BCJ filter (big endian only)\n",
    "  --ia64[=OPTS]       IA-64 (Itanium) BCJ filter\n",
    "  --sparc[=OPTS]      SPARC BCJ filter\n",
    "  --riscv[=OPTS]      RISC-V BCJ filter\n",
    "                      Valid OPTS for all BCJ filters:\n",
    "                        start=NUM   start offset for conversions (default=0)\n",
    "\n",
    "  --delta[=OPTS]      Delta filter; valid OPTS (valid values; default):\n",
    "                        dist=NUM    distance between bytes being subtracted\n",
    "                                    from each other (1-256; 1)\n",
    "\n",
    " Other options:\n",
    "\n",
    "  -q, --quiet         suppress warnings; specify twice to suppress errors too\n",
    "  -v, --verbose       be verbose; specify twice for even more verbose\n",
    "  -Q, --no-warn       make warnings not affect the exit status\n",
    "      --robot         use machine-parsable messages (useful for scripts)\n",
    "\n",
    "      --info-memory   display the total amount of RAM and the currently active\n",
    "                      memory usage limits, and exit\n",
    "  -h, --help          display the short help (lists only the basic options)\n",
    "  -H, --long-help     display this long help and exit\n",
    "  -V, --version       display the version number and exit\n",
    "\n",
    "With no FILE, or when FILE is -, read standard input.\n",
    "\n",
    "Report bugs to <xz@tukaani.org> (in English or Finnish).\n",
    "XZ Utils home page: <https://tukaani.org/xz/>\n",
);

// ---- tuklib_exit.c ----

/// tuklib_exit.c: tuklib_exit, when standard output cannot be flushed or
/// closed after a successful run (with `strerror`; a flush always has a
/// reason, so tuklib_exit's "Unknown error" for `ferror` alone never
/// arises).
pub(super) const WRITE_FAILED: &str = "%s: Writing to standard output failed: %s\n";

// ---- util.c ----

/// util.c: str_to_uint64, a value that does not start with a digit
/// (`"%s: %s"`, the value after leading blanks).
pub(super) const NOT_AN_INTEGER: &str = "%s: Value is not a non-negative decimal integer";

/// util.c: str_to_uint64, an unknown multiplier (`V_ERROR`, then
/// [`VALID_SUFFIXES`] as the fatal message).
pub(super) const INVALID_MULTIPLIER: &str = "%s: Invalid multiplier suffix";

/// util.c: str_to_uint64.
pub(super) const VALID_SUFFIXES: &str =
    "Valid suffixes are 'KiB' (2^10), 'MiB' (2^20), and 'GiB' (2^30).";

/// util.c: str_to_uint64, a value out of `[min, max]` or overflowing.
pub(super) const OUT_OF_RANGE: &str = "Value of the option '%s' must be in the range [%s, %s]";

/// util.c: is_tty_stdin.
pub(super) const TTY_STDIN: &str = "Compressed data cannot be read from a terminal";

/// util.c: is_tty_stdout.
pub(super) const TTY_STDOUT: &str = "Compressed data cannot be written to a terminal";

// ---- args.c ----

/// args.c: parse_block_list, an empty list or one starting with a comma.
pub(super) const BLOCK_LIST_INVALID: &str = "%s: Invalid argument to --block-list";

/// args.c: parse_block_list, a chain number with no size after it.
pub(super) const BLOCK_LIST_NO_SIZE: &str =
    "In --block-list, block size is missing after filter chain number '%s:'";

/// args.c: parse_block_list, a 0 before the last entry.
pub(super) const BLOCK_LIST_ZERO: &str = "0 can only be used as the last element in --block-list";

/// args.c: parse_real, `--format` with an unknown name.
pub(super) const UNKNOWN_FORMAT: &str = "%s: Unknown file format type";

/// args.c: parse_real, `--check` with an unknown name.
pub(super) const UNSUPPORTED_CHECK: &str = "%s: Unsupported integrity check type";

/// args.c: parse_real, a second `--files`/`--files0`.
pub(super) const ONLY_ONE_FILES: &str =
    "Only one file can be specified with '--files' or '--files0'.";

/// args.c: parse_real, `--files=FILE` that cannot be opened (`"%s: %s"`,
/// the name and `strerror`).
pub(super) const NAME_AND_REASON: &str = "%s: %s";

/// args.c: args_parse.
pub(super) const LZIP_COMPRESS: &str = "Compression of lzip files (.lz) is not supported";

/// args.c: args_parse (`V_WARNING`, without setting the exit status).
pub(super) const BLOCK_LIST_IGNORED: &str =
    "--block-list is ignored unless compressing to the .xz format";

/// args.c: args_parse.
pub(super) const RAW_NEEDS_SUFFIX: &str =
    "With --format=raw, --suffix=.SUF is required unless writing to stdout";

// ---- main.c ----

/// main.c: main.
pub(super) const ROBOT_CODING: &str =
    "Compression and decompression with --robot are not supported yet.";

/// main.c: main, `-` among the operands under `--files`/`--files0` from
/// standard input.
pub(super) const STDIN_BOTH: &str =
    "Cannot read data from standard input when reading filenames from standard input";

/// main.c: read_name, a read error (`"%s: Error reading filenames: %s"`).
pub(super) const READ_NAMES_FAILED: &str = "%s: Error reading filenames: %s";

/// main.c: read_name, end of input inside a name.
pub(super) const NAMES_UNEXPECTED_END: &str = "%s: Unexpected end of input when reading filenames";

/// main.c: read_name, a NUL under `--files`.
pub(super) const NAMES_NUL: &str = "%s: Null character found when reading filenames; \
     maybe you meant to use '--files0' instead of '--files'?";

/// The name standard input goes by (args.c: `stdin_filename`).
pub(super) const STDIN_NAME: &[u8] = b"(stdin)";

// ---- options.c ----

/// options.c: parse_options, a value missing or empty (`"%s: %s"` with the
/// whole option string).
pub(super) const NAME_VALUE_PAIRS: &str =
    "Options must be 'name=value' pairs separated with commas";

/// options.c: parse_options.
pub(super) const INVALID_OPTION_NAME: &str = "%s: Invalid option name";

/// options.c: parse_options (`"%s: %s"` with the value).
pub(super) const INVALID_OPTION_VALUE: &str = "Invalid option value";

/// options.c: error_lzma_preset.
pub(super) const UNSUPPORTED_PRESET: &str = "Unsupported LZMA1/LZMA2 preset: %s";

/// options.c: options_lzma.
pub(super) const LC_LP: &str = "The sum of lc and lp must not exceed 4";

// ---- coder.c ----

/// coder.c: coder_add_filter, a fifth filter.
pub(super) const MAX_FILTERS: &str = "Maximum number of filters is four";

/// coder.c: str_to_filters, the first of four lines (`%s` is the chain
/// number, empty for `--filters`).
pub(super) const FILTERS_ERROR: &str = "Error in --filters%s=FILTERS option:";

/// coder.c: str_to_filters, the caret line (`"%*s^"`; the caller pads).
pub(super) const CARET: &str = "%s^";

// ---- string_conversion.c (liblzma's error texts, which xz prints) ----

/// string_conversion.c: str_to_filters.
pub(super) const SC_EMPTY: &str =
    "Empty string is not allowed, try '6' if a default value is needed";
/// string_conversion.c: str_to_filters and set_lzma12_preset.
pub(super) const SC_UNSUPPORTED_PRESET: &str = "Unsupported preset";
/// string_conversion.c: parse_lzma12_preset.
pub(super) const SC_PRESET_FLAG: &str = "Unsupported flag in the preset";
/// string_conversion.c: str_to_filters.
pub(super) const SC_MAX_FILTERS: &str = "The maximum number of filters is four";
/// string_conversion.c: str_to_filters.
pub(super) const SC_NAME_MISSING: &str = "Filter name is missing";
/// string_conversion.c: str_to_filters, `lzma_validate_chain` refused.
pub(super) const SC_INVALID_CHAIN: &str = "Invalid filter chain ('lzma2' missing at the end?)";
/// string_conversion.c: parse_filter.
pub(super) const SC_UNKNOWN_FILTER: &str = "Unknown filter name";
/// string_conversion.c: parse_filter, LZMA1 without `LZMA_STR_ALL_FILTERS`.
pub(super) const SC_NOT_IN_XZ: &str = "This filter cannot be used in the .xz format";
/// string_conversion.c: parse_options.
pub(super) const SC_PAIRS: &str = "Options must be 'name=value' pairs separated with commas";
/// string_conversion.c: parse_options.
pub(super) const SC_UNKNOWN_OPTION: &str = "Unknown option name";
/// string_conversion.c: parse_options.
pub(super) const SC_EMPTY_VALUE: &str = "Option value cannot be empty";
/// string_conversion.c: parse_options.
pub(super) const SC_INVALID_VALUE: &str = "Invalid option value";
/// string_conversion.c: parse_options.
pub(super) const SC_NOT_INTEGER: &str = "Value is not a non-negative decimal integer";
/// string_conversion.c: parse_options.
pub(super) const SC_OUT_OF_RANGE: &str = "Value out of range";
/// string_conversion.c: parse_options.
pub(super) const SC_NO_SUFFIX: &str = "This option does not support any multiplier suffixes";
/// string_conversion.c: parse_options.
pub(super) const SC_BAD_SUFFIX: &str = "Invalid multiplier suffix (KiB, MiB, or GiB)";
/// string_conversion.c: parse_lzma12.
pub(super) const SC_LC_LP: &str = "The sum of lc and lp must not exceed 4";

// ---- suffix.c ----

/// suffix.c: suffix_set.
pub(super) const INVALID_SUFFIX: &str = "%s: Invalid filename suffix";

/// suffix.c: uncompressed_name (a warning).
pub(super) const UNKNOWN_SUFFIX: &str = "%s: Filename has an unknown suffix, skipping";

/// suffix.c: msg_suffix (a warning).
pub(super) const HAS_SUFFIX: &str = "%s: File already has '%s' suffix, skipping";

// ---- hardware.c ----

/// hardware.c: hardware_memlimit_show under `--robot`: physical memory, the
/// compression, decompression and multi-threaded decompression limits,
/// the `-T0` default and the thread count, tab-separated.
pub(super) const INFO_MEMORY_ROBOT: &str = "%s\t%s\t%s\t%s\t%s\t%s\n";

/// hardware.c: hardware_memlimit_show, the heading.
pub(super) const INFO_HARDWARE: &str = "Hardware information:\n";

/// hardware.c: hardware_memlimit_show, the second heading (after a blank
/// line).
pub(super) const INFO_LIMITS: &str = "\nMemory usage limits:\n";

/// hardware.c: hardware_memlimit_show, the row labels in order, each padded
/// to the widest (`%-*s`).
pub(super) const INFO_LABELS: [&str; 6] = [
    "Amount of physical memory (RAM):",
    "Number of processor threads:",
    "Compression:",
    "Decompression:",
    "Multi-threaded decompression:",
    "Default for -T0:",
];

/// hardware.c: memlimit_show, a row with a limit (`"  %-*s  %s MiB (%s B)\n"`;
/// the caller pads the label).
pub(super) const INFO_ROW_LIMIT: &str = "  %s  %s MiB (%s B)\n";

/// hardware.c: memlimit_show, a row with no limit.
pub(super) const INFO_ROW_DISABLED: &str = "  %s  Disabled\n";

/// hardware.c: hardware_memlimit_show, the thread-count row.
pub(super) const INFO_ROW_THREADS: &str = "  %s  %s\n";

// ---- getopt (the C library's) ----

/// BSD libc getopt_long.c: an unknown short option (`illoptchar`).
pub(super) const BSD_INVALID_OPTION: &str = "%s: invalid option -- %s\n";
/// BSD libc getopt_long.c: the same under `POSIXLY_CORRECT` (`illoptchar`).
pub(super) const BSD_ILLEGAL_OPTION: &str = "%s: illegal option -- %s\n";
/// BSD libc getopt_long.c: `recargchar`.
pub(super) const BSD_NEEDS_ARGUMENT_SHORT: &str = "%s: option requires an argument -- %s\n";
/// BSD libc getopt_long.c: `ambig`, the name as typed up to any `=`.
pub(super) const BSD_AMBIGUOUS: &str = "%s: option `--%s' is ambiguous\n";
/// BSD libc getopt_long.c: `noarg`, the name as typed up to the `=`.
pub(super) const BSD_NO_ARGUMENT: &str = "%s: option `--%s' doesn't allow an argument\n";
/// BSD libc getopt_long.c: `recargstring`, the name as typed.
pub(super) const BSD_NEEDS_ARGUMENT_LONG: &str = "%s: option `--%s' requires an argument\n";
/// BSD libc getopt_long.c: `illoptstring`, the word after `--`, `=value`
/// included.
pub(super) const BSD_UNRECOGNIZED: &str = "%s: unrecognized option `--%s'\n";

/// glibc getopt.c: an unknown short option.
pub(super) const GLIBC_INVALID_OPTION: &str = "%s: invalid option -- '%s'\n";
/// glibc getopt.c: a short option without its argument.
pub(super) const GLIBC_NEEDS_ARGUMENT_SHORT: &str = "%s: option requires an argument -- '%s'\n";
/// glibc getopt.c: process_long_option, followed by [`GLIBC_CANDIDATE`]
/// for each candidate and a newline. The word as typed, `=value` included.
pub(super) const GLIBC_AMBIGUOUS: &str = "%s: option '--%s' is ambiguous; possibilities:";
/// glibc getopt.c: process_long_option, one candidate.
pub(super) const GLIBC_CANDIDATE: &str = " '--%s'";
/// glibc getopt.c: process_long_option, the option's full name.
pub(super) const GLIBC_NO_ARGUMENT: &str = "%s: option '--%s' doesn't allow an argument\n";
/// glibc getopt.c: process_long_option, the option's full name.
pub(super) const GLIBC_NEEDS_ARGUMENT_LONG: &str = "%s: option '--%s' requires an argument\n";
/// glibc getopt.c: process_long_option, the word as typed.
pub(super) const GLIBC_UNRECOGNIZED: &str = "%s: unrecognized option '--%s'\n";

// ---- stuffr's own, until Task 6 ----

/// Compression, decompression and `--list` arrive with the coder (0.13.0
/// Tasks 6 and 7); until then a file operand gets this error.
pub(super) const NOT_YET: &str = "%s: not yet supported by this build";
