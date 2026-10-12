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

/// message.c: message_bug (fatal).
pub(super) const BUG: &str = "Internal error (bug)";

/// message.c: message_strm, `LZMA_UNSUPPORTED_CHECK`.
pub(super) const STRM_UNSUPPORTED_CHECK: &str =
    "Unsupported type of integrity check; not verifying file integrity";

/// message.c: message_strm, `LZMA_MEMLIMIT_ERROR`.
pub(super) const STRM_MEMLIMIT: &str = "Memory usage limit reached";

/// message.c: message_strm, `LZMA_FORMAT_ERROR`.
pub(super) const STRM_FORMAT: &str = "File format not recognized";

/// message.c: message_strm, `LZMA_OPTIONS_ERROR`.
pub(super) const STRM_OPTIONS: &str = "Unsupported options";

/// message.c: message_strm, `LZMA_DATA_ERROR`.
pub(super) const STRM_DATA: &str = "Compressed data is corrupt";

/// message.c: message_strm, `LZMA_BUF_ERROR`.
pub(super) const STRM_BUF: &str = "Unexpected end of input";

/// message.c: message_mem_needed with no limit (`uint64_to_str` of the
/// rounded-up MiB).
pub(super) const MEM_NEEDED_NO_LIMIT: &str =
    "%s MiB of memory is required. The limiter is disabled.";

/// message.c: message_mem_needed (the limit as [`MEM_LIMIT_BYTES`] or
/// [`MEM_LIMIT_MIB`]).
pub(super) const MEM_NEEDED: &str = "%s MiB of memory is required. The limit is %s.";

/// message.c: message_mem_needed, a limit under 1 MiB.
pub(super) const MEM_LIMIT_BYTES: &str = "%s B";

/// message.c: message_mem_needed, a limit of 1 MiB or more (rounded up).
pub(super) const MEM_LIMIT_MIB: &str = "%s MiB";

/// message.c: message_filters_show (`fprintf(stderr, ...)`, the program
/// name and lzma_str_from_filters' string).
pub(super) const FILTER_CHAIN: &str = "%s: Filter chain: %s\n";

/// message.c: message_error/message_warning's `"%s: %s"` around a name: the
/// coder's (coder.c: coder_init, coder_normal, with message_strm) and
/// file_io.c's (io_open_src_real, io_open_dest_real, with `strerror`).
pub(super) const NAME_COLON: &str = "%s: %s";

/// coder.c: str_to_filters (the masked filter string) and its fatal
/// message (`message(V_ERROR, "%s", ...)`, `message_fatal("%s", ...)`).
pub(super) const PLAIN: &str = "%s";

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

/// coder.c: memlimit_too_small.
pub(super) const MEMLIMIT_TOO_LOW: &str =
    "Memory usage limit is too low for the given filter setup.";

/// coder.c: coder_set_compression_settings, a `--block-list` chain with no
/// `--filtersN` (the number twice).
pub(super) const CHAIN_NOT_SPECIFIED: &str =
    "filter chain %s used by --block-list but not specified with --filters%s=";

/// coder.c: coder_set_compression_settings, a preset in raw mode
/// (`V_WARNING`, the status unchanged), first line.
pub(super) const RAW_PRESET: &str = "Using a preset in raw mode is discouraged.";

/// coder.c: coder_set_compression_settings, a preset in raw mode, second
/// line.
pub(super) const RAW_PRESET_VARIES: &str =
    "The exact options of the presets may vary between software versions.";

/// coder.c: coder_set_compression_settings.
pub(super) const LZMA_NEEDS_LZMA1: &str = "The .lzma format supports only the LZMA1 filter";

/// coder.c: coder_set_compression_settings.
pub(super) const LZMA1_NOT_IN_XZ: &str = "LZMA1 cannot be used with the .xz format";

/// coder.c: coder_set_compression_settings, `--flush-timeout` with a chain
/// holding something other than LZMA2 and Delta.
pub(super) const FLUSH_INCOMPATIBLE: &str = "Filter chain %s is incompatible with --flush-timeout";

/// coder.c: coder_set_compression_settings (`V_WARNING`, the status
/// unchanged).
pub(super) const FLUSH_SINGLE_THREADED: &str =
    "Switching to single-threaded mode due to --flush-timeout";

/// coder.c: coder_set_compression_settings, `lzma_mt_block_size` refusing a
/// chain.
pub(super) const UNSUPPORTED_CHAIN_N: &str = "Unsupported options in filter chain %s";

/// coder.c: coder_set_compression_settings (`V_DEBUG`).
pub(super) const USING_THREADS: &str = "Using up to %s threads.";

/// coder.c: coder_set_compression_settings, a memusage of `UINT64_MAX`.
pub(super) const UNSUPPORTED_CHAIN: &str = "Unsupported filter chain or filter options";

/// coder.c: coder_set_compression_settings (`V_DEBUG`).
pub(super) const DECOMPRESSION_NEEDS: &str = "Decompression will need %s MiB of memory.";

/// coder.c: coder_set_compression_settings (`V_DEBUG` since 5.6.1).
pub(super) const REDUCED_THREADS: &str = "Reduced the number of threads from %s to %s to not \
     exceed the memory usage limit of %s MiB";

/// coder.c: coder_set_compression_settings (`V_DEBUG` since 5.6.1).
pub(super) const REDUCED_TO_ONE: &str = "Reduced the number of threads from %s to one. The \
     automatic memory usage limit of %s MiB is still being exceeded. %s MiB of memory is \
     required. Continuing anyway.";

/// coder.c: coder_set_compression_settings (`V_WARNING`, the status
/// unchanged).
pub(super) const SINGLE_THREADED_FOR_LIMIT: &str =
    "Switching to single-threaded mode to not exceed the memory usage limit of %s MiB";

/// coder.c: coder_set_compression_settings, the default chain (`V_WARNING`,
/// the status unchanged).
pub(super) const ADJUSTED_DICT: &str = "Adjusted LZMA%s dictionary size from %s MiB to %s MiB \
     to not exceed the memory usage limit of %s MiB";

/// coder.c: coder_set_compression_settings, a `--filtersN` chain.
pub(super) const ADJUSTED_DICT_N: &str = "Adjusted LZMA%s dictionary size for --filters%s from \
     %s MiB to %s MiB to not exceed the memory usage limit of %s MiB";

// ---- file_io.c ----

/// file_io.c: io_open_src.
pub(super) const EMPTY_FILENAME: &str = "Empty filename, skipping";

/// file_io.c: io_open_src_real (a warning).
pub(super) const IS_SYMLINK: &str = "%s: Is a symbolic link, skipping";

/// file_io.c: io_open_src_real (a warning).
pub(super) const IS_DIRECTORY: &str = "%s: Is a directory, skipping";

/// file_io.c: io_open_src_real (a warning).
pub(super) const NOT_REGULAR: &str = "%s: Not a regular file, skipping";

/// file_io.c: io_open_src_real (a warning).
pub(super) const SETID: &str = "%s: File has setuid or setgid bit set, skipping";

/// file_io.c: io_open_src_real (a warning).
pub(super) const STICKY: &str = "%s: File has sticky bit set, skipping";

/// file_io.c: io_open_src_real (a warning).
pub(super) const HARD_LINKS: &str = "%s: Input file has more than one hard link, skipping";

/// file_io.c: io_unlink (a warning).
pub(super) const MOVED: &str = "%s: File seems to have been moved, not removing";

/// file_io.c: io_unlink (a warning) and io_open_dest_real (an error).
pub(super) const CANNOT_REMOVE: &str = "%s: Cannot remove: %s";

/// file_io.c: io_copy_attrs (a warning, only when root).
pub(super) const CANNOT_SET_OWNER: &str = "%s: Cannot set the file owner: %s";

/// file_io.c: io_copy_attrs (a warning).
pub(super) const CANNOT_SET_GROUP: &str = "%s: Cannot set the file group: %s";

/// file_io.c: io_copy_attrs (a warning).
pub(super) const CANNOT_SET_PERMISSIONS: &str = "%s: Cannot set the file permissions: %s";

/// file_io.c: io_sync_dest.
pub(super) const SYNC_FILE_FAILED: &str = "%s: Synchronizing the file failed: %s";

/// file_io.c: io_sync_dest.
pub(super) const SYNC_DIR_FAILED: &str = "%s: Synchronizing the directory of the file failed: %s";

/// file_io.c: io_open_dest_real, `--synchronous`'s directory.
pub(super) const OPEN_DIR_FAILED: &str = "%s: Opening the directory failed: %s";

/// file_io.c: io_close_dest.
pub(super) const CLOSE_FAILED: &str = "%s: Closing the file failed: %s";

/// file_io.c: io_write and io_close.
pub(super) const SPARSE_SEEK_FAILED: &str =
    "%s: Seeking failed when trying to create a sparse file: %s";

/// file_io.c: io_read.
pub(super) const READ_ERROR: &str = "%s: Read error: %s";

/// file_io.c: io_seek_src.
pub(super) const SEEK_ERROR: &str = "%s: Error seeking the file: %s";

/// file_io.c: io_pread, a short read.
pub(super) const UNEXPECTED_EOF: &str = "%s: Unexpected end of file";

/// file_io.c: io_write_buf (not for `EPIPE`).
pub(super) const WRITE_ERROR: &str = "%s: Write error: %s";

/// file_io.c: io_wait.
pub(super) const POLL_FAILED: &str = "%s: poll() failed: %s";

/// file_io.c: io_open_dest_real, standard output's name.
pub(super) const STDOUT_NAME: &[u8] = b"(stdout)";

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

// ---- message.c: print_filename (under --list, to standard output) ----

/// message.c: print_filename, the number of files known.
pub(super) const FILENAME_OF: &str = "%s (%s/%s)\n";

/// message.c: print_filename, `--files`/`--files0` in use.
pub(super) const FILENAME_NTH: &str = "%s (%s)\n";

// ---- list.c ----
//
// Every `%s` of a table row is a field list.rs has already padded to its
// column (the C code's `%*s`/`%-*s` with tuklib_mbstr_fw, which in the C
// locale pads to the column's width); the spacing between is verbatim.

/// list.c: list_file (with tuklib_exit(E_ERROR, E_ERROR, false) after).
pub(super) const LIST_XZ_ONLY: &str =
    "--list works only on .xz files (--format=xz or --format=auto)";

/// list.c: list_file, after [`LIST_XZ_ONLY`] under `--format=lzma`.
pub(super) const LIST_LZMAINFO: &str = "Try 'lzmainfo' with .lzma files.";

/// list.c: list_file.
pub(super) const LIST_STDIN: &str = "--list does not support reading from standard input";

/// list.c: parse_indexes.
pub(super) const LIST_EMPTY: &str = "%s: File is empty";

/// list.c: parse_indexes.
pub(super) const LIST_TOO_SMALL: &str = "%s: Too small to be a valid .xz file";

/// list.c: update_totals (message_fatal).
pub(super) const LIST_TOTALS_TOO_LARGE: &str =
    "Error: The total compressed or uncompressed size of the files is too large";

/// list.c: colon_strs[], in their enum's order (init_colon_strs pads them
/// all to the longest).
pub(super) const COLON_STRS: [&str; 10] = [
    "Streams:",
    "Blocks:",
    "Compressed size:",
    "Uncompressed size:",
    "Ratio:",
    "Check:",
    "Stream Padding:",
    "Memory needed:",
    "Sizes in headers:",
    "Number of files:",
];

/// list.c: headings[], each with its minimum columns, in their enum's
/// order (init_headings widens a column to its heading, and Check to the
/// widest check name).
pub(super) const HEADINGS: [(&str, usize); 16] = [
    ("Stream", 6),
    ("Block", 9),
    ("Blocks", 9),
    ("CompOffset", 15),
    ("UncompOffset", 15),
    ("CompSize", 15),
    ("UncompSize", 15),
    ("TotalSize", 15),
    ("Ratio", 5),
    ("Check", 10),
    ("CheckVal", 1),
    ("Padding", 7),
    ("Header", 5),
    ("Flags", 2),
    ("MemUsage", 7 + 4),
    ("Filters", 1),
];

/// list.c: check_names[], by check ID.
pub(super) const CHECK_NAMES: [&str; 16] = [
    "None",
    "CRC32",
    "Unknown-2",
    "Unknown-3",
    "CRC64",
    "Unknown-5",
    "Unknown-6",
    "Unknown-7",
    "Unknown-8",
    "Unknown-9",
    "SHA-256",
    "Unknown-11",
    "Unknown-12",
    "Unknown-13",
    "Unknown-14",
    "Unknown-15",
];

/// list.c: get_check_names, the separator in tables and under `--robot`.
pub(super) const CHECK_SEP: &str = ",";

/// list.c: get_check_names, the separator in the `-v` summaries.
pub(super) const CHECK_SEP_SPACE: &str = ", ";

/// list.c: get_ratio, and parse_check_value with no check.
pub(super) const NO_VALUE: &str = "---";

/// list.c: print_info_basic, the headings (`puts`).
pub(super) const BASIC_HEADINGS: &str =
    "Strms  Blocks   Compressed Uncompressed  Ratio  Check   Filename\n";

/// list.c: print_info_basic, one file (`"%*s %*s  %*s  %*s  %*s  %-*s %s\n"`).
pub(super) const BASIC_ROW: &str = "%s %s  %s  %s  %s  %s %s\n";

/// list.c: print_totals_basic, the separator (79 dashes, `puts`).
pub(super) const BASIC_TOTALS_LINE: &str =
    "-------------------------------------------------------------------------------\n";

/// list.c: print_totals_basic (`"%5s %7s  %11s  %11s  %5s  %-7s "`, then
/// ngettext's plural, the count always above one).
pub(super) const BASIC_TOTALS: &str = "%s %s  %s  %s  %s  %s %s files\n";

/// list.c: print_adv_helper and friends (`"  %-*s %s\n"`).
pub(super) const ADV_ROW: &str = "  %s %s\n";

/// list.c: print_info_adv and print_totals_adv (`"  %-*s %s MiB\n"`).
pub(super) const ADV_ROW_MIB: &str = "  %s %s MiB\n";

/// list.c: print_info_adv and print_totals_adv.
pub(super) const ADV_MIN_VERSION: &str = "  Minimum XZ Utils version: %s\n";

/// list.c: print_info_adv and print_totals_adv, "Sizes in headers".
pub(super) const YES: &str = "Yes";
pub(super) const NO: &str = "No";

/// list.c: print_info_adv, the Streams table's headings
/// (`"  %s\n    %*s %*s %*s %*s %*s %*s  %*s  %-*s %*s\n"`).
pub(super) const ADV_STREAMS_HEADINGS: &str = "  %s\n    %s %s %s %s %s %s  %s  %s %s\n";

/// list.c: print_info_adv, one Stream (`"    %*s %*s %*s %*s "` then
/// `"%*s %*s  %*s  %-*s %*s\n"`).
pub(super) const ADV_STREAM_ROW: &str = "    %s %s %s %s %s %s  %s  %s %s\n";

/// list.c: print_info_adv, the Blocks table's headings
/// (`"  %s\n    %*s %*s %*s %*s %*s %*s  %*s  %-*s"`).
pub(super) const ADV_BLOCKS_HEADINGS: &str = "  %s\n    %s %s %s %s %s %s  %s  %s";

/// list.c: print_info_adv, the `-vv` headings after them
/// (`" %-*s  %*s  %-*s %*s %*s  %s"`).
pub(super) const ADV_BLOCKS_HEADINGS_DEBUG: &str = " %s  %s  %s %s %s  %s";

/// list.c: print_info_adv, one Block (`"    %*s %*s %*s %*s "` then
/// `"%*s %*s  %*s  %-*s"`).
pub(super) const ADV_BLOCK_ROW: &str = "    %s %s %s %s %s %s  %s  %s";

/// list.c: print_info_adv, a Block's `-vv` fields
/// (`" %-*s  %*s  %-*s %*s %*s MiB  %s"`).
pub(super) const ADV_BLOCK_ROW_DEBUG: &str = " %s  %s  %s %s %s MiB  %s";

/// list.c: the end of a table line (`putchar('\n')`).
pub(super) const NEWLINE: &str = "\n";

/// list.c: print_totals_adv (`putchar('\n')`, then `puts`).
pub(super) const ADV_TOTALS: &str = "\nTotals:\n";

/// list.c: xz_ver_to_str (`"%u.%u.%u%s"`), and its stability suffixes.
pub(super) const VERSION: &str = "%s.%s.%s%s";
pub(super) const VERSION_ALPHA: &str = "alpha";
pub(super) const VERSION_BETA: &str = "beta";

/// util.c: uint64_to_nicestr, the units.
pub(super) const NICESTR_UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

/// util.c: uint64_to_nicestr (`"%u"` or `"%.1f"`, then `" %s"`).
pub(super) const NICESTR: &str = "%s %s";

/// util.c: uint64_to_nicestr with `always_also_bytes`.
pub(super) const NICESTR_BYTES: &str = " (%s B)";

/// list.c: print_info_robot.
pub(super) const ROBOT_NAME: &str = "name\t%s\n";

/// list.c: print_info_robot.
pub(super) const ROBOT_FILE: &str = "file\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n";

/// list.c: print_info_robot, under `-v`.
pub(super) const ROBOT_STREAM: &str = "stream\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n";

/// list.c: print_info_robot, under `-v`.
pub(super) const ROBOT_BLOCK: &str = "block\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s";

/// list.c: print_info_robot, a Block's `-vv` fields.
pub(super) const ROBOT_BLOCK_DEBUG: &str = "\t%s\t%s\t%s\t%s\t%s\t%s";

/// list.c: print_info_robot, under `-vv`.
pub(super) const ROBOT_SUMMARY: &str = "summary\t%s\t%s\t%s\n";

/// list.c: print_totals_robot.
pub(super) const ROBOT_TOTALS: &str = "totals\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s";

/// list.c: print_totals_robot, under `-vv`.
pub(super) const ROBOT_TOTALS_DEBUG: &str = "\t%s\t%s\t%s";

/// list.c: print_info_robot and print_totals_robot, "sizes in headers".
pub(super) const ROBOT_YES: &str = "yes";
pub(super) const ROBOT_NO: &str = "no";
