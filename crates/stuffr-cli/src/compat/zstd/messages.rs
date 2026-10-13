//! Every string the zstd family prints, as zstd 1.5.7's `zstd` prints it
//! (C locale; zstd has no NLS).
//!
//! Ported from zstd 1.5.7 `programs/` (BSD-3-Clause, Meta Platforms, Inc.;
//! `LICENSE-zstd`). Each constant names the file and function it comes
//! from. Formats follow C's `printf` as [`printf`] renders them: `%s` and
//! `%d` take the next argument (an integer is formatted by the caller),
//! `%%` is a literal percent sign.
//!
//! The help texts are `usage`/`usageAdvanced` for the configuration the
//! Global Constraints fix: gzip, lzma and lz4 on, multi-threading on,
//! legacy on, and `ZSTD_NOBENCH`/`ZSTD_NOTRACE` defined, so the benchmark
//! section and `--trace` are not printed (R13, spec deviation 5).
//!
//! The deliberate change: the welcome banner names stuffr ([`WELCOME`],
//! spec deviation 1).

pub(super) use crate::compat::host::printf;

// ---- zstdcli.c: constants and the banner ----

/// zstdcli.c: `ZSTD_VERSION_STRING`, what `printVersion` prints below the
/// default display level (`zstd -qV`).
pub(super) const VERSION_STRING: &str = "1.5.7";

/// zstdcli.c: `WELCOME_MESSAGE`, `"*** %s (%i-bit) %s, by %s ***\n"` with
/// `COMPRESSOR_NAME`, the pointer width, `ZSTD_VERSION` and `AUTHOR`. Spec
/// deviation 1: the compressor name carries stuffr's version (the argument).
pub(super) const WELCOME: &str =
    "*** Zstandard CLI (stuffr %s; zstd 1.5.7 compatible) (64-bit) v1.5.7, by Yann Collet ***\n";

/// zstdcli.c: printVersion, `"%s\n"` with `ZSTD_VERSION_STRING`.
pub(super) const VERSION_ONLY: &str = "%s\n";

/// zstdcli.c: printVersion at display level 3: the format support line
/// (legacy v0.5+, `ZSTD_GZCOMPRESS`, `ZSTD_LZ4COMPRESS`,
/// `ZSTD_LZMACOMPRESS`), its pieces joined as the reference prints them.
pub(super) const SUPPORTS: &str = "*** supports: zstd, zstd legacy v0.5+, gzip, lz4, lzma, xz \n";

/// zstdcli.c: printVersion at display level 4, under `#ifdef
/// _POSIX_C_SOURCE` (platform.h defines it on Linux).
pub(super) const POSIX_C_SOURCE: &str = "_POSIX_C_SOURCE defined: %dL\n";

/// zstdcli.c: printVersion at display level 4, under `#ifdef
/// _POSIX_VERSION` (the trailing space is the reference's).
pub(super) const POSIX_VERSION: &str = "_POSIX_VERSION defined: %dL \n";

/// zstdcli.c: printVersion at display level 4, under `#ifdef
/// PLATFORM_POSIX_VERSION`.
pub(super) const PLATFORM_POSIX_VERSION: &str = "PLATFORM_POSIX_VERSION defined: %dL\n";

// ---- zstdcli.c: usage ----

/// zstdcli.c: usage, up to the gzip-only line (`%s`: the program name).
pub(super) const USAGE_HEAD: &str = concat!(
    "Compress or decompress the INPUT file(s); reads from STDIN if INPUT is `-` or not provided.\n\n",
    "Usage: %s [OPTIONS...] [INPUT... | -] [-o OUTPUT]\n\n",
    "Options:\n",
    "  -o OUTPUT                     Write output to a single file, OUTPUT.\n",
    "  -k, --keep                    Preserve INPUT file(s). [Default] \n",
    "  --rm                          Remove INPUT file(s) after successful (de)compression.\n",
);

/// zstdcli.c: usage, invoked as `gzip` (`ZSTD_GZCOMPRESS`).
pub(super) const USAGE_GZ_NO_NAME: &str =
    "  -n, --no-name                 Do not store original filename when compressing.\n\n";

/// zstdcli.c: usage, the rest (`%d`: `ZSTDCLI_CLEVEL_MAX`, then
/// `ZSTDCLI_CLEVEL_DEFAULT`).
pub(super) const USAGE_TAIL: &str = concat!(
    "\n",
    "  -#                            Desired compression level, where `#` is a number between 1 and %d;\n",
    "                                lower numbers provide faster compression, higher numbers yield\n",
    "                                better compression ratios. [Default: %d]\n\n",
    "  -d, --decompress              Perform decompression.\n",
    "  -D DICT                       Use DICT as the dictionary for compression or decompression.\n\n",
    "  -f, --force                   Disable input and output checks. Allows overwriting existing files,\n",
    "                                receiving input from the console, printing output to STDOUT, and\n",
    "                                operating on links, block devices, etc. Unrecognized formats will be\n",
    "                                passed-through through as-is.\n\n",
    "  -h                            Display short usage and exit.\n",
    "  -H, --help                    Display full help and exit.\n",
    "  -V, --version                 Display the program version and exit.\n",
    "\n",
);

// ---- zstdcli.c: usageAdvanced ----

/// zstdcli.c: usageAdvanced, after the banner (the blank line before
/// `usage`).
pub(super) const ADV_AFTER_BANNER: &str = "\n";

/// zstdcli.c: usageAdvanced, "Advanced options" up to the file-list lines
/// (`--trace` is under `#ifndef ZSTD_NOTRACE`, not printed).
pub(super) const ADV_OPTIONS: &str = concat!(
    "Advanced options:\n",
    "  -c, --stdout                  Write to STDOUT (even if it is a console) and keep the INPUT file(s).\n\n",
    "  -v, --verbose                 Enable verbose output; pass multiple times to increase verbosity.\n",
    "  -q, --quiet                   Suppress warnings; pass twice to suppress errors.\n",
    "\n",
    "  --[no-]progress               Forcibly show/hide the progress counter. NOTE: Any (de)compressed\n",
    "                                output to terminal will mix with progress counter text.\n\n",
);

/// zstdcli.c: usageAdvanced, `UTIL_HAS_CREATEFILELIST`.
pub(super) const ADV_FILELIST: &str = concat!(
    "  -r                            Operate recursively on directories.\n",
    "  --filelist LIST               Read a list of files to operate on from LIST.\n",
    "  --output-dir-flat DIR         Store processed files in DIR.\n",
);

/// zstdcli.c: usageAdvanced, `UTIL_HAS_MIRRORFILELIST` (not on Windows).
pub(super) const ADV_MIRROR: &str = "  --output-dir-mirror DIR       Store processed files in DIR, respecting original directory structure.\n";

/// zstdcli.c: usageAdvanced, `AIO_supported()` (multi-threading on).
pub(super) const ADV_ASYNCIO: &str =
    "  --[no-]asyncio                Use asynchronous IO. [Default: Enabled]\n";

/// zstdcli.c: usageAdvanced, the checksum lines and `--`.
pub(super) const ADV_CHECK: &str = concat!(
    "\n",
    "  --[no-]check                  Add XXH64 integrity checksums during compression. [Default: Add, Validate]\n",
    "                                If `-d` is present, ignore/validate checksums during decompression.\n",
    "\n",
    "  --                            Treat remaining arguments after `--` as files.\n",
);

/// zstdcli.c: usageAdvanced, "Advanced compression options" up to the
/// gzip-only `--best` line (`%d`: `ZSTDCLI_CLEVEL_MAX`, `ZSTD_maxCLevel()`,
/// then `--fast`'s default, 1).
pub(super) const ADV_COMPRESSION: &str = concat!(
    "\n",
    "Advanced compression options:\n",
    "  --ultra                       Enable levels beyond %d, up to %d; requires more memory.\n",
    "  --fast[=#]                    Use to very fast compression levels. [Default: %d]\n",
);

/// zstdcli.c: usageAdvanced, invoked as `gzip` (`ZSTD_GZCOMPRESS`).
pub(super) const ADV_GZ_BEST: &str =
    "  --best                        Compatibility alias for `-9`.\n";

/// zstdcli.c: usageAdvanced, the rest of the compression options (`%d`:
/// `g_defaultMaxWindowLog`). `ZSTD_MULTITHREAD`, `ZSTD_GZCOMPRESS`,
/// `ZSTD_LZMACOMPRESS` and `ZSTD_LZ4COMPRESS` are on; the lz4 line's short
/// padding is the reference's.
pub(super) const ADV_COMPRESSION_REST: &str = concat!(
    "  --adapt                       Dynamically adapt compression level to I/O conditions.\n",
    "  --long[=#]                    Enable long distance matching with window log #. [Default: %d]\n",
    "  --patch-from=REF              Use REF as the reference point for Zstandard's diff engine. \n\n",
    "  -T#                           Spawn # compression threads. [Default: 1; pass 0 for core count.]\n",
    "  --single-thread               Share a single thread for I/O and compression (slightly different than `-T1`).\n",
    "  --auto-threads={physical|logical}\n",
    "                                Use physical/logical cores when using `-T0`. [Default: Physical]\n\n",
    "  -B#                           Set job size to #. [Default: 0 (automatic)]\n",
    "  --rsyncable                   Compress using a rsync-friendly method (`-B` sets block size). \n",
    "\n",
    "  --exclude-compressed          Only compress files that are not already compressed.\n\n",
    "  --stream-size=#               Specify size of streaming input from STDIN.\n",
    "  --size-hint=#                 Optimize compression parameters for streaming input of approximately size #.\n",
    "  --target-compressed-block-size=#\n",
    "                                Generate compressed blocks of approximately # size.\n\n",
    "  --no-dictID                   Don't write `dictID` into the header (dictionary compression only).\n",
    "  --[no-]compress-literals      Force (un)compressed literals.\n",
    "  --[no-]row-match-finder       Explicitly enable/disable the fast, row-based matchfinder for\n",
    "                                the 'greedy', 'lazy', and 'lazy2' strategies.\n",
    "\n",
    "  --format=zstd                 Compress files to the `.zst` format. [Default]\n",
    "  --[no-]mmap-dict              Memory-map dictionary file rather than mallocing and loading all at once\n",
    "  --format=gzip                 Compress files to the `.gz` format.\n",
    "  --format=xz                   Compress files to the `.xz` format.\n",
    "  --format=lzma                 Compress files to the `.lzma` format.\n",
    "  --format=lz4                 Compress files to the `.lz4` format.\n",
);

/// zstdcli.c: usageAdvanced, "Advanced decompression options" up to the
/// sparse line.
pub(super) const ADV_DECOMPRESSION: &str = concat!(
    "\n",
    "Advanced decompression options:\n",
    "  -l                            Print information about Zstandard-compressed files.\n",
    "  --test                        Test compressed file integrity.\n",
    "  -M#                           Set the memory usage limit to # megabytes.\n",
);

/// zstdcli.c: usageAdvanced, `ZSTD_SPARSE_DEFAULT` 1 (everywhere but
/// Apple's platforms, platform.h).
pub(super) const ADV_SPARSE_ON: &str = "  --[no-]sparse                 Enable sparse mode. [Default: Enabled for files, disabled for STDOUT.]\n";

/// zstdcli.c: usageAdvanced, `ZSTD_SPARSE_DEFAULT` 0 (Apple's platforms).
pub(super) const ADV_SPARSE_OFF: &str =
    "  --[no-]sparse                 Enable sparse mode. [Default: Disabled]\n";

/// zstdcli.c: usageAdvanced, the pass-through line (`%s`: `Enabled` or
/// `Disabled`).
pub(super) const ADV_PASS_THROUGH: &str =
    "  --[no-]pass-through           Pass through uncompressed files as-is. [Default: %s]\n";

/// zstdcli.c: usageAdvanced, the pass-through default for the `cat` names.
pub(super) const ENABLED: &str = "Enabled";

/// zstdcli.c: usageAdvanced, the pass-through default otherwise.
pub(super) const DISABLED: &str = "Disabled";

/// zstdcli.c: usageAdvanced, "Dictionary builder" (`%d`:
/// `g_defaultSelectivityLevel`; `%s`: `g_defaultDictName`; `%d`:
/// `g_defaultMaxDictSize`). The benchmark section after it is under
/// `#ifndef ZSTD_NOBENCH`, not printed.
pub(super) const ADV_DICTIONARY: &str = concat!(
    "\n",
    "Dictionary builder:\n",
    "  --train                       Create a dictionary from a training set of files.\n\n",
    "  --train-cover[=k=#,d=#,steps=#,split=#,shrink[=#]]\n",
    "                                Use the cover algorithm (with optional arguments).\n",
    "  --train-fastcover[=k=#,d=#,f=#,steps=#,split=#,accel=#,shrink[=#]]\n",
    "                                Use the fast cover algorithm (with optional arguments).\n\n",
    "  --train-legacy[=s=#]          Use the legacy algorithm with selectivity #. [Default: %d]\n",
    "  -o NAME                       Use NAME as dictionary name. [Default: %s]\n",
    "  --maxdict=#                   Limit dictionary to specified size #. [Default: %d]\n",
    "  --dictID=#                    Force dictionary ID to #. [Default: Random]\n",
);

// ---- zstdcli.c: argument errors ----

/// zstdcli.c: badUsage.
pub(super) const INCORRECT_PARAMETER: &str = "Incorrect parameter: %s \n";

/// zstdcli.c: errorOut (`%s`: the message).
pub(super) const ERROR_OUT: &str = "%s \n";

/// zstdcli.c: readU32FromChar.
pub(super) const OVERFLOW_U32: &str = "error: numeric value overflows 32-bit unsigned int";

/// zstdcli.c: readIntFromChar.
pub(super) const OVERFLOW_INT: &str = "error: numeric value overflows 32-bit int";

/// zstdcli.c: readSizeTFromChar.
pub(super) const OVERFLOW_SIZE_T: &str = "error: numeric value overflows size_t";

/// zstdcli.c: NEXT_UINT32 and NEXT_TSIZE.
pub(super) const ONLY_NUMERIC: &str =
    "error: only numeric values with optional suffixes K, KB, KiB, M, MB, MiB are allowed";

/// zstdcli.c: NEXT_FIELD, no argument left.
pub(super) const MISSING_ARGUMENT: &str = "error: missing command argument \n";

/// zstdcli.c: NEXT_FIELD, the next argument is an option.
pub(super) const SEPARATED: &str =
    "error: command cannot be separated from its argument by another command \n";

/// zstdcli.c: main, `--output-dir-flat` and `--output-dir-mirror` given "".
pub(super) const EMPTY_OUTPUT_DIR: &str =
    "error: output dir cannot be empty string (did you mean to pass '.' instead?)\n";

/// zstdcli.c: parseAdaptParameters and parseCompressionParameters (display
/// level 4).
pub(super) const INVALID_CPARAM: &str = "invalid compression parameter \n";

/// zstdcli.c: parseAdaptParameters (display level 4).
pub(super) const INCOHERENT_ADAPT: &str = "incoherent adaptation limits \n";

/// zstdcli.c: parseCoverParameters (display level 4; `%d`: k, d, steps,
/// split percentage, shrinkDictMaxRegression).
pub(super) const COVER_PARAMS: &str = "cover: k=%d\nd=%d\nsteps=%d\nsplit=%d\nshrink%d\n";

/// zstdcli.c: parseFastCoverParameters (display level 4; `%d`: k, d, f,
/// steps, split percentage, accel, shrinkDictMaxRegression).
pub(super) const FASTCOVER_PARAMS: &str =
    "cover: k=%d\nd=%d\nf=%d\nsteps=%d\nsplit=%d\naccel=%d\nshrink=%d\n";

/// zstdcli.c: parseLegacyParameters (display level 4).
pub(super) const LEGACY_PARAMS: &str = "legacy: selectivity=%d\n";

// ---- zstdcli.c: the environment ----

/// zstdcli.c: init_cLevel and default_nbThreads (`%s`: the variable, its
/// value).
pub(super) const ENV_TOO_LARGE: &str =
    "Ignore environment variable setting %s=%s: numeric value too large \n";

/// zstdcli.c: init_cLevel.
pub(super) const ENV_NOT_INT: &str =
    "Ignore environment variable setting %s=%s: not a valid integer value \n";

/// zstdcli.c: default_nbThreads.
pub(super) const ENV_NOT_UNSIGNED: &str =
    "Ignore environment variable setting %s=%s: not a valid unsigned value \n";

// ---- zstdcli.c: main, after the arguments ----

/// zstdcli.c: main, `-d` with more than one worker.
pub(super) const DECOMPRESS_NO_MT: &str =
    "Warning : decompression does not support multi-threading\n";

/// zstdcli.c: main, `-T0` with `--auto-threads=logical`.
pub(super) const LOGICAL_CORES: &str = "Note: %d logical core(s) detected \n";

/// zstdcli.c: main, `-T0`.
pub(super) const PHYSICAL_CORES: &str = "Note: %d physical core(s) detected \n";

/// zstdcli.c: main (display level 4; `%d` is printed as `%u`).
pub(super) const COMPRESSING_WITH: &str = "Compressing with %d worker threads \n";

/// zstdcli.c: main, a symbolic link without `-f`.
pub(super) const SYMLINK_IGNORED: &str = "Warning : %s is a symbolic link, ignoring \n";

/// zstdcli.c: main, `--filelist` unreadable.
pub(super) const ERROR_READING: &str = "zstd: error reading %s \n";

/// zstdcli.c: main, every input an empty directory.
pub(super) const NO_INPUT_LEFT: &str =
    "please provide correct input file(s) or non-empty directories -- ignored \n";

/// zstdcli.c: main.
pub(super) const STDIN_CONSOLE: &str = "stdin is a console, aborting\n";

/// zstdcli.c: main.
pub(super) const STDOUT_CONSOLE: &str = "stdout is a console, aborting\n";

/// zstdcli.c: main, the compression level limit.
pub(super) const LEVEL_REDUCED: &str =
    "Warning : compression level higher than max, reduced to %d \n";

/// zstdcli.c: main.
pub(super) const CPARAMS_DECOMPRESS: &str =
    "error : can't use --show-default-cparams in decompression mode \n";

/// zstdcli.c: main.
pub(super) const DICT_AND_PATCH: &str =
    "error : can't use -D and --patch-from=# at the same time \n";

/// zstdcli.c: main.
pub(super) const PATCH_MULTIPLE: &str = "error : can't use --patch-from=# on multiple files \n";

/// zstdcli.c: main (display level 3).
pub(super) const SRC_KEPT_STDOUT: &str = "Note: src files are not removed when output is stdout \n";

/// zstdcli.c: waitEnter.
pub(super) const PRESS_ENTER: &str = "Press enter to continue... \n";

// ---- zstdcli.c: printDefaultCParams, printActualCParams ----

/// zstdcli.c: printDefaultCParams, a known size (`%s`: the name; `%d`: the
/// size, `%llu`).
pub(super) const CPARAMS_SIZE: &str = "%s (%d bytes)\n";

/// zstdcli.c: printDefaultCParams, an unknown size.
pub(super) const CPARAMS_UNKNOWN: &str = "%s (src size unknown)\n";

/// zstdcli.c: printDefaultCParams, the six numeric parameters and the
/// strategy (`%s`: `ZSTD_strategyMap`'s name; `%d`: its number).
pub(super) const CPARAMS_LINES: &str = concat!(
    " - windowLog     : %d\n",
    " - chainLog      : %d\n",
    " - hashLog       : %d\n",
    " - searchLog     : %d\n",
    " - minMatch      : %d\n",
    " - targetLength  : %d\n",
    " - strategy      : %s (%d)\n",
);

/// zstdcli.c: `ZSTD_strategyMap`, by strategy number.
pub(super) const STRATEGY_MAP: [&str; 10] = [
    "",
    "ZSTD_fast",
    "ZSTD_dfast",
    "ZSTD_greedy",
    "ZSTD_lazy",
    "ZSTD_lazy2",
    "ZSTD_btlazy2",
    "ZSTD_btopt",
    "ZSTD_btultra",
    "ZSTD_btultra2",
];

/// zstdcli.c: printActualCParams (display level 4).
pub(super) const ACTUAL_CPARAMS: &str =
    "--zstd=wlog=%d,clog=%d,hlog=%d,slog=%d,mml=%d,tlen=%d,strat=%d\n";

// ---- fileio.c: the preference setters zstdcli.c calls ----

/// fileio.c: FIO_setBlockSize.
pub(super) const BLOCK_SIZE_USELESS: &str =
    "Setting block size is useless in single-thread mode \n";

/// fileio.c: FIO_setOverlapLog.
pub(super) const OVERLAP_LOG_USELESS: &str =
    "Setting overlapLog is useless in single-thread mode \n";

/// fileio.c: FIO_setAdaptiveMode (`EXM_THROW(1, …)`).
pub(super) const ADAPT_SINGLE_THREAD: &str =
    "Adaptive mode is not compatible with single thread mode \n";

/// fileio.c: FIO_setRsyncable (`EXM_THROW(1, …)`).
pub(super) const RSYNCABLE_SINGLE_THREAD: &str =
    "Rsyncable mode is not compatible with single thread mode \n";

/// fileio.c: FIO_displayCompressionParameters (display level 4), its
/// pieces in order: the format (`%s`: `formatOptions`).
pub(super) const DCP_FORMAT: &str = "--format=%s";

/// fileio.c: FIO_displayCompressionParameters, `sparseOptions`.
pub(super) const DCP_SPARSE: [&str; 3] = [" --no-sparse", "", " --sparse"];

/// fileio.c: FIO_displayCompressionParameters, no dictionary ID.
pub(super) const DCP_NO_DICT_ID: &str = " --no-dictID";

/// fileio.c: FIO_displayCompressionParameters, `checkSumOptions`.
pub(super) const DCP_CHECKSUM: [&str; 3] = [" --no-check", "", " --check"];

/// fileio.c: FIO_displayCompressionParameters.
pub(super) const DCP_BLOCK_SIZE: &str = " --block-size=%d";

/// fileio.c: FIO_displayCompressionParameters.
pub(super) const DCP_ADAPT: &str = " --adapt=min=%d,max=%d";

/// fileio.c: FIO_displayCompressionParameters, `rowMatchFinderOptions`,
/// indexed by `ZSTD_ParamSwitch_e` as the reference indexes it (so
/// `--row-match-finder`, `ZSTD_ps_enable`, prints the "no-" form).
pub(super) const DCP_ROW_MATCH_FINDER: [&str; 3] =
    ["", " --no-row-match-finder", " --row-match-finder"];

/// fileio.c: FIO_displayCompressionParameters.
pub(super) const DCP_RSYNCABLE: &str = " --rsyncable";

/// fileio.c: FIO_displayCompressionParameters.
pub(super) const DCP_STREAM_SIZE: &str = " --stream-size=%d";

/// fileio.c: FIO_displayCompressionParameters.
pub(super) const DCP_SIZE_HINT: &str = " --size-hint=%d";

/// fileio.c: FIO_displayCompressionParameters.
pub(super) const DCP_TARGET_CBLOCK: &str = " --target-compressed-block-size=%d";

/// fileio.c: FIO_displayCompressionParameters, `compressLiteralsOptions`,
/// indexed by `ZSTD_ParamSwitch_e`.
pub(super) const DCP_LITERALS: [&str; 3] = ["", " --compress-literals", " --no-compress-literals"];

/// fileio.c: FIO_displayCompressionParameters.
pub(super) const DCP_MEMORY: &str = " --memory=%d";

/// fileio.c: FIO_displayCompressionParameters.
pub(super) const DCP_THREADS: &str = " --threads=%d";

/// fileio.c: FIO_displayCompressionParameters.
pub(super) const DCP_EXCLUDE: &str = " --exclude-compressed";

/// fileio.c: FIO_displayCompressionParameters (`%s`: "" or "no-"), and the
/// line's end.
pub(super) const DCP_CONTENT_SIZE: &str = " --%scontent-size\n";

/// fileio.c: FIO_displayCompressionParameters, `contentSize` off (the
/// `%s` of [`DCP_CONTENT_SIZE`]).
pub(super) const DCP_NO: &str = "no-";

/// fileio.c: `formatOptions`, by `FIO_compressionType_t`.
pub(super) const FORMAT_OPTIONS: [&str; 5] = [".zst", ".gz", ".xz", ".lzma", ".lz4"];

// ---- fileio_common.h: EXM_THROW ----

/// fileio_common.h: EXM_THROW, the prefix.
pub(super) const EXM_PREFIX: &str = "zstd: ";

/// fileio_common.h: EXM_THROW, the code (`%d`).
pub(super) const EXM_ERROR: &str = "error %d : ";

/// fileio_common.h: EXM_THROW, after the message.
pub(super) const EXM_END: &str = " \n";

// ---- util.c ----

/// util.c: readLinesFromFile, `perror("zstd:util:readLinesFromFile")`.
pub(super) const PERROR_READ_LINES: &str = "zstd:util:readLinesFromFile: %s\n";

/// util.c: UTIL_prepareFileList (POSIX).
pub(super) const CANNOT_OPEN_DIR: &str = "Cannot open directory '%s': %s\n";

/// util.c: UTIL_prepareFileList (POSIX).
pub(super) const READDIR_ERROR: &str = "readdir(%s) error: %s \n";

/// util.c: UTIL_prepareFileList (POSIX), a link under a `-r` directory.
pub(super) const UTIL_SYMLINK_IGNORED: &str = "Warning : %s is a symbolic link, ignoring\n";

/// util.c: getDirMode.
pub(super) const DIR_STAT_FAILED: &str = "zstd: failed to get DIR stats %s: %s\n";

/// util.c: getDirMode.
pub(super) const EXPECTED_DIRECTORY: &str = "zstd: expected directory: %s\n";

/// util.c: makeDir.
pub(super) const MKDIR_FAILED: &str = "zstd: failed to create DIR %s: %s\n";

/// util.c: UTIL_requireUserConfirmation, when standard input is an input.
pub(super) const STDIN_IS_AN_INPUT: &str = "stdin is an input - not proceeding.\n";

/// util.c: UTIL_requireUserConfirmation, the abort message's format
/// (`"%s \n"`).
pub(super) const CONFIRM_ABORT: &str = "%s \n";

// ---- fileio.c: files ----

/// fileio.c: FIO_removeFile.
pub(super) const REMOVE_STAT_FAILED: &str = "zstd: Failed to stat %s while trying to remove it\n";

/// fileio.c: FIO_removeFile.
pub(super) const REMOVE_NOT_REGULAR: &str = "zstd: Refusing to remove non-regular file %s\n";

/// fileio.c: FIO_openSrcFile (display level 4).
pub(super) const USING_STDIN: &str = "Using stdin for input \n";

/// fileio.c: FIO_openSrcFile.
pub(super) const CANT_STAT: &str = "zstd: can't stat %s : %s -- ignored \n";

/// fileio.c: FIO_openSrcFile.
pub(super) const NOT_REGULAR: &str = "zstd: %s is not a regular file -- ignored \n";

/// fileio.c: FIO_openSrcFile, FIO_compressFilename_dstFile and others: a
/// name and `strerror(errno)`.
pub(super) const NAME_ERRNO: &str = "zstd: %s: %s \n";

/// fileio.c: FIO_openDstFile (display level 4).
pub(super) const USING_STDOUT: &str = "Using stdout for output \n";

/// fileio.c: FIO_openDstFile (display level 4).
pub(super) const SPARSE_OFF_STDOUT: &str =
    "Sparse File Support is automatically disabled on stdout ; try --sparse \n";

/// fileio.c: FIO_openDstFile, the same-file guard.
pub(super) const REFUSING_OVERWRITE_INPUT: &str =
    "zstd: Refusing to open an output file which will overwrite the input file \n";

/// fileio.c: FIO_openDstFile (display level 4).
pub(super) const SPARSE_OFF_NOT_FILE: &str =
    "Sparse File Support is disabled when output is not a file \n";

/// fileio.c: FIO_openDstFile (`EXM_THROW(40, …)`).
pub(super) const NUL_IS_REGULAR: &str = "%s is unexpectedly categorized as a regular file";

/// fileio.c: FIO_openDstFile, at display level 1 or below (two spaces
/// before the newline, as zstd prints it).
pub(super) const NOT_OVERWRITTEN: &str = "zstd: %s already exists; not overwritten  \n";

/// fileio.c: FIO_openDstFile, before the prompt.
pub(super) const ALREADY_EXISTS: &str = "zstd: %s already exists; ";

/// fileio.c: FIO_openDstFile, UTIL_requireUserConfirmation's prompt.
pub(super) const OVERWRITE_PROMPT: &str = "overwrite (y/n) ? ";

/// fileio.c: FIO_openDstFile, UTIL_requireUserConfirmation's abort
/// message.
pub(super) const OVERWRITE_ABORT: &str = "Not overwritten  \n";

/// fileio.c: FIO_openDstFile, `open` failing (no space before the
/// newline).
pub(super) const OPEN_DST_FAILED: &str = "zstd: %s: %s\n";

/// fileio.c: FIO_getDictFileStat (`EXM_THROW(31, …)`).
pub(super) const DICT_STAT_FAILED: &str = "Stat failed on dictionary file %s: %s";

/// fileio.c: FIO_getDictFileStat (`EXM_THROW(32, …)`).
pub(super) const DICT_NOT_REGULAR: &str = "Dictionary %s must be a regular file.";

/// fileio.c: FIO_setDictBufferMalloc (display level 4).
pub(super) const LOADING_DICT: &str = "Loading %s as dictionary \n";

/// fileio.c: FIO_setDictBufferMalloc (`EXM_THROW(33, …)`).
pub(super) const DICT_OPEN_FAILED: &str = "Couldn't open dictionary %s: %s";

/// fileio.c: FIO_setDictBufferMalloc (`EXM_THROW(34, …)`).
pub(super) const DICT_TOO_LARGE: &str = "Dictionary file %s is too large (> %d bytes)";

/// fileio.c: FIO_setDictBufferMalloc (`EXM_THROW(35, …)`).
pub(super) const DICT_READ_FAILED: &str = "Error reading dictionary file %s : %s";

/// fileio.c: FIO_checkFilenameCollisions (display level 2).
pub(super) const SAME_FILENAME: &str = "WARNING: Two files have same filename: %s\n";

/// fileio.c: FIO_adjustMemLimitForPatchFromMode (`EXM_THROW(42, …)`).
pub(super) const PATCH_FROM_STDIN: &str = "Using --patch-from with stdin requires --stream-size";

/// fileio.c: FIO_adjustMemLimitForPatchFromMode (`EXM_THROW(42, …)`; the
/// newline is zstd's).
pub(super) const PATCH_FROM_TOO_LARGE: &str = "Can't handle files larger than %d GB\n";

/// fileio.c: FIO_multiFilesConcatWarning (`EXM_THROW(43, …)`).
pub(super) const RM_TO_STDOUT: &str = concat!(
    "It's not allowed to remove input files when processed output is piped to stdout. ",
    "This scenario is not supposed to be possible. ",
    "This is a programming error. File an issue for it to be fixed."
);

/// fileio.c: FIO_multiFilesConcatWarning (`EXM_THROW(43, …)`).
pub(super) const RM_IN_TEST: &str = concat!(
    "Test mode shall not remove input files! ",
    "This scenario is not supposed to be possible. ",
    "This is a programming error. File an issue for it to be fixed."
);

/// fileio.c: FIO_multiFilesConcatWarning (display level 2).
pub(super) const CONCAT_STDOUT: &str =
    "zstd: WARNING: all input files will be processed and concatenated into stdout. \n";

/// fileio.c: FIO_multiFilesConcatWarning (display level 2).
pub(super) const CONCAT_FILE: &str = "zstd: WARNING: all input files will be processed and concatenated into a single output file: %s \n";

/// fileio.c: FIO_multiFilesConcatWarning (display level 2).
pub(super) const CONCAT_NO_NAMES: &str =
    "The concatenated output CANNOT regenerate original file names nor directory structure. \n";

/// fileio.c: FIO_multiFilesConcatWarning (display level 2).
pub(super) const CONCAT_NOT_REMOVED: &str =
    "Since it's a destructive operation, input files will not be removed. \n";

/// fileio.c: FIO_multiFilesConcatWarning, quiet.
pub(super) const CONCAT_LOSES_METADATA: &str =
    "Concatenating multiple processed inputs into a single output loses file metadata. \n";

/// fileio.c: FIO_multiFilesConcatWarning, quiet.
pub(super) const CONCAT_ABORTING: &str = "Aborting. \n";

/// fileio.c: FIO_multiFilesConcatWarning, UTIL_requireUserConfirmation's
/// prompt.
pub(super) const PROCEED_PROMPT: &str = "Proceed? (y/n): ";

/// fileio.c: FIO_multiFilesConcatWarning, UTIL_requireUserConfirmation's
/// abort message.
pub(super) const PROCEED_ABORT: &str = "Aborting...";

/// fileio.c: CHECK (`EXM_THROW(11, "%s", ZSTD_getErrorName(…))`).
pub(super) const ERROR_NAME: &str = "%s";

/// Not zstd's: compressing with a dictionary or prefix on the pure tier
/// (spec deviation 7), `EXM_THROW(1, …)`.
pub(super) const PURE_NO_DICTIONARY: &str =
    "dictionary compression is not available in this build (stuffr pure tier)";

// ---- fileio.c: compression ----

/// fileio.c: FIO_adjustParamsForPatchFromMode.
pub(super) const MAX_WINDOW_LOG_EXCEEDED: &str =
    "Max window log exceeded by file (compression ratio will suffer)\n";

/// fileio.c: FIO_adjustParamsForPatchFromMode (display level 2).
pub(super) const LONG_MODE_TRIGGERED: &str = "long mode automatically triggered\n";

/// fileio.c: FIO_adjustParamsForPatchFromMode (display level 4; `%d`:
/// `ZSTD_CHAINLOG_MAX`, `ZSTD_LDM_HASHLOG_MAX`, `ZSTD_LDM_HASHRATELOG_MIN`).
pub(super) const OPTIMAL_PARSER_NOTES: &str = concat!(
    "[Optimal parser notes] Consider the following to improve patch size at the cost of speed:\n",
    "- Set a larger targetLength (e.g. --zstd=targetLength=4096)\n",
    "- Set a larger chainLog (e.g. --zstd=chainLog=%d)\n",
    "- Set a larger LDM hashLog (e.g. --zstd=ldmHashLog=%d)\n",
    "- Set a smaller LDM rateLog (e.g. --zstd=ldmHashRateLog=%d)\n",
    "Also consider playing around with searchLog and hashLog\n",
);

/// fileio.c: FIO_createCResources (display level 6).
pub(super) const CREATE_CRESOURCES: &str = "FIO_createCResources \n";

/// fileio.c: FIO_createCResources (display level 5).
pub(super) const SET_NB_WORKERS: &str = "set nb workers = %d \n";

/// fileio.c: FIO_createCResources (display level 3).
pub(super) const SET_OVERLAP_LOG: &str = "set overlapLog = %d \n";

/// fileio.c: FIO_compressZstdFrame (display level 6).
pub(super) const USING_ZSTD_FORMAT: &str = "compression using zstd format \n";

/// fileio.c: FIO_compressZstdFrame (display level 4; `%s`: `%.*f%s`).
pub(super) const DECOMPRESSION_MEMORY: &str = "Decompression will require %s of memory\n";

/// fileio.c: FIO_compressZstdFrame (display level 6).
pub(super) const FREAD_BYTES: &str = "fread %d bytes from source \n";

/// fileio.c: FIO_compressZstdFrame (display level 6): one
/// `ZSTD_compressStream2` call (`%u`: the directive, the input position and
/// size, the bytes produced).
pub(super) const COMPRESS_GENERIC: &str =
    "ZSTD_compress_generic(end:%d) => input pos(%d)<=(%d)size ; output generated %d bytes \n";

/// fileio.c: FIO_compressZstdFrame, the progress line's clearing
/// (`"\r%79s\r"` with `""`).
pub(super) const CLEAR_LINE: &str = "\r%s\r";

/// fileio.c: FIO_compressZstdFrame, verbose progress (`(L%i)
/// Buffered:%5.*f%s - Consumed:%5.*f%s - Compressed:%5.*f%s => %.2f%% `).
pub(super) const PROGRESS_VERBOSE: &str =
    "(L%s) Buffered:%s - Consumed:%s - Compressed:%s => %s%% ";

/// fileio.c: FIO_compressZstdFrame, a long name's progress (`%u/%u`,
/// `...%s`).
pub(super) const PROGRESS_FILES_LONG: &str = "Compress: %s/%s files. Current: ...%s ";

/// fileio.c: FIO_compressZstdFrame, a short name's progress (`%u/%u`,
/// `%*s`).
pub(super) const PROGRESS_FILES: &str = "Compress: %s/%s files. Current: %s ";

/// fileio.c: FIO_compressZstdFrame (`Read:%6.*f%4s `).
pub(super) const PROGRESS_READ: &str = "Read:%s ";

/// fileio.c: FIO_compressZstdFrame (`/%6.*f%4s`).
pub(super) const PROGRESS_OF: &str = "/%s";

/// fileio.c: FIO_compressZstdFrame (` ==> %2.f%%`).
pub(super) const PROGRESS_RATIO: &str = " ==> %s%%";

/// fileio.c: FIO_compressZstdFrame (`EXM_THROW(27, …)`).
pub(super) const INCOMPLETE_READ: &str = "Read error : Incomplete read : %d / %d B";

/// fileio.c: FIO_compressFilename_internal (display level 5; `%llu`).
pub(super) const SRC_BYTES: &str = "%s: %d bytes \n";

/// fileio.c: FIO_compressFilename_internal, the summary of an empty input
/// (`%-20s :  (%6.*f%s => %6.*f%s, %s) \n`).
pub(super) const SUMMARY_EMPTY: &str = "%s :  (%s => %s, %s) \n";

/// fileio.c: FIO_compressFilename_internal, the summary (`%-20s
/// :%6.2f%%   (%6.*f%s => %6.*f%s, %s) \n`).
pub(super) const SUMMARY: &str = "%s :%s%%   (%s => %s, %s) \n";

/// fileio.c: FIO_compressFilename_internal (display level 4; `%-20s :
/// Completed in %.2f sec  (cpu load : %.0f%%)\n`).
pub(super) const COMPLETED: &str = "%s : Completed in %s sec  (cpu load : %s%%)\n";

/// fileio.c: FIO_compressFilename_dstFile (display level 6).
pub(super) const OPENING_DST: &str = "FIO_compressFilename_dstFile: opening dst: %s \n";

/// fileio.c: FIO_compressFilename_dstFile (display level 6).
pub(super) const CLOSING_DST: &str = "FIO_compressFilename_dstFile: closing dst: %s \n";

/// fileio.c: FIO_compressFilename_srcFile (display level 6).
pub(super) const COMPRESS_SRC_FILE: &str = "FIO_compressFilename_srcFile: %s \n";

/// fileio.c: FIO_compressFilename_srcFile and FIO_decompressSrcFile.
pub(super) const IS_A_DIRECTORY: &str = "zstd: %s is a directory -- ignored \n";

/// fileio.c: FIO_compressFilename_srcFile.
pub(super) const INPUT_IS_DICTIONARY: &str =
    "zstd: cannot use %s as an input file and dictionary \n";

/// fileio.c: FIO_compressFilename_srcFile (display level 4).
pub(super) const ALREADY_COMPRESSED: &str = "File is already compressed : %s \n";

/// fileio.c: FIO_compressFilename_srcFile, `--rm` failing (`EXM_THROW(1,
/// …)`).
pub(super) const RM_FAILED: &str = "zstd: %s: %s";

/// fileio.c: FIO_compressMultipleFilenames (display level 2).
pub(super) const MIRROR_CANNOT_COMPRESS: &str =
    "zstd: --output-dir-mirror cannot compress '%s' into '%s' \n";

/// fileio.c: FIO_compressMultipleFilenames (`EXM_THROW(29, …)`).
pub(super) const CLOSE_FAILED: &str = "Write error (%s) : cannot properly close %s";

/// fileio.c: FIO_compressMultipleFilenames, nothing read (`%3d files
/// compressed : (%6.*f%4s => %6.*f%4s)\n`).
pub(super) const FILES_COMPRESSED_EMPTY: &str = "%s files compressed : (%s => %s)\n";

/// fileio.c: FIO_compressMultipleFilenames (`%3d files compressed :
/// %.2f%% (%6.*f%4s => %6.*f%4s)\n`).
pub(super) const FILES_COMPRESSED: &str = "%s files compressed : %s%% (%s => %s)\n";

/// fileio.c: `compressedFileExtensions` (`--exclude-compressed`).
pub(super) const COMPRESSED_EXTENSIONS: &[&str] = &[
    ".zst", ".tzst", ".gz", ".tgz", ".lzma", ".xz", ".txz", ".lz4", ".tlz4", ".7z", ".aa3", ".aac",
    ".aar", ".ace", ".alac", ".ape", ".apk", ".apng", ".arc", ".archive", ".arj", ".ark", ".asf",
    ".avi", ".avif", ".ba", ".br", ".bz2", ".cab", ".cdx", ".chm", ".cr2", ".divx", ".dmg", ".dng",
    ".docm", ".docx", ".dotm", ".dotx", ".dsft", ".ear", ".eftx", ".emz", ".eot", ".epub", ".f4v",
    ".flac", ".flv", ".gho", ".gif", ".gifv", ".gnp", ".iso", ".jar", ".jpeg", ".jpg", ".jxl",
    ".lz", ".lzh", ".m4a", ".m4v", ".mkv", ".mov", ".mp2", ".mp3", ".mp4", ".mpa", ".mpc", ".mpe",
    ".mpeg", ".mpg", ".mpl", ".mpv", ".msi", ".odp", ".ods", ".odt", ".ogg", ".ogv", ".otp",
    ".ots", ".ott", ".pea", ".png", ".pptx", ".qt", ".rar", ".s7z", ".sfx", ".sit", ".sitx",
    ".sqx", ".svgz", ".swf", ".tbz2", ".tib", ".tlz", ".vob", ".war", ".webm", ".webp", ".wma",
    ".wmv", ".woff", ".woff2", ".wvl", ".xlsx", ".xpi", ".xps", ".zip", ".zipx", ".zoo", ".zpaq",
];

// ---- fileio.c: decompression ----

/// fileio.c: FIO_zstdErrorHelp (`%llu > %u`).
pub(super) const WINDOW_TOO_LARGE: &str = "%s : Window size larger than maximum : %d > %d \n";

/// fileio.c: FIO_zstdErrorHelp.
pub(super) const WINDOW_HINT: &str = "%s : Use --long=%d or --memory=%dMB \n";

/// fileio.c: FIO_zstdErrorHelp.
pub(super) const WINDOW_LOG_TOO_LARGE: &str =
    "%s : Window log larger than ZSTD_WINDOWLOG_MAX=%d; not supported \n";

/// fileio.c: FIO_decompressZstdFrame.
pub(super) const DECODING_ERROR: &str = "%s : Decoding error (36) : %s \n";

/// fileio.c: FIO_decompressZstdFrame, several files (`\rDecompress: %2u/%2u
/// files. Current: %s : %.*f%s...    `).
pub(super) const PROGRESS_DECOMPRESS_FILES: &str =
    "\rDecompress: %s/%s files. Current: %s : %s...    ";

/// fileio.c: FIO_decompressZstdFrame, one file (`\r%-20.20s : %.*f%s...
/// `).
pub(super) const PROGRESS_DECOMPRESS: &str = "\r%s : %s...     ";

/// fileio.c: FIO_decompressZstdFrame.
pub(super) const PREMATURE_END: &str = "%s : Read error (39) : premature end \n";

/// fileio.c: FIO_decompressFrames, an empty input.
pub(super) const UNEXPECTED_EOF: &str = "zstd: %s: unexpected end of file \n";

/// fileio.c: FIO_decompressFrames, fewer than four bytes left.
pub(super) const UNKNOWN_HEADER: &str = "zstd: %s: unknown header \n";

/// fileio.c: FIO_decompressFrames.
pub(super) const UNSUPPORTED_FORMAT: &str = "zstd: %s: unsupported format \n";

/// fileio.c: FIO_decompressFrames, the summary (`%-20s: %llu bytes \n`).
pub(super) const DECOMPRESSED_BYTES: &str = "%s: %d bytes \n";

/// fileio.c: FIO_determineDstName (`%s`: the name, then `suffixListStr`).
pub(super) const UNKNOWN_SUFFIX: &str = "zstd: %s: unknown suffix (%s expected). Can't derive the output file name. Specify it with -o dstFileName. Ignoring.\n";

/// fileio.c: `suffixListStr` with gzip, lzma and lz4 decompression.
pub(super) const SUFFIX_LIST_STR: &str = ".zst/.tzst/.gz/.tgz/.lzma/.xz/.txz/.lz4/.tlz4";

/// fileio.c: `suffixList` with gzip, lzma and lz4 decompression.
pub(super) const SUFFIX_LIST: &[&str] = &[
    ".zst", ".tzst", ".zstd", ".gz", ".tgz", ".lzma", ".xz", ".txz", ".lz4", ".tlz4",
];

/// fileio.c: FIO_determineDstName, the tar suffixes' output suffix.
pub(super) const TAR_SUFFIX: &str = ".tar";

/// fileio.c: FIO_decompressMultipleFilenames (`EXM_THROW(19, …)`).
pub(super) const CANNOT_OPEN: &str = "cannot open %s";

/// fileio.c: FIO_decompressMultipleFilenames (`EXM_THROW(72, …)`).
pub(super) const CLOSE_OUTPUT_FAILED: &str = "Write error : %s : cannot properly close output file";

/// fileio.c: FIO_decompressMultipleFilenames (display level 2).
pub(super) const MIRROR_CANNOT_DECOMPRESS: &str =
    "zstd: --output-dir-mirror cannot decompress '%s' into '%s'\n";

/// fileio.c: FIO_decompressMultipleFilenames (`%d files decompressed :
/// %6llu bytes total \n`).
pub(super) const FILES_DECOMPRESSED: &str = "%s files decompressed : %s bytes total \n";

// ---- fileio_asyncio.c ----

/// fileio_asyncio.c: AIO_fwriteSparse (`EXM_THROW(70, …)`).
pub(super) const WRITE_BLOCK_FAILED: &str = "Write error : cannot write block : %s";

/// fileio_asyncio.c: AIO_fwriteSparse (`EXM_THROW(91, …)`).
pub(super) const SKIP_1GB_FAILED: &str = "1 GB skip error (sparse file support)";

/// fileio_asyncio.c: AIO_fwriteSparse (`EXM_THROW(92, …)`).
pub(super) const SPARSE_SKIP_FAILED: &str = "Sparse skip error ; try --no-sparse";

/// fileio_asyncio.c: AIO_fwriteSparse (`EXM_THROW(93, …)`).
pub(super) const SPARSE_WRITE_FAILED: &str = "Write error : cannot write block : %s";

/// fileio_asyncio.c: AIO_fwriteSparse (`EXM_THROW(95, …)`).
pub(super) const SPARSE_END_WRITE_FAILED: &str =
    "Write error : cannot write end of decoded block : %s";

/// fileio_asyncio.c: AIO_fwriteSparseEnd (`EXM_THROW(69, …)`).
pub(super) const FINAL_SKIP_FAILED: &str = "Final skip error (sparse file support)";

/// fileio_asyncio.c: AIO_fwriteSparseEnd (`EXM_THROW(69, …)`).
pub(super) const LAST_ZERO_FAILED: &str = "Write error : cannot write last zero : %s";

/// fileio_asyncio.c: AIO_ReadPool_executeReadJob (`EXM_THROW(37, …)`).
pub(super) const READ_ERROR: &str = "Read error";

// ---- scaffolding (0.14.0 Ruling P1; Tasks 5-8 remove every use) ----

/// Not zstd's: an operation whose task is not done yet, debug builds only
/// (`%s`: the operation, then the task that brings it).
pub(super) const TODO: &str = "todo: zstd %s is not implemented yet (0.14.0 Task %s)\n";

// ---- fileio.c: --list (list.rs) ----
//
// The `ERROR_IF` messages are printed at display level 1 followed by
// `" \n"`, which each constant below carries. The rows are `displayInfo`'s
// and `FIO_listMultipleFiles`'s formats with their numbers already padded
// by the caller (`%6d`, `%5d`, `%6.*f%4s`, `%8.*f%4s`, `%5.3f`, `%5s`).

/// fileio.c: FIO_listMultipleFiles (`ERROR_IF(…, 1, …)` for a `-` operand,
/// and `DISPLAYLEVEL(1, …)` for no operand at all).
pub(super) const LIST_NO_STDIN: &str =
    "zstd: --list does not support reading from standard input \n";

/// fileio.c: FIO_listMultipleFiles.
pub(super) const LIST_NO_FILES: &str = "No files given \n";

/// fileio.c: FIO_listMultipleFiles (display level 2 and below).
pub(super) const LIST_HEADER: &str =
    "Frames  Skips  Compressed  Uncompressed  Ratio  Check  Filename\n";

/// fileio.c: displayInfo (level 2 and below): frames, skips, compressed
/// value and suffix, decompressed value and suffix, ratio, check, name.
pub(super) const LIST_ROW: &str = "%s  %s  %s%s  %s%s  %s  %s  %s\n";

/// fileio.c: displayInfo, the decompressed size unavailable: frames, skips,
/// compressed value and suffix, check, name.
pub(super) const LIST_ROW_NO_DECOMP: &str = "%s  %s  %s%s                       %s  %s\n";

/// fileio.c: FIO_listMultipleFiles, above the totals.
pub(super) const LIST_RULE: &str =
    "----------------------------------------------------------------- \n";

/// fileio.c: FIO_listMultipleFiles, the totals row (as [`LIST_ROW`], with
/// the file count in place of the name).
pub(super) const LIST_TOTAL: &str = "%s  %s  %s%s  %s%s  %s  %s  %s files\n";

/// fileio.c: FIO_listMultipleFiles, the totals row without the
/// decompressed size (as [`LIST_ROW_NO_DECOMP`]).
pub(super) const LIST_TOTAL_NO_DECOMP: &str = "%s  %s  %s%s                       %s  %s files\n";

/// fileio.c: displayInfo (level 3 and above).
pub(super) const LIST_V_NAME: &str = "%s \n";

/// fileio.c: displayInfo.
pub(super) const LIST_V_FRAMES: &str = "# Zstandard Frames: %s\n";

/// fileio.c: displayInfo.
pub(super) const LIST_V_SKIPPABLE: &str = "# Skippable Frames: %s\n";

/// fileio.c: displayInfo.
pub(super) const LIST_V_DICTID: &str = "DictID: %s\n";

/// fileio.c: displayInfo: the scaled value and suffix, then the bytes.
pub(super) const LIST_V_WINDOW: &str = "Window Size: %s%s (%s B)\n";

/// fileio.c: displayInfo.
pub(super) const LIST_V_COMPRESSED: &str = "Compressed Size: %s%s (%s B)\n";

/// fileio.c: displayInfo.
pub(super) const LIST_V_DECOMPRESSED: &str = "Decompressed Size: %s%s (%s B)\n";

/// fileio.c: displayInfo (`%.4f`).
pub(super) const LIST_V_RATIO: &str = "Ratio: %s\n";

/// fileio.c: displayInfo, one frame with a checksum: the name and the
/// four bytes in hex, most significant first.
pub(super) const LIST_V_CHECK_VALUE: &str = "Check: %s %s\n";

/// fileio.c: displayInfo.
pub(super) const LIST_V_CHECK: &str = "Check: %s\n";

/// fileio.c: displayInfo, the blank line after each file's block.
pub(super) const LIST_V_END: &str = "\n";

/// fileio.c: FIO_analyzeFrames, `DISPLAY` (any level, no newline).
pub(super) const LIST_DICTID_WARNING: &str = "WARNING: File contains multiple frames with different dictionary IDs. Showing dictID 0 instead";

/// fileio.c: FIO_listFile (`info_frame_error`).
pub(super) const LIST_PARSE_ERROR: &str = "Error while parsing \"%s\" \n";

/// fileio.c: FIO_listFile (`info_not_zstd`, standard output).
pub(super) const LIST_NOT_ZSTD: &str = "File \"%s\" not compressed by zstd \n";

/// fileio.c: FIO_listFile (`info_truncated_input`, standard output).
pub(super) const LIST_TRUNCATED: &str = "File \"%s\" is truncated \n";

/// fileio.c: getFileInfo.
pub(super) const LIST_NOT_A_FILE: &str = "Error : %s is not a file \n";

/// fileio.c: getFileInfo_fileConfirmed.
pub(super) const LIST_CANT_OPEN: &str = "Error: could not open source file %s \n";

/// fileio.c: FIO_analyzeFrames.
pub(super) const LIST_BEYOND_END: &str =
    "Error: seeked to position %s, which is beyond file size of %s\n \n";

/// fileio.c: FIO_analyzeFrames.
pub(super) const LIST_INCOMPLETE: &str = "Error: reached end of file with incomplete frame \n";

/// fileio.c: FIO_analyzeFrames.
pub(super) const LIST_OUT_OF_FRAMES: &str =
    "Error: did not reach end of file but ran out of frames \n";

/// fileio.c: FIO_analyzeFrames.
pub(super) const LIST_HEADER_UNDECODABLE: &str = "Error: could not decode frame header \n";

/// fileio.c: FIO_analyzeFrames.
pub(super) const LIST_BLOCK_HEADER: &str = "Error while reading block header \n";

/// fileio.c: FIO_analyzeFrames.
pub(super) const LIST_BLOCK_TYPE: &str = "Error: unsupported block type \n";

/// fileio.c: FIO_analyzeFrames.
pub(super) const LIST_BLOCK_SKIP: &str = "Error: could not skip to end of block \n";

/// fileio.c: FIO_analyzeFrames.
pub(super) const LIST_CHECKSUM: &str = "Error: could not read checksum \n";

/// fileio.c: FIO_analyzeFrames.
pub(super) const LIST_SKIPPABLE_END: &str = "Error: could not find end of skippable frame \n";

// ---- fileio.c: the gzip, xz, lzma and lz4 frames (formats.rs) ----

/// fileio.c: FIO_compressGzFrame, `deflateInit2` refusing the level
/// (`EXM_THROW(71, …)`).
pub(super) const GZ_DEFLATE_INIT: &str = "zstd: %s: deflateInit2 error %d \n";

/// fileio.c: FIO_compressGzFrame, `deflate` failing (`EXM_THROW(72, …)`
/// with `Z_NO_FLUSH`, `EXM_THROW(77, …)` with `Z_FINISH`).
pub(super) const GZ_DEFLATE_ERROR: &str = "zstd: %s: deflate error %d \n";

/// fileio.c: FIO_compressGzFrame (`\rRead : %u MB ==> %.2f%% `).
pub(super) const GZ_PROGRESS: &str = "\rRead : %s MB ==> %s%% ";

/// fileio.c: FIO_compressGzFrame (`\rRead : %u / %u MB ==> %.2f%% `).
pub(super) const GZ_PROGRESS_OF: &str = "\rRead : %s / %s MB ==> %s%% ";

/// fileio.c: FIO_compressLzmaFrame, `lzma_alone_encoder` failing
/// (`EXM_THROW(82, …)`).
pub(super) const LZMA_ALONE_ENCODER_ERROR: &str = "zstd: %s: lzma_alone_encoder error %d";

/// fileio.c: FIO_compressLzmaFrame, `lzma_easy_encoder` failing
/// (`EXM_THROW(83, …)`).
pub(super) const LZMA_EASY_ENCODER_ERROR: &str = "zstd: %s: lzma_easy_encoder error %d";

/// fileio.c: FIO_compressLzmaFrame, `lzma_code` failing (`EXM_THROW(84,
/// …)`).
pub(super) const LZMA_ENCODING_ERROR: &str = "zstd: %s: lzma_code encoding error %d";

/// fileio.c: FIO_compressLzmaFrame and FIO_compressLz4Frame (`\rRead : %u
/// MB ==> %.2f%%`).
pub(super) const READ_PROGRESS: &str = "\rRead : %s MB ==> %s%%";

/// fileio.c: FIO_compressLzmaFrame and FIO_compressLz4Frame (`\rRead : %u /
/// %u MB ==> %.2f%%`).
pub(super) const READ_PROGRESS_OF: &str = "\rRead : %s / %s MB ==> %s%%";

/// fileio.c: FIO_compressLz4Frame, `LZ4F_compressUpdate` failing
/// (`EXM_THROW(35, …)`).
pub(super) const LZ4_COMPRESS_FAILED: &str = "zstd: %s: lz4 compression failed : %s";

/// fileio.c: FIO_compressLz4Frame, `LZ4F_compressEnd` failing
/// (`EXM_THROW(38, …)`).
pub(super) const LZ4_END_FAILED: &str = "zstd: %s: lz4 end of file generation failed : %s";

/// fileio.c: FIO_decompressGzFrame, `inflate` returning `Z_BUF_ERROR`.
pub(super) const GZ_PREMATURE: &str = "zstd: %s: premature gz end \n";

/// fileio.c: FIO_decompressGzFrame, `inflate` failing otherwise.
pub(super) const GZ_INFLATE_ERROR: &str = "zstd: %s: inflate error %d \n";

/// fileio.c: FIO_decompressLzmaFrame, the decoder's initialiser failing:
/// the format's first `%s` is the initialiser's name, the second the file
/// (zstd passes them in that order).
pub(super) const LZMA_DECODER_INIT_ERROR: &str = "zstd: %s: %s error %d \n";

/// fileio.c: FIO_decompressLzmaFrame, [`LZMA_DECODER_INIT_ERROR`]'s
/// initialiser for `.lzma`.
pub(super) const LZMA_ALONE_DECODER: &str = "lzma_alone_decoder";

/// fileio.c: FIO_decompressLzmaFrame, [`LZMA_DECODER_INIT_ERROR`]'s
/// initialiser for `.xz`.
pub(super) const LZMA_STREAM_DECODER: &str = "lzma_stream_decoder";

/// fileio.c: FIO_decompressLzmaFrame, `lzma_code` returning
/// `LZMA_BUF_ERROR`.
pub(super) const LZMA_PREMATURE: &str = "zstd: %s: premature lzma end \n";

/// fileio.c: FIO_decompressLzmaFrame, `lzma_code` failing otherwise.
pub(super) const LZMA_DECODING_ERROR: &str = "zstd: %s: lzma_code decoding error %d \n";

/// fileio.c: FIO_decompressLz4Frame (`\rDecompressed : %.*f%s  `).
pub(super) const LZ4_PROGRESS: &str = "\rDecompressed : %s  ";

/// fileio.c: FIO_decompressLz4Frame, `LZ4F_decompress` failing (the name
/// is `LZ4F_getErrorName`'s).
pub(super) const LZ4_DECOMPRESSION_ERROR: &str = "zstd: %s: lz4 decompression error : %s \n";

/// fileio.c: FIO_decompressLz4Frame, the input ending inside a frame.
pub(super) const LZ4_UNFINISHED: &str = "zstd: %s: unfinished lz4 stream \n";

/// fileio.c: FIO_compressLzmaFrame, `lzma_lzma_preset` failing
/// (`EXM_THROW(81, …)`).
pub(super) const LZMA_PRESET_ERROR: &str = "zstd: %s: lzma_lzma_preset error";

/// C's `printf("%.2f")` of a NaN (the compressing loops' ratio of an empty
/// input): glibc on x86 prints the sign of the NaN 0.0/0.0 makes there.
pub(super) const NAN: &str = if cfg!(all(
    target_os = "linux",
    any(target_arch = "x86", target_arch = "x86_64")
)) {
    "-nan"
} else {
    "nan"
};

/// C's `printf("%.2f")` of an infinity.
pub(super) const INF: &str = "inf";

// lz4frame.c (liblz4 1.10.0): `LZ4F_getErrorName`'s names for the errors
// fileio.c prints.

/// lz4frame.c: `LZ4F_ERROR_GENERIC`.
pub(super) const LZ4F_GENERIC: &str = "ERROR_GENERIC";

/// lz4frame.c: `LZ4F_ERROR_reservedFlag_set`.
pub(super) const LZ4F_RESERVED_FLAG_SET: &str = "ERROR_reservedFlag_set";

/// lz4frame.c: `LZ4F_ERROR_headerVersion_wrong`.
pub(super) const LZ4F_HEADER_VERSION_WRONG: &str = "ERROR_headerVersion_wrong";

/// lz4frame.c: `LZ4F_ERROR_maxBlockSize_invalid`.
pub(super) const LZ4F_MAX_BLOCK_SIZE_INVALID: &str = "ERROR_maxBlockSize_invalid";

/// lz4frame.c: `LZ4F_ERROR_headerChecksum_invalid`.
pub(super) const LZ4F_HEADER_CHECKSUM_INVALID: &str = "ERROR_headerChecksum_invalid";

/// lz4frame.c: `LZ4F_ERROR_blockChecksum_invalid`.
pub(super) const LZ4F_BLOCK_CHECKSUM_INVALID: &str = "ERROR_blockChecksum_invalid";

/// lz4frame.c: `LZ4F_ERROR_decompressionFailed`.
pub(super) const LZ4F_DECOMPRESSION_FAILED: &str = "ERROR_decompressionFailed";

/// lz4frame.c: `LZ4F_ERROR_frameSize_wrong`.
pub(super) const LZ4F_FRAME_SIZE_WRONG: &str = "ERROR_frameSize_wrong";

/// lz4frame.c: `LZ4F_ERROR_contentChecksum_invalid`.
pub(super) const LZ4F_CONTENT_CHECKSUM_INVALID: &str = "ERROR_contentChecksum_invalid";
