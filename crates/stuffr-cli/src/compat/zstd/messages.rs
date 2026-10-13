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
#[allow(dead_code)] // Used from Task 5 (`--filelist`).
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

// ---- scaffolding (0.14.0 Ruling P1; Tasks 5-8 remove every use) ----

/// Not zstd's: an operation whose task is not done yet, debug builds only
/// (`%s`: the operation, then the task that brings it).
pub(super) const TODO: &str = "todo: zstd %s is not implemented yet (0.14.0 Task %s)\n";
