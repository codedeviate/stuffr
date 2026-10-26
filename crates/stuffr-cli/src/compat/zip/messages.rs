//! Every string the zip family's front end prints, as Info-ZIP Zip 3.0
//! prints it (C locale).
//!
//! Ported from Info-ZIP Zip 3.0 (`zip30`, the Info-ZIP licence,
//! `LICENSE-infozip`), with Apple's `zip-33` changes and Ubuntu's
//! `3.0-13ubuntu0.2` differences where they show. Each literal names its C
//! function (`zip.c:help`), an Apple change (`apple.diff`), an Ubuntu patch
//! or the binary it was recorded from. Formats follow C's `printf` as
//! [`printf`] renders them: `%s` takes the next argument.
//!
//! The help, licence and `-v` texts are the references' own output,
//! recorded by Task 1 (`zip-measurements.md`, `texts/`), split where a
//! stuffr banner replaces a reference line (deviation 2: only the banner
//! line of `-v` and the header line of each program's help name stuffr and
//! say they are altered, Info-ZIP licence clause 3). The
//! collapsed-indentation scan exempts this file. The option descriptions of
//! the options tables (`-so`'s last column and `optionerr`'s text) are table
//! data and live in `cli.rs` with the tables.

pub(super) use crate::compat::host::printf;

// ---- banners (deviation 2, Info-ZIP licence clause 3) ----

/// revision.h's `by Info-ZIP, with modifications by Apple Inc.`, in the
/// words of stuffr's banner: whose build it alters.
pub(super) const APPLE_ORIGIN: &str = "original by Info-ZIP, with modifications by Apple Inc.";
/// Ubuntu's package of upstream's `by Info-ZIP.` banner.
pub(super) const UBUNTU_ORIGIN: &str = "Debian's build, original by Info-ZIP";
/// revision.h:versinfolines[0], `-v`'s banner line. `%s` is the program
/// (`Zip`, `ZipCloak`, `ZipNote`, `ZipSplit`), stuffr's version, the origin.
pub(super) const VERSION_BANNER: &str =
    "This is %s 3.0 (July 5th 2008), by stuffr %s (altered; %s).\n";
/// zip.c:help, the header line (`Zip %s (%s). Usage:`).
pub(super) const ZIP_HELP_HEADER: &str =
    "Zip 3.0 (July 5th 2008), by stuffr %s (altered; %s). Usage:\n";
/// zipcloak.c:help_info, the header line (`ZipCloak %s (%s)`).
pub(super) const ZIPCLOAK_HELP_HEADER: &str =
    "ZipCloak 3.0 (July 5th 2008), by stuffr %s (altered; %s)\n";
/// zipnote.c:help, the header line (`ZipNote %s (%s)`).
pub(super) const ZIPNOTE_HELP_HEADER: &str =
    "ZipNote 3.0 (July 5th 2008), by stuffr %s (altered; %s)\n";
/// zipsplit.c:help, the header line (`ZipSplit %s (%s)`).
pub(super) const ZIPSPLIT_HELP_HEADER: &str =
    "ZipSplit 3.0 (July 5th 2008), by stuffr %s (altered; %s)\n";

// ---- version_info ----

/// zip.c:version_info, after the compile options.
pub(super) const ENV_HEADER: &str = "Zip environment options:\n";
/// zip.c:version_info, a variable that is unset or empty.
pub(super) const ENV_NONE: &str = "[none]";
/// zip.c:version_info, `zipenv_names[]` on unix.
pub(super) const ENV_NAMES: [&str; 2] = ["ZIP", "ZIPOPT"];

// ---- errors and warnings ----

/// ziperr.h:ziperrors, the message of each `ZE_*` code (indexed by code;
/// the unused 1 and 17 are empty).
pub(super) const ZIPERRORS: [&str; 21] = [
    "Normal successful completion",
    "",
    "Unexpected end of zip file",
    "Zip file structure invalid",
    "Out of memory",
    "Internal logic error",
    "Entry too big to split, read, or write",
    "Invalid comment format",
    "Zip file invalid, could not spawn unzip, or wrong unzip",
    "Interrupted",
    "Temporary file failure",
    "Input file read failure",
    "Nothing to do!",
    "Missing or empty zip file",
    "Output file write failure",
    "Could not create output file",
    "Invalid command arguments",
    "",
    "File not found or no read permission",
    "Not supported",
    "Attempt to read unsupported Zip64 archive",
];
/// zip.c:ziperr, the line for a `ZE_S_PERR` code (`%s` is `strerror`; the
/// next format begins with the newline).
pub(super) const ZIP_IO_ERROR: &str = "zip I/O error: %s";
/// zip.c:ziperr.
pub(super) const ZIP_ERROR: &str = "\nzip error: %s (%s)\n";
/// zipcloak.c:ziperr, zipnote.c:ziperr, zipsplit.c:ziperr (`%s` is the
/// program).
pub(super) const HELPER_ERROR: &str = "%s error: %s (%s)\n";
/// zip.c:zipwarn.
pub(super) const ZIP_WARNING: &str = "\tzip warning: %s%s\n";
/// zipcloak.c:zipwarn, zipnote.c:zipwarn, zipsplit.c:zipwarn (`%s` is the
/// program).
pub(super) const HELPER_WARNING: &str = "%s warning: %s%s\n";
/// The helpers' `perror("zipcloak error")` (the program, `strerror`).
pub(super) const HELPER_PERROR: &str = "%s error: %s\n";

// ---- get_option's errors (fileio.c) ----

/// fileio.c:op_not_neg_err
pub(super) const OP_NOT_NEG_ERR: &str = "option %s not negatable";
/// fileio.c:op_req_val_err
pub(super) const OP_REQ_VAL_ERR: &str = "option %s requires a value";
/// fileio.c:op_no_allow_val_err
pub(super) const OP_NO_ALLOW_VAL_ERR: &str = "option %s does not allow a value";
/// fileio.c:sh_op_not_sup_err (`%s` is the byte)
pub(super) const SH_OP_NOT_SUP_ERR: &str = "short option '%s' not supported";
/// fileio.c:oco_req_val_err
pub(super) const OCO_REQ_VAL_ERR: &str = "option %s requires one character value";
/// fileio.c:num_req_val_err
pub(super) const NUM_REQ_VAL_ERR: &str = "option %s requires number value";
/// fileio.c:long_op_ambig_err
pub(super) const LONG_OP_AMBIG_ERR: &str = "long option '%s' ambiguous";
/// fileio.c:long_op_not_sup_err
pub(super) const LONG_OP_NOT_SUP_ERR: &str = "long option '%s' not supported";
/// fileio.c:optionerr, the name with its description.
pub(super) const OPTION_NAME_DESC: &str = "'%s' (%s)";
/// fileio.c:optionerr, the name alone.
pub(super) const OPTION_NAME: &str = "'%s'";

// ---- zip.c: main()'s messages ----

/// zip.c:main, an option ID without a case (`%s` the ID).
pub(super) const NO_SUCH_OPTION_ID: &str = "no such option ID: %s";
/// zip.c:finish, `-o` with an empty archive, a warning.
pub(super) const ZIP_EMPTY_NO_LATEST: &str =
    "zip file is empty, can't make it as old as latest entry";
/// zip.c:add_filter, `-i @` or `-x @` with no file name.
pub(super) const MISSING_FILE_AFTER_AT: &str = "missing file after @";
/// zip.c:add_filter, a pattern file that cannot be opened (`%s` the flag,
/// then the pattern as given).
pub(super) const PATTERN_FILE: &str = "%s pattern file '%s'";

/// zip.c:main, `-d`, `-f`, `-u`, `-U` after another action.
pub(super) const JUST_ONE_ACTION: &str = "specify just one action";
/// zip.c:main, `-r` with `-R`.
pub(super) const NOT_BOTH_R: &str = "do not specify both -r and -R";
/// zip.c:main, `-mm`.
pub(super) const MM_NOT_SUPPORTED: &str = "-mm not supported, Must_Match is -MM";
/// zip.c:main, `-ds`.
pub(super) const DS_BAD_SIZE: &str = "option -ds (--dot-size) has bad size:  '%s'";
/// zip.c:main, `-ds`.
pub(super) const DS_TOO_SMALL: &str = "dot size must be at least 32 KB:  '%s'";
/// zip.c:main, `-s`.
pub(super) const BAD_SPLIT_SIZE: &str = "bad split size:  '%s'";
/// zip.c:main, `-s`.
pub(super) const SPLIT_TOO_SMALL: &str = "minimum split size is 64 KB:  '%s'";
/// zip.c:main, `-t`.
pub(super) const BAD_T_DATE: &str =
    "invalid date entered for -t option - use mmddyyyy or yyyy-mm-dd";
/// zip.c:main, `-tt`.
pub(super) const BAD_TT_DATE: &str =
    "invalid date entered for -tt option - use mmddyyyy or yyyy-mm-dd";
/// zip.c:main, `-UN` (ubuntu: UNICODE_SUPPORT), a warning.
pub(super) const UN_MUST_BE: &str = "-UN must be Quit, Warn, Ignore, No, Escape, or UTF8: ";
/// zip.c:main, `-UN`.
pub(super) const UN_BAD_VALUE: &str = "-UN (unicode) bad value";
/// zip.c:main, `-Z` with BZIP2_SUPPORT (ubuntu), a warning.
pub(super) const Z_METHODS_BZIP2: &str = "valid compression methods are:  store, deflate, bzip2";
/// zip.c:main, `-Z` without BZIP2_SUPPORT (apple; the stray `)` is the
/// source's), a warning.
pub(super) const Z_METHODS_PLAIN: &str = "valid compression methods are:  store, deflate)";
/// zip.c:main, `-Z`, a warning (the method follows).
pub(super) const Z_UNKNOWN_FOUND: &str = "unknown compression method found:  ";
/// zip.c:main, `-Z`.
pub(super) const Z_UNKNOWN: &str = "Option -Z (--compression-method):  unknown method";
/// zip.c:main, `-Z bzip2` without BZIP2_SUPPORT (apple).
pub(super) const Z_BZIP2_NOT_ENABLED: &str = "Compression method bzip2 not enabled";
/// zip.c:main, `--` before the archive name.
pub(super) const DOUBLEDASH_BEFORE_NAME: &str = "can't use -- before archive name";
/// zip.c:main, `-` among the names with `-@`.
pub(super) const STDIN_BOTH: &str = "can't read input (-) and filenames (-@) both from stdin";
/// zip.c:main, `-e` and `-P`.
pub(super) const ZERO_LENGTH_PASSWORD: &str = "zero length password not allowed";
/// zip.c:encr_passwd, no terminal to prompt on.
pub(super) const STDERR_NOT_TTY: &str = "stderr is not a tty";
/// zip.c:main, `-sd`.
pub(super) const SD_ZIPFILE_NAME: &str = "sd: Zipfile name '%s'\n";
/// zip.c:main, `-sd`.
pub(super) const SD_COMMAND_LINE_READ: &str = "sd: Command line read\n";
/// zip.c:main, `-sd`.
pub(super) const SD_ZIPPING_TO_STDOUT: &str = "sd: Zipping to stdout\n";
/// zip.c:handler (the text of a caught SIGINT, SIGTERM, SIGABRT, SIGBUS,
/// SIGILL or SIGSEGV).
pub(super) const ABORTING: &str = "aborting";
/// zip.c:main, `-sc`.
pub(super) const COMMAND_LINE: &str = "command line:\n";
/// zip.c:main, `-sc`, one argument.
pub(super) const COMMAND_LINE_ARG: &str = "'%s'  ";
/// zip.c:main, `-sc`, the error.
pub(super) const SHOW_COMMAND_LINE: &str = "show command line";
/// zip.c:main, `-so`.
pub(super) const AVAILABLE_OPTIONS: &str = "available options:\n";
/// zip.c:main, `-so`, the column headings (widths applied by the caller).
pub(super) const SO_HEADINGS: [&str; 5] = ["sh", "long", "val", "neg", "description"];
/// zip.c:main, `-so`, the underlines.
pub(super) const SO_UNDERLINES: [&str; 5] = ["--", "----", "---", "---", "-----------"];
/// zip.c:main, `-so`, the value-type words.
pub(super) const SO_REQ: &str = "req";
/// zip.c:main, `-so`.
pub(super) const SO_OPT: &str = "opt";
/// zip.c:main, `-so`.
pub(super) const SO_LIST: &str = "list";
/// zip.c:main, `-so`.
pub(super) const SO_CHAR: &str = "char";
/// zip.c:main, `-so`.
pub(super) const SO_NUM: &str = "num";
/// zip.c:main, `-so`, negatable.
pub(super) const SO_NEG: &str = "neg";
/// zip.c:main, `-lf`, a log file that cannot be opened.
pub(super) const COULD_NOT_OPEN_LOG: &str = "could not open logfile '%s'";
/// zip.c:main, the log file's first line.
pub(super) const LOG_SEPARATOR: &str = "---------\n";
/// zip.c:main (`%s` is `asctime`'s text, newline included).
pub(super) const LOG_OPENED: &str = "Zip log opened %s";
/// zip.c:main
pub(super) const LOG_COMMAND_LINE: &str = "command line arguments:\n ";
/// zip.c:main, an argument holding a space.
pub(super) const LOG_ARG_QUOTED: &str = "\"%s\" ";
/// zip.c:main, any other argument.
pub(super) const LOG_ARG: &str = "%s ";
/// zip.c:main, after the arguments.
pub(super) const LOG_ARGS_END: &str = "\n\n";
/// zip.c:main, a split archive's name.
pub(super) const SPLIT_NEEDS_ZIP: &str = "archive name must end in .zip for splits";
/// zip.c:main, `--out` as the input.
pub(super) const OUT_PATH_DIFFERENT: &str = "--out path must be different than in path: %s";
/// zip.c:main
pub(super) const DIFF_WITH_FIX: &str = "can't use --diff (-DF) with fix (-F or -FF)";
/// zip.c:main
pub(super) const COPY_NEEDS_OUT: &str = "-U (--copy) requires -O (--out)";
/// zip.c:main, a warning (`%s` follows its first line).
pub(super) const FIX_NEEDS_OUT_WARN: &str = "fix options -F and -FF require --out:\n";
/// zip.c:main, the warning's second line.
pub(super) const FIX_NEEDS_OUT_EXAMPLE: &str =
    "                     zip -F indamagedarchive --out outfixedarchive";
/// zip.c:main
pub(super) const FIX_NEEDS_OUT: &str = "fix options require --out";
/// zip.c:main
pub(super) const FIX_NO_OTHER_ACTIONS: &str =
    "no other actions allowed when fixing archive (-F or -FF)";
/// zip.c:main
pub(super) const DIFF_NEEDS_OUT: &str = "-DF (--diff) requires -O (--out)";
/// zip.c:main
pub(super) const DIFF_WITH_D_OR_U: &str = "can't use --diff (-DF) with -d or -U";
/// zip.c:main
pub(super) const NOTHING_TO_SELECT: &str = "nothing to select from";
/// zip.c:zipstdout
pub(super) const CANNOT_WRITE_TO_TERMINAL: &str = "cannot write zip file to terminal";
/// zip.c:main, `-` as the archive with `-@`.
pub(super) const DASH_AND_AT: &str = "can't use - and -@ together";
/// zip.c:main, `-n` without a list.
pub(super) const MISSING_SUFFIX_LIST: &str = "missing suffix list";
/// zip.c:main, a warning.
pub(super) const D_INVALID_OPTIONS: &str = "invalid option(s) used with -d; ignored.";
/// zip.c:main, a warning.
pub(super) const COPY_MODE_OPTIONS: &str =
    "can't set method, move, recurse, or comments with copy mode.";
/// zip.c:main, a warning.
pub(super) const Y_WITH_K: &str = "can't use -y with -k, -y ignored";
/// zip.c:main, a warning.
pub(super) const F_WITH_A: &str = "can't use -F with -A, -F ignored";
/// zip.c:main, a warning.
pub(super) const FF_WITH_A: &str = "can't use -FF with -A, -FF ignored";
/// zip.c:main, a warning.
pub(super) const T_ON_STDOUT: &str = "can't use -T on stdout, -T ignored";
/// zip.c:main (the newline is the source's).
pub(super) const SPLIT_WITH_FIX: &str = "can't create split archive while fixing or adjusting\n";
/// zip.c:main (the newline is the source's).
pub(super) const SPLIT_WITH_D_OR_STDOUT: &str =
    "can't create split archive with -d or -g or on stdout\n";
/// zip.c:main (the newline is the source's).
pub(super) const FILESYNC_WITH_ACTION: &str = "can't use -d, -f, -u, -U, or -g with filesync -FS\n";
/// zip.c:main (the newline is the source's).
pub(super) const ACTION_ON_STDOUT: &str = "can't use -d, -f, -u, -U, or -g on stdout\n";
/// zip.c:main, `-F`.
pub(super) const FIX_ARCHIVE_F: &str = "Fix archive (-F) - assume mostly intact archive";
/// zip.c:main, `-FF`.
pub(super) const FIX_ARCHIVE_FF: &str = "Fix archive (-FF) - salvage what can";
/// util.c:ReadNumString, a warning (the number follows).
pub(super) const NUM_NOT_DIGIT: &str = "Unable to read number (must start with digit): ";
/// util.c:ReadNumString, a warning (the number follows).
pub(super) const NUM_TOO_LONG: &str = "Number too long to read (8 characters max): ";

// ---- helpers' own messages ----

/// zipcloak.c:main
pub(super) const CLOAK_MORE_THAN_ONE_TEMP: &str = "more than one temp_path";
/// zipcloak.c:main, zipnote.c:main, zipsplit.c:main
pub(super) const ZIP_FILE_STDIN: &str = "zip file cannot be stdin";
/// zipcloak.c:main, zipnote.c:main, zipsplit.c:main
pub(super) const ONLY_ONE_ZIP_FILE: &str = "can only specify one zip file";
/// zipcloak.c:main, zipnote.c:main, zipsplit.c:main
pub(super) const NEED_ZIP_FILE: &str = "need to specify zip file";
/// zipcloak.c:main, zipnote.c:main
pub(super) const UNKNOWN_OPTION: &str = "unknown option";
/// zipnote.c:main
pub(super) const USE_B_BEFORE_NAME: &str = "use -b before zip file name";
/// zipsplit.c:main
pub(super) const OPTIONS_SEPARATE: &str = "options are separate and precede zip file";
/// zipsplit.c:main
pub(super) const USE_H_FOR_HELP: &str = "Use option -h for help.";
/// zipsplit.c:main
pub(super) const INVALID_SIZE: &str = "invalid size given. Use option -h for help.";

// ---- stuffr's own words ----

/// stuffr's own: the flavour variable holds neither name (exit 1). `%s` is
/// the program name, then the value.
pub(super) const FLAVOR_REFUSED: &str = "%s: STUFFR_ZIP_FLAVOR must be apple or ubuntu, not '%s'\n";

// ---- scanning names (Task 5: fileio.c, unix.c, zip.c:main) ----

/// zip.c:main, `zipwarn(NAME_NOT_MATCHED, name)`.
pub(super) const NAME_NOT_MATCHED: &str = "name not matched: ";
/// zip.c:main, the name for an unmatched `-R` run.
pub(super) const FOR_R_NAME: &str = "current directory for -R";
/// zip.c:main, `ZIPERR(ZE_OPEN, "-R")`.
pub(super) const R_NAME: &str = "-R";
/// unix.c:procname, a FIFO without `-FI`.
pub(super) const IGNORING_FIFO: &str = "ignoring FIFO (Named Pipe) - use -FI to read: ";
/// unix.c:procname, a FIFO with `-FI`.
pub(super) const READING_FIFO: &str = "Reading FIFO (Named Pipe): ";
/// unix.c:procname, a device, socket or the like.
pub(super) const IGNORING_SPECIAL: &str = "ignoring special file: ";
/// fileio.c:newname, `error()` for a name that reduces to nothing.
pub(super) const EMPTY_NAME: &str = "empty name without -j or -r";
/// fileio.c:newname, `-v`.
pub(super) const MATCHES_ZIP: &str = "file matches zip file -- skipping\n";
/// zip.c:main, `-sd`.
pub(super) const SD_READING_ARCHIVE: &str = "sd: Reading archive\n";
/// zip.c:main, `-sd`.
pub(super) const SD_SCANNING_FILES: &str = "sd: Scanning files\n";
/// zip.c:main, `-sd`.
pub(super) const SD_APPLYING_FILTERS: &str = "sd: Applying filters\n";
/// zip.c:main, `-sd`.
pub(super) const SD_CHECKING_DUPS: &str = "sd: Checking dups\n";
/// zip.c:main, `-sd`.
pub(super) const SD_SCANNING_TO_UPDATE: &str = "sd: Scanning files to update\n";
/// zip.c:main, `-sd` (`%u` there).
pub(super) const SD_FCOUNT: &str = "sd: fcount = %d\n";
/// fileio.c:check_dup, the first of the three lines.
pub(super) const DUP_FIRST: &str = "  first full name: %s\n";
/// fileio.c:check_dup, the indent before the second and third lines.
pub(super) const DUP_INDENT: &str = "                     ";
/// fileio.c:check_dup, the second line.
pub(super) const DUP_SECOND: &str = " second full name: %s\n";
/// fileio.c:check_dup, the third.
pub(super) const DUP_REPEATED: &str = "name in zip file repeated: %s";
/// fileio.c:check_dup, appended under `-j`.
pub(super) const DUP_JUNK: &str = "\n                     this may be a result of using -j";
/// zip.c:main, `ZIPERR(ZE_PARMS, ...)` after check_dup.
pub(super) const CANNOT_REPEAT: &str = "cannot repeat names in zip file";
/// zip.c:main, no archive and an action other than add.
pub(super) const NOT_FOUND_OR_EMPTY: &str = " not found or empty";
/// zip.c:main, `-sf`, the heading with an archive and no names.
pub(super) const ARCHIVE_CONTAINS: &str = "Archive contains:\n";
/// zip.c:main, `-sf` with `-d`.
pub(super) const WOULD_DELETE: &str = "Would Delete:\n";
/// zip.c:main, `-sf` with `-f`.
pub(super) const WOULD_FRESHEN: &str = "Would Freshen:\n";
/// zip.c:main, `-sf` with `-U`.
pub(super) const WOULD_COPY: &str = "Would Copy:\n";
/// zip.c:main, `-sf` otherwise.
pub(super) const WOULD_ADD: &str = "Would Add/Update:\n";
/// zip.c:main, `-sf`, one name.
pub(super) const SF_ENTRY: &str = "  %s\n";
/// zip.c:main, `-sf`, the last line.
pub(super) const SF_TOTAL: &str = "Total %d entries (%d bytes)\n";
/// zip.c:main, nothing to do with `-r` and no `-i`: the hint's start.
pub(super) const TRY_ZIP: &str = "try: zip";
/// zip.c:main, the hint's `. -i`.
pub(super) const TRY_DOT_I: &str = " . -i";

// ---- recorded texts (the references' own output) ----

/// zip.c:help, `copyright[]` (printed before the header line).
pub(super) const ZIP_HELP_PRE: &str =
    "Copyright (c) 1990-2008 Info-ZIP - Type 'zip \"-L\"' for software license.\n";

/// zip.c:help, `text[]` after its header line (recorded `zip -h`, both builds).
pub(super) const ZIP_HELP_POST: &str = concat!(
    "zip [-options] [-b path] [-t mmddyyyy] [-n suffixes] [zipfile list] [-xi list]\n",
    "  The default action is to add or replace zipfile entries from list, which\n",
    "  can include the special name - to compress standard input.\n",
    "  If zipfile and list are omitted, zip compresses stdin to stdout.\n",
    "  -f   freshen: only changed files  -u   update: only changed or new files\n",
    "  -d   delete entries in zipfile    -m   move into zipfile (delete OS files)\n",
    "  -r   recurse into directories     -j   junk (don't record) directory names\n",
    "  -0   store only                   -l   convert LF to CR LF (-ll CR LF to LF)\n",
    "  -1   compress faster              -9   compress better\n",
    "  -q   quiet operation              -v   verbose operation/print version info\n",
    "  -c   add one-line comments        -z   add zipfile comment\n",
    "  -@   read names from stdin        -o   make zipfile as old as latest entry\n",
    "  -x   exclude the following names  -i   include only the following names\n",
    "  -F   fix zipfile (-FF try harder) -D   do not add directory entries\n",
    "  -A   adjust self-extracting exe   -J   junk zipfile prefix (unzipsfx)\n",
    "  -T   test zipfile integrity       -X   eXclude eXtra file attributes\n",
    "  -y   store symbolic links as the link instead of the referenced file\n",
    "  -e   encrypt                      -n   don't compress these suffixes\n",
    "  -h2  show more help\n",
    "  \n",
);

/// zip.c:help_extended up to the `-TT` lines (recorded `zip -h2`, both builds).
pub(super) const ZIP_HELP2_HEAD: &str = concat!(
    "\n",
    "Extended Help for Zip\n",
    "\n",
    "See the Zip Manual for more detailed help\n",
    "\n",
    "\n",
    "Zip stores files in zip archives.  The default action is to add or replace\n",
    "zipfile entries.\n",
    "\n",
    "Basic command line:\n",
    "  zip options archive_name file file ...\n",
    "\n",
    "Some examples:\n",
    "  Add file.txt to z.zip (create z if needed):      zip z file.txt\n",
    "  Zip all files in current dir:                    zip z *\n",
    "  Zip files in current dir and subdirs also:       zip -r z .\n",
    "\n",
    "Basic modes:\n",
    " External modes (selects files from file system):\n",
    "        add      - add new files/update existing files in archive (default)\n",
    "  -u    update   - add new files/update existing files only if later date\n",
    "  -f    freshen  - update existing files only (no files added)\n",
    "  -FS   filesync - update if date or size changed, delete if no OS match\n",
    " Internal modes (selects entries in archive):\n",
    "  -d    delete   - delete files from archive (see below)\n",
    "  -U    copy     - select files in archive to copy (use with --out)\n",
    "\n",
    "Basic options:\n",
    "  -r        recurse into directories (see Recursion below)\n",
    "  -m        after archive created, delete original files (move into archive)\n",
    "  -j        junk directory names (store just file names)\n",
    "  -q        quiet operation\n",
    "  -v        verbose operation (just \"zip -v\" shows version information)\n",
    "  -c        prompt for one-line comment for each entry\n",
    "  -z        prompt for comment for archive (end with just \".\" line or EOF)\n",
    "  -@        read names to zip from stdin (one path per line)\n",
    "  -o        make zipfile as old as latest entry\n",
    "\n",
    "\n",
    "Syntax:\n",
    "  The full command line syntax is:\n",
    "\n",
    "    zip [-shortopts ...] [--longopt ...] [zipfile [path path ...]] [-xi list]\n",
    "\n",
    "  Any number of short option and long option arguments are allowed\n",
    "  (within limits) as well as any number of path arguments for files\n",
    "  to zip up.  If zipfile exists, the archive is read in.  If zipfile\n",
    "  is \"-\", stream to stdout.  If any path is \"-\", zip stdin.\n",
    "\n",
    "Options and Values:\n",
    "  For short options that take values, use -ovalue or -o value or -o=value\n",
    "  For long option values, use either --longoption=value or --longoption value\n",
    "  For example:\n",
    "    zip -ds 10 --temp-dir=path zipfile path1 path2 --exclude pattern pattern\n",
    "  Avoid -ovalue (no space between) to avoid confusion\n",
    "  In particular, be aware of 2-character options.  For example:\n",
    "    -d -s is (delete, split size) while -ds is (dot size)\n",
    "  Usually better to break short options across multiple arguments by function\n",
    "    zip -r -dbdcds 10m -lilalf logfile archive input_directory -ll\n",
    "\n",
    "  All args after just \"--\" arg are read verbatim as paths and not options.\n",
    "    zip zipfile path path ... -- verbatimpath verbatimpath ...\n",
    "  Use -nw to also disable wildcards, so paths are read literally:\n",
    "    zip zipfile -nw -- \"-leadingdashpath\" \"a[path].c\" \"path*withwildcard\"\n",
    "  You may still have to escape or quote arguments to avoid shell expansion\n",
    "\n",
    "Wildcards:\n",
    "  Internally zip supports the following wildcards:\n",
    "    ?       (or %% or #, depending on OS) matches any single character\n",
    "    *       matches any number of characters, including zero\n",
    "    [list]  matches char in list (regex), can do range [ac-f], all but [!bf]\n",
    "  If port supports [], must escape [ as [[] or use -nw to turn off wildcards\n",
    "  For shells that expand wildcards, escape (\\* or \"*\") so zip can recurse\n",
    "    zip zipfile -r . -i \"*.h\"\n",
    "\n",
    "  Normally * crosses dir bounds in path, e.g. 'a*b' can match 'ac/db'.  If\n",
    "   -ws option used, * does not cross dir bounds but ** does\n",
    "\n",
    "  For DOS and Windows, [list] is now disabled unless the new option\n",
    "  -RE       enable [list] (regular expression) matching\n",
    "  is used to avoid problems with file paths containing \"[\" and \"]\":\n",
    "    zip files_ending_with_number -RE foo[0-9].c\n",
    "\n",
    "Include and Exclude:\n",
    "  -i pattern pattern ...   include files that match a pattern\n",
    "  -x pattern pattern ...   exclude files that match a pattern\n",
    "  Patterns are paths with optional wildcards and match paths as stored in\n",
    "  archive.  Exclude and include lists end at next option, @, or end of line.\n",
    "    zip -x pattern pattern @ zipfile path path ...\n",
    "\n",
    "Case matching:\n",
    "  On most OS the case of patterns must match the case in the archive, unless\n",
    "  the -ic option is used.\n",
    "  -ic       ignore case of archive entries\n",
    "  This option not available on case-sensitive file systems.  On others, case\n",
    "  ignored when matching files on file system but matching against archive\n",
    "  entries remains case sensitive for modes -f (freshen), -U (archive copy),\n",
    "  and -d (delete) because archive paths are always case sensitive.  With\n",
    "  -ic, all matching ignores case, but it's then possible multiple archive\n",
    "  entries that differ only in case will match.\n",
    "\n",
    "End Of Line Translation (text files only):\n",
    "  -l        change CR or LF (depending on OS) line end to CR LF (Unix->Win)\n",
    "  -ll       change CR LF to CR or LF (depending on OS) line end (Win->Unix)\n",
    "  If first buffer read from file contains binary the translation is skipped\n",
    "\n",
    "Recursion:\n",
    "  -r        recurse paths, include files in subdirs:  zip -r a path path ...\n",
    "  -R        recurse current dir and match patterns:   zip -R a ptn ptn ...\n",
    "  Use -i and -x with either to include or exclude paths\n",
    "  Path root in archive starts at current dir, so if /a/b/c/file and\n",
    "   current dir is /a/b, 'zip -r archive .' puts c/file in archive\n",
    "\n",
    "Date filtering:\n",
    "  -t date   exclude before (include files modified on this date and later)\n",
    "  -tt date  include before (include files modified before date)\n",
    "  Can use both at same time to set a date range\n",
    "  Dates are mmddyyyy or yyyy-mm-dd\n",
    "\n",
    "Deletion, File Sync:\n",
    "  -d        delete files\n",
    "  Delete archive entries matching internal archive paths in list\n",
    "    zip archive -d pattern pattern ...\n",
    "  Can use -t and -tt to select files in archive, but NOT -x or -i, so\n",
    "    zip archive -d \"*\" -t 2005-12-27\n",
    "  deletes all files from archive.zip with date of 27 Dec 2005 and later\n",
    "  Note the * (escape as \"*\" on Unix) to select all files in archive\n",
    "\n",
    "  -FS       file sync\n",
    "  Similar to update, but files updated if date or size of entry does not\n",
    "  match file on OS.  Also deletes entry from archive if no matching file\n",
    "  on OS.\n",
    "    zip archive_to_update -FS -r dir_used_before\n",
    "  Result generally same as creating new archive, but unchanged entries\n",
    "  are copied instead of being read and compressed so can be faster.\n",
    "      WARNING:  -FS deletes entries so make backup copy of archive first\n",
    "\n",
    "Compression:\n",
    "  -0        store files (no compression)\n",
    "  -1 to -9  compress fastest to compress best (default is 6)\n",
    "  -Z cm     set compression method to cm:\n",
    "              store   - store without compression, same as option -0\n",
    "              deflate - original zip deflate, same as -1 to -9 (default)\n",
    "            if bzip2 is enabled:\n",
    "              bzip2 - use bzip2 compression (need modern unzip)\n",
    "\n",
    "Encryption:\n",
    "  -e        use standard (weak) PKZip 2.0 encryption, prompt for password\n",
    "  -P pswd   use standard encryption, password is pswd\n",
    "\n",
    "Splits (archives created as a set of split files):\n",
    "  -s ssize  create split archive with splits of size ssize, where ssize nm\n",
    "              n number and m multiplier (kmgt, default m), 100k -> 100 kB\n",
    "  -sp       pause after each split closed to allow changing disks\n",
    "      WARNING:  Archives created with -sp use data descriptors and should\n",
    "                work with most unzips but may not work with some\n",
    "  -sb       ring bell when pause\n",
    "  -sv       be verbose about creating splits\n",
    "      Split archives CANNOT be updated, but see --out and Copy Mode below\n",
    "\n",
    "Using --out (output to new archive):\n",
    "  --out oa  output to new archive oa\n",
    "  Instead of updating input archive, create new output archive oa.\n",
    "  Result is same as without --out but in new archive.  Input archive\n",
    "  unchanged.\n",
    "      WARNING:  --out ALWAYS overwrites any existing output file\n",
    "  For example, to create new_archive like old_archive but add newfile1\n",
    "  and newfile2:\n",
    "    zip old_archive newfile1 newfile2 --out new_archive\n",
    "  Cannot update split archive, so use --out to out new archive:\n",
    "    zip in_split_archive newfile1 newfile2 --out out_split_archive\n",
    "  If input is split, output will default to same split size\n",
    "  Use -s=0 or -s- to turn off splitting to convert split to single file:\n",
    "    zip in_split_archive -s 0 --out out_single_file_archive\n",
    "      WARNING:  If overwriting old split archive but need less splits,\n",
    "                old splits not overwritten are not needed but remain\n",
    "\n",
    "Copy Mode (copying from archive to archive):\n",
    "  -U        (also --copy) select entries in archive to copy (reverse delete)\n",
    "  Copy Mode copies entries from old to new archive with --out and is used by\n",
    "  zip when either no input files on command line or -U (--copy) used.\n",
    "    zip inarchive --copy pattern pattern ... --out outarchive\n",
    "  To copy only files matching *.c into new archive, excluding foo.c:\n",
    "    zip old_archive --copy \"*.c\" --out new_archive -x foo.c\n",
    "  If no input files and --out, copy all entries in old archive:\n",
    "    zip old_archive --out new_archive\n",
    "\n",
    "Streaming and FIFOs:\n",
    "  prog1 | zip -ll z -      zip output of prog1 to zipfile z, converting CR LF\n",
    "  zip - -R \"*.c\" | prog2   zip *.c files in current dir and stream to prog2 \n",
    "  prog1 | zip | prog2      zip in pipe with no in or out acts like zip - -\n",
    "  If Zip is Zip64 enabled, streaming stdin creates Zip64 archives by default\n",
    "   that need PKZip 4.5 unzipper like UnZip 6.0\n",
    "  WARNING:  Some archives created with streaming use data descriptors and\n",
    "            should work with most unzips but may not work with some\n",
    "  Can use -fz- to turn off Zip64 if input not large (< 4 GB):\n",
    "    prog_with_small_output | zip archive -fz-\n",
    "\n",
    "  Zip now can read Unix FIFO (named pipes).  Off by default to prevent zip\n",
    "  from stopping unexpectedly on unfed pipe, use -FI to enable:\n",
    "    zip -FI archive fifo\n",
    "\n",
    "Dots, counts:\n",
    "  -db       display running count of bytes processed and bytes to go\n",
    "              (uncompressed size, except delete and copy show stored size)\n",
    "  -dc       display running count of entries done and entries to go\n",
    "  -dd       display dots every 10 MB (or dot size) while processing files\n",
    "  -dg       display dots globally for archive instead of for each file\n",
    "    zip -qdgds 10m   will turn off most output except dots every 10 MB\n",
    "  -ds siz   each dot is siz processed where siz is nm as splits (0 no dots)\n",
    "  -du       display original uncompressed size for each entry as added\n",
    "  -dv       display volume (disk) number in format in_disk>out_disk\n",
    "  Dot size is approximate, especially for dot sizes less than 1 MB\n",
    "  Dot options don't apply to Scanning files dots (dot/2sec) (-q turns off)\n",
    "\n",
    "Logging:\n",
    "  -lf path  open file at path as logfile (overwrite existing file)\n",
    "  -la       append to existing logfile\n",
    "  -li       include info messages (default just warnings and errors)\n",
    "\n",
    "Testing archives:\n",
    "  -T        test completed temp archive with unzip before updating archive\n",
    "  -TT cmd   use command cmd instead of 'unzip -tqq' to test archive\n",
    "             On Unix, to use unzip in current directory, could use:\n",
    "               zip archive file1 file2 -T -TT \"./unzip -tqq\"\n",
);

/// ubuntu: the `{}` line Apple comments out (apple.diff, zip.c:925).
pub(super) const ZIP_HELP2_UBUNTU_LINE: &str =
    "             In cmd, {} replaced by temp archive path, else temp appended.\n";

/// zip.c:help_extended after that line.
pub(super) const ZIP_HELP2_TAIL: &str = concat!(
    "             The return code is checked for success (0 on Unix)\n",
    "\n",
    "Fixing archives:\n",
    "  -F        attempt to fix a mostly intact archive (try this first)\n",
    "  -FF       try to salvage what can (may get more but less reliable)\n",
    "  Fix options copy entries from potentially bad archive to new archive.\n",
    "  -F tries to read archive normally and copy only intact entries, while\n",
    "  -FF tries to salvage what can and may result in incomplete entries.\n",
    "  Must use --out option to specify output archive:\n",
    "    zip -F bad.zip --out fixed.zip\n",
    "  Use -v (verbose) with -FF to see details:\n",
    "    zip reallybad.zip -FF -v --out fixed.zip\n",
    "  Currently neither option fixes bad entries, as from text mode ftp get.\n",
    "\n",
    "Difference mode:\n",
    "  -DF       (also --dif) only include files that have changed or are\n",
    "             new as compared to the input archive\n",
    "  Difference mode can be used to create incremental backups.  For example:\n",
    "    zip --dif full_backup.zip -r somedir --out diff.zip\n",
    "  will store all new files, as well as any files in full_backup.zip where\n",
    "  either file time or size have changed from that in full_backup.zip,\n",
    "  in new diff.zip.  Output archive not excluded automatically if exists,\n",
    "  so either use -x to exclude it or put outside what is being zipped.\n",
    "\n",
    "DOS Archive bit (Windows only):\n",
    "  -AS       include only files with the DOS Archive bit set\n",
    "  -AC       after archive created, clear archive bit of included files\n",
    "      WARNING: Once the archive bits are cleared they are cleared\n",
    "               Use -T to test the archive before the bits are cleared\n",
    "               Can also use -sf to save file list before zipping files\n",
    "\n",
    "Show files:\n",
    "  -sf       show files to operate on and exit (-sf- logfile only)\n",
    "  -su       as -sf but show escaped UTF-8 Unicode names also if exist\n",
    "  -sU       as -sf but show escaped UTF-8 Unicode names instead\n",
    "  Any character not in the current locale is escaped as #Uxxxx, where x\n",
    "  is hex digit, if 16-bit code is sufficient, or #Lxxxxxx if 24-bits\n",
    "  are needed.  If add -UN=e, Zip escapes all non-ASCII characters.\n",
    "\n",
    "Unicode:\n",
    "  If compiled with Unicode support, Zip stores UTF-8 path of entries.\n",
    "  This is backward compatible.  Unicode paths allow better conversion\n",
    "  of entry names between different character sets.\n",
    "\n",
    "  New Unicode extra field includes checksum to verify Unicode path\n",
    "  goes with standard path for that entry (as utilities like ZipNote\n",
    "  can rename entries).  If these do not match, use below options to\n",
    "  set what Zip does:\n",
    "      -UN=Quit     - if mismatch, exit with error\n",
    "      -UN=Warn     - if mismatch, warn, ignore UTF-8 (default)\n",
    "      -UN=Ignore   - if mismatch, quietly ignore UTF-8\n",
    "      -UN=No       - ignore any UTF-8 paths, use standard paths for all\n",
    "  An exception to -UN=N are entries with new UTF-8 bit set (instead\n",
    "  of using extra fields).  These are always handled as Unicode.\n",
    "\n",
    "  Normally Zip escapes all chars outside current char set, but leaves\n",
    "  as is supported chars, which may not be OK in path names.  -UN=Escape\n",
    "  escapes any character not ASCII:\n",
    "    zip -sU -UN=e archive\n",
    "  Can use either normal path or escaped Unicode path on command line\n",
    "  to match files in archive.\n",
    "\n",
    "  Zip now stores UTF-8 in entry path and comment fields on systems\n",
    "  where UTF-8 char set is default, such as most modern Unix, and\n",
    "  and on other systems in new extra fields with escaped versions in\n",
    "  entry path and comment fields for backward compatibility.\n",
    "  Option -UN=UTF8 will force storing UTF-8 in entry path and comment\n",
    "  fields:\n",
    "      -UN=UTF8     - store UTF-8 in entry path and comment fields\n",
    "  This option can be useful for multi-byte char sets on Windows where\n",
    "  escaped paths and comments can be too long to be valid as the UTF-8\n",
    "  versions tend to be shorter.\n",
    "\n",
    "  Only UTF-8 comments on UTF-8 native systems supported.  UTF-8 comments\n",
    "  for other systems planned in next release.\n",
    "\n",
    "Self extractor:\n",
    "  -A        Adjust offsets - a self extractor is created by prepending\n",
    "             the extractor executable to archive, but internal offsets\n",
    "             are then off.  Use -A to fix offsets.\n",
    "  -J        Junk sfx - removes prepended extractor executable from\n",
    "             self extractor, leaving a plain zip archive.\n",
    "\n",
    "More option highlights (see manual for additional options and details):\n",
    "  -b dir    when creating or updating archive, create the temp archive in\n",
    "             dir, which allows using seekable temp file when writing to a\n",
    "             write once CD, such archives compatible with more unzips\n",
    "             (could require additional file copy if on another device)\n",
    "  -MM       input patterns must match at least one file and matched files\n",
    "             must be readable or exit with OPEN error and abort archive\n",
    "             (without -MM, both are warnings only, and if unreadable files\n",
    "             are skipped OPEN error (18) returned after archive created)\n",
    "  -nw       no wildcards (wildcards are like any other character)\n",
    "  -sc       show command line arguments as processed and exit\n",
    "  -sd       show debugging as Zip does each step\n",
    "  -so       show all available options on this system\n",
    "  -X        default=strip old extra fields, -X- keep old, -X strip most\n",
    "  -ws       wildcards don't span directory boundaries in paths\n",
    "\n",
);

/// zip.c:license, `swlicense[]` (recorded `zip -L`, both builds; zipnote and zipsplit print the same).
pub(super) const ZIP_LICENSE: &str = concat!(
    "Copyright (c) 1990-2008 Info-ZIP.  All rights reserved.\n",
    "\n",
    "For the purposes of this copyright and license, \"Info-ZIP\" is defined as\n",
    "the following set of individuals:\n",
    "\n",
    "   Mark Adler, John Bush, Karl Davis, Harald Denker, Jean-Michel Dubois,\n",
    "   Jean-loup Gailly, Hunter Goatley, Ed Gordon, Ian Gorman, Chris Herborth,\n",
    "   Dirk Haase, Greg Hartwig, Robert Heath, Jonathan Hudson, Paul Kienitz,\n",
    "   David Kirschbaum, Johnny Lee, Onno van der Linden, Igor Mandrichenko,\n",
    "   Steve P. Miller, Sergio Monesi, Keith Owens, George Petrov, Greg Roelofs,\n",
    "   Kai Uwe Rommel, Steve Salisbury, Dave Smith, Steven M. Schweda,\n",
    "   Christian Spieler, Cosmin Truta, Antoine Verheijen, Paul von Behren,\n",
    "   Rich Wales, Mike White\n",
    "\n",
    "This software is provided \"as is,\" without warranty of any kind, express\n",
    "or implied.  In no event shall Info-ZIP or its contributors be held liable\n",
    "for any direct, indirect, incidental, special or consequential damages\n",
    "arising out of the use of or inability to use this software.\n",
    "\n",
    "Permission is granted to anyone to use this software for any purpose,\n",
    "including commercial applications, and to alter it and redistribute it\n",
    "freely, subject to the above disclaimer and the following restrictions:\n",
    "\n",
    "    1. Redistributions of source code (in whole or in part) must retain\n",
    "       the above copyright notice, definition, disclaimer, and this list\n",
    "       of conditions.\n",
    "\n",
    "    2. Redistributions in binary form (compiled executables and libraries)\n",
    "       must reproduce the above copyright notice, definition, disclaimer,\n",
    "       and this list of conditions in documentation and/or other materials\n",
    "       provided with the distribution.  The sole exception to this condition\n",
    "       is redistribution of a standard UnZipSFX binary (including SFXWiz) as\n",
    "       part of a self-extracting archive; that is permitted without inclusion\n",
    "       of this license, as long as the normal SFX banner has not been removed\n",
    "       from the binary or disabled.\n",
    "\n",
    "    3. Altered versions--including, but not limited to, ports to new operating\n",
    "       systems, existing ports with new graphical interfaces, versions with\n",
    "       modified or added functionality, and dynamic, shared, or static library\n",
    "       versions not from Info-ZIP--must be plainly marked as such and must not\n",
    "       be misrepresented as being the original source or, if binaries,\n",
    "       compiled from the original source.  Such altered versions also must not\n",
    "       be misrepresented as being Info-ZIP releases--including, but not\n",
    "       limited to, labeling of the altered versions with the names \"Info-ZIP\"\n",
    "       (or any variation thereof, including, but not limited to, different\n",
    "       capitalizations), \"Pocket UnZip,\" \"WiZ\" or \"MacZip\" without the\n",
    "       explicit permission of Info-ZIP.  Such altered versions are further\n",
    "       prohibited from misrepresentative use of the Zip-Bugs or Info-ZIP\n",
    "       e-mail addresses or the Info-ZIP URL(s), such as to imply Info-ZIP\n",
    "       will provide support for the altered versions.\n",
    "\n",
    "    4. Info-ZIP retains the right to use the names \"Info-ZIP,\" \"Zip,\" \"UnZip,\"\n",
    "       \"UnZipSFX,\" \"WiZ,\" \"Pocket UnZip,\" \"Pocket Zip,\" and \"MacZip\" for its\n",
    "       own source and binary releases.\n",
);

/// zipcloak.c:license after `swlicense[]`: a blank line, the export notice.
pub(super) const ZIPCLOAK_LICENSE_EXTRA: &str = concat!(
    "\n",
    "Export notice:\n",
    "The encryption code of this program is not copyrighted and is\n",
    "put in the public domain. It was originally written in Europe\n",
    "and can be freely distributed in both source and object forms\n",
    "from any country, including the USA under License Exception\n",
    "TSU of the U.S. Export Administration Regulations (section\n",
    "740.13(e)) of 6 June 2002.  (Prior to January 2000, re-export\n",
    "from the US was a violation of US law.)\n",
);

/// zipcloak.c:help, what precedes the header line.
pub(super) const ZIPCLOAK_HELP_PRE: &str = "\n";

/// zipcloak.c:help, what follows the header line (recorded `zipcloak -h`, both builds).
pub(super) const ZIPCLOAK_HELP_POST: &str = concat!(
    "Usage:  zipcloak [-dq] [-b path] zipfile\n",
    "  the default action is to encrypt all unencrypted entries in the zip file\n",
    "\n",
    "  -d  --decrypt      decrypt encrypted entries (copy if given wrong password)\n",
    "  -b  --temp-path    use \"path\" for the temporary zip file\n",
    "  -O  --output-file  write output to new zip file\n",
    "  -q  --quiet        quiet operation, suppress some informational messages\n",
    "  -h  --help         show this help\n",
    "  -v  --version      show version info\n",
    "  -L  --license      show software license\n",
);

/// zipnote.c:help, what precedes the header line.
pub(super) const ZIPNOTE_HELP_PRE: &str = concat!(
    "Copyright (c) 1990-2008 Info-ZIP - Type 'zipnote \"-L\"' for software license.\n",
    "\n",
);

/// zipnote.c:help, what follows the header line (recorded `zipnote -h`, both builds).
pub(super) const ZIPNOTE_HELP_POST: &str = concat!(
    "Usage:  zipnote [-w] [-q] [-b path] zipfile\n",
    "  the default action is to write the comments in zipfile to stdout\n",
    "  -w   write the zipfile comments from stdin\n",
    "  -b   use \"path\" for the temporary zip file\n",
    "  -q   quieter operation, suppress some informational messages\n",
    "  -h   show this help    -v   show version info    -L   show software license\n",
    "\n",
    "Example:\n",
    "     zipnote foo.zip > foo.tmp\n",
    "     ed foo.tmp\n",
    "     ... then you edit the comments, save, and exit ...\n",
    "     zipnote -w foo.zip < foo.tmp\n",
    "\n",
    "  \"@ name\" can be followed by an \"@=newname\" line to change the name\n",
);

/// zipsplit.c:help, what precedes the header line.
pub(super) const ZIPSPLIT_HELP_PRE: &str = concat!(
    "Copyright (c) 1990-2008 Info-ZIP - Type 'zipsplit \"-L\"' for software license.\n",
    "\n",
);

/// zipsplit.c:help, what follows the header line (recorded `zipsplit -h`, both builds).
pub(super) const ZIPSPLIT_HELP_POST: &str = concat!(
    "Usage:  zipsplit [-tipqs] [-n size] [-r room] [-b path] zipfile\n",
    "  -t   report how many files it will take, but don't make them\n",
    "  -i   make index (zipsplit.idx) and count its size against first zip file\n",
    "  -n   make zip files no larger than \"size\" (default = 36000)\n",
    "  -r   leave room for \"room\" bytes on the first disk (default = 0)\n",
    "  -b   use \"path\" for the output zip files\n",
    "  -q   quieter operation, suppress some informational messages\n",
    "  -p   pause between output zip files\n",
    "  -s   do a sequential split even if it takes more zip files\n",
    "  -h   show this help    -v   show version info    -L   show software license\n",
);

/// zip.c:version_info, what precedes the banner line (recorded `zip -v`, apple).
pub(super) const ZIP_V_APPLE_PRE: &str =
    "Copyright (c) 1990-2008 Info-ZIP - Type 'zip \"-L\"' for software license.\n";

/// zip.c:version_info, what follows the banner line (recorded `zip -v`, apple), up to the environment section.
pub(super) const ZIP_V_APPLE_POST: &str = concat!(
    "Please report bugs to Apple.\n",
    "\n",
    "Compiled with gcc Apple LLVM 21.0.0 (clang-2100.3.31.1) [+internal-os] for Unix (Mac OS X) on Aug  8 2026.\n",
    "\n",
    "Zip special compilation options:\n",
    "\tUSE_EF_UT_TIME       (store Universal Time)\n",
    "\tSYMLINK_SUPPORT      (symbolic links supported)\n",
    "\tLARGE_FILE_SUPPORT   (can read and write large files on file system)\n",
    "\tZIP64_SUPPORT        (use Zip64 to store large files in archives)\n",
    "\tSTORE_UNIX_UIDs_GIDs (store UID/GID sizes/values using new extra field)\n",
    "\tUIDGID_16BIT         (old Unix 16-bit UID/GID extra field also used)\n",
    "\t[encryption, version 2.91 of 05 Jan 2007] (modified for Zip 3)\n",
    "\n",
    "Encryption notice:\n",
    "\tThe encryption code of this program is not copyrighted and is\n",
    "\tput in the public domain.  It was originally written in Europe\n",
    "\tand, to the best of our knowledge, can be freely distributed\n",
    "\tin both source and object forms from any country, including\n",
    "\tthe USA under License Exception TSU of the U.S. Export\n",
    "\tAdministration Regulations (section 740.13(e)) of 6 June 2002.\n",
    "\n",
);

/// zip.c:version_info, what precedes the banner line (recorded `zip -v`, ubuntu).
pub(super) const ZIP_V_UBUNTU_PRE: &str =
    "Copyright (c) 1990-2008 Info-ZIP - Type 'zip \"-L\"' for software license.\n";

/// zip.c:version_info, what follows the banner line (recorded `zip -v`, ubuntu), up to the environment section.
pub(super) const ZIP_V_UBUNTU_POST: &str = concat!(
    "Currently maintained by E. Gordon.  Please send bug reports to\n",
    "the authors using the web page at www.info-zip.org; see README for details.\n",
    "\n",
    "Latest sources and executables are at ftp://ftp.info-zip.org/pub/infozip,\n",
    "as of above date; see http://www.info-zip.org/ for other sites.\n",
    "\n",
    "Compiled with gcc 13.3.0 for Unix (Linux ELF).\n",
    "\n",
    "Zip special compilation options:\n",
    "\tUSE_EF_UT_TIME       (store Universal Time)\n",
    "\tBZIP2_SUPPORT        (bzip2 library version 1.0.8, 13-Jul-2019)\n",
    "\t    bzip2 code and library copyright (c) Julian R Seward\n",
    "\t    (See the bzip2 license for terms of use)\n",
    "\tSYMLINK_SUPPORT      (symbolic links supported)\n",
    "\tLARGE_FILE_SUPPORT   (can read and write large files on file system)\n",
    "\tZIP64_SUPPORT        (use Zip64 to store large files in archives)\n",
    "\tUNICODE_SUPPORT      (store and read UTF-8 Unicode paths)\n",
    "\tSTORE_UNIX_UIDs_GIDs (store UID/GID sizes/values using new extra field)\n",
    "\tUIDGID_NOT_16BIT     (old Unix 16-bit UID/GID extra field not used)\n",
    "\t[encryption, version 2.91 of 05 Jan 2007] (modified for Zip 3)\n",
    "\n",
    "Encryption notice:\n",
    "\tThe encryption code of this program is not copyrighted and is\n",
    "\tput in the public domain.  It was originally written in Europe\n",
    "\tand, to the best of our knowledge, can be freely distributed\n",
    "\tin both source and object forms from any country, including\n",
    "\tthe USA under License Exception TSU of the U.S. Export\n",
    "\tAdministration Regulations (section 740.13(e)) of 6 June 2002.\n",
    "\n",
);

/// zipcloak.c:version_info, what precedes the banner line (recorded `zipcloak -v`, apple).
pub(super) const ZIPCLOAK_V_APPLE_PRE: &str = concat!(
    "Copyright (c) 1990-2008 Info-ZIP - Type 'zipcloak \"-L\"' for software license.\n",
    "\n",
);

/// zipcloak.c:version_info, what follows the banner line (recorded `zipcloak -v`, apple).
pub(super) const ZIPCLOAK_V_APPLE_POST: &str = concat!(
    "Please report bugs to Apple.\n",
    "\n",
    "Compiled with gcc Apple LLVM 21.0.0 (clang-2100.3.31.1) [+internal-os] for Unix (Mac OS X) on Aug  8 2026.\n",
    "\n",
    "ZipCloak special compilation options:\n",
    "\t[encryption, version 2.91 of 05 Jan 2007]\n",
);

/// zipcloak.c:version_info, what precedes the banner line (recorded `zipcloak -v`, ubuntu).
pub(super) const ZIPCLOAK_V_UBUNTU_PRE: &str = concat!(
    "Copyright (c) 1990-2008 Info-ZIP - Type 'zipcloak \"-L\"' for software license.\n",
    "\n",
);

/// zipcloak.c:version_info, what follows the banner line (recorded `zipcloak -v`, ubuntu).
pub(super) const ZIPCLOAK_V_UBUNTU_POST: &str = concat!(
    "Currently maintained by E. Gordon.  Please send bug reports to\n",
    "the authors using the web page at www.info-zip.org; see README for details.\n",
    "\n",
    "Latest sources and executables are at ftp://ftp.info-zip.org/pub/infozip,\n",
    "as of above date; see http://www.info-zip.org/ for other sites.\n",
    "\n",
    "Compiled with gcc 13.3.0 for Unix (Linux ELF).\n",
    "\n",
    "ZipCloak special compilation options:\n",
    "\t[encryption, version 2.91 of 05 Jan 2007]\n",
);

/// zipnote.c:version_info, what precedes the banner line (recorded `zipnote -v`, apple).
pub(super) const ZIPNOTE_V_APPLE_PRE: &str =
    "Copyright (c) 1990-2008 Info-ZIP - Type 'zipnote \"-L\"' for software license.\n";

/// zipnote.c:version_info, what follows the banner line (recorded `zipnote -v`, apple).
pub(super) const ZIPNOTE_V_APPLE_POST: &str = concat!(
    "Please report bugs to Apple.\n",
    "\n",
    "Compiled with gcc Apple LLVM 21.0.0 (clang-2100.3.31.1) [+internal-os] for Unix (Mac OS X) on Aug  8 2026.\n",
    "\n",
    "ZipNote special compilation options:\n",
    "\t[none]\n",
);

/// zipnote.c:version_info, what precedes the banner line (recorded `zipnote -v`, ubuntu).
pub(super) const ZIPNOTE_V_UBUNTU_PRE: &str =
    "Copyright (c) 1990-2008 Info-ZIP - Type 'zipnote \"-L\"' for software license.\n";

/// zipnote.c:version_info, what follows the banner line (recorded `zipnote -v`, ubuntu).
pub(super) const ZIPNOTE_V_UBUNTU_POST: &str = concat!(
    "Currently maintained by E. Gordon.  Please send bug reports to\n",
    "the authors using the web page at www.info-zip.org; see README for details.\n",
    "\n",
    "Latest sources and executables are at ftp://ftp.info-zip.org/pub/infozip,\n",
    "as of above date; see http://www.info-zip.org/ for other sites.\n",
    "\n",
    "Compiled with gcc 13.3.0 for Unix (Linux ELF).\n",
    "\n",
    "ZipNote special compilation options:\n",
    "\t[none]\n",
);

/// zipsplit.c:version_info, what precedes the banner line (recorded `zipsplit -v`, apple).
pub(super) const ZIPSPLIT_V_APPLE_PRE: &str = "";

/// zipsplit.c:version_info, what follows the banner line (recorded `zipsplit -v`, apple).
pub(super) const ZIPSPLIT_V_APPLE_POST: &str = concat!(
    "Please report bugs to Apple.\n",
    "\n",
    "Compiled with gcc Apple LLVM 21.0.0 (clang-2100.3.31.1) [+internal-os] for Unix (Mac OS X) on Aug  8 2026.\n",
    "\n",
    "ZipSplit special compilation options:\n",
    "\t[none]\n",
);

/// zipsplit.c:version_info, what precedes the banner line (recorded `zipsplit -v`, ubuntu).
pub(super) const ZIPSPLIT_V_UBUNTU_PRE: &str = "";

/// zipsplit.c:version_info, what follows the banner line (recorded `zipsplit -v`, ubuntu).
pub(super) const ZIPSPLIT_V_UBUNTU_POST: &str = concat!(
    "Currently maintained by E. Gordon.  Please send bug reports to\n",
    "the authors using the web page at www.info-zip.org; see README for details.\n",
    "\n",
    "Latest sources and executables are at ftp://ftp.info-zip.org/pub/infozip,\n",
    "as of above date; see http://www.info-zip.org/ for other sites.\n",
    "\n",
    "Compiled with gcc 13.3.0 for Unix (Linux ELF).\n",
    "\n",
    "ZipSplit special compilation options:\n",
    "\t[none]\n",
);

// ---- writing new archives (Task 6: zipup.c, zipfile.c, zip.c:main) ----

/// zip.c:main, before each new entry (`%s` the shown name).
pub(super) const ADDING: &str = "  adding: %s";
/// zipup.c:zipup, `-du`: the size the scan found, `DisplayNumString`.
pub(super) const USIZE: &str = " (%s)";
/// zipup.c:zipup, `-v`.
pub(super) const IN_OUT: &str = "\t(in=%s) (out=%s)";
/// zipup.c:zipup, a deflated entry (`%d%%`).
pub(super) const DEFLATED: &str = " (deflated %s%%)\n";
/// zipup.c:zipup, a stored entry.
pub(super) const STORED: &str = " (stored 0%%)\n";
/// zip.c:main, `-v`'s last line (`%s`, `%s`, `%d%%`).
pub(super) const TOTAL_BYTES: &str = "total bytes=%s, compressed=%s -> %s%% savings\n";
/// zip.c:main, `perror("zip warning")` and its log copy.
pub(super) const PERROR_WARNING: &str = "zip warning: %s\n";
/// zipup.c:zipup, `perror("\nzip warning")` and its log copy.
pub(super) const PERROR_WARNING_NL: &str = "\nzip warning: %s\n";
/// zip.c:main, an input that could not be opened.
pub(super) const COULD_NOT_OPEN: &str = "could not open for reading: ";
/// zip.c:main, a name that is a file in the scan and a directory now (or
/// the other way round).
pub(super) const FILE_AND_DIR: &str = "file and directory with the same name: ";
/// zip.c:main, `ZIPERR(r, errbuf)` after zipup.
pub(super) const WAS_ZIPPING: &str = "was zipping %s";
/// zipup.c:zipup, a read error (stored entries).
pub(super) const COULD_NOT_READ: &str = "could not read input file: ";
/// zipup.c:zipup, the size read is not the size `stat` gave.
pub(super) const SIZE_CHANGED: &str = " file size changed while zipping ";
/// zipup.c:zipup, `-l` on a file `is_text_buf` found binary.
pub(super) const L_BINARY_IGNORED: &str = "has binary so -l ignored";
/// zipup.c:zipup, `-ll` on such a file.
pub(super) const LL_BINARY_IGNORED: &str = "has binary so -ll ignored";
/// zipup.c:zipup, `-l` on a file deflate found binary.
pub(super) const L_CORRUPTED: &str = "-l used on binary file - corrupted?";
/// zipup.c:zipup, `-ll` likewise.
pub(super) const LL_CORRUPTED: &str = "-ll used on binary file - corrupted?";
/// zipup.c:zipup, `-0` and an input of unknown size on a pipe.
pub(super) const NO_STORE_ON_PIPES: &str = "zip -0 not supported for I/O on pipes or devices";
/// deflate.c:lm_init, `error("bad pack level")` (`-Z deflate` after `-0`).
pub(super) const BAD_PACK_LEVEL: &str = "bad pack level";
/// trees.c:flush_block, `error("block vanished")`.
pub(super) const BLOCK_VANISHED: &str = "block vanished";
/// zipup.c:zipup, the stream's error flag after a local header.
pub(super) const UNEXPECTED_ERROR_ON_ZIP: &str = "unexpected error on zip file";
/// zipup.c:zipup, `error()` when a descriptor follows an entry deflate
/// stored.
pub(super) const CANT_REWRITE_METHOD: &str = "can't rewrite method";
/// fileio.c:bfwrite and zipup.c:flush_outbuf, `ziperr(ZE_WRITE, ...)`.
pub(super) const WRITE_ERROR_ON_ZIP: &str = "write error on zip file";
/// zip.c:main, the summary after unreadable inputs.
pub(super) const NOT_ALL_READABLE: &str = "\nzip warning: Not all files were readable\n";
/// zip.c:main, the summary's counts (`%lu`).
pub(super) const FILES_READ: &str = "  files/entries read:  %s";
/// zip.c:main, a byte count of the summary.
pub(super) const N_BYTES: &str = " (%s bytes)";
/// zip.c:main, the summary's skipped count (`%lu`).
pub(super) const SKIPPED: &str = "  skipped:  %s";
/// zip.c:main, `-c`'s question.
pub(super) const ENTER_COMMENT: &str = "Enter comment for %s:\n";
/// zip.c:main, `-z`'s question.
pub(super) const ENTER_ZIP_COMMENT: &str = "enter new zip file comment (end with .):\n";
/// zip.c:main, nothing in the central directory.
pub(super) const ZIP_FILE_EMPTY: &str = "zip file empty";
/// zip.c:main, `replace()` failed.
pub(super) const NEW_ZIP_LEFT_AS: &str = "new zip file left as: ";
/// zip.c:main, `ZIPERR(r, ...)` after a failed `replace()`.
pub(super) const WAS_REPLACING: &str = "was replacing the original zip file";
/// zip.c:main, `-sd`.
pub(super) const SD_OPEN_ZIP: &str = "sd: Open zip file and create temp file\n";
/// zip.c:main, `-sd`.
pub(super) const SD_CREATING: &str = "sd: Creating new zip file\n";
/// zip.c:main, `-sd`.
pub(super) const SD_ZIPPING_NEW: &str = "sd: Zipping up new entries\n";
/// zip.c:main, `-sd`.
pub(super) const SD_GET_COMMENT: &str = "sd: Get comment if any\n";
/// zip.c:main, `-sd`.
pub(super) const SD_WRITING_CENTRAL: &str = "sd: Writing central directory\n";
/// zip.c:main, `-sd`.
pub(super) const SD_WRITING_END: &str = "sd: Writing end of central directory\n";
/// zip.c:main, `-sd`.
pub(super) const SD_REPLACING: &str = "sd: Replacing old zip file\n";
/// zip.c:main, `-sd`.
pub(super) const SD_SETTING_TYPE: &str = "sd: Setting file type\n";
/// zip.c:DisplayRunningStats, `-dv` (`%lu>%lu: `).
pub(super) const DV: &str = "%s>%s: ";
/// zip.c:DisplayRunningStats, `-dc` (`%3ld/%3ld `).
pub(super) const DC: &str = "%s/%s ";
/// zip.c:DisplayRunningStats, `-db`'s start (`[%4s`).
pub(super) const DB_START: &str = "[%s";
/// zip.c:DisplayRunningStats, `-db`'s bytes to go (`/%4s] `).
pub(super) const DB_LEFT: &str = "/%s] ";
/// zip.c:DisplayRunningStats, `-db` past the planned total (`-%4s] `).
pub(super) const DB_OVER: &str = "-%s] ";
/// zip.c:main, the log file's last lines (`-lf`).
pub(super) const LOG_TOTAL: &str = "\nTotal %s entries (";
/// zip.c:main, the log's planned/actual bytes.
pub(super) const LOG_PLANNED: &str = "planned ";
/// zip.c:main, the log.
pub(super) const LOG_ACTUAL: &str = " bytes, actual ";
/// zip.c:main, the log.
pub(super) const LOG_BYTES: &str = " bytes)";
/// zip.c:main, the log's end (`%s` is `asctime()`).
pub(super) const LOG_DONE: &str = "\nDone %s";
/// zipfile.c:putlocal, before a `ZE_BIG` error.
pub(super) const ENTRY_TOO_BIG: &str = "Entry too big:";
/// zipfile.c:putlocal, `-fz-` and an entry that needs Zip64.
pub(super) const LARGE_DISABLED_NEEDED: &str = "Large entry support disabled with -fz- but needed";
/// zipfile.c:putlocal, `-fz-` and an entry that turned out to need Zip64.
pub(super) const LARGE_DISABLED_ENTRY_NEEDS: &str =
    "Large entry support disabled with -fz- but entry needs";
/// zipfile.c:putlocal, an entry that needs Zip64 only once written.
pub(super) const UNEXPECTEDLY_LARGE: &str =
    "Compressed/stored entry unexpectedly large - do not use -fz-";
/// zipfile.c:putlocal, likewise under `-fz`.
pub(super) const POOR_COMPRESSION: &str =
    "Poor compression resulted in unexpectedly large entry - try -fz";
/// zipfile.c:add_central_zip64_extra_field, `-fz-` and a field too big.
pub(super) const LARGE_DISABLED_USING: &str = "Large entry support disabled using -fz- but needed";
/// zipfile.c:trash, `-m` with `-v`.
pub(super) const DELETING_FILE: &str = "zip diagnostic: deleting file %s\n";
/// zipfile.c:trash, a failed `unlink`.
pub(super) const ERROR_DELETING: &str = "error deleting ";
/// zipfile.c:trash, `-m` with `-v`, a directory.
pub(super) const DELETING_DIR: &str = "deleting directory %s (if empty)                \n";
/// zip.c:finish, `-o` over directories only.
pub(super) const ONLY_DIRS_NO_LATEST: &str =
    "zip file has only directories, can't make it as old as latest entry";

// ---- updating archives (Task 7: zipfile.c, fileio.c, zip.c:main) ----

/// zip.c:handler + ziperr(ZE_ABORT, "aborting"): what the interrupt
/// handler prints after its newlines.
pub(crate) const INTERRUPTED_ABORTING: &[u8] = b"\nzip error: Interrupted (aborting)\n";
/// zipfile.c:scanzipf_regnew (no separator before the name).
pub(super) const COULD_NOT_OPEN_INPUT_ARCHIVE: &str = "could not open input archive";
/// zipfile.c:scanzipf_regnew
pub(super) const UNABLE_TO_SEEK: &str = "unable to seek in input file ";
/// zipfile.c:scanzipf_regnew, no end record.
pub(super) const MISSING_END_1: &str = "missing end signature--probably not a zip file (did you";
pub(super) const MISSING_END_2: &str = "remember to use binary mode when you transferred it?)";
pub(super) const MISSING_END_3: &str = "(if you are trying to read a damaged archive try -F)";
/// zipfile.c:scanzipf_regnew, `-A` on a split archive.
pub(super) const ADJUST_SPLITS: &str = "Adjusting split archives not yet supported";
/// zipfile.c:scanzipf_regnew
pub(super) const SPLIT_NAME_ZIP: &str = "archive name must end in .zip for splits";
/// zipfile.c:scanzipf_regnew
pub(super) const CANNOT_UPDATE_SPLIT: &str = "cannot update a split archive (use --out option)";
/// zipfile.c:scanzipf_regnew and friends (`%s` follows: `strerror`).
pub(super) const READING_ARCHIVE_FSEEK: &str = "reading archive fseek: ";
/// zipfile.c:scanzipf_regnew, `-A`.
pub(super) const CENTRAL_NOT_WHERE_EXPECTED: &str =
    "central dir not where expected - could not adjust offsets";
/// zipfile.c:scanzipf_regnew
pub(super) const TRY_FF: &str = "(try -FF)";
/// zipfile.c:scanzipf_regnew
pub(super) const READING_ARCHIVE: &str = "reading archive: ";
/// zipfile.c:scanzipf_regnew
pub(super) const UNABLE_TO_READ_EOCD: &str = "unable to read EOCD after seek: ";
/// zipfile.c:scanzipf_regnew, `-A`.
pub(super) const ADJUST_SPLITS_NOT_SUPPORTED: &str = "Adjusting split archives not supported:  ";
/// zipfile.c:scanzipf_regnew, `-A`.
pub(super) const COULD_NOT_DETERMINE_OFFSET: &str = "Could not determine offset of entries";
/// zipfile.c:scanzipf_regnew, `-A` (`%s` bytes).
pub(super) const OFFSETS_OFF_BY: &str = "Zip entry offsets appear off by %s bytes - correcting...";
/// zipfile.c:scanzipf_regnew, `-A`.
pub(super) const OFFSETS_DO_NOT_NEED: &str = "Zip entry offsets do not need adjusting";
/// zipfile.c:scanzipf_regnew
pub(super) const Z64_COMPENSATING: &str = "Zip64 EOCDR not found where expected - compensating";
/// zipfile.c:scanzipf_regnew
pub(super) const TRY_A: &str = "(try -A to adjust offsets)";
/// zipfile.c:scanzipf_regnew
pub(super) const Z64_EOCDR_NOT_FOUND: &str = "Zip64 End Of Central Directory Record not found:  ";
/// zipfile.c:scanzipf_regnew
pub(super) const Z64_EOCDR_TRUNCATED: &str = "Zip64 EOCD Record bad or truncated";
/// zipfile.c:scanzipf_regnew (`%d.%d`).
pub(super) const REQUIRES_VERSION: &str = "This archive requires version %s.%s";
/// zipfile.c:scanzipf_regnew
pub(super) const SUPPORTS_UP_TO_46: &str = "Zip currently only supports up to version 4.6 archives";
/// zipfile.c:scanzipf_regnew
pub(super) const UP_TO_45: &str = "(up to 4.5 if bzip2 is not compiled in)";
/// zipfile.c:scanzipf_regnew
pub(super) const TRY_F_READ_ANYWAY: &str = "Try -F to attempt to read anyway";
/// zipfile.c:scanzipf_regnew (`%lu`, `%s`; the newline is the C's).
pub(super) const UNEXPECTED_SIGNATURE: &str = "unexpected signature on disk %s at %s\n";
/// zipfile.c:scanzipf_regnew
pub(super) const NOT_IN_CORRECT_FORMAT: &str = "archive not in correct format: ";
/// zipfile.c:scanzipf_regnew
pub(super) const TRY_F: &str = "(try -F to attempt recovery)";
/// zipfile.c:scanzipf_regnew
pub(super) const READING_CENTRAL: &str = "reading central directory: ";
/// zipfile.c:scanzipf_regnew
pub(super) const ZERO_LENGTH_NAME: &str = "zero-length name for entry #";
/// zipfile.c:scanzipf_regnew (`%s`, `%s`).
pub(super) const EXPECTED_ENTRIES: &str = "expected %s entries but found %s";
/// zipfile.c:zipoddities (`%d.%d`, `%d`).
pub(super) const MADE_BY_VERSION: &str = "made by version %s.%s on system type %s: ";
/// zipfile.c:zipoddities
pub(super) const NEEDS_UNZIP: &str = "needs unzip %s.%s on system type %s: ";
/// zipfile.c:zipoddities (`0x%04x`)
pub(super) const UNDEFINED_BITS: &str = "undefined bits used in flags = 0x%s: ";
/// zipfile.c:zipoddities
pub(super) const UNKNOWN_METHOD: &str = "unknown compression method %s: ";
/// zipfile.c:zipoddities
pub(super) const STARTS_ON_DISK: &str = "starts on disk %s: ";
/// zipfile.c:zipoddities (`0x%04x`)
pub(super) const UNKNOWN_INTERNAL: &str = "unknown internal attributes = 0x%s: ";
/// zipfile.c:readlocal, zipcopy
pub(super) const DID_NOT_FIND_ENTRY: &str = "Did not find entry for ";
/// zipfile.c:readlocal, zipcopy
pub(super) const READING_LOCAL_ENTRY: &str = "reading local entry: ";
/// zipfile.c:readlocal (`%d`, `%d`).
pub(super) const LOCAL_VERSION_NEEDED: &str = "Local Version Needed (%s) does not match CD (%s): ";
/// zipfile.c:zipcopy
pub(super) const LOCAL_VERSION_MISMATCH: &str =
    "Local Version Needed To Extract does not match CD: ";
/// zipfile.c:readlocal, zipcopy
pub(super) const LOCAL_FLAG_MISMATCH: &str = "Local Entry Flag does not match CD: ";
/// zipfile.c:readlocal, zipcopy
pub(super) const LOCAL_CRC_MISMATCH: &str = "Local Entry CRC does not match CD: ";
/// zipfile.c:zipcopy
pub(super) const LOCAL_NAME_MISMATCH: &str = "Local Entry name does not match CD: ";
/// zip.c:main, an old entry being replaced (`%s`).
pub(super) const UPDATING: &str = "updating: %s";
/// zip.c:main, `-f`.
pub(super) const FRESHENING: &str = "freshening: %s";
/// zip.c:main, `-FS -v` and an entry that matches its file.
pub(super) const FS_OK: &str = "      ok: %s";
/// zip.c:main, the log's line for it.
pub(super) const FS_CURRENT_LOG: &str = " current: %s";
/// zip.c:main, `-d` and `-FS`.
pub(super) const DELETING: &str = "deleting: %s";
/// zip.c:main, `-U`.
pub(super) const COPYING: &str = " copying: %s";
/// zip.c:main
pub(super) const COULD_NOT_READ_LOCAL: &str = "could not read local entry information: ";
/// zip.c:main, an entry whose file could not be opened.
pub(super) const WILL_JUST_COPY: &str = "will just copy entry over: ";
/// zip.c:main, `ZIPERR(r, errbuf)` after zipcopy.
pub(super) const WAS_COPYING: &str = "was copying %s";
/// zip.c:main, `-U` after a failed copy.
pub(super) const TRY_F_TO_FIX: &str = "(try -F to attempt to fix)";
/// zip.c:main, `-v` and an entry left as it is (`%s %s`).
pub(super) const ZIP_DIAGNOSTIC: &str = "zip diagnostic: %s %s\n";
/// zip.c:main
pub(super) const UP_TO_DATE: &str = "up to date";
/// zip.c:main
pub(super) const MISSING_OR_EARLY: &str = "missing or early";
/// unix.c:procname, fileio.c:proc_archive_name, `-v` (`%s`: `in`/`ex`).
pub(super) const INCLUDING: &str = "zip diagnostic: %scluding %s\n";
/// fileio.c:newname, `-v` and an archive entry the filters exclude.
pub(super) const EXCLUDING: &str = "excluding %s\n";
/// fileio.c:proc_archive_name
pub(super) const CANNOT_SELECT_STDIN: &str = "Cannot select stdin when selecting archive entries";
/// zip.c:main, `-U` and a name no entry matches.
pub(super) const NOT_IN_ARCHIVE: &str = "not in archive: ";
/// zip.c:main, `-FS` with nothing to do.
pub(super) const ARCHIVE_IS_CURRENT: &str = "Archive is current";
/// zip.c:main, `-z` on an archive with a comment.
pub(super) const CURRENT_COMMENT: &str = "current zip file comment is:\n";
/// zip.c:main, `-sd`.
pub(super) const SD_GOING_THROUGH: &str = "sd: Going through old zip file\n";
/// zip.c:check_zipfile
pub(super) const TEST_FAILED: &str = "test of %s FAILED\n";
/// zip.c:check_zipfile
pub(super) const TEST_OK: &str = "test of %s OK\n";
/// zip.c:check_zipfile, `ziperr(ZE_TEST, ...)`.
pub(super) const ORIGINAL_UNMODIFIED: &str = "original files unmodified";
/// apple.diff, zip.c:check_zipfile.
pub(super) const BRACES_NOT_SUPPORTED: &str = "{} in -TT not supported";
/// zip.c:check_unzip_version
pub(super) const FAILED_UNZIP_INFO: &str = "failed to get information from UnZip";
/// zip.c:check_unzip_version
pub(super) const UNEXPECTED_UNZIP_V: &str = "unexpected output of UnZip -v";
/// zip.c:check_unzip_version (`%4.2f`).
pub(super) const FOUND_UNZIP_VERSION: &str = "Found UnZip version %s";
/// zip.c:check_unzip_version
pub(super) const NEED_UNZIP_6: &str = "Need UnZip 6.00 or later to test this Zip64 archive";
/// zip.c:check_unzip_version, `perror("unzip pipe error")`.
pub(super) const UNZIP_PIPE_ERROR: &str = "unzip pipe error: %s\n";
/// zip.c:check_zipfile: the program and its options.
pub(super) const UNZIP: &str = "unzip";
pub(super) const UNZIP_T: &str = "-t";
pub(super) const UNZIP_QQ: &str = "-qq";
/// zip.c:check_unzip_version, the version probe's command.
pub(super) const UNZIP_V_CMD: &str = " -v";
/// zip.c:check_zipfile (Ubuntu): `system()`'s command and its quoting.
pub(super) const UNZIP_T_CMD: &str = "unzip -t ";
pub(super) const QQ_CMD: &str = "-qq ";
/// zip.c:check_unzip_version's `sscanf(buf, "UnZip %f ", ...)` prefix.
pub(super) const UNZIP_V_PREFIX: &str = "UnZip";
/// zip.c:main, the temporary's template.
pub(super) const TEMP_TEMPLATE: &str = "zi";
/// zip.c:main, `-sd` before `-U`'s names.
pub(super) const SD_SCANNING_ARCHIVE: &str = "sd: Scanning archive entries\n";
/// zip.c:BlankRunningStats, `-dv` (`%lu>%lu: ` of disks 1 and 1).
pub(super) const BLANK_DV: &str = "1>1: ";
/// zip.c:BlankRunningStats, `-dc`.
pub(super) const BLANK_DC: &str = "   /    ";
/// zip.c:BlankRunningStats, `-db`.
pub(super) const BLANK_DB: &str = "     /      ";
/// zip.c:ziperr under `-g` (`tempzip == zipfile`).
pub(super) const ATTEMPTING_RESTORE: &str = "attempting to restore %s to its previous state\n";

// ---- Task 8: -F, -FF and split archives ----

/// fileio.c:ask_for_split_read_path, the part not found (`%s` its path).
pub(super) const COULD_NOT_FIND: &str = "\n\nCould not find:\n  %s\n";
/// fileio.c:ask_for_split_read_path, the choices (each starts a line).
pub(super) const HIT_C: &str = "\nHit c      (change path to where this split file is)";
pub(super) const HIT_S: &str = "\n    s      (skip this split)";
pub(super) const HIT_Q: &str = "\n    q      (abort archive - quit)";
pub(super) const HIT_E: &str = "\n    e      (end this archive - no more splits)";
pub(super) const HIT_Z: &str = "\n    z      (look for .zip split - the last split)";
pub(super) const HIT_ENTER_CONTINUE: &str = "\n or ENTER  (continue with this split): ";
pub(super) const HIT_ENTER_AGAIN: &str = "\n or ENTER  (try reading this split again): ";
/// fileio.c:ask_for_split_read_path, after `c`.
pub(super) const ENTER_SPLIT_PATH: &str =
    "\nEnter path where this split is (ENTER = same dir, . = current dir)\n: ";
/// fileio.c:ask_for_split_read_path and ask_for_split_write_path, the
/// directory of a bare name.
pub(super) const CURRENT_DIRECTORY: &str = "(current directory)";
/// fileio.c:ask_for_split_read_path, the path tried again.
pub(super) const COULD_NOT_FIND_OR_OPEN: &str = "\nCould not find or open\n  %s\n";
/// fileio.c:ask_for_split_read_path, after a new path.
pub(super) const FOUND_SPLIT: &str = "Found:  %s\n";
/// fileio.c:ask_for_split_read_path, the path as it was.
pub(super) const FOUND_SPLIT_NL: &str = "\nFound:  %s\n";
/// fileio.c:ask_for_split_write_path (`%s`: the disk, then the directory).
pub(super) const OPENING_DISK: &str = "\nOpening disk %s\nHit ENTER to write to default path of\n  %s\nor enter a new directory path (. for cur dir) and hit ENTER\n";
pub(super) const SPLIT_PATH_PROMPT: &str = "\nPath (or hit ENTER to continue): ";
pub(super) const WRITING_TO: &str = "Writing to:\n  %s\n";
/// fileio.c:close_split, under `-sv`.
pub(super) const CLOSING_SPLIT: &str = "\tClosing split ";
/// fileio.c:bfwrite's errors.
pub(super) const COULD_NOT_WRITE_SPLIT: &str = "Could not write split";
pub(super) const NOT_ENOUGH_SPACE_SPLIT: &str = "Not enough space to write split";
pub(super) const NOT_ENOUGH_ROOM: &str = "Not enough room on disk";
/// fileio.c:get_in_split_path, get_out_split_path.
pub(super) const MORE_THAN_99999: &str = "More than 99999 splits needed";
/// zip.c:rename_split
pub(super) const WAS_REPLACING_SPLIT: &str = "was replacing split file";
/// fileio.c:bfcopy, zipfile.c:scanzipf_regnew and scanzipf_fixnew.
pub(super) const COULD_NOT_FIND_SPLIT: &str = "could not find split: ";
pub(super) const USER_ENDED_READING: &str = "user ended reading - closing archive";
pub(super) const SKIPPING_SPLIT_FILE: &str = "skipping split file: ";
pub(super) const SEEK_FAILED_DESCRIPTOR: &str = "seek failed reading descriptor";
/// zipfile.c:scanzipf_regnew and scanzipf_fixnew (`%s` the disk number).
pub(super) const SKIPPING_DISK: &str = "skipping disk %s ...\n";
/// zipfile.c:scanzipf_regnew under -F.
pub(super) const F_MISSING_END_1: &str = "bad archive - missing end signature";
pub(super) const F_MISSING_END_2: &str = "(If downloaded, was binary mode used?  If not, the";
pub(super) const F_MISSING_END_3: &str = " archive may be scrambled and not recoverable)";
pub(super) const F_MISSING_END_4: &str = "Can't use -F to fix (try -FF)";
pub(super) const MUST_USE_OUT: &str = "must use --out when fixing an archive";
pub(super) const F_SEEK_CENTRAL: &str = "could not seek back to start of central directory: ";
pub(super) const F_SEEK_EOCDL: &str = "could not seek back to Zip64 EOCDL: ";
pub(super) const F_BAD_SEEK_EOCDL: &str = "bad archive - could not seek back to Zip64 EOCDL: ";
pub(super) const F_SEEK_EOCDR: &str = "could not seek back to Zip64 EOCDR: ";
pub(super) const F_BAD_SEEK_EOCDR: &str = "bad archive - could not seek back to Zip64 EOCDR: ";
pub(super) const F_Z64_NOT_IN_SPLIT: &str = "bad archive - Zip64 EOCDR not found in split:  ";
pub(super) const F_Z64_TRUNCATED: &str = "bad archive - Zip64 EOCDR bad or truncated";
pub(super) const F_TRY_FF_SALVAGE: &str = "If -F fails try -FF to try to salvage something";
pub(super) const FF_SALVAGING: &str = "Attempting to salvage what can";
/// zipfile.c:scanzipf_regnew under -F (`%s` the four bytes as `%02x `).
pub(super) const F_UNEXPECTED_SIGNATURE: &str = "bad archive - unexpected signature ";
/// zipfile.c:scanzipf_regnew and scanzipf_fixnew, after the bytes.
pub(super) const SIG_ON_DISK: &str = "on disk %s at %s\n";
pub(super) const SKIPPING_SIGNATURE: &str = "skipping this signature...";
pub(super) const CENTRAL_SIG_ON_DISK: &str =
    "central directory header signature on disk %s at %s\n";
pub(super) const F_ERROR_READING_CENTRAL: &str = "bad archive - error reading central directory";
pub(super) const SKIPPING_ENTRY: &str = "skipping this entry...";
pub(super) const ERROR_READING_ENTRY: &str = "error reading entry:  ";
/// zipfile.c:scanzipf_fixnew
pub(super) const FF_NEED_ZIP: &str = "if archive to fix is split archive, need to provide\n      path of the last split with .zip extension,\n      even if it doesn't exist (zip will ask for splits)";
pub(super) const FF_COULD_NOT_OPEN: &str = "could not open input archive: ";
pub(super) const FF_MISSING_EOCDR: &str = "Missing end (EOCDR) signature - either this archive\n                     is not readable or the end is damaged";
pub(super) const FF_EOCDR_SHORT: &str = "End record (EOCDR) only %s bytes - assume truncated";
pub(super) const FF_EOCDR_BAD_DISKS: &str =
    "End record (EOCDR) has bad disk numbers - ignoring EOCDR";
pub(super) const FF_COMMENT_TRUNCATED: &str = "zipfile comment truncated - ignoring";
pub(super) const FF_EXPECT_SPLITS: &str = " Found end record (EOCDR) - says expect %s splits";
pub(super) const FF_EXPECT_SINGLE: &str =
    " Found end record (EOCDR) - says expect single disk archive";
pub(super) const FF_FOUND_COMMENT: &str = "  Found archive comment";
pub(super) const FF_SINGLE_DISK_Q: &str = "Is this a single-disk archive?  (y/n): ";
pub(super) const FF_ASSUMING_SINGLE: &str = "  Assuming single-disk archive";
pub(super) const FF_SCANNING: &str = "Scanning for entries...";
/// zipfile.c:scanzipf_fixnew (`%s`: the disk, `%2lu`, then the offset,
/// `%6s`).
pub(super) const FF_EOCDR_FOUND: &str = "EOCDR found (%s %s)...";
pub(super) const FF_Z64_EOCDR_FOUND: &str = "Zip64 EOCDR found (%s %s)...";
pub(super) const FF_Z64_EOCDL_FOUND: &str = "Zip64 EOCDL found (%s %s)...";
pub(super) const FF_LOCAL: &str = " Local (%s %s):";
pub(super) const FF_ENTRY_AFTER_CENTRAL: &str = "Entry after central directory found (%s %s)...";
pub(super) const FF_CENTRAL_FOUND: &str = "Central Directory found...";
pub(super) const FF_CEN: &str = " Cen   (%s %s): ";
pub(super) const FF_CEN_UPDATING: &str = "updating: %s";
pub(super) const FF_CRC_MISMATCH: &str = "local (%s) and cen (%s) crc mismatch";
pub(super) const FF_WRITING_SEEK: &str = "writing archive seek: ";
pub(super) const FF_ERROR_REWRITING: &str = "Error rewriting local header";
pub(super) const FF_WRITE_SEEK: &str = "write archive seek: ";
pub(super) const FF_SEEK_AFTER_LOCAL: &str = "seek after local: ";
pub(super) const FF_NO_LOCAL_ENTRY: &str = "no local entry: %s";
pub(super) const FF_SPAN_NOT_EXPECTED: &str =
    "  Found spanning marker, but did not expect split (multi-disk) archive...";
pub(super) const FF_SPAN_EXPECTED: &str =
    "  Found spanning marker - expected as this is split (multi-disk) archive...";
pub(super) const FF_SPAN_MAYBE: &str = "  Found spanning marker - could be split archive...";
pub(super) const FF_UNEXPECTED_SIGNATURE: &str = "unexpected signature ";
/// zipfile.c:zipcopy under -FF (`%s`: the number).
pub(super) const FF_ILLEGAL_HOST: &str = "Illegal host system mapping in local header:  %s";
pub(super) const FF_ILLEGAL_PKVER: &str = "Illegal PK version mapping in local header:  %s";
pub(super) const FF_UNRECOGNIZED_METHOD: &str =
    "Unrecognized compression method in local header:  %s";
pub(super) const FF_SKIPPING: &str = "Skipping:  ";
pub(super) const FF_COPYING: &str = " copying: %s ";
pub(super) const FF_BYTES: &str = " (%s bytes)";
pub(super) const FF_ENTRY_TRUNCATED: &str = "entry truncated: ";
pub(super) const FF_EXPECTED_SIZE: &str = "expected compressed/stored size %s, actual %s";
pub(super) const FF_NO_END_OF_STREAM: &str = "no end of stream entry found: ";
pub(super) const FF_REWINDING: &str = "rewinding and scanning for later entries";
/// zipfile.c:zipcopy
pub(super) const COULD_NOT_FIND_SPLIT_ABORT: &str = "Could not find split";
pub(super) const ABORTING_ENTRY: &str = "aborting: ";
pub(super) const SEEK_FAILED_OUTPUT: &str = "seek failed on output file";
/// zip.c:main, `-F`'s copy loop.
pub(super) const SKIPPING_ENTRY_NAME: &str = " skipping: %s";
pub(super) const BAD_SKIPPING: &str = "bad - skipping: ";
pub(super) const COULD_NOT_SEEK_OUTPUT: &str = "could not seek in output file";
pub(super) const USER_REQUESTED_ABORT: &str = "user requested abort";
/// zip.c:main, an input split archive's first part.
pub(super) const NO_INFO_INPUT_SPLIT: &str = "Could not get info for input split: ";
/// zip.c:main, `-sv`.
pub(super) const SPLITSIZE: &str = "splitsize = ";
/// zip.c:main, -FF's `sd:` lines.
pub(super) const SD_OPEN_FF: &str = "sd: Open zip file and create temp file (-FF)\n";
pub(super) const SD_CREATING_FF: &str = "sd: Creating new zip file (-FF)\n";
pub(super) const SD_WRITING_CENTRAL_FF: &str = "sd: Writing central directory (-FF)\n";
/// zip.c:main, the spanning signature's `sd:` line.
pub(super) const SD_SPANNING: &str = "sd: Adding spanning/splitting signature at top of archive\n";
/// zip.c:main, `-g` over a split archive.
pub(super) const CANNOT_GROW_SPLIT: &str = "cannot grow split archive";
/// zip.c:main, the first part of the archive could not be opened.
pub(super) const COULD_NOT_OPEN_TO_READ: &str = "could not open archive to read";
/// zipfile.c:readzipfile, `-F` with no archive.
pub(super) const NO_ZIP_FOUND_1: &str = "No .zip file found\n        ";
pub(super) const NO_ZIP_FOUND_2: &str =
    "(If all you have are splits (.z01, .z02, ...) and no .zip, try -FF)";
/// zipup.c:zipup, the data written is not the size counted.
pub(super) const SIZE_ACTUAL: &str = " s=%s, actual=%s ";
pub(super) const INCORRECT_COMPRESSED_SIZE: &str = "incorrect compressed size";

// ---- encryption, the password prompts and zipcloak (Task 9) ----

/// zip.c:encr_passwd, zipcloak.c:main: the first prompt.
pub(super) const ENTER_PASSWORD: &str = "Enter password: ";
/// zip.c:encr_passwd, zipcloak.c:main: the second prompt.
pub(super) const VERIFY_PASSWORD: &str = "Verify password: ";
/// zip.c:main, zipcloak.c:main: the two answers differ.
pub(super) const PASSWORD_VERIFICATION_FAILED: &str = "password verification failed";
/// zipcloak.c:main, no terminal to prompt on.
pub(super) const CLOAK_STDERR_NOT_TTY: &str =
    "stderr is not a tty (you may never see this message!)";
/// zipcloak.c:main, `-d` and no entry encrypted.
pub(super) const NO_ENCRYPTED_FILES: &str = "no encrypted files";
/// zipcloak.c:main, every entry encrypted.
pub(super) const ALL_ENCRYPTED_ALREADY: &str = "all files encrypted already";
/// zipcloak.c:main (no newline: the answer follows on the line).
pub(super) const DECRYPTING: &str = "decrypting: %s";
/// zipcloak.c:main, the header's check byte did not match.
pub(super) const WRONG_PASSWORD_JUST_COPYING: &str = " (wrong password--just copying)";
/// zipcloak.c:main
pub(super) const ENCRYPTING: &str = "encrypting: %s\n";
/// zipcloak.c:main
pub(super) const CLOAK_COPYING: &str = "   copying: %s\n";
/// zipcloak.c:main
pub(super) const WAS_DECRYPTING: &str = "was decrypting an entry";
/// zipcloak.c:main
pub(super) const WAS_ENCRYPTING: &str = "was encrypting an entry";
/// zipcloak.c:main, crypt.c:zipbare
pub(super) const WAS_COPYING_AN_ENTRY: &str = "was copying an entry";
/// zipcloak.c:handler + ziperr(ZE_ABORT, "aborting"): what the interrupt
/// handler prints after its newline.
pub(crate) const CLOAK_INTERRUPTED: &[u8] = b"zipcloak error: Interrupted (aborting)\n";
/// stuffr's own (Task 9): the system gave no random bytes for an
/// encryption header (zip's `rand()` cannot fail; `ZE_LOGIC`).
pub(super) const NO_RANDOM_BYTES: &str = "no random bytes for the encryption header";

// ---- zipnote and zipsplit (Task 10) ----

/// zipnote.c:handler + ziperr(ZE_ABORT, "aborting"): what the interrupt
/// handler prints after its newline.
pub(crate) const NOTE_INTERRUPTED: &[u8] = b"zipnote error: Interrupted (aborting)\n";
/// zipsplit.c:handler + ziperr(ZE_ABORT, "aborting").
pub(crate) const SPLIT_INTERRUPTED: &[u8] = b"zipsplit error: Interrupted (aborting)\n";
/// zipnote.c:main, an entry's name line (`%s` is its name).
pub(super) const NOTE_NAME: &str = "@ %s\n";
/// zipnote.c:main, the line after an entry's comment.
pub(super) const NOTE_END_OF_COMMENT: &str = "@ (comment above this line)\n";
/// zipnote.c:main, the line before the archive's comment.
pub(super) const NOTE_ZIP_COMMENT: &str = "@ (zip file comment below this line)\n";
/// zipnote.c:MARKZ, what follows the `@` of that line.
pub(super) const NOTE_MARKZ: &str = " (zip file comment below this line)";
/// zipnote.c:main
pub(super) const UNEXPECTED_INPUT: &str = "unexpected input";
/// zipnote.c:main
pub(super) const UNKNOWN_ENTRY_NAME: &str = "unknown entry name";
/// zipsplit.c:main (`%s` is the numbers: how many, `ould` or `ill`, how
/// efficient).
pub(super) const SPLIT_WILL_BE_MADE: &str = "%s zip files w%s be made (%s%% efficiency)\n";
/// zipsplit.c:main, the largest an entry may be (`%s` is the number).
pub(super) const ENTRY_LARGER_THAN_MAX: &str = "Entry is larger than max split size of: %s";
/// zipsplit.c:main
pub(super) const USE_N_TO_SET: &str = "use -n to set split size";
/// zipsplit.c:main
pub(super) const WAY_TOO_MANY: &str = "way too many zip files must be made";
/// zipsplit.c:main, a file being made (`%s` is its path).
pub(super) const SPLIT_CREATING: &str = "creating: %s\n";
/// zipsplit.c:main, `-p`.
pub(super) const INSERT_DISK: &str = "Insert disk #%s of %s and hit return: ";
/// zipsplit.c:main, `-p`, at the end.
pub(super) const SPLIT_DONE: &str = "Done.\n";
/// zipsplit.c:retry
pub(super) const REDO_DISK: &str = "Error writing to disk--redo entire disk? ";
/// zipsplit.c:main, a line of the index (`%s` the number, as `%5s` makes
/// it, then the name).
pub(super) const INDEX_LINE: &str = "%s %s\n";
/// zipsplit.c:main: `ziperr(r, zipfile)` with `zipfile` freed and NULL: the
/// C library prints `(null)`.
pub(super) const NULL_TEXT: &str = "(null)";

// ---- Ubuntu's UNICODE_SUPPORT (Task 11) ----

/// zipfile.c:read_Unicode_Path_entry: a leftover debugging `printf` to
/// standard output on a checksum mismatch (central directory only; `%d` is
/// `unicode_mismatch`).
pub(super) const UNICODE_MISMATCH_DEBUG: &str = "unicode_mismatch = %d\n";
/// zipfile.c:read_Unicode_Path_entry (and the local one): `zipwarn` with
/// the entry's oname, NULL there (glibc prints `(null)`), no space between.
pub(super) const UNICODE_VERSION_SKIP: &str = "Unicode Path Extra Field version > 1 - skipping";
/// zipfile.c:read_Unicode_Path_entry, `-UN warn` (the default).
pub(super) const UNICODE_MISMATCH_WARN: &str = "Unicode does not match path - ignoring Unicode: ";
/// zipfile.c:read_Unicode_Path_entry, `-UN quit`: `errbuf`, then
/// `ZIPERR(ZE_FORM, "Unicode path error")`.
pub(super) const UNICODE_MISMATCH_QUIT: &str = "Unicode does not match path:  %s\n                     Likely entry name changed but Unicode not updated\n                     Use -UN=i to ignore errors or n for no Unicode paths";
pub(super) const UNICODE_PATH_ERROR: &str = "Unicode path error";
/// zip.c:main (`-su`, and fileio.c:proc_archive_name under `-v`).
pub(super) const ESCAPED_UNICODE: &str = "     Escaped Unicode:  %s\n";
/// zipup.c (zip_stats): a bzip2 entry's line, `-Z bzip2` (Ubuntu).
pub(super) const BZIPPED: &str = " (bzipped %s%%)\n";
/// zipup.c:bz_compress_init, `BZ2_bzCompressInit`'s BZ_PARAM_ERROR (-2): a
/// block size out of 1..9 (`-0 -Z bzip2`).
pub(super) const BZ_INIT_FAILURE: &str = "bzlib bzCompressInit failure (-2)";
/// zipup.c:bzfilecompress, an encoder error (unreachable with a valid
/// level: stuffr's encoder does not fail on its own).
pub(super) const BZ_COMPRESS_ERROR: &str = "unexpected bzlib compress error -1";
