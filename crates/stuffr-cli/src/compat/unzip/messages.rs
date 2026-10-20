//! Every string the unzip family's front end prints, as Info-ZIP UnZip 6.00
//! prints it (C locale).
//!
//! Ported from Apple's `zip-33` tree (`unzip60/`, the Info-ZIP licence,
//! `LICENSE-infozip`). Each literal names its C array (`unzip.c:Zfirst`),
//! an Apple change (`// apple: <file>.c:<line>`), an Ubuntu patch
//! (`// ubuntu: <patch>`) or the binary it was recorded from
//! (`// probe: <command>`). Formats follow C's `printf` as [`printf`]
//! renders them: `%s` and `%d` take the next argument (an integer is
//! formatted by the caller); a width or precision is applied by the caller
//! and says so.
//!
//! The deliberate changes are the banners (R2, deviation 2): the first line
//! of each program's usage and `-v` names stuffr and says it is altered
//! (Info-ZIP licence clause 3), and the placeholders that answer until
//! archive processing is built (stuffr's own words).

pub(super) use crate::compat::host::printf;

// ---- banners (R2: deviation 2, Info-ZIP licence clause 3) ----

/// unzip.c:UnzipUsageLine1's first line under Apple's build (`apple:
/// unzip.c:574`: `UnZip 6.00 of 20 April 2009, by Info-ZIP, with
/// modifications by Apple Inc.`), as R2 words it. `%s` is stuffr's version.
pub(super) const APPLE_UNZIP_BANNER: &str = "UnZip 6.00 of 20 April 2009, by stuffr %s \
     (altered; original by Info-ZIP, with modifications by Apple Inc.).\n";
/// apple: unzip.c:575, the rest of Apple's `UnzipUsageLine1`.
pub(super) const APPLE_REPORT_BUGS: &str = "Please report bugs to Apple.\n\n";
/// ubuntu: 02-this-is-debian-unzip.patch (`UnZip 6.00 of 20 April 2009, by
/// Debian. Original by Info-ZIP.`), as R2 words it.
pub(super) const UBUNTU_UNZIP_BANNER: &str = "UnZip 6.00 of 20 April 2009, by stuffr %s \
     (altered; Debian's build, original by Info-ZIP).\n";
/// unzip.c:ZipInfoUsageLine1's first line (`ZipInfo 3.00 of 20 April 2009,
/// by Greg Roelofs and the Info-ZIP group.`, both builds), after R2's
/// pattern for Apple's build.
pub(super) const APPLE_ZIPINFO_BANNER: &str = "ZipInfo 3.00 of 20 April 2009, by stuffr %s \
     (altered; original by Greg Roelofs and the Info-ZIP group, with modifications by \
     Apple Inc.).\n";
/// The same line after R2's pattern for Ubuntu's build.
pub(super) const UBUNTU_ZIPINFO_BANNER: &str = "ZipInfo 3.00 of 20 April 2009, by stuffr %s \
     (altered; Debian's build, original by Greg Roelofs and the Info-ZIP group).\n";
/// funzip.c:main's first usage line (`fUnZip (filter UnZip), version 3.95 of
/// 20 January 2009`, both builds), after R2's pattern for Apple's build.
pub(super) const APPLE_FUNZIP_BANNER: &str = "fUnZip (filter UnZip), version 3.95 of \
     20 January 2009, by stuffr %s (altered; original by Info-ZIP, with modifications by \
     Apple Inc.).\n";
/// The same line after R2's pattern for Ubuntu's build.
pub(super) const UBUNTU_FUNZIP_BANNER: &str = "fUnZip (filter UnZip), version 3.95 of \
     20 January 2009, by stuffr %s (altered; Debian's build, original by Info-ZIP).\n";

// ---- unzip.c: unzip() and uz_opts() ----

/// unzip.c:CmdLineParamTooLong. `%d` is the argument's index (1 is the first
/// after the program name, environment arguments included).
pub(super) const CMD_LINE_PARAM_TOO_LONG: &str =
    "error:  command line parameter #%d exceeds internal size limit\n";
/// unzip.c:NotExtracting.
pub(super) const NOT_EXTRACTING: &str = "caution:  not extracting; -d ignored\n";
/// unzip.c:MustGiveExdir.
pub(super) const MUST_GIVE_EXDIR: &str =
    "error:  must specify directory to which to extract with -d option\n";
/// unzip.c:OnlyOneExdir.
pub(super) const ONLY_ONE_EXDIR: &str =
    "error:  -d option used more than once (only one exdir allowed)\n";
/// unzip.c:MustGivePasswd.
pub(super) const MUST_GIVE_PASSWD: &str = "error:  must give decryption password with -P option\n";
/// unzip.c:Zfirst.
pub(super) const Z_FIRST: &str =
    "error:  -Z must be first option for ZipInfo mode (check UNZIP variable?)\n";
/// unzip.c:InvalidOptionsMsg.
pub(super) const INVALID_OPTIONS: &str =
    "error:  -fn or any combination of -c, -l, -p, -t, -u and -v options invalid\n";
/// unzip.c:IgnoreOOptionMsg.
pub(super) const IGNORE_O_OPTION: &str = "caution:  both -n and -o specified; ignoring -o\n";

// ---- unzip.c: usage(), UnZip mode ----

/// unzip.c:UnzipUsageLine2 with `ZIPINFO_MODE_OPTION` (`[-Z] `) and
/// `ZipInfoMode`.
pub(super) const UNZIP_USAGE_LINE2: &str = concat!(
    "Usage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]\n",
    "  Default action is to extract files in list, except those in xlist, to exdir;\n",
    "  file[.zip] may be a wildcard.  -Z => ZipInfo mode (\"unzip -Z\" for usage).\n",
);
/// unzip.c:UnzipUsageLine3 with `local1` (`TIMESTAMP`: `  -T  timestamp
/// archive to latest`).
pub(super) const UNZIP_USAGE_LINE3: &str = concat!(
    "\n",
    "  -p  extract files to pipe, no messages     -l  list files (short format)\n",
    "  -f  freshen existing files, create none    -t  test compressed archive data\n",
    "  -u  update files, create if necessary      -z  display archive comment only\n",
    "  -v  list verbosely/show version info       -T  timestamp archive to latest\n",
    "  -x  exclude files that follow (in xlist)   -d  extract files into exdir\n",
);
/// unzip.c:UnzipUsageLine4, its lines before the `-U` line.
pub(super) const UNZIP_USAGE_LINE4_HEAD: &str = concat!(
    "modifiers:\n",
    "  -n  never overwrite existing files         -q  quiet mode (-qq => quieter)\n",
    "  -o  overwrite files WITHOUT prompting      -a  auto-convert any text files\n",
    "  -j  junk paths (do not make directories)   -aa treat ALL files as text\n",
);
/// unzip.c:UnzipUsageLine4's `-U` line, in the `UNICODE_SUPPORT` build only
/// (ubuntu: -DUNICODE_SUPPORT).
pub(super) const UNZIP_USAGE_LINE4_UNICODE: &str =
    "  -U  use escapes for all non-ASCII Unicode  -UU ignore any Unicode fields\n";
/// unzip.c:UnzipUsageLine4's last lines, ` %-42s` filled with `local2`
/// (`ATH_BEO_UNX`: ` -X  restore UID/GID info`) and `%s` with `local3`
/// (`MORE`: the `-K`/`-M` line).
pub(super) const UNZIP_USAGE_LINE4_TAIL: &str = concat!(
    "  -C  match filenames case-insensitively     -L  make (some) names lowercase\n",
    "  -X  restore UID/GID info                   -V  retain VMS version numbers\n",
    "  -K  keep setuid/setgid/tacky permissions   -M  pipe through \"more\" pager\n",
);
/// ubuntu: 20-unzip60-alt-iconv-utf8.patch, the end of its Unix
/// `UnzipUsageLine4`.
pub(super) const UNZIP_USAGE_LINE4_ICONV: &str = concat!(
    "  -O CHARSET  specify a character encoding for DOS, Windows and OS/2 archives\n",
    "  -I CHARSET  specify a character encoding for UNIX and other archives\n",
    "\n",
);
/// unzip.c:UnzipUsageLine5 with `Example2` and `Example3` (`ReadMe`, which
/// fills `%-6s` exactly).
pub(super) const UNZIP_USAGE_LINE5: &str = concat!(
    "See \"unzip -hh\" or unzip.txt for more help.  Examples:\n",
    "  unzip data1 -x joe   => extract all files except joe from zipfile data1.zip\n",
    "  unzip -p foo | more  => send contents of foo.zip via pipe into program more\n",
    "  unzip -fo foo ReadMe => quietly replace existing ReadMe if archive file newer\n",
);

// ---- unzip.c: usage(), ZipInfo mode ----

/// unzip.c:ZipInfoUsageLine1 after its banner line, with `ZipInfoExample`
/// and `QUOTS` (`""`).
pub(super) const ZIPINFO_USAGE_LINE1: &str = concat!(
    "\n",
    "List name, date/time, attribute, size, compression method, etc., about files\n",
    "in list (excluding those in xlist) contained in the specified .zip archive(s).\n",
    "\"file[.zip]\" may be a wildcard name containing *, ?, [] (e.g., \"[a-j]*.zip\").\n",
    "\n",
    "   usage:  zipinfo [-12smlvChMtTz] file[.zip] [list...] [-x xlist...]\n",
    "      or:  unzip -Z [-12smlvChMtTz] file[.zip] [list...] [-x xlist...]\n",
);
/// unzip.c:ZipInfoUsageLine2.
pub(super) const ZIPINFO_USAGE_LINE2: &str = concat!(
    "\n",
    "main listing-format options:             -s  short Unix \"ls -l\" format (def.)\n",
    "  -1  filenames ONLY, one per line       -m  medium Unix \"ls -l\" format\n",
    "  -2  just filenames but allow -h/-t/-z  -l  long Unix \"ls -l\" format\n",
    "                                         -v  verbose, multi-page format\n",
);
/// unzip.c:ZipInfoUsageLine3 with `ZipInfoUsageLine4` (`MORE`: the `-M`
/// part).
pub(super) const ZIPINFO_USAGE_LINE3: &str = concat!(
    "miscellaneous options:\n",
    "  -h  print header line       -t  print totals for listed files or for all\n",
    "  -z  print zipfile comment   -T  print file times in sortable decimal format\n",
    "  -C  be case-insensitive     -M  page output through built-in \"more\"\n",
    "  -x  exclude filenames that follow from listing\n",
);
/// ubuntu: 20-unzip60-alt-iconv-utf8.patch, the end of its Unix
/// `ZipInfoUsageLine3`.
pub(super) const ZIPINFO_USAGE_ICONV: &str = concat!(
    "  -O CHARSET  specify a character encoding for DOS, Windows and OS/2 archives\n",
    "  -I CHARSET  specify a character encoding for UNIX and other archives\n",
);

// ---- unzip.c: show_version_info() ----

/// unzip.c:UnzipUsageLine2v.
pub(super) const UNZIP_USAGE_LINE2V: &str = concat!(
    "Latest sources and executables are at ftp://ftp.info-zip.org/pub/infozip/ ;\n",
    "see ftp://ftp.info-zip.org/pub/infozip/UnZip.html for other sites.\n",
    "\n",
);
/// unix/unix.c:version()'s line of Apple's build, as its `/usr/bin/unzip -v`
/// prints it (it names the compiler and date of that build; R11 compares
/// the whole `-v` with the recorded build's). probe: `/usr/bin/unzip -v`
/// (macOS, 2026-10-20).
pub(super) const APPLE_COMPILED_WITH: &str = "Compiled with gcc Apple LLVM 21.0.0 \
     (clang-2100.3.31.1) [+internal-os] for Unix Mac OS X on Aug  8 2026.\n\n";
/// unix/unix.c:version()'s line of Ubuntu's build (13-remove-build-date.patch
/// drops the date). probe: `unzip -v` (ubuntu:24.04, unzip 6.0-28ubuntu4.1).
pub(super) const UBUNTU_COMPILED_WITH: &str = "Compiled with gcc 13.2.0 for Unix (Linux ELF).\n\n";
/// unzip.c:CompileOptions.
pub(super) const COMPILE_OPTIONS: &str = "UnZip special compilation options:\n";
/// unzip.c:CompileOptFormat.
pub(super) const COMPILE_OPT_FORMAT: &str = "        %s\n";
/// unzip.c:AcornFtypeNFS (ubuntu: -DACORN_FTYPE_NFS).
pub(super) const OPT_ACORN_FTYPE_NFS: &str = "ACORN_FTYPE_NFS";
/// unzip.c:Copyright_Clean.
pub(super) const OPT_COPYRIGHT_CLEAN: &str =
    "COPYRIGHT_CLEAN (PKZIP 0.9x unreducing method not supported)";
/// unzip.c:SetDirAttrib.
pub(super) const OPT_SET_DIR_ATTRIB: &str = "SET_DIR_ATTRIB";
/// unzip.c:SymLinkSupport.
pub(super) const OPT_SYMLINKS: &str =
    "SYMLINKS (symbolic links supported, if RTL and file system permit)";
/// unzip.c:TimeStamp.
pub(super) const OPT_TIMESTAMP: &str = "TIMESTAMP";
/// unzip.c:UnixBackup.
pub(super) const OPT_UNIXBACKUP: &str = "UNIXBACKUP";
/// unzip.c:Use_EF_UT_time.
pub(super) const OPT_USE_EF_UT_TIME: &str = "USE_EF_UT_TIME";
/// unzip.c:Use_Unshrink.
pub(super) const OPT_USE_UNSHRINK: &str =
    "USE_UNSHRINK (PKZIP/Zip 1.x unshrinking method supported)";
/// unzip.c:Use_Deflate64.
pub(super) const OPT_USE_DEFLATE64: &str = "USE_DEFLATE64 (PKZIP 4.x Deflate64(tm) supported)";
/// unzip.c:Use_Unicode (`UTF8_MAYBE_NATIVE` and `UNICODE_WCHAR`; ubuntu:
/// -DUNICODE_SUPPORT). `%s` is `SysChUTF8` or `SysChOther`.
pub(super) const OPT_USE_UNICODE: &str =
    "UNICODE_SUPPORT [wide-chars, char coding: %s] (handle UTF-8 paths)";
/// unzip.c:SysChUTF8.
pub(super) const SYS_CH_UTF8: &str = "UTF-8";
/// unzip.c:SysChOther.
pub(super) const SYS_CH_OTHER: &str = "other";
/// unzip.c:Use_LFS.
pub(super) const OPT_USE_LFS: &str = "LARGE_FILE_SUPPORT (large files over 2 GiB supported)";
/// unzip.c:Use_Zip64.
pub(super) const OPT_USE_ZIP64: &str =
    "ZIP64_SUPPORT (archives using Zip64 for large files supported)";
/// unzip.c:UseBZip2 with `BZ2_bzlibVersion()` (ubuntu: -DUSE_BZIP2). probe:
/// `unzip -v` (ubuntu:24.04): the library is `1.0.8, 13-Jul-2019`.
pub(super) const OPT_USE_BZIP2: &str =
    "USE_BZIP2 (PKZIP 4.6+, using bzip2 lib version 1.0.8, 13-Jul-2019)";
/// unzip.c:VmsTextConv.
pub(super) const OPT_VMS_TEXT_CONV: &str = "VMS_TEXT_CONV";
/// unzip.c:WildStopAtDir (ubuntu: -DWILD_STOP_AT_DIR).
pub(super) const OPT_WILD_STOP_AT_DIR: &str = "WILD_STOP_AT_DIR";
/// unzip.c:Decryption with `CR_MAJORVER`, `CR_MINORVER`, `CR_BETA_VER` and
/// `CryptDate` (crypt.h: 2, 11, `""`, `05 Jan 2007`).
pub(super) const DECRYPTION: &str = "        [decryption, version 2.11 of 05 Jan 2007]\n";
/// unzip.c:EnvOptions.
pub(super) const ENV_OPTIONS: &str = "\nUnZip and ZipInfo environment options:\n";
/// unzip.c:None.
pub(super) const NONE: &str = "[none]";

// ---- unzip.c: help_extended() ----

/// unzip.c:help_extended()'s `text[]`, each element printed with `%s\n`.
pub(super) const HELP_EXTENDED: &[&str] = &[
    "",
    "Extended Help for UnZip",
    "",
    "See the UnZip Manual for more detailed help",
    "",
    "",
    "UnZip lists and extracts files in zip archives.  The default action is to",
    "extract zipfile entries to the current directory, creating directories as",
    "needed.  With appropriate options, UnZip lists the contents of archives",
    "instead.",
    "",
    "Basic unzip command line:",
    "  unzip [-Z] options archive[.zip] [file ...] [-x xfile ...] [-d exdir]",
    "",
    "Some examples:",
    "  unzip -l foo.zip        - list files in short format in archive foo.zip",
    "",
    "  unzip -t foo            - test the files in archive foo",
    "",
    "  unzip -Z foo            - list files using more detailed zipinfo format",
    "",
    "  unzip foo               - unzip the contents of foo in current dir",
    "",
    "  unzip -a foo            - unzip foo and convert text files to local OS",
    "",
    "If unzip is run in zipinfo mode, a more detailed list of archive contents",
    "is provided.  The -Z option sets zipinfo mode and changes the available",
    "options.",
    "",
    "Basic zipinfo command line:",
    "  zipinfo options archive[.zip] [file ...] [-x xfile ...]",
    "  unzip -Z options archive[.zip] [file ...] [-x xfile ...]",
    "",
    "Below, Mac OS refers to Mac OS before Mac OS X.  Mac OS X is a Unix based",
    "port and is referred to as Unix Apple.",
    "",
    "",
    "unzip options:",
    "  -Z   Switch to zipinfo mode.  Must be first option.",
    "  -hh  Display extended help.",
    "  -A   [OS/2, Unix DLL] Print extended help for DLL.",
    "  -c   Extract files to stdout/screen.  As -p but include names.  Also,",
    "         -a allowed and EBCDIC conversions done if needed.",
    "  -f   Freshen by extracting only if older file on disk.",
    "  -l   List files using short form.",
    "  -p   Extract files to pipe (stdout).  Only file data is output and all",
    "         files extracted in binary mode (as stored).",
    "  -t   Test archive files.",
    "  -T   Set timestamp on archive(s) to that of newest file.  Similar to",
    "       zip -o but faster.",
    "  -u   Update existing older files on disk as -f and extract new files.",
    "  -v   Use verbose list format.  If given alone as unzip -v show version",
    "         information.  Also can be added to other list commands for more",
    "         verbose output.",
    "  -z   Display only archive comment.",
    "",
    "unzip modifiers:",
    "  -a   Convert text files to local OS format.  Convert line ends, EOF",
    "         marker, and from or to EBCDIC character set as needed.",
    "  -b   Treat all files as binary.  [Tandem] Force filecode 180 ('C').",
    "         [VMS] Autoconvert binary files.  -bb forces convert of all files.",
    "  -B   [UNIXBACKUP compile option enabled] Save a backup copy of each",
    "         overwritten file in foo~ or foo~99999 format.",
    "  -C   Use case-insensitive matching.",
    "  -D   Skip restoration of timestamps for extracted directories.  On VMS this",
    "         is on by default and -D essentially becames -DD.",
    "  -DD  Skip restoration of timestamps for all entries.",
    "  -E   [MacOS (not Unix Apple)]  Display contents of MacOS extra field during",
    "         restore.",
    "  -F   [Acorn] Suppress removal of NFS filetype extension.  [Non-Acorn if",
    "         ACORN_FTYPE_NFS] Translate filetype and append to name.",
    "  -i   [MacOS] Ignore filenames in MacOS extra field.  Instead, use name in",
    "         standard header.",
    "  -j   Junk paths and deposit all files in extraction directory.",
    "  -J   [BeOS] Junk file attributes.  [MacOS] Ignore MacOS specific info.",
    "  -K   [AtheOS, BeOS, Unix] Restore SUID/SGID/Tacky file attributes.",
    "  -L   Convert to lowercase any names from uppercase only file system.",
    "  -LL  Convert all files to lowercase.",
    "  -M   Pipe all output through internal pager similar to Unix more(1).",
    "  -n   Never overwrite existing files.  Skip extracting that file, no prompt.",
    "  -N   [Amiga] Extract file comments as Amiga filenotes.",
    "  -o   Overwrite existing files without prompting.  Useful with -f.  Use with",
    "         care.",
    "  -P p Use password p to decrypt files.  THIS IS INSECURE!  Some OS show",
    "         command line to other users.",
    "  -q   Perform operations quietly.  The more q (as in -qq) the quieter.",
    "  -s   [OS/2, NT, MS-DOS] Convert spaces in filenames to underscores.",
    "  -S   [VMS] Convert text files (-a, -aa) into Stream_LF format.",
    "  -U   [UNICODE enabled] Show non-local characters as #Uxxxx or #Lxxxxxx ASCII",
    "         text escapes where x is hex digit.  [Old] -U used to leave names",
    "         uppercase if created on MS-DOS, VMS, etc.  See -L.",
    "  -UU  [UNICODE enabled] Disable use of stored UTF-8 paths.  Note that UTF-8",
    "         paths stored as native local paths are still processed as Unicode.",
    "  -V   Retain VMS file version numbers.",
    "  -W   [Only if WILD_STOP_AT_DIR] Modify pattern matching so ? and * do not",
    "         match directory separator /, but ** does.  Allows matching at specific",
    "         directory levels.",
    "  -X   [VMS, Unix, OS/2, NT, Tandem] Restore UICs and ACL entries under VMS,",
    "         or UIDs/GIDs under Unix, or ACLs under certain network-enabled",
    "         versions of OS/2, or security ACLs under Windows NT.  Can require",
    "         user privileges.",
    "  -XX  [NT] Extract NT security ACLs after trying to enable additional",
    "         system privileges.",
    "  -Y   [VMS] Treat archived name endings of .nnn as VMS version numbers.",
    "  -$   [MS-DOS, OS/2, NT] Restore volume label if extraction medium is",
    "         removable.  -$$ allows fixed media (hard drives) to be labeled.",
    "  -/ e [Acorn] Use e as extension list.",
    "  -:   [All but Acorn, VM/CMS, MVS, Tandem] Allow extract archive members into",
    "         locations outside of current extraction root folder.  This allows",
    "         paths such as ../foo to be extracted above the current extraction",
    "         directory, which can be a security problem.",
    "  -^   [Unix] Allow control characters in names of extracted entries.  Usually",
    "         this is not a good thing and should be avoided.",
    "  -2   [VMS] Force unconditional conversion of names to ODS-compatible names.",
    "         Default is to exploit destination file system, preserving cases and",
    "         extended name characters on ODS5 and applying ODS2 filtering on ODS2.",
    "",
    "",
    "Wildcards:",
    "  Internally unzip supports the following wildcards:",
    // unzip.c prints `%%` through `"%s\n"`, so it reaches the output as is.
    "    ?       (or %% or #, depending on OS) matches any single character",
    "    *       matches any number of characters, including zero",
    "    [list]  matches char in list (regex), can do range [ac-f], all but [!bf]",
    "  If port supports [], must escape [ as [[]",
    "  For shells that expand wildcards, escape (\\* or \"*\") so unzip can recurse.",
    "",
    "Include and Exclude:",
    "  -i pattern pattern ...   include files that match a pattern",
    "  -x pattern pattern ...   exclude files that match a pattern",
    "  Patterns are paths with optional wildcards and match paths as stored in",
    "  archive.  Exclude and include lists end at next option or end of line.",
    "    unzip archive -x pattern pattern ...",
    "",
    "Multi-part (split) archives (archives created as a set of split files):",
    "  Currently split archives are not readable by unzip.  A workaround is",
    "  to use zip to convert the split archive to a single-file archive and",
    "  use unzip on that.  See the manual page for Zip 3.0 or later.",
    "",
    "Streaming (piping into unzip):",
    "  Currently unzip does not support streaming.  The funzip utility can be",
    "  used to process the first entry in a stream.",
    "    cat archive | funzip",
    "",
    "Testing archives:",
    "  -t        test contents of archive",
    "  This can be modified using -q for quieter operation, and -qq for even",
    "  quieter operation.",
    "",
    "Unicode:",
    "  If compiled with Unicode support, unzip automatically handles archives",
    "  with Unicode entries.  Currently Unicode on Win32 systems is limited.",
    "  Characters not in the current character set are shown as ASCII escapes",
    "  in the form #Uxxxx where the Unicode character number fits in 16 bits,",
    "  or #Lxxxxxx where it doesn't, where x is the ASCII character for a hex",
    "  digit.",
    "",
    "",
    "zipinfo options (these are used in zipinfo mode (unzip -Z ...)):",
    "  -1  List names only, one per line.  No headers/trailers.  Good for scripts.",
    "  -2  List names only as -1, but include headers, trailers, and comments.",
    "  -s  List archive entries in short Unix ls -l format.  Default list format.",
    "  -m  List in long Unix ls -l format.  As -s, but includes compression %.",
    "  -l  List in long Unix ls -l format.  As -m, but compression in bytes.",
    "  -v  List zipfile information in verbose, multi-page format.",
    "  -h  List header line.  Includes archive name, actual size, total files.",
    "  -M  Pipe all output through internal pager similar to Unix more(1) command.",
    "  -t  List totals for files listed or for all files.  Includes uncompressed",
    "        and compressed sizes, and compression factors.",
    "  -T  Print file dates and times in a sortable decimal format (yymmdd.hhmmss)",
    "        Default date and time format is a more human-readable version.",
    "  -U  [UNICODE] If entry has a UTF-8 Unicode path, display any characters",
    "        not in current character set as text #Uxxxx and #Lxxxxxx escapes",
    "        representing the Unicode character number of the character in hex.",
    "  -UU [UNICODE]  Disable use of any UTF-8 path information.",
    "  -z  Include archive comment if any in listing.",
    "",
    "",
    "funzip stream extractor:",
    "  funzip extracts the first member in an archive to stdout.  Typically",
    "  used to unzip the first member of a stream or pipe.  If a file argument",
    "  is given, read from that file instead of stdin.",
    "",
    "funzip command line:",
    "  funzip [-password] [input[.zip|.gz]]",
    "",
    "",
    "unzipsfx self extractor:",
    "  Self-extracting archives made with unzipsfx are no more (or less)",
    "  portable across different operating systems than unzip executables.",
    "  In general, a self-extracting archive made on a particular Unix system,",
    "  for example, will only self-extract under the same flavor of Unix.",
    "  Regular unzip may still be used to extract embedded archive however.",
    "",
    "unzipsfx command line:",
    "  <unzipsfx+archive_filename>  [-options] [file(s) ... [-x xfile(s) ...]]",
    "",
    "unzipsfx options:",
    "  -c, -p - Output to pipe.  (See above for unzip.)",
    "  -f, -u - Freshen and Update, as for unzip.",
    "  -t     - Test embedded archive.  (Can be used to list contents.)",
    "  -z     - Print archive comment.  (See unzip above.)",
    "",
    "unzipsfx modifiers:",
    "  Most unzip modifiers are supported.  These include",
    "  -a     - Convert text files.",
    "  -n     - Never overwrite.",
    "  -o     - Overwrite without prompting.",
    "  -q     - Quiet operation.",
    "  -C     - Match names case-insensitively.",
    "  -j     - Junk paths.",
    "  -V     - Keep version numbers.",
    "  -s     - Convert spaces to underscores.",
    "  -$     - Restore volume label.",
    "",
    "If unzipsfx compiled with SFX_EXDIR defined, -d option also available:",
    "  -d exd - Extract to directory exd.",
    "By default, all files extracted to current directory.  This option",
    "forces extraction to specified directory.",
    "",
    "See unzipsfx manual page for more information.",
    "",
];

// ---- funzip.c: main() ----

/// funzip.c:main's usage after its banner line, with `s` (`CRYPT`:
/// ` [-password]`).
pub(super) const FUNZIP_USAGE: &str = concat!(
    "usage: ... | funzip [-password] | ...\n",
    "       ... | funzip [-password] > outfile\n",
    "       funzip [-password] infile.zip > outfile\n",
    "       funzip [-password] infile.gz > outfile\n",
    "Extracts to stdout the gzip file or first zip entry of stdin or the given file.\n",
);

// ---- stuffr's own ----

/// stuffr's own: the flavour variable holds neither name (exit 1). `%s` is
/// the program name, then the value.
pub(super) const FLAVOR_REFUSED: &str =
    "%s: STUFFR_UNZIP_FLAVOR must be apple or ubuntu, not '%s'\n";
/// stuffr's own, until Tasks 8–11 build archive processing: what a run
/// that parsed its command line says instead of opening the archive (exit
/// `PK_BADERR`). `%s` is `unzip` or `zipinfo`.
pub(super) const NOT_BUILT_YET: &str =
    "%s:  archive processing is not implemented in this build yet (stuffr)\n";
/// stuffr's own, until Task 12 builds funzip's decoder (exit 3, funzip.c's
/// `err()` code for a bad input).
pub(super) const FUNZIP_NOT_BUILT_YET: &str =
    "funzip error: decoding is not implemented in this build yet (stuffr)\n";
