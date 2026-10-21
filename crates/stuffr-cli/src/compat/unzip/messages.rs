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

/// funzip.c:err, every error: `Info(slide, 1, ((char *)slide, "funzip
/// error: %s\n", m))`. `%s` is one of the `FZ_*` texts below.
pub(super) const FUNZIP_ERROR: &str = "funzip error: %s\n";
/// funzip.c:main, `err(2, ...)`: the input file cannot be opened.
pub(super) const FZ_NO_INPUT_FILE: &str = "cannot find input file";
/// funzip.c:main, `err(2, ...)`: `fdopen(0, FOPR)` failed.
pub(super) const FZ_NO_STDIN: &str = "cannot find stdin";
/// funzip.c:main, `err(2, ...)`: `fdopen(1, FOPW)` failed.
pub(super) const FZ_NO_STDOUT: &str = "cannot write to stdout";
/// funzip.c:main, `err(3, ...)`: a short local header, or no `PK\3\4`.
pub(super) const FZ_INVALID_ZIPFILE: &str = "invalid zipfile";
/// funzip.c:main, `err(3, ...)`: a method other than stored, deflated
/// and deflate64.
pub(super) const FZ_NOT_DEFLATED_OR_STORED: &str =
    "first entry not deflated or stored--cannot unpack";
/// funzip.c:main, `err(3, ...)`: a gzip header shorter than 8 bytes.
pub(super) const FZ_INVALID_GZIP: &str = "invalid gzip file";
/// funzip.c:main, `err(3, ...)`: a gzip method other than 8 and 9.
pub(super) const FZ_GZIP_NOT_DEFLATED: &str = "gzip file not deflated";
/// funzip.c:main, `err(3, ...)`: gzip flag bit 1 (`GZPMUL`, today's
/// FHCRC).
pub(super) const FZ_MULTI_PART: &str = "cannot handle multi-part gzip files";
/// funzip.c:main, `err(3, ...)`: neither magic.
pub(super) const FZ_NOT_ZIP_OR_GZIP: &str = "input not a zip or gzip file";
/// funzip.c:main, `err(1, ...)`: `malloc()` failed, or inflate's 3.
pub(super) const FZ_OUT_OF_MEMORY: &str = "out of memory";
/// funzip.c:main, `err(1, ...)`: `getp()` gave `NULL`.
pub(super) const FZ_NO_TTY: &str = "no tty to prompt for password";
/// funzip.c:main: `getp()`'s prompt.
pub(super) const FZ_ENTER_PASSWORD: &str = "Enter password: ";
/// funzip.c:main, `err(3, ...)`: the header's check byte differs.
pub(super) const FZ_INCORRECT_PASSWORD: &str = "incorrect password for first entry";
/// funzip.c:main, `err(4, ...)`: inflate's 1 or 2.
pub(super) const FZ_FORMAT_VIOLATED: &str = "invalid compressed data--format violated";
/// funzip.c:main: a stored entry's sizes disagree, `"len %ld, siz %ld\n"`
/// (the caller formats both numbers).
pub(super) const FZ_LEN_SIZ: &str = "len %d, siz %d\n";
/// funzip.c:main, `err(4, ...)`: after [`FZ_LEN_SIZ`].
pub(super) const FZ_LENGTH_MISMATCH: &str = "invalid compressed data--length mismatch";
/// funzip.c:flush and main, `err(9, ...)`: `fwrite()` failed (not `EPIPE`).
pub(super) const FZ_OUT_OF_SPACE: &str = "out of space on stdout";
/// funzip.c:main, `err(3, ...)`: the gzip trailer is short.
pub(super) const FZ_GZIP_ENDED: &str = "gzip file ended prematurely";
/// funzip.c:main, `err(3, ...)`: the data descriptor is short.
pub(super) const FZ_ZIP_ENDED: &str = "zipfile ended prematurely";
/// funzip.c:main, `err(4, ...)`: the CRC differs.
pub(super) const FZ_CRC_ERROR: &str = "invalid compressed data--crc error";
/// funzip.c:main, `err(4, ...)`: the length differs.
pub(super) const FZ_LENGTH_ERROR: &str = "invalid compressed data--length error";
/// funzip.c:main: another local header follows the first entry.
pub(super) const FZ_MORE_THAN_ONE: &str =
    "funzip warning: zipfile has more than one entry--rest ignored\n";

// ---- process.c (Task 8) ----

/// unzip.c's `Zipnfo` (consts.h): the program's name in zipinfo mode.
pub(super) const ZIPNFO: &str = "zipinfo";
/// process.c's `Unzip`.
pub(super) const UNZIP: &str = "unzip";
/// unzpriv.h's `ZSUFX`, tried after a single archive name failed.
pub(super) const ZSUFX: &str = ".zip";
/// unzpriv.h's `ALT_ZSUFX` (unix only), tried after `ZSUFX`.
pub(super) const ALT_ZSUFX: &str = ".ZIP";
/// process.c:FilesProcessOK. `%d` is the count, `%s` ` was` or `s were`.
pub(super) const FILES_PROCESS_OK: &str = "%d archive%s successfully processed.\n";
/// process.c:ArchiveWarning.
pub(super) const ARCHIVE_WARNING: &str = "%d archive%s had warnings but no fatal errors.\n";
/// process.c:ArchiveFatalError.
pub(super) const ARCHIVE_FATAL_ERROR: &str = "%d archive%s had fatal errors.\n";
/// process.c:FileHadNoZipfileDir.
pub(super) const FILE_HAD_NO_ZIPFILE_DIR: &str = "%d file%s had no zipfile directory.\n";
/// process.c:ZipfileWasDir.
pub(super) const ZIPFILE_WAS_DIR: &str = "1 \"zipfile\" was a directory.\n";
/// process.c:ManyZipfilesWereDir.
pub(super) const MANY_ZIPFILES_WERE_DIR: &str = "%d \"zipfiles\" were directories.\n";
/// process.c:NoZipfileFound.
pub(super) const NO_ZIPFILE_FOUND: &str = "No zipfiles found.\n";
/// process.c:CannotFindZipfileDirMsg (unix): program, operand, `"  "` in
/// zipinfo mode, operand, the last name tried.
pub(super) const CANNOT_FIND_ZIPFILE_DIR_MSG: &str = "%s:  cannot find zipfile directory in one of %s or\n        %s%s.zip, and cannot find %s, period.\n";
/// process.c:CannotFindEitherZipfile (unix).
pub(super) const CANNOT_FIND_EITHER_ZIPFILE: &str = "%s:  cannot find or open %s, %s.zip or %s.\n";
/// process.c:MaybeExe.
pub(super) const MAYBE_EXE: &str = "note:  %s may be a plain executable, not an archive\n";
/// process.c:CentDirNotInZipMsg (zipinfo mode). `%s` the archive, then
/// the two disk numbers (`%lu`, formatted by the caller).
pub(super) const CENT_DIR_NOT_IN_ZIP_MSG: &str = "\n   [%s]:\n     Zipfile is disk %s of a multi-disk archive, and this is not the disk on\n     which the central zipfile directory begins (disk %s).\n";
/// process.c:EndCentDirBogus (zipinfo mode).
pub(super) const END_CENT_DIR_BOGUS: &str = "\nwarning [%s]:  end-of-central-directory record claims this\n  is disk %s but that the central directory starts on disk %s; this is a\n  contradiction.  Attempting to process anyway.\n";
/// process.c:MaybePakBug (no `NO_MULTIPART`).
pub(super) const MAYBE_PAK_BUG: &str = "warning [%s]:  zipfile claims to be last disk of a multi-part archive;\n  attempting to process anyway, assuming all parts have been concatenated\n  together in order.  Expect \"errors\" and warnings...true multi-part support\n  doesn't exist yet (coming soon).\n";
/// process.c:ExtraBytesAtStart. `%s` the archive, the count, `""`/`"s"`.
pub(super) const EXTRA_BYTES_AT_START: &str = "warning [%s]:  %s extra byte%s at beginning or within zipfile\n  (attempting to process anyway)\n";
/// process.c:LogInitline.
pub(super) const LOG_INITLINE: &str = "Archive:  %s\n";
/// process.c:MissingBytes. `%s` the archive, the count (`FmZofft`).
pub(super) const MISSING_BYTES: &str =
    "error [%s]:  missing %s bytes in zipfile\n  (attempting to process anyway)\n";
/// process.c:NullCentDirOffset.
pub(super) const NULL_CENT_DIR_OFFSET: &str =
    "error [%s]:  NULL central directory offset\n  (attempting to process anyway)\n";
/// process.c:ZipfileEmpty.
pub(super) const ZIPFILE_EMPTY: &str = "warning [%s]:  zipfile is empty\n";
/// process.c:do_seekable's zipinfo-mode empty archive (a literal there).
/// `%s` is `"\n  "` for zipinfo's verbose listing, else empty.
pub(super) const EMPTY_ZIPFILE_ZI: &str = "%sEmpty zipfile.\n";
/// process.c:CentDirStartNotFound. `%s` the archive, then `ReportMsg`.
pub(super) const CENT_DIR_START_NOT_FOUND: &str =
    "error [%s]:  start of central directory not found;\n  zipfile corrupt.\n%s";
/// process.c:Cent64EndSigSearchErr.
pub(super) const CENT64_END_SIG_SEARCH_ERR: &str = "fatal error: read failure while seeking for End-of-centdir-64 signature.\n  This zipfile is corrupt.\n";
/// process.c:Cent64EndSigSearchOff.
pub(super) const CENT64_END_SIG_SEARCH_OFF: &str = "error: End-of-centdir-64 signature not where expected (prepended bytes?)\n  (attempting to process anyway)\n";
/// process.c:CentDirTooLong. `%s` the archive, the count.
pub(super) const CENT_DIR_TOO_LONG: &str = "error [%s]:  reported length of central directory is\n  %s bytes too long (Atari STZip zipfile?  J.H.Holm ZIPSPLIT 1.1\n  zipfile?).  Compensating...\n";
/// process.c:CentDirEndSigNotFound (not `SFX`).
pub(super) const CENT_DIR_END_SIG_NOT_FOUND: &str = "  End-of-central-directory signature not found.  Either this file is not\n  a zipfile, or it constitutes one disk of a multi-part archive.  In the\n  latter case the central directory and zipfile comment will be found on\n  the last disk(s) of this archive.\n";
/// process.c's `"[%s]\n"` (find_ecrec(), find_ecrec64()): the archive's
/// name before an end-record failure under `-q` or in zipinfo mode.
pub(super) const BRACKETED_NAME: &str = "[%s]\n";
/// process.c:ZipTimeStampFailed (`TIMESTAMP`).
pub(super) const ZIP_TIME_STAMP_FAILED: &str = "warning:  cannot set time for %s\n";
/// process.c:ZipTimeStampSuccess.
pub(super) const ZIP_TIME_STAMP_SUCCESS: &str = "Updated time stamp for %s.\n";
/// process.c:ZipfileCommTrunc1.
pub(super) const ZIPFILE_COMM_TRUNC1: &str = "\ncaution:  zipfile comment truncated\n";
/// process.c:NoZipfileComment (zipinfo's verbose listing).
pub(super) const NO_ZIPFILE_COMMENT: &str = "There is no zipfile comment.\n";
/// process.c:ZipfileCommentDesc. `%u` is the length (formatted by the
/// caller).
pub(super) const ZIPFILE_COMMENT_DESC: &str =
    "The zipfile comment is %s bytes long and contains the following text:\n";
/// process.c:ZipfileCommBegin.
pub(super) const ZIPFILE_COMM_BEGIN: &str =
    "======================== zipfile comment begins ==========================\n";
/// process.c:ZipfileCommEnd.
pub(super) const ZIPFILE_COMM_END: &str =
    "========================= zipfile comment ends ===========================\n";
/// process.c:ZipfileCommTrunc2.
pub(super) const ZIPFILE_COMM_TRUNC2: &str = "\n  The zipfile comment is truncated.\n";
/// consts.h:CentSigMsg. `%lu` is the entry's number (by the caller).
pub(super) const CENT_SIG_MSG: &str =
    "error:  expected central file header signature not found (file #%s).\n";
/// consts.h:EndSigMsg (printed with `"%s"`: apple: list.c:510).
pub(super) const END_SIG_MSG: &str =
    "\nnote:  didn't find end-of-central-dir signature at end of central dir.\n";
/// consts.h:SeekMsg. `%s` the archive, then `ReportMsg`.
pub(super) const SEEK_MSG: &str = "error [%s]:  attempt to seek before beginning of zipfile\n%s";
/// consts.h:ReportMsg (not `VMS`).
pub(super) const REPORT_MSG: &str = "  (please check that you have transferred or created the zipfile in the\n  appropriate BINARY mode and that you have compiled UnZip properly)\n";

// ---- fileio.c (Task 8) ----

/// fileio.c:CannotOpenZipfile. `%s` the archive, then `strerror(errno)`.
pub(super) const CANNOT_OPEN_ZIPFILE: &str = "error:  cannot open zipfile [ %s ]\n        %s\n";
/// fileio.c:ReadError.
pub(super) const READ_ERROR: &str = "error:  zipfile read error\n";
/// fileio.c:FilenameTooLongTrunc.
pub(super) const FILENAME_TOO_LONG_TRUNC: &str = "warning:  filename too long--truncating.\n";
/// fileio.c:UFilenameTooLongTrunc (ubuntu: -DUNICODE_SUPPORT, its text as
/// 28-cve-2022-0529-and-cve-2022-0530.patch has it).
pub(super) const UFILENAME_TOO_LONG_TRUNC: &str =
    "warning:  Converted Unicode filename too long--truncating.\n";
/// fileio.c:UFilenameCorrupt (ubuntu: -DUNICODE_SUPPORT,
/// 28-cve-2022-0529-and-cve-2022-0530.patch).
pub(super) const UFILENAME_CORRUPT: &str = "error: Unicode filename corrupt.\n";
/// process.c:UnicodeVersionError (ubuntu: -DUNICODE_SUPPORT).
pub(super) const UNICODE_VERSION_ERROR: &str = "\nwarning:  Unicode Path version > 1\n";
/// process.c:UnicodeMismatchError (ubuntu: -DUNICODE_SUPPORT).
pub(super) const UNICODE_MISMATCH_ERROR: &str = "\nwarning:  Unicode Path checksum invalid\n";
/// process.c:UFilenameTooLongTrunc (ubuntu: -DUNICODE_SUPPORT,
/// 28-cve-2022-0529-and-cve-2022-0530.patch): `wide_to_local_string()`'s
/// escape cut short.
pub(super) const UFILENAME_TOO_LONG_P1: &str = "warning:  filename too long (P1) -- truncating.\n";
/// fileio.c:do_string's `"[ %s ]\n"`: what is left of a truncated name.
pub(super) const TRUNCATED_NAME: &str = "[ %s ]\n";
/// fileio.c:ExtraFieldCorrupt (apple: fileio.c:183). `%04x` is the block
/// id, always `EF_PKSZ64` ([`EF_PKSZ64_HEX`]).
pub(super) const EXTRA_FIELD_CORRUPT: &str =
    "warning:  extra field (type: 0x%s) corrupt.  Continuing...\n";
/// `EF_PKSZ64` as `%04x` prints it.
pub(super) const EF_PKSZ64_HEX: &str = "0001";
/// ebcdic.h's `oem2iso_850[]`: code page 850's bytes 0x80..0xff as ISO
/// 8859-1 (fileio.c's `_OEM_INTERN` on unix).
pub(super) const OEM2ISO_850: [u8; 128] = [
    0xC7, 0xFC, 0xE9, 0xE2, 0xE4, 0xE0, 0xE5, 0xE7, // 80 - 87
    0xEA, 0xEB, 0xE8, 0xEF, 0xEE, 0xEC, 0xC4, 0xC5, // 88 - 8F
    0xC9, 0xE6, 0xC6, 0xF4, 0xF6, 0xF2, 0xFB, 0xF9, // 90 - 97
    0xFF, 0xD6, 0xDC, 0xF8, 0xA3, 0xD8, 0xD7, 0x83, // 98 - 9F
    0xE1, 0xED, 0xF3, 0xFA, 0xF1, 0xD1, 0xAA, 0xBA, // A0 - A7
    0xBF, 0xAE, 0xAC, 0xBD, 0xBC, 0xA1, 0xAB, 0xBB, // A8 - AF
    0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xC1, 0xC2, 0xC0, // B0 - B7
    0xA9, 0xA6, 0xA6, 0x2B, 0x2B, 0xA2, 0xA5, 0x2B, // B8 - BF
    0x2B, 0x2D, 0x2D, 0x2B, 0x2D, 0x2B, 0xE3, 0xC3, // C0 - C7
    0x2B, 0x2B, 0x2D, 0x2D, 0xA6, 0x2D, 0x2B, 0xA4, // C8 - CF
    0xF0, 0xD0, 0xCA, 0xCB, 0xC8, 0x69, 0xCD, 0xCE, // D0 - D7
    0xCF, 0x2B, 0x2B, 0xA6, 0x5F, 0xA6, 0xCC, 0xAF, // D8 - DF
    0xD3, 0xDF, 0xD4, 0xD2, 0xF5, 0xD5, 0xB5, 0xFE, // E0 - E7
    0xDE, 0xDA, 0xDB, 0xD9, 0xFD, 0xDD, 0xAF, 0xB4, // E8 - EF
    0xAD, 0xB1, 0x3D, 0xBE, 0xB6, 0xA7, 0xF7, 0xB8, // F0 - F7
    0xB0, 0xA8, 0xB7, 0xB9, 0xB3, 0xB2, 0xA6, 0xA0, // F8 - FF
];

// ---- list.c (Task 8) ----

/// list.c:CompFactor100.
pub(super) const COMP_FACTOR_100: &str = "100%";
/// list.c:list_files's `method[]`, by `find_compr_idx()`.
pub(super) const LIST_METHODS: [&str; 18] = [
    "Stored", "Shrunk", "Reduce1", "Reduce2", "Reduce3", "Reduce4", "Implode", "Token", "Defl:#",
    "Def64#", "ImplDCL", "BZip2", "LZMA", "Terse", "IBMLZ77", "WavPack", "PPMd", "Unk:###",
];
/// list.c:list_files's `dtype[]`: deflate's option letter by flag bits 1-2
/// (zi_short()'s too).
pub(super) const DTYPE: [u8; 4] = *b"NXFS";
/// unzpriv.h's `DATE_SEPCHAR`.
pub(super) const DATE_SEPCHAR: u8 = b'-';
/// list.c:HeadersS (no `OS2_EAS`).
pub(super) const HEADERS_S: &str = "  Length      Date    Time    Name";
/// list.c:HeadersS1.
pub(super) const HEADERS_S1: &str = "---------  ---------- -----   ----";
/// list.c:HeadersL.
pub(super) const HEADERS_L: &str = " Length   Method    Size  Cmpr    Date    Time   CRC-32   Name";
/// list.c:HeadersL1.
pub(super) const HEADERS_L1: &str =
    "--------  ------  ------- ---- ---------- ----- --------  ----";
/// list.c:CaseConversion: the heading under `-L`.
pub(super) const CASE_CONVERSION: &str = "%s (\"^\" ==> case\n%s   conversion)\n";
/// list.c:list_files's `"%s\n%s\n"`: the heading.
pub(super) const TWO_LINES: &str = "%s\n%s\n";

/// `%<w>llu` of a 64-bit size (`FmZofft(v, "w", "u")`).
fn zofft_u(v: u64, w: usize) -> String {
    format!("{v:>w$}")
}

/// list.c:LongHdrStats, `"%s  %-7s%s %4s %02u%c%02u%c%02u %02u:%02u %08lx %c"`:
/// the size (`%8llu`), method, compressed size (`%8llu`), ratio, date
/// (`fields` in print order: month, day, year, hour, minute under
/// `DF_MDY`), CRC and the case mark.
#[allow(clippy::too_many_arguments)]
pub(super) fn long_hdr_stats(
    ucsize: u64,
    methbuf: &[u8],
    csiz: u64,
    cfactorstr: &[u8],
    fields: [u64; 5],
    sep: u8,
    crc: u32,
    lc: u8,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(zofft_u(ucsize, 8).as_bytes());
    v.extend_from_slice(b"  ");
    v.extend_from_slice(methbuf);
    v.extend(std::iter::repeat_n(
        b' ',
        7usize.saturating_sub(methbuf.len()),
    ));
    v.extend_from_slice(zofft_u(csiz, 8).as_bytes());
    v.push(b' ');
    v.extend(std::iter::repeat_n(
        b' ',
        4usize.saturating_sub(cfactorstr.len()),
    ));
    v.extend_from_slice(cfactorstr);
    v.push(b' ');
    date_time(&mut v, fields, sep);
    v.extend_from_slice(format!(" {crc:08x} ").as_bytes());
    v.push(lc);
    v
}

/// `%02u%c%02u%c%02u %02u:%02u`.
fn date_time(v: &mut Vec<u8>, [a, b, c, hh, mm]: [u64; 5], sep: u8) {
    v.extend_from_slice(format!("{a:02}").as_bytes());
    v.push(sep);
    v.extend_from_slice(format!("{b:02}").as_bytes());
    v.push(sep);
    v.extend_from_slice(format!("{c:02} {hh:02}:{mm:02}").as_bytes());
}

/// list.c:ShortHdrStats (no `OS2_EAS`), `"%s  %02u%c%02u%c%02u %02u:%02u  %c"`:
/// the size (`%9llu`), date and the case mark.
pub(super) fn short_hdr_stats(ucsize: u64, fields: [u64; 5], sep: u8, lc: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(zofft_u(ucsize, 9).as_bytes());
    v.extend_from_slice(b"  ");
    date_time(&mut v, fields, sep);
    v.extend_from_slice(b"  ");
    v.push(lc);
    v
}

/// list.c:LongFileTrailer: the sizes (`%8llu`), the ratio (`%4s`), the
/// count (`%lu file%s`).
pub(super) fn long_file_trailer(
    ucsize: u64,
    csize: u64,
    cfactorstr: &[u8],
    members: u64,
) -> Vec<u8> {
    let mut v = b"--------          -------  ---                            -------\n".to_vec();
    v.extend_from_slice(zofft_u(ucsize, 8).as_bytes());
    v.extend_from_slice(b"         ");
    v.extend_from_slice(zofft_u(csize, 8).as_bytes());
    v.push(b' ');
    v.extend(std::iter::repeat_n(
        b' ',
        4usize.saturating_sub(cfactorstr.len()),
    ));
    v.extend_from_slice(cfactorstr);
    v.extend_from_slice(b"                            ");
    files(&mut v, members);
    v
}

/// list.c:ShortFileTrailer (no `OS2_EAS`): the size (`%9llu`), the count.
pub(super) fn short_file_trailer(ucsize: u64, members: u64) -> Vec<u8> {
    let mut v = b"---------                     -------\n".to_vec();
    v.extend_from_slice(zofft_u(ucsize, 9).as_bytes());
    v.extend_from_slice(b"                     ");
    files(&mut v, members);
    v
}

/// `%lu file%s\n`.
fn files(v: &mut Vec<u8>, members: u64) {
    v.extend_from_slice(members.to_string().as_bytes());
    v.extend_from_slice(if members == 1 {
        b" file\n"
    } else {
        b" files\n"
    });
}

// ---- consts.h: the not-matched cautions (zipinfo.c's, Task 9; extract.c's
// too) ----

/// consts.h:FilenameNotMatched. `%s` is the pattern.
pub(super) const FILENAME_NOT_MATCHED: &str = "caution: filename not matched:  %s\n";
/// consts.h:ExclFilenameNotMatched. `%s` is the pattern.
pub(super) const EXCL_FILENAME_NOT_MATCHED: &str = "caution: excluded filename not matched:  %s\n";

// ---- zipinfo.c (Task 9) ----
//
// Every `%s` below stands for the C's own conversion, which the caller
// applies and the doc names: `FmZofft(v, "11", NULL)` is `%11lld`,
// `FmZofft(v, NULL, "u")` `%llu`, `FmZofft(v, FZOFFT_HEX_DOT_WID, "X")`
// `%.16llX` (`LARGE_FILE_SUPPORT`'s `FZOFFT_HEX_WID_VALUE` is "16").

/// zipinfo.c:ZipInfHeader2: `%s` the archive's size (`%lld`), then the
/// entry count (`%llu`).
pub(super) const ZIP_INF_HEADER2: &str = "Zip file size: %s bytes, number of entries: %s\n";
/// zipinfo.c:EndCentDirRec.
pub(super) const END_CENT_DIR_REC: &str = "\nEnd-of-central-directory record:\n";
/// zipinfo.c:LineSeparators.
pub(super) const LINE_SEPARATORS: &str = "-------------------------------\n\n";
/// zipinfo.c:ZipFSizeVerbose: the size (`%11lld`, `%.16llX`).
pub(super) const ZIP_FSIZE_VERBOSE: &str = "  Zip archive file size:               %s (%sh)\n";
/// zipinfo.c:ActOffsetCentDir: the actual and the expected end record
/// offsets (`%11llu`, `%.16llX` each).
pub(super) const ACT_OFFSET_CENT_DIR: &str = "  Actual end-cent-dir record offset:   %s (%sh)\n  \
     Expected end-cent-dir record offset: %s (%sh)\n  (based on the length of the central \
     directory and its expected offset)\n\n";
/// zipinfo.c:SinglePartArchive1: the entry count (`%llu`), `entry` or
/// `entries`, the directory's size (`%llu`, `%.16llX`).
pub(super) const SINGLE_PART_ARCHIVE1: &str = "  This zipfile constitutes the sole disk of a \
     single-part archive; its\n  central directory contains %s %s.\n  The central directory \
     is %s (%sh) bytes long,\n";
/// zipinfo.c:SinglePartArchive2: the directory's offset (`%llu`,
/// `%.16llX`).
pub(super) const SINGLE_PART_ARCHIVE2: &str = "  and its (expected) offset in bytes from the \
     beginning of the zipfile\n  is %s (%sh).\n\n";
/// zipinfo.c:MultiPartArchive1: the disks (`%lu` each, plus one).
pub(super) const MULTI_PART_ARCHIVE1: &str = "  This zipfile constitutes disk %s of a \
     multi-part archive.  The central\n  directory starts on disk %s at an offset within that \
     archive part\n";
/// zipinfo.c:MultiPartArchive2: the directory's offset and size (`%llu`,
/// `%.16llX` each).
pub(super) const MULTI_PART_ARCHIVE2: &str = "  of %s (%sh) bytes.  The entire\n  central \
     directory is %s (%sh) bytes long.\n";
/// zipinfo.c:MultiPartArchive3: this disk's count (`%llu`), `is` or `are`,
/// the total (`%llu`), `entry` or `entries`.
pub(super) const MULTI_PART_ARCHIVE3: &str = "  %s of the archive entries %s contained within \
     this zipfile volume,\n  out of a total of %s %s.\n\n";
/// zi_end_central()'s count words.
pub(super) const ENTRY: &str = "entry";
pub(super) const ENTRIES: &str = "entries";
pub(super) const IS: &str = "is";
pub(super) const ARE: &str = "are";
/// zipinfo.c:CentralDirEntry: the entry's number (`%lu`).
pub(super) const CENTRAL_DIR_ENTRY: &str =
    "\nCentral directory entry #%s:\n---------------------------\n\n";
/// zipinfo.c:ZipfileStats: the count (`%lu`), `s` or nothing (`PlurSufx`,
/// `nullStr`), the sizes (`%llu` each), the sign, the ratio's percent and
/// tenth (`%d.%d`).
pub(super) const ZIPFILE_STATS: &str =
    "%s file%s, %s bytes uncompressed, %s bytes compressed:  %s%s.%s%%\n";
/// zipinfo.c:PlurSufx.
pub(super) const PLUR_SUFX: &str = "s";

/// zi_long()'s `os[NUM_HOSTS]`: the host names (`OS_FAT` .. `OS_AtheOS`),
/// by host number; `None` where the C has `NULL` (20..29).
pub(super) const OS_NAMES: [Option<&str>; 31] = [
    Some("MS-DOS, OS/2 or NT FAT"),
    Some("Amiga"),
    Some("VMS"),
    Some("Unix"),
    Some("VM/CMS"),
    Some("Atari ST"),
    Some("OS/2 or NT HPFS"),
    Some("Macintosh HFS"),
    Some("Z-System"),
    Some("CP/M"),
    Some("TOPS-20"),
    Some("NTFS"),
    Some("SMS/QDOS"),
    Some("Acorn RISC OS"),
    Some("Win32 VFAT"),
    Some("MVS"),
    Some("BeOS"),
    Some("Tandem NSK"),
    Some("Theos"),
    Some("Mac OS/X (Darwin)"),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some("AtheOS"),
];
/// What both references' `printf("%s", NULL)` prints (Apple's libc and
/// glibc alike): zi_long()'s host name for host numbers 20..29.
/// probe: `zipinfo -v` of an entry made by host 20.
pub(super) const PRINTF_NULL: &str = "(null)";

/// zi_long()'s `method[NUM_METHODS]` (`MthdNone` .. `MthdPPMd`), by
/// `find_compr_idx()`.
pub(super) const ZI_LONG_METHODS: [&str; 17] = [
    "none (stored)",
    "shrunk",
    "reduced (factor 1)",
    "reduced (factor 2)",
    "reduced (factor 3)",
    "reduced (factor 4)",
    "imploded",
    "tokenized",
    "deflated",
    "deflated (enhanced-64k)",
    "imploded (PK DCL)",
    "bzipped",
    "LZMA-ed",
    "tersed (IBM)",
    "LZ77-compressed (IBM)",
    "WavPacked",
    "PPMd-ed",
];
/// zi_long()'s `dtypelng[4]` (`DeflNorm` .. `DeflSFast`), by flag bits 1-2.
pub(super) const DTYPELNG: [&str; 4] = ["normal", "maximum", "fast", "superfast"];

/// zipinfo.c:ExtraBytesPreceding: the gap (`%lld`).
pub(super) const EXTRA_BYTES_PRECEDING: &str =
    "  There are an extra %s bytes preceding this file.\n\n";
/// zipinfo.c:UnknownNo: the number (`%d`).
pub(super) const UNKNOWN_NO: &str = "unknown (%s)";
/// zipinfo.c:LocalHeaderOffset (`ZIP64_SUPPORT`): the offset (`%llu`,
/// `%.16llX`).
pub(super) const LOCAL_HEADER_OFFSET: &str = "\n  offset of local header from start of \
     archive:   %s\n                                                  (%sh) bytes\n";
/// zipinfo.c:HostOS.
pub(super) const HOST_OS: &str = "  file system or operating system of origin:      %s\n";
/// zipinfo.c:EncodeSWVer: the version's two digits (`%u.%u`).
pub(super) const ENCODE_SW_VER: &str = "  version of encoding software:                   %s.%s\n";
/// zipinfo.c:MinOSCompReq.
pub(super) const MIN_OS_COMP_REQ: &str = "  minimum file system compatibility required:     %s\n";
/// zipinfo.c:MinSWVerReq (`%u.%u`).
pub(super) const MIN_SW_VER_REQ: &str = "  minimum software version required to extract:   %s.%s\n";
/// zipinfo.c:CompressMethod.
pub(super) const COMPRESS_METHOD: &str = "  compression method:                             %s\n";
/// zipinfo.c:SlideWindowSizeImplode (`%c`).
pub(super) const SLIDE_WINDOW_SIZE_IMPLODE: &str =
    "  size of sliding dictionary (implosion):         %sK\n";
/// zipinfo.c:ShannonFanoTrees (`%c`).
pub(super) const SHANNON_FANO_TREES: &str =
    "  number of Shannon-Fano trees (implosion):       %s\n";
/// zipinfo.c:CompressSubtype.
pub(super) const COMPRESS_SUBTYPE: &str = "  compression sub-type (deflation):               %s\n";
/// zipinfo.c:FileSecurity: `""` or `"not "`.
pub(super) const FILE_SECURITY: &str =
    "  file security status:                           %sencrypted\n";
/// zi_long()'s `"not "`.
pub(super) const NOT_: &str = "not ";
/// zipinfo.c:ExtendedLocalHdr.
pub(super) const EXTENDED_LOCAL_HDR: &str =
    "  extended local header:                          %s\n";
/// zi_long()'s `"yes"` and `"no"`.
pub(super) const YES: &str = "yes";
pub(super) const NO: &str = "no";
/// zipinfo.c:FileModDate.
pub(super) const FILE_MOD_DATE: &str = "  file last modified on (DOS date/time):          %s\n";
/// zipinfo.c:UT_FileModDate (`USE_EF_UT_TIME`): the time, `local` or `UTC`.
pub(super) const UT_FILE_MOD_DATE: &str =
    "  file last modified on (UT extra field modtime): %s %s\n";
/// zipinfo.c:LocalTime.
pub(super) const LOCAL_TIME: &str = "local";
/// zipinfo.c:GMTime.
pub(super) const GM_TIME: &str = "UTC";
/// zipinfo.c:CRC32Value (`%.8lx`).
pub(super) const CRC32_VALUE: &str = "  32-bit CRC value (hex):                         %s\n";
/// zipinfo.c:CompressedFileSize (`%llu`).
pub(super) const COMPRESSED_FILE_SIZE: &str =
    "  compressed size:                                %s bytes\n";
/// zipinfo.c:UncompressedFileSize (`%llu`).
pub(super) const UNCOMPRESSED_FILE_SIZE: &str =
    "  uncompressed size:                              %s bytes\n";
/// zipinfo.c:FilenameLength (`%u`).
pub(super) const FILENAME_LENGTH: &str =
    "  length of filename:                             %s characters\n";
/// zipinfo.c:ExtraFieldLength (`%u`).
pub(super) const EXTRA_FIELD_LENGTH: &str =
    "  length of extra field:                          %s bytes\n";
/// zipinfo.c:FileCommentLength (`%u`).
pub(super) const FILE_COMMENT_LENGTH: &str =
    "  length of file comment:                         %s characters\n";
/// zipinfo.c:FileDiskNum (`%lu`).
pub(super) const FILE_DISK_NUM: &str =
    "  disk number on which file begins:               disk %s\n";
/// zipinfo.c:ApparentFileType.
pub(super) const APPARENT_FILE_TYPE: &str =
    "  apparent file type:                             %s\n";
/// zi_long()'s file types, by internal attribute bits 0 and 1.
pub(super) const TEXT: &str = "text";
pub(super) const EBCDIC: &str = "ebcdic";
pub(super) const BINARY: &str = "binary";
/// zipinfo.c:VMSFileAttributes (`%06o`).
pub(super) const VMS_FILE_ATTRIBUTES: &str = "  VMS file attributes (%s octal):             %s\n";
/// zipinfo.c:AmigaFileAttributes (`%06o`).
pub(super) const AMIGA_FILE_ATTRIBUTES: &str = "  Amiga file attributes (%s octal):           %s\n";
/// zipinfo.c:UnixFileAttributes (`%06o`).
pub(super) const UNIX_FILE_ATTRIBUTES: &str = "  Unix file attributes (%s octal):            %s\n";
/// zipinfo.c:NonMSDOSFileAttributes (`%06lX`).
pub(super) const NON_MSDOS_FILE_ATTRIBUTES: &str =
    "  non-MSDOS external file attributes:             %s hex\n";
/// zipinfo.c:MSDOSFileAttributes (`%02X`).
pub(super) const MSDOS_FILE_ATTRIBUTES: &str =
    "  MS-DOS file attributes (%s hex):                none\n";
/// zipinfo.c:MSDOSFileAttributesRO (`%02X`).
pub(super) const MSDOS_FILE_ATTRIBUTES_RO: &str =
    "  MS-DOS file attributes (%s hex):                read-only\n";
/// zipinfo.c:MSDOSFileAttributesAlpha (`%02X`, then the eight words).
pub(super) const MSDOS_FILE_ATTRIBUTES_ALPHA: &str =
    "  MS-DOS file attributes (%s hex):                %s%s%s%s%s%s%s%s\n";
/// zi_long()'s MS-DOS attribute words, bit 0 to bit 7.
pub(super) const MSDOS_ATTR_WORDS: [&str; 8] = [
    "rdo ", "hid ", "sys ", "lab ", "dir ", "arc ", "lnk ", "exe",
];
/// zipinfo.c:TheosFileAttributes (`%04X`).
pub(super) const THEOS_FILE_ATTRIBUTES: &str =
    "  Theos file attributes (%s hex):               %s\n";
/// zipinfo.c:TheosFTyp*: the Theos file types (`TheosFTypLib` ..
/// `TheosFTypP32`, then `TheosFTypUkn`).
pub(super) const THEOS_FTYP_LIB: &str = "Library     ";
pub(super) const THEOS_FTYP_DIR: &str = "Directory   ";
pub(super) const THEOS_FTYP_REG: &str = "Sequential  ";
pub(super) const THEOS_FTYP_REL: &str = "Direct      ";
pub(super) const THEOS_FTYP_KEY: &str = "Keyed       ";
pub(super) const THEOS_FTYP_IND: &str = "Indexed     ";
pub(super) const THEOS_FTYP_R16: &str = " 86 program ";
pub(super) const THEOS_FTYP_P16: &str = "286 program ";
pub(super) const THEOS_FTYP_P32: &str = "386 program ";
pub(super) const THEOS_FTYP_UKN: &str = "???         ";

/// zipinfo.c:ExtraFieldTrunc: the block's id (`%04x`), its length and what
/// is left (`%u` each).
pub(super) const EXTRA_FIELD_TRUNC: &str = "\n  error: EF data block (type 0x%s) size %s \
     exceeds remaining extra field\n         space %s; block length has been truncated.\n";
/// zipinfo.c:ExtraFields.
pub(super) const EXTRA_FIELDS: &str = "\n  The central-directory extra field contains:";
/// zipinfo.c:ExtraFieldType: the id (`%04x`), its name, the length (`%u`).
pub(super) const EXTRA_FIELD_TYPE: &str = "\n  - A subfield with ID 0x%s (%s) and %s data bytes";
/// zipinfo.c:efPKSZ64 .. efUnknown: the extra block names.
pub(super) const EF_PKSZ64_NAME: &str = "PKWARE 64-bit sizes";
pub(super) const EF_AV_NAME: &str = "PKWARE AV";
pub(super) const EF_OS2_NAME: &str = "OS/2";
pub(super) const EF_PKVMS_NAME: &str = "PKWARE VMS";
pub(super) const EF_PKWIN32_NAME: &str = "PKWARE Win32";
pub(super) const EF_PKUNIX_NAME: &str = "PKWARE Unix";
pub(super) const EF_IZVMS_NAME: &str = "Info-ZIP VMS";
pub(super) const EF_IZUNIX_NAME: &str = "old Info-ZIP Unix/OS2/NT";
pub(super) const EF_IZUNIX2_NAME: &str = "Unix UID/GID (16-bit)";
pub(super) const EF_IZUNIX3_NAME: &str = "Unix UID/GID (any size)";
pub(super) const EF_TIME_NAME: &str = "universal time";
pub(super) const EF_U8PATH_NAME: &str = "UTF8 path name";
pub(super) const EF_U8COMMNT_NAME: &str = "UTF8 entry comment";
pub(super) const EF_JLMAC_NAME: &str = "old Info-ZIP Macintosh";
pub(super) const EF_MAC3_NAME: &str = "new Info-ZIP Macintosh";
pub(super) const EF_ZIPIT_NAME: &str = "ZipIt Macintosh";
pub(super) const EF_SMARTZIP_NAME: &str = "SmartZip Macintosh";
pub(super) const EF_ZIPIT2_NAME: &str = "ZipIt Macintosh (short)";
pub(super) const EF_VMCMS_NAME: &str = "VM/CMS";
pub(super) const EF_MVS_NAME: &str = "MVS";
pub(super) const EF_ACL_NAME: &str = "OS/2 ACL";
pub(super) const EF_NTSD_NAME: &str = "Security Descriptor";
pub(super) const EF_ATHEOS_NAME: &str = "AtheOS";
pub(super) const EF_BEOS_NAME: &str = "BeOS";
pub(super) const EF_QDOS_NAME: &str = "SMS/QDOS";
pub(super) const EF_AOSVS_NAME: &str = "AOS/VS";
pub(super) const EF_SPARK_NAME: &str = "Acorn SparkFS";
pub(super) const EF_MD5_NAME: &str = "Fred Kantor MD5";
pub(super) const EF_ASIUNIX_NAME: &str = "ASi Unix";
pub(super) const EF_TANDEM_NAME: &str = "Tandem NSK";
pub(super) const EF_THEOS_NAME: &str = "Theos";
pub(super) const EF_UNKNOWN_NAME: &str = "unknown";

/// zipinfo.c:OS2EAs (`%lu`).
pub(super) const OS2_EAS: &str = ".\n    The local extra field has %s bytes of OS/2 extended \
     attributes.\n    (May not match OS/2 \"dir\" amount due to storage method)";
/// zipinfo.c:izVMSdata: the storage word, the size (`%u`), the record
/// kind, the version note.
pub(super) const IZ_VMS_DATA: &str =
    ".  The extra\n    field is %s and has %s bytes of VMS %s information%s";
/// zipinfo.c:izVMScomp[4] (`izVMSstored` .. `izVMScunknw`).
pub(super) const IZ_VMS_COMP: [&str; 4] =
    ["stored", "run-length encoded", "deflated", "compressed(?)"];
/// zi_long()'s IZVMS record kinds, by tag (`VFAB` .. `VMSV`, then the
/// rest).
pub(super) const VMS_FAB: &str = "FAB";
pub(super) const VMS_XABALL: &str = "XABALL";
pub(super) const VMS_XABFHC: &str = "XABFHC";
pub(super) const VMS_XABDAT: &str = "XABDAT";
pub(super) const VMS_XABRDT: &str = "XABRDT";
pub(super) const VMS_XABPRO: &str = "XABPRO";
pub(super) const VMS_XABKEY: &str = "XABKEY";
pub(super) const VMS_VERSION: &str = "version";
pub(super) const VMS_UNKNOWN: &str = "unknown";
/// zipinfo.c:ACLdata (`%lu`).
pub(super) const ACL_DATA: &str =
    ".\n    The local extra field has %s bytes of access control list information";
/// zipinfo.c:NTSDData (`%lu`).
pub(super) const NTSD_DATA: &str =
    ".\n    The local extra field has %s bytes of NT security descriptor data";
/// zipinfo.c:UTdata: the time names, `s` or nothing.
pub(super) const UT_DATA: &str = ".\n    The local extra field has UTC/GMT %s time%s";
/// zipinfo.c:UTmodification, UTaccess, UTcreation.
pub(super) const UT_MODIFICATION: &str = "modification";
pub(super) const UT_ACCESS: &str = "access";
pub(super) const UT_CREATION: &str = "creation";
/// zipinfo.c:U8PthCmnComplete: the version (`%u`), the name's CRC (`%.8lx`).
pub(super) const U8_PTH_CMN_COMPLETE: &str = ".\n    The UTF8 data of the extra field (V%s, \
     ASCII name CRC `%s') are:\n   ";
/// zipinfo.c:U8PthCmnF24 (as `U8PthCmnComplete`).
pub(super) const U8_PTH_CMN_F24: &str = ". The first\n    24 UTF8 bytes in the extra field \
     (V%s, ASCII name CRC `%s') are:\n   ";
/// zipinfo.c:ZipItFname.
pub(super) const ZIP_IT_FNAME: &str = ".\n    The Mac long filename is %s";
/// zipinfo.c:Mac3data (`%lu`, then `un` or nothing).
pub(super) const MAC3_DATA: &str = ".\n    The local extra field has %s bytes of %scompressed \
     Macintosh\n    finder attributes";
/// zi_long()'s `"un"`.
pub(super) const UN: &str = "un";
/// zipinfo.c:MacOSdata: the type and creator, a `%c` each.
pub(super) const MAC_OS_DATA: &str =
    ".\n    The associated file has type code `%s' and creator code `%s'";
/// zipinfo.c:MacOSdata1 (`0x%lx` each).
pub(super) const MAC_OS_DATA1: &str =
    ".\n    The associated file has type code `0x%s' and creator code `0x%s'";
/// zipinfo.c:MacOSJLEEflags.
pub(super) const MAC_OS_JLEE_FLAGS: &str = ".\n    File is marked as %s";
/// zipinfo.c:MacOS_RF, MacOS_DF.
pub(super) const MAC_OS_RF: &str = "Resource-fork";
pub(super) const MAC_OS_DF: &str = "Data-fork";
/// zipinfo.c:MacOSMAC3flags: the fork, the time width (`%d`).
pub(super) const MAC_OS_MAC3_FLAGS: &str = ".\n    File is marked as %s, File Dates are in %s Bit";
/// zipinfo.c:AtheOSdata (`%lu`, `un` or nothing).
pub(super) const ATHE_OS_DATA: &str =
    ".\n    The local extra field has %s bytes of %scompressed AtheOS file attributes";
/// zipinfo.c:BeOSdata (`%lu`, `un` or nothing).
pub(super) const BE_OS_DATA: &str =
    ".\n    The local extra field has %s bytes of %scompressed BeOS file attributes";
/// zipinfo.c:QDOSdata: four `%c`.
pub(super) const QDOS_DATA: &str = ".\n    The QDOS extra field subtype is `%s'";
/// zipinfo.c:AOSVSdata (`%d.%d`).
pub(super) const AOSVS_DATA: &str = ".\n    The AOS/VS extra field revision is %s.%s";
/// zipinfo.c:TandemFileformat[6] (`TandemUnstr` .. `TandemObj`).
pub(super) const TANDEM_FILEFORMAT: [&str; 6] = [
    "Unstructured",
    "Relative",
    "Entry Sequenced",
    "Key Sequenced",
    "Edit",
    "Object",
];
/// zipinfo.c:Tandemdata: the format, the file code (`%u`).
pub(super) const TANDEM_DATA: &str =
    ".\n    The file was originally a Tandem %s file, with file code %s";
/// zipinfo.c:MD5data.
pub(super) const MD5_DATA: &str = ".\n    The 128-bit MD5 signature is %s";
/// zipinfo.c:First20.
pub(super) const FIRST20: &str = ".  The first\n    20 are:  ";
/// zipinfo.c:ColonIndent.
pub(super) const COLON_INDENT: &str = ":\n   ";
/// zipinfo.c:efFormat (`" %02x"`): one byte.
pub(super) const EF_FORMAT: &str = " %s";
/// zipinfo.c:lExtraFieldType: `is` or `may be`, the id (`%04x`), its
/// name, the length (`%u`), what it holds.
pub(super) const L_EXTRA_FIELD_TYPE: &str = "\n  There %s a local extra field with ID 0x%s \
     (%s) and\n  %s data bytes (%s).\n";
/// zi_long()'s `"may be"`.
pub(super) const MAY_BE: &str = "may be";
/// zipinfo.c:efIZuid.
pub(super) const EF_IZ_UID: &str = "GMT modification/access times and Unix UID/GID";
/// zipinfo.c:efIZnouid.
pub(super) const EF_IZ_NOUID: &str = "GMT modification/access times only";
/// zipinfo.c:NoFileComment.
pub(super) const NO_FILE_COMMENT: &str = "\n  There is no file comment.\n";
/// zipinfo.c:FileCommBegin.
pub(super) const FILE_COMM_BEGIN: &str = "\n------------------------- file comment begins \
     ----------------------------\n";
/// zipinfo.c:FileCommEnd.
pub(super) const FILE_COMM_END: &str =
    "-------------------------- file comment ends -----------------------------\n";

/// zi_short()'s `os[NUM_HOSTS+1][4]`: three-letter host names.
pub(super) const ZI_SHORT_OS: [&str; 32] = [
    "fat", "ami", "vms", "unx", "cms", "atr", "hpf", "mac", "zzz", "cpm", "t20", "ntf", "qds",
    "aco", "vft", "mvs", "be ", "nsk", "ths", "osx", "???", "???", "???", "???", "???", "???",
    "???", "???", "???", "???", "ath", "???",
];
/// zi_short()'s `method[NUM_METHODS+1][5]`, by `find_compr_idx()`.
pub(super) const ZI_SHORT_METHODS: [&str; 18] = [
    "stor", "shrk", "re:1", "re:2", "re:3", "re:4", "i#:#", "tokn", "def#", "d64#", "dcli", "bzp2",
    "lzma", "ters", "lz77", "wavp", "ppmd", "u###",
];
/// zi_short()'s MS-DOS attribute template (`".r.-...     %u.%u"`): the
/// version follows.
pub(super) const ZI_SHORT_FAT_ATTRIBS: &str = ".r.-...     ";
/// zi_short()'s executable extensions (`STRNICMP(p, ..., 3)`).
pub(super) const ZI_SHORT_EXE_EXTS: [&str; 5] = ["com", "exe", "btm", "cmd", "bat"];
/// zi_short()'s `"%s %s %s "`: the attributes, the host, the size
/// (`%8llu`).
pub(super) const ZI_SHORT_HEAD: &str = "%s %s %s ";
/// zi_short()'s `"%3d%%"` (`-m`): the ratio.
pub(super) const ZI_SHORT_PERCENT: &str = "%s%%";
/// zi_short()'s `" %s"` (`-l`): the compressed size (`%8llu`).
pub(super) const ZI_SHORT_CSIZE: &str = " %s";
/// zi_short()'s `" %s %s "`: the method and the time.
pub(super) const ZI_SHORT_TAIL: &str = " %s %s ";

/// zi_time()'s `month[12][4]`.
pub(super) const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
/// zipinfo.c:lngYMDHMSTimeError (`USE_EF_UT_TIME`).
pub(super) const LNG_YMDHMS_TIME_ERROR: &str = "???? ??? ?? ??:??:??";

/// zipinfo.c:lngYMDHMSTime, `"%u %s %u %02u:%02u:%02u"`.
pub(super) fn lng_ymdhms_time(
    yr: u32,
    month: &[u8],
    dy: u32,
    hh: u32,
    mm: u32,
    ss: u32,
) -> Vec<u8> {
    let mut v = format!("{yr} ").into_bytes();
    v.extend_from_slice(month);
    v.extend_from_slice(format!(" {dy} {hh:02}:{mm:02}:{ss:02}").as_bytes());
    v
}

/// zipinfo.c:DecimalTime, `"%04u%02u%02u.%02u%02u%02u"`.
pub(super) fn decimal_time(yr: u32, mo: u32, dy: u32, hh: u32, mm: u32, ss: u32) -> Vec<u8> {
    format!("{yr:04}{mo:02}{dy:02}.{hh:02}{mm:02}{ss:02}").into_bytes()
}

/// zipinfo.c:shtYMDHMTime, `"%02u-%s-%02u %02u:%02u"`.
pub(super) fn sht_ymdhm_time(yr: u32, month: &[u8], dy: u32, hh: u32, mm: u32) -> Vec<u8> {
    let mut v = format!("{yr:02}-").into_bytes();
    v.extend_from_slice(month);
    v.extend_from_slice(format!("-{dy:02} {hh:02}:{mm:02}").as_bytes());
    v
}

// ---- extract.c (Task 10) ----

/// extract.c:VersionMsg. The name is padded by the caller (`%-22s`).
pub(super) const VERSION_MSG: &str = "   skipping: %s  need %s compat. v%s.%s (can do v%s.%s)\n";
/// extract.c:ComprMsgNum (`%-22s`, `%u`).
pub(super) const COMPR_MSG_NUM: &str = "   skipping: %s  unsupported compression method %s\n";
/// extract.c:ComprMsgName (`%-22s`).
pub(super) const COMPR_MSG_NAME: &str = "   skipping: %s  `%s' method not supported\n";
/// extract.c:ComprNames, by extract.c:ComprIDs (`find_compr_idx()`).
pub(super) const COMPR_NAMES: [(u16, &str); 17] = [
    (0, "store"),
    (1, "shrink"),
    (2, "reduce"),
    (3, "reduce"),
    (4, "reduce"),
    (5, "reduce"),
    (6, "implode"),
    (7, "tokenize"),
    (8, "deflate"),
    (9, "deflate64"),
    (10, "DCL implode"),
    (12, "bzip2"),
    (14, "LZMA"),
    (18, "IBM/Terse"),
    (19, "IBM LZ77"),
    (97, "WavPack"),
    (98, "PPMd"),
];
/// extract.c:FilNamMsg (`central` or `local`).
pub(super) const FIL_NAM_MSG: &str = "%s:  bad filename length (%s)\n";
/// extract.c:LvsCFNamMsg.
pub(super) const LVS_CF_NAM_MSG: &str = "%s:  mismatching \"local\" filename (%s),\n         continuing with \"central\" filename version\n";
/// extract.c:GP11FlagsDiffer (ubuntu: -DUNICODE_SUPPORT; `%lu`, `%s`, `%d`
/// formatted by the caller).
pub(super) const GP11_FLAGS_DIFFER: &str = "file #%s (%s):\n         mismatch between local and central GPF bit 11 (\"UTF-8\"),\n         continuing with central flag (IsUTF8 = %s)\n";
/// extract.c:WrnStorUCSizCSizDiff.
pub(super) const WRN_STOR_UCSIZ_CSIZ_DIFF: &str = "%s:  ucsize %s <> csize %s for STORED entry\n         continuing with \"compressed\" size value\n";
/// extract.c:ExtFieldMsg.
pub(super) const EXT_FIELD_MSG: &str = "%s:  bad extra field length (%s)\n";
/// extract.c:OffsetMsg (`%lu`, `%s`, `%ld`).
pub(super) const OFFSET_MSG: &str = "file #%s:  bad zipfile offset (%s):  %s\n";
/// extract.c:ExtractMsg: `%8s` (right-aligned verb) and `%-22s` are the
/// caller's.
pub(super) const EXTRACT_MSG: &str = "%sing: %s  %s%s";
/// extract.c:LengthMsg.
pub(super) const LENGTH_MSG: &str = "%s  %s:  %s bytes required to uncompress to %s bytes;\n    %s      supposed to require %s bytes%s%s%s\n";
/// extract.c:BadFileCommLength.
pub(super) const BAD_FILE_COMM_LENGTH: &str = "%s:  bad file comment length\n";
/// extract.c:LocalHdrSig.
pub(super) const LOCAL_HDR_SIG: &str = "local header sig";
/// extract.c:BadLocalHdr.
pub(super) const BAD_LOCAL_HDR: &str = "file #%s:  bad local header\n";
/// extract.c:AttemptRecompensate.
pub(super) const ATTEMPT_RECOMPENSATE: &str = "  (attempting to re-compensate)\n";
/// extract.c:BackslashPathSep.
pub(super) const BACKSLASH_PATH_SEP: &str =
    "warning:  %s appears to use backslashes as path separators\n";
/// extract.c:AbsolutePathWarning.
pub(super) const ABSOLUTE_PATH_WARNING: &str = "warning:  stripped absolute path spec from %s\n";
/// extract.c:SkipVolumeLabel (`%-22s`).
pub(super) const SKIP_VOLUME_LABEL: &str = "   skipping: %s  %svolume label\n";
/// extract.c:DirlistSetAttrFailed.
pub(super) const DIRLIST_SET_ATTR_FAILED: &str = "warning:  set times/attribs failed for %s\n";
/// extract.c:DirlistFailAttrSum (`%lu`).
pub(super) const DIRLIST_FAIL_ATTR_SUM: &str =
    "     failed setting times/attribs for %s dir entries";
/// extract.c:SymLnkWarnInvalid.
pub(super) const SYM_LNK_WARN_INVALID: &str =
    "warning:  deferred symlink (%s) failed:\n          invalid placeholder file\n";
/// extract.c:SymLnkDeferred.
pub(super) const SYM_LNK_DEFERRED: &str = "finishing deferred symbolic links:\n";
/// extract.c:SymLnkFinish (`%-22s`).
pub(super) const SYM_LNK_FINISH: &str = "  %s -> %s\n";
/// extract.c:set_deferred_symlink's `perror("symlink error")`.
pub(super) const SYMLINK_ERROR: &str = "symlink error";
/// extract.c:ReplaceQuery.
pub(super) const REPLACE_QUERY: &str = "replace %s? [y]es, [n]o, [A]ll, [N]one, [r]ename: ";
/// extract.c:AssumeNone.
pub(super) const ASSUME_NONE: &str = " NULL\n(EOF or read error, treating as \"[N]one\" ...)\n";
/// extract.c:NewNameQuery.
pub(super) const NEW_NAME_QUERY: &str = "new name: ";
/// extract.c:InvalidResponse.
pub(super) const INVALID_RESPONSE: &str = "error:  invalid response [%s]\n";
/// extract_or_test_entrylist's echo of an empty answer.
pub(super) const ENTER: &[u8] = b"{ENTER}";
/// extract.c:ErrorInArchive.
pub(super) const ERROR_IN_ARCHIVE: &str = "At least one %serror was detected in %s.\n";
/// extract.c:ZeroFilesTested.
pub(super) const ZERO_FILES_TESTED: &str = "Caution:  zero files tested in %s.\n";
/// extract.c:VMSFormatQuery.
pub(super) const VMS_FORMAT_QUERY: &str = "\n%s:  stored in VMS format.  Extract anyway? (y/n) ";
/// extract.c:SkipCannotGetPasswd (`%-22s`).
pub(super) const SKIP_CANNOT_GET_PASSWD: &str = "   skipping: %s  unable to get password\n";
/// extract.c:SkipIncorrectPasswd (`%-22s`).
pub(super) const SKIP_INCORRECT_PASSWD: &str = "   skipping: %s  incorrect password\n";
/// extract.c:FilesSkipBadPasswd (`%lu`).
pub(super) const FILES_SKIP_BAD_PASSWD: &str = "%s file%s skipped because of incorrect password.\n";
/// extract.c:MaybeBadPasswd.
pub(super) const MAYBE_BAD_PASSWD: &str = "    (may instead be incorrect password)\n";
/// extract.c:NoErrInCompData.
pub(super) const NO_ERR_IN_COMP_DATA: &str = "No errors detected in compressed data of %s.\n";
/// extract.c:NoErrInTestedFiles (`%lu`).
pub(super) const NO_ERR_IN_TESTED_FILES: &str =
    "No errors detected in %s for the %s file%s tested.\n";
/// extract.c:FilesSkipped (`%lu`).
pub(super) const FILES_SKIPPED: &str =
    "%s file%s skipped because of unsupported compression or encoding.\n";
/// extract.c:ErrUnzipFile.
pub(super) const ERR_UNZIP_FILE: &str = "  error:  %s%s %s\n";
/// extract.c:ErrUnzipNoFile.
pub(super) const ERR_UNZIP_NO_FILE: &str = "\n  error:  %s%s\n";
/// extract.c:NotEnoughMem.
pub(super) const NOT_ENOUGH_MEM: &str = "not enough memory to ";
/// extract.c:InvalidComprData.
pub(super) const INVALID_COMPR_DATA: &str = "invalid compressed data to ";
/// extract.c:Inflate.
pub(super) const INFLATE: &str = "inflate";
/// extract.c:Explode.
pub(super) const EXPLODE: &str = "explode";
/// extract.c:Unshrink.
pub(super) const UNSHRINK: &str = "unshrink";
/// extract.c:BUnzip (ubuntu: -DUSE_BZIP2).
pub(super) const BUNZIP: &str = "bunzip";
/// extract.c:FileTruncated.
pub(super) const FILE_TRUNCATED: &str = "warning:  %s is probably truncated\n";
/// extract.c:FileUnknownCompMethod.
pub(super) const FILE_UNKNOWN_COMP_METHOD: &str = "%s:  unknown compression method\n";
/// extract.c:BadCRC (`%08lx` twice, formatted by the caller).
pub(super) const BAD_CRC: &str = " bad CRC %s  (should be %s)\n";
/// extract_or_test_member's `"%-22s "` (the name padded by the caller).
pub(super) const NAME_22: &str = "%s ";
/// extract_or_test_member's and TestExtraField's `" OK\n"`.
pub(super) const OK: &str = " OK\n";
/// extract.c's verbs (`%8s`, padded by the caller) and file kinds.
pub(super) const VERB_TEST: &[u8] = b"test";
pub(super) const VERB_LINK: &[u8] = b"link";
pub(super) const VERB_EXTRACT: &[u8] = b"extract";
pub(super) const VERB_UNSHRINK: &[u8] = b"unshrink";
pub(super) const VERB_EXPLOD: &[u8] = b"explod";
pub(super) const VERB_INFLAT: &[u8] = b"inflat";
/// extract_or_test_member's BZIPPED verb (ubuntu: -DUSE_BZIP2).
pub(super) const VERB_BUNZIPP: &[u8] = b"bunzipp";
/// extract_or_test_member's `nul`, `txt`, `bin`.
pub(super) const KIND_EMPTY: &[u8] = b"[empty] ";
pub(super) const KIND_TEXT: &[u8] = b"[text]  ";
pub(super) const KIND_BINARY: &[u8] = b"[binary]";
/// extract.c:TruncEAs (`%d`).
pub(super) const TRUNC_EAS: &str = " compressed EA data missing (%s bytes)%s";
/// extract.c:TruncNTSD (`%d`).
pub(super) const TRUNC_NTSD: &str = " compressed WinNT security data missing (%s bytes)%s";
/// extract.c:InconsistEFlength (`%u` twice).
pub(super) const INCONSIST_EF_LENGTH: &str = "bad extra-field entry:\n      EF block length (%s bytes) exceeds remaining EF data (%s bytes)\n";
/// extract.c:TooSmallEBlength (`%u`, `%d`).
pub(super) const TOO_SMALL_EB_LENGTH: &str =
    "bad extra-field entry:\n      EF block length (%s bytes) invalid (< %s)\n";
/// extract.c:InvalidComprDataEAs.
pub(super) const INVALID_COMPR_DATA_EAS: &str = " invalid compressed data for EAs\n";
/// extract.c:UnsuppNTSDVersEAs (`%d`).
pub(super) const UNSUPP_NTSD_VERS_EAS: &str = " unsupported NTSD EAs version %s\n";
/// extract.c:BadCRC_EAs.
pub(super) const BAD_CRC_EAS: &str = " bad CRC for extended attributes\n";
/// extract.c:UnknComprMethodEAs (`%u`).
pub(super) const UNKN_COMPR_METHOD_EAS: &str = " unknown compression method for EAs (%s)\n";
/// extract.c:NotEnoughMemEAs.
pub(super) const NOT_ENOUGH_MEM_EAS: &str = " out of memory while inflating EAs\n";
/// extract.c:UnknErrorEAs.
pub(super) const UNKN_ERROR_EAS: &str = " unknown error on extended attributes\n";
/// extract.c:UnsupportedExtraField (`%u`).
pub(super) const UNSUPPORTED_EXTRA_FIELD: &str =
    "\nerror:  unsupported extra-field compression type (%s)--skipping\n";
/// extract.c:BadExtraFieldCRC (`%08lx` twice).
pub(super) const BAD_EXTRA_FIELD_CRC: &str = "error [%s]:  bad extra-field CRC %s (should be %s)\n";

// ---- fileio.c's output side (Task 10) ----

/// fileio.c:is_vms_varlen_txt's warning for a PKWARE VMS block whose CRC
/// does not match.
pub(super) const VMS_CRC_WARNING: &str = "[Warning: CRC error, discarding PKWARE extra field]\n";

/// fileio.c:CannotDeleteOldFile.
pub(super) const CANNOT_DELETE_OLD_FILE: &str = "error:  cannot delete old %s\n        %s\n";
/// fileio.c:CannotRenameOldFile.
pub(super) const CANNOT_RENAME_OLD_FILE: &str = "error:  cannot rename old %s\n        %s\n";
/// fileio.c:BackupSuffix.
pub(super) const BACKUP_SUFFIX: &[u8] = b"~";
/// fileio.c:CannotCreateFile.
pub(super) const CANNOT_CREATE_FILE: &str = "error:  cannot create %s\n        %s\n";
/// apple: fileio.c:168, CannotEnterDir.
pub(super) const CANNOT_ENTER_DIR: &str = "error:  cannot enter %s\n        %s\n";
/// fileio.c:DiskFullQuery.
pub(super) const DISK_FULL_QUERY: &str = "%s:  write error (disk full?).  Continue? (y/n/^C) ";
/// fileio.c:FileIsSymLink.
pub(super) const FILE_IS_SYMLINK: &str = "%s exists and is a symbolic link%s.\n";
/// check_for_newer()'s second `FileIsSymLink` argument.
pub(super) const WITH_NO_REAL_FILE: &[u8] = b" with no real file";
/// apple: unix.c:1003, `ENOTCAPABLE`'s text on macOS (`strerror(107)`),
/// for an escape off macOS, where the errno does not exist.
/// probe: `strerror(ENOTCAPABLE)` on this Mac.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(super) const NOT_CAPABLE: &str = "Capabilities insufficient";

// ---- unix/unix.c (Task 10) ----

/// unix.c:CannotSetItemUidGid (`%lu` twice).
pub(super) const CANNOT_SET_ITEM_UID_GID: &str =
    "warning:  cannot set UID %s and/or GID %s for %s\n          %s\n";
/// unix.c:CannotSetUidGid (`%lu` twice).
pub(super) const CANNOT_SET_UID_GID: &str =
    " (warning) cannot set UID %s and/or GID %s\n          %s";
/// unix.c:CannotSetItemTimestamps.
pub(super) const CANNOT_SET_ITEM_TIMESTAMPS: &str =
    "warning:  cannot set modif./access times for %s\n          %s\n";
/// unix.c:CannotSetTimestamps.
pub(super) const CANNOT_SET_TIMESTAMPS: &str =
    " (warning) cannot set modif./access times\n          %s";
/// unix.c:DirlistChmodFailed.
pub(super) const DIRLIST_CHMOD_FAILED: &str =
    "warning:  cannot set permissions for %s\n          %s\n";
/// unix.c:mapname's warning for stripped `../` components.
pub(super) const SKIPPED_DDOT: &str = "warning:  skipped \"../\" path component(s) in %s\n";
/// unix.c:mapname's report of a created directory.
pub(super) const CREATING: &str = "   creating: %s\n";
/// unix.c:mapname's `perror()` texts.
pub(super) const PERROR_DIR_ATTRS: &str = "Could not read directory attributes";
pub(super) const PERROR_CHMOD_DIR: &str = "chmod (directory attributes) error";
/// unix.c:close_outfile's `perror()`.
pub(super) const PERROR_FCHMOD: &str = "fchmod (file attributes) error";
/// unix.c:set_symlnk_attribs's `perror()`.
pub(super) const PERROR_LCHMOD: &str = "lchmod (file attributes) error";
/// unix.c:mapname, a name that maps to nothing.
pub(super) const MAPNAME_FAILED: &str = "mapname:  conversion of %s failed\n";
/// unix.c:checkdir, `APPEND_DIR` past `FILNAMSIZ`.
pub(super) const CHECKDIR_TOO_LONG: &str = "checkdir error:  path too long: %s\n";
/// unix.c:checkdir, a directory that could not be made.
pub(super) const CHECKDIR_CANNOT_CREATE: &str = "checkdir error:  cannot create %s\n                 %s\n                 unable to process %s.\n";
/// unix.c:checkdir, a path component that is not a directory.
pub(super) const CHECKDIR_NOT_DIR: &str =
    "checkdir error:  %s exists but is not directory\n                 unable to process %s.\n";
/// unix.c:checkdir, `APPEND_NAME` past `FILNAMSIZ`.
pub(super) const CHECKDIR_TRUNCATING: &str =
    "checkdir warning:  path too long; truncating\n                   %s\n                -> %s\n";
/// unix.c:checkdir, `ROOT` that could not be made.
pub(super) const CHECKDIR_CANNOT_CREATE_ROOT: &str =
    "checkdir:  cannot create extraction directory: %s\n           %s\n";
/// unix.c:close_outfile, a symlink whose target could not be read back.
pub(super) const SYMLINK_FAILED: &str = "warning:  symbolic link (%s) failed\n";
/// unix.c:close_outfile, the link target after the name.
pub(super) const SYMLINK_ARROW: &str = "-> %s ";

// ---- the terminal: fileio.c's pager and password prompt, ttyio.c ----

/// fileio.c:MorePrompt (`%lu` there: `%d` is `G.numlines`, formatted by
/// the caller).
pub(super) const MORE_PROMPT: &str = "--More--(%d)";
/// fileio.c:QuitPrompt, the `^S` pause in a comment while extracting.
pub(super) const QUIT_PROMPT: &str = "--- Press `Q' to quit, or any other key to continue ---";
/// fileio.c:HidePrompt, which covers a pause's prompt.
pub(super) const HIDE_PROMPT: &str =
    "\r                                                         \r";
/// fileio.c:PasswPrompt (not `MACOS`): the archive's name, then the entry's.
pub(super) const PASSW_PROMPT: &str = "[%s] %s password: ";
/// fileio.c:PasswPrompt2, when the names would not fit the prompt.
pub(super) const PASSW_PROMPT2: &str = "Enter password: ";
/// fileio.c:PasswRetry.
pub(super) const PASSW_RETRY: &str = "password incorrect--reenter: ";
/// ttyio.c:getp's warning before it asks again.
#[cfg(unix)]
pub(super) const LINE_TOO_LONG: &str = "(line too long--try again)\n";
/// ttyio.c:getp's `PUTC('\n', stderr)` after each line read.
#[cfg(unix)]
pub(super) const GETP_NEWLINE: &str = "\n";
/// ttyio.c:getp's `_PATH_TTY`.
#[cfg(unix)]
pub(super) const PATH_TTY: &std::ffi::CStr = c"/dev/tty";
/// fileio.c:handler: nothing. Its leading-newline message is compiled only
/// where neither SIGBUS nor SIGSEGV exists (`#if !(defined(SIGBUS) ||
/// defined(SIGSEGV))`), never on unix.
pub(super) const HANDLER_TEXT: &[u8] = b"";

// ---- stuffr's own ----

/// stuffr's own: the flavour variable holds neither name (exit 1). `%s` is
/// the program name, then the value.
pub(super) const FLAVOR_REFUSED: &str =
    "%s: STUFFR_UNZIP_FLAVOR must be apple or ubuntu, not '%s'\n";
