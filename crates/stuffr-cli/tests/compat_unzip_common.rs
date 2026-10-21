//! The unzip family's recorded tables (0.16.0 Task 2, rulings R4 and R13):
//! one [`Row`] per probed command, with the exit code, a text its standard
//! output holds and its exact standard error, as each reference gave them.
//!
//! Each row is tagged with the flavour whose reference it was recorded on
//! ([`Which`]); a row runs on its own platform's reference only (Apple on
//! macOS, Ubuntu on Linux: CI and `make compat-ubuntu`). Two uses:
//! - `recorded_rows_hold_on_the_reference` (always on) runs every row of
//!   this platform's flavour on the reference and checks the recording, so
//!   the table cannot rot;
//! - `taskN_rows_match_stuffr` runs the rows Task N implements against
//!   stuffr in that flavour (`assert_same_unzip`) and is `#[ignore = "Task
//!   N"]` until then. R13: on Ubuntu a row whose answer needs a patch of its
//!   series runs under Task 14 instead ([`Row::needs_patch`]); Ubuntu's
//!   build options are Task 13's, done.
//!
//! Every row runs under `LANG=C` and `TZ=UTC` (the harness's defaults);
//! every archive is built here with `zip_with`, so both references read the
//! same bytes. The probe notes are in `.claude/rules/compat.md`, "unzip
//! family (0.16.0)".

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;

    /// Which reference a row was recorded on.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Which {
        Apple,
        Ubuntu,
        /// Both gave exactly this answer.
        Both,
    }

    /// This platform's reference.
    fn own() -> Which {
        if platform_unzip_flavour() == "apple" {
            Which::Apple
        } else {
            Which::Ubuntu
        }
    }

    /// One probed command and what the reference did (2026-10-20).
    struct Row {
        flavour: Which,
        /// The task whose differential runs the row (on Ubuntu, a `Both`
        /// row that needs a patch runs under Task 14: [`Row::task_here`]).
        task: u8,
        /// The Ubuntu patch a `Both` row's answer needs there (R13: Task
        /// 14's), named for the record.
        ubuntu_patch: Option<&'static str>,
        label: &'static str,
        name: &'static str,
        args: Vec<&'static str>,
        files: Vec<(&'static str, Vec<u8>)>,
        /// Piped standard input; `None` is `/dev/null`.
        stdin: Option<Vec<u8>>,
        /// `stdin` is typed at the controlling terminal instead (R12,
        /// `Case::tty_ctl`).
        tty: bool,
        /// Standard output is a terminal (`-M`).
        tty_stdout: bool,
        /// Extra environment (`UNZIP`, `ZIPINFO`, ...), both sides.
        env: Vec<(&'static str, &'static str)>,
        /// The reference's exit code.
        code: i32,
        /// Text its standard output holds (`""`: nothing is checked).
        stdout_contains: &'static str,
        /// Its standard error, exactly.
        stderr: &'static str,
    }

    impl Row {
        fn runs_here(&self) -> bool {
            self.flavour == Which::Both || self.flavour == own()
        }

        fn task_here(&self) -> u8 {
            match (self.flavour, own()) {
                (Which::Both, Which::Ubuntu) if self.ubuntu_patch.is_some() => 14,
                _ => self.task,
            }
        }

        /// The row's Ubuntu side needs `patch` (Task 14, R13).
        fn needs_patch(mut self, patch: &'static str) -> Row {
            self.ubuntu_patch = Some(patch);
            self
        }

        fn case(&self) -> Case<'_> {
            let mut c = unzip_case(self.name, self.args.clone(), self.files.clone());
            c.stdin = self.stdin.clone();
            c.env = self.env.clone();
            c.tty_ctl = self.tty;
            c.tty_stdout = self.tty_stdout;
            c
        }

        /// The row with `keys` typed at its controlling terminal.
        fn typed(mut self, keys: &[u8]) -> Row {
            self.stdin = Some(keys.to_vec());
            self.tty = true;
            self
        }

        /// The row with `data` piped to standard input.
        fn piped(mut self, data: &[u8]) -> Row {
            self.stdin = Some(data.to_vec());
            self
        }

        /// The row with standard output a terminal.
        fn stdout_tty(mut self) -> Row {
            self.tty_stdout = true;
            self
        }

        /// The row run with `env` added to its environment.
        fn env(mut self, env: &[(&'static str, &'static str)]) -> Row {
            self.env = env.to_vec();
            self
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn row(
        flavour: Which,
        task: u8,
        label: &'static str,
        name: &'static str,
        args: &[&'static str],
        files: Vec<(&'static str, Vec<u8>)>,
        code: i32,
        stdout_contains: &'static str,
        stderr: &'static str,
    ) -> Row {
        Row {
            flavour,
            task,
            ubuntu_patch: None,
            label,
            name,
            args: args.to_vec(),
            files,
            stdin: None,
            tty: false,
            tty_stdout: false,
            env: Vec::new(),
            code,
            stdout_contains,
            stderr,
        }
    }

    // ---- fixtures ----

    fn text() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog\n".repeat(50)
    }

    /// Two entries: `a.txt` stored, `b.txt` deflated.
    fn a_zip() -> Vec<u8> {
        let t = text();
        zip_with(
            &[
                ZipEntrySpec::new(b"a.txt", b"alpha\n"),
                ZipEntrySpec {
                    method: 8,
                    ..ZipEntrySpec::new(b"b.txt", &t)
                },
            ],
            b"",
            b"",
        )
    }

    /// `a.zip` cut in the middle of `b.txt`'s data: no central directory.
    fn truncated_zip() -> Vec<u8> {
        let mut z = a_zip();
        z.truncate(z.len() / 2);
        z
    }

    /// `a.zip`'s entries after a 17-byte shell stub (offsets not adjusted).
    fn preamble_zip() -> Vec<u8> {
        let t = text();
        zip_with(
            &[
                ZipEntrySpec::new(b"a.txt", b"alpha\n"),
                ZipEntrySpec {
                    method: 8,
                    ..ZipEntrySpec::new(b"b.txt", &t)
                },
            ],
            b"",
            b"#!/bin/sh\nexit 0\n",
        )
    }

    /// `a.zip`'s entries under an archive comment (CR LF, an escape, a ^S)
    /// and an entry comment.
    fn comment_zip() -> Vec<u8> {
        zip_with(
            &[ZipEntrySpec::new(b"a.txt", b"alpha\n")],
            b"archive\r\ncomment\x1b[1m here\x13\nend",
            b"",
        )
    }

    /// No entries, no comment: the end record alone.
    fn empty_zip() -> Vec<u8> {
        zip_with(&[], b"", b"")
    }

    /// No entries, only a comment.
    fn comment_only_zip() -> Vec<u8> {
        zip_with(&[], b"just a comment", b"")
    }

    /// One entry whose name holds high bytes (0x80, 0xa0, 0xad, 0xe9, 0xff)
    /// and DEL: what each locale's `isprint()` lets through.
    fn high_zip() -> Vec<u8> {
        zip_with(
            &[ZipEntrySpec::new(b"c\x80\xa0\xad\xe9\xff\x7f.txt", b"x")],
            b"",
            b"",
        )
    }

    /// `a.txt` stored with one byte changed after its CRC was taken.
    fn crc_zip() -> Vec<u8> {
        zip_with(
            &[ZipEntrySpec {
                stored_data: Some(b"alphA\n"),
                ..ZipEntrySpec::new(b"a.txt", b"alpha\n")
            }],
            b"",
            b"",
        )
    }

    /// One entry of method 7 (tokenizing; neither build has it).
    fn method_zip() -> Vec<u8> {
        zip_with(
            &[ZipEntrySpec {
                method: 7,
                ..ZipEntrySpec::new(b"t.txt", b"tokenized\n")
            }],
            b"",
            b"",
        )
    }

    /// `s.txt` stored and encrypted under the password `secret`.
    fn encrypted_zip() -> Vec<u8> {
        let plain = b"secret data\n";
        let body = zipcrypto(b"secret", (crc32(plain) >> 24) as u8, plain);
        zip_with(
            &[ZipEntrySpec {
                flags: 1,
                stored_data: Some(&body),
                ..ZipEntrySpec::new(b"s.txt", plain)
            }],
            b"",
            b"",
        )
    }

    /// Plain `p.txt`, `s.txt` encrypted with `secret`, plain `t.txt`.
    fn mixed_zip() -> Vec<u8> {
        let plain = b"secret data\n";
        let body = zipcrypto(b"secret", (crc32(plain) >> 24) as u8, plain);
        zip_with(
            &[
                ZipEntrySpec::new(b"p.txt", b"plain\n"),
                ZipEntrySpec {
                    flags: 1,
                    stored_data: Some(&body),
                    ..ZipEntrySpec::new(b"s.txt", plain)
                },
                ZipEntrySpec::new(b"t.txt", b"other\n"),
            ],
            b"",
            b"",
        )
    }

    /// Sixty small entries: listings longer than a 24-line screen.
    fn many_zip() -> Vec<u8> {
        let names: Vec<String> = (0..60).map(|i| format!("f{i:02}.txt")).collect();
        let data: Vec<Vec<u8>> = (0..60).map(|i| vec![b'x'; i]).collect();
        let specs: Vec<ZipEntrySpec> = names
            .iter()
            .zip(&data)
            .map(|(n, d)| ZipEntrySpec::new(n.as_bytes(), d))
            .collect();
        zip_with(&specs, b"", b"")
    }

    /// An archive comment with a `^S` pause before a line end and one
    /// inside a line.
    fn comment_pauses_zip() -> Vec<u8> {
        zip_with(
            &[ZipEntrySpec::new(b"c.txt", b"hi")],
            b"line one\x13\nline two\x13more\nend",
            b"",
        )
    }

    /// `ow.zip` with `a.txt` and `b.txt`, both already in the directory.
    fn overwrite_files() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            (
                "ow.zip",
                zip_with(
                    &[
                        ZipEntrySpec::new(b"a.txt", b"new a\n"),
                        ZipEntrySpec::new(b"b.txt", b"new b\n"),
                    ],
                    b"",
                    b"",
                ),
            ),
            ("a.txt", b"old\n".to_vec()),
            ("b.txt", b"old\n".to_vec()),
        ]
    }

    /// The minimal overlapped archive (Fifield's "zip bomb" shape): one local
    /// header, two central entries pointing at it.
    fn overlapped_zip() -> Vec<u8> {
        let t = text();
        let one = zip_with(
            &[ZipEntrySpec {
                method: 8,
                ..ZipEntrySpec::new(b"o.txt", &t)
            }],
            b"",
            b"",
        );
        let eocd = one.len() - 22;
        let word = |at: usize| u32::from_le_bytes(one[at..at + 4].try_into().unwrap()) as usize;
        let (cd_len, cd_at) = (word(eocd + 12), word(eocd + 16));
        let central = &one[cd_at..cd_at + cd_len];
        let mut z = one[..cd_at].to_vec();
        z.extend_from_slice(central);
        z.extend_from_slice(central);
        z.extend_from_slice(b"PK\x05\x06");
        for v in [0u16, 0, 2, 2] {
            z.extend_from_slice(&v.to_le_bytes());
        }
        z.extend_from_slice(&((2 * cd_len) as u32).to_le_bytes());
        z.extend_from_slice(&(cd_at as u32).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z
    }

    // ---- the table ----

    /// Apple's `unzip` usage after its banner line (`unzip`, `-h`; stderr for a bad option).
    const APPLE_USAGE: &str = concat!(
        "Please report bugs to Apple.\n",
        "\n",
        "Usage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]\n",
        "  Default action is to extract files in list, except those in xlist, to exdir;\n",
        "  file[.zip] may be a wildcard.  -Z => ZipInfo mode (\"unzip -Z\" for usage).\n",
        "\n",
        "  -p  extract files to pipe, no messages     -l  list files (short format)\n",
        "  -f  freshen existing files, create none    -t  test compressed archive data\n",
        "  -u  update files, create if necessary      -z  display archive comment only\n",
        "  -v  list verbosely/show version info       -T  timestamp archive to latest\n",
        "  -x  exclude files that follow (in xlist)   -d  extract files into exdir\n",
        "modifiers:\n",
        "  -n  never overwrite existing files         -q  quiet mode (-qq => quieter)\n",
        "  -o  overwrite files WITHOUT prompting      -a  auto-convert any text files\n",
        "  -j  junk paths (do not make directories)   -aa treat ALL files as text\n",
        "  -C  match filenames case-insensitively     -L  make (some) names lowercase\n",
        "  -X  restore UID/GID info                   -V  retain VMS version numbers\n",
        "  -K  keep setuid/setgid/tacky permissions   -M  pipe through \"more\" pager\n",
        "See \"unzip -hh\" or unzip.txt for more help.  Examples:\n",
        "  unzip data1 -x joe   => extract all files except joe from zipfile data1.zip\n",
        "  unzip -p foo | more  => send contents of foo.zip via pipe into program more\n",
        "  unzip -fo foo ReadMe => quietly replace existing ReadMe if archive file newer\n",
    );

    /// Ubuntu's `unzip` usage after its banner line.
    const UBUNTU_USAGE: &str = concat!(
        "\n",
        "Usage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]\n",
        "  Default action is to extract files in list, except those in xlist, to exdir;\n",
        "  file[.zip] may be a wildcard.  -Z => ZipInfo mode (\"unzip -Z\" for usage).\n",
        "\n",
        "  -p  extract files to pipe, no messages     -l  list files (short format)\n",
        "  -f  freshen existing files, create none    -t  test compressed archive data\n",
        "  -u  update files, create if necessary      -z  display archive comment only\n",
        "  -v  list verbosely/show version info       -T  timestamp archive to latest\n",
        "  -x  exclude files that follow (in xlist)   -d  extract files into exdir\n",
        "modifiers:\n",
        "  -n  never overwrite existing files         -q  quiet mode (-qq => quieter)\n",
        "  -o  overwrite files WITHOUT prompting      -a  auto-convert any text files\n",
        "  -j  junk paths (do not make directories)   -aa treat ALL files as text\n",
        "  -U  use escapes for all non-ASCII Unicode  -UU ignore any Unicode fields\n",
        "  -C  match filenames case-insensitively     -L  make (some) names lowercase\n",
        "  -X  restore UID/GID info                   -V  retain VMS version numbers\n",
        "  -K  keep setuid/setgid/tacky permissions   -M  pipe through \"more\" pager\n",
        "  -O CHARSET  specify a character encoding for DOS, Windows and OS/2 archives\n",
        "  -I CHARSET  specify a character encoding for UNIX and other archives\n",
        "\n",
        "See \"unzip -hh\" or unzip.txt for more help.  Examples:\n",
        "  unzip data1 -x joe   => extract all files except joe from zipfile data1.zip\n",
        "  unzip -p foo | more  => send contents of foo.zip via pipe into program more\n",
        "  unzip -fo foo ReadMe => quietly replace existing ReadMe if archive file newer\n",
    );

    /// Apple's zipinfo usage after its banner line (`zipinfo`, `-h`, `unzip -Z`).
    const APPLE_ZIPINFO_USAGE: &str = concat!(
        "\n",
        "List name, date/time, attribute, size, compression method, etc., about files\n",
        "in list (excluding those in xlist) contained in the specified .zip archive(s).\n",
        "\"file[.zip]\" may be a wildcard name containing *, ?, [] (e.g., \"[a-j]*.zip\").\n",
        "\n",
        "   usage:  zipinfo [-12smlvChMtTz] file[.zip] [list...] [-x xlist...]\n",
        "      or:  unzip -Z [-12smlvChMtTz] file[.zip] [list...] [-x xlist...]\n",
        "\n",
        "main listing-format options:             -s  short Unix \"ls -l\" format (def.)\n",
        "  -1  filenames ONLY, one per line       -m  medium Unix \"ls -l\" format\n",
        "  -2  just filenames but allow -h/-t/-z  -l  long Unix \"ls -l\" format\n",
        "                                         -v  verbose, multi-page format\n",
        "miscellaneous options:\n",
        "  -h  print header line       -t  print totals for listed files or for all\n",
        "  -z  print zipfile comment   -T  print file times in sortable decimal format\n",
        "  -C  be case-insensitive     -M  page output through built-in \"more\"\n",
        "  -x  exclude filenames that follow from listing\n",
    );

    /// Ubuntu's zipinfo usage after its banner line (adds `-O`/`-I`).
    const UBUNTU_ZIPINFO_USAGE: &str = concat!(
        "\n",
        "List name, date/time, attribute, size, compression method, etc., about files\n",
        "in list (excluding those in xlist) contained in the specified .zip archive(s).\n",
        "\"file[.zip]\" may be a wildcard name containing *, ?, [] (e.g., \"[a-j]*.zip\").\n",
        "\n",
        "   usage:  zipinfo [-12smlvChMtTz] file[.zip] [list...] [-x xlist...]\n",
        "      or:  unzip -Z [-12smlvChMtTz] file[.zip] [list...] [-x xlist...]\n",
        "\n",
        "main listing-format options:             -s  short Unix \"ls -l\" format (def.)\n",
        "  -1  filenames ONLY, one per line       -m  medium Unix \"ls -l\" format\n",
        "  -2  just filenames but allow -h/-t/-z  -l  long Unix \"ls -l\" format\n",
        "                                         -v  verbose, multi-page format\n",
        "miscellaneous options:\n",
        "  -h  print header line       -t  print totals for listed files or for all\n",
        "  -z  print zipfile comment   -T  print file times in sortable decimal format\n",
        "  -C  be case-insensitive     -M  page output through built-in \"more\"\n",
        "  -x  exclude filenames that follow from listing\n",
        "  -O CHARSET  specify a character encoding for DOS, Windows and OS/2 archives\n",
        "  -I CHARSET  specify a character encoding for UNIX and other archives\n",
    );

    /// The end of Apple's `unzip -v`: compile options and environment (the lines above name the compiler and date, which vary by build: R11).
    const APPLE_OPTIONS: &str = concat!(
        "UnZip special compilation options:\n",
        "        COPYRIGHT_CLEAN (PKZIP 0.9x unreducing method not supported)\n",
        "        SET_DIR_ATTRIB\n",
        "        SYMLINKS (symbolic links supported, if RTL and file system permit)\n",
        "        TIMESTAMP\n",
        "        UNIXBACKUP\n",
        "        USE_EF_UT_TIME\n",
        "        USE_UNSHRINK (PKZIP/Zip 1.x unshrinking method supported)\n",
        "        USE_DEFLATE64 (PKZIP 4.x Deflate64(tm) supported)\n",
        "        LARGE_FILE_SUPPORT (large files over 2 GiB supported)\n",
        "        ZIP64_SUPPORT (archives using Zip64 for large files supported)\n",
        "        VMS_TEXT_CONV\n",
        "        [decryption, version 2.11 of 05 Jan 2007]\n",
        "\n",
        "UnZip and ZipInfo environment options:\n",
        "           UNZIP:  [none]\n",
        "        UNZIPOPT:  [none]\n",
        "         ZIPINFO:  [none]\n",
        "      ZIPINFOOPT:  [none]\n",
    );

    /// The end of Ubuntu's `unzip -v` under `LANG=C` (`char coding: other`; the UTF-8 locales are `compat_unzip_ubuntu::ubuntu_build_rows`').
    const UBUNTU_OPTIONS: &str = concat!(
        "UnZip special compilation options:\n",
        "        ACORN_FTYPE_NFS\n",
        "        COPYRIGHT_CLEAN (PKZIP 0.9x unreducing method not supported)\n",
        "        SET_DIR_ATTRIB\n",
        "        SYMLINKS (symbolic links supported, if RTL and file system permit)\n",
        "        TIMESTAMP\n",
        "        UNIXBACKUP\n",
        "        USE_EF_UT_TIME\n",
        "        USE_UNSHRINK (PKZIP/Zip 1.x unshrinking method supported)\n",
        "        USE_DEFLATE64 (PKZIP 4.x Deflate64(tm) supported)\n",
        "        UNICODE_SUPPORT [wide-chars, char coding: other] (handle UTF-8 paths)\n",
        "        LARGE_FILE_SUPPORT (large files over 2 GiB supported)\n",
        "        ZIP64_SUPPORT (archives using Zip64 for large files supported)\n",
        "        USE_BZIP2 (PKZIP 4.6+, using bzip2 lib version 1.0.8, 13-Jul-2019)\n",
        "        VMS_TEXT_CONV\n",
        "        WILD_STOP_AT_DIR\n",
        "        [decryption, version 2.11 of 05 Jan 2007]\n",
        "\n",
        "UnZip and ZipInfo environment options:\n",
        "           UNZIP:  [none]\n",
        "        UNZIPOPT:  [none]\n",
        "         ZIPINFO:  [none]\n",
        "      ZIPINFOOPT:  [none]\n",
    );

    /// `banner` + newline + `body`, as one text (a bad option prints the
    /// whole usage to standard error).
    fn whole(banner: &str, body: &str) -> &'static str {
        Box::leak(format!("{banner}\n{body}").into_boxed_str())
    }

    /// unzip.c:Zfirst.
    const Z_FIRST: &str =
        "error:  -Z must be first option for ZipInfo mode (check UNZIP variable?)\n";

    /// unzip.c:MustGiveExdir.
    const MUST_GIVE_EXDIR: &str =
        "error:  must specify directory to which to extract with -d option\n";

    /// unzip.c:InvalidOptionsMsg (on standard output under `-t`).
    const INVALID_OPTIONS: &str =
        "error:  -fn or any combination of -c, -l, -p, -t, -u and -v options invalid\n";

    /// End-of-central-directory not found (unzip's `find_ecrec` failure),
    /// for `name`, after `Archive:  name`.
    const NO_EOCD: &str = concat!(
        "  End-of-central-directory signature not found.  Either this file is not\n",
        "  a zipfile, or it constitutes one disk of a multi-part archive.  In the\n",
        "  latter case the central directory and zipfile comment will be found on\n",
        "  the last disk(s) of this archive.\n",
    );

    fn rows() -> Vec<Row> {
        use Which::*;
        let a = || vec![("a.zip", a_zip())];
        let mut v = Vec::new();
        // Usage, help, version, a bad option (Task 7). On Ubuntu `-v` is its
        // build options' (Task 13); the usage texts carry the `-O`/`-I`
        // lines of 20-unzip60-alt-iconv-utf8.patch (Task 14).
        for (who, task, version_task, usage, zipinfo, options, banner) in [
            (
                Apple,
                7,
                7,
                APPLE_USAGE,
                APPLE_ZIPINFO_USAGE,
                APPLE_OPTIONS,
                APPLE_UNZIP_BANNER,
            ),
            (
                Ubuntu,
                14,
                13,
                UBUNTU_USAGE,
                UBUNTU_ZIPINFO_USAGE,
                UBUNTU_OPTIONS,
                UBUNTU_UNZIP_BANNER,
            ),
        ] {
            v.extend([
                row(
                    who,
                    task,
                    "no arguments",
                    "unzip",
                    &[],
                    vec![],
                    0,
                    usage,
                    "",
                ),
                row(who, task, "-h", "unzip", &["-h"], vec![], 0, usage, ""),
                row(
                    who,
                    version_task,
                    "-v",
                    "unzip",
                    &["-v"],
                    vec![],
                    0,
                    options,
                    "",
                ),
                row(
                    who,
                    task,
                    "bad option",
                    "unzip",
                    &["-k", "a.zip"],
                    a(),
                    10,
                    "",
                    whole(banner, usage),
                ),
                row(
                    who,
                    task,
                    "zipinfo, no arguments",
                    "zipinfo",
                    &[],
                    vec![],
                    0,
                    zipinfo,
                    "",
                ),
                row(
                    who,
                    task,
                    "zipinfo -h",
                    "zipinfo",
                    &["-h"],
                    vec![],
                    0,
                    zipinfo,
                    "",
                ),
                row(who, task, "-Z", "unzip", &["-Z"], vec![], 0, zipinfo, ""),
                row(
                    who,
                    task,
                    "-Z -h",
                    "unzip",
                    &["-Z", "-h"],
                    vec![],
                    0,
                    zipinfo,
                    "",
                ),
                // Task 7's probes (2026-10-20): no archive, `-Z` late, the
                // environment's options (zipinfo mode reads ZIPINFO only).
                row(
                    who,
                    task,
                    "options, no archive",
                    "unzip",
                    &["-l"],
                    vec![],
                    10,
                    "",
                    whole(banner, usage),
                ),
                row(
                    who,
                    task,
                    "zipinfo, options, no archive",
                    "zipinfo",
                    &["-l"],
                    vec![],
                    0,
                    zipinfo,
                    "",
                ),
                row(
                    who,
                    task,
                    "zipinfo bad option",
                    "zipinfo",
                    &["-k"],
                    vec![],
                    10,
                    "",
                    whole(ZIPINFO_BANNER, zipinfo),
                ),
                row(
                    who,
                    task,
                    "-Z not first",
                    "unzip",
                    &["-lZ", "a.zip"],
                    a(),
                    10,
                    "",
                    Box::leak(format!("{Z_FIRST}{}", whole(banner, usage)).into_boxed_str()),
                ),
                row(who, task, "UNZIP alone", "unzip", &[], vec![], 0, usage, "")
                    .env(&[("UNZIP", "-q")]),
                row(
                    who,
                    task,
                    "UNZIP negated",
                    "unzip",
                    &["--v"],
                    vec![],
                    10,
                    "",
                    whole(banner, usage),
                )
                .env(&[("UNZIP", "-v")]),
                row(
                    who,
                    task,
                    "UNZIP -Z",
                    "unzip",
                    &["-l", "a.zip"],
                    a(),
                    10,
                    "",
                    Box::leak(format!("{Z_FIRST}{}", whole(banner, usage)).into_boxed_str()),
                )
                .env(&[("UNZIP", "-Z")]),
                row(
                    who,
                    task,
                    "ZIPINFO bad option",
                    "zipinfo",
                    &[],
                    vec![],
                    10,
                    "",
                    whole(ZIPINFO_BANNER, zipinfo),
                )
                .env(&[("ZIPINFO", "-k")]),
                row(
                    who,
                    task,
                    "-Z skips UNZIP",
                    "unzip",
                    &["-Z"],
                    vec![],
                    0,
                    zipinfo,
                    "",
                )
                .env(&[("UNZIP", "-k")]),
            ]);
        }
        // Task 7's probes both references answer alike (2026-10-20).
        let long: &'static str = Box::leak("a".repeat(16225).into_boxed_str());
        v.extend([
            // Ubuntu's extended help gains the patch's `-I`/`-O` lines.
            row(
                Both,
                7,
                "-hh",
                "unzip",
                &["-hh"],
                vec![],
                0,
                "\nExtended Help for UnZip\n",
                "",
            )
            .needs_patch("20-unzip60-alt-iconv-utf8.patch"),
            row(
                Both,
                7,
                "-vqqqq",
                "unzip",
                &["-vqqqq"],
                vec![],
                0,
                "600\n",
                "",
            ),
            row(
                Both,
                7,
                "-d alone",
                "unzip",
                &["-d"],
                vec![],
                10,
                "",
                MUST_GIVE_EXDIR,
            ),
            row(
                Both,
                7,
                "-d -x",
                "unzip",
                &["-d", "-x", "a.zip"],
                a(),
                10,
                "",
                MUST_GIVE_EXDIR,
            ),
            row(
                Both,
                7,
                "-d twice",
                "unzip",
                &["-d", "x", "-d", "y", "a.zip"],
                a(),
                10,
                "",
                "error:  -d option used more than once (only one exdir allowed)\n",
            ),
            row(
                Both,
                7,
                "-P alone",
                "unzip",
                &["-P"],
                vec![],
                10,
                "",
                "error:  must give decryption password with -P option\n",
            ),
            // Under -t the message and the usage go to standard output
            // (Ubuntu's usage has the patch's `-O`/`-I` lines).
            row(
                Both,
                7,
                "-ct",
                "unzip",
                &["-ct", "a.zip"],
                a(),
                10,
                INVALID_OPTIONS,
                "",
            )
            .needs_patch("20-unzip60-alt-iconv-utf8.patch"),
            row(
                Both,
                7,
                "UNZIP -t",
                "unzip",
                &["-c"],
                vec![],
                10,
                INVALID_OPTIONS,
                "",
            )
            .env(&[("UNZIP", "-t")])
            .needs_patch("20-unzip60-alt-iconv-utf8.patch"),
            row(
                Both,
                7,
                "argument too long",
                "unzip",
                &[long],
                vec![],
                10,
                "",
                "error:  command line parameter #1 exceeds internal size limit\n",
            ),
            row(
                Both,
                7,
                "UNZIP -v",
                "unzip",
                &[],
                vec![],
                0,
                "           UNZIP:  -v\n",
                "",
            )
            .env(&[("UNZIP", "-v")]),
            row(
                Both,
                7,
                "UNZIPOPT -v",
                "unzip",
                &[],
                vec![],
                0,
                "        UNZIPOPT:  -v\n",
                "",
            )
            .env(&[("UNZIPOPT", "-v")]),
            row(
                Both,
                7,
                "blank UNZIP, UNZIPOPT -v",
                "unzip",
                &[],
                vec![],
                0,
                "           UNZIP:     \n        UNZIPOPT:  -v\n",
                "",
            )
            .env(&[("UNZIP", "   "), ("UNZIPOPT", "-v")]),
            row(
                Both,
                7,
                "UNZIP quoted",
                "unzip",
                &["-v"],
                vec![],
                0,
                "           UNZIP:  -q \"-d\" x \"-\\q\"\n",
                "",
            )
            // `"-d"` and `x` are `-d x`; `"-\q"` unquotes to `-q`.
            .env(&[("UNZIP", r#"-q "-d" x "-\q""#)]),
        ]);
        // Opening the archive (Task 8): both builds answer alike.
        v.extend([
            row(
                Both,
                8,
                "missing archive",
                "unzip",
                &["nosuch"],
                vec![],
                9,
                "",
                "unzip:  cannot find or open nosuch, nosuch.zip or nosuch.ZIP.\n",
            ),
            row(
                Both,
                8,
                "not a zip",
                "unzip",
                &["notazip"],
                vec![("notazip", b"this is not a zip file\n".to_vec())],
                9,
                "Archive:  notazip\n",
                whole(
                    NO_EOCD.trim_end_matches('\n'),
                    "unzip:  cannot find zipfile directory in one of notazip or\n        \
                     notazip.zip, and cannot find notazip.ZIP, period.\n",
                ),
            ),
            // Under -t the same answer goes to standard output.
            row(
                Both,
                8,
                "truncated",
                "unzip",
                &["-t", "cut.zip"],
                vec![("cut.zip", truncated_zip())],
                9,
                whole(
                    &format!("Archive:  cut.zip\n{}", NO_EOCD.trim_end_matches('\n')),
                    "unzip:  cannot find zipfile directory in one of cut.zip or\n        \
                     cut.zip.zip, and cannot find cut.zip.ZIP, period.\n",
                ),
                "",
            ),
            // Testing it is Task 10's.
            row(
                Both,
                10,
                "preamble",
                "unzip",
                &["-t", "pre.zip"],
                vec![("pre.zip", preamble_zip())],
                1,
                concat!(
                    "Archive:  pre.zip\n",
                    "warning [pre.zip]:  17 extra bytes at beginning or within zipfile\n",
                    "  (attempting to process anyway)\n",
                    "    testing: a.txt                    OK\n",
                    "    testing: b.txt                    OK\n",
                    "No errors detected in compressed data of pre.zip.\n",
                ),
                "",
            ),
            // The caution is the extraction's (Task 10).
            row(
                Both,
                10,
                "no match",
                "unzip",
                &["a.zip", "nomatch"],
                a(),
                11,
                "Archive:  a.zip\n",
                "caution: filename not matched:  nomatch\n",
            ),
        ]);
        // Listing (Task 8): what does not print a date is the same in both
        // builds (Ubuntu's dates are year first: `DF_YMD`).
        v.extend([
            row(
                Both,
                8,
                "-l",
                "unzip",
                &["-l", "a.zip"],
                a(),
                0,
                "Archive:  a.zip\n  Length      Date    Time    Name\n---------  ---------- -----   ----\n",
                "",
            ),
            row(
                Both,
                8,
                "-l totals",
                "unzip",
                &["-l", "a.zip"],
                a(),
                0,
                "---------                     -------\n     2206                     2 files\n",
                "",
            ),
            row(
                Both,
                8,
                "-v",
                "unzip",
                &["-v", "a.zip"],
                a(),
                0,
                concat!(
                    " Length   Method    Size  Cmpr    Date    Time   CRC-32   Name\n",
                    "--------  ------  ------- ---- ---------- ----- --------  ----\n",
                ),
                "",
            ),
            row(
                Both,
                8,
                "-v entry",
                "unzip",
                &["-v", "a.zip"],
                a(),
                0,
                "       6  Stored        6   0% ",
                "",
            ),
            row(
                Both,
                8,
                "-z",
                "unzip",
                &["-z", "c.zip"],
                vec![("c.zip", comment_zip())],
                0,
                "Archive:  c.zip\narchive\ncomment^[[1m here\nend\n",
                "",
            ),
            row(
                Both,
                8,
                "-l comment",
                "unzip",
                &["-l", "c.zip"],
                vec![("c.zip", comment_zip())],
                0,
                "Archive:  c.zip\narchive\ncomment^[[1m here\nend\n  Length",
                "",
            ),
            row(
                Both,
                8,
                "-lq",
                "unzip",
                &["-lq", "a.zip"],
                a(),
                0,
                "  Length      Date    Time    Name\n",
                "",
            ),
            row(
                Both,
                8,
                "-lqq",
                "unzip",
                &["-lqq", "a.zip"],
                a(),
                0,
                "   a.txt\n",
                "",
            ),
            row(
                Both,
                8,
                "-l include and exclude",
                "unzip",
                &["-l", "a.zip", "*.txt", "-x", "b.txt"],
                a(),
                0,
                "     1 file\n",
                "",
            ),
            row(
                Both,
                8,
                "-l no match",
                "unzip",
                &["-l", "a.zip", "B.TXT"],
                a(),
                11,
                "        0                     0 files\n",
                "",
            ),
            row(
                Both,
                8,
                "-lC",
                "unzip",
                &["-lC", "a.zip", "B.TXT"],
                a(),
                0,
                "   b.txt\n",
                "",
            ),
            // One archive of three has no end record: the only text on
            // standard error is its own and the summary's, whatever order
            // the directory lists them in.
            row(
                Both,
                8,
                "-l by wildcard",
                "unzip",
                &["-l", "*.zip"],
                vec![
                    ("a.zip", a_zip()),
                    ("c.zip", comment_zip()),
                    ("bad.zip", b"junk".to_vec()),
                ],
                9,
                "Archive:  bad.zip\n",
                concat!(
                    "  End-of-central-directory signature not found.  Either this file is not\n",
                    "  a zipfile, or it constitutes one disk of a multi-part archive.  In the\n",
                    "  latter case the central directory and zipfile comment will be found on\n",
                    "  the last disk(s) of this archive.\n",
                    "\n",
                    "2 archives were successfully processed.\n",
                    "1 file had no zipfile directory.\n",
                ),
            ),
            row(
                Both,
                8,
                "wildcard matching nothing",
                "unzip",
                &["-l", "nomatch*.zip"],
                a(),
                9,
                "",
                "unzip:  cannot find or open nomatch*.zip, nomatch*.zip.zip or nomatch*.zip.ZIP.\n\nNo zipfiles found.\n",
            ),
            row(
                Both,
                8,
                "-l a directory",
                "unzip",
                &["-l", "d"],
                vec![("d/x", b"x".to_vec())],
                9,
                "",
                "unzip:  cannot find or open d, d.zip or d.ZIP.\n",
            ),
            row(
                Both,
                8,
                "-l .zip added",
                "unzip",
                &["-l", "a"],
                a(),
                0,
                "Archive:  a.zip\n",
                "",
            ),
            row(
                Both,
                8,
                "-l not a zip",
                "unzip",
                &["-l", "notazip"],
                vec![("notazip", b"this is not a zip file\n".to_vec())],
                9,
                "Archive:  notazip\n",
                whole(
                    NO_EOCD.trim_end_matches('\n'),
                    "unzip:  cannot find zipfile directory in one of notazip or\n        \
                     notazip.zip, and cannot find notazip.ZIP, period.\n",
                ),
            ),
            row(
                Both,
                8,
                "-lq truncated",
                "unzip",
                &["-lq", "cut.zip"],
                vec![("cut.zip", truncated_zip())],
                9,
                "",
                whole(
                    &format!("[cut.zip]\n{}", NO_EOCD.trim_end_matches('\n')),
                    "unzip:  cannot find zipfile directory in one of cut.zip or\n        \
                     cut.zip.zip, and cannot find cut.zip.ZIP, period.\n",
                ),
            ),
            row(
                Both,
                8,
                "-l preamble",
                "unzip",
                &["-l", "pre.zip"],
                vec![("pre.zip", preamble_zip())],
                1,
                "     2206                     2 files\n",
                concat!(
                    "warning [pre.zip]:  17 extra bytes at beginning or within zipfile\n",
                    "  (attempting to process anyway)\n",
                ),
            ),
            row(
                Both,
                8,
                "-l comment only",
                "unzip",
                &["-l", "conly.zip"],
                vec![("conly.zip", comment_only_zip())],
                1,
                "Archive:  conly.zip\njust a comment\n",
                "warning [conly.zip]:  zipfile is empty\n",
            ),
            row(
                Both,
                8,
                "-z comment only",
                "unzip",
                &["-z", "conly.zip"],
                vec![("conly.zip", comment_only_zip())],
                0,
                "Archive:  conly.zip\njust a comment\n",
                "",
            ),
            row(
                Both,
                8,
                "-l empty",
                "unzip",
                &["-l", "empty.zip"],
                vec![("empty.zip", empty_zip())],
                1,
                "Archive:  empty.zip\n",
                "warning [empty.zip]:  zipfile is empty\n",
            ),
        ]);
        // zipinfo's listings (Task 9): zi_time() takes no DATE_FORMAT, so
        // both builds print the same dates.
        let enc = || vec![("e.zip", encrypted_zip())];
        v.extend([
            row(
                Both,
                9,
                "zipinfo",
                "zipinfo",
                &["a.zip"],
                a(),
                0,
                "-rw-r--r--  3.0 unx        6 b- stor 20-Jan-02 03:04 a.txt\n",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo totals",
                "zipinfo",
                &["a.zip"],
                a(),
                0,
                "2 files, 2206 bytes uncompressed, ",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo -1",
                "zipinfo",
                &["-1", "a.zip"],
                a(),
                0,
                "a.txt\nb.txt\n",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo -2ht",
                "zipinfo",
                &["-2ht", "a.zip"],
                a(),
                0,
                "a.txt\nb.txt\n2 files, 2206 bytes uncompressed, ",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo -m",
                "zipinfo",
                &["-m", "a.zip"],
                a(),
                0,
                "-rw-r--r--  3.0 unx        6 b-  0% stor 20-Jan-02 03:04 a.txt\n",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo -l",
                "zipinfo",
                &["-l", "a.zip"],
                a(),
                0,
                "-rw-r--r--  3.0 unx        6 b-        6 stor 20-Jan-02 03:04 a.txt\n",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo -T",
                "zipinfo",
                &["-T", "a.zip"],
                a(),
                0,
                " stor 20200102.030406 a.txt\n",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo -v",
                "zipinfo",
                &["-v", "a.zip"],
                a(),
                0,
                concat!(
                    "\nCentral directory entry #1:\n---------------------------\n\n  a.txt\n\n",
                    "  offset of local header from start of archive:   0\n",
                    "                                                  (0000000000000000h) bytes\n",
                    "  file system or operating system of origin:      Unix\n",
                ),
                "",
            ),
            row(
                Both,
                9,
                "zipinfo -v times",
                "zipinfo",
                &["-v", "a.zip"],
                a(),
                0,
                "  file last modified on (DOS date/time):          2020 Jan 2 03:04:06\n",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo -h",
                "zipinfo",
                &["-h", "a.zip"],
                a(),
                0,
                "Archive:  a.zip\nZip file size: ",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo -z",
                "zipinfo",
                &["-z", "c.zip"],
                vec![("c.zip", comment_zip())],
                0,
                "Archive:  c.zip\narchive\ncomment^[[1m here\nend\nZip file size: ",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo encrypted",
                "zipinfo",
                &["-m", "e.zip"],
                enc(),
                0,
                "       12 B-  0% stor 20-Jan-02 03:04 s.txt\n1 file, 12 bytes uncompressed, 12 bytes compressed:  0.0%\n",
                "",
            ),
            row(
                Both,
                9,
                "unzip -Z",
                "unzip",
                &["-Z", "a.zip"],
                a(),
                0,
                "-rw-r--r--  3.0 unx        6 b- stor 20-Jan-02 03:04 a.txt\n",
                "",
            ),
            row(
                Both,
                9,
                "unzip -Z1",
                "unzip",
                &["-Z1", "a.zip"],
                a(),
                0,
                "a.txt\nb.txt\n",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo include and exclude",
                "zipinfo",
                &["a.zip", "*.txt", "-x", "b.txt"],
                a(),
                0,
                " a.txt\n",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo no match",
                "zipinfo",
                &["a.zip", "nomatch"],
                a(),
                11,
                "",
                "caution: filename not matched:  nomatch\n",
            ),
            row(
                Both,
                9,
                "zipinfo -t no match",
                "zipinfo",
                &["-t", "a.zip", "nomatch", "-x", "nox"],
                a(),
                11,
                concat!(
                    "0 files, 0 bytes uncompressed, 0 bytes compressed:  0.0%\n",
                    "caution: filename not matched:  nomatch\n",
                    "caution: excluded filename not matched:  nox\n",
                ),
                "",
            ),
            row(
                Both,
                9,
                "zipinfo empty",
                "zipinfo",
                &["empty.zip"],
                vec![("empty.zip", empty_zip())],
                1,
                "Empty zipfile.\n",
                "",
            ),
            row(
                Both,
                9,
                "zipinfo not a zip",
                "zipinfo",
                &["notazip"],
                vec![("notazip", b"just text\n".to_vec())],
                9,
                "",
                "",
            ),
        ]);
        // The locale unzip.c's `setlocale(LC_CTYPE, "")` takes, as Apple's
        // libc reads it (P24): `UTF-8` alone is a macOS locale, a missing
        // one leaves C, ISO8859-1 prints the Latin-1 letters. `\u{fffd}` is
        // how the check's lossy view shows each high byte let through.
        let high = || vec![("h.zip", high_zip())];
        for (label, env, shown) in [
            (
                "locale LC_CTYPE=UTF-8",
                ("LC_CTYPE", "UTF-8"),
                "c?\u{fffd}?\u{fffd}\u{fffd}?.txt\n",
            ),
            (
                "locale xx_XX.UTF-8",
                ("LANG", "xx_XX.UTF-8"),
                "c??????.txt\n",
            ),
            (
                "locale ISO8859-1",
                ("LC_CTYPE", "en_US.ISO8859-1"),
                "c???\u{fffd}\u{fffd}?.txt\n",
            ),
        ] {
            v.push(
                row(
                    Apple,
                    9,
                    label,
                    "zipinfo",
                    &["-1", "h.zip"],
                    high(),
                    0,
                    shown,
                    "",
                )
                .env(&[env]),
            );
            v.push(
                row(
                    Apple,
                    9,
                    label,
                    "unzip",
                    &["-l", "h.zip"],
                    high(),
                    0,
                    shown,
                    "",
                )
                .env(&[env]),
            );
        }
        // Testing entries (Task 10), passwords (Task 11).
        v.extend([
            row(
                Both,
                10,
                "-t CRC mismatch",
                "unzip",
                &["-t", "crc.zip"],
                vec![("crc.zip", crc_zip())],
                2,
                concat!(
                    "Archive:  crc.zip\n",
                    "    testing: a.txt                    bad CRC 0ae44a4e  (should be 9f606eec)\n",
                    "At least one error was detected in crc.zip.\n",
                ),
                "",
            ),
            row(
                Both,
                10,
                "-t unsupported method",
                "unzip",
                &["-t", "m7.zip"],
                vec![("m7.zip", method_zip())],
                81,
                concat!(
                    "Archive:  m7.zip\n",
                    "   skipping: t.txt                   `tokenize' method not supported\n",
                    "Caution:  zero files tested in m7.zip.\n",
                    "1 file skipped because of unsupported compression or encoding.\n",
                ),
                "",
            ),
            row(
                Both,
                11,
                "wrong -P",
                "unzip",
                &["-P", "wrong", "-t", "enc.zip"],
                vec![("enc.zip", encrypted_zip())],
                82,
                concat!(
                    "Archive:  enc.zip\n",
                    "   skipping: s.txt                   incorrect password\n",
                    "Caution:  zero files tested in enc.zip.\n",
                    "1 file skipped because of incorrect password.\n",
                ),
                "",
            ),
            row(
                Both,
                11,
                "right -P",
                "unzip",
                &["-P", "secret", "-t", "enc.zip"],
                vec![("enc.zip", encrypted_zip())],
                0,
                concat!(
                    "Archive:  enc.zip\n",
                    "    testing: s.txt                    OK\n",
                    "No errors detected in compressed data of enc.zip.\n",
                ),
                "",
            ),
        ]);
        // At the terminal (Task 11, R12): the password prompt on the
        // controlling terminal, the questions typed there, `-M`, `^S`.
        let enc = || vec![("enc.zip", encrypted_zip())];
        let hide = "\r                                                         \r";
        let more =
            |ns: &[u32]| -> String { ns.iter().map(|n| format!("--More--({n}){hide}")).collect() };
        let keys = |k: &[u8]| -> Vec<u8> { k.iter().flat_map(|&b| [b, TTY_BREAK]).collect() };
        let quit = "--- Press `Q' to quit, or any other key to continue ---";
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        v.extend([
            row(
                Both,
                11,
                "prompt: right password",
                "unzip",
                &["-t", "enc.zip"],
                enc(),
                0,
                "    testing: s.txt                    OK\n",
                "[enc.zip] s.txt password: \n",
            )
            .typed(b"secret\n"),
            row(
                Both,
                11,
                "prompt: wrong then right",
                "unzip",
                &["-t", "enc.zip"],
                enc(),
                0,
                "    testing: s.txt                    OK\n",
                "[enc.zip] s.txt password: \npassword incorrect--reenter: \n",
            )
            .typed(b"wrong\nsecret\n"),
            row(
                Both,
                11,
                "prompt: wrong three times",
                "unzip",
                &["-t", "enc.zip"],
                enc(),
                82,
                "   skipping: s.txt                   incorrect password\n",
                concat!(
                    "[enc.zip] s.txt password: \n",
                    "password incorrect--reenter: \n",
                    "password incorrect--reenter: \n",
                ),
            )
            .typed(b"wrong\nbad\nworse\n"),
            row(
                Both,
                11,
                "prompt: empty answer",
                "unzip",
                &["-t", "enc.zip"],
                enc(),
                82,
                "1 file skipped because of incorrect password.\n",
                "[enc.zip] s.txt password: \n",
            )
            .typed(b"\n"),
            row(
                Both,
                11,
                "prompt: mixed archive",
                "unzip",
                &["-t", "mix.zip"],
                vec![("mix.zip", mixed_zip())],
                0,
                "No errors detected in compressed data of mix.zip.\n",
                "[mix.zip] s.txt password: \n",
            )
            .typed(b"secret\n"),
            row(
                Both,
                11,
                "-P ''",
                "unzip",
                &["-P", "", "-t", "mix.zip"],
                vec![("mix.zip", mixed_zip())],
                1,
                concat!(
                    "   skipping: s.txt                   incorrect password\n",
                    "    testing: t.txt                    OK\n",
                    "No errors detected in mix.zip for the 2 files tested.\n",
                    "1 file skipped because of incorrect password.\n",
                ),
                "",
            ),
            row(
                Both,
                11,
                "no terminal: unable to get password",
                "unzip",
                &["-t", "mix.zip"],
                vec![("mix.zip", mixed_zip())],
                5,
                "   skipping: s.txt                   unable to get password\n",
                "",
            ),
            row(
                Both,
                11,
                "[r]ename at a terminal",
                "unzip",
                &["ow.zip"],
                overwrite_files(),
                0,
                " extracting: c.txt                   \n",
                concat!(
                    "replace a.txt? [y]es, [n]o, [A]ll, [N]one, [r]ename: new name: ",
                    "replace b.txt? [y]es, [n]o, [A]ll, [N]one, [r]ename: ",
                ),
            )
            .typed(b"r\nc.txt\nn\n"),
            row(
                Apple,
                11,
                "-M listing",
                "unzip",
                &["-M", "-l", "many.zip"],
                vec![("many.zip", many_zip())],
                0,
                "       41  01-02-2020 03:04   f41.txt\r\n",
                leak(more(&[22, 44, 45])),
            )
            .typed(&keys(b" \nq"))
            .stdout_tty(),
            row(
                Both,
                11,
                "-M testing",
                "unzip",
                &["-M", "-t", "many.zip"],
                vec![("many.zip", many_zip())],
                0,
                "    testing: f43.txt                  OK\r\n",
                leak(more(&[22, 44, 45])),
            )
            .typed(&keys(b" \nq"))
            .stdout_tty(),
            row(
                Apple,
                11,
                "-Mh paged to a pipe",
                "unzip",
                &["-Mh"],
                vec![],
                0,
                "Usage: unzip ",
                leak(more(&[22])),
            )
            .piped(b" "),
            row(
                Both,
                11,
                "^S in a comment, then q",
                "unzip",
                &["-o", "cs.zip"],
                vec![("cs.zip", comment_pauses_zip())],
                0,
                "Archive:  cs.zip\nline one\n",
                leak(format!("{quit}{hide}")),
            )
            .piped(b"q"),
            row(
                Both,
                11,
                "^S in a comment at a terminal",
                "unzip",
                &["-o", "cs.zip"],
                vec![("cs.zip", comment_pauses_zip())],
                0,
                "line twomore\nend\n extracting: c.txt",
                leak(format!("{quit}{hide}\n{quit}{hide}")),
            )
            .typed(&keys(b"x ")),
        ]);
        // Extraction (Task 10), as both references extract.
        let up = || {
            vec![(
                "up.zip",
                zip_with(
                    &[
                        ZipEntrySpec::new(b"../up.txt", b"up\n"),
                        ZipEntrySpec::new(b"/abs.txt", b"abs\n"),
                    ],
                    b"",
                    b"",
                ),
            )]
        };
        let linked = || {
            vec![(
                "l.zip",
                zip_with(
                    &[
                        ZipEntrySpec::new(b"a.txt", b"alpha\n"),
                        ZipEntrySpec {
                            external_attr: 0o120777 << 16,
                            ..ZipEntrySpec::new(b"l", b"a.txt")
                        },
                    ],
                    b"",
                    b"",
                ),
            )]
        };
        let existing = || {
            let mut f = a();
            f.push(("a.txt", b"already here\n".to_vec()));
            f
        };
        v.extend([
            row(
                Both,
                10,
                "extract",
                "unzip",
                &["a.zip"],
                a(),
                0,
                concat!(
                    "Archive:  a.zip\n",
                    " extracting: a.txt                   \n",
                    "  inflating: b.txt                   \n",
                ),
                "",
            ),
            row(Both, 10, "-p", "unzip", &["-p", "a.zip", "a.txt"], a(), 0, "alpha\n", ""),
            row(
                Both,
                10,
                "-d, made",
                "unzip",
                &["-d", "new", "a.zip"],
                a(),
                0,
                " extracting: new/a.txt               \n",
                "",
            ),
            row(
                Both,
                10,
                "../ and absolute names",
                "unzip",
                &["up.zip"],
                up(),
                1,
                concat!(
                    "warning:  skipped \"../\" path component(s) in ../up.txt\n",
                    " extracting: up.txt                  \n",
                ),
                "warning:  stripped absolute path spec from /abs.txt\n",
            ),
            row(
                Both,
                10,
                "existing file, no answer",
                "unzip",
                &["a.zip"],
                existing(),
                1,
                "  inflating: b.txt                   \n",
                "replace a.txt? [y]es, [n]o, [A]ll, [N]one, [r]ename:  NULL\n(EOF or read error, treating as \"[N]one\" ...)\n",
            ),
            row(
                Both,
                10,
                "existing file, -n",
                "unzip",
                &["-n", "a.zip"],
                existing(),
                0,
                "Archive:  a.zip\n  inflating: b.txt                   \n",
                "",
            ),
            row(
                Both,
                10,
                "existing file, -o",
                "unzip",
                &["-o", "a.zip"],
                existing(),
                0,
                " extracting: a.txt                   \n",
                "",
            ),
            row(
                Both,
                10,
                "a symlink, deferred",
                "unzip",
                &["l.zip"],
                linked(),
                0,
                concat!(
                    "    linking: l                       -> a.txt \n",
                    "finishing deferred symbolic links:\n",
                    "  l                      -> a.txt\n",
                ),
                "",
            ),
        ]);
        // The overlapped archive: Apple tests both entries; Ubuntu's
        // bomb-detection patch (Task 14) stops at the second, exit 12.
        v.extend([
            row(
                Apple,
                10,
                "overlapped",
                "unzip",
                &["-t", "bomb.zip"],
                vec![("bomb.zip", overlapped_zip())],
                0,
                concat!(
                    "Archive:  bomb.zip\n",
                    "    testing: o.txt                    OK\n",
                    "    testing: o.txt                    OK\n",
                    "No errors detected in compressed data of bomb.zip.\n",
                ),
                "",
            ),
            row(
                Ubuntu,
                14,
                "overlapped",
                "unzip",
                &["-t", "bomb.zip"],
                vec![("bomb.zip", overlapped_zip())],
                12,
                concat!(
                    "Archive:  bomb.zip\n",
                    "    testing: o.txt                    OK\n",
                    "error: invalid zip file with overlapped components (possible zip bomb)\n",
                ),
                "",
            ),
        ]);
        // funzip (Task 12): the first entry or a gzip member, from standard
        // input or a file (both references gave every row).
        let more = "funzip warning: zipfile has more than one entry--rest ignored\n";
        let fz = |e: &str| -> &'static str {
            match e {
                "" => "",
                _ => Box::leak(format!("funzip error: {e}\n").into_boxed_str()),
            }
        };
        for (label, args, stdin, code, out, err) in [
            ("funzip a zip", &[][..], a_zip(), 0, "alpha\n", more),
            (
                "funzip stored",
                &[],
                fz_zip(0, 0, b"alpha\n"),
                0,
                "alpha\n",
                "",
            ),
            (
                "funzip deflated",
                &[],
                fz_zip(8, 0, &text()),
                0,
                "the quick",
                "",
            ),
            (
                "funzip deflate64",
                &[],
                fz_zip(9, 0, &text()),
                4,
                "the quick",
                fz("invalid compressed data--crc error"),
            ),
            ("funzip directory first", &[], fz_dir_zip(), 0, "", more),
            (
                "funzip method 12",
                &[],
                fz_zip(12, 0, b"BZh9"),
                3,
                "",
                fz("first entry not deflated or stored--cannot unpack"),
            ),
            (
                "funzip method 264",
                &[],
                fz_zip(0x108, 0, b"x"),
                3,
                "",
                fz("first entry not deflated or stored--cannot unpack"),
            ),
            (
                "funzip encrypted stored",
                &["-pw"],
                fz_enc(0, b"secret\n", 0),
                0,
                "secret\n",
                "",
            ),
            (
                "funzip encrypted deflated",
                &["-pw"],
                fz_enc(8, &text(), 0),
                0,
                "the quick",
                "",
            ),
            (
                "funzip encrypted streamed",
                &["-pw"],
                fz_enc(8, &text(), 8),
                0,
                "the quick",
                "",
            ),
            (
                "funzip wrong password",
                &["-px"],
                fz_enc(8, &text(), 0),
                3,
                "",
                fz("incorrect password for first entry"),
            ),
            (
                "funzip no tty for a password",
                &[],
                fz_enc(0, b"secret\n", 0),
                1,
                "",
                fz("no tty to prompt for password"),
            ),
            (
                "funzip encrypted cut short",
                &["-pw"],
                fz_cut(fz_enc(8, &text(), 0), 70),
                4,
                "",
                fz("invalid compressed data--format violated"),
            ),
            (
                "funzip encrypted header cut",
                &["-pw"],
                fz_cut(fz_enc(8, &text(), 0), 40),
                3,
                "",
                fz("incorrect password for first entry"),
            ),
            (
                "funzip a gzip",
                &[],
                gzm(b"gzip data\n", b"g.txt"),
                0,
                "gzip data\n",
                "",
            ),
            (
                "funzip gzip extra name comment",
                &[],
                fz_gzip_xnc(),
                0,
                "gzip data\n",
                "",
            ),
            (
                "funzip gzip header crc",
                &[],
                fz_gzip_hcrc(),
                3,
                "",
                fz("cannot handle multi-part gzip files"),
            ),
            (
                "funzip gzip two members",
                &[],
                [gzm(b"one\n", b"1"), gzm(b"two\n", b"2")].concat(),
                0,
                "one\n",
                "",
            ),
            (
                "funzip gzip trailing garbage",
                &[],
                [gzm(b"gzip data\n", b"g"), b"garbage".to_vec()].concat(),
                0,
                "gzip data\n",
                "",
            ),
            (
                "funzip gzip method 7",
                &[],
                fz_gzip_method(7),
                3,
                "",
                fz("gzip file not deflated"),
            ),
            (
                "funzip gzip method 9",
                &[],
                fz_gzip_method(9),
                4,
                "the quick",
                fz("invalid compressed data--crc error"),
            ),
            (
                "funzip gzip cut header",
                &[],
                b"\x1f\x8b\x08\x00".to_vec(),
                3,
                "",
                fz("invalid gzip file"),
            ),
            (
                "funzip gzip cut trailer",
                &[],
                fz_cut(gzm(b"gzip data\n", b"g"), -4),
                3,
                "gzip data\n",
                fz("gzip file ended prematurely"),
            ),
            (
                "funzip gzip bad crc",
                &[],
                fz_gzip_crc(),
                4,
                "gzip data\n",
                fz("invalid compressed data--crc error"),
            ),
            (
                "funzip garbage",
                &[],
                b"garbage\n".to_vec(),
                3,
                "",
                fz("input not a zip or gzip file"),
            ),
            (
                "funzip empty",
                &[],
                vec![],
                3,
                "",
                fz("input not a zip or gzip file"),
            ),
            (
                "funzip one byte",
                &[],
                b"P".to_vec(),
                3,
                "",
                fz("input not a zip or gzip file"),
            ),
            (
                "funzip end record",
                &[],
                fz_cut(a_zip(), -22),
                0,
                "alpha\n",
                more,
            ),
            (
                "funzip only PK",
                &[],
                b"PK\x05\x06".to_vec(),
                3,
                "",
                fz("invalid zipfile"),
            ),
            (
                "funzip deflate cut short",
                &[],
                fz_cut(fz_zip(8, 0, &text()), 60),
                4,
                "",
                fz("invalid compressed data--format violated"),
            ),
            (
                "funzip stored cut short",
                &[],
                fz_cut(fz_zip(0, 0, &text()), 100),
                4,
                "the quick",
                fz("invalid compressed data--crc error"),
            ),
            (
                "funzip stored sizes differ",
                &[],
                fz_stored_mismatch(),
                4,
                "",
                "len 7, siz 5\nfunzip error: invalid compressed data--length mismatch\n",
            ),
            (
                "funzip stored streamed",
                &[],
                fz_zip(0, 8, b"hello"),
                4,
                "",
                fz("invalid compressed data--crc error"),
            ),
            (
                "funzip deflated streamed",
                &[],
                fz_zip(8, 8, &text()),
                0,
                "the quick",
                "",
            ),
            (
                "funzip descriptor cut",
                &[],
                fz_cut(fz_zip(8, 8, &text()), -27),
                3,
                "the quick",
                fz("zipfile ended prematurely"),
            ),
            (
                "funzip incomplete l-tree",
                &[],
                fz_ltree(),
                4,
                "",
                "(incomplete l-tree)  funzip error: invalid compressed data--format violated\n",
            ),
            (
                "funzip -h piped",
                &["-h"],
                vec![],
                3,
                "",
                fz("input not a zip or gzip file"),
            ),
        ] {
            v.push(row(Both, 12, label, "funzip", args, vec![], code, out, err).piped(&stdin));
        }
        // An encrypted deflate stream cut short: past the end funzip's
        // NEXTBYTE gives `EOF ^ decrypt_byte()`, a negative `int` but not
        // `EOF` (`ByteSource::next_bits`), and inflate decodes on.
        let violated = fz("invalid compressed data--format violated");
        for (cut, out, err) in [
            (
                55,
                "",
                "(incomplete l-tree)  funzip error: invalid compressed data--format violated\n",
            ),
            (60, "", violated),
            (65, "", violated),
            (70, "the iqqqqqqqq", violated),
            (75, "", violated),
            (80, "", violated),
            (90, "the lavqqqqqqqq", violated),
            (100, "", violated),
        ] {
            let label: &'static str =
                Box::leak(format!("funzip encrypted cut at {cut}").into_boxed_str());
            v.push(
                row(Both, 12, label, "funzip", &["-pw"], vec![], 4, out, err)
                    .piped(&fz_cut(fz_enc(8, &text(), 0), cut)),
            );
        }
        let usage: &'static str = Box::leak(
            format!("{FUNZIP_BANNER}\n{}", concat!(
                "usage: ... | funzip [-password] | ...\n",
                "       ... | funzip [-password] > outfile\n",
                "       funzip [-password] infile.zip > outfile\n",
                "       funzip [-password] infile.gz > outfile\n",
                "Extracts to stdout the gzip file or first zip entry of stdin or the given file.\n",
            ))
            .into_boxed_str(),
        );
        v.extend([
            row(
                Both,
                12,
                "funzip a file",
                "funzip",
                &["f.zip"],
                vec![("f.zip", fz_zip(8, 0, &text()))],
                0,
                "the quick",
                "",
            ),
            row(
                Both,
                12,
                "funzip a password and a file",
                "funzip",
                &["-pw", "e.zip", "x"],
                vec![("e.zip", fz_enc(0, b"secret\n", 0))],
                0,
                "secret\n",
                "",
            ),
            row(
                Both,
                12,
                "funzip no such file",
                "funzip",
                &["nosuch"],
                vec![],
                2,
                "",
                "funzip error: cannot find input file\n",
            ),
            row(
                Both,
                12,
                "funzip an empty name",
                "funzip",
                &[""],
                vec![],
                2,
                "",
                "funzip error: cannot find input file\n",
            ),
            row(
                Both,
                12,
                "funzip a directory",
                "funzip",
                &["."],
                vec![],
                3,
                "",
                "funzip error: input not a zip or gzip file\n",
            ),
            // standard input a terminal: the usage
            row(
                Both,
                12,
                "funzip usage",
                "funzip",
                &[],
                vec![],
                3,
                "",
                usage,
            )
            .typed(b""),
            row(
                Both,
                12,
                "funzip -h usage",
                "funzip",
                &["-h"],
                vec![],
                3,
                "",
                usage,
            )
            .typed(b""),
            // the password typed at the terminal
            row(
                Both,
                12,
                "funzip typed password",
                "funzip",
                &["e.zip"],
                vec![("e.zip", fz_enc(8, &text(), 0))],
                0,
                "the quick",
                "Enter password: \n",
            )
            .typed(b"pw\n"),
            row(
                Both,
                12,
                "funzip typed wrong password",
                "funzip",
                &["e.zip"],
                vec![("e.zip", fz_enc(8, &text(), 0))],
                3,
                "",
                "Enter password: \nfunzip error: incorrect password for first entry\n",
            )
            .typed(b"no\n"),
        ]);
        v
    }

    // ---- funzip's fixtures (Task 12) ----

    /// A local header for `data` under `method` and `flags` (bit 3: a
    /// signed data descriptor follows), one name byte, the data (deflated
    /// for 8 and 9, else as is), and an end record.
    fn fz_zip(method: u16, flags: u16, data: &[u8]) -> Vec<u8> {
        let body = if matches!(method, 8 | 9) {
            deflate_raw(data)
        } else {
            data.to_vec()
        };
        fz_local(method, flags, &body, data, crc32(data))
    }

    fn fz_local(method: u16, flags: u16, body: &[u8], data: &[u8], crc: u32) -> Vec<u8> {
        let dd = flags & 8 != 0;
        let mut v = b"PK\x03\x04".to_vec();
        for x in [20u16, flags, method, 0x1883, 0x5022] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        let sizes = [crc, body.len() as u32, data.len() as u32];
        for x in if dd { [0; 3] } else { sizes } {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&[1, 0, 0, 0, b'a']);
        v.extend_from_slice(body);
        if dd {
            v.extend_from_slice(b"PK\x07\x08");
            for x in sizes {
                v.extend_from_slice(&x.to_le_bytes());
            }
        }
        v.extend_from_slice(b"PK\x05\x06");
        v.extend_from_slice(&[0; 18]);
        v
    }

    /// `data` under `method`, encrypted with `pw` (check byte: the CRC's
    /// high byte, or the DOS time's under flag bit 3 in `flags`).
    fn fz_enc(method: u16, data: &[u8], flags: u16) -> Vec<u8> {
        let body = if method == 8 {
            deflate_raw(data)
        } else {
            data.to_vec()
        };
        let check = if flags & 8 != 0 {
            0x18
        } else {
            (crc32(data) >> 24) as u8
        };
        fz_local(
            method,
            flags | 1,
            &zipcrypto(b"pw", check, &body),
            data,
            crc32(data),
        )
    }

    /// `v` cut to `n` bytes (`n` < 0: that many fewer).
    fn fz_cut(mut v: Vec<u8>, n: isize) -> Vec<u8> {
        let n = if n < 0 {
            v.len() - n.unsigned_abs()
        } else {
            n as usize
        };
        v.truncate(n);
        v
    }

    /// A directory entry, then a file.
    fn fz_dir_zip() -> Vec<u8> {
        zip_with(
            &[
                ZipEntrySpec::new(b"d/", b""),
                ZipEntrySpec::new(b"d/a", b"x"),
            ],
            b"",
            b"",
        )
    }

    /// A stored entry whose sizes say 5 and 7.
    fn fz_stored_mismatch() -> Vec<u8> {
        let mut v = fz_zip(0, 0, b"hello");
        v[22..26].copy_from_slice(&7u32.to_le_bytes());
        v
    }

    /// A gzip member with FEXTRA, FNAME and FCOMMENT.
    fn fz_gzip_xnc() -> Vec<u8> {
        member(Member {
            extra: Some(b"AB\x02\x00hi"),
            name: Some(b"g.txt"),
            comment: Some(b"c"),
            ..plain_member(b"gzip data\n")
        })
    }

    /// A gzip member with FHCRC (funzip's "multi-part" bit).
    fn fz_gzip_hcrc() -> Vec<u8> {
        member(Member {
            hcrc: true,
            ..plain_member(b"gzip data\n")
        })
    }

    /// The text as a gzip member whose method byte is `method`.
    fn fz_gzip_method(method: u8) -> Vec<u8> {
        let mut v = member(plain_member(&text()));
        v[2] = method;
        v
    }

    /// A gzip member whose trailer has the wrong CRC.
    fn fz_gzip_crc() -> Vec<u8> {
        member_with(plain_member(b"gzip data\n"), Some(1), None)
    }

    /// A dynamic block whose literal/length tree is incomplete
    /// (`stuffr-formats`' hand stream `l-tree-incomplete`).
    fn fz_ltree() -> Vec<u8> {
        let mut body = vec![0x05, 0xc0, 0x01, 0x04, 0x00, 0x00, 0x00, 0x80, 0x20];
        body.extend_from_slice(&[0; 12]);
        body.push(0x01);
        body.extend_from_slice(&[0; 19]);
        body.push(0x07);
        fz_local(8, 0, &body, b"x", crc32(b"x"))
    }

    // ---- checks ----

    /// The table, run on this platform's reference alone (always on): every
    /// row's exit code, standard output text and standard error are what was
    /// recorded, so a changed reference or a wrong transcription fails here,
    /// not in the task that enables the row.
    #[test]
    fn recorded_rows_hold_on_the_reference() {
        let rows: Vec<Row> = rows().into_iter().filter(Row::runs_here).collect();
        let mut bad = Vec::new();
        let mut ran = 0;
        for r in &rows {
            // No reference: a skip (a panic under CI); the rows already
            // judged are still reported.
            let Some(run) = unzip_reference(&r.case()) else {
                continue;
            };
            ran += 1;
            let stdout = String::from_utf8_lossy(&run.stdout);
            if run.code != r.code || !stdout.contains(r.stdout_contains) || run.stderr != r.stderr {
                bad.push(format!(
                    "{} ({} {:?}): recorded exit {}, stdout holding {:?}, stderr {:?};\n  \
                     the reference gave exit {}\n  stdout {:?}\n  stderr {:?}",
                    r.label,
                    r.name,
                    r.args,
                    r.code,
                    r.stdout_contains,
                    r.stderr,
                    run.code,
                    stdout,
                    run.stderr
                ));
            }
        }
        println!("{ran} of {} rows on the {:?} reference", rows.len(), own());
        // R11: on another Apple build, say so before every mismatch.
        let (head, prefix) = match own() {
            Which::Apple => apple_drift_note(apple_unzip_identity()).unwrap_or_default(),
            _ => Default::default(),
        };
        assert!(
            bad.is_empty(),
            "{head}{} rows differ:\n{}",
            bad.len(),
            bad.iter()
                .map(|b| format!("{prefix}{b}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// Every stub below has rows to compare once enabled.
    #[test]
    fn every_front_end_task_has_rows() {
        let rows = rows();
        for task in [7, 8, 9, 10, 11, 12, 13, 14] {
            assert!(
                rows.iter().any(|r| r.task == task),
                "Task {task} has no row"
            );
        }
    }

    /// The rows of `task` on this platform, against stuffr in this
    /// platform's flavour.
    fn differential(task: u8) {
        let rows: Vec<Row> = rows()
            .into_iter()
            .filter(|r| r.runs_here() && r.task_here() == task)
            .collect();
        let cases: Vec<Case> = rows.iter().map(Row::case).collect();
        run_group(
            &format!("task{task}"),
            &cases,
            Skipped::none(),
            &assert_same_unzip,
        );
    }

    /// Task 7's rows (options, usage, banners, the environment): this
    /// platform's and the `Both` ones (on Ubuntu, its usage texts are Task
    /// 14's: the iconv patch's `-O`/`-I` lines).
    #[test]
    fn task7_rows_match_stuffr() {
        differential(7);
    }

    /// Task 8's rows (opening archives, wildcards, listings).
    #[test]
    fn task8_rows_match_stuffr() {
        differential(8);
    }

    /// Task 9's rows (zipinfo's listings).
    #[test]
    fn task9_rows_match_stuffr() {
        differential(9);
    }

    /// Task 10's rows (testing and extraction).
    #[test]
    fn task10_rows_match_stuffr() {
        differential(10);
    }

    /// Task 11's rows (the password prompt, the questions at a terminal,
    /// `-M`, the `^S` pause).
    #[test]
    fn task11_rows_match_stuffr() {
        differential(11);
    }

    /// Task 12's rows (funzip).
    #[test]
    fn task12_rows_match_stuffr() {
        differential(12);
    }

    /// Task 13's rows: Ubuntu's `-v` (its build options); the rest of
    /// Task 13's differential is `compat_unzip_ubuntu::ubuntu_build_rows`.
    #[test]
    fn task13_rows_match_stuffr() {
        differential(13);
    }

    /// Task 14's rows: Ubuntu's answers that need its patch series (each
    /// `Both` row names its patch: [`Row::needs_patch`]).
    #[test]
    fn task14_rows_match_stuffr() {
        differential(14);
    }
}
