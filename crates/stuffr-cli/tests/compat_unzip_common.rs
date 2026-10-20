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
//!   N"]` until then. R13: Ubuntu's side of every row waits for Task 13 (its
//!   build options) or Task 14 (its patches).
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
        /// The task whose differential runs the row on Apple; on Ubuntu a
        /// `Both` row waits for Task 13 (R13, see [`Row::task_here`]).
        task: u8,
        label: &'static str,
        name: &'static str,
        args: Vec<&'static str>,
        files: Vec<(&'static str, Vec<u8>)>,
        /// Piped standard input; `None` is `/dev/null`.
        stdin: Option<Vec<u8>>,
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
                (Which::Both, Which::Ubuntu) => 13,
                _ => self.task,
            }
        }

        fn case(&self) -> Case<'_> {
            let mut c = unzip_case(self.name, self.args.clone(), self.files.clone());
            c.stdin = self.stdin.clone();
            c
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
            label,
            name,
            args: args.to_vec(),
            files,
            stdin: None,
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

    /// The end of Ubuntu's `unzip -v` under `LANG=C` (`char coding: other`; other locales are Task 13's).
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
        // Usage, help, version, a bad option (Task 7; Ubuntu's Task 13).
        for (who, task, usage, zipinfo, options, banner) in [
            (
                Apple,
                7,
                APPLE_USAGE,
                APPLE_ZIPINFO_USAGE,
                APPLE_OPTIONS,
                APPLE_UNZIP_BANNER,
            ),
            (
                Ubuntu,
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
                row(who, task, "-v", "unzip", &["-v"], vec![], 0, options, ""),
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
            ]);
        }
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
            row(
                Both,
                8,
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
            row(
                Both,
                8,
                "no match",
                "unzip",
                &["a.zip", "nomatch"],
                a(),
                11,
                "Archive:  a.zip\n",
                "caution: filename not matched:  nomatch\n",
            ),
        ]);
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
        // funzip on standard input (Task 12).
        for (label, stdin, code, out, err) in [
            (
                "funzip a zip",
                a_zip(),
                0,
                "alpha\n",
                "funzip warning: zipfile has more than one entry--rest ignored\n",
            ),
            (
                "funzip a gzip",
                gzm(b"gzip data\n", b"g.txt"),
                0,
                "gzip data\n",
                "",
            ),
            (
                "funzip garbage",
                b"garbage\n".to_vec(),
                3,
                "",
                "funzip error: input not a zip or gzip file\n",
            ),
        ] {
            let mut r = row(Both, 12, label, "funzip", &[], vec![], code, out, err);
            r.stdin = Some(stdin);
            v.push(r);
        }
        v
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
        for r in &rows {
            let Some(run) = unzip_reference(&r.case()) else {
                return;
            };
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
        println!("{} rows on the {:?} reference", rows.len(), own());
        assert!(
            bad.is_empty(),
            "{} rows differ:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// Every stub below has rows to compare once enabled, except Task 9's
    /// (zipinfo listings: that task records its own rows).
    #[test]
    fn every_front_end_task_has_rows() {
        let rows = rows();
        for task in [7, 8, 10, 11, 12, 13, 14] {
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

    #[test]
    #[ignore = "Task 7"]
    fn task7_rows_match_stuffr() {
        differential(7);
    }

    #[test]
    #[ignore = "Task 8"]
    fn task8_rows_match_stuffr() {
        differential(8);
    }

    #[test]
    #[ignore = "Task 9"]
    fn task9_rows_match_stuffr() {
        differential(9);
    }

    #[test]
    #[ignore = "Task 10"]
    fn task10_rows_match_stuffr() {
        differential(10);
    }

    #[test]
    #[ignore = "Task 11"]
    fn task11_rows_match_stuffr() {
        differential(11);
    }

    #[test]
    #[ignore = "Task 12"]
    fn task12_rows_match_stuffr() {
        differential(12);
    }

    #[test]
    #[ignore = "Task 13"]
    fn task13_rows_match_stuffr() {
        differential(13);
    }

    #[test]
    #[ignore = "Task 14"]
    fn task14_rows_match_stuffr() {
        differential(14);
    }
}
