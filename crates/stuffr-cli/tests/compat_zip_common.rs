//! The zip family's recorded table (0.19.0 Task 1): one [`Row`] per probed
//! command, with the exit code, a text its standard output holds and its
//! exact standard error, as each reference gave them (measured 2026-10-25;
//! the record is `~/Development/Thomas/superpowers/stuffr/upstream/zip-measurements.md`).
//!
//! Each row is tagged with the flavour whose reference it was recorded on
//! ([`Which`]); a row runs on its own platform's reference only (Apple on
//! macOS, Ubuntu on Linux: CI and `make compat-ubuntu`).
//! `zip_recorded_rows_hold_on_the_reference` runs every row of this
//! platform's flavour on the reference and checks the recording, so the
//! table cannot rot. Each row names the task whose differential will run
//! it against stuffr (`taskN_rows_match_the_reference`, added by Tasks
//! 4-11 over [`rows_of`]).
//!
//! zip prints its messages on standard OUTPUT (`mesg` is stdout unless the
//! archive goes there); standard error carries only `perror`-style lines,
//! a shell's, and the messages of a run writing its archive to stdout.
//! Both streams are compared after `mask_temp_names` (zip's `ziXXXXXX`
//! temporary names are random). Every row runs under `LANG=C` and `TZ=UTC`
//! (the harness's defaults) over a [`ZipTree`].

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
        if platform_zip_flavour() == "apple" {
            Which::Apple
        } else {
            Which::Ubuntu
        }
    }

    /// One probed command and what the reference did.
    struct Row {
        flavour: Which,
        /// The task whose behaviour the row records.
        task: u8,
        /// A later task that makes the row comparable with stuffr (its
        /// answer needs code that task writes); 0 when `task` is enough.
        needs: u8,
        label: &'static str,
        name: &'static str,
        args: Vec<&'static str>,
        tree: ZipTree,
        /// Piped standard input; `None` is `/dev/null`.
        stdin: Option<Vec<u8>>,
        /// Extra environment (`ZIP`, `ZIPOPT`), both sides.
        env: Vec<(&'static str, &'static str)>,
        /// The reference's exit code.
        code: i32,
        /// Text its standard output holds (`""`: nothing is checked).
        stdout_contains: &'static str,
        /// Its standard error, exactly (or, with `stderr_contains`, a text
        /// it holds).
        stderr: &'static str,
        stderr_contains: bool,
        /// Compared with stuffr (false: the reference's answer is
        /// undefined behaviour stuffr does not reproduce, a ruling).
        differential: bool,
    }

    impl Row {
        fn runs_here(&self) -> bool {
            self.flavour == Which::Both || self.flavour == own()
        }

        fn case(&self) -> Case<'static> {
            let mut c = zip_case(self.name, &self.args, self.tree.clone());
            c.stdin = self.stdin.clone();
            c.env = self.env.clone();
            c
        }

        fn piped(mut self, data: &[u8]) -> Row {
            self.stdin = Some(data.to_vec());
            self
        }

        fn env(mut self, env: &[(&'static str, &'static str)]) -> Row {
            self.env = env.to_vec();
            self
        }

        /// Check only that standard error holds the recorded text.
        fn stderr_contains(mut self) -> Row {
            self.stderr_contains = true;
            self
        }

        fn tree(mut self, tree: ZipTree) -> Row {
            self.tree = tree;
            self
        }

        /// The row's answer comes from archive code of a later task.
        fn needs(mut self, task: u8) -> Row {
            self.needs = task;
            self
        }

        /// Recorded only: stuffr answers otherwise by a ruling.
        fn reference_only(mut self) -> Row {
            self.differential = false;
            self
        }

        /// The task whose differential runs the row.
        fn ready_at(&self) -> u8 {
            self.task.max(self.needs)
        }
    }

    /// A row over the standard tree ([`ZipTree::standard`]).
    #[allow(clippy::too_many_arguments)]
    fn row(
        flavour: Which,
        task: u8,
        label: &'static str,
        name: &'static str,
        args: &[&'static str],
        code: i32,
        stdout_contains: &'static str,
        stderr: &'static str,
    ) -> Row {
        Row {
            flavour,
            task,
            needs: 0,
            label,
            name,
            args: args.to_vec(),
            tree: ZipTree::standard(),
            stdin: None,
            env: vec![],
            code,
            stdout_contains,
            stderr,
            stderr_contains: false,
            differential: true,
        }
    }

    /// The standard tree plus `t.zip`, an archive of `entries` (name, data)
    /// made by `zip_with` (stored, MS-DOS defaults): input for updates.
    fn with_archive(entries: &[(&[u8], &[u8])]) -> ZipTree {
        let specs: Vec<ZipEntrySpec> = entries
            .iter()
            .map(|(n, d)| ZipEntrySpec::new(n, d))
            .collect();
        ZipTree::standard().file("t.zip", zip_with(&specs, b"", b""))
    }

    /// The standard tree plus `big`, 200000 random bytes (four 64 KiB
    /// splits; too large for a 1000-byte `zipsplit`).
    fn with_big() -> ZipTree {
        ZipTree::standard().file("big", random(200_000, 7))
    }

    const MISSING_END: &str = "\tzip warning: missing end signature--probably not a zip file (did you\n\
        \tzip warning: remember to use binary mode when you transferred it?)\n\
        \tzip warning: (if you are trying to read a damaged archive try -F)\n\n\
        zip error: Zip file structure invalid (g.zip)\n";

    fn rows() -> Vec<Row> {
        use Which::*;
        vec![
            // ---- Task 4: options, help, version, environment ----
            row(Both, 4, "help", "zip", &["-h"], 0,
                "Copyright (c) 1990-2008 Info-ZIP - Type 'zip \"-L\"' for software license.\n\
                 Zip 3.0 (July 5th 2008). Usage:\n\
                 zip [-options] [-b path] [-t mmddyyyy] [-n suffixes] [zipfile list] [-xi list]\n", ""),
            row(Both, 4, "help after names", "zip", &["t.zip", "a.txt", "-h"], 0,
                "Zip 3.0 (July 5th 2008). Usage:\n", ""),
            row(Both, 4, "-?", "zip", &["-?"], 0, "Zip 3.0 (July 5th 2008). Usage:\n", ""),
            row(Both, 4, "extended help", "zip", &["-h2"], 0,
                "\nExtended Help for Zip\n\nSee the Zip Manual for more detailed help", ""),
            row(Apple, 4, "-h2 has no {} line", "zip", &["-h2"], 0,
                "use command cmd instead of 'unzip -tqq' to test archive\n\
                 \x20            On Unix, to use unzip in current directory, could use:\n\
                 \x20              zip archive file1 file2 -T -TT \"./unzip -tqq\"\n\
                 \x20            The return code is checked for success (0 on Unix)\n", ""),
            row(Ubuntu, 4, "-h2 has the {} line", "zip", &["-h2"], 0,
                "             In cmd, {} replaced by temp archive path, else temp appended.\n", ""),
            row(Both, 4, "show options", "zip", &["-so"], 0,
                "available options:\n sh  long               val  neg description", ""),
            row(Ubuntu, 4, "show options lists -UN", "zip", &["-so"], 0,
                " UN  unicode            req      UN=quit, warn, ignore, no, escape\n", ""),
            row(Both, 4, "licence", "zip", &["-L"], 0,
                "Copyright (c) 1990-2008 Info-ZIP.  All rights reserved.\n", ""),
            row(Apple, 4, "version", "zip", &["-v"], 0,
                "This is Zip 3.0 (July 5th 2008), by Info-ZIP, with modifications by Apple Inc.\n\
                 Please report bugs to Apple.\n", ""),
            row(Apple, 4, "version options", "zip", &["-v"], 0,
                "\tSTORE_UNIX_UIDs_GIDs (store UID/GID sizes/values using new extra field)\n\
                 \tUIDGID_16BIT         (old Unix 16-bit UID/GID extra field also used)\n\
                 \t[encryption, version 2.91 of 05 Jan 2007] (modified for Zip 3)\n", ""),
            row(Ubuntu, 4, "version", "zip", &["--version"], 0,
                "This is Zip 3.0 (July 5th 2008), by Info-ZIP.\n\
                 Currently maintained by E. Gordon.  Please send bug reports to\n", ""),
            row(Ubuntu, 4, "version options", "zip", &["-v"], 0,
                "Compiled with gcc 13.3.0 for Unix (Linux ELF).\n\n\
                 Zip special compilation options:\n\
                 \tUSE_EF_UT_TIME       (store Universal Time)\n\
                 \tBZIP2_SUPPORT        (bzip2 library version 1.0.8, 13-Jul-2019)\n", ""),
            row(Both, 4, "environment in -v", "zip", &["-v"], 0,
                "Zip environment options:\n             ZIP:  [none]\n          ZIPOPT:  [none]\n", ""),
            row(Both, 4, "unknown short option", "zip", &["-%", "t.zip", "a.txt"], 16,
                "\nzip error: Invalid command arguments (short option '%' not supported)\n", ""),
            row(Both, 4, "unknown long option", "zip", &["--nosuch", "t.zip", "a.txt"], 16,
                "\nzip error: Invalid command arguments (long option 'nosuch' not supported)\n", ""),
            row(Both, 4, "ambiguous long option", "zip", &["--s", "t.zip", "a.txt"], 16,
                "\nzip error: Invalid command arguments (long option 's' ambiguous)\n", ""),
            row(Both, 4, "value missing", "zip", &["t.zip", "a.txt", "-b"], 16,
                "\nzip error: Invalid command arguments (option 'b' (dir to use for temp archive) requires a value)\n", ""),
            row(Both, 4, "-mm", "zip", &["t.zip", "a.txt", "-mm"], 16,
                "\nzip error: Invalid command arguments (-mm not supported, Must_Match is -MM)\n", ""),
            row(Apple, 4, "-Z unknown", "zip", &["-Z", "foo", "t.zip", "a.txt"], 16,
                "\tzip warning: valid compression methods are:  store, deflate)\n\
                 \tzip warning: unknown compression method found:  foo\n\n\
                 zip error: Invalid command arguments (Option -Z (--compression-method):  unknown method)\n", ""),
            row(Ubuntu, 4, "-Z unknown", "zip", &["-Z", "foo", "t.zip", "a.txt"], 16,
                "\tzip warning: valid compression methods are:  store, deflate, bzip2\n\
                 \tzip warning: unknown compression method found:  foo\n\n\
                 zip error: Invalid command arguments (Option -Z (--compression-method):  unknown method)\n", ""),
            row(Apple, 4, "-Z bzip2", "zip", &["-Z", "bzip2", "t.zip", "b.txt"], 19,
                "\nzip error: Not supported (Compression method bzip2 not enabled)\n", ""),
            row(Both, 4, "-e without a terminal", "zip", &["-e", "t.zip", "a.txt"], 16,
                "\nzip error: Invalid command arguments (stderr is not a tty)\n", ""),
            row(Both, 4, "bad -t date", "zip", &["-t", "13452002", "t.zip", "a.txt"], 16,
                "\nzip error: Invalid command arguments (invalid date entered for -t option - use mmddyyyy or yyyy-mm-dd)\n", ""),
            row(Both, 4, "split below 64k", "zip", &["-s", "10k", "t.zip", "b.txt"], 16,
                "\nzip error: Invalid command arguments (minimum split size is 64 KB:  '10k')\n", ""),
            row(Both, 4, "bad split size", "zip", &["-s", "1q", "t.zip", "b.txt"], 16,
                "\nzip error: Invalid command arguments (bad split size:  '1q')\n", ""),
            row(Both, 4, "dot size", "zip", &["t.zip", "a.txt", "-ds", "1k"], 16,
                "\nzip error: Invalid command arguments (dot size must be at least 32 KB:  '1k')\n", ""),
            row(Both, 4, "-DF without --out", "zip", &["t.zip", "a.txt", "-DF"], 16,
                "\nzip error: Invalid command arguments (-DF (--diff) requires -O (--out))\n", ""),
            row(Both, 4, "-F without --out", "zip", &["t.zip", "a.txt", "-F"], 16,
                "\tzip warning: fix options -F and -FF require --out:\n\
                 \x20                    zip -F indamagedarchive --out outfixedarchive\n\n\
                 zip error: Invalid command arguments (fix options require --out)\n", ""),
            row(Both, 4, "-U without --out", "zip", &["t.zip", "a.txt", "-U"], 16,
                "\nzip error: Invalid command arguments (-U (--copy) requires -O (--out))\n", ""),
            row(Both, 4, "show command", "zip", &["-sc", "t.zip", "a.txt"], 9,
                "'  '-sc'  't.zip'  'a.txt'  \n\nzip error: Interrupted (show command line)\n", ""),
            row(Apple, 4, "-su is -s u", "zip", &["-su", "t.zip", "a.txt"], 16,
                "\tzip warning: Unable to read number (must start with digit): u\n\n\
                 zip error: Invalid command arguments (bad split size:  'u')\n", ""),
            row(Ubuntu, 4, "-su", "zip", &["-su", "t.zip", "a.txt"], 0,
                "Would Add/Update:\n  a.txt\nTotal 1 entries (6 bytes)\n", "")
                .needs(5),
            row(Apple, 4, "-UN", "zip", &["t.zip", "a.txt", "-UN", "warn"], 16,
                "\nzip error: Invalid command arguments (short option 'N' not supported)\n", ""),
            row(Ubuntu, 4, "-UN", "zip", &["t.zip", "a.txt", "-UN", "warn"], 0,
                "  adding: a.txt (stored 0%)\n", "")
                .needs(6),
            row(Both, 4, "ZIP quiet", "zip", &["t.zip", "a.txt"], 0, "", "")
                .env(&[("ZIP", "-q")])
                .needs(6),
            row(Both, 4, "ZIPOPT verbose", "zip", &["t.zip", "a.txt"], 0,
                "  adding: a.txt\t(in=6) (out=6) (stored 0%)\ntotal bytes=6, compressed=6 -> 0% savings\n", "")
                .env(&[("ZIP", "-q"), ("ZIPOPT", "-v")])
                .needs(6),
            row(Both, 4, "ZIP bad option", "zip", &["t.zip", "a.txt"], 16,
                "\nzip error: Invalid command arguments (short option '%' not supported)\n", "")
                .env(&[("ZIP", "-%")]),
            row(Both, 4, "-d on stdout", "zip", &["-d", "-", "a.txt"], 16, "",
                "\nzip error: Invalid command arguments (can't use -d, -f, -u, -U, or -g on stdout\n)\n"),
            row(Both, 4, "split to stdout", "zip", &["-s", "64k", "-", "a.txt"], 16, "",
                "\nzip error: Invalid command arguments (archive name must end in .zip for splits)\n"),
            row(Both, 4, "zipcloak help", "zipcloak", &["-h"], 0,
                "\nZipCloak 3.0 (July 5th 2008)\nUsage:  zipcloak [-dq] [-b path] zipfile\n", ""),
            row(Both, 4, "zipnote help", "zipnote", &[], 0,
                "ZipNote 3.0 (July 5th 2008)\nUsage:  zipnote [-w] [-q] [-b path] zipfile\n", ""),
            row(Both, 4, "zipsplit help", "zipsplit", &["-h"], 0,
                "ZipSplit 3.0 (July 5th 2008)\nUsage:  zipsplit [-tipqs] [-n size] [-r room] [-b path] zipfile\n", ""),
            row(Both, 4, "zipcloak bad option", "zipcloak", &["-x", "t.zip"], 16,
                "zipcloak error: Invalid command arguments (short option 'x' not supported)\n", ""),
            row(Both, 4, "zipnote bad option", "zipnote", &["-x", "t.zip"], 16, "",
                "zipnote error: Invalid command arguments (unknown option)\n"),
            row(Both, 4, "zipsplit bad option", "zipsplit", &["-x", "t.zip"], 16,
                "zipsplit error: Invalid command arguments (Use option -h for help.)\n", ""),
            row(Both, 4, "zipcloak two archives", "zipcloak", &["t.zip", "t.zip"], 16,
                "zipcloak error: Invalid command arguments (can only specify one zip file)\n", ""),
            row(Both, 4, "zipcloak version", "zipcloak", &["-v"], 0,
                "ZipCloak special compilation options:\n\t[encryption, version 2.91 of 05 Jan 2007]\n", ""),
            // ---- Task 5: names, patterns, attributes ----
            row(Both, 5, "name not matched", "zip", &["t.zip", "nosuch"], 12,
                "\tzip warning: name not matched: nosuch\n\nzip error: Nothing to do! (t.zip)\n", ""),
            row(Both, 5, "no names", "zip", &["t.zip"], 12, "\nzip error: Nothing to do! (t.zip)\n", ""),
            row(Both, 5, "unreadable file among readable", "zip", &["t.zip", "a.txt", "b.txt", "d/c.txt"], 18,
                "  adding: a.txt (stored 0%)\n  adding: b.txt\n\
                 \tzip warning: could not open for reading: b.txt\n\
                 \x20 adding: d/c.txt (stored 0%)\n\n\
                 zip warning: Not all files were readable\n\
                 \x20 files/entries read:  2 (8 bytes)  skipped:  1 (2.1K bytes)\n",
                "zip warning: Permission denied\n")
                .tree(ZipTree::standard().file_mode("b.txt", vec![b'x'; 2240], 0o000))
                .needs(6),
            row(Both, 5, "-MM missing name", "zip", &["-MM", "t.zip", "a.txt", "nosuch"], 18,
                "\tzip warning: name not matched: nosuch\nzip I/O error: No such file or directory\n\
                 zip error: File not found or no read permission (nosuch)\n", ""),
            row(Both, 5, "FIFO without -FI", "zip", &["t.zip", "f", "a.txt"], 0,
                "\tzip warning: ignoring FIFO (Named Pipe) - use -FI to read: f\n  adding: a.txt (stored 0%)\n", "")
                .tree(ZipTree::standard().fifo("f"))
                .needs(6),
            row(Both, 5, "dangling symlink without -y", "zip", &["t.zip", "l", "a.txt"], 0,
                "\tzip warning: name not matched: l\n  adding: a.txt (stored 0%)\n", "")
                .tree(ZipTree::standard().symlink("l", "nosuch"))
                .needs(6),
            row(Both, 5, "special file", "zip", &["t.zip", "/dev/null"], 12,
                "\tzip warning: ignoring special file: /dev/null\n\nzip error: Nothing to do! (t.zip)\n", ""),
            row(Both, 5, "show files", "zip", &["-sf", "t.zip", "a.txt"], 0,
                "Would Add/Update:\n  a.txt\nTotal 1 entries (6 bytes)\n", ""),
            row(Both, 5, "DOS names", "zip", &["-k", "t.zip", "b.txt", "d/c.txt"], 0,
                "  adding: B.TXT (deflated 92%)\n  adding: D/C.TXT (stored 0%)\n", "")
                .needs(6),
            row(Both, 5, "-x pattern", "zip", &["-r", "t.zip", ".", "-x", "*.txt"], 0,
                "  adding: d/ (stored 0%)\n", "")
                .needs(6),
            row(Both, 5, "-j", "zip", &["-j", "t.zip", "d/c.txt", "a.txt"], 0,
                "  adding: c.txt (stored 0%)\n  adding: a.txt (stored 0%)\n", "")
                .needs(6),
            row(Both, 5, "names from stdin", "zip", &["-@", "t.zip"], 0,
                "  adding: a.txt (stored 0%)\n  adding: d/c.txt (stored 0%)\n", "")
                .piped(b"a.txt\nd/c.txt\n")
                .needs(6),
            row(Both, 5, "-t date excludes all", "zip", &["-t", "01012002", "t.zip", "a.txt"], 12,
                "\nzip error: Nothing to do! (t.zip)\n", ""),
            row(Apple, 5, "newline in a name", "zip", &["t.zip", "new\nline"], 0,
                "  adding: new\nline (stored 0%)\n", "")
                .tree(ZipTree::standard().file("new\nline", b"x"))
                .needs(6),
            row(Ubuntu, 5, "newline in a name", "zip", &["t.zip", "new\nline"], 0,
                "  adding: new^Jline (stored 0%)\n", "")
                .tree(ZipTree::standard().file("new\nline", b"x"))
                .needs(6),
            // ---- Task 6: writing ----
            row(Both, 6, "store and deflate", "zip", &["t.zip", "a.txt", "b.txt"], 0,
                "  adding: a.txt (stored 0%)\n  adding: b.txt (deflated 92%)\n", ""),
            row(Both, 6, "verbose", "zip", &["-v", "t.zip", "a.txt", "b.txt"], 0,
                "  adding: a.txt\t(in=6) (out=6) (stored 0%)\n\
                 \x20 adding: b.txt\t(in=2240) (out=170) (deflated 92%)\n\
                 total bytes=2246, compressed=176 -> 92% savings\n", ""),
            row(Both, 6, "display counts and bytes", "zip", &["-dc", "-db", "t.zip", "a.txt"], 0,
                "  0/  1 [   0/   6]   adding: a.txt (stored 0%)\n", ""),
            // a pipe cannot be rewound: the 6 bytes stay deflated (-32%), with a
            // data descriptor
            row(Both, 6, "archive to a pipe", "zip", &["-", "a.txt"], 0, "PK\u{3}\u{4}",
                "  adding: a.txt (deflated -32%)\n"),
            row(Both, 6, "stdin to a pipe", "zip", &[], 0, "PK\u{3}\u{4}", "  adding: - (deflated -32%)\n")
                .piped(b"hello\n"),
            row(Both, 6, "forced descriptors", "zip", &["-fd", "t.zip", "a.txt"], 0,
                "  adding: a.txt (deflated -32%)\n", ""),
            row(Both, 6, "could not create", "zip", &["nodir/t.zip", "a.txt"], 15,
                "zip I/O error: No such file or directory\nzip error: Could not create output file (nodir/t.zip)\n", ""),
            row(Both, 6, "read-only directory", "zip", &["ro/t.zip", "a.txt"], 15,
                "zip I/O error: Permission denied\nzip error: Could not create output file (ro/t.zip)\n", "")
                .tree(ZipTree::standard().dir_mode("ro", 0o555)),
            // ---- Task 7: updating, temp, -T ----
            row(Both, 7, "delete the last entry", "zip", &["-d", "t.zip", "a.txt"], 0,
                "deleting: a.txt\n\tzip warning: zip file empty\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 7, "delete no match", "zip", &["-d", "t.zip", "nosuch"], 12,
                "\tzip warning: name not matched: nosuch\n\nzip error: Nothing to do! (t.zip)\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 7, "delete from a missing archive", "zip", &["-d", "nosuch.zip", "a.txt"], 12,
                "\tzip warning: nosuch.zip not found or empty\n\nzip error: Nothing to do! (nosuch.zip)\n", ""),
            row(Both, 7, "update an entry", "zip", &["t.zip", "a.txt"], 0, "updating: a.txt (stored 0%)\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 7, "freshen nothing", "zip", &["-f", "t.zip"], 12, "", "")
                .tree(with_archive(&[(b"x.txt", b"x\n")])),
            row(Both, 7, "not a zip file", "zip", &["g.zip", "a.txt"], 3, MISSING_END, "")
                .tree(ZipTree::standard().file("g.zip", b"garbage")),
            row(Both, 7, "temp directory missing", "zip", &["-b", "nodir", "t.zip", "a.txt"], 10,
                "zip I/O error: No such file or directory\nzip error: Temporary file failure (nodir/zi??????)\n", ""),
            row(Both, 7, "test passes", "zip", &["-T", "t.zip", "a.txt", "b.txt"], 0,
                "  adding: a.txt (stored 0%)\n  adding: b.txt (deflated 92%)\ntest of t.zip OK\n", ""),
            row(Both, 7, "-T on stdout", "zip", &["-T", "-", "a.txt"], 0, "PK\u{3}\u{4}",
                "\tzip warning: can't use -T on stdout, -T ignored\n  adding: a.txt (deflated -32%)\n"),
            row(Apple, 7, "-TT test fails", "zip", &["-T", "-TT", "false", "t.zip", "a.txt"], 8,
                "test of t.zip FAILED\n\nzip error: Zip file invalid, could not spawn unzip, or wrong unzip (original files unmodified)\n", ""),
            row(Ubuntu, 7, "-TT test fails (double free)", "zip", &["-T", "-TT", "false", "t.zip", "a.txt"], 5,
                "test of t.zip FAILED\n\nzip error: Zip file invalid, could not spawn unzip, or wrong unzip (original files unmodified)\n\n",
                // glibc's wording may differ on CI's x86_64
                "double free"
            ).stderr_contains().reference_only(),
            row(Apple, 7, "-TT with {}", "zip", &["-T", "-TT", "true {}", "t.zip", "a.txt"], 16,
                "\nzip error: Invalid command arguments ({} in -TT not supported)\n", ""),
            row(Ubuntu, 7, "-TT through a shell", "zip", &["-T", "-TT", "true {}", "t.zip", "a.txt"], 0,
                "test of t.zip OK\n", ""),
            row(Both, 7, "adjust a plain archive", "zip", &["-A", "t.zip"], 3,
                "\tzip warning: reading archive fseek: Invalid argument\n\nzip error: Zip file structure invalid (t.zip)\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            // ---- Task 8: fix and splits ----
            // -F looks for the central directory from the end record back
            // by its size plus 80 bytes (a Zip64 end record and locator
            // assumed): the seek fails (EINVAL) for any archive whose
            // entries take less than 80 bytes, zip's own `zip t.zip a.txt`
            // too (measured, Task 8): not the harness's archive's fault
            row(Both, 8, "fix a zip_with archive", "zip", &["-F", "t.zip", "--out", "f.zip"], 3,
                "Fix archive (-F) - assume mostly intact archive\n\
                 \tzip warning: could not seek back to start of central directory: Invalid argument\n\
                 \tzip warning: (try -FF)\n\nzip error: Zip file structure invalid (t.zip)\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 8, "fix a missing archive", "zip", &["-F", "nosuch.zip", "--out", "f.zip"], 18,
                "Fix archive (-F) - assume mostly intact archive\n\tzip warning: No .zip file found\n", ""),
            row(Both, 8, "fix onto itself", "zip", &["-F", "t.zip", "--out", "t.zip"], 16,
                "\nzip error: Invalid command arguments (--out path must be different than in path: t.zip)\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 8, "split", "zip", &["-s", "64k", "t.zip", "big"], 0, "  adding: big (", "")
                .tree(with_big()),
            // ---- Task 9: encryption ----
            row(Both, 9, "zipcloak without a terminal", "zipcloak", &["t.zip"], 16,
                "zipcloak error: Invalid command arguments (stderr is not a tty (you may never see this message!))\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 9, "zipcloak a missing archive", "zipcloak", &["nosuch.zip"], 13,
                "zipcloak error: Missing or empty zip file (nosuch.zip)\n", ""),
            row(Both, 9, "zipcloak not a zip", "zipcloak", &["g.zip"], 3,
                "zipcloak warning: missing end signature--probably not a zip file (did you\n", "")
                .tree(ZipTree::standard().file("g.zip", b"garbage")),
            row(Both, 9, "zipcloak, every entry encrypted", "zipcloak", &["t.zip"], 12,
                "zipcloak error: Nothing to do! (all files encrypted already)\n", "")
                .tree(with_encrypted(&[(b"a.txt", true), (b"b.txt", true)])),
            row(Both, 9, "zipcloak -d, no entry encrypted", "zipcloak", &["-d", "t.zip"], 12,
                "zipcloak error: Nothing to do! (no encrypted files)\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 9, "zipcloak -d without a terminal", "zipcloak", &["-d", "t.zip"], 16,
                "zipcloak error: Invalid command arguments (stderr is not a tty (you may never see this message!))\n", "")
                .tree(with_encrypted(&[(b"a.txt", true), (b"b.txt", false)])),
            row(Both, 9, "zipcloak -O without a terminal", "zipcloak", &["-O", "o.zip", "t.zip"], 16,
                "zipcloak error: Invalid command arguments (stderr is not a tty (you may never see this message!))\n", "")
                .tree(with_encrypted(&[(b"a.txt", true), (b"b.txt", false)])),
            row(Both, 9, "zipcloak -O, a missing archive", "zipcloak", &["-O", "o.zip", "nosuch.zip"], 18,
                "zipcloak error: File not found or no read permission (nosuch.zip)\n",
                "zipcloak error: No such file or directory\n"),
            row(Both, 9, "zipcloak, a read-only archive", "zipcloak", &["t.zip"], 15,
                "zipcloak error: Could not create output file (t.zip)\n",
                "zipcloak error: Permission denied\n")
                .tree(with_archive(&[(b"a.txt", b"hello\n")]).file_mode("t.zip", zip_with(&[ZipEntrySpec::new(b"a.txt", b"hello\n")], b"", b""), 0o444)),
            row(Both, 9, "zipcloak -b into a missing directory", "zipcloak", &["-b", "nodir", "t.zip"], 10,
                "zipcloak error: Temporary file failure (nodir/zi??????)\n",
                "zipcloak error: No such file or directory\n")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 9, "zipcloak, a split archive", "zipcloak", &["s.zip"], 16,
                "zipcloak warning: cannot update a split archive (use --out option)\n\
                 zipcloak error: Invalid command arguments (s.zip)\n", "")
                .tree(with_parts(ZipTree::standard(), &zip_split_set("apple"), &[])),
            row(Both, 9, "zipcloak -O, a split archive, without a terminal", "zipcloak",
                &["-O", "o.zip", "s.zip"], 16,
                "zipcloak error: Invalid command arguments (stderr is not a tty (you may never see this message!))\n", "")
                .tree(with_parts(ZipTree::standard(), &zip_split_set("apple"), &[])),
            row(Both, 9, "-P then -e asks, without a terminal", "zip", &["-P", "pw", "-e", "t.zip", "a.txt"], 16,
                "\nzip error: Invalid command arguments (stderr is not a tty)\n", ""),
            // ---- Task 10: zipnote, zipsplit ----
            row(Both, 10, "zipnote list", "zipnote", &["t.zip"], 0,
                "@ a.txt\n@ (comment above this line)\n@ (zip file comment below this line)\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 10, "zipnote -w unexpected input", "zipnote", &["-w", "t.zip"], 7, "",
                "zipnote error: Invalid comment format (unexpected input)\n")
                .tree(with_archive(&[(b"a.txt", b"hello\n")]))
                .piped(b"garbage\n"),
            row(Both, 10, "zipnote -w unknown entry", "zipnote", &["-w", "t.zip"], 7, "",
                "zipnote error: Invalid comment format (unknown entry name)\n")
                .tree(with_archive(&[(b"a.txt", b"hello\n")]))
                .piped(b"@ nosuch\n@ (comment above this line)\n"),
            row(Apple, 10, "zipnote -w always fails", "zipnote", &["-w", "t.zip"], 10, "",
                "zipnote error: Bad file descriptor\nzipnote error: Temporary file failure (zi??????)\n")
                .tree(with_archive(&[(b"a.txt", b"hello\n")]))
                .piped(b"@ a.txt\nnew comment\n@ (comment above this line)\n@ (zip file comment below this line)\n")
                .reference_only(),
            row(Ubuntu, 10, "zipnote -w", "zipnote", &["-w", "t.zip"], 0, "", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")]))
                .piped(b"@ a.txt\nnew comment\n@ (comment above this line)\n@ (zip file comment below this line)\n"),
            row(Both, 10, "zipnote a missing archive", "zipnote", &["nosuch.zip"], 9, "",
                "\nzipnote error: Interrupted (aborting)\n"),
            row(Both, 10, "zipsplit entry too big", "zipsplit", &["-n", "1000", "t.zip"], 6,
                "zipsplit warning: Entry is larger than max split size of: 978\n\
                 zipsplit warning: use -n to set split size\n\
                 zipsplit error: Entry too big to split, read, or write (big)\n", "")
                .tree(with_big().file("t.zip", zip_with(&[ZipEntrySpec::new(b"big", &random(200_000, 7))], b"", b""))),
            row(Both, 10, "zipsplit size too small", "zipsplit", &["-n", "50", "t.zip"], 16,
                "zipsplit error: Invalid command arguments (invalid size given. Use option -h for help.)\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            row(Both, 10, "zipsplit a missing archive", "zipsplit", &["nosuch.zip"], 9,
                "\nzipsplit error: Interrupted (aborting)\n", ""),
            row(Both, 10, "zipsplit -t", "zipsplit", &["-t", "t.zip"], 0,
                "1 zip files would be made (100% efficiency)\n", "")
                .tree(with_archive(&[(b"a.txt", b"hello\n"), (b"b.txt", b"b\n")])),
            row(Both, 10, "zipsplit into a missing directory", "zipsplit", &["-b", "nodir", "t.zip"], 15,
                "1 zip files will be made (100% efficiency)\ncreating: nodir/t1.zip\n\
                 zipsplit error: Could not create output file (nodir/t1.zip)\n",
                "zipsplit error: No such file or directory\n")
                .tree(with_archive(&[(b"a.txt", b"hello\n")])),
            // ---- Task 11: Ubuntu's build ----
            row(Ubuntu, 11, "-Z bzip2", "zip", &["-Z", "bzip2", "t.zip", "b.txt"], 0,
                "  adding: b.txt (bzipped 91%)\n", ""),
            row(Ubuntu, 11, "Unicode support in -v", "zip", &["-v"], 0,
                "\tUNICODE_SUPPORT      (store and read UTF-8 Unicode paths)\n\
                 \tSTORE_UNIX_UIDs_GIDs (store UID/GID sizes/values using new extra field)\n\
                 \tUIDGID_NOT_16BIT     (old Unix 16-bit UID/GID extra field not used)\n", ""),
            row(Both, 11, "UTF-8 name", "zip", &["t.zip", "caf\u{e9}.txt"], 0,
                "  adding: caf\u{e9}.txt (stored 0%)\n", "")
                .tree(ZipTree::standard().file("caf\u{e9}.txt", b"x")),
            row(Apple, 11, "-Z bzip2 not built", "zip", &["-Z", "bzip2", "t.zip", "b.txt"], 19,
                "\nzip error: Not supported (Compression method bzip2 not enabled)\n", ""),
            row(Both, 11, "a stored name that is not UTF-8", "zip", &["-sf", "t.zip"], 0,
                "Archive contains:\n", "")
                .tree(with_archive(&[(b"h\xe9.txt", b"x\n"), (b"n\nl", b"y\n")])),
            row(Both, 11, "copying a name that is not UTF-8", "zip", &["t.zip", "b.txt"], 0,
                "  adding: b.txt (deflated 92%)\n", "")
                .tree(with_archive(&[(b"h\xe9.txt", b"x\n"), (b"-n", b"y\n")])),
        ]
    }

    /// The rows `task` makes comparable that run on this platform's
    /// reference, as cases (for the tasks' differentials).
    fn rows_of(task: u8) -> Vec<Case<'static>> {
        rows()
            .into_iter()
            .filter(|r| r.ready_at() == task && r.runs_here() && r.differential)
            .map(|r| r.case())
            .collect()
    }

    /// The rows of `task` on this platform's reference, against stuffr in
    /// this platform's flavour: exit code, standard output and error, every
    /// byte of the tree.
    fn differential(task: u8) {
        let cases = rows_of(task);
        assert!(!cases.is_empty(), "Task {task} has no row here");
        run_group(
            &format!("task{task}"),
            &cases,
            Skipped::none(),
            &assert_same_zip,
        );
    }

    /// Task 4's rows: options, help and version screens, the environment,
    /// the checks of `main()` and the helpers' usage. The rows whose answer
    /// needs the archive code (the `ZIP` and `ZIPOPT` that archive, Ubuntu's
    /// `-su` and `-UN`) run with the task that builds it.
    #[test]
    fn task4_rows_match_the_reference() {
        differential(4);
    }

    /// Task 5's rows: the names zip finds, and the runs that end before
    /// anything is written (nothing to do, a name that matched nothing,
    /// `-MM`, a special file, `-sf`'s listing). The rows that archive what
    /// they find (a FIFO or dangling link skipped beside a file that is
    /// added, `-k`, `-j`, `-x`, names from standard input, an unreadable
    /// file among readable ones, Review Focus 2) run with Task 6, which
    /// writes the archive; the scanning matrices are in
    /// `compat_zip_apple` and `compat_zip_ubuntu`.
    #[test]
    fn task5_rows_match_the_reference() {
        differential(5);
    }

    /// Task 6's rows: writing new archives (stored and deflated entries,
    /// `-v` and the progress counters, an archive or standard input on a
    /// pipe, descriptors, an archive that cannot be created), and the rows
    /// of Tasks 4 and 5 whose answer is written (`ZIP`/`ZIPOPT` that
    /// archive, Ubuntu's `-UN`, a FIFO or a dangling link beside a file,
    /// `-k`, `-j`, `-x`, `-@`, names with a newline, and Review Focus 2's
    /// unreadable file among readable ones).
    #[test]
    fn task6_rows_match_the_reference() {
        differential(6);
    }

    /// Task 7's rows: updating, deleting, the temporary, `-T`/`-TT`, `-A`
    /// (Ubuntu's `-T` double free is recorded only: ruling Z3).
    #[test]
    fn task7_rows_match_the_reference() {
        differential(7);
    }

    /// Task 8's rows: `-F` (the `zip_with` archive is too small for -F's
    /// look back from the end record: a quirk of zip's, not of the
    /// harness's archive), a missing archive, `--out` onto itself, `-s`.
    #[test]
    fn task8_rows_match_the_reference() {
        differential(8);
    }

    /// Task 9's rows: zipcloak's answers before its prompt (nothing to do,
    /// no terminal, an archive it cannot open, append to, or make a
    /// temporary beside), and `-e` after `-P`. The prompts themselves are
    /// `compat_zip_tty`'s; the `-P` archives `compat_zip_bytes`'.
    #[test]
    fn task9_rows_match_the_reference() {
        differential(9);
    }

    /// Task 10's rows: `zipnote` and `zipsplit` (the full matrices are
    /// `compat_zip_helpers`'). Apple's `zipnote -w` row is recorded only
    /// (ruling Z4).
    #[test]
    fn task10_rows_match_the_reference() {
        differential(10);
    }

    /// Task 11's rows: Ubuntu's `-Z bzip2` and Unicode names, Apple's
    /// answers to the same (its build has neither).
    #[test]
    fn task11_rows_match_the_reference() {
        differential(11);
    }

    /// Review Focus 5: names with a newline, a byte that is not UTF-8, a
    /// leading `-` or `/`, under `LANG=C` and `C.UTF-8`, in this platform's
    /// flavour: on disk (APFS refuses the high byte: macOS gets it from
    /// standard input only, where zip finds no such file) and stored in an
    /// archive zip reads, updates, lists and copies; and a leading `/`, on
    /// the command line and stored.
    #[test]
    fn awkward_names_match_the_reference() {
        let linux = cfg!(target_os = "linux");
        let disk = || {
            let t = ZipTree::standard()
                .file_at(b"n\nl", b"x", 0o644)
                .file_at(b"-n", b"x", 0o644)
                .file_at("caf\u{e9}.txt".as_bytes(), b"x", 0o644);
            if linux {
                t.file_at(b"h\xe9.txt", b"x", 0o644)
            } else {
                t
            }
        };
        let stored = || {
            let specs = [
                ZipEntrySpec::new(b"h\xe9.txt", b"x\n"),
                ZipEntrySpec::new(b"n\nl", b"y\n"),
                ZipEntrySpec::new(b"-n", b"z\n"),
                ZipEntrySpec::new("caf\u{e9}.txt".as_bytes(), b"w\n"),
                ZipEntrySpec::new(b"/abs.txt", b"v\n"),
            ];
            disk().file("t.zip", zip_with(&specs, b"", b""))
        };
        let mut cases = Vec::new();
        for env in [&[][..], &[("LC_ALL", "C.UTF-8")]] {
            let mut add = |args: &[&'static str], tree: ZipTree, stdin: Option<&[u8]>| {
                let mut c = zip_case(args[0], &args[1..], tree);
                c.env = env.to_vec();
                c.stdin = stdin.map(<[u8]>::to_vec);
                cases.push(c);
            };
            add(&["zip", "t.zip", "n\nl", "--", "-n"], disk(), None);
            add(&["zip", "-sf", "t.zip", "n\nl", "--", "-n"], disk(), None);
            add(&["zip", "-r", "t.zip", "."], disk(), None);
            add(
                &["zip", "t.zip", "-@"],
                disk(),
                Some(b"h\xe9.txt\nn\nl\n-n\n"),
            );
            add(&["zip", "-sf", "t.zip", "-@"], disk(), Some(b"h\xe9.txt\n"));
            add(&["zip", "-sf", "t.zip"], stored(), None);
            add(&["zip", "t.zip", "b.txt"], stored(), None);
            add(&["zip", "t.zip", "n\nl", "--", "-n"], stored(), None);
            add(&["zip", "-d", "t.zip", "h*", "--", "-n"], stored(), None);
            add(
                &["zip", "-v", "-U", "t.zip", "*", "--out", "o.zip"],
                stored(),
                None,
            );
            add(&["zip", "-FF", "t.zip", "--out", "f.zip"], stored(), None);
            add(&["zipnote", "t.zip"], stored(), None);
            add(&["zipsplit", "-n", "65536", "t.zip"], stored(), None);
            // a leading `/`: an absolute operand (a file every system has,
            // -X so its access time is not stored) loses it; a stored one
            // is kept
            add(&["zip", "-X", "t.zip", "/etc/passwd"], disk(), None);
            add(&["zip", "-X", "-sf", "t.zip", "/etc/passwd"], disk(), None);
            add(&["zip", "-X", "-j", "t.zip", "/etc/passwd"], disk(), None);
            add(&["zip", "-d", "t.zip", "/abs.txt"], stored(), None);
            add(
                &["zip", "-U", "t.zip", "/abs.txt", "--out", "o.zip"],
                stored(),
                None,
            );
        }
        run_group("awkward names", &cases, Skipped::none(), &assert_same_zip);
    }

    /// The first central header's general-purpose flags and internal
    /// attributes in archive `b`.
    fn central_flags(b: &[u8]) -> (u16, u16) {
        let at = b
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("a central header");
        let h = |o: usize| u16::from_le_bytes([b[at + o], b[at + o + 1]]);
        (h(8), h(36))
    }

    fn archive_of(run: &ZipRun, name: &[u8]) -> Vec<u8> {
        match run.tree.get(name) {
            Some(UnzipNode::File { bytes, .. }) => bytes.clone(),
            other => panic!("{} is {other:?}", String::from_utf8_lossy(name)),
        }
    }

    /// stuffr-only pins of the undefined behaviour Ubuntu's patches 12 and
    /// 13 remove and of Task 11's rulings (deviations 28 and 29), in both
    /// flavours:
    /// - patch 12 (`mbstowcs` told the buffer is `strlen + 1` wide
    ///   characters; glibc's fortify aborts on any non-ASCII name): a
    ///   non-ASCII name is archived (Ubuntu: bit 11; Apple, which has no
    ///   Unicode code: no flag);
    /// - patch 13 (`-TT`'s command one byte short): the test command runs
    ///   whatever the archive name's length;
    /// - deviation 28: where Ubuntu's C reads through a NULL from a
    ///   conversion that failed (a bit-11 name that is not UTF-8, a Unicode
    ///   Path field with no name), the answer is its crash's, without the
    ///   crash; Apple reads such archives as any other;
    /// - deviation 29: `-Z bzip2`'s text test of a first entry sees zeros
    ///   past the bytes read (a short text file is binary).
    #[test]
    fn ub_rulings() {
        for flavour in ["apple", "ubuntu"] {
            let ubuntu = flavour == "ubuntu";
            // patch 12
            let mut c = zip_case(
                "zip",
                &["t.zip", "caf\u{e9}.txt"],
                ZipTree::standard().file("caf\u{e9}.txt", b"x"),
            );
            c.zip_flavour = Some(flavour);
            let r = stuffr_zip(&c);
            assert_eq!(r.code, 0, "{flavour}");
            let (flags, _) = central_flags(&archive_of(&r, b"t.zip"));
            assert_eq!(flags, if ubuntu { 0x800 } else { 0 }, "{flavour}");
            // patch 13: end to end at three name lengths (the boundary
            // itself is `update::tests::tt_command_is_whole_at_every_length`)
            for name in [
                "q.zip",
                "qqqq.zip",
                "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq.zip",
            ] {
                let mut c = zip_case(
                    "zip",
                    &["-T", "-TT", "true", name, "a.txt"],
                    ZipTree::standard(),
                );
                c.zip_flavour = Some(flavour);
                let r = stuffr_zip(&c);
                assert_eq!(
                    r.code,
                    0,
                    "{flavour} {name}: {}",
                    String::from_utf8_lossy(&r.stdout)
                );
                assert!(
                    String::from_utf8_lossy(&r.stdout).contains(&format!("test of {name} OK")),
                    "{flavour} {name}"
                );
            }
            // deviation 28
            let mut up = 0x7075u16.to_le_bytes().to_vec();
            up.extend_from_slice(&5u16.to_le_bytes());
            up.push(1);
            let mut crc = flate2::Crc::new();
            crc.update("caf\u{e9}.txt".as_bytes());
            up.extend_from_slice(&crc.sum().to_le_bytes());
            let mut empty_up = ZipEntrySpec::new("caf\u{e9}.txt".as_bytes(), b"x\n");
            empty_up.extra = &up;
            let mut not_utf8 = ZipEntrySpec::new(b"h\xe9.txt", b"x\n");
            not_utf8.flags = 0x800;
            for spec in [empty_up, not_utf8] {
                let tree = ZipTree::standard().file("t.zip", zip_with(&[spec], b"", b""));
                for (prog, args) in [
                    ("zip", &["-sf", "t.zip"][..]),
                    ("zip", &["t.zip", "b.txt"]),
                    ("zipnote", &["t.zip"]),
                    ("zipsplit", &["t.zip"]),
                ] {
                    let mut c = zip_case(prog, args, tree.clone());
                    c.zip_flavour = Some(flavour);
                    let r = stuffr_zip(&c);
                    if !ubuntu {
                        assert_eq!(r.code, 0, "{flavour} {prog} {args:?}");
                        continue;
                    }
                    assert_eq!(r.code, 9, "{prog} {args:?}");
                    let (out, err) = (r.stdout.clone(), r.stderr.clone());
                    let text = match prog {
                        "zip" => (out, b"\n\nzip error: Interrupted (aborting)\n".to_vec()),
                        "zipnote" => (err, b"\nzipnote error: Interrupted (aborting)\n".to_vec()),
                        _ => (out, b"\nzipsplit error: Interrupted (aborting)\n".to_vec()),
                    };
                    assert!(
                        text.0.ends_with(&text.1),
                        "{prog} {args:?}: {:?}",
                        String::from_utf8_lossy(&text.0)
                    );
                }
            }
            // deviation 29 (Ubuntu only: Apple refuses -Z bzip2)
            if ubuntu {
                let mut c = zip_case(
                    "zip",
                    &["-Z", "bzip2", "t.zip", "b.txt"],
                    ZipTree::standard(),
                );
                c.zip_flavour = Some(flavour);
                let r = stuffr_zip(&c);
                assert_eq!(r.code, 0);
                let (_, iattr) = central_flags(&archive_of(&r, b"t.zip"));
                assert_eq!(iattr, 0, "a short first text entry is binary");
            }
        }
    }

    /// Ruling Z3 (deviation 15): a failing `-T` answers as Apple's zip in
    /// both flavours, where Ubuntu's frees the temporary's stream twice and
    /// aborts (exit 5): `test of t.zip FAILED`, `ZE_TEST` (exit 8), nothing
    /// on standard error, no temporary left and no archive made.
    #[test]
    fn a_failing_test_is_apples_answer_in_both_flavours() {
        for flavour in ["apple", "ubuntu"] {
            for args in [
                &["-T", "-TT", "false", "t.zip", "a.txt"][..],
                &["-T", "t.zip", "a.txt"],
            ] {
                let tree = with_fake_unzip(ZipTree::standard(), "", 1);
                let mut c = zip_case("zip", args, tree);
                c.zip_flavour = Some(flavour);
                c.env = vec![FAKE_UNZIP_PATH];
                let r = stuffr_zip(&c);
                assert_eq!(r.code, 8, "{flavour} {args:?}");
                let out = String::from_utf8_lossy(&r.stdout);
                assert!(
                    out.ends_with(
                        "test of t.zip FAILED\n\nzip error: Zip file invalid, could not spawn unzip, \
                         or wrong unzip (original files unmodified)\n"
                    ),
                    "{flavour} {args:?}: {out:?}"
                );
                assert!(r.stderr.is_empty(), "{flavour}: {:?}", r.stderr);
                let names: Vec<&Vec<u8>> = r.tree.keys().collect();
                assert!(
                    !names
                        .iter()
                        .any(|k| k.as_slice() == b"t.zip" || k.starts_with(b"zi")),
                    "{flavour}: {names:?}"
                );
            }
        }
    }

    /// Deviation 13: `-T -g` tests stuffr's copy, so the test program is
    /// given the temporary's name (zip, writing in place, gives the
    /// archive's), and the grown archive is in place after the test.
    #[test]
    fn a_grown_archive_is_tested_under_the_temporarys_name() {
        for flavour in ["apple", "ubuntu"] {
            let old = zip_made(flavour, &ZipTree::standard(), &["t.zip", "a.txt"], "t.zip");
            let tree = env_probe(ZipTree::standard().file("t.zip", old));
            let mut c = zip_case("zip", &["-T", "-TT", "probe", "-g", "t.zip", "b.txt"], tree);
            c.zip_flavour = Some(flavour);
            c.env = vec![FAKE_UNZIP_PATH];
            let r = stuffr_zip(&c);
            assert_eq!(r.code, 0, "{flavour}");
            let out = String::from_utf8_lossy(&mask_temp_names(&r.stdout)).into_owned();
            assert!(out.contains("args: zi??????\n"), "{flavour}: {out}");
            assert!(out.ends_with("test of t.zip OK\n"), "{flavour}: {out}");
        }
    }

    #[test]
    fn zip_recorded_rows_hold_on_the_reference() {
        let rows: Vec<Row> = rows().into_iter().filter(Row::runs_here).collect();
        assert!(rows.len() >= 40, "only {} rows here", rows.len());
        let mut bad = Vec::new();
        let mut ran = 0;
        for r in &rows {
            // No reference: a skip (a panic under CI).
            let Some(run) = zip_reference(&r.case()) else {
                continue;
            };
            ran += 1;
            let stdout = String::from_utf8_lossy(&mask_temp_names(&run.stdout)).into_owned();
            let stderr = mask_temp_names(&run.stderr);
            let stderr_ok = if r.stderr_contains {
                stderr
                    .windows(r.stderr.len())
                    .any(|w| w == r.stderr.as_bytes())
            } else {
                stderr == r.stderr.as_bytes()
            };
            let stderr = String::from_utf8_lossy(&stderr);
            if run.code != r.code || !stdout.contains(r.stdout_contains) || !stderr_ok {
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
                    stderr
                ));
            }
        }
        println!("{ran} of {} rows on the {:?} reference", rows.len(), own());
        assert!(
            bad.is_empty(),
            "{} rows differ:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// Every later task has rows to compare.
    #[test]
    fn every_front_end_task_has_rows() {
        let rows = rows();
        for task in 4..=11 {
            assert!(
                rows.iter().any(|r| r.task == task),
                "Task {task} has no row"
            );
        }
    }

    fn node<'a>(run: &'a ZipRun, name: &str) -> Option<&'a UnzipNode> {
        run.tree.get(name.as_bytes())
    }

    fn is_link_to(run: &ZipRun, name: &str, to: &str) -> bool {
        matches!(node(run, name), Some(UnzipNode::Symlink { target, .. }) if target == to.as_bytes())
    }

    /// Deviation 31 (ruling T5): a symlink at the archive's name that
    /// leads to no regular file (here dangling) is refused before any work,
    /// `Could not create output file`, exit 15, the link kept and nothing
    /// created through it (Info-ZIP creates the file the link names); with
    /// `-b` too, and no temporary left. A link to an existing archive is
    /// still updated through it, as Info-ZIP updates it. stuffr alone.
    #[test]
    fn a_dangling_symlink_archive_name_is_refused() {
        for args in [&["d.zip", "a.txt"][..], &["-b", ".", "d.zip", "a.txt"]] {
            let tree = ZipTree::standard().symlink("d.zip", "nowhere");
            let s = stuffr_zip(&zip_case("zip", args, tree));
            // zip's errors go to standard output
            let err = String::from_utf8_lossy(&s.stdout);
            assert_eq!(s.code, 15, "{args:?}: {err}");
            assert!(
                err.contains("zip error: Could not create output file (d.zip)"),
                "{args:?}: {err}"
            );
            assert!(is_link_to(&s, "d.zip", "nowhere"), "{args:?}");
            assert!(node(&s, "nowhere").is_none(), "{args:?}: created");
            assert!(
                !s.tree.keys().any(|k| k.starts_with(b"zi")),
                "{args:?}: a temporary is left"
            );
        }
        let tree = with_archive(&[(b"x.txt", b"x\n")]).symlink("l.zip", "t.zip");
        let s = stuffr_zip(&zip_case("zip", &["l.zip", "a.txt"], tree));
        assert_eq!(s.code, 0, "{}", String::from_utf8_lossy(&s.stderr));
        assert!(is_link_to(&s, "l.zip", "t.zip"));
        let t = archive_of(&s, b"t.zip");
        assert!(t.windows(5).any(|w| w == b"a.txt") && t.windows(5).any(|w| w == b"x.txt"));
    }

    /// Deviation 31: a symlink at `-O`/`--out` is refused whatever it
    /// points at (Info-ZIP truncates the target), here a live link to a
    /// regular file, also under `-FF`; an in-place update through a link to
    /// an EMPTY file is refused too (zip read no archive there). Exit 15,
    /// the link and its target untouched. stuffr alone.
    #[test]
    fn a_symlink_at_an_output_name_zip_did_not_read_is_refused() {
        let cases: [(&[&'static str], &str); 3] = [
            (&["t.zip", "a.txt", "--out", "o.zip"], "o.zip"),
            (&["-FF", "t.zip", "--out", "o.zip"], "o.zip"),
            (&["e.zip", "a.txt"], "e.zip"),
        ];
        for (args, out) in cases {
            let tree = with_archive(&[(b"x.txt", b"x\n")])
                .file("victim", b"old victim")
                .file("empty", b"")
                .symlink("o.zip", "victim")
                .symlink("e.zip", "empty");
            let s = stuffr_zip(&zip_case("zip", args, tree));
            let text = String::from_utf8_lossy(&s.stdout);
            assert_eq!(s.code, 15, "{args:?}: {text}");
            assert!(
                text.contains(&format!("zip error: Could not create output file ({out})")),
                "{args:?}: {text}"
            );
            assert!(is_link_to(&s, "o.zip", "victim"), "{args:?}");
            assert!(is_link_to(&s, "e.zip", "empty"), "{args:?}");
            assert_eq!(archive_of(&s, b"victim"), b"old victim", "{args:?}");
            assert_eq!(archive_of(&s, b"empty"), b"", "{args:?}");
            assert!(
                !s.tree.keys().any(|k| k.starts_with(b"zi")),
                "{args:?}: a temporary is left"
            );
        }
    }

    /// Deviation 32 (ruling T5): zipsplit never writes a part through a
    /// symlink at its name (live or dangling): `O_NOFOLLOW` fails the open
    /// (`ELOOP`'s text, `Could not create output file`), the link and its
    /// target untouched, the link not removed by the cleanup.
    /// zipsplit writes through it. stuffr alone.
    #[test]
    fn zipsplit_never_writes_a_part_through_a_symlink() {
        for live in [true, false] {
            let mut tree = with_archive(&[(b"x.txt", b"x\n")]).symlink("t1.zip", "victim");
            if live {
                tree = tree.file("victim", b"old victim");
            }
            let s = stuffr_zip(&zip_case("zipsplit", &["t.zip"], tree));
            let err =
                String::from_utf8_lossy(&[s.stdout.as_slice(), &s.stderr].concat()).into_owned();
            assert_ne!(s.code, 0, "live {live}: {err}");
            assert!(
                err.contains("Too many levels of symbolic links")
                    && err.contains("Could not create output file (t1.zip)"),
                "live {live}: {err}"
            );
            assert!(is_link_to(&s, "t1.zip", "victim"), "live {live}");
            if live {
                assert_eq!(archive_of(&s, b"victim"), b"old victim");
            } else {
                assert!(node(&s, "victim").is_none(), "created through");
            }
        }
    }

    /// Deviation 33 (ruling T6): the `-lf` log shows `-P`'s password as
    /// `********`, a new log is created 0600, and a symlink at the log's
    /// name (live or dangling, `-la` too) is not written through: `could
    /// not open logfile`, exit 16, the link and its target untouched. zip
    /// writes the password into a `0666 & ~umask` file through the link.
    /// stuffr alone.
    #[test]
    fn the_log_hides_the_password_and_follows_no_symlink() {
        let s = stuffr_zip(&zip_case(
            "zip",
            &["-q", "-P", "hunter2", "-lf", "z.log", "z.zip", "a.txt"],
            ZipTree::standard(),
        ));
        assert_eq!(s.code, 0, "{}", String::from_utf8_lossy(&s.stdout));
        match node(&s, "z.log") {
            Some(UnzipNode::File { bytes, mode, .. }) => {
                let log = String::from_utf8_lossy(bytes);
                assert!(!log.contains("hunter2"), "{log}");
                assert!(log.contains("-P ******** "), "{log}");
                assert_eq!(mode & 0o777, 0o600, "{mode:o}");
            }
            other => panic!("z.log is {other:?}"),
        }
        for append in [false, true] {
            for live in [true, false] {
                let mut tree = ZipTree::standard().symlink("z.log", "victim");
                if live {
                    tree = tree.file("victim", b"old victim");
                }
                let mut args = vec!["-q", "-P", "hunter2", "-lf", "z.log"];
                if append {
                    args.push("-la");
                }
                args.extend(["z.zip", "a.txt"]);
                let s = stuffr_zip(&zip_case("zip", &args, tree));
                let out = String::from_utf8_lossy(&s.stdout);
                assert_eq!(s.code, 16, "append {append} live {live}: {out}");
                assert!(
                    out.contains("could not open logfile 'z.log'"),
                    "append {append} live {live}: {out}"
                );
                assert!(is_link_to(&s, "z.log", "victim"));
                if live {
                    assert_eq!(archive_of(&s, b"victim"), b"old victim");
                } else {
                    assert!(node(&s, "victim").is_none(), "created through");
                }
            }
        }
    }
}
