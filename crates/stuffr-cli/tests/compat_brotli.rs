//! The brotli compatibility family against brotli 1.2.1: stuffr invoked as
//! `brotli`, `unbrotli` and `brcat`, compared with the reference (stdout,
//! stderr, exit code, the file tree) through `compat_harness`, every case
//! under `LC_ALL=C`.
//!
//! **Task 1 wrote the probe tables** (probed 2026-10-28 by running the
//! reference binary only, with `c/tools/brotli.c` of the 1.2.1 tag as the
//! authority for which message a command line can reach; the tables are also
//! in `.claude/rules/compat.md`, "brotli 1.2.1 probes"). A [`Row`] is one
//! probed command: its fixtures, the reference's exit code and the exact text
//! of its standard error. Two uses:
//! - `the_recorded_table_holds_on_the_reference` (always on) runs every row
//!   on the reference and checks the recorded code and standard error, so
//!   the table cannot rot;
//! - `taskN_rows_match_the_reference` runs the rows a later task implements
//!   against stuffr and compares everything (`assert_same`). They are
//!   `#[ignore = "Task N"]`: un-ignoring the one for your task is the whole
//!   enablement. Task 3 owns [`USAGE_ROWS`] (parsing and usage, no file is
//!   touched; four rows that go on to open an input or compress standard
//!   input are Task 4's, `needs_io`), Task 4 [`COMPRESS_ROWS`] and
//!   [`DECOMPRESS_ROWS`], Task 5 the verbose, comment and error-name rows
//!   (the rows whose message ends in a `reason:` line or a timing figure).
//!
//! Conventions of the tables:
//! - A fixture named `<stdin>` is not a file: its bytes are fed to standard
//!   input.
//! - `a` is `hello\n` and `d` is a directory (made by every run's setup).
//! - A usage error (exit 1) prints its message, if it has one, to standard
//!   error and the help text to STANDARD OUTPUT; `-h` (exit 0) prints the
//!   help text to standard ERROR. A row records all of it in `stderr`: a
//!   usage row ends in the help text ([`help!`]), and the checker moves that
//!   tail to standard output when the exit code is 1
//!   ([`expected_streams`]). The first line names the invoked program
//!   (`brotli`); a row run under another name is compared with that name
//!   substituted ([`expected_stderr`]).
//! - Timing is the reference's own clock: `in 0.00 sec` is compared as
//!   `in X sec` on both sides ([`blank_timing`]).
//!
//! Not reproducible by the harness, recorded in `compat.md` only: `fclose
//! failed`, `failed to write output` (a full device; `/dev/full` is
//! Linux only), `out of memory`, `failed to emit metadata`, `failed to
//! compress data`, `failed to prepare dictionary` (the library refuses none
//! of these for a command line), `setting access bits|group|user failed`
//! (needs a file system that refuses `chmod`/`chown`), and a dictionary
//! directory (`-D d`: the size of a directory differs between macOS, which
//! says `failed to read dictionary [d]: Is a directory`, and other systems).

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::fs;
    use std::path::Path;

    /// One probed command.
    pub struct Row {
        pub args: &'static [&'static str],
        pub fixtures: &'static [(&'static str, &'static [u8])],
        /// The reference's exit code.
        pub code: i32,
        /// Its standard error, exactly (timing blanked, see the module
        /// documentation).
        pub stderr: &'static str,
    }

    const fn r(
        args: &'static [&'static str],
        fixtures: &'static [(&'static str, &'static [u8])],
        code: i32,
        stderr: &'static str,
    ) -> Row {
        Row {
            args,
            fixtures,
            code,
            stderr,
        }
    }

    /// The help text as the reference prints it for the name `brotli`.
    const HELP: &str = include_str!("data/brotli/help.txt");

    /// A message, then the help text: every usage error.
    macro_rules! help {
        ($msg:literal) => {
            concat!($msg, include_str!("data/brotli/help.txt"))
        };
    }

    // ---- fixtures ----

    const A: &[u8] = b"hello\n";
    const DICT: &[u8] = b"hello\nhello\nhello\nhello\n";
    /// `brotli -c a` (lgwin 16 by size).
    const BR: &[u8] = b"\x21\x14\x00\x04hello\n\x03";
    /// The same with the comment `foo` (`-C Zm9v`).
    const BR_FOO: &[u8] = b"\x21\x4b\x00foo\x28\x00\x08hello\n\x03";
    /// `brotli -c --large_window=25 a`.
    const BR_LARGE: &[u8] = b"\x11\x19\x0a\x00\x02hello\n\x03";
    /// `brotli -c -D dict a`.
    const BR_DICT: &[u8] = b"\xa1\x28\x00\xc0\x2f\x01\x10\x84\xc4\x01";
    const DICT2: &[u8] =
        b"The quick brown fox jumps over the lazy dog, again and again and again.\n";
    /// `brotli -c -D d2 d2`: it needs the dictionary to decode.
    const BR_DICT2: &[u8] = b"\xa1\x38\x02\xc0\x2f\x01\x10\x80\xc5\x15\x02";
    /// `BR` twice.
    const BR2: &[u8] = b"\x21\x14\x00\x04hello\n\x03\x21\x14\x00\x04hello\n\x03";
    /// `BR` and one byte more.
    const BR_EXTRA: &[u8] = b"\x21\x14\x00\x04hello\n\x03x";
    /// `BR` cut after eight bytes.
    const BR_CUT: &[u8] = b"\x21\x14\x00\x04hell";
    /// Not brotli: the first meta-block header is invalid.
    const JUNK: &[u8] = b"this is not brotli\n";
    const FF: &[u8] = b"\xff\xff\xff\xff\xff\xff";

    /// The one fixture every row lists by name.
    const STDIN: &str = "<stdin>";

    // ---- the tables ----

    /// Parsing and usage: nothing is read, written or decoded.
    pub const USAGE_ROWS: &[Row] = &[
        // -h and -V
        r(&["-h"], &[], 0, HELP),
        r(&["--help"], &[], 0, HELP),
        r(&["-k", "-h"], &[], 0, HELP),
        r(&["-hV"], &[], 0, HELP),
        r(&["-V"], &[], 0, ""),
        r(&["--version"], &[], 0, ""),
        r(&["-Vh"], &[], 0, ""),
        r(&["-k", "--version"], &[], 0, ""),
        // too many options: 23 empty arguments make the 24th an overflow
        r(
            &[
                "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                "", "", "-k",
            ],
            &[],
            1,
            help!("too many options passed\n"),
        ),
        // already set
        r(&["-1", "-2"], &[], 1, help!("quality already set\n")),
        r(
            &["-q", "1", "-q", "2"],
            &[],
            1,
            help!("quality already set\n"),
        ),
        r(&["-1", "-Z"], &[], 1, help!("quality already set\n")),
        r(&["-Z", "-1"], &[], 1, help!("quality already set\n")),
        r(&["--best", "-1"], &[], 1, help!("quality already set\n")),
        r(&["-1", "--best"], &[], 1, help!("quality already set\n")),
        r(
            &["--quality=1", "-1"],
            &[],
            1,
            help!("quality already set\n"),
        ),
        r(
            &["-1", "--quality=2"],
            &[],
            1,
            help!("quality already set\n"),
        ),
        r(
            &["-c", "-c"],
            &[],
            1,
            help!("write to standard output already set\n"),
        ),
        r(
            &["--stdout", "-c"],
            &[],
            1,
            help!("write to standard output already set\n"),
        ),
        r(
            &["-c", "--stdout"],
            &[],
            1,
            help!("write to standard output already set\n"),
        ),
        r(
            &["-c", "-o", "x"],
            &[],
            1,
            help!("write to standard output already set (-o)\n"),
        ),
        r(
            &["-c", "--output=x"],
            &[],
            1,
            help!("write to standard output already set (--output)\n"),
        ),
        r(
            &["-c", "--o=x"],
            &[],
            1,
            help!("write to standard output already set (--output)\n"),
        ),
        r(
            &["-d", "-d"],
            &[],
            1,
            help!("command already set when parsing -d\n"),
        ),
        r(
            &["-t", "-d"],
            &[],
            1,
            help!("command already set when parsing -d\n"),
        ),
        r(
            &["--decompress", "-d"],
            &[],
            1,
            help!("command already set when parsing -d\n"),
        ),
        r(
            &["-d", "-t"],
            &[],
            1,
            help!("command already set when parsing -t\n"),
        ),
        r(
            &["-t", "-t"],
            &[],
            1,
            help!("command already set when parsing -t\n"),
        ),
        r(
            &["-d", "--decompress"],
            &[],
            1,
            help!("command already set when parsing --decompress\n"),
        ),
        r(
            &["-t", "--decompress"],
            &[],
            1,
            help!("command already set when parsing --decompress\n"),
        ),
        r(
            &["-d", "--test"],
            &[],
            1,
            help!("command already set when parsing --test\n"),
        ),
        r(
            &["--test", "--test"],
            &[],
            1,
            help!("command already set when parsing --test\n"),
        ),
        r(
            &["-f", "-f"],
            &[],
            1,
            help!("force output overwrite already set\n"),
        ),
        r(
            &["-f", "--force"],
            &[],
            1,
            help!("force output overwrite already set\n"),
        ),
        r(
            &["--force", "-f"],
            &[],
            1,
            help!("force output overwrite already set\n"),
        ),
        r(
            &["-k", "-k"],
            &[],
            1,
            help!("argument --rm / -j or --keep / -k already set\n"),
        ),
        r(
            &["-j", "-k"],
            &[],
            1,
            help!("argument --rm / -j or --keep / -k already set\n"),
        ),
        r(
            &["-k", "-j"],
            &[],
            1,
            help!("argument --rm / -j or --keep / -k already set\n"),
        ),
        r(
            &["--rm", "-k"],
            &[],
            1,
            help!("argument --rm / -j or --keep / -k already set\n"),
        ),
        r(
            &["--keep", "-j"],
            &[],
            1,
            help!("argument --rm / -j or --keep / -k already set\n"),
        ),
        r(
            &["-k", "--keep"],
            &[],
            1,
            help!("argument --rm / -j or --keep / -k already set\n"),
        ),
        r(
            &["-j", "--rm"],
            &[],
            1,
            help!("argument --rm / -j or --keep / -k already set\n"),
        ),
        r(
            &["-n", "-n"],
            &[],
            1,
            help!("argument --no-copy-stat / -n already set\n"),
        ),
        r(
            &["--no-copy-stat", "-n"],
            &[],
            1,
            help!("argument --no-copy-stat / -n already set\n"),
        ),
        r(
            &["-n", "--no-copy-stat"],
            &[],
            1,
            help!("argument --no-copy-stat / -n already set\n"),
        ),
        r(
            &["-s", "-s"],
            &[],
            1,
            help!("argument --squash / -s already set\n"),
        ),
        r(
            &["--squash", "-s"],
            &[],
            1,
            help!("argument --squash / -s already set\n"),
        ),
        r(
            &["-s", "--squash"],
            &[],
            1,
            help!("argument --squash / -s already set\n"),
        ),
        r(
            &["-v", "-v"],
            &[],
            1,
            help!("argument --verbose / -v already set\n"),
        ),
        r(
            &["--verbose", "-v"],
            &[],
            1,
            help!("argument --verbose / -v already set\n"),
        ),
        r(
            &["-v", "--verbose"],
            &[],
            1,
            help!("argument --verbose / -v already set\n"),
        ),
        r(
            &["-K", "-K"],
            &[],
            1,
            help!("argument -K / --concatenated already set\n"),
        ),
        r(
            &["--concatenated", "-K"],
            &[],
            1,
            help!("argument -K / --concatenated already set\n"),
        ),
        r(
            &["-K", "--concatenated"],
            &[],
            1,
            help!("argument -K / --concatenated already set\n"),
        ),
        r(
            &["-w", "10", "-w", "11"],
            &[],
            1,
            help!("lgwin parameter already set\n"),
        ),
        r(
            &["--lgwin=10", "-w", "11"],
            &[],
            1,
            help!("lgwin parameter already set\n"),
        ),
        r(
            &["-w", "10", "--lgwin=11"],
            &[],
            1,
            help!("lgwin parameter already set\n"),
        ),
        r(
            &["-w", "10", "--large_window=25"],
            &[],
            1,
            help!("lgwin parameter already set\n"),
        ),
        r(
            &["--large_window=25", "--lgwin=10"],
            &[],
            1,
            help!("lgwin parameter already set\n"),
        ),
        r(
            &["-C", "Zm9v", "-C", "Zm9v"],
            &[],
            1,
            help!("comment already set\n"),
        ),
        r(
            &["--comment=Zm9v", "-C", "Zm9v"],
            &[],
            1,
            help!("comment already set\n"),
        ),
        r(
            &["-C", "Zm9v", "--comment=Zm9v"],
            &[],
            1,
            help!("comment already set\n"),
        ),
        r(
            &["-D", "a", "-D", "b"],
            &[],
            1,
            help!("dictionary path already set\n"),
        ),
        r(
            &["--dictionary=a", "-D", "b"],
            &[],
            1,
            help!("dictionary path already set\n"),
        ),
        r(
            &["-D", "a", "--dictionary=b"],
            &[],
            1,
            help!("dictionary path already set\n"),
        ),
        r(
            &["-S", ".a", "-S", ".b"],
            &[],
            1,
            help!("suffix already set\n"),
        ),
        r(
            &["--suffix=.a", "-S", ".b"],
            &[],
            1,
            help!("suffix already set\n"),
        ),
        r(
            &["-S", ".a", "--suffix=.b"],
            &[],
            1,
            help!("suffix already set\n"),
        ),
        // invalid or incomplete arguments
        r(&["-x"], &[], 1, help!("invalid argument -x\n")),
        r(&["-kx"], &[], 1, help!("invalid argument -x\n")),
        r(&["-k", "-a"], &[], 1, help!("invalid argument -a\n")),
        r(
            &["-qo"],
            &[],
            1,
            help!("expected parameter for argument -q\n"),
        ),
        r(
            &["-oq"],
            &[],
            1,
            help!("expected parameter for argument -o\n"),
        ),
        r(
            &["-wk"],
            &[],
            1,
            help!("expected parameter for argument -w\n"),
        ),
        r(
            &["-Cq"],
            &[],
            1,
            help!("expected parameter for argument -C\n"),
        ),
        r(
            &["-Dq"],
            &[],
            1,
            help!("expected parameter for argument -D\n"),
        ),
        r(
            &["-Sq"],
            &[],
            1,
            help!("expected parameter for argument -S\n"),
        ),
        r(
            &["-o"],
            &[],
            1,
            help!("expected parameter for argument -o\n"),
        ),
        r(
            &["-q"],
            &[],
            1,
            help!("expected parameter for argument -q\n"),
        ),
        r(
            &["-w"],
            &[],
            1,
            help!("expected parameter for argument -w\n"),
        ),
        r(
            &["-C"],
            &[],
            1,
            help!("expected parameter for argument -C\n"),
        ),
        r(
            &["-D"],
            &[],
            1,
            help!("expected parameter for argument -D\n"),
        ),
        r(
            &["-S"],
            &[],
            1,
            help!("expected parameter for argument -S\n"),
        ),
        r(
            &["-kS"],
            &[],
            1,
            help!("expected parameter for argument -S\n"),
        ),
        r(
            &["-o", ""],
            &[],
            1,
            help!("expected parameter for argument -o\n"),
        ),
        r(
            &["-S", ""],
            &[],
            1,
            help!("expected parameter for argument -S\n"),
        ),
        r(
            &["-q", ""],
            &[],
            1,
            help!("expected parameter for argument -q\n"),
        ),
        // numbers
        r(
            &["-q", "x"],
            &[],
            1,
            help!("error parsing quality value [x]\n"),
        ),
        r(
            &["-q", "12"],
            &[],
            1,
            help!("error parsing quality value [12]\n"),
        ),
        r(
            &["-q", "01"],
            &[],
            1,
            help!("error parsing quality value [01]\n"),
        ),
        r(
            &["-q", "-1"],
            &[],
            1,
            help!("error parsing quality value [-1]\n"),
        ),
        r(
            &["-q", "123456"],
            &[],
            1,
            help!("error parsing quality value [123456]\n"),
        ),
        r(
            &["-q", "1x"],
            &[],
            1,
            help!("error parsing quality value [1x]\n"),
        ),
        r(
            &["--quality=12"],
            &[],
            1,
            help!("error parsing quality value [12]\n"),
        ),
        r(
            &["--quality=x"],
            &[],
            1,
            help!("error parsing quality value [x]\n"),
        ),
        r(
            &["--q=12"],
            &[],
            1,
            help!("error parsing quality value [12]\n"),
        ),
        r(
            &["-w", "x"],
            &[],
            1,
            help!("error parsing lgwin value [x]\n"),
        ),
        r(
            &["-w", "25"],
            &[],
            1,
            help!("error parsing lgwin value [25]\n"),
        ),
        r(
            &["-w", "00"],
            &[],
            1,
            help!("error parsing lgwin value [00]\n"),
        ),
        r(
            &["--lgwin=25"],
            &[],
            1,
            help!("error parsing lgwin value [25]\n"),
        ),
        r(
            &["--lgwin=x"],
            &[],
            1,
            help!("error parsing lgwin value [x]\n"),
        ),
        r(
            &["--large_window=31"],
            &[],
            1,
            help!("error parsing lgwin value [31]\n"),
        ),
        r(
            &["--large_window=x"],
            &[],
            1,
            help!("error parsing lgwin value [x]\n"),
        ),
        r(
            &["-w", "5"],
            &[],
            1,
            help!("lgwin parameter (5) smaller than the minimum (10)\n"),
        ),
        r(
            &["-w", "9"],
            &[],
            1,
            help!("lgwin parameter (9) smaller than the minimum (10)\n"),
        ),
        r(
            &["--lgwin=1"],
            &[],
            1,
            help!("lgwin parameter (1) smaller than the minimum (10)\n"),
        ),
        r(
            &["--large_window=9"],
            &[],
            1,
            help!("lgwin parameter (9) smaller than the minimum (10)\n"),
        ),
        // comments
        r(
            &["-C", "!"],
            &[],
            1,
            help!("invalid base64-encoded comment\n"),
        ),
        r(&["-C", "Zm9v="], &[], 0, ""),
        r(
            &["-C", "Zm9v=x"],
            &[],
            1,
            help!("invalid base64-encoded comment\n"),
        ),
        r(
            &["-C", "Zm9v==="],
            &[],
            1,
            help!("invalid base64-encoded comment\n"),
        ),
        r(
            &["--comment=!"],
            &[],
            1,
            help!("invalid base64-encoded comment\n"),
        ),
        r(
            &[
                "-C",
                "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            ],
            &[],
            1,
            help!("invalid base64-encoded comment\n"),
        ),
        // long options
        r(
            &["--foo"],
            &[],
            1,
            help!("must pass the parameter as --foo=value\n"),
        ),
        r(
            &["--foo="],
            &[],
            1,
            help!("must pass the parameter as --foo==value\n"),
        ),
        r(
            &["--quality"],
            &[],
            1,
            help!("must pass the parameter as --quality=value\n"),
        ),
        r(
            &["--qualit=1x"],
            &[],
            1,
            help!("error parsing quality value [1x]\n"),
        ),
        r(&["--foo=1"], &[], 1, help!("invalid parameter: [foo=1]\n")),
        r(
            &["--best=1"],
            &[],
            1,
            help!("invalid parameter: [best=1]\n"),
        ),
        r(
            &["--Quality=1"],
            &[],
            1,
            help!("invalid parameter: [Quality=1]\n"),
        ),
        r(
            &["--quality2=1"],
            &[],
            1,
            help!("invalid parameter: [quality2=1]\n"),
        ),
        r(&["--=1"], &[], 0, ""),
        r(&["--=!"], &[], 1, help!("invalid base64-encoded comment\n")),
        // checks after the arguments (no message, the help text)
        r(
            &["-c", "-o", "x"],
            &[],
            1,
            help!("write to standard output already set (-o)\n"),
        ),
        r(&["a", "b", "-c"], &[], 1, HELP),
        r(
            &["a", "b", "-o", "x"],
            &[],
            1,
            "failed to open input file [a]: No such file or directory\n",
        ),
        r(&["-t", "-o", "x"], &[], 1, HELP),
        r(&["-t", "--output=x"], &[], 1, HELP),
        r(&["-t", "-c"], &[], 1, HELP),
        r(&["-t", "--stdout"], &[], 1, HELP),
        r(&["-s", "-c"], &[], 1, HELP),
        r(&["--squash", "--stdout"], &[], 1, HELP),
        r(&["-S", "a/b"], &[], 1, HELP),
        r(&["-S", "a\\b"], &[], 1, HELP),
        r(&["--suffix=/"], &[], 1, HELP),
        r(&["-K"], &[], 1, HELP),
        r(&["--concatenated"], &[], 1, HELP),
        r(&["-t", "-K", "-C", "Zm9v"], &[], 1, HELP),
        r(&["-d", "-K", "-C", "Zm9v"], &[], 1, HELP),
        r(
            &["-d", "-K", "-C", ""],
            &[],
            1,
            help!("expected parameter for argument -C\n"),
        ),
    ];

    /// Compression: messages and exits.
    pub const COMPRESS_ROWS: &[Row] = &[
        r(&["-c", "a"], &[("a", A)], 0, ""),
        r(&["a"], &[("a", A)], 0, ""),
        r(&["-c", "-"], &[("<stdin>", A)], 0, ""),
        r(&["-c"], &[("<stdin>", A)], 0, ""),
        r(&["-c"], &[("<stdin>", b"")], 0, ""),
        r(&["-c", "a"], &[("a", b"")], 0, ""),
        r(&["-c", "--", "-k"], &[("-k", A)], 0, ""),
        r(&["-c", "a", "a"], &[("a", A)], 1, HELP),
        r(&["-0c", "a"], &[("a", A)], 0, ""),
        r(&["-9c", "a"], &[("a", A)], 0, ""),
        r(&["-Zc", "a"], &[("a", A)], 0, ""),
        r(&["--best", "-c", "a"], &[("a", A)], 0, ""),
        r(&["-q", "5", "-c", "a"], &[("a", A)], 0, ""),
        r(&["--quality=5", "-c", "a"], &[("a", A)], 0, ""),
        r(&["--q=5", "-c", "a"], &[("a", A)], 0, ""),
        r(&["-w", "0", "-c", "a"], &[("a", A)], 0, ""),
        r(&["-w", "10", "-c", "a"], &[("a", A)], 0, ""),
        r(&["--lgwin=24", "-c", "a"], &[("a", A)], 0, ""),
        r(&["--large_window=25", "-c", "a"], &[("a", A)], 0, ""),
        r(&["--large_window=30", "-c", "a"], &[("a", A)], 0, ""),
        r(&["--large_window=0", "-c", "a"], &[("a", A)], 0, ""),
        r(&["-C", "Zm9v", "-c", "a"], &[("a", A)], 0, ""),
        r(&["--comment=Zm9v", "-c", "a"], &[("a", A)], 0, ""),
        r(
            &["-C", "", "-c", "a"],
            &[("a", A)],
            1,
            help!("expected parameter for argument -C\n"),
        ),
        r(&["--comment=Zg==", "-c", "a"], &[("a", A)], 0, ""),
        r(
            &["-D", "dict", "-c", "a"],
            &[("a", A), ("dict", DICT)],
            0,
            "",
        ),
        r(
            &["--dictionary=dict", "-c", "a"],
            &[("a", A), ("dict", DICT)],
            0,
            "",
        ),
        r(
            &["-D", "dict", "-c", "a"],
            &[("a", A), ("dict", b"")],
            0,
            "",
        ),
        r(
            &["-c", "-D", "nodict", "a"],
            &[("a", A)],
            1,
            "failed to open dictionary file [nodict]: No such file or directory\n",
        ),
        r(&["-D", "nodict", "-h"], &[], 0, HELP),
        r(&["-D", "nodict", "-V"], &[], 0, ""),
        r(
            &["-c", "nosuch"],
            &[],
            1,
            "failed to open input file [nosuch]: No such file or directory\n",
        ),
        r(
            &["nosuch"],
            &[],
            1,
            "failed to open input file [nosuch]: No such file or directory\n",
        ),
        r(&["-c", "a", "nosuch"], &[("a", A)], 1, HELP),
        r(&["-c", "nosuch", "a"], &[("a", A)], 1, HELP),
        r(
            &["-c", "d"],
            &[],
            1,
            "failed to read input [d]: Is a directory\n",
        ),
        r(&["d"], &[], 1, "failed to read input [d]: Is a directory\n"),
        r(
            &["a"],
            &[("a", A), ("a.br", b"x")],
            1,
            "failed to open output file [a.br]: File exists\n",
        ),
        r(&["-f", "a"], &[("a", A), ("a.br", b"x")], 0, ""),
        r(&["--force", "a"], &[("a", A), ("a.br", b"x")], 0, ""),
        r(&["-S", ".x", "a"], &[("a", A)], 0, ""),
        r(&["--suffix=.x", "a"], &[("a", A)], 0, ""),
        r(
            &["-S", ".x", "a"],
            &[("a", A), ("a.x", b"x")],
            1,
            "failed to open output file [a.x]: File exists\n",
        ),
        r(&["-o", "out", "a"], &[("a", A)], 0, ""),
        r(&["--output=out", "a"], &[("a", A)], 0, ""),
        r(
            &["-o", "out", "a"],
            &[("a", A), ("out", b"x")],
            1,
            "failed to open output file [out]: File exists\n",
        ),
        r(&["-f", "-o", "out", "a"], &[("a", A), ("out", b"x")], 0, ""),
        r(
            &["-o", "nodir/out", "a"],
            &[("a", A)],
            1,
            "failed to open output file [nodir/out]: No such file or directory\n",
        ),
        r(
            &["-o", "d", "-f", "a"],
            &[("a", A)],
            1,
            "failed to open output file [d]: Is a directory\n",
        ),
        r(&["-o", "out", "-c", "a"], &[("a", A)], 0, ""),
        r(
            &["-c", "-o", "out", "a"],
            &[("a", A)],
            1,
            help!("write to standard output already set (-o)\n"),
        ),
        r(&["-o", "out"], &[("<stdin>", A)], 0, ""),
        r(&["-o", "out", "-"], &[("<stdin>", A)], 0, ""),
        r(&["-k", "a"], &[("a", A)], 0, ""),
        r(&["-j", "a"], &[("a", A)], 0, ""),
        r(&["--rm", "a"], &[("a", A)], 0, ""),
        r(&["-j", "-c", "a"], &[("a", A)], 0, ""),
        r(&["-n", "a"], &[("a", A)], 0, ""),
        r(&["--no-copy-stat", "a"], &[("a", A)], 0, ""),
        r(&["-s", "a"], &[("a", A)], 0, ""),
        r(&["--squash", "a"], &[("a", A)], 0, ""),
        r(&["-s", "a", "b"], &[("a", A), ("b", A)], 0, ""),
        r(&["a", "b"], &[("a", A), ("b", A)], 0, ""),
        r(
            &["a", "b"],
            &[("a", A), ("b", A), ("b.br", b"x")],
            1,
            "failed to open output file [b.br]: File exists\n",
        ),
        r(&["--", "-c"], &[("-c", A)], 0, ""),
        r(&["-c", "a", "-"], &[("a", A), ("<stdin>", A)], 1, HELP),
        r(&["-c", "-", "-"], &[("<stdin>", A)], 1, HELP),
        // a path with a directory part and a suffix
        r(&["d/x"], &[("d/x", A)], 0, ""),
        r(&["-S", ".br", "d/x"], &[("d/x", A)], 0, ""),
    ];

    /// Decompression and `-t`: messages and exits (no `-v`).
    pub const DECOMPRESS_ROWS: &[Row] = &[
        r(&["-dc", "a.br"], &[("a.br", BR)], 0, ""),
        r(&["-d", "a.br"], &[("a.br", BR)], 0, ""),
        r(&["-dc"], &[("<stdin>", BR)], 0, ""),
        r(&["-dc", "-"], &[("<stdin>", BR)], 0, ""),
        r(
            &["--decompress", "--stdout", "a.br"],
            &[("a.br", BR)],
            0,
            "",
        ),
        r(&["-t", "a.br"], &[("a.br", BR)], 0, ""),
        r(&["--test", "a.br"], &[("a.br", BR)], 0, ""),
        r(&["-t"], &[("<stdin>", BR)], 0, ""),
        r(&["-t", "-"], &[("<stdin>", BR)], 0, ""),
        r(
            &["-t", "a.br", "b.br"],
            &[("a.br", BR), ("b.br", BR)],
            0,
            "",
        ),
        r(
            &["-t", "a.br", "b.br"],
            &[("a.br", BR), ("b.br", JUNK)],
            1,
            "corrupt input [b.br]\n",
        ),
        r(
            &["-t", "nosuch.br"],
            &[],
            1,
            "failed to open input file [nosuch.br]: No such file or directory\n",
        ),
        r(
            &["-t", "d"],
            &[],
            1,
            "failed to read input [d]: Is a directory\n",
        ),
        r(&["-t", "a"], &[("a", BR)], 0, ""),
        r(
            &["-t", "-v", "a.br"],
            &[("a.br", BR)],
            0,
            "Decompressed [a.br]: 11 B -> 6 B in X sec\n",
        ),
        r(&["-dc", "a.br", "a.br"], &[("a.br", BR)], 1, HELP),
        r(
            &["-dc", "a.br", "b.br"],
            &[("a.br", BR), ("b.br", BR)],
            1,
            HELP,
        ),
        r(&["-dc", "-K", "a.br"], &[("a.br", BR2)], 0, ""),
        r(&["-dc", "--concatenated", "a.br"], &[("a.br", BR2)], 0, ""),
        r(&["-t", "-K", "a.br"], &[("a.br", BR2)], 1, HELP),
        r(&["-dc", "-K", "a.br"], &[("a.br", BR)], 0, ""),
        r(
            &["-dc", "a.br"],
            &[("a.br", BR2)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "a.br"],
            &[("a.br", BR_EXTRA)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-K", "a.br"],
            &[("a.br", BR_EXTRA)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "a.br"],
            &[("a.br", BR_CUT)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "a.br"],
            &[("a.br", JUNK)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "a.br"],
            &[("a.br", FF)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "a.br"],
            &[("a.br", b"")],
            1,
            "corrupt input [a.br]\n",
        ),
        r(&["-dc"], &[("<stdin>", b"")], 1, "corrupt input [con]\n"),
        r(&["-dc"], &[("<stdin>", JUNK)], 1, "corrupt input [con]\n"),
        r(
            &["-dc", "-"],
            &[("<stdin>", BR_CUT)],
            1,
            "corrupt input [con]\n",
        ),
        r(
            &["-dc", "nosuch.br"],
            &[],
            1,
            "failed to open input file [nosuch.br]: No such file or directory\n",
        ),
        r(
            &["-d", "nosuch.br"],
            &[],
            1,
            "failed to open input file [nosuch.br]: No such file or directory\n",
        ),
        r(
            &["-dc", "d"],
            &[],
            1,
            "failed to read input [d]: Is a directory\n",
        ),
        r(
            &["-d", "d"],
            &[],
            1,
            "empty output file name for [d] input file\n",
        ),
        // names
        r(
            &["-d", "a"],
            &[("a", BR)],
            1,
            "empty output file name for [a] input file\n",
        ),
        r(
            &["-d", "abcd"],
            &[("abcd", BR)],
            1,
            "input file [abcd] suffix mismatch\n",
        ),
        r(
            &["-d", "a.bz"],
            &[("a.bz", BR)],
            1,
            "input file [a.bz] suffix mismatch\n",
        ),
        r(
            &["-d", ".br"],
            &[(".br", BR)],
            1,
            "empty output file name for [.br] input file\n",
        ),
        r(
            &["-d", "d/.br"],
            &[("d/.br", BR)],
            1,
            "empty output file name for [d/.br] input file\n",
        ),
        r(
            &["-d", "a.br", "x"],
            &[("a.br", BR), ("x", BR)],
            1,
            "empty output file name for [x] input file\n",
        ),
        r(
            &["-d", "x", "a.br"],
            &[("a.br", BR), ("x", BR)],
            1,
            "empty output file name for [x] input file\n",
        ),
        r(
            &["-d", "a.br"],
            &[("a.br", BR), ("a", b"x")],
            1,
            "failed to open output file [a]: File exists\n",
        ),
        r(&["-df", "a.br"], &[("a.br", BR), ("a", b"x")], 0, ""),
        r(&["-d", "-S", ".x", "a.x"], &[("a.x", BR)], 0, ""),
        r(&["-d", "--suffix=.x", "a.x"], &[("a.x", BR)], 0, ""),
        r(
            &["-d", "-S", ".x", "a.br"],
            &[("a.br", BR)],
            1,
            "input file [a.br] suffix mismatch\n",
        ),
        r(&["-d", "-S", "x", "ax"], &[("ax", BR)], 0, ""),
        r(&["-d", "-S", ".br", "d/a.br"], &[("d/a.br", BR)], 0, ""),
        r(&["-d", "-o", "out", "a.br"], &[("a.br", BR)], 0, ""),
        r(&["-d", "-o", "out", "a"], &[("a", BR)], 0, ""),
        r(&["-d", "-o", "out"], &[("<stdin>", BR)], 0, ""),
        r(&["-d", "-o", "out", "-"], &[("<stdin>", BR)], 0, ""),
        r(
            &["-d", "-o", "out", "a.br"],
            &[("a.br", BR), ("out", b"x")],
            1,
            "failed to open output file [out]: File exists\n",
        ),
        r(&["-d", "-k", "a.br"], &[("a.br", BR)], 0, ""),
        r(&["-d", "-j", "a.br"], &[("a.br", BR)], 0, ""),
        r(
            &["-d", "-j", "a.br"],
            &[("a.br", JUNK)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-d", "a.br"],
            &[("a.br", JUNK)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(&["-d", "-n", "a.br"], &[("a.br", BR)], 0, ""),
        r(
            &["-d", "a.br", "b.br"],
            &[("a.br", BR), ("b.br", JUNK)],
            1,
            "corrupt input [b.br]\n",
        ),
        r(
            &["-d", "b.br", "a.br"],
            &[("a.br", BR), ("b.br", JUNK)],
            1,
            "corrupt input [b.br]\n",
        ),
        // large window, dictionary, comment
        r(&["-dc", "a.br"], &[("a.br", BR_LARGE)], 0, ""),
        r(
            &["-dc", "-D", "dict", "a.br"],
            &[("a.br", BR_DICT), ("dict", DICT)],
            0,
            "",
        ),
        r(
            &["-dc", "--dictionary=dict", "a.br"],
            &[("a.br", BR_DICT), ("dict", DICT)],
            0,
            "",
        ),
        r(&["-dc", "a.br"], &[("a.br", BR_DICT)], 0, ""),
        r(
            &["-dc", "-D", "d2", "a.br"],
            &[("a.br", BR_DICT2), ("d2", DICT2)],
            0,
            "",
        ),
        r(
            &["-dc", "a.br"],
            &[("a.br", BR_DICT2)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-D", "dict", "a.br"],
            &[("a.br", BR_DICT2), ("dict", DICT)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-D", "nodict", "a.br"],
            &[("a.br", BR)],
            1,
            "failed to open dictionary file [nodict]: No such file or directory\n",
        ),
        r(
            &["-t", "-D", "nodict", "a.br"],
            &[("a.br", BR)],
            1,
            "failed to open dictionary file [nodict]: No such file or directory\n",
        ),
        r(&["-dc", "-C", "Zm9v", "a.br"], &[("a.br", BR_FOO)], 0, ""),
        r(
            &["-dc", "--comment=Zm9v", "a.br"],
            &[("a.br", BR_FOO)],
            0,
            "",
        ),
        r(&["-t", "-C", "Zm9v", "a.br"], &[("a.br", BR_FOO)], 0, ""),
        r(&["-dc", "-C", "Zm9v"], &[("<stdin>", BR_FOO)], 0, ""),
        r(
            &["-dc", "-C", "Zm9x", "a.br"],
            &[("a.br", BR_FOO)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-C", "Zm9vYg==", "a.br"],
            &[("a.br", BR_FOO)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-C", "Zm8=", "a.br"],
            &[("a.br", BR_FOO)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-d", "-C", "Zm9x", "a.br"],
            &[("a.br", BR_FOO)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-C", "Zm9v", "a.br"],
            &[("a.br", BR)],
            0,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-d", "-C", "Zm9v", "a.br"],
            &[("a.br", BR)],
            0,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-t", "-C", "Zm9v", "a.br"],
            &[("a.br", BR)],
            0,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-C", "Zm9v", "a.br"],
            &[("a.br", JUNK)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-C", "Zm9v", "a.br"],
            &[("a.br", BR_CUT)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-C", "Zm9v", "a.br"],
            &[("a.br", BR_EXTRA)],
            1,
            "corrupt input [a.br]\n",
        ),
        r(
            &["-dc", "-C", "Zm9v", "a.br"],
            &[("a.br", b"")],
            1,
            "corrupt input [a.br]\n",
        ),
        r(&["-dc", "a.br"], &[("a.br", BR_FOO)], 0, ""),
    ];

    /// Verbose runs, the `reason:` lines and `-K`'s `extra input`.
    pub const VERBOSE_ROWS: &[Row] = &[
        r(
            &["-v", "-c", "a"],
            &[("a", A)],
            0,
            "Compressed [a]: 6 B -> 11 B in X sec\n",
        ),
        r(
            &["-v", "a"],
            &[("a", A)],
            0,
            "Compressed [a]: 6 B -> 11 B in X sec\n",
        ),
        r(
            &["-vc"],
            &[("<stdin>", A)],
            0,
            "Compressed [con]: 6 B -> 10 B in X sec\n",
        ),
        r(
            &["-vc"],
            &[("<stdin>", b"")],
            0,
            "Compressed [con]: 0 B -> 1 B in X sec\n",
        ),
        r(
            &["-v", "a", "b"],
            &[("a", A), ("b", A)],
            0,
            "Compressed [a]: 6 B -> 11 B in X sec\nCompressed [b]: 6 B -> 11 B in X sec\n",
        ),
        r(
            &["-v", "-s", "a"],
            &[("a", A)],
            0,
            "Compressed [a]: 6 B -> 11 B in X sec\nOutput is larger than input\n",
        ),
        r(
            &["--verbose", "--squash", "a"],
            &[("a", A)],
            0,
            "Compressed [a]: 6 B -> 11 B in X sec\nOutput is larger than input\n",
        ),
        r(
            &["-v", "-c", "-C", "Zm9v", "a"],
            &[("a", A)],
            0,
            "Compressed [a]: 6 B -> 16 B in X sec\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", BR)],
            0,
            "Decompressed [a.br]: 11 B -> 6 B in X sec\n",
        ),
        r(
            &["-vdc"],
            &[("<stdin>", BR)],
            0,
            "Decompressed [con]: 11 B -> 6 B in X sec\n",
        ),
        r(
            &["-vd", "a.br", "b.br"],
            &[("a.br", BR), ("b.br", BR)],
            0,
            "Decompressed [a.br]: 11 B -> 6 B in X sec\nDecompressed [b.br]: 11 B -> 6 B in X sec\n",
        ),
        r(
            &["-vdcK", "a.br"],
            &[("a.br", BR2)],
            0,
            "extra input\nDecompressed [a.br]: 22 B -> 12 B in X sec\n",
        ),
        r(
            &["-vdc", "-C", "Zm9v", "a.br"],
            &[("a.br", BR_FOO)],
            0,
            "Decompressed [a.br]: 16 B -> 6 B in X sec\n",
        ),
        r(
            &["-vdc", "-C", "Zm9v", "a.br"],
            &[("a.br", BR)],
            0,
            "Decompressed [a.br]: 11 B -> 6 B in X sec\ncorrupt input [a.br]\nreason: comment mismatch\n",
        ),
        r(
            &["-vdc", "-C", "Zm9x", "a.br"],
            &[("a.br", BR_FOO)],
            1,
            "corrupt input [a.br]\nreason: comment mismatch\n",
        ),
        r(
            &["-vdc", "-C", "Zm9vYg==", "a.br"],
            &[("a.br", BR_FOO)],
            1,
            "corrupt input [a.br]\nreason: comment mismatch\n",
        ),
        r(
            &["-vdc", "-C", "Zm8=", "a.br"],
            &[("a.br", BR_FOO)],
            1,
            "corrupt input [a.br]\nreason: comment mismatch\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", BR_EXTRA)],
            1,
            "corrupt input [a.br]\nreason: extra input\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", BR2)],
            1,
            "corrupt input [a.br]\nreason: extra input\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", BR_CUT)],
            1,
            "corrupt input [a.br]\nreason: truncated input\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", b"")],
            1,
            "corrupt input [a.br]\nreason: truncated input\n",
        ),
        r(
            &["-vdc"],
            &[("<stdin>", b"")],
            1,
            "corrupt input [con]\nreason: truncated input\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", JUNK)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_PADDING_1 (-14)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", FF)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_PADDING_2 (-15)\n",
        ),
        r(
            &["-vt", "a.br"],
            &[("a.br", JUNK)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_PADDING_1 (-14)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", BR_DICT2)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_DICTIONARY (-12)\n",
        ),
    ];

    /// Rows run under another name: `(invoked name, row)`.
    pub const ALIAS_ROWS: &[(&str, Row)] = &[
        ("unbrotli", r(&["-h"], &[], 0, HELP)),
        ("brcat", r(&["-h"], &[], 0, HELP)),
        (
            "unbrotli",
            r(&["-x"], &[], 1, help!("invalid argument -x\n")),
        ),
        ("brcat", r(&["-x"], &[], 1, help!("invalid argument -x\n"))),
        (
            "unbrotli",
            r(
                &["-d"],
                &[],
                1,
                help!("command already set when parsing -d\n"),
            ),
        ),
        (
            "unbrotli",
            r(
                &["-t"],
                &[],
                1,
                help!("command already set when parsing -t\n"),
            ),
        ),
        (
            "unbrotli",
            r(
                &["--decompress"],
                &[],
                1,
                help!("command already set when parsing --decompress\n"),
            ),
        ),
        (
            "unbrotli",
            r(
                &["--test"],
                &[],
                1,
                help!("command already set when parsing --test\n"),
            ),
        ),
        (
            "brcat",
            r(
                &["-d"],
                &[],
                1,
                help!("command already set when parsing -d\n"),
            ),
        ),
        (
            "brcat",
            r(
                &["-t"],
                &[],
                1,
                help!("command already set when parsing -t\n"),
            ),
        ),
        (
            "brcat",
            r(
                &["-c"],
                &[],
                1,
                help!("write to standard output already set\n"),
            ),
        ),
        (
            "brcat",
            r(
                &["--stdout"],
                &[],
                1,
                help!("write to standard output already set\n"),
            ),
        ),
        (
            "brcat",
            r(
                &["-o", "x"],
                &[],
                1,
                help!("write to standard output already set (-o)\n"),
            ),
        ),
        (
            "brcat",
            r(
                &["--output=x"],
                &[],
                1,
                help!("write to standard output already set (--output)\n"),
            ),
        ),
        (
            "brcat",
            r(
                &["-K"],
                &[],
                1,
                help!("argument -K / --concatenated already set\n"),
            ),
        ),
        (
            "brcat",
            r(
                &["--concatenated"],
                &[],
                1,
                help!("argument -K / --concatenated already set\n"),
            ),
        ),
        ("brcat", r(&["-s"], &[], 1, HELP)),
        ("brcat", r(&["-C", "Zm9v"], &[], 1, HELP)),
        ("unbrotli", r(&["-C", "Zm9v", "-K"], &[], 1, HELP)),
        ("unbrotli", r(&["a.br"], &[("a.br", BR)], 0, "")),
        (
            "unbrotli",
            r(
                &["-t", "a.br"],
                &[("a.br", BR)],
                1,
                help!("command already set when parsing -t\n"),
            ),
        ),
        (
            "unbrotli",
            r(
                &["abcd"],
                &[("abcd", BR)],
                1,
                "input file [abcd] suffix mismatch\n",
            ),
        ),
        ("unbrotli", r(&["-c", "a.br"], &[("a.br", BR)], 0, "")),
        (
            "unbrotli",
            r(&["a.br"], &[("a.br", JUNK)], 1, "corrupt input [a.br]\n"),
        ),
        (
            "unbrotli",
            r(&["a.br"], &[("a.br", BR2)], 1, "corrupt input [a.br]\n"),
        ),
        ("unbrotli", r(&["-K", "a.br"], &[("a.br", BR2)], 0, "")),
        ("brcat", r(&["a.br"], &[("a.br", BR)], 0, "")),
        (
            "brcat",
            r(&["a.br", "b.br"], &[("a.br", BR), ("b.br", BR)], 1, HELP),
        ),
        ("brcat", r(&["a.br"], &[("a.br", BR2)], 0, "")),
        (
            "brcat",
            r(&["a.br"], &[("a.br", JUNK)], 1, "corrupt input [a.br]\n"),
        ),
        (
            "brcat",
            r(
                &["a.br"],
                &[("a.br", BR_EXTRA)],
                1,
                "corrupt input [a.br]\n",
            ),
        ),
        ("brcat", r(&[], &[("<stdin>", BR2)], 0, "")),
        ("brcat", r(&["-"], &[("<stdin>", BR)], 0, "")),
        (
            "brcat",
            r(
                &["-v", "a.br"],
                &[("a.br", BR2)],
                0,
                "extra input\nDecompressed [a.br]: 22 B -> 12 B in X sec\n",
            ),
        ),
        (
            "brcat",
            r(
                &["nosuch.br"],
                &[],
                1,
                "failed to open input file [nosuch.br]: No such file or directory\n",
            ),
        ),
        (
            "brcat",
            r(
                &["-D", "nodict", "a.br"],
                &[("a.br", BR)],
                1,
                "failed to open dictionary file [nodict]: No such file or directory\n",
            ),
        ),
        ("brcat", r(&["-q", "1", "a.br"], &[("a.br", BR)], 0, "")),
        ("brcat", r(&["-j", "a.br"], &[("a.br", BR)], 0, "")),
        (
            "brcat",
            r(&["-C", "Zm9v", "a.br"], &[("a.br", BR_FOO)], 1, HELP),
        ),
    ];

    /// Rows with a terminal: `(stdin is a tty, stdout is a tty, row)`.
    pub const TTY_ROWS: &[(bool, bool, Row)] = &[
        (false, true, r(&["a"], &[("a", A)], 0, "")),
        (
            false,
            true,
            r(
                &["-c", "a"],
                &[("a", A)],
                1,
                "Use -h help. Use -f to force output to a terminal.\n",
            ),
        ),
        (
            false,
            true,
            r(
                &[],
                &[("<stdin>", A)],
                1,
                "Use -h help. Use -f to force output to a terminal.\n",
            ),
        ),
        (
            false,
            true,
            r(
                &["-c", "-"],
                &[("<stdin>", A)],
                1,
                "Use -h help. Use -f to force output to a terminal.\n",
            ),
        ),
        (false, true, r(&["-fc", "a"], &[("a", A)], 0, "")),
        (false, true, r(&["-dc", "a.br"], &[("a.br", BR)], 0, "")),
        (false, true, r(&["-dc"], &[("<stdin>", BR)], 0, "")),
        (false, true, r(&["-t", "a.br"], &[("a.br", BR)], 0, "")),
        (
            true,
            false,
            r(
                &["-dc"],
                &[],
                1,
                "Use -h help. Use -f to force input from a terminal.\n",
            ),
        ),
        (
            true,
            false,
            r(
                &["-dc", "-"],
                &[],
                1,
                "Use -h help. Use -f to force input from a terminal.\n",
            ),
        ),
        (
            true,
            false,
            r(
                &["-t"],
                &[],
                1,
                "Use -h help. Use -f to force input from a terminal.\n",
            ),
        ),
        (
            true,
            false,
            r(
                &["-d", "-o", "out"],
                &[],
                1,
                "Use -h help. Use -f to force input from a terminal.\n",
            ),
        ),
        (true, false, r(&["-dc", "a.br"], &[("a.br", BR)], 0, "")),
        (true, false, r(&["-c", "a"], &[("a", A)], 0, "")),
        (
            true,
            true,
            r(
                &["-dc"],
                &[],
                1,
                "Use -h help. Use -f to force input from a terminal.\n",
            ),
        ),
        (
            true,
            true,
            r(
                &["-c", "a"],
                &[("a", A)],
                1,
                "Use -h help. Use -f to force output to a terminal.\n",
            ),
        ),
        (true, false, r(&["-dfc"], &[], 1, "corrupt input [con]\n")),
    ];

    /// Every table: the reference alone runs all of them.
    fn all_tables() -> Vec<(&'static str, &'static str, bool, bool, &'static Row)> {
        let mut v = Vec::new();
        for r in USAGE_ROWS {
            v.push(("usage", "brotli", false, false, r));
        }
        for r in COMPRESS_ROWS {
            v.push(("compress", "brotli", false, false, r));
        }
        for r in DECOMPRESS_ROWS {
            v.push(("decompress", "brotli", false, false, r));
        }
        for r in VERBOSE_ROWS {
            v.push(("verbose", "brotli", false, false, r));
        }
        for (name, r) in ALIAS_ROWS {
            v.push(("alias", *name, false, false, r));
        }
        for (i, o, r) in TTY_ROWS {
            v.push(("tty", "brotli", *i, *o, r));
        }
        v
    }

    // ---- running a row ----

    /// `d` is a directory with nothing in it.
    fn mkdir_d(w: &Path) {
        fs::create_dir_all(w.join("d")).unwrap();
    }

    fn case<'a>(name: &'a str, r: &'a Row, tty_stdin: bool, tty_stdout: bool) -> Case<'a> {
        let mut stdin = None;
        let mut files = Vec::new();
        for (n, bytes) in r.fixtures {
            if *n == STDIN {
                stdin = Some(bytes.to_vec());
            } else {
                files.push((*n, bytes.to_vec()));
            }
        }
        Case {
            name,
            args: r.args.to_vec(),
            files,
            // A terminal on standard input is fed nothing.
            stdin: if tty_stdin { None } else { stdin },
            tty_stdin,
            tty_stdout,
            env: vec![("LC_ALL", "C")],
            compare_output_bytes: true,
            tz: None,
            unzip_flavour: None,
            zip_flavour: None,
            zip_tree: None,
            tty_ctl: false,
            tty_signal: None,
            expect_stdout_plain: None,
            setup: Some(mkdir_d),
            roundtrip: Roundtrip::Exact,
        }
    }

    /// `in 0.00 sec` becomes `in X sec`: the reference reads the processor
    /// clock.
    pub fn blank_timing(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::new();
        let mut i = 0;
        while i < b.len() {
            if s[i..].starts_with(" in ") {
                let mut j = i + 4;
                let digits = b[j..].iter().take_while(|c| c.is_ascii_digit()).count();
                j += digits;
                if digits > 0
                    && b.get(j) == Some(&b'.')
                    && b.get(j + 1).is_some_and(u8::is_ascii_digit)
                    && b.get(j + 2).is_some_and(u8::is_ascii_digit)
                    && s[j + 3..].starts_with(" sec")
                {
                    out.push_str(" in X sec");
                    i = j + 3 + 4;
                    continue;
                }
            }
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    /// What `r.stderr` is for the program called `name`: the help text's
    /// first line carries the invoked name.
    fn expected_stderr(name: &str, r: &Row) -> String {
        r.stderr
            .replace("Usage: brotli [", &format!("Usage: {name} ["))
    }

    /// `(standard error, standard output)` the row records. A usage error
    /// (exit 1, `stderr` ending in the help text) prints its message to
    /// standard error and the help text to STANDARD OUTPUT (`PrintHelp(name,
    /// is_ok)` picks `stderr` when `is_ok`, which is the `-h` case: exit 0,
    /// the help text on standard error). Every other row's text is all
    /// standard error.
    fn expected_streams(name: &str, r: &Row) -> (String, String) {
        let all = expected_stderr(name, r);
        let help = expected_stderr(name, &r_with(HELP));
        if r.code == 1 && all.ends_with(&help) {
            (all[..all.len() - help.len()].to_owned(), help)
        } else {
            (all, String::new())
        }
    }

    fn r_with(stderr: &'static str) -> Row {
        r(&[], &[], 0, stderr)
    }

    #[test]
    fn the_recorded_table_holds_on_the_reference() {
        let Some(dir) = brotli_dir() else { return };
        let mut bad = Vec::new();
        let mut n = 0;
        for (table, name, tty_in, tty_out, r) in all_tables() {
            n += 1;
            let c = case(name, r, tty_in, tty_out);
            let Some(run) = reference(dir, &c) else {
                return;
            };
            let got = blank_timing(&run.stderr);
            let (want, want_out) = expected_streams(name, r);
            let out = String::from_utf8_lossy(&run.stdout);
            // A row run with `-c` may write the stream to standard output:
            // only the usage rows have text there.
            let out_ok = if want_out.is_empty() {
                true
            } else {
                out == want_out
            };
            if run.code != r.code || got != want || !out_ok {
                bad.push(format!(
                    "{table} {name} {:?}: recorded exit {} with {:?} (stdout help: {}); the reference gave exit {} and {:?} (stdout {} bytes)",
                    r.args, r.code, want, !want_out.is_empty(), run.code, got, run.stdout.len()
                ));
            }
        }
        println!("{n} rows on the reference");
        assert!(
            bad.is_empty(),
            "{} rows differ:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// `-h` writes the help text to standard error, `-V` the version line to
    /// standard output.
    #[test]
    fn help_goes_to_standard_error_and_version_to_standard_output() {
        let Some(dir) = brotli_dir() else { return };
        // `-h` writes the help text to standard error (exit 0).
        for (name, args) in [
            ("brotli", &["-h"][..]),
            ("brotli", &["--help"]),
            ("brotli", &["-k", "-h", "-x"]),
            ("unbrotli", &["-h"]),
            ("brcat", &["-h"]),
        ] {
            let row = r(&[], &[], 0, "");
            let mut c = case(name, &row, false, false);
            c.args = args.to_vec();
            let run = reference(dir, &c).unwrap();
            assert_eq!(run.code, 0, "{name} {args:?}");
            assert_eq!(run.stdout, b"", "{name} {args:?}");
            assert_eq!(
                run.stderr,
                HELP.replace("Usage: brotli [", &format!("Usage: {name} [")),
                "{name} {args:?}"
            );
        }
        for (name, args, want) in [
            ("brotli", &["-V"][..], "brotli 1.2.1\n".to_owned()),
            ("brotli", &["--version"], "brotli 1.2.1\n".to_owned()),
            ("brotli", &["-Vh"], "brotli 1.2.1\n".to_owned()),
            ("unbrotli", &["-V"], "brotli 1.2.1\n".to_owned()),
        ] {
            let row = r(&[], &[], 0, "");
            let mut c = case(name, &row, false, false);
            c.args = args.to_vec();
            let run = reference(dir, &c).unwrap();
            assert_eq!(run.code, 0, "{name} {args:?}");
            assert_eq!(
                String::from_utf8_lossy(&run.stdout),
                want,
                "{name} {args:?}"
            );
            assert_eq!(run.stderr, "", "{name} {args:?}");
        }
    }

    /// A dictionary larger than `BROTLI_MAX_DISTANCE -
    /// BROTLI_MAX_BACKWARD_LIMIT(24)` = 50331660 bytes is refused, before
    /// the input is opened; one of exactly that size is not.
    #[test]
    fn a_dictionary_over_the_limit_is_refused_on_the_reference() {
        let Some(dir) = brotli_dir() else { return };
        fn big(w: &Path) {
            mkdir_d(w);
            fs::File::create(w.join("big"))
                .unwrap()
                .set_len(50_331_661)
                .unwrap();
        }
        fn exact(w: &Path) {
            mkdir_d(w);
            fs::File::create(w.join("big"))
                .unwrap()
                .set_len(50_331_660)
                .unwrap();
        }
        let row = r(&["-c", "-D", "big", "nosuch"], &[], 1, "");
        let mut c = case("brotli", &row, false, false);
        c.setup = Some(big);
        let run = reference(dir, &c).unwrap();
        assert_eq!(run.code, 1);
        assert_eq!(
            run.stderr,
            "dictionary [big] is larger than maximum allowed: 50331660\n"
        );
        c.setup = Some(exact);
        let run = reference(dir, &c).unwrap();
        assert_eq!(run.code, 1);
        assert_eq!(
            run.stderr,
            "failed to open input file [nosuch]: No such file or directory\n"
        );
    }

    #[test]
    fn the_timing_blanker_changes_only_the_figure() {
        assert_eq!(
            blank_timing("Compressed [a]: 6 B -> 11 B in 0.00 sec\n"),
            "Compressed [a]: 6 B -> 11 B in X sec\n"
        );
        assert_eq!(
            blank_timing("a in 12.34 sec in 1.5 sec in x"),
            "a in X sec in 1.5 sec in x"
        );
        assert_eq!(blank_timing("no figure"), "no figure");
        assert_eq!(blank_timing("é in 0.01 sec é"), "é in X sec é");
    }

    // ---- the rows a later task enables ----

    /// Every row of `rows` against the reference and stuffr.
    fn check_rows(label: &str, rows: &[(&str, &Row)]) {
        let Some(dir) = brotli_dir() else { return };
        assert!(!rows.is_empty(), "no rows for {label}");
        let mut bad = Vec::new();
        for (name, r) in rows {
            let c = case(name, r, false, false);
            let Some(mut want) = reference(dir, &c) else {
                return;
            };
            let mut got = stuffr_as(&c);
            want.stderr = blank_timing(&want.stderr);
            got.stderr = blank_timing(&got.stderr);
            let outcome = std::panic::catch_unwind(|| assert_same(&c, &want, &got));
            if let Err(p) = outcome {
                bad.push(panic_text(p));
            }
        }
        assert!(
            bad.is_empty(),
            "{label}: {} of {} rows differ:\n{}",
            bad.len(),
            rows.len(),
            bad.join("\n")
        );
    }

    fn plain(rows: &'static [Row]) -> Vec<(&'static str, &'static Row)> {
        rows.iter().map(|r| ("brotli", r)).collect()
    }

    /// The usage and alias rows that, once the command line parses, go on
    /// to open an input or compress standard input: they pass with Task 4.
    fn needs_io(r: &Row) -> bool {
        matches!(
            r.args,
            ["-C", "Zm9v="] | ["--=1"] | ["a", "b", "-o", "x"] | ["nosuch.br"]
        )
    }

    #[test]
    fn task3_rows_match_the_reference() {
        let mut rows: Vec<_> = plain(USAGE_ROWS)
            .into_iter()
            .filter(|(_, r)| !needs_io(r))
            .collect();
        rows.extend(
            ALIAS_ROWS
                .iter()
                .filter(|(_, r)| r.fixtures.is_empty() && !needs_io(r))
                .map(|(n, r)| (*n, r)),
        );
        check_rows("Task 3", &rows);
    }

    #[test]
    #[ignore = "Task 4"]
    fn task4_rows_match_the_reference() {
        let mut rows = plain(COMPRESS_ROWS);
        rows.extend(plain(DECOMPRESS_ROWS));
        rows.extend(plain(USAGE_ROWS).into_iter().filter(|(_, r)| needs_io(r)));
        rows.extend(
            ALIAS_ROWS
                .iter()
                .filter(|(_, r)| !r.fixtures.is_empty() || needs_io(r))
                .map(|(n, r)| (*n, r)),
        );
        check_rows("Task 4", &rows);
    }

    #[test]
    #[ignore = "Task 5"]
    fn task5_rows_match_the_reference() {
        check_rows("Task 5", &plain(VERBOSE_ROWS));
    }
}
