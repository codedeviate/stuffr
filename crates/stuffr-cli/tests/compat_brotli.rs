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
    /// `BR` with the stream header flipped (probed 2026-10-28): each fails
    /// with the error its name says (`reason: <name> (<n>)`).
    const E_EXUBERANT_NIBBLE: &[u8] = b"\xa1\x14\x00\x04hello\n\x03";
    const E_RESERVED: &[u8] = b"\x1c";
    const E_HUFFMAN_SAME: &[u8] = b"\x23\x14\x00\x04hello\n\x03";
    const E_CL_SPACE: &[u8] = b"\x21\x15\x00\x04hello\n\x03";
    const E_WINDOW_BITS: &[u8] = b"\x91";
    /// One bit flipped in a 33-byte `-q 11` stream: libbrotli fails with the
    /// names below. The pure tier names all but `BLOCK_LENGTH_2` the same
    /// (Ruling T1-e), which is compared on the C tier only
    /// ([`C_REASON_ROWS`]).
    const E_TRANSFORM: &[u8] = b"\x1f\x42\x00\x00\x05\xdc\x60\x98\xb2\xbf\xe6\x81\x69\x88\x2c\xfb\x64\x8f\x11\x3c\xc8\xc8\xe8\x03\x80\x02\x14\xfc\xa0\x91\xd5\xb3\x07";
    const E_BLOCK_LENGTH_2: &[u8] = b"\x1f\x40\x00\x08\x05\xdc\x60\x98\xb2\xbf\xe6\x81\x69\x88\x2c\xfb\x64\x8f\x11\x3c\xc8\xc8\xe8\x03\x80\x02\x14\xfc\xa0\x91\xd5\xb3\x07";
    const E_BLOCK_LENGTH_1: &[u8] = b"\x1f\x42\x00\x08\x04\xdc\x60\x98\xb2\xbf\xe6\x81\x69\x88\x2c\xfb\x64\x8f\x11\x3c\xc8\xc8\xe8\x03\x80\x02\x14\xfc\xa0\x91\xd5\xb3\x07";
    const E_HUFFMAN_SPACE: &[u8] = b"\x1f\x42\x00\x0a\x05\xdc\x60\x98\xb2\xbf\xe6\x81\x69\x88\x2c\xfb\x64\x8f\x11\x3c\xc8\xc8\xe8\x03\x80\x02\x14\xfc\xa0\x91\xd5\xb3\x07";
    const E_SIMPLE_HUFFMAN_ALPHABET: &[u8] = b"\x1f\x42\x00\x28\x05\xdc\x60\x98\xb2\xbf\xe6\x81\x69\x88\x2c\xfb\x64\x8f\x11\x3c\xc8\xc8\xe8\x03\x80\x02\x14\xfc\xa0\x91\xd5\xb3\x07";
    /// `BR` twice, then a byte that starts no stream.
    const BR2_X: &[u8] = b"\x21\x14\x00\x04hello\n\x03\x21\x14\x00\x04hello\n\x03x";
    /// `BR`, then `BR_CUT`.
    const BR_BR_CUT: &[u8] = b"\x21\x14\x00\x04hello\n\x03\x21\x14\x00\x04hell";
    /// `BR`, then `E_RESERVED`.
    const BR_RESERVED: &[u8] = b"\x21\x14\x00\x04hello\n\x03\x1c";
    /// `BR` three times.
    const BR3: &[u8] =
        b"\x21\x14\x00\x04hello\n\x03\x21\x14\x00\x04hello\n\x03\x21\x14\x00\x04hello\n\x03";

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
        // Task 5: the reason lines (corrupt_reason_lines).
        r(
            &["-vdc", "a.br"],
            &[("a.br", E_EXUBERANT_NIBBLE)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_EXUBERANT_NIBBLE (-1)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", E_RESERVED)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_RESERVED (-2)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", E_HUFFMAN_SAME)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_SIMPLE_HUFFMAN_SAME (-5)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", E_CL_SPACE)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_CL_SPACE (-6)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", E_WINDOW_BITS)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_WINDOW_BITS (-13)\n",
        ),
        r(
            &["-vt"],
            &[("<stdin>", E_RESERVED)],
            1,
            "corrupt input [con]\nreason: FORMAT_RESERVED (-2)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", E_SIMPLE_HUFFMAN_ALPHABET)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_SIMPLE_HUFFMAN_ALPHABET (-4)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", E_HUFFMAN_SPACE)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_HUFFMAN_SPACE (-7)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", E_BLOCK_LENGTH_1)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_BLOCK_LENGTH_1 (-9)\n",
        ),
        r(
            &["-vdc", "a.br"],
            &[("a.br", E_TRANSFORM)],
            1,
            "corrupt input [a.br]\nreason: FORMAT_TRANSFORM (-11)\n",
        ),
        // -K: a fresh decoder on what follows each stream
        // (concatenated_then_garbage).
        r(
            &["-vdcK", "a.br"],
            &[("a.br", BR2_X)],
            1,
            "extra input\nextra input\ncorrupt input [a.br]\nreason: truncated input\n",
        ),
        r(
            &["-vdcK", "a.br"],
            &[("a.br", BR_BR_CUT)],
            1,
            "extra input\ncorrupt input [a.br]\nreason: truncated input\n",
        ),
        r(
            &["-vdcK", "a.br"],
            &[("a.br", BR_EXTRA)],
            1,
            "extra input\ncorrupt input [a.br]\nreason: truncated input\n",
        ),
        r(
            &["-vdcK", "a.br"],
            &[("a.br", BR_RESERVED)],
            1,
            "extra input\ncorrupt input [a.br]\nreason: FORMAT_RESERVED (-2)\n",
        ),
        r(
            &["-vdK", "a.br"],
            &[("a.br", BR_EXTRA)],
            1,
            "extra input\ncorrupt input [a.br]\nreason: truncated input\n",
        ),
        r(&["-dcK", "a.br"], &[("a.br", BR3)], 0, ""),
        r(&["-dK", "a.br"], &[("a.br", BR3)], 0, ""),
        r(
            &["-vdK", "a.br"],
            &[("a.br", BR3)],
            0,
            "extra input\nextra input\nDecompressed [a.br]: 33 B -> 18 B in X sec\n",
        ),
        // second_file_fails_on_decode, verbose: the first output kept.
        r(
            &["-vd", "a.br", "b.br"],
            &[("a.br", BR), ("b.br", JUNK)],
            1,
            "Decompressed [a.br]: 11 B -> 6 B in X sec\ncorrupt input [b.br]\nreason: FORMAT_PADDING_1 (-14)\n",
        ),
        r(
            &["-vt", "a.br", "b.br"],
            &[("a.br", BR), ("b.br", BR_CUT)],
            1,
            "Decompressed [a.br]: 11 B -> 6 B in X sec\ncorrupt input [b.br]\nreason: truncated input\n",
        ),
    ];

    /// Reason lines the pure tier's decoder does not reproduce (Ruling T1-e:
    /// it has no `BLOCK_LENGTH_2` check and fails this stream with
    /// `FORMAT_BLOCK_LENGTH_1 (-9)`). The C tier is compared in full; the
    /// pure tier only for exit 1 and its first line, `corrupt input [a.br]`.
    pub const C_REASON_ROWS: &[Row] = &[r(
        &["-vdc", "a.br"],
        &[("a.br", E_BLOCK_LENGTH_2)],
        1,
        "corrupt input [a.br]\nreason: FORMAT_BLOCK_LENGTH_2 (-10)\n",
    )];

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
        for r in C_REASON_ROWS {
            v.push(("reason", "brotli", false, false, r));
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
            compare_output_bytes: EXACT,
            tz: None,
            unzip_flavour: None,
            zip_flavour: None,
            zip_tree: None,
            tty_ctl: false,
            tty_signal: None,
            expect_stdout_plain: None,
            setup: Some(mkdir_d),
            roundtrip: Roundtrip::Brotli {
                ref_brotli: ref_brotli(),
            },
        }
    }

    /// The C tier promises the reference's bytes; the pure tier's streams
    /// are judged by the reference decoding them.
    const EXACT: bool = cfg!(feature = "brotli-c");

    /// The reference `brotli`, for decoding the pure tier's streams.
    fn ref_brotli() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| format!("{}/brotli", brotli_dir().unwrap_or("/nonexistent")))
    }

    /// Ruling T1-b: the pure tier refuses `-D` (both directions) once the
    /// dictionary has been read.
    pub const PURE_DICTIONARY_REFUSAL: &str =
        "-D is not supported by this build (pure tier); build with --features brotli-c\n";

    /// The dictionary a row names with `-D f` or `--dictionary=f`, when the
    /// row makes that file (so it is read and the pure tier refuses it).
    fn dictionary_fixture(r: &Row) -> Option<&'static str> {
        let mut it = r.args.iter();
        while let Some(a) = it.next() {
            let name = if *a == "-D" {
                it.next().copied()
            } else {
                a.strip_prefix("--dictionary=")
            };
            if let Some(n) = name
                && r.fixtures.iter().any(|(f, _)| *f == n)
            {
                return Some(n);
            }
        }
        None
    }

    /// The decoded length of a row's `-C`/`--comment=` value.
    fn comment_len(r: &Row) -> Option<usize> {
        let mut it = r.args.iter();
        while let Some(a) = it.next() {
            let v = if *a == "-C" {
                it.next().copied()
            } else {
                a.strip_prefix("--comment=")
            };
            if let Some(v) = v {
                return Some(v.trim_end_matches('=').len() * 3 / 4);
            }
        }
        None
    }

    /// What the pure tier says instead of doing the row, if it refuses it:
    /// a `-D` file that exists (ruling T1-b), or a comment of one byte when
    /// compressing (the `brotli` crate writes that metadata block's header
    /// wrong, so the seam refuses it: `failed to emit metadata`). Only for
    /// a command line that parses.
    fn pure_refusal(name: &str, r: &Row) -> Option<String> {
        if EXACT || r.stderr.ends_with(HELP) {
            return None;
        }
        if dictionary_fixture(r).is_some() {
            return Some(PURE_DICTIONARY_REFUSAL.to_owned());
        }
        if !decodes(name, r) && comment_len(r) == Some(1) {
            let input = first_operand(r).unwrap_or("con");
            return Some(format!("failed to emit metadata [{input}]\n"));
        }
        None
    }

    /// Whether the invoked name and arguments decompress or test.
    fn decodes(name: &str, r: &Row) -> bool {
        name != "brotli"
            || r.args.iter().take_while(|a| **a != "--").any(|a| {
                matches!(*a, "--decompress" | "--test")
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && a[1..].chars().any(|c| matches!(c, 'd' | 't')))
            })
    }

    /// Whether a row gets as far as decoding a stream: a decompression or
    /// test that is not stopped first by its command line, its dictionary,
    /// its names, an open or a terminal (Task 4's code) — Task 5's rows.
    fn reaches_decoder(name: &str, r: &Row) -> bool {
        const BEFORE: [&str; 4] = [
            "failed to open ",
            "empty output file name for [",
            "input file [",
            "Use -h help. ",
        ];
        // A failure before decoding counts only when it is the first
        // input's: an earlier input would have been decoded first.
        let first = first_operand(r).unwrap_or("con");
        let stopped_first = BEFORE.iter().any(|b| r.stderr.starts_with(b))
            && (r.stderr.contains(&format!("[{first}]"))
                || !r.stderr.contains('[')
                || r.stderr.starts_with("failed to open dictionary"));
        decodes(name, r) && !(r.code == 1 && (r.stderr.ends_with(HELP) || stopped_first))
    }

    /// A row's first input operand (`-` and no operand: `None`), skipping
    /// the values of the options that take one.
    fn first_operand(r: &Row) -> Option<&'static str> {
        let mut it = r.args.iter();
        let mut dash_dash = false;
        while let Some(a) = it.next() {
            if dash_dash {
                return Some(a);
            }
            match *a {
                "--" => dash_dash = true,
                "-" => return None,
                "-o" | "-S" | "-D" | "-C" | "-q" | "-w" => {
                    it.next();
                }
                _ if a.starts_with('-') => {}
                _ => return Some(a),
            }
        }
        None
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

    /// Off the C tier the compressed size in a `Compressed [f]: A -> B in X
    /// sec` line is the tier's own: `B` becomes `N` (the input size and every
    /// other line are compared).
    fn blank_sizes(s: &str) -> String {
        if EXACT {
            return s.to_owned();
        }
        s.split_inclusive('\n')
            .map(|line| {
                match (
                    line.strip_prefix("Compressed ["),
                    line.find(" -> "),
                    line.rfind(" in X sec"),
                ) {
                    (Some(_), Some(a), Some(b)) if a < b => {
                        format!("{} -> N{}", &line[..a], &line[b..])
                    }
                    _ => line.to_owned(),
                }
            })
            .collect()
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
        let rows: Vec<_> = rows.iter().map(|(n, r)| (*n, false, false, *r)).collect();
        check_tty_rows(label, &rows);
    }

    /// [`check_rows`] with `(name, stdin a tty, stdout a tty, row)`.
    fn check_tty_rows(label: &str, rows: &[(&str, bool, bool, &Row)]) {
        let Some(dir) = brotli_dir() else { return };
        assert!(!rows.is_empty(), "no rows for {label}");
        let mut bad = Vec::new();
        for (name, tty_in, tty_out, r) in rows {
            let c = case(name, r, *tty_in, *tty_out);
            if let Some(refusal) = pure_refusal(name, r) {
                let got = stuffr_as(&c);
                if got.code != 1 || got.stderr != refusal || !got.stdout.is_empty() {
                    bad.push(format!(
                        "{name} {:?}: the pure tier should refuse with {refusal:?}, got exit {} {:?}",
                        r.args, got.code, got.stderr
                    ));
                }
                continue;
            }
            let Some(mut want) = reference(dir, &c) else {
                return;
            };
            let mut got = stuffr_as(&c);
            want.stderr = blank_sizes(&blank_timing(&want.stderr));
            got.stderr = blank_sizes(&blank_timing(&got.stderr));
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

    /// Every file-handling row: Task 4 runs those that stop before a
    /// stream is decoded, Task 5 the rest ([`reaches_decoder`]).
    fn io_rows() -> Vec<(&'static str, &'static Row)> {
        let mut rows = plain(COMPRESS_ROWS);
        rows.extend(plain(DECOMPRESS_ROWS));
        rows.extend(plain(USAGE_ROWS).into_iter().filter(|(_, r)| needs_io(r)));
        rows.extend(
            ALIAS_ROWS
                .iter()
                .filter(|(_, r)| !r.fixtures.is_empty() || needs_io(r))
                .map(|(n, r)| (*n, r)),
        );
        rows
    }

    #[test]
    fn task4_rows_match_the_reference() {
        let rows: Vec<_> = io_rows()
            .into_iter()
            .filter(|(n, r)| !reaches_decoder(n, r) || pure_refusal(n, r).is_some())
            .collect();
        check_rows("Task 4", &rows);
    }

    #[test]
    fn task5_rows_match_the_reference() {
        let mut rows: Vec<_> = io_rows()
            .into_iter()
            .filter(|(n, r)| reaches_decoder(n, r) && pure_refusal(n, r).is_none())
            .collect();
        rows.extend(plain(VERBOSE_ROWS));
        if EXACT {
            rows.extend(plain(C_REASON_ROWS));
        }
        check_rows("Task 5", &rows);
        let tty: Vec<_> = TTY_ROWS
            .iter()
            .filter(|(_, _, r)| reaches_decoder("brotli", r))
            .map(|(i, o, r)| ("brotli", *i, *o, r))
            .collect();
        check_tty_rows("Task 5 terminals", &tty);
    }

    /// Ruling T1-e: off the C tier, a corruption whose reason line the
    /// pure decoder does not reproduce still fails: exit 1, `corrupt input
    /// [a.br]` first, nothing on standard output.
    #[test]
    fn pure_tier_still_refuses_what_it_names_differently() {
        if EXACT {
            return;
        }
        let mut bad = Vec::new();
        for r in C_REASON_ROWS {
            let c = case("brotli", r, false, false);
            let got = stuffr_as(&c);
            if got.code != 1 || !got.stderr.starts_with("corrupt input [a.br]\n") {
                bad.push(format!(
                    "{:?}: exit {} {:?}",
                    r.stderr, got.code, got.stderr
                ));
            }
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }

    /// The terminal refusals (and the rows beside them that stop before
    /// decoding) through the pty harness.
    #[test]
    fn task4_terminal_rows_match_the_reference() {
        let rows: Vec<_> = TTY_ROWS
            .iter()
            .filter(|(_, _, r)| !reaches_decoder("brotli", r))
            .map(|(i, o, r)| ("brotli", *i, *o, r))
            .collect();
        check_tty_rows("Task 4 terminals", &rows);
    }

    // ---- Task 4: file handling beyond the recorded rows ----

    /// A fixture or row made at run time, kept for the test's life.
    fn leak<T: ?Sized>(v: Box<T>) -> &'static T {
        Box::leak(v)
    }

    fn row(
        args: &[&'static str],
        fixtures: Vec<(&'static str, Vec<u8>)>,
        code: i32,
        stderr: &'static str,
    ) -> &'static Row {
        let fixtures: Vec<(&'static str, &'static [u8])> = fixtures
            .into_iter()
            .map(|(n, b)| (n, leak(b.into_boxed_slice())))
            .collect();
        leak(Box::new(r(
            leak(args.to_vec().into_boxed_slice()),
            leak(fixtures.into_boxed_slice()),
            code,
            stderr,
        )))
    }

    /// The window a stream's header declares (RFC 7932 9.1, `WBITS`);
    /// `None` for the large-window header.
    fn stream_lgwin(b: &[u8]) -> Option<u32> {
        let b = *b.first()?;
        if b & 1 == 0 {
            return Some(16);
        }
        let n = u32::from((b >> 1) & 7);
        if n != 0 {
            return Some(17 + n);
        }
        match u32::from((b >> 4) & 7) {
            0 => Some(17),
            1 => None,
            m => Some(8 + m),
        }
    }

    /// Standard input's length is unknown: the window is 24, whatever the
    /// input's size, where the same bytes from a file get the smallest
    /// window that holds them.
    #[test]
    fn stdin_uses_the_default_window() {
        let data = text(100_000, 41);
        let piped = row(&["-c"], vec![(STDIN, data.clone())], 0, "");
        let file = row(&["-c", "f"], vec![("f", data)], 0, "");
        check_rows(
            "stdin_uses_the_default_window",
            &[("brotli", piped), ("brotli", file)],
        );
        let out = stuffr_as(&case("brotli", piped, false, false)).stdout;
        assert_eq!(stream_lgwin(&out), Some(24));
        let out = stuffr_as(&case("brotli", file, false, false)).stdout;
        assert_eq!(stream_lgwin(&out), Some(17));
    }

    fn hard_link_b_to_a(w: &Path) {
        mkdir_d(w);
        fs::hard_link(w.join("a"), w.join("b")).unwrap();
    }

    fn hard_link_a_to_a_br(w: &Path) {
        mkdir_d(w);
        fs::hard_link(w.join("a.br"), w.join("a")).unwrap();
    }

    fn symlink_a_br_to_a(w: &Path) {
        mkdir_d(w);
        std::os::unix::fs::symlink("a", w.join("a.br")).unwrap();
    }

    /// `(args, input bytes, setup, message, files that must keep them)`.
    type SelfCase = (
        &'static [&'static str],
        &'static [u8],
        Option<fn(&Path)>,
        &'static str,
        &'static [&'static str],
    );

    /// Ruling T1-f (deviation 4): an output that is the input itself (the
    /// same name, a hard link, a symlink) is refused before it is opened for
    /// writing, compressing and decompressing alike; the reference truncates
    /// the input. Without `-f` the reference's own `O_EXCL` refusal stands.
    #[test]
    fn self_output_never_loses_the_input() {
        const SAME_A: &str = "input file [a] is the same as the output file\n";
        const SAME_A_BR: &str = "input file [a.br] is the same as the output file\n";
        let cases: [SelfCase; 6] = [
            (&["-f", "-o", "a", "a"], A, None, SAME_A, &["a"]),
            (
                &["-f", "-o", "b", "a"],
                A,
                Some(hard_link_b_to_a),
                SAME_A,
                &["a", "b"],
            ),
            (&["-f", "a"], A, Some(symlink_a_br_to_a), SAME_A, &["a"]),
            (&["-df", "-o", "a", "a"], BR, None, SAME_A, &["a"]),
            (
                &["-df", "-o", "b", "a"],
                BR,
                Some(hard_link_b_to_a),
                SAME_A,
                &["a", "b"],
            ),
            (&["-df", "a.br"], BR, None, SAME_A_BR, &["a.br", "a"]),
        ];
        for (i, (args, data, setup, msg, kept)) in cases.into_iter().enumerate() {
            // The last case's input is `a.br`, hard-linked as `a`.
            let (name, setup) = if i == 5 {
                ("a.br", Some(hard_link_a_to_a_br as fn(&Path)))
            } else {
                ("a", setup)
            };
            let rw = row(args, vec![(name, data.to_vec())], 1, msg);
            let mut c = case("brotli", rw, false, false);
            if let Some(f) = setup {
                c.setup = Some(f);
            }
            let got = stuffr_as(&c);
            assert_eq!((got.code, got.stderr.as_str()), (1, msg), "{args:?}");
            assert!(got.stdout.is_empty(), "{args:?}");
            for k in kept {
                let (bytes, _, _) = got
                    .tree
                    .get(*k)
                    .unwrap_or_else(|| panic!("{args:?}: {k} gone"));
                assert_eq!(bytes, data, "{args:?}: {k} changed");
            }
        }
        // Without `-f`: the reference's own refusal, input intact.
        let rw = row(
            &["-o", "a", "a"],
            vec![("a", A.to_vec())],
            1,
            "failed to open output file [a]: File exists\n",
        );
        let rw2 = row(
            &["-d", "-o", "a", "a"],
            vec![("a", BR.to_vec())],
            1,
            "failed to open output file [a]: File exists\n",
        );
        check_rows(
            "self_output_without_force",
            &[("brotli", rw), ("brotli", rw2)],
        );
    }

    fn b_unreadable(w: &Path) {
        use std::os::unix::fs::PermissionsExt;
        mkdir_d(w);
        fs::set_permissions(w.join("b"), fs::Permissions::from_mode(0o000)).unwrap();
    }

    /// The second input cannot be opened: the first one's output is kept,
    /// the run stops there, exit 1.
    #[test]
    fn second_file_fails_keeps_the_first() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root reads a mode-000 file");
            return;
        }
        let Some(dir) = brotli_dir() else { return };
        let rw = row(
            &["a", "b", "c"],
            vec![("a", A.to_vec()), ("b", A.to_vec()), ("c", A.to_vec())],
            1,
            "failed to open input file [b]: Permission denied\n",
        );
        let mut c = case("brotli", rw, false, false);
        c.setup = Some(b_unreadable);
        let want = reference(dir, &c).unwrap();
        let got = stuffr_as(&c);
        assert_same(&c, &want, &got);
        assert!(got.tree.contains_key("a.br") && !got.tree.contains_key("c.br"));
        assert_eq!(got.stderr, rw.stderr);
    }

    /// `(mode, atime, mtime)`, times as `(seconds, nanoseconds)`.
    type Stat = (u32, (i64, i64), (i64, i64));

    fn stat_of(p: &Path) -> Stat {
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(p).unwrap();
        (
            m.mode() & 0o7777,
            (m.atime(), m.atime_nsec()),
            (m.mtime(), m.mtime_nsec()),
        )
    }

    /// Run `exe` in a fresh work directory holding `a` (mode 0640, fixed
    /// times with nanoseconds); the stat of `a.br` afterwards.
    /// Also the input's own stat after the run: under Linux `relatime` the
    /// tool's read moves the input's access time (its ctime is newer), and
    /// CopyStat copies what it finds after the read.
    fn run_for_stat(exe: &Path, args: &[&str]) -> (i32, Stat, Stat) {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, SystemTime};
        let s = Scratch::new();
        let w = s.0.join("work");
        fs::write(w.join("a"), text(5000, 3)).unwrap();
        let t = |secs, nanos| SystemTime::UNIX_EPOCH + Duration::new(secs, nanos);
        let f = fs::File::options().write(true).open(w.join("a")).unwrap();
        f.set_times(
            fs::FileTimes::new()
                .set_accessed(t(1_100_000_000, 123_456_789))
                .set_modified(t(1_000_000_000, 987_654_321)),
        )
        .unwrap();
        drop(f);
        fs::set_permissions(w.join("a"), fs::Permissions::from_mode(0o640)).unwrap();
        let out = output(
            std::process::Command::new(exe)
                .args(args)
                .current_dir(&w)
                .env_clear()
                .env("LC_ALL", "C")
                .stdin(std::process::Stdio::null()),
        )
        .unwrap();
        (
            out.status.code().unwrap_or(-1),
            stat_of(&w.join("a.br")),
            stat_of(&w.join("a")),
        )
    }

    /// CopyStat: the output gets the input's permission bits and its
    /// access and modification times to the nanosecond; `-n` copies none.
    #[test]
    fn copy_stat_matches() {
        let Some(dir) = brotli_dir() else { return };
        let reference = Path::new(dir).join("brotli");
        let rw = row(&[], vec![], 0, "");
        let (_guard, ours) = stuffr_link(&case("brotli", rw, false, false));
        let (rc, want, want_in) = run_for_stat(&reference, &["a"]);
        let (sc, got, got_in) = run_for_stat(&ours, &["a"]);
        assert_eq!((rc, sc), (0, 0));
        // Mode and modification time exactly as the reference's.
        assert_eq!((got.0, got.2), (want.0, want.2));
        assert_eq!(got.0, 0o640);
        // Seconds only where the reference was built without
        // `utimensat` (macOS: no `_POSIX_C_SOURCE`), nanoseconds on glibc.
        assert_eq!(got.2.0, 1_000_000_000);
        // The access time is each tool's own input's, after its read; the
        // nanoseconds copied where the reference copies them.
        assert_eq!(want.1.0, want_in.1.0, "reference atime");
        assert_eq!(got.1.0, got_in.1.0, "stuffr atime");
        let ns = |out: (i64, i64), input: (i64, i64)| out.1 == input.1 && out.1 != 0;
        assert_eq!(
            ns(got.1, got_in.1),
            ns(want.1, want_in.1),
            "atime nanoseconds"
        );
        if want.1.1 == 0 {
            assert_eq!(got.1.1, 0);
        }
        let (rc, want, _) = run_for_stat(&reference, &["-n", "a"]);
        let (sc, got, _) = run_for_stat(&ours, &["-n", "a"]);
        assert_eq!((rc, sc), (0, 0));
        assert_eq!(got.0, want.0, "-n: the mode is the created file's");
        assert_ne!(got.2, (1_000_000_000, 987_654_321), "-n copied the time");
    }

    /// `(args, fixtures, message, the later input that must survive)`.
    type LaterCase = (
        &'static [&'static str],
        &'static [(&'static str, &'static [u8])],
        &'static str,
        &'static str,
    );

    /// Ruling T4-f: an output that is a later input operand is refused
    /// before it is opened (the reference overwrites that input unread),
    /// compressing and decompressing; the later input keeps its bytes.
    #[test]
    fn a_later_input_is_never_overwritten() {
        let cases: [LaterCase; 3] = [
            (
                &["-f", "a", "a.br"],
                &[("a", A), ("a.br", BR)],
                "input file [a.br] would be overwritten by the output of [a]\n",
                "a.br",
            ),
            (
                &["-df", "a.br", "a"],
                &[("a.br", BR), ("a", A)],
                "input file [a] would be overwritten by the output of [a.br]\n",
                "a",
            ),
            (
                &["-f", "-S", ".x", "b", "c", "b.x"],
                &[("b", A), ("c", A), ("b.x", BR)],
                "input file [b.x] would be overwritten by the output of [b]\n",
                "b.x",
            ),
        ];
        for (args, files, msg, kept) in cases {
            let fixtures = files.iter().map(|(n, b)| (*n, b.to_vec())).collect();
            let rw = row(args, fixtures, 1, msg);
            let got = stuffr_as(&case("brotli", rw, false, false));
            assert_eq!((got.code, got.stderr.as_str()), (1, msg), "{args:?}");
            let want = files.iter().find(|(n, _)| *n == kept).unwrap().1;
            assert_eq!(
                got.tree.get(kept).map(|t| t.0.as_slice()),
                Some(want),
                "{args:?}"
            );
        }
    }

    /// Ruling T4-g: `-j` keeps the input when the output could not be
    /// written out at its close (here `/dev/full`'s ENOSPC at the flush).
    #[cfg(target_os = "linux")]
    #[test]
    fn rm_keeps_the_input_when_the_close_fails() {
        let rw = row(
            &["-jf", "-o", "/dev/full", "a"],
            vec![("a", A.to_vec())],
            1,
            "",
        );
        let got = stuffr_as(&case("brotli", rw, false, false));
        assert_eq!(
            (got.code, got.stderr.as_str()),
            (1, "fclose failed [/dev/full]: No space left on device\n")
        );
        assert_eq!(got.tree.get("a").map(|t| t.0.as_slice()), Some(A));
    }

    /// `-s`: an output not smaller than its input is removed (the input
    /// stays); `-v` says so after the usual line.
    #[test]
    fn squash_removes_larger_output() {
        let noise = random(4096, 77);
        let rows = [
            row(&["-s", "r"], vec![("r", noise.clone())], 0, ""),
            row(&["-s", "-j", "r"], vec![("r", noise.clone())], 0, ""),
            row(
                &["-v", "-s", "r"],
                vec![("r", noise.clone())],
                0,
                "Compressed [r]: 4.000 KiB -> 4.005 KiB in X sec\nOutput is larger than input\n",
            ),
            row(&["-s", "t"], vec![("t", text(4096, 78))], 0, ""),
        ];
        let rows: Vec<_> = rows.iter().map(|r| ("brotli", *r)).collect();
        check_rows("squash_removes_larger_output", &rows);
        let got = stuffr_as(&case("brotli", rows[0].1, false, false));
        assert!(got.tree.contains_key("r") && !got.tree.contains_key("r.br"));
        let got = stuffr_as(&case("brotli", rows[2].1, false, false));
        assert!(
            got.stderr.ends_with("\nOutput is larger than input\n"),
            "{}",
            got.stderr
        );
    }

    /// `-j`: the input is removed only after its output is complete; a
    /// failure (output exists, the next input missing) keeps it.
    #[test]
    fn rm_removes_only_after_success() {
        let rows = [
            row(&["-j", "a"], vec![("a", A.to_vec())], 0, ""),
            row(
                &["-j", "a"],
                vec![("a", A.to_vec()), ("a.br", b"x".to_vec())],
                1,
                "failed to open output file [a.br]: File exists\n",
            ),
            row(
                &["-j", "a", "nosuch", "b"],
                vec![("a", A.to_vec()), ("b", A.to_vec())],
                1,
                "failed to open input file [nosuch]: No such file or directory\n",
            ),
            row(&["-j", "-c", "a"], vec![("a", A.to_vec())], 0, ""),
            row(&["-j"], vec![(STDIN, A.to_vec())], 0, ""),
            row(
                &["-j", "d"],
                vec![],
                1,
                "failed to read input [d]: Is a directory\n",
            ),
        ];
        let rows: Vec<_> = rows.iter().map(|r| ("brotli", *r)).collect();
        check_rows("rm_removes_only_after_success", &rows);
        let got = stuffr_as(&case("brotli", rows[1].1, false, false));
        assert!(got.tree.contains_key("a"), "a removed after a failure");
        let got = stuffr_as(&case("brotli", rows[2].1, false, false));
        assert!(!got.tree.contains_key("a") && got.tree.contains_key("b"));
    }

    fn out_links_to_target(w: &Path) {
        mkdir_d(w);
        fs::write(w.join("t"), b"old target").unwrap();
        std::os::unix::fs::symlink("t", w.join("o")).unwrap();
    }
    fn out_dangles(w: &Path) {
        mkdir_d(w);
        std::os::unix::fs::symlink("t", w.join("o")).unwrap();
    }

    /// Deviation 11 (ruling T5): a symlink at the output name, live or
    /// dangling. Without `-f` both refuse it (`O_EXCL`, `File exists`),
    /// the link and its target untouched; with `-f` the reference writes
    /// through it, stuffr replaces the link with a fresh file and leaves
    /// the target alone. stuffr alone (the reference differs).
    #[test]
    fn force_never_writes_through_a_symlink_at_the_output_name() {
        for (setup, live) in [
            (out_links_to_target as fn(&Path), true),
            (out_dangles, false),
        ] {
            for (args, input, want) in [
                (&["-o", "o", "a"][..], A, A),
                (&["-d", "-o", "o", "a"], BR, A),
            ] {
                let what = format!("{args:?}, live {live}");
                let msg = "failed to open output file [o]: File exists\n";
                let rw = row(args, vec![("a", input.to_vec())], 1, msg);
                let mut c = case("brotli", rw, false, false);
                c.setup = Some(setup);
                let got = stuffr_as(&c);
                assert_eq!((got.code, got.stderr.as_str()), (1, msg), "{what}");
                assert_eq!(got.tree["o"].0, b"t", "{what}: link replaced");
                if live {
                    assert_eq!(got.tree["t"].0, b"old target", "{what}");
                } else {
                    assert!(!got.tree.contains_key("t"), "{what}: t created");
                }

                let mut forced = vec!["-f"];
                forced.extend_from_slice(args);
                let rw = row(&forced, vec![("a", input.to_vec())], 0, "");
                let mut c = case("brotli", rw, false, false);
                c.setup = Some(setup);
                let got = stuffr_as(&c);
                assert_eq!((got.code, got.stderr.as_str()), (0, ""), "-f {what}");
                let o = &got.tree["o"].0;
                assert_ne!(o.as_slice(), b"t", "-f {what}: still the link");
                if args[0] == "-d" {
                    assert_eq!(o.as_slice(), want, "-f {what}");
                }
                if live {
                    assert_eq!(got.tree["t"].0, b"old target", "-f {what}");
                } else {
                    assert!(!got.tree.contains_key("t"), "-f {what}: t created");
                }
            }
        }
    }
}
