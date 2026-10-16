//! The lz4 command line: the invoked name's presets (R12), `LZ4_CLEVEL`
//! and `LZ4_NBWORKERS`, the argument loop with its number reader, `lz4c`'s
//! legacy arguments, the help texts and `-V`, the thread count (R4), and
//! the decision table for where each input's output goes (Review Focus 5),
//! up to the point of opening files.
//!
//! **Clean room.** Every rule here was recovered from the man page
//! (`lz4.1`), `lz4 -h`/`-H` and probes of the 1.10.0 binary (Task 3's
//! report and `.claude/rules/compat.md`, "lz4 1.10.0 probes"); lz4's
//! `programs/` was never read. Each rule carries its source.
//!
//! The grammar, in short (all probed):
//! - An argument not starting with `-`, the empty argument, and every
//!   argument after `--` is an operand. `-` alone is standard input when no
//!   input was named yet, else standard output.
//! - Short options aggregate (`-9dkf`). A digit run is a level; `-B`,
//!   `-T`, `-e`, `-i`, `-b` read a number in place (`-T4`, `-B32`), and
//!   `-D` takes the rest of the argument or the next one. Numbers wrap at
//!   2^32 and take a `K`/`M` suffix, optionally `i` then `B` (`-B64KiB`).
//! - Long options are matched whole, except `--fast[=#]` and
//!   `--threads[=#| #]`.
//! - Under a name matching `lz4c`, the rest of a short argument equal to
//!   `c0`, `c1`, `c2`, `hc` or `y` is a legacy argument (`-hc` compresses;
//!   `-hc9` is `-h`).
//! - Usage errors print at display level 1 and exit 1; `-h`, `-H`, `-V`
//!   exit 0 as soon as they are read, whatever the display level.

use std::ffi::OsString;
use std::io::Write;

use stuffr::lz4_opts::{BlockSizeId, EncodeOptions};

use super::messages::{self as m, printf};
use crate::compat::host::Cores;

/// lz4 -H: "when FILE is - or stdin, read standard input"; probe: `lz4
/// stdin`, `lz4 -m a stdin` (also in a list, naming its output
/// `stdin.lz4`).
pub(crate) const STDINMARK: &[u8] = b"stdin";
/// lz4 -H: "'stdout', or '-' for standard output" (only as the output
/// operand; probe: `lz4 STDOUT a` and `lz4 -m a stdout` name files).
const STDOUTMARK: &[u8] = b"stdout";
/// lz4 -H: "'null' to discard output (test mode)" (only as the output
/// operand).
const NULMARK: &[u8] = b"null";
/// The system's null device, spelled exactly so, is the same output as
/// [`NULMARK`] (probe 2026-10-16: `lz4 a /dev/null` and `lz4 -d a.lz4
/// /dev/null` print their summaries and exit 0 with no question, and
/// `lz4 a /dev/null -m -d a.lz4` writes standard output as `null` does;
/// `//dev/null`, `/dev//null`, `./../../dev/null`, a symlink to it and
/// `/dev/zero` are files, asked about when they exist).
const DEVNULL: &[u8] = b"/dev/null";
/// lz4 -H: "for compression, output to filename.lz4"; probe: `lz4 x.LZ4`
/// compresses (the match is case-sensitive).
pub(crate) const EXTENSION: &[u8] = b".lz4";
/// probe: `lz4 -h` is printed at display level 2; `lz4cat -vv` is the
/// first `lz4cat` to print the banner, so `lz4cat` starts at 1.
pub(crate) const DISPLAY_LEVEL_DEFAULT: i32 = 2;
/// lz4.1, LZ4_NBWORKERS: "capped at LZ4_NBWORKERS_MAX (200 by default)";
/// probe: `lz4 -v -T201` says `Requested 201 threads too large =>
/// automatically reduced to 200`.
pub(crate) const THREADS_MAX: u32 = 200;
/// lz4 -H: "-B# : cut file into blocks of size # bytes [32+]"; probe:
/// `-B31` is a usage error, `-B32` is accepted.
const BLOCK_BYTES_MIN: u32 = 32;
/// probe: `-B4194305` and `-B99999999999` both say `using blocks of size
/// 4096 KB`: a byte count is capped at 4 MiB before it is printed.
const BLOCK_BYTES_MAX: u32 = 4 << 20;
/// lz4.1, `--best`: "Same as -12"; lz4 -H: "-12 : slowest compression
/// level".
const LEVEL_BEST: i32 = 12;
/// lz4 -H, Legacy arguments (`lz4c`): "-c1 : high compression"; probe:
/// `lz4c -c1` writes `lz4 -9`'s bytes.
const LEVEL_LEGACY_HIGH: i32 = 9;

/// The operation the arguments ask for; the last one given wins (lz4.1,
/// "Multiple commands"; probe: `lz4 -t -d b.lz4` decompresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// None given: decompress an input ending in `.lz4`, else compress
    /// (lz4.1, `-z`).
    Auto,
    /// `-z`, `--compress`.
    Compress,
    /// `-d`, `--decompress`, `--uncompress`; the `unlz4` and `lz4cat`
    /// names.
    Decompress,
    /// `-t`, `--test`.
    Test,
    /// `--list` (lz4.1: "automatically triggers -m").
    List,
    /// `-b#`: refused when the parse ends (spec deviation 5).
    Bench,
}

/// The output operand as given (`-c` and `-` set [`Output::Stdout`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Output {
    /// None given.
    Auto,
    /// `-c`, `--stdout`, `-`, or the operand `stdout`.
    Stdout,
    /// The operand `null`.
    Null,
    /// A file.
    File(Vec<u8>),
}

/// A parsed command line.
#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "keep and legacy_cli are parse results the run does not need"
)]
pub(crate) struct Command {
    /// The program name usage texts print (R12: the last path component of
    /// `argv[0]`).
    pub program: Vec<u8>,
    /// The operation asked for.
    pub mode: Mode,
    /// The frame options, level and `-l` (`content_size` and `dictionary`
    /// are left for the run: see [`Command::content_size`] and
    /// [`Command::dict_file`]).
    pub opts: EncodeOptions,
    /// The inputs, [`STDINMARK`] standing for standard input. With
    /// [`Command::from_list`] they are `-m`'s operands; otherwise exactly
    /// one.
    pub inputs: Vec<Vec<u8>>,
    /// The output operand, as given.
    pub output: Output,
    /// `-m`, `-r`, `--list` or the `lz4cat` name.
    pub multiple: bool,
    /// The inputs are `-m`'s operands, each with its own output (probe:
    /// `lz4 a b -m` has none, so it compresses standard input into `b`, as
    /// does `lz4 a -m` into standard output).
    pub from_list: bool,
    /// `-r`.
    pub recursive: bool,
    /// `-f`, `--force` (`--no-force` clears it); the `lz4cat` name.
    pub force: bool,
    /// `-c`, `--stdout`, `--to-stdout`; the `lz4cat` name.
    pub force_stdout: bool,
    /// `-k`, `--keep`: the last of `-k`/`--rm` was not `--rm` (probe: `lz4
    /// --rm -k a` keeps `a`).
    pub keep: bool,
    /// `--rm`.
    pub remove: bool,
    /// `--sparse` / `--no-sparse`; `None` when neither was given.
    pub sparse: Option<bool>,
    /// `--content-size` (`--no-content-size` clears it).
    pub content_size: bool,
    /// The display level as parsed: 2, or 1 under `lz4cat`, plus `-v`s,
    /// minus `-q`s. Lowering it for `-m` or standard output is the run's.
    pub display_level: i32,
    /// The compression thread count lz4 would use (R4): `-T#`,
    /// `--threads`, `LZ4_NBWORKERS`, or the automatic count; at most
    /// [`THREADS_MAX`].
    pub threads: u32,
    /// The count asked for when it was above [`THREADS_MAX`] (the `-v`
    /// line [`m::THREADS_REDUCED`] reports it).
    pub threads_reduced_from: Option<u32>,
    /// `-D`'s file.
    pub dict_file: Option<Vec<u8>>,
    /// The name matches `lz4c`: the legacy arguments are read, and the help
    /// texts list them.
    pub legacy_cli: bool,
    /// The hidden `-p`: wait for a key at a clean exit (probe: `lz4 -p -V
    /// < /dev/null` prints [`m::PRESS_ENTER`]).
    pub pause: bool,
}

/// How a parse ended without a command: the exit code, and whether the
/// exit is a clean one `-p` pauses at (`-h`, `-H`, `-V`; not a usage
/// error: probe: `lz4 -p --bogus` does not pause).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stop {
    pub code: i32,
    pub pause: bool,
}

impl Stop {
    /// A usage error's exit: 1, no pause.
    const USAGE: Stop = Stop {
        code: 1,
        pause: false,
    };
}

// ---- names (R12) ----

/// The program name: `argv[0]` after its last `/` or `\` (probe: `exec -a
/// 'a\b/c\unlz4' lz4 -y` prints `unlz4` in its usage on macOS; `exec -a
/// 'unlz4\' lz4 -y` prints an empty name).
pub(crate) fn program_name(argv0: &[u8]) -> &[u8] {
    match argv0.iter().rposition(|&b| b == b'/' || b == b'\\') {
        Some(at) => &argv0[at + 1..],
        None => argv0,
    }
}

/// R12: whether `program` is `name`, or `name` followed by `.` and
/// anything (probe, on `exec -a` names: `unlz4`, `unlz4.exe`, `unlz4.`,
/// `unlz4.1`, `unlz4.exe.bak` decompress; `unlz4-1`, `xunlz4`, `UNLZ4`,
/// `Unlz4`, `unlz4_` do not; likewise `lz4cat.x`, `lz4c.exe`, `lz4c.`
/// against `lz4cat-1`, `LZ4CAT`, `lz4c-x`, `xlz4c`, `LZ4C`).
pub(crate) fn name_matches(program: &[u8], name: &str) -> bool {
    match program.strip_prefix(name.as_bytes()) {
        Some(rest) => rest.is_empty() || rest[0] == b'.',
        None => false,
    }
}

// ---- numbers ----

/// The byte at `p`, or 0 past the end (C's terminating NUL).
fn at(s: &[u8], p: usize) -> u8 {
    s.get(p).copied().unwrap_or(0)
}

/// Read a number at `s[*p..]`: decimal digits (none is 0), wrapping at
/// 2^32, then an optional `K` or `M` (times 2^10 or 2^20, wrapping) with an
/// optional `i` and then `B` after it. `*p` ends after what was read.
///
/// probe: `-B4294967396` is 100 bytes and `-B42949672960` is `-B0`;
/// `-B64K`, `-B64KB`, `-B64KiB` and `-B64Ki` are 64 KB, `-B64k` is 64
/// bytes; `-B4194305K` is 1 KB; `-T1i` is `-T1` then `-i`; `-TK` is `-T0`.
fn read_u32(s: &[u8], p: &mut usize) -> u32 {
    let mut n: u32 = 0;
    while at(s, *p).is_ascii_digit() {
        n = n.wrapping_mul(10).wrapping_add(u32::from(at(s, *p) - b'0'));
        *p += 1;
    }
    let shift = match at(s, *p) {
        b'K' => 10,
        b'M' => 20,
        _ => return n,
    };
    n = n.wrapping_shl(shift);
    *p += 1;
    if at(s, *p) == b'i' {
        *p += 1;
    }
    if at(s, *p) == b'B' {
        *p += 1;
    }
    n
}

/// An environment variable's number: `None` (with [`m::ENV_IGNORED`],
/// printed whatever the display level) when it is set and does not start
/// with a digit; anything after the number is ignored.
///
/// probe: `LZ4_CLEVEL=3x` is 3, `=1K` is 1024, `=4294967297` is 1; `=x`,
/// `=-1`, `=` and `= 4` print the warning, under every name and before the
/// arguments are read (`LZ4_CLEVEL=x lz4 -qq -c` prints it).
fn read_env(env: &dyn Fn(&str) -> Option<OsString>, var: &str, err: &mut dyn Write) -> Option<u32> {
    let v = env(var)?;
    let s = v.as_encoded_bytes();
    if !at(s, 0).is_ascii_digit() {
        printf(err, m::ENV_IGNORED, &[var.as_bytes(), s]);
        return None;
    }
    Some(read_u32(s, &mut 0))
}

/// R4: the threads lz4 compresses with for a count of `requested` (0 is
/// automatic), and the count asked for when the cap lowered it.
///
/// The automatic count is the logical cores less an eighth (rounded down)
/// less one, at least 1. Probed by running the reference with an
/// interposed `sysctlbyname("hw.logicalcpu")` (the one core count it asks
/// for on macOS) answering 0..=13, 16, 20, 24, 32, 64, 100, 128, 200, 250,
/// 256, 300 and 1000: 1, 1, 1, 2, 3, 4, 5, 6, 6, 7, 8, 9, 10, 11, 13, 17,
/// 20, 27, 55, 87, 111, 174, and 218, 223, 262, 874 reduced to 200. This
/// machine (12 logical cores) prints `Using 10 threads`. Elsewhere the
/// logical count is [`Cores::detect`]'s (not probed off macOS).
pub(crate) fn resolve_threads(requested: u32, cores: Cores) -> (u32, Option<u32>) {
    let n = if requested == 0 {
        let logical = cores.logical;
        (logical - logical / 8).saturating_sub(1).max(1)
    } else {
        requested
    };
    if n > THREADS_MAX {
        (THREADS_MAX, Some(n))
    } else {
        (n, None)
    }
}

// ---- help, version, usage ----

/// The banner, deviation 1's (to standard output for `-V`, standard error
/// otherwise).
pub(crate) fn print_banner(w: &mut dyn Write) {
    printf(w, m::BANNER, &[env!("CARGO_PKG_VERSION").as_bytes()]);
}

/// lz4 -h (`long` false) or -H (`long` true), to standard error (probe:
/// `lz4 -h 2>/dev/null` prints nothing). `--help` is `-h` (probe: both are
/// 2117 bytes).
fn print_help(err: &mut dyn Write, program: &[u8], legacy: bool, long: bool) {
    print_banner(err);
    printf(err, m::USAGE, &[program]);
    printf(err, m::HELP_REST, &[]);
    if legacy {
        printf(err, m::HELP_LEGACY, &[]);
    }
    if long {
        printf(err, m::LONG_HELP, &[program; 6]);
        if legacy {
            printf(err, m::LONG_HELP_LEGACY, &[program; 2]);
        }
    }
}

/// A usage error: `Incorrect parameters` and the short usage at display
/// level 1 (probe: `lz4 -q --bogus` prints them, `lz4 -qq --bogus` does
/// not, and `lz4 --bogus -qq` does: the level when the error is read).
pub(crate) fn bad_usage(err: &mut dyn Write, program: &[u8], display_level: i32) -> Stop {
    if display_level >= 1 {
        printf(err, m::INCORRECT_PARAMETERS, &[]);
        printf(err, m::USAGE, &[program]);
    }
    Stop::USAGE
}

/// An error line at display level 1 and exit 1 (`--threads`' errors, a
/// surplus operand).
fn fail(err: &mut dyn Write, display_level: i32, fmt: &str, args: &[&[u8]]) -> Stop {
    if display_level >= 1 {
        printf(err, fmt, args);
    }
    Stop::USAGE
}

// ---- the argument loop ----

/// What the loop builds before the operands are settled.
struct State<'a> {
    program: &'a [u8],
    mode: Mode,
    opts: EncodeOptions,
    input: Option<Vec<u8>>,
    output: Output,
    list: Vec<Vec<u8>>,
    multiple: bool,
    recursive: bool,
    force: bool,
    force_stdout: bool,
    remove: bool,
    sparse: Option<bool>,
    content_size: bool,
    display_level: i32,
    threads: u32,
    dict_file: Option<Vec<u8>>,
    legacy_cli: bool,
    pause: bool,
    bench: bool,
}

impl State<'_> {
    /// An operand (probe: `lz4 a b c` refuses `c` before reading anything
    /// after it; `lz4 a b -c` writes standard output, `lz4 -c a b` refuses
    /// `b`; `lz4 a b -m` compresses standard input into `b`).
    fn operand(&mut self, a: &[u8], err: &mut dyn Write) -> Result<(), Stop> {
        if self.multiple {
            self.list.push(a.to_vec());
        } else if self.input.is_none() {
            self.input = Some(a.to_vec());
        } else if self.output == Output::Auto {
            // lz4 -H: "[output] : 'stdout' ... 'null' to discard output".
            self.output = match a {
                STDOUTMARK => Output::Stdout,
                NULMARK | DEVNULL => Output::Null,
                _ => Output::File(a.to_vec()),
            };
        } else {
            return Err(fail(err, self.display_level, m::WONT_BE_USED, &[a]));
        }
        Ok(())
    }

    /// `-c` (and `--stdout`): standard output, replacing an output operand
    /// already given (probe: `lz4 a null -c` writes standard output).
    fn set_stdout(&mut self) {
        self.force_stdout = true;
        self.output = Output::Stdout;
    }

    /// `-B`'s number (probe: `-B4`..`-B7` are IDs, `-B32` and up a byte
    /// count, anything else a usage error; the line is printed while
    /// parsing, at display level 2: `lz4 -q -B4` prints nothing, `lz4 -B4
    /// -q` prints it).
    fn block_size(&mut self, n: u32, err: &mut dyn Write) -> Result<(), Stop> {
        let (shown, unit) = if let Some(id) = u8::try_from(n).ok().and_then(BlockSizeId::from_id) {
            self.opts.block_size = id;
            self.opts.block_bytes = None;
            (id.bytes() as u32 >> 10, m::BLOCKS_KB)
        } else if n >= BLOCK_BYTES_MIN {
            let bytes = n.min(BLOCK_BYTES_MAX);
            self.opts.block_bytes = Some(bytes);
            if bytes >= 1024 {
                (bytes >> 10, m::BLOCKS_KB)
            } else {
                (bytes, m::BLOCKS_BYTES)
            }
        } else {
            return Err(bad_usage(err, self.program, self.display_level));
        };
        if self.display_level >= 2 {
            printf(err, unit, &[shown.to_string().as_bytes()]);
        }
        Ok(())
    }
}

/// The argument after `args[*i]`, for `--threads #` (probe: `lz4 a
/// --threads` is [`m::MISSING_ARGUMENT`], `lz4 --threads -c a` and `lz4
/// --threads - a` are [`m::SEPARATED_ARGUMENT`]).
fn next_field<'a>(
    args: &'a [OsString],
    i: &mut usize,
    st: &State,
    err: &mut dyn Write,
) -> Result<&'a [u8], Stop> {
    *i += 1;
    let Some(next) = args.get(*i) else {
        return Err(fail(err, st.display_level, m::MISSING_ARGUMENT, &[]));
    };
    let next = next.as_encoded_bytes();
    if at(next, 0) == b'-' {
        return Err(fail(err, st.display_level, m::SEPARATED_ARGUMENT, &[]));
    }
    Ok(next)
}

/// A long option (`a` starts with `--` and is not `--` itself).
fn long_option(
    a: &[u8],
    args: &[OsString],
    i: &mut usize,
    st: &mut State,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), Stop> {
    // lz4.1, OPTIONS, and probes of each spelling (`--decomp`,
    // `--favor-decspeed`, `--best=1`, `--no-keep` are usage errors).
    match a {
        b"--compress" => st.mode = Mode::Compress,
        b"--decompress" | b"--uncompress" => st.mode = Mode::Decompress,
        b"--test" => st.mode = Mode::Test,
        b"--list" => {
            st.mode = Mode::List;
            st.multiple = true;
        }
        b"--favor-decSpeed" => st.opts.favor_dec_speed = true,
        b"--force" => st.force = true,
        b"--no-force" => st.force = false,
        b"--stdout" | b"--to-stdout" => st.set_stdout(),
        b"--multiple" => st.multiple = true,
        b"--frame-crc" => st.opts.content_checksum = true,
        b"--no-frame-crc" => st.opts.content_checksum = false,
        // probe: `--no-crc` then `-BX` keeps the block checksum,
        // `-BX --no-crc` drops it.
        b"--no-crc" => {
            st.opts.content_checksum = false;
            st.opts.block_checksum = false;
        }
        b"--content-size" => st.content_size = true,
        b"--no-content-size" => st.content_size = false,
        b"--sparse" => st.sparse = Some(true),
        b"--no-sparse" => st.sparse = Some(false),
        b"--verbose" => st.display_level += 1,
        b"--quiet" => st.display_level -= 1,
        b"--help" => {
            print_help(err, st.program, st.legacy_cli, false);
            return Err(Stop {
                code: 0,
                pause: st.pause,
            });
        }
        b"--version" => {
            print_banner(out);
            return Err(Stop {
                code: 0,
                pause: st.pause,
            });
        }
        b"--keep" => st.remove = false,
        b"--rm" => st.remove = true,
        b"--best" => st.opts.level = LEVEL_BEST,
        _ => {
            if let Some(rest) = a.strip_prefix(b"--fast") {
                // lz4.1: "--fast[=#] ... If =# is not present, it defaults
                // to 1". probe: `--fast=0`, `--fast=`, `--fast=x`,
                // `--fast=-1`, `--fast=4294967296` and `--fast3` are usage
                // errors; `--fast=1x` is `--fast=1`.
                let n = match rest {
                    [] => 1,
                    [b'=', v @ ..] => read_u32(v, &mut 0),
                    _ => 0,
                };
                if n == 0 {
                    return Err(bad_usage(err, st.program, st.display_level));
                }
                // probe: `--fast=4294967295` writes level 1's bytes: the
                // count is negated as a 32-bit int.
                st.opts.level = (n as i32).wrapping_neg();
            } else if let Some(rest) = a.strip_prefix(b"--threads") {
                // lz4.1: "-T#, --threads=#". probe: `--threads=` is 0,
                // `--threads 4` takes the next argument, and so does
                // `--threadsx 4`; `--threads4 a` reads `a` and fails.
                let v = match rest {
                    [b'=', v @ ..] => v,
                    _ => next_field(args, i, st, err)?,
                };
                let mut p = 0;
                let n = read_u32(v, &mut p);
                if p != v.len() {
                    return Err(fail(err, st.display_level, m::NUMERIC_ONLY, &[]));
                }
                st.threads = n;
            } else {
                return Err(bad_usage(err, st.program, st.display_level));
            }
        }
    }
    Ok(())
}

/// One aggregated short argument (`a[0]` is `-`, `a.len() > 1`).
fn short_options(
    a: &[u8],
    args: &[OsString],
    i: &mut usize,
    st: &mut State,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), Stop> {
    let clean = |st: &State| Stop {
        code: 0,
        pause: st.pause,
    };
    let mut p = 1;
    while p < a.len() {
        if st.legacy_cli {
            // lz4c -h, "Legacy arguments"; probe: matched against the rest
            // of the argument from here (`lz4c -fc0` and `-9c1` are legacy,
            // `-c0d` is `-c -0 -d`, `-hc9` is `-h`, `-yf` is an error,
            // `-fy` forces). `-c0` writes level 1's bytes, `-c1` level
            // 9's, `-c2` and `-hc` level 12's.
            let level = match &a[p..] {
                b"c0" => Some(0),
                b"c1" => Some(LEVEL_LEGACY_HIGH),
                b"c2" | b"hc" => Some(LEVEL_BEST),
                b"y" => {
                    st.force = true;
                    return Ok(());
                }
                _ => None,
            };
            if let Some(level) = level {
                st.opts.level = level;
                return Ok(());
            }
        }
        let c = a[p];
        if c.is_ascii_digit() {
            // lz4 -H: "-1 : fast compression (default) / -12 : slowest
            // compression level"; probe: `-99` and `-1K` write level 12's
            // bytes, `-4294967295` level -1's (liblz4 clamps, not the
            // command line).
            st.opts.level = read_u32(a, &mut p) as i32;
            continue;
        }
        p += 1;
        match c {
            b'V' => {
                print_banner(out);
                return Err(clean(st));
            }
            b'h' => {
                print_help(err, st.program, st.legacy_cli, false);
                return Err(clean(st));
            }
            b'H' => {
                print_help(err, st.program, st.legacy_cli, true);
                return Err(clean(st));
            }
            b'z' => st.mode = Mode::Compress,
            b'd' => st.mode = Mode::Decompress,
            b't' => st.mode = Mode::Test,
            b'l' => st.opts.legacy = true,
            b'c' => st.set_stdout(),
            b'f' => st.force = true,
            b'k' => st.remove = false,
            b'v' => st.display_level += 1,
            b'q' => st.display_level -= 1,
            b'm' => st.multiple = true,
            // lz4.1: "-r operate recursively on directories. This mode
            // also sets -m".
            b'r' => {
                st.recursive = true;
                st.multiple = true;
            }
            // Hidden; probe: `lz4 -p -V` pauses at the end.
            b'p' => st.pause = true,
            // Hidden; probe: `lz4 -S -c a` writes `lz4 -c a`'s bytes (a
            // benchmark switch with no effect elsewhere).
            b'S' => {}
            b'D' => {
                // lz4 -H: "-D FILE"; probe: `-Dx` names `x`, `-D -h`
                // names `-h`, a final `-D` is a usage error.
                let name = if p < a.len() {
                    a[p..].to_vec()
                } else {
                    *i += 1;
                    match args.get(*i) {
                        Some(next) => next.as_encoded_bytes().to_vec(),
                        None => return Err(bad_usage(err, st.program, st.display_level)),
                    }
                };
                st.dict_file = Some(name);
                return Ok(());
            }
            b'B' => {
                // lz4 -H: -B#, -BI, -BD, -BX; probe: they chain (`-BDX`,
                // `-B4D`, `-BX4`, `-B4B5`), and any other letter goes back
                // to the outer loop (`-B4d` decompresses, `-Bc` writes
                // standard output, `-B1x` is a usage error).
                loop {
                    match at(a, p) {
                        b'D' => st.opts.block_linked = true,
                        b'I' => st.opts.block_linked = false,
                        b'X' => st.opts.block_checksum = true,
                        d if d.is_ascii_digit() => {
                            let n = read_u32(a, &mut p);
                            st.block_size(n, err)?;
                            continue;
                        }
                        _ => break,
                    }
                    p += 1;
                }
            }
            b'T' => st.threads = read_u32(a, &mut p),
            // Spec deviation 5: the benchmark is refused when the parse
            // ends. probe: `-b` reads a number only after a digit (`-bK` is
            // a usage error), `-e` and `-i` always (`-eK` is accepted).
            b'b' => {
                st.mode = Mode::Bench;
                st.bench = true;
                if at(a, p).is_ascii_digit() {
                    read_u32(a, &mut p);
                }
            }
            b'e' | b'i' => {
                st.bench = true;
                read_u32(a, &mut p);
            }
            _ => return Err(bad_usage(err, st.program, st.display_level)),
        }
    }
    Ok(())
}

/// Parse `args` (after `argv[0]`) as `program` would. `Err` carries the
/// exit of a run that ends here: help, version, a usage error, or the
/// benchmark's refusal; everything it prints is printed.
pub(crate) fn parse(
    program: &[u8],
    env: &dyn Fn(&str) -> Option<OsString>,
    args: &[OsString],
    cores: Cores,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Command, Stop> {
    // lz4.1: "unlz4 is equivalent to lz4 -d", "lz4cat is equivalent to lz4
    // -dcfm"; R12's rule matches the names.
    let unlz4 = name_matches(program, "unlz4");
    let lz4cat = name_matches(program, "lz4cat");
    let mut st = State {
        program,
        mode: if unlz4 || lz4cat {
            Mode::Decompress
        } else {
            Mode::Auto
        },
        opts: EncodeOptions::default(),
        input: None,
        output: Output::Auto,
        list: Vec::new(),
        multiple: lz4cat,
        recursive: false,
        force: lz4cat,
        force_stdout: false,
        remove: false,
        sparse: None,
        content_size: false,
        display_level: if lz4cat { 1 } else { DISPLAY_LEVEL_DEFAULT },
        threads: 0,
        dict_file: None,
        legacy_cli: name_matches(program, "lz4c"),
        pause: false,
        bench: false,
    };
    if lz4cat {
        st.set_stdout();
    }
    // lz4.1, Environment Variables: LZ4_CLEVEL then LZ4_NBWORKERS (probe:
    // both invalid print in that order), below the command line.
    if let Some(level) = read_env(env, "LZ4_CLEVEL", err) {
        // probe: `LZ4_CLEVEL=4294967295` writes `--fast=1`'s bytes.
        st.opts.level = level as i32;
    }
    if let Some(n) = read_env(env, "LZ4_NBWORKERS", err) {
        st.threads = n;
    }

    let mut all_operands = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_encoded_bytes();
        if all_operands || at(a, 0) != b'-' {
            st.operand(a, err)?;
        } else if a == b"-" {
            // probe: `lz4 - a` reads standard input into `a`; `lz4 a b -`
            // and `lz4 - - -` write standard output.
            if st.input.is_none() {
                st.input = Some(STDINMARK.to_vec());
            } else {
                st.output = Output::Stdout;
            }
        } else if a == b"--" {
            // lz4.1: "-- Treat all subsequent arguments as files".
            all_operands = true;
        } else if at(a, 1) == b'-' {
            long_option(a, args, &mut i, &mut st, out, err)?;
        } else {
            short_options(a, args, &mut i, &mut st, out, err)?;
        }
        i += 1;
    }

    if st.bench {
        if st.display_level >= 1 {
            printf(err, m::BENCH_REFUSED, &[]);
        }
        return Err(Stop::USAGE);
    }

    // probe: with `-m`, only the operands after it are inputs (`lz4 a -m
    // b` reads `b` only), and with none standard input is read into the
    // output operand (`lz4 a b -m` writes `b`); a list gets its own output
    // names unless the output is standard output (`lz4 a b -m c` writes
    // `c.lz4`, `lz4 a - -m c` standard output).
    let from_list = st.multiple && !st.list.is_empty();
    let (inputs, output) = if from_list {
        let output = match st.output {
            Output::Stdout => Output::Stdout,
            // probe: `lz4 a null -m -d b.lz4` decodes to standard output,
            // `lz4 a null -m c` compresses to `c.lz4` ([`list_target`]).
            Output::Null => Output::Null,
            Output::Auto | Output::File(_) => Output::Auto,
        };
        (std::mem::take(&mut st.list), output)
    } else {
        let input = match st.input.take() {
            Some(name) if !st.multiple => name,
            _ => STDINMARK.to_vec(),
        };
        (vec![input], st.output.clone())
    };
    let (threads, threads_reduced_from) = resolve_threads(st.threads, cores);
    Ok(Command {
        program: program.to_vec(),
        mode: st.mode,
        opts: st.opts,
        inputs,
        output,
        multiple: st.multiple,
        from_list,
        recursive: st.recursive,
        force: st.force,
        force_stdout: st.force_stdout,
        keep: !st.remove,
        remove: st.remove,
        sparse: st.sparse,
        content_size: st.content_size,
        display_level: st.display_level,
        threads,
        threads_reduced_from,
        dict_file: st.dict_file,
        legacy_cli: st.legacy_cli,
        pause: st.pause,
    })
}

// ---- where the output goes (Review Focus 5) ----

/// The operation one input gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Compress,
    Decompress,
    Test,
    List,
}

/// Where one input's output goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    Stdout,
    /// Discarded (`-t`, the operand `null`).
    Null,
    File(Vec<u8>),
}

/// The run's plan before any file is opened: the operation and where the
/// output goes. For a list (`Command::from_list`), `target` is only the
/// console check's subject; each input's own comes from [`list_target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub op: Op,
    pub target: Target,
    /// The output name was derived from the input's, so the run announces
    /// it at display level 2 ([`m::COMPRESSED_FILENAME`],
    /// [`m::DECODING_FILE`]; probe: `lz4 a` and `lz4 -d b.lz4` print it,
    /// `lz4 a out` does not).
    pub derived: bool,
}

/// Why a run stops before opening anything (exit 1, display level 1, no
/// `-p` pause: probe: `lz4 -p -d a`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// [`m::STDIN_CONSOLE`].
    StdinConsole,
    /// [`m::STDOUT_CONSOLE`].
    StdoutConsole,
    /// [`m::CANNOT_DETERMINE`], then the usage error.
    NoOutputName,
}

/// The operation for `mode`, `first` being the first input (lz4.1: ".lz4
/// extension implies --decompress by default"; probe: `lz4 -m b.lz4 a`
/// decompresses both, `lz4 -m a b.lz4` compresses both, `lz4 x.LZ4` and
/// standard input compress).
pub(crate) fn op_for(mode: Mode, first: &[u8]) -> Op {
    match mode {
        Mode::Auto if first.ends_with(EXTENSION) => Op::Decompress,
        // `Bench` never leaves `parse`.
        Mode::Auto | Mode::Compress | Mode::Bench => Op::Compress,
        Mode::Decompress => Op::Decompress,
        Mode::Test => Op::Test,
        Mode::List => Op::List,
    }
}

/// `name` without `.lz4`, when something is left (probe: `lz4 .lz4` cannot
/// determine an output name; `lz4 y.lz4.lz4` writes `y.lz4`).
fn strip_extension(name: &[u8]) -> Option<Vec<u8>> {
    name.strip_suffix(EXTENSION)
        .filter(|stem| !stem.is_empty())
        .map(<[u8]>::to_vec)
}

/// The decision table (Review Focus 5), probed with standard input and
/// output as pipes and as terminals:
///
/// | command | output |
/// |---|---|
/// | `lz4 f` (stdout a pipe or a terminal) | `f.lz4`, announced |
/// | `lz4 f -`, `lz4 f stdout`, `lz4 -c f` | standard output |
/// | `lz4 f null`, `lz4 -t f`, `lz4 -t f out` | discarded |
/// | `lz4`, `lz4 -`, `lz4 -d` (stdin) | standard output |
/// | `lz4 - out`, `lz4 f out` | `out` |
/// | `lz4 -d f.lz4`, `lz4 f.lz4`, `unlz4 f.lz4` | `f`, announced |
/// | `lz4 -d f`, `unlz4 f`, `lz4 .lz4` | [`Refusal::NoOutputName`] |
/// | standard input a terminal, read (also `-c`, `-f`, `-t`, `--list`, `-m` with no operand) | [`Refusal::StdinConsole`] |
/// | standard output a terminal, written, no `-c` (`lz4 f -`, `lz4 < f`, `unlz4 < f.lz4`, `lz4 -m` with no operand) | [`Refusal::StdoutConsole`] |
///
/// The terminal checks look at the first input only (probe: `lz4 -m a
/// stdin` with standard input a terminal reads it, as `stdin.lz4`), and
/// standard input's comes first.
pub(crate) fn plan(cmd: &Command, stdin_tty: bool, stdout_tty: bool) -> Result<Plan, Refusal> {
    let first = cmd.inputs.first().map_or(STDINMARK, Vec::as_slice);
    let is_stdin = first == STDINMARK;
    if is_stdin && stdin_tty {
        return Err(Refusal::StdinConsole);
    }
    let op = op_for(cmd.mode, first);
    let mut derived = false;
    let target = match (op, &cmd.output) {
        (Op::Test, _) => Target::Null,
        (_, Output::Stdout) => Target::Stdout,
        (_, Output::Null) => Target::Null,
        (_, Output::File(name)) => Target::File(name.clone()),
        (_, Output::Auto) if is_stdin => Target::Stdout,
        // A list names each output itself ([`list_target`]).
        (_, Output::Auto) if cmd.from_list => Target::Null,
        (Op::Decompress, Output::Auto) => {
            derived = true;
            Target::File(strip_extension(first).ok_or(Refusal::NoOutputName)?)
        }
        (Op::Compress, Output::Auto) => {
            derived = true;
            Target::File([first, EXTENSION].concat())
        }
        (Op::List, Output::Auto) => Target::Stdout,
    };
    // `--list` writes its table to a terminal (probe: `lz4 --list b.lz4`
    // with standard output a terminal).
    if target == Target::Stdout && stdout_tty && !cmd.force_stdout && op != Op::List {
        return Err(Refusal::StdoutConsole);
    }
    Ok(Plan {
        op,
        target,
        derived,
    })
}

/// Where `name`, one of a list's inputs, goes under `op` (lz4.1: "-m ...
/// Compressed file names will be appended a .lz4 suffix"); `None` when a
/// decompressed name cannot be made ([`m::EXTENSION_MISMATCH`]: that input
/// is skipped and the run ends with exit 1).
///
/// probe: `lz4 -m -c a b` and `lz4 a - -m c` write standard output; a
/// decompression or test whose output is standard output or `null` writes
/// standard output (`lz4 -m -t b.lz4`, `lz4 a null -m -d b.lz4`, and
/// `lz4cat -t`), which a terminal does not refuse; `lz4 -m a stdin` writes
/// `stdin.lz4`.
pub(crate) fn list_target(cmd: &Command, op: Op, name: &[u8]) -> Option<Target> {
    match op {
        Op::Test => Some(Target::Stdout),
        Op::Decompress => match cmd.output {
            Output::Stdout | Output::Null => Some(Target::Stdout),
            Output::Auto | Output::File(_) => strip_extension(name).map(Target::File),
        },
        Op::Compress if cmd.output == Output::Stdout => Some(Target::Stdout),
        Op::Compress => Some(Target::File([name, EXTENSION].concat())),
        Op::List => Some(Target::Stdout),
    }
}

/// Print `refusal` (display level 1) and return the exit code, 1.
pub(crate) fn refuse(err: &mut dyn Write, cmd: &Command, refusal: Refusal) -> i32 {
    if cmd.display_level >= 1 {
        match refusal {
            Refusal::StdinConsole => printf(err, m::STDIN_CONSOLE, &[]),
            Refusal::StdoutConsole => printf(err, m::STDOUT_CONSOLE, &[]),
            Refusal::NoOutputName => {
                printf(err, m::CANNOT_DETERMINE, &[]);
            }
        }
    }
    if refusal == Refusal::NoOutputName {
        return bad_usage(err, &cmd.program, cmd.display_level).code;
    }
    1
}

#[cfg(test)]
mod tests;
