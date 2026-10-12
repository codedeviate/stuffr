//! `args.c`: the command line and `XZ_DEFAULTS`/`XZ_OPT`, with the parts
//! of `coder.c` and `util.c` its options reach (the preset, the filter
//! chains, `str_to_uint64`), from XZ Utils 5.8.4 (0BSD, `LICENSE-xz`).
//!
//! **Order** (`args_parse`): the invoked name sets the mode and format
//! (`xzcat`, `unxz`, `lzcat`, `unlzma`, `lzma`, by substring, in that
//! order: R2); then the words of `XZ_DEFAULTS`, then of `XZ_OPT` (split on
//! C `isspace`, their operands ignored), then argv, each through the same
//! `getopt_long` from the start. Every option acts as it is returned, so
//! `--help`, `--version`, `--filters-help` and `--info-memory` stop the run
//! where they stand, and an invalid value stops it at its option.
//!
//! **getopt_long is the C library's**, so its error texts differ by
//! platform ([`Style`]): BSD libc's on Apple platforms and the BSDs (the
//! program named by `getprogname()`, the basename of `argv[0]`; backquoted
//! names; a `-` inside a cluster starts a long option), glibc's elsewhere
//! (the full `argv[0]`; quoted names; an ambiguous prefix lists its
//! candidates). Both permute operands unless `POSIXLY_CORRECT` is set, take
//! a long option's unique prefix, and take a required argument from the
//! next word whatever it is; an optional one only after `=`. Each error is
//! followed by xz's own "Try 'xz --help'" line (hidden by `-q`), exit 1.
//!
//! What `args_parse` calls last, `coder_set_compression_settings`, is
//! `coder.c`'s, in `coder.rs`.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write;

use stuffr::xz_opts::{Bcj, Check, Filter};

use super::coder;
use super::hardware::{Hardware, Limits, THREADS_MAX};
use super::message::{self, Messages, Status, Verbosity, mask_nonprint};
use super::messages as m;
use super::options;
use super::suffix;
use crate::compat::host::{Host, InFile, strerror};

/// `enum operation_mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpMode {
    Compress,
    Decompress,
    Test,
    List,
}

/// `enum format_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormatChoice {
    Auto,
    Xz,
    Lzma,
    Lzip,
    Raw,
}

/// One `--block-list` entry (`block_list_entry`): a Block's uncompressed
/// size (never 0; `u64::MAX` for a trailing `0`, "the rest") and the
/// filter chain it uses (0 = the default chain, 1-9 = `--filtersN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockListEntry {
    pub size: u64,
    pub chain: u8,
}

/// The coder's settings as `args.c` and `coder.c` leave them before
/// `coder_set_compression_settings`.
#[derive(Debug, Clone)]
pub(crate) struct CoderSettings {
    /// The preset level, 0-9 (`preset_number & LZMA_PRESET_LEVEL_MASK`).
    pub preset: u32,
    /// `-e` (`LZMA_PRESET_EXTREME` in `preset_number`).
    pub extreme: bool,
    /// The default filter chain, `chains[0]`; empty while a preset is in
    /// force (`filters_count == 0`).
    pub chain: Vec<Filter>,
    /// The chain came from `--filters` (`string_to_filter_used`).
    pub string_to_filter_used: bool,
    /// `--filters1`..`--filters9`: `chains[1..=9]` (`chains[0]` unused).
    pub chains: [Option<Vec<Filter>>; 10],
    /// `chains_used_mask`.
    pub chains_used_mask: u32,
    /// `--check`; `None` for the default (`check_default`).
    pub check: Option<Check>,
    /// `--block-size` (0: the encoder's default).
    pub block_size: u64,
    /// `--block-list`, with no 0-size entry (a trailing 0 is `u64::MAX`).
    pub block_list: Option<Vec<BlockListEntry>>,
    /// `block_list_chain_mask`.
    pub block_list_chain_mask: u32,
    /// `block_list_largest`.
    pub block_list_largest: u64,
    /// `opt_auto_adjust` (`--no-adjust` clears it).
    pub auto_adjust: bool,
    /// `--flush-timeout`, in milliseconds (0: none).
    pub flush_timeout: u64,
    /// `opt_synchronous` (`--no-sync` clears it; so does keeping the input).
    pub synchronous: bool,
    /// hardware.c's threads and memory limits.
    pub limits: Limits,
    /// `mt_options.threads`: the threaded encoder's thread count, which
    /// `coder_set_compression_settings` may lower below the limits' count
    /// to fit the memory limit.
    pub mt_threads: u32,
}

/// Where `--files`/`--files0` read names from.
#[derive(Debug)]
pub(crate) struct FilesFrom {
    /// The file's name as given, or `None` for standard input (whose name
    /// in messages is `(stdin)`).
    pub name: Option<Vec<u8>>,
    /// The terminator: `\n` for `--files`, NUL for `--files0`.
    pub delim: u8,
    /// The file, opened while parsing as `fopen` opens it there, through
    /// [`Host::track`] so a sandboxed run counts what is read of it.
    pub file: Option<InFile>,
}

impl FilesFrom {
    /// The name messages give it (`args->files_name`).
    pub(crate) fn display_name(&self) -> &[u8] {
        self.name.as_deref().unwrap_or(m::STDIN_NAME)
    }
}

/// Everything `args_parse` leaves behind.
#[derive(Debug)]
pub(crate) struct Args {
    pub op: OpMode,
    pub format: FormatChoice,
    pub to_stdout: bool,
    pub keep: bool,
    pub force: bool,
    pub single_stream: bool,
    /// `io_no_sparse` clears it.
    pub sparse: bool,
    pub verbosity: Verbosity,
    pub robot: bool,
    /// `-Q`/`--no-warn`.
    pub no_warn: bool,
    pub ignore_check: bool,
    /// `-S`/`--suffix` (`custom_suffix`).
    pub suffix: Option<Vec<u8>>,
    /// The operands, `-` included; `["-"]` when there are none and no
    /// `--files`/`--files0`.
    pub files: Vec<Vec<u8>>,
    pub files_from: Option<FilesFrom>,
    pub coder: CoderSettings,
}

/// util.c: str_to_uint64, `name` naming the option in the range message.
/// Fatal (exit 1, the message printed) when `value` is not an integer with
/// an optional `KiB`/`MiB`/`GiB` suffix (any case of the first letter; `K`,
/// `Ki`, `KB` too) within `[min, max]`; `max` itself is spelt `max`.
pub(crate) fn str_to_uint64(
    name: &str,
    value: &[u8],
    min: u64,
    max: u64,
    msg: &Messages,
    err: &mut dyn Write,
) -> Result<u64, u8> {
    let range = |err: &mut dyn Write| {
        msg.fatal(
            err,
            m::OUT_OF_RANGE,
            &[
                name.as_bytes(),
                min.to_string().as_bytes(),
                max.to_string().as_bytes(),
            ],
        )
    };
    let skip = value
        .iter()
        .take_while(|&&b| b == b' ' || b == b'\t')
        .count();
    let value = &value[skip..];
    if value == b"max" {
        return Ok(max);
    }
    if !value.first().is_some_and(u8::is_ascii_digit) {
        return Err(msg.fatal(err, m::NOT_AN_INTEGER, &[&mask_nonprint(value)]));
    }
    let digits = value.iter().take_while(|b| b.is_ascii_digit()).count();
    let mut result: u64 = 0;
    for &d in &value[..digits] {
        match result
            .checked_mul(10)
            .and_then(|r| r.checked_add(u64::from(d - b'0')))
        {
            Some(r) => result = r,
            None => return Err(range(err)),
        }
    }
    let rest = &value[digits..];
    if !rest.is_empty() {
        let mut multiplier: u64 = match rest[0] {
            b'k' | b'K' => 1 << 10,
            b'm' | b'M' => 1 << 20,
            b'g' | b'G' => 1 << 30,
            _ => 0,
        };
        let after = &rest[1..];
        if !after.is_empty() && after != b"i" && after != b"iB" && after != b"B" {
            multiplier = 0;
        }
        if multiplier == 0 {
            msg.message(
                err,
                Verbosity::Error,
                m::INVALID_MULTIPLIER,
                &[&mask_nonprint(rest)],
            );
            return Err(msg.fatal(err, m::VALID_SUFFIXES, &[]));
        }
        result = match result.checked_mul(multiplier) {
            Some(r) => r,
            None => return Err(range(err)),
        };
    }
    if result < min || result > max {
        return Err(range(err));
    }
    Ok(result)
}

// ---- getopt_long ----

/// Whose `getopt_long` the platform has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Style {
    /// BSD libc (OpenBSD lineage, `GNU_COMPATIBLE`): Apple platforms and
    /// the BSDs.
    Bsd,
    /// glibc, and everything else.
    Glibc,
}

/// The platform's getopt.
pub(crate) const STYLE: Style = if cfg!(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)) {
    Style::Bsd
} else {
    Style::Glibc
};

/// What an option does: its short letter, or a long-only option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Ch(u8),
    /// `--filters` (0) and `--filters1`..`--filters9`.
    Filters(u8),
    FiltersHelp,
    Bcj(Bcj),
    Delta,
    Lzma1,
    Lzma2,
    NoSync,
    SingleStream,
    NoSparse,
    Files,
    Files0,
    BlockSize,
    BlockList,
    MemCompress,
    MemDecompress,
    MemMtDecompress,
    NoAdjust,
    InfoMemory,
    Robot,
    FlushTimeout,
    IgnoreCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HasArg {
    No,
    Required,
    Optional,
}

/// args.c's `short_opts`.
const SHORT: &[u8] = b"cC:defF:hHlkM:qQrS:tT:vVz0123456789";

/// args.c's `long_opts`, in table order.
const LONG: &[(&str, HasArg, Key)] = &[
    ("compress", HasArg::No, Key::Ch(b'z')),
    ("decompress", HasArg::No, Key::Ch(b'd')),
    ("uncompress", HasArg::No, Key::Ch(b'd')),
    ("test", HasArg::No, Key::Ch(b't')),
    ("list", HasArg::No, Key::Ch(b'l')),
    ("keep", HasArg::No, Key::Ch(b'k')),
    ("force", HasArg::No, Key::Ch(b'f')),
    ("stdout", HasArg::No, Key::Ch(b'c')),
    ("to-stdout", HasArg::No, Key::Ch(b'c')),
    ("no-sync", HasArg::No, Key::NoSync),
    ("single-stream", HasArg::No, Key::SingleStream),
    ("no-sparse", HasArg::No, Key::NoSparse),
    ("suffix", HasArg::Required, Key::Ch(b'S')),
    ("files", HasArg::Optional, Key::Files),
    ("files0", HasArg::Optional, Key::Files0),
    ("format", HasArg::Required, Key::Ch(b'F')),
    ("check", HasArg::Required, Key::Ch(b'C')),
    ("ignore-check", HasArg::No, Key::IgnoreCheck),
    ("block-size", HasArg::Required, Key::BlockSize),
    ("block-list", HasArg::Required, Key::BlockList),
    ("memlimit-compress", HasArg::Required, Key::MemCompress),
    ("memlimit-decompress", HasArg::Required, Key::MemDecompress),
    (
        "memlimit-mt-decompress",
        HasArg::Required,
        Key::MemMtDecompress,
    ),
    ("memlimit", HasArg::Required, Key::Ch(b'M')),
    ("memory", HasArg::Required, Key::Ch(b'M')),
    ("no-adjust", HasArg::No, Key::NoAdjust),
    ("threads", HasArg::Required, Key::Ch(b'T')),
    ("flush-timeout", HasArg::Required, Key::FlushTimeout),
    ("extreme", HasArg::No, Key::Ch(b'e')),
    ("fast", HasArg::No, Key::Ch(b'0')),
    ("best", HasArg::No, Key::Ch(b'9')),
    ("filters", HasArg::Required, Key::Filters(0)),
    ("filters1", HasArg::Required, Key::Filters(1)),
    ("filters2", HasArg::Required, Key::Filters(2)),
    ("filters3", HasArg::Required, Key::Filters(3)),
    ("filters4", HasArg::Required, Key::Filters(4)),
    ("filters5", HasArg::Required, Key::Filters(5)),
    ("filters6", HasArg::Required, Key::Filters(6)),
    ("filters7", HasArg::Required, Key::Filters(7)),
    ("filters8", HasArg::Required, Key::Filters(8)),
    ("filters9", HasArg::Required, Key::Filters(9)),
    ("filters-help", HasArg::No, Key::FiltersHelp),
    ("lzma1", HasArg::Optional, Key::Lzma1),
    ("lzma2", HasArg::Optional, Key::Lzma2),
    ("x86", HasArg::Optional, Key::Bcj(Bcj::X86)),
    ("powerpc", HasArg::Optional, Key::Bcj(Bcj::PowerPc)),
    ("ia64", HasArg::Optional, Key::Bcj(Bcj::Ia64)),
    ("arm", HasArg::Optional, Key::Bcj(Bcj::Arm)),
    ("armthumb", HasArg::Optional, Key::Bcj(Bcj::ArmThumb)),
    ("arm64", HasArg::Optional, Key::Bcj(Bcj::Arm64)),
    ("sparc", HasArg::Optional, Key::Bcj(Bcj::Sparc)),
    ("riscv", HasArg::Optional, Key::Bcj(Bcj::RiscV)),
    ("delta", HasArg::Optional, Key::Delta),
    ("quiet", HasArg::No, Key::Ch(b'q')),
    ("verbose", HasArg::No, Key::Ch(b'v')),
    ("no-warn", HasArg::No, Key::Ch(b'Q')),
    ("robot", HasArg::No, Key::Robot),
    ("info-memory", HasArg::No, Key::InfoMemory),
    ("help", HasArg::No, Key::Ch(b'h')),
    ("long-help", HasArg::No, Key::Ch(b'H')),
    ("version", HasArg::No, Key::Ch(b'V')),
];

/// What one `getopt_long` call returned.
#[derive(Debug, PartialEq, Eq)]
enum Got {
    /// An option and its argument (an optional one may be absent).
    Opt(Key, Option<Vec<u8>>),
    /// `'?'`: an error, its message (if any) printed.
    Bad,
    /// No more options.
    End,
}

/// One pass of `getopt_long` over `words` (no `argv[0]`).
struct Getopt<'w> {
    words: &'w [Vec<u8>],
    /// `optind`.
    ind: usize,
    /// Inside a cluster: the offset of the next letter in `words[ind]`.
    place: usize,
    posix: bool,
    style: Style,
    /// The name getopt's messages start with.
    name: Vec<u8>,
    operands: Vec<Vec<u8>>,
}

impl<'w> Getopt<'w> {
    fn new(words: &'w [Vec<u8>], posix: bool, style: Style, argv0: &[u8]) -> Self {
        let name = match style {
            // getprogname(): the basename of the program as executed.
            Style::Bsd => argv0
                .rsplit(|&b| b == b'/')
                .next()
                .unwrap_or(argv0)
                .to_vec(),
            Style::Glibc => argv0.to_vec(),
        };
        Getopt {
            words,
            ind: 0,
            place: 0,
            posix,
            style,
            name,
            operands: Vec::new(),
        }
    }

    fn say(&self, err: &mut dyn Write, fmt: &str, arg: &[u8]) {
        m::printf(err, fmt, &[&self.name, arg]);
    }

    fn rest_are_operands(&mut self, from: usize) {
        self.operands.extend(self.words[from..].iter().cloned());
        self.ind = self.words.len();
    }

    fn next(&mut self, err: &mut dyn Write) -> Got {
        if self.place == 0 {
            loop {
                let Some(w) = self.words.get(self.ind) else {
                    return Got::End;
                };
                if w.first() != Some(&b'-') || w.len() == 1 {
                    if self.posix {
                        self.rest_are_operands(self.ind);
                        return Got::End;
                    }
                    self.operands.push(w.clone());
                    self.ind += 1;
                    continue;
                }
                if w.as_slice() == b"--" {
                    self.rest_are_operands(self.ind + 1);
                    return Got::End;
                }
                break;
            }
            self.place = 1;
            let words = self.words;
            let w = &words[self.ind];
            if w[1] == b'-' {
                let body = w[2..].to_vec();
                self.place = 0;
                self.ind += 1;
                return self.long(&body, err);
            }
        }
        let words = self.words;
        let w = &words[self.ind];
        let c = w[self.place];
        if self.style == Style::Bsd && c == b'-' && self.place > 1 {
            // BSD: a `-` inside a cluster starts a long option there.
            self.place += 1;
            self.ind += 1;
            if self.place == w.len() {
                // `-k-`: malformed, no message.
                self.place = 0;
                return Got::Bad;
            }
            let body = w[self.place..].to_vec();
            self.place = 0;
            return self.long(&body, err);
        }
        self.place += 1;
        let at_end = self.place == w.len();
        let spec = SHORT.iter().position(|&o| o == c).filter(|_| c != b':');
        let Some(i) = spec else {
            if at_end {
                self.ind += 1;
                self.place = 0;
            }
            let fmt = match (self.style, self.posix) {
                (Style::Bsd, false) => m::BSD_INVALID_OPTION,
                (Style::Bsd, true) => m::BSD_ILLEGAL_OPTION,
                (Style::Glibc, _) => m::GLIBC_INVALID_OPTION,
            };
            self.say(err, fmt, &[c]);
            return Got::Bad;
        };
        if SHORT.get(i + 1) != Some(&b':') {
            if at_end {
                self.ind += 1;
                self.place = 0;
            }
            return Got::Opt(Key::Ch(c), None);
        }
        let arg = if !at_end {
            w[self.place..].to_vec()
        } else {
            match self.words.get(self.ind + 1) {
                Some(a) => {
                    self.ind += 1;
                    a.clone()
                }
                None => {
                    self.ind += 1;
                    self.place = 0;
                    let fmt = match self.style {
                        Style::Bsd => m::BSD_NEEDS_ARGUMENT_SHORT,
                        Style::Glibc => m::GLIBC_NEEDS_ARGUMENT_SHORT,
                    };
                    self.say(err, fmt, &[c]);
                    return Got::Bad;
                }
            }
        };
        self.ind += 1;
        self.place = 0;
        Got::Opt(Key::Ch(c), Some(arg))
    }

    /// The long option `body` (the word after `--`, or after a `-` inside a
    /// BSD cluster); `ind` already points past its word.
    fn long(&mut self, body: &[u8], err: &mut dyn Write) -> Got {
        let (typed, inline) = match body.iter().position(|&b| b == b'=') {
            Some(i) => (&body[..i], Some(body[i + 1..].to_vec())),
            None => (body, None),
        };
        let exact = LONG.iter().position(|(n, _, _)| n.as_bytes() == typed);
        let found = match exact {
            Some(i) => i,
            None => {
                let hits: Vec<usize> = (0..LONG.len())
                    .filter(|&i| LONG[i].0.as_bytes().starts_with(typed))
                    .collect();
                let Some(&first) = hits.first() else {
                    let fmt = match self.style {
                        Style::Bsd => m::BSD_UNRECOGNIZED,
                        Style::Glibc => m::GLIBC_UNRECOGNIZED,
                    };
                    self.say(err, fmt, body);
                    return Got::Bad;
                };
                // Only a candidate that means something else than the
                // first one makes the prefix ambiguous.
                let same = |i: usize| LONG[i].1 == LONG[first].1 && LONG[i].2 == LONG[first].2;
                let differing: Vec<usize> = hits.iter().copied().filter(|&i| !same(i)).collect();
                if !differing.is_empty() {
                    match self.style {
                        Style::Bsd => self.say(err, m::BSD_AMBIGUOUS, typed),
                        Style::Glibc => {
                            let mut line = Vec::new();
                            m::printf(&mut line, m::GLIBC_AMBIGUOUS, &[&self.name, body]);
                            for i in std::iter::once(first).chain(differing) {
                                m::printf(&mut line, m::GLIBC_CANDIDATE, &[LONG[i].0.as_bytes()]);
                            }
                            line.push(b'\n');
                            let _ = err.write_all(&line);
                        }
                    }
                    return Got::Bad;
                }
                first
            }
        };
        let (full, has_arg, key) = LONG[found];
        match (has_arg, inline) {
            (HasArg::No, Some(_)) => {
                match self.style {
                    Style::Bsd => self.say(err, m::BSD_NO_ARGUMENT, typed),
                    Style::Glibc => self.say(err, m::GLIBC_NO_ARGUMENT, full.as_bytes()),
                }
                Got::Bad
            }
            (HasArg::No, None) | (HasArg::Optional, None) => Got::Opt(key, None),
            (_, Some(v)) => Got::Opt(key, Some(v)),
            (HasArg::Required, None) => match self.words.get(self.ind) {
                Some(v) => {
                    self.ind += 1;
                    Got::Opt(key, Some(v.clone()))
                }
                None => {
                    match self.style {
                        Style::Bsd => self.say(err, m::BSD_NEEDS_ARGUMENT_LONG, body),
                        Style::Glibc => {
                            self.say(err, m::GLIBC_NEEDS_ARGUMENT_LONG, full.as_bytes())
                        }
                    }
                    Got::Bad
                }
            },
        }
    }
}

// ---- parse_real ----

/// What parsing goes on with, or the exit code it stopped with.
type Step = Result<(), u8>;

/// The parser's state: what `args_info` and the globals of args.c, coder.c,
/// hardware.c and message.c hold while options are applied.
struct Parser<'a> {
    a: Args,
    msg: Messages,
    host: &'a Host,
    style: Style,
    argv0: Vec<u8>,
}

/// `LZMA_VLI_MAX`.
const VLI_MAX: u64 = u64::MAX / 2;

impl Parser<'_> {
    /// coder.c: forget_filter_chain.
    fn forget_filter_chain(&mut self) {
        self.a.coder.chain.clear();
        self.a.coder.string_to_filter_used = false;
    }

    /// coder.c: coder_add_filter.
    fn add_filter(&mut self, f: Filter, err: &mut dyn Write) -> Step {
        if self.a.coder.chain.len() == 4 {
            return Err(self.msg.fatal(err, m::MAX_FILTERS, &[]));
        }
        if self.a.coder.string_to_filter_used {
            self.forget_filter_chain();
        }
        self.a.coder.chain.push(f);
        self.a.coder.preset = options::PRESET_DEFAULT;
        self.a.coder.extreme = false;
        Ok(())
    }

    /// coder.c: str_to_filters, `index` 0 for `--filters`.
    fn str_to_filters(&self, s: &[u8], index: u8, err: &mut dyn Write) -> Result<Vec<Filter>, u8> {
        options::str_to_filters(s, index == 0).map_err(|e| {
            let num: &[u8] = if index > 0 { &[b'0' + index] } else { b"" };
            let msg = &self.msg;
            msg.message(err, Verbosity::Error, m::FILTERS_ERROR, &[num]);
            msg.message(err, Verbosity::Error, m::PLAIN, &[&mask_nonprint(s)]);
            msg.message(
                err,
                Verbosity::Error,
                m::CARET,
                &[" ".repeat(e.pos).as_bytes()],
            );
            msg.fatal(err, m::PLAIN, &[e.msg.as_bytes()])
        })
    }

    /// args.c: parse_memlimit.
    fn memlimit(
        &mut self,
        name: &str,
        value: &[u8],
        which: (bool, bool, bool),
        err: &mut dyn Write,
    ) -> Step {
        let (pct, v) = match value.strip_suffix(b"%") {
            Some(num) => {
                let pct_name = format!("{name}%");
                (true, str_to_uint64(&pct_name, num, 1, 100, &self.msg, err)?)
            }
            None => (
                false,
                str_to_uint64(name, value, 0, u64::MAX, &self.msg, err)?,
            ),
        };
        self.a
            .coder
            .limits
            .memlimit_set(v, which.0, which.1, which.2, pct);
        Ok(())
    }

    /// args.c: parse_block_list.
    fn block_list(&mut self, s: &[u8], err: &mut dyn Write) -> Step {
        if s.is_empty() || s[0] == b',' {
            return Err(self
                .msg
                .fatal(err, m::BLOCK_LIST_INVALID, &[&mask_nonprint(s)]));
        }
        let parts: Vec<&[u8]> = s.split(|&b| b == b',').collect();
        let count = parts.len();
        let mut list: Vec<BlockListEntry> = Vec::with_capacity(count);
        let mut mask = 0u32;
        let mut largest = 0u64;
        for (i, part) in parts.into_iter().enumerate() {
            let mut entry = BlockListEntry { size: 0, chain: 0 };
            let mut p = part;
            if p.len() >= 2 && p[0].is_ascii_digit() && p[1] == b':' {
                if p.len() == 2 {
                    return Err(self.msg.fatal(err, m::BLOCK_LIST_NO_SIZE, &[&p[..1]]));
                }
                entry.chain = p[0] - b'0';
                mask |= 1 << entry.chain;
                p = &p[2..];
            } else {
                mask |= 1;
            }
            if p.is_empty() {
                // A comma after a comma: the previous entry again (the
                // first entry cannot be empty, checked above).
                entry = list[i - 1];
            } else {
                entry.size = str_to_uint64("block-list", p, 0, u64::MAX, &self.msg, err)?;
                if entry.size == 0 {
                    if i + 1 != count {
                        return Err(self.msg.fatal(err, m::BLOCK_LIST_ZERO, &[]));
                    }
                    entry.size = u64::MAX;
                }
                largest = largest.max(entry.size);
            }
            list.push(entry);
        }
        self.a.coder.block_list = Some(list);
        self.a.coder.block_list_chain_mask = mask;
        self.a.coder.block_list_largest = largest;
        Ok(())
    }

    /// args.c: the `OPT_FILES`/`OPT_FILES0` case.
    fn files(&mut self, delim: u8, arg: Option<Vec<u8>>, err: &mut dyn Write) -> Step {
        if self.a.files_from.is_some() {
            return Err(self.msg.fatal(err, m::ONLY_ONE_FILES, &[]));
        }
        let file = match &arg {
            None => None,
            Some(name) => match File::open(self.host.path(name)) {
                Ok(f) => Some(self.host.track(&self.host.path(name), f)),
                Err(e) => {
                    return Err(self.msg.fatal(
                        err,
                        m::NAME_AND_REASON,
                        &[&mask_nonprint(name), &strerror(&e)],
                    ));
                }
            },
        };
        self.a.files_from = Some(FilesFrom {
            name: arg,
            delim,
            file,
        });
        Ok(())
    }

    /// One option, as parse_real's `switch` acts on it.
    fn apply(
        &mut self,
        key: Key,
        arg: Option<Vec<u8>>,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Step {
        let a = arg.as_deref().unwrap_or_default();
        let msg = &self.msg;
        match key {
            Key::Ch(c @ b'0'..=b'9') => {
                self.a.coder.preset = u32::from(c - b'0');
                self.forget_filter_chain();
            }
            Key::MemCompress => self.memlimit("memlimit-compress", a, (true, false, false), err)?,
            Key::MemDecompress => {
                self.memlimit("memlimit-decompress", a, (false, true, false), err)?
            }
            Key::MemMtDecompress => {
                self.memlimit("memlimit-mt-decompress", a, (false, false, true), err)?
            }
            Key::Ch(b'M') => self.memlimit("memlimit", a, (true, true, true), err)?,
            Key::Ch(b'S') => {
                suffix::check(a, msg, err)?;
                self.a.suffix = Some(a.to_vec());
            }
            Key::Ch(b'T') => {
                let plus = a.first() == Some(&b'+');
                let s = if plus { &a[1..] } else { a };
                let mut t = str_to_uint64("threads", s, 0, THREADS_MAX, msg, err)? as u32;
                if t == 1 && plus {
                    t = u32::MAX;
                }
                self.a.coder.limits.threads_set(t);
            }
            Key::Ch(b'V') => return Err(message::version(msg, self.a.robot, out, err)),
            Key::Ch(b'c') => self.a.to_stdout = true,
            Key::Ch(b'd') => self.a.op = OpMode::Decompress,
            Key::Ch(b'e') => {
                self.a.coder.extreme = true;
                self.forget_filter_chain();
            }
            Key::Ch(b'f') => self.a.force = true,
            Key::InfoMemory => {
                self.a.coder.limits.show(self.a.robot, out);
                return Err(message::exit(
                    Status::Success,
                    &msg.progname,
                    out,
                    err,
                    msg.verbosity != Verbosity::Silent,
                ));
            }
            Key::Ch(b'h') => return Err(message::help(msg, false, out, err)),
            Key::Ch(b'H') => return Err(message::help(msg, true, out, err)),
            Key::Ch(b'l') => self.a.op = OpMode::List,
            Key::Ch(b'k') => self.a.keep = true,
            Key::Ch(b'q') => self.msg.verbosity = self.msg.verbosity.decrease(),
            Key::Ch(b'Q') => self.a.no_warn = true,
            Key::Ch(b't') => self.a.op = OpMode::Test,
            Key::Ch(b'v') => self.msg.verbosity = self.msg.verbosity.increase(),
            Key::Robot => self.a.robot = true,
            Key::Ch(b'z') => self.a.op = OpMode::Compress,
            Key::Filters(0) => {
                // coder.c: coder_add_filters_from_str.
                self.forget_filter_chain();
                self.a.coder.preset = options::PRESET_DEFAULT;
                self.a.coder.extreme = false;
                self.a.coder.string_to_filter_used = true;
                self.a.coder.chain = self.str_to_filters(a, 0, err)?;
            }
            Key::Filters(n) => {
                // coder.c: coder_add_block_filters.
                let chain = self.str_to_filters(a, n, err)?;
                self.a.coder.chains[usize::from(n)] = Some(chain);
                self.a.coder.chains_used_mask |= 1 << n;
            }
            Key::FiltersHelp => return Err(message::filters_help(msg, self.a.robot, out, err)),
            Key::Bcj(kind) => {
                let f = options::options_bcj(kind, arg.as_deref(), msg, err)?;
                self.add_filter(f, err)?;
            }
            Key::Delta => {
                let f = options::options_delta(arg.as_deref(), msg, err)?;
                self.add_filter(f, err)?;
            }
            Key::Lzma1 | Key::Lzma2 => {
                let f = options::options_lzma(key == Key::Lzma1, arg.as_deref(), msg, err)?;
                self.add_filter(f, err)?;
            }
            Key::Ch(b'F') => {
                self.a.format = match a {
                    b"auto" => FormatChoice::Auto,
                    b"xz" => FormatChoice::Xz,
                    b"lzma" | b"alone" => FormatChoice::Lzma,
                    b"lzip" => FormatChoice::Lzip,
                    b"raw" => FormatChoice::Raw,
                    _ => return Err(msg.fatal(err, m::UNKNOWN_FORMAT, &[&mask_nonprint(a)])),
                };
            }
            Key::Ch(b'C') => {
                self.a.coder.check = Some(match a {
                    b"none" => Check::None,
                    b"crc32" => Check::Crc32,
                    b"crc64" => Check::Crc64,
                    b"sha256" => Check::Sha256,
                    _ => return Err(msg.fatal(err, m::UNSUPPORTED_CHECK, &[&mask_nonprint(a)])),
                });
            }
            Key::IgnoreCheck => self.a.ignore_check = true,
            Key::BlockSize => {
                self.a.coder.block_size = str_to_uint64("block-size", a, 0, VLI_MAX, msg, err)?;
            }
            Key::BlockList => self.block_list(a, err)?,
            Key::SingleStream => {
                self.a.single_stream = true;
                // Since 5.7.1alpha --single-stream implies --keep.
                self.a.keep = true;
            }
            Key::NoSparse => self.a.sparse = false,
            Key::Files => self.files(b'\n', arg, err)?,
            Key::Files0 => self.files(0, arg, err)?,
            Key::NoAdjust => self.a.coder.auto_adjust = false,
            Key::FlushTimeout => {
                self.a.coder.flush_timeout =
                    str_to_uint64("flush-timeout", a, 0, u64::MAX, msg, err)?;
            }
            Key::NoSync => self.a.coder.synchronous = false,
            // `-r` is in `short_opts` but has no case.
            Key::Ch(_) => {
                msg.try_help(err);
                return Err(Status::Error as u8);
            }
        }
        Ok(())
    }

    /// args.c: parse_real over `words`; the operands it collected.
    fn parse_real(
        &mut self,
        words: &[Vec<u8>],
        posix: bool,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<Vec<Vec<u8>>, u8> {
        let mut g = Getopt::new(words, posix, self.style, &self.argv0);
        loop {
            match g.next(err) {
                Got::End => return Ok(g.operands),
                Got::Opt(key, arg) => self.apply(key, arg, out, err)?,
                Got::Bad => {
                    self.msg.try_help(err);
                    return Err(Status::Error as u8);
                }
            }
        }
    }
}

/// args.c: parse_environment's split: words separated by C `isspace`
/// (space, `\t`, `\n`, `\v`, `\f`, `\r`).
fn env_words(value: &[u8]) -> Vec<Vec<u8>> {
    value
        .split(|&b| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .filter(|w| !w.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// R2: args.c's name rule, by substring in this order.
fn mode_from_name(name: &str) -> (OpMode, FormatChoice, bool) {
    if name.contains("xzcat") {
        (OpMode::Decompress, FormatChoice::Auto, true)
    } else if name.contains("unxz") {
        (OpMode::Decompress, FormatChoice::Auto, false)
    } else if name.contains("lzcat") {
        (OpMode::Decompress, FormatChoice::Lzma, true)
    } else if name.contains("unlzma") {
        (OpMode::Decompress, FormatChoice::Lzma, false)
    } else if name.contains("lzma") {
        (OpMode::Compress, FormatChoice::Lzma, false)
    } else {
        (OpMode::Compress, FormatChoice::Auto, false)
    }
}

/// args.c: args_parse, for the canonical invoked `name` (the mode rule) and
/// the full `argv0` (every message's program name), up to
/// `coder_set_compression_settings`. `out` takes help, version and
/// `--info-memory`; `Err` is the exit code once everything is printed (0
/// after a help text). `hw` is the machine (R3), and the real process's
/// resource limits are read only under `Host::Real`.
#[allow(clippy::too_many_arguments)] // args_parse's inputs, each distinct
pub(crate) fn parse(
    name: &str,
    argv0: &[u8],
    env: &dyn Fn(&str) -> Option<OsString>,
    args: &[OsString],
    host: &Host,
    hw: Hardware,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(Args, Messages), u8> {
    let real = matches!(host, Host::Real);
    let limits = Limits::init(
        hw,
        real,
        (!real).then_some(super::hardware::SANDBOX_DECODER_CAP),
    );
    let (op, format, to_stdout) = mode_from_name(name);
    let mut p = Parser {
        a: Args {
            op,
            format,
            to_stdout,
            keep: false,
            force: false,
            single_stream: false,
            sparse: true,
            verbosity: Verbosity::Warning,
            robot: false,
            no_warn: false,
            ignore_check: false,
            suffix: None,
            files: Vec::new(),
            files_from: None,
            coder: CoderSettings {
                preset: options::PRESET_DEFAULT,
                extreme: false,
                chain: Vec::new(),
                string_to_filter_used: false,
                chains: Default::default(),
                chains_used_mask: 1,
                check: None,
                block_size: 0,
                block_list: None,
                block_list_chain_mask: 0,
                block_list_largest: 0,
                auto_adjust: true,
                flush_timeout: 0,
                synchronous: true,
                limits,
                mt_threads: 0,
            },
        },
        msg: Messages::new(argv0),
        host,
        style: STYLE,
        argv0: argv0.to_vec(),
    };
    let posix = env("POSIXLY_CORRECT").is_some();
    let r = parse_all(&mut p, env, args, posix, out, err);
    p.a.verbosity = p.msg.verbosity;
    p.msg.no_warn = p.a.no_warn;
    r?;
    Ok((p.a, p.msg))
}

/// args_parse's body after the name rule.
fn parse_all(
    p: &mut Parser,
    env: &dyn Fn(&str) -> Option<OsString>,
    args: &[OsString],
    posix: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Step {
    for var in ["XZ_DEFAULTS", "XZ_OPT"] {
        if let Some(v) = env(var) {
            // The operands are ignored.
            p.parse_real(&env_words(v.as_encoded_bytes()), posix, out, err)?;
        }
    }
    let words: Vec<Vec<u8>> = args.iter().map(|a| a.as_encoded_bytes().to_vec()).collect();
    let operands = p.parse_real(&words, posix, out, err)?;
    let a = &mut p.a;
    let msg = &p.msg;

    if a.op == OpMode::Compress && a.format == FormatChoice::Lzip {
        return Err(msg.fatal(err, m::LZIP_COMPRESS, &[]));
    }
    // Never remove the input when the output is not on disk.
    if a.to_stdout || a.op == OpMode::Test {
        a.keep = true;
        a.to_stdout = true;
    }
    if a.keep {
        a.coder.synchronous = false;
    }
    if a.op == OpMode::Compress && a.format == FormatChoice::Auto {
        a.format = FormatChoice::Xz;
    }
    if (a.op != OpMode::Compress || a.format != FormatChoice::Xz) && a.coder.block_list.is_some() {
        msg.message(err, Verbosity::Warning, m::BLOCK_LIST_IGNORED, &[]);
        a.coder.block_list = None;
    }
    if a.format == FormatChoice::Raw
        && a.suffix.is_none()
        && !a.to_stdout
        && matches!(a.op, OpMode::Compress | OpMode::Decompress)
        && (a.files_from.is_some() || operands.iter().any(|o| o != b"-"))
    {
        return Err(msg.fatal(err, m::RAW_NEEDS_SUFFIX, &[]));
    }
    // Compression settings are validated (the options and their memory
    // usage) when compressing to any format, and when decoding raw data,
    // whose chain comes from the command line.
    if a.op == OpMode::Compress || (a.format == FormatChoice::Raw && a.op != OpMode::List) {
        coder::set_compression_settings(a, msg, err)?;
    }
    a.files = if operands.is_empty() && a.files_from.is_none() {
        vec![b"-".to_vec()]
    } else {
        operands
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Parsed {
        args: Option<Args>,
        code: u8,
        out: String,
        err: String,
    }

    fn run_named(name: &str, args: &[&str], env: &[(&str, &str)]) -> Parsed {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let lookup = move |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| OsString::from(v))
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let r = parse(
            name,
            format!("/x/{name}").as_bytes(),
            &lookup,
            &args,
            &Host::Real,
            Hardware::SANDBOX,
            &mut out,
            &mut err,
        );
        let (args, code) = match r {
            Ok((a, _)) => (Some(a), 0),
            Err(c) => (None, c),
        };
        Parsed {
            args,
            code,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    fn run(args: &[&str]) -> Parsed {
        run_named("xz", args, &[])
    }

    fn ok(args: &[&str]) -> Args {
        let p = run(args);
        p.args
            .unwrap_or_else(|| panic!("{args:?} stopped: {} {}", p.code, p.err))
    }

    const TRY: &str = "/x/xz: Try '/x/xz --help' for more information.\n";

    #[test]
    fn the_name_sets_mode_format_and_stdout() {
        let m = |n: &str| {
            let a = run_named(n, &[], &[]).args.unwrap();
            (a.op, a.format, a.to_stdout)
        };
        assert_eq!(m("xz"), (OpMode::Compress, FormatChoice::Xz, false));
        assert_eq!(m("unxz"), (OpMode::Decompress, FormatChoice::Auto, false));
        assert_eq!(m("xzcat"), (OpMode::Decompress, FormatChoice::Auto, true));
        assert_eq!(m("lzma"), (OpMode::Compress, FormatChoice::Lzma, false));
        assert_eq!(m("unlzma"), (OpMode::Decompress, FormatChoice::Lzma, false));
        assert_eq!(m("lzcat"), (OpMode::Decompress, FormatChoice::Lzma, true));
        // The substring rule, in args.c's order.
        assert_eq!(mode_from_name("xzcat-unlzma").0, OpMode::Decompress);
        assert_eq!(
            mode_from_name("my-lzma"),
            (OpMode::Compress, FormatChoice::Lzma, false)
        );
    }

    #[test]
    fn operands_interleave_and_default_to_stdin() {
        let a = ok(&["a", "-k", "--", "-c"]);
        assert!(a.keep && !a.to_stdout);
        assert_eq!(a.files, vec![b"a".to_vec(), b"-c".to_vec()]);
        assert_eq!(ok(&[]).files, vec![b"-".to_vec()]);
        let a = ok(&["-9ekc"]);
        assert!(a.keep && a.to_stdout && a.coder.extreme);
        assert_eq!(a.coder.preset, 9);
        let a = run_named("xz", &["-c", "a", "-v"], &[("POSIXLY_CORRECT", "")])
            .args
            .unwrap();
        assert_eq!(a.files, vec![b"a".to_vec(), b"-v".to_vec()]);
    }

    #[test]
    fn long_options_take_unique_prefixes() {
        let a = ok(&["--dec", "--stdo", "--memo=1MiB"]);
        assert_eq!((a.op, a.to_stdout), (OpMode::Decompress, true));
        assert_eq!(a.coder.limits.memlimit_get(OpMode::Compress), 1 << 20);
        let a = ok(&["--lzma2", "a"]);
        assert_eq!(a.files, vec![b"a".to_vec()]);
        assert_eq!(a.coder.chain.len(), 1);
    }

    /// The platform's getopt texts (recorded on macOS from 5.8.4; glibc's
    /// from its getopt.c).
    #[test]
    fn getopt_errors_use_the_platforms_words() {
        let p = run(&["-Y"]);
        let (bsd, glibc) = (
            format!("xz: invalid option -- Y\n{TRY}"),
            format!("/x/xz: invalid option -- 'Y'\n{TRY}"),
        );
        assert_eq!(p.code, 1);
        assert_eq!(p.err, if STYLE == Style::Bsd { bsd } else { glibc });
        let p = run(&["--fil"]);
        let want = match STYLE {
            Style::Bsd => format!("xz: option `--fil' is ambiguous\n{TRY}"),
            Style::Glibc => format!(
                "/x/xz: option '--fil' is ambiguous; possibilities: '--files' '--files0' \
                 '--filters' '--filters1' '--filters2' '--filters3' '--filters4' '--filters5' \
                 '--filters6' '--filters7' '--filters8' '--filters9' '--filters-help'\n{TRY}"
            ),
        };
        assert_eq!(p.err, want);
    }

    /// Both styles, on any platform, against their recorded texts.
    #[test]
    fn both_getopt_styles_word_errors_as_their_libc() {
        fn errs(style: Style, args: &[&str]) -> String {
            let words: Vec<Vec<u8>> = args.iter().map(|a| a.as_bytes().to_vec()).collect();
            let mut g = Getopt::new(&words, false, style, b"/x/xz");
            let mut err = Vec::new();
            while !matches!(g.next(&mut err), Got::Bad | Got::End) {}
            String::from_utf8(err).unwrap()
        }
        use Style::*;
        for (style, args, want) in [
            (Bsd, &["--frob"][..], "xz: unrecognized option `--frob'\n"),
            (Bsd, &["--frob=1"], "xz: unrecognized option `--frob=1'\n"),
            (Bsd, &["--mem=1"], "xz: option `--mem' is ambiguous\n"),
            (Bsd, &["--=x"], "xz: option `--' is ambiguous\n"),
            (Bsd, &["-T"], "xz: option requires an argument -- T\n"),
            (
                Bsd,
                &["--threads"],
                "xz: option `--threads' requires an argument\n",
            ),
            (
                Bsd,
                &["--q=1"],
                "xz: option `--q' doesn't allow an argument\n",
            ),
            (Bsd, &["-k-"], ""),
            (Bsd, &["-?"], "xz: invalid option -- ?\n"),
            (Bsd, &["-:"], "xz: invalid option -- :\n"),
            (
                Glibc,
                &["--frob=1"],
                "/x/xz: unrecognized option '--frob=1'\n",
            ),
            (
                Glibc,
                &["--mem=1"],
                "/x/xz: option '--mem=1' is ambiguous; possibilities: \
                 '--memlimit-compress' '--memlimit-decompress' \
                 '--memlimit-mt-decompress' '--memlimit' '--memory'\n",
            ),
            (
                Glibc,
                &["-T"],
                "/x/xz: option requires an argument -- 'T'\n",
            ),
            (
                Glibc,
                &["--thr"],
                "/x/xz: option '--threads' requires an argument\n",
            ),
            (
                Glibc,
                &["--q=1"],
                "/x/xz: option '--quiet' doesn't allow an argument\n",
            ),
            (Glibc, &["-k-x"], "/x/xz: invalid option -- '-'\n"),
        ] {
            assert_eq!(errs(style, args), want, "{style:?} {args:?}");
        }
        // BSD: a `-` inside a cluster starts a long option.
        let words = vec![b"-k-stdout".to_vec()];
        let mut g = Getopt::new(&words, false, Bsd, b"xz");
        let mut err = Vec::new();
        assert_eq!(g.next(&mut err), Got::Opt(Key::Ch(b'k'), None));
        assert_eq!(g.next(&mut err), Got::Opt(Key::Ch(b'c'), None));
        assert_eq!(g.next(&mut err), Got::End);
        // POSIXLY_CORRECT: BSD says "illegal".
        let words = vec![b"-Y".to_vec()];
        let mut g = Getopt::new(&words, true, Bsd, b"xz");
        let mut err = Vec::new();
        assert_eq!(g.next(&mut err), Got::Bad);
        assert_eq!(String::from_utf8(err).unwrap(), "xz: illegal option -- Y\n");
    }

    #[test]
    fn quiet_hides_the_try_line_but_not_getopts() {
        let p = run(&["-q", "-Y"]);
        assert_eq!(p.code, 1);
        assert!(!p.err.contains("Try"), "{}", p.err);
        let p = run(&["-r"]);
        assert_eq!((p.code, p.err.as_str()), (1, TRY));
    }

    #[test]
    fn stops_happen_in_argv_order() {
        let p = run(&["-h", "-Y"]);
        assert_eq!((p.code, p.err.as_str()), (0, ""));
        assert!(p.out.starts_with("Usage: /x/xz [OPTION]... [FILE]...\n"));
        let p = run(&["-T", "x", "-h"]);
        assert_eq!(
            (p.code, p.out.as_str(), p.err.as_str()),
            (
                1,
                "",
                "/x/xz: x: Value is not a non-negative decimal integer\n"
            )
        );
        let p = run(&["--robot", "-V"]);
        assert_eq!(p.out, "XZ_VERSION=50080042\nLIBLZMA_VERSION=50080042\n");
    }

    /// util.c's texts, recorded from 5.8.4 (`xz -T VALUE -h`).
    #[test]
    fn size_values_parse_as_str_to_uint64() {
        let t = |v: &str| {
            let p = run(&["-T", v]);
            (p.args.map(|a| a.coder.limits.threads_get()), p.err)
        };
        assert_eq!(t("5K"), (Some(5120), String::new()));
        assert_eq!(t(" max"), (Some(16384), String::new()));
        assert_eq!(t("\t 4ki"), (Some(4096), String::new()));
        let range = "/x/xz: Value of the option 'threads' must be in the range [0, 16384]\n";
        assert_eq!(t("16385"), (None, range.into()));
        assert_eq!(t("99999999999999999999"), (None, range.into()));
        assert_eq!(t("5MiB"), (None, range.into()));
        let bad_suffix = |s: &str| {
            format!(
                "/x/xz: {s}: Invalid multiplier suffix\n/x/xz: Valid suffixes are \
                 'KiB' (2^10), 'MiB' (2^20), and 'GiB' (2^30).\n"
            )
        };
        assert_eq!(t("5x").1, bad_suffix("x"));
        assert_eq!(t("5Kib").1, bad_suffix("Kib"));
        assert_eq!(t("5kiBB").1, bad_suffix("kiBB"));
        assert_eq!(
            t("").1,
            "/x/xz: : Value is not a non-negative decimal integer\n"
        );
        // `-T+1` is one thread in threaded mode.
        let a = ok(&["-T+1"]);
        assert!(a.coder.limits.threads_is_mt());
        assert_eq!(a.coder.limits.threads_get(), 1);
        // -qq silences even the fatal message.
        let p = run(&["-qq", "-T", "x"]);
        assert_eq!((p.code, p.err.as_str()), (1, ""));
    }

    #[test]
    fn memlimits_take_percentages() {
        let a = ok(&["-M", "50%"]);
        assert_eq!(a.coder.limits.memlimit_get(OpMode::Compress), 2 << 30);
        let p = run(&["-M", "101%"]);
        assert_eq!(
            p.err,
            "/x/xz: Value of the option 'memlimit%' must be in the range [1, 100]\n"
        );
        let p = run(&["--memlimit-mt-decompress=%"]);
        assert_eq!(
            p.err,
            "/x/xz: : Value is not a non-negative decimal integer\n"
        );
        let p = run(&["-M", "18446744073709551616"]);
        assert_eq!(
            p.err,
            "/x/xz: Value of the option 'memlimit' must be in the range [0, 18446744073709551615]\n"
        );
    }

    /// args.c: parse_block_list (recorded from 5.8.4 where it errs). The
    /// chains the lists name are given, or coder_set_compression_settings
    /// would refuse them.
    #[test]
    fn block_lists_parse_as_args_c() {
        let l = |s: &str| {
            let list = format!("--block-list={s}");
            ok(&["--filters1=lzma2", "--filters2=lzma2", &list])
                .coder
                .block_list
                .unwrap()
        };
        let e = |size, chain| BlockListEntry { size, chain };
        assert_eq!(l("1,,2"), vec![e(1, 0), e(1, 0), e(2, 0)]);
        assert_eq!(
            l("2:1KiB,1:5,,0"),
            vec![e(1024, 2), e(5, 1), e(5, 1), e(u64::MAX, 0)]
        );
        assert_eq!(l("1:5,2:0"), vec![e(5, 1), e(u64::MAX, 2)]);
        let a = ok(&[
            "--filters1=lzma2",
            "--filters2=lzma2",
            "--block-list=2:1KiB,1:5,,0",
        ]);
        assert_eq!(a.coder.block_list_chain_mask, 0b111);
        assert_eq!(a.coder.block_list_largest, u64::MAX);
        // No entry is ever 0.
        assert!(l("0").iter().all(|x| x.size != 0));
        for (s, want) in [
            ("", "/x/xz: : Invalid argument to --block-list\n"),
            (",1", "/x/xz: ,1: Invalid argument to --block-list\n"),
            (
                "0,1",
                "/x/xz: 0 can only be used as the last element in --block-list\n",
            ),
            (
                "1:",
                "/x/xz: In --block-list, block size is missing after filter chain number '1:'\n",
            ),
            (
                "x",
                "/x/xz: x: Value is not a non-negative decimal integer\n",
            ),
            (
                "a:1",
                "/x/xz: a:1: Value is not a non-negative decimal integer\n",
            ),
        ] {
            let p = run(&[&format!("--block-list={s}")]);
            assert_eq!((p.code, p.err.as_str()), (1, want), "{s:?}");
        }
        // Not compressing to .xz: a warning, the list dropped, exit not set.
        let p = run(&["-d", "--block-list=1"]);
        assert_eq!(
            p.err,
            "/x/xz: --block-list is ignored unless compressing to the .xz format\n"
        );
        assert!(p.args.unwrap().coder.block_list.is_none());
    }

    #[test]
    fn filters_errors_print_four_lines() {
        let p = run(&["--filters=lzma2:dict=1"]);
        assert_eq!(
            p.err,
            format!(
                "/x/xz: Error in --filters=FILTERS option:\n/x/xz: lzma2:dict=1\n\
                 /x/xz: {}^\n/x/xz: Value out of range\n",
                " ".repeat(11)
            )
        );
        let p = run(&["--filters3=x86"]);
        assert!(
            p.err
                .starts_with("/x/xz: Error in --filters3=FILTERS option:\n")
        );
        // coder_set_compression_settings keeps only the chains the list
        // uses.
        let a = ok(&["--filters2=x86 lzma2", "--block-list=2:1"]);
        assert_eq!(a.coder.chains_used_mask, 0b100);
        assert!(a.coder.chains[2].is_some());
        let a = ok(&["-d", "--filters2=x86 lzma2", "--filters4=lzma2"]);
        assert_eq!(a.coder.chains_used_mask, 0b10101);
    }

    /// coder.c's preset/chain interplay: a preset forgets a chain, a
    /// filter option resets the preset to 6, `--filters` is replaced by a
    /// later filter option. Seen when decompressing, where
    /// coder_set_compression_settings does not run; compressing, the
    /// preset becomes the chain.
    #[test]
    fn presets_and_chains_forget_each_other() {
        let a = ok(&["-d", "-9", "--lzma2", "-e"]);
        assert!(a.coder.chain.is_empty());
        assert_eq!((a.coder.preset, a.coder.extreme), (6, true));
        let a = ok(&["-d", "--filters=x86 lzma2", "--delta"]);
        assert_eq!(a.coder.chain, vec![Filter::Delta { dist: 1 }]);
        let a = ok(&["-9", "--lzma2", "-e"]);
        let six_e = stuffr::xz_opts::Lzma::preset(6, true).unwrap();
        assert_eq!(a.coder.chain, vec![Filter::Lzma2(six_e)]);
        let p = run(&["--x86", "--x86", "--x86", "--x86", "--x86"]);
        assert_eq!(p.err, "/x/xz: Maximum number of filters is four\n");
    }

    #[test]
    fn format_check_and_suffix_values() {
        assert_eq!(ok(&["-F", "alone"]).format, FormatChoice::Lzma);
        assert_eq!(ok(&["-dF", "lzip"]).format, FormatChoice::Lzip);
        let p = run(&["-F", "\u{1}x"]);
        assert_eq!(p.err, "/x/xz: ?x: Unknown file format type\n");
        let p = run(&["-C", "crc16"]);
        assert_eq!(p.err, "/x/xz: crc16: Unsupported integrity check type\n");
        assert_eq!(ok(&["-C", "sha256"]).coder.check, Some(Check::Sha256));
        let p = run(&["--suffix="]);
        assert_eq!(p.err, "/x/xz: : Invalid filename suffix\n");
        let p = run(&["-F", "lzip"]);
        assert_eq!(
            p.err,
            "/x/xz: Compression of lzip files (.lz) is not supported\n"
        );
        let raw = "/x/xz: With --format=raw, --suffix=.SUF is required unless writing to stdout\n";
        assert_eq!(run(&["-F", "raw", "a"]).err, raw);
        assert!(run(&["-F", "raw", "-", "-"]).args.is_some());
        assert!(run(&["-F", "raw", "-c", "a"]).args.is_some());
        assert!(run(&["-F", "raw", "-S", ".r", "a"]).args.is_some());
        assert!(run(&["-lF", "raw", "a"]).args.is_some());
    }

    #[test]
    fn keep_stdout_and_sync_follow_args_parse() {
        let a = ok(&["-t"]);
        assert!(a.to_stdout && a.keep && !a.coder.synchronous);
        let a = ok(&["--single-stream"]);
        assert!(a.keep && a.single_stream);
        let a = ok(&[]);
        assert!(a.coder.synchronous && !a.keep);
        assert!(!ok(&["--no-sync"]).coder.synchronous);
    }

    #[test]
    fn the_environment_comes_first_and_its_operands_are_ignored() {
        let a = run_named(
            "xz",
            &["-1"],
            &[("XZ_DEFAULTS", "-9 a"), ("XZ_OPT", "-T1\n-k")],
        )
        .args
        .unwrap();
        assert_eq!(a.coder.preset, 1);
        assert!(a.keep && !a.coder.limits.threads_is_mt());
        assert_eq!(a.files, vec![b"-".to_vec()]);
        let p = run_named("xz", &[], &[("XZ_OPT", "-T x")]);
        assert_eq!(
            p.err,
            "/x/xz: x: Value is not a non-negative decimal integer\n"
        );
        let p = run_named("xz", &[], &[("XZ_OPT", "-h")]);
        assert_eq!(p.code, 0);
        assert!(p.out.starts_with("Usage: /x/xz"));
        let p = run_named("xz", &["--files"], &[("XZ_OPT", "--files")]);
        assert_eq!(
            p.err,
            "/x/xz: Only one file can be specified with '--files' or '--files0'.\n"
        );
    }

    #[test]
    fn files_open_while_parsing() {
        let p = run(&["--files=/nonexistent/x"]);
        assert_eq!(p.err, "/x/xz: /nonexistent/x: No such file or directory\n");
        let a = ok(&["--files0"]);
        let f = a.files_from.unwrap();
        assert_eq!((f.display_name(), f.delim), (&b"(stdin)"[..], 0));
        assert!(a.files.is_empty());
    }
}
