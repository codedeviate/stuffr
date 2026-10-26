//! The zip family's command lines: zip.c's option table and `main()`'s
//! option loop and checks, fileio.c's `get_option()` (with `get_shortopt()`
//! and `get_longopt()`), util.c's `envargs()`, and the three helpers' own
//! argument handling (`zipcloak.c`, `zipnote.c`, `zipsplit.c`).
//!
//! `get_option()` is ported as the C has it, state and all: it permutes the
//! arguments in place (so `-sc` shows them options first), inserts a `@` to
//! end a value list, and keeps its position in three integers that the
//! caller owns ([`GetOpt`]). Its errors, which the C raises through
//! `ZIPERR(ZE_PARMS, ...)`, come back as `Err(text)` and the caller makes
//! them the `ziperr`.
//!
//! What this front end stops short of (the later tasks fill it, and until
//! then a command line that gets past every check answers
//! [`messages::NOT_BUILT`], exit 1): the names and patterns it collects are
//! stored as the command line gave them (`Options::names`, `Options::filters`;
//! Task 5 converts them, `add_filter()`'s `ex2in`/`in2ex`), `procname("-")`
//! for a run with no names (Task 5), reading the old archive, and the
//! encryption prompt (a terminal is Task 11's; without one the answer is
//! zip's own).

use std::ffi::OsString;
use std::io::{self, BufRead, Read};

use super::flavour::{self, Flavour};
use super::messages::{self as m, printf};
use super::scan;
use super::{Exit, Zr};

// ziperr.h's ZE_* codes the front end meets.
/// ziperr.h:ZE_OK
pub(crate) const ZE_OK: i32 = 0;
/// ziperr.h:ZE_ABORT, user interrupt or `-sc`.
pub(crate) const ZE_ABORT: i32 = 9;
/// ziperr.h:ZE_PARMS, bad command line.
pub(crate) const ZE_PARMS: i32 = 16;
/// ziperr.h:ZE_OPEN, could not open a specified file to read.
pub(crate) const ZE_OPEN: i32 = 18;
/// ziperr.h:ZE_COMPERR, error in compilation options.
pub(crate) const ZE_COMPERR: i32 = 19;

// ---- the option table (zip.c:options[]) ----

/// zip.h:o_NO_VALUE ... o_NUMBER_VALUE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueType {
    /// o_NO_VALUE
    No,
    /// o_REQUIRED_VALUE
    Required,
    /// o_OPTIONAL_VALUE (no option of the tables takes one; `get_option`
    /// handles it)
    #[allow(dead_code)]
    Optional,
    /// o_VALUE_LIST
    List,
    /// o_ONE_CHAR_VALUE (as above)
    #[allow(dead_code)]
    OneChar,
    /// o_NUMBER_VALUE (as above)
    #[allow(dead_code)]
    Number,
}

/// zip.h:struct option_struct.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OptionSpec {
    /// The short name (1 or 2 characters, or empty).
    pub(crate) short: &'static str,
    /// The long name (or empty).
    pub(crate) long: &'static str,
    pub(crate) value: ValueType,
    /// o_NEGATABLE
    pub(crate) negatable: bool,
    /// The ID `get_option()` returns.
    pub(crate) id: u32,
    /// The description `-so` lists.
    pub(crate) name: &'static str,
}

/// zip.c's option IDs (the `o_*` defines); an option's ID is its short
/// character when it has one.
pub(crate) mod o {
    pub(crate) const DB: u32 = 0x105;
    pub(crate) const DC: u32 = 0x106;
    pub(crate) const DD: u32 = 0x107;
    pub(crate) const DES: u32 = 0x108;
    pub(crate) const DF_CAP: u32 = 0x110;
    pub(crate) const DG: u32 = 0x111;
    pub(crate) const DS: u32 = 0x112;
    pub(crate) const DU: u32 = 0x113;
    pub(crate) const DV: u32 = 0x114;
    pub(crate) const FF: u32 = 0x115;
    pub(crate) const FI: u32 = 0x116;
    pub(crate) const FS: u32 = 0x117;
    pub(crate) const H2: u32 = 0x118;
    pub(crate) const LA: u32 = 0x121;
    pub(crate) const LF: u32 = 0x122;
    pub(crate) const LI: u32 = 0x123;
    pub(crate) const LL: u32 = 0x124;
    pub(crate) const MM: u32 = 0x125;
    pub(crate) const MM_CAP: u32 = 0x126;
    pub(crate) const NW: u32 = 0x127;
    pub(crate) const RE: u32 = 0x128;
    pub(crate) const SB: u32 = 0x129;
    pub(crate) const SC: u32 = 0x130;
    pub(crate) const SD: u32 = 0x131;
    pub(crate) const SF: u32 = 0x132;
    pub(crate) const SO: u32 = 0x133;
    pub(crate) const SP: u32 = 0x134;
    pub(crate) const SU: u32 = 0x135;
    pub(crate) const SU_CAP: u32 = 0x136;
    pub(crate) const SV: u32 = 0x137;
    pub(crate) const TT: u32 = 0x138;
    pub(crate) const TT_CAP: u32 = 0x139;
    pub(crate) const UN: u32 = 0x140;
    pub(crate) const VE: u32 = 0x141;
    pub(crate) const WS: u32 = 0x143;
    pub(crate) const Z64: u32 = 0x145;
    /// zip.h:o_NON_OPTION_ARG
    pub(crate) const NON_OPTION_ARG: u32 = 0xFFFF;
}

const fn spec(
    short: &'static str,
    long: &'static str,
    value: ValueType,
    negatable: bool,
    id: u32,
    name: &'static str,
) -> OptionSpec {
    OptionSpec {
        short,
        long,
        value,
        negatable,
        id,
        name,
    }
}

use ValueType::{List as VList, No as VNo, Required as VReq};

/// The characters an option's ID is, for the one-character options.
const fn ch(c: char) -> u32 {
    c as u32
}

/// zip.c:options[] as the unix build compiles it, in the table's order
/// (`-so` lists it so, and a long name's abbreviation is looked up in it).
/// Ubuntu's `UNICODE_SUPPORT` adds `-su`, `-sU` and `-UN`.
// port: zip.c:options
pub(crate) fn table(f: Flavour) -> Vec<OptionSpec> {
    let mut t = vec![
        spec("0", "store", VNo, false, ch('0'), "store"),
        spec("1", "compress-1", VNo, false, ch('1'), "compress 1"),
        spec("2", "compress-2", VNo, false, ch('2'), "compress 2"),
        spec("3", "compress-3", VNo, false, ch('3'), "compress 3"),
        spec("4", "compress-4", VNo, false, ch('4'), "compress 4"),
        spec("5", "compress-5", VNo, false, ch('5'), "compress 5"),
        spec("6", "compress-6", VNo, false, ch('6'), "compress 6"),
        spec("7", "compress-7", VNo, false, ch('7'), "compress 7"),
        spec("8", "compress-8", VNo, false, ch('8'), "compress 8"),
        spec("9", "compress-9", VNo, false, ch('9'), "compress 9"),
        spec(
            "A",
            "adjust-sfx",
            VNo,
            false,
            ch('A'),
            "adjust self extractor offsets",
        ),
        spec(
            "b",
            "temp-path",
            VReq,
            false,
            ch('b'),
            "dir to use for temp archive",
        ),
        spec(
            "c",
            "entry-comments",
            VNo,
            false,
            ch('c'),
            "add comments for each entry",
        ),
        spec(
            "d",
            "delete",
            VNo,
            false,
            ch('d'),
            "delete entries from archive",
        ),
        spec(
            "db",
            "display-bytes",
            VNo,
            true,
            o::DB,
            "display running bytes",
        ),
        spec(
            "dc",
            "display-counts",
            VNo,
            true,
            o::DC,
            "display running file count",
        ),
        spec(
            "dd",
            "display-dots",
            VNo,
            true,
            o::DD,
            "display dots as process each file",
        ),
        spec(
            "dg",
            "display-globaldots",
            VNo,
            true,
            o::DG,
            "display dots for archive instead of files",
        ),
        spec(
            "ds",
            "dot-size",
            VReq,
            false,
            o::DS,
            "set progress dot size - default 10M bytes",
        ),
        spec(
            "du",
            "display-usize",
            VNo,
            true,
            o::DU,
            "display uncompressed size in bytes",
        ),
        spec(
            "dv",
            "display-volume",
            VNo,
            true,
            o::DV,
            "display volume (disk) number",
        ),
        spec(
            "D",
            "no-dir-entries",
            VNo,
            false,
            ch('D'),
            "no entries for dirs themselves (-x */)",
        ),
        spec(
            "DF",
            "difference-archive",
            VNo,
            false,
            o::DF_CAP,
            "create diff archive with changed/new files",
        ),
        spec(
            "e",
            "encrypt",
            VNo,
            false,
            ch('e'),
            "encrypt entries, ask for password",
        ),
        spec(
            "F",
            "fix",
            VNo,
            false,
            ch('F'),
            "fix mostly intact archive (try first)",
        ),
        spec(
            "FF",
            "fixfix",
            VNo,
            false,
            o::FF,
            "try harder to fix archive (not as reliable)",
        ),
        spec(
            "FI",
            "fifo",
            VNo,
            true,
            o::FI,
            "read Unix FIFO (zip will wait on open pipe)",
        ),
        spec(
            "FS",
            "filesync",
            VNo,
            false,
            o::FS,
            "add/delete entries to make archive match OS",
        ),
        spec(
            "f",
            "freshen",
            VNo,
            false,
            ch('f'),
            "freshen existing archive entries",
        ),
        spec(
            "fd",
            "force-descriptors",
            VNo,
            false,
            o::DES,
            "force data descriptors as if streaming",
        ),
        spec(
            "fz",
            "force-zip64",
            VNo,
            true,
            o::Z64,
            "force use of Zip64 format, negate prevents",
        ),
        spec(
            "g",
            "grow",
            VNo,
            false,
            ch('g'),
            "grow existing archive instead of replace",
        ),
        spec("h", "help", VNo, false, ch('h'), "help"),
        spec("H", "", VNo, false, ch('h'), "help"),
        spec("?", "", VNo, false, ch('h'), "help"),
        spec("h2", "more-help", VNo, false, o::H2, "extended help"),
        spec(
            "i",
            "include",
            VList,
            false,
            ch('i'),
            "include only files matching patterns",
        ),
        spec(
            "j",
            "junk-paths",
            VNo,
            false,
            ch('j'),
            "strip paths and just store file names",
        ),
        spec(
            "J",
            "junk-sfx",
            VNo,
            false,
            ch('J'),
            "strip self extractor from archive",
        ),
        spec(
            "k",
            "DOS-names",
            VNo,
            false,
            ch('k'),
            "force use of 8.3 DOS names",
        ),
        spec(
            "l",
            "to-crlf",
            VNo,
            false,
            ch('l'),
            "convert text file line ends - LF->CRLF",
        ),
        spec(
            "ll",
            "from-crlf",
            VNo,
            false,
            o::LL,
            "convert text file line ends - CRLF->LF",
        ),
        spec(
            "lf",
            "logfile-path",
            VReq,
            false,
            o::LF,
            "log to log file at path (default overwrite)",
        ),
        spec(
            "la",
            "log-append",
            VNo,
            true,
            o::LA,
            "append to existing log file",
        ),
        spec(
            "li",
            "log-info",
            VNo,
            true,
            o::LI,
            "include informational messages in log",
        ),
        spec("L", "license", VNo, false, ch('L'), "display license"),
        spec(
            "m",
            "move",
            VNo,
            false,
            ch('m'),
            "add files to archive then delete files",
        ),
        spec("mm", "", VNo, false, o::MM, "not used"),
        spec(
            "MM",
            "must-match",
            VNo,
            false,
            o::MM_CAP,
            "error if in file not matched/not readable",
        ),
        spec(
            "n",
            "suffixes",
            VReq,
            false,
            ch('n'),
            "suffixes to not compress: .gz:.zip",
        ),
        spec(
            "nw",
            "no-wild",
            VNo,
            false,
            o::NW,
            "no wildcards during add or update",
        ),
        spec(
            "o",
            "latest-time",
            VNo,
            false,
            ch('o'),
            "use latest entry time as archive time",
        ),
        spec(
            "O",
            "output-file",
            VReq,
            false,
            ch('O'),
            "set out zipfile different than in zipfile",
        ),
        spec("p", "paths", VNo, false, ch('p'), "store paths"),
        spec(
            "P",
            "password",
            VReq,
            false,
            ch('P'),
            "encrypt entries, option value is password",
        ),
        spec("q", "quiet", VNo, false, ch('q'), "quiet"),
        spec(
            "r",
            "recurse-paths",
            VNo,
            false,
            ch('r'),
            "recurse down listed paths",
        ),
        spec(
            "R",
            "recurse-patterns",
            VNo,
            false,
            ch('R'),
            "recurse current dir and match patterns",
        ),
        spec(
            "RE",
            "regex",
            VNo,
            false,
            o::RE,
            "allow [list] matching (regex)",
        ),
        spec(
            "s",
            "split-size",
            VReq,
            false,
            ch('s'),
            "do splits, set split size (-s=0 no splits)",
        ),
        spec(
            "sp",
            "split-pause",
            VNo,
            false,
            o::SP,
            "pause while splitting to select destination",
        ),
        spec(
            "sv",
            "split-verbose",
            VNo,
            false,
            o::SV,
            "be verbose about creating splits",
        ),
        spec(
            "sb",
            "split-bell",
            VNo,
            false,
            o::SB,
            "when pause for next split ring bell",
        ),
        spec("sc", "show-command", VNo, false, o::SC, "show command line"),
        spec("sd", "show-debug", VNo, false, o::SD, "show debug"),
        spec(
            "sf",
            "show-files",
            VNo,
            true,
            o::SF,
            "show files to operate on and exit",
        ),
        spec("so", "show-options", VNo, false, o::SO, "show options"),
        spec(
            "t",
            "from-date",
            VReq,
            false,
            ch('t'),
            "exclude before date",
        ),
        spec(
            "tt",
            "before-date",
            VReq,
            false,
            o::TT,
            "include before date",
        ),
        spec(
            "T",
            "test",
            VNo,
            false,
            ch('T'),
            "test updates before replacing archive",
        ),
        spec(
            "TT",
            "unzip-command",
            VReq,
            false,
            o::TT_CAP,
            "unzip command to use, name is added to end",
        ),
        spec(
            "u",
            "update",
            VNo,
            false,
            ch('u'),
            "update existing entries and add new",
        ),
        spec(
            "U",
            "copy-entries",
            VNo,
            false,
            ch('U'),
            "select from archive instead of file system",
        ),
        spec(
            "v",
            "verbose",
            VNo,
            false,
            ch('v'),
            "display additional information",
        ),
        spec(
            "",
            "version",
            VNo,
            false,
            o::VE,
            "(if no other args) show version information",
        ),
        spec(
            "ws",
            "wild-stop-dirs",
            VNo,
            false,
            o::WS,
            "* stops at /, ** includes any /",
        ),
        spec(
            "x",
            "exclude",
            VList,
            false,
            ch('x'),
            "exclude files matching patterns",
        ),
        spec(
            "X",
            "strip-extra",
            VNo,
            true,
            ch('X'),
            "-X- keep all ef, -X strip but critical ef",
        ),
        spec("y", "symlinks", VNo, false, ch('y'), "store symbolic links"),
        spec(
            "z",
            "archive-comment",
            VNo,
            false,
            ch('z'),
            "ask for archive comment",
        ),
        spec(
            "Z",
            "compression-method",
            VReq,
            false,
            ch('Z'),
            "compression method",
        ),
        spec(
            "@",
            "names-stdin",
            VNo,
            false,
            ch('@'),
            "get file names from stdin, one per line",
        ),
    ];
    // ubuntu: -DUNICODE_SUPPORT (the options after `-so` and `-U`)
    if flavour::unicode_support(f) {
        let at = t
            .iter()
            .position(|s| s.short == "so")
            .map_or(t.len(), |i| i + 1);
        t.insert(
            at,
            spec(
                "su",
                "show-unicode",
                VNo,
                true,
                o::SU,
                "as -sf but also show escaped Unicode",
            ),
        );
        t.insert(
            at + 1,
            spec(
                "sU",
                "show-just-unicode",
                VNo,
                true,
                o::SU_CAP,
                "as -sf but only show escaped Unicode",
            ),
        );
        let at = t
            .iter()
            .position(|s| s.short == "U")
            .map_or(t.len(), |i| i + 1);
        t.insert(
            at,
            spec(
                "UN",
                "unicode",
                VReq,
                false,
                o::UN,
                "UN=quit, warn, ignore, no, escape",
            ),
        );
    }
    t
}

/// zipcloak.c:options (CRYPT builds).
// port: zipcloak.c:options
pub(crate) fn cloak_table() -> Vec<OptionSpec> {
    vec![
        spec("b", "temp-path", VReq, false, ch('b'), "path for temp file"),
        spec("d", "decrypt", VNo, false, ch('d'), "decrypt"),
        spec("h", "help", VNo, false, ch('h'), "help"),
        spec("L", "license", VNo, false, ch('L'), "license"),
        spec("l", "", VNo, false, ch('L'), "license"),
        spec(
            "O",
            "output-file",
            VReq,
            false,
            ch('O'),
            "output to new archive",
        ),
        spec("v", "version", VNo, false, ch('v'), "version"),
    ]
}

// ---- get_option (fileio.c) ----

/// fileio.c:SKIP_VALUE_ARG
const SKIP_VALUE_ARG: i64 = -1;
/// fileio.c:THIS_ARG_DONE
const THIS_ARG_DONE: i64 = -2;
/// fileio.c:START_VALUE_LIST
const START_VALUE_LIST: i64 = -3;
/// fileio.c:IN_VALUE_LIST
const IN_VALUE_LIST: i64 = -4;
/// fileio.c:NON_OPTION_ARG
const NON_OPTION_ARG: i64 = -5;
/// fileio.c:STOP_VALUE_LIST
const STOP_VALUE_LIST: i64 = -6;
/// fileio.c:READ_REST_ARGS_VERBATIM
const READ_REST_ARGS_VERBATIM: i64 = -7;
/// zip.h:o_NO_OPTION_MATCH
const NO_OPTION_MATCH: i64 = -1;

/// `get_option()`'s state, which the caller owns (`argnum`, `optchar`,
/// `first_nonopt_arg` and `option_num` of the C).
#[derive(Debug, Clone, Copy)]
pub(crate) struct GetOpt {
    /// Index of the current argument (0 at the first call).
    pub(crate) argnum: i64,
    pub(crate) optchar: i64,
    pub(crate) first_nonopt_arg: i64,
    pub(crate) option_num: i64,
}

impl GetOpt {
    pub(crate) fn new() -> GetOpt {
        GetOpt {
            argnum: 0,
            optchar: 0,
            first_nonopt_arg: 0,
            option_num: 0,
        }
    }
}

/// What one `get_option()` call returns: the option's ID (0 when the
/// arguments are used up), its value and whether a trailing `-` negated it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Got {
    pub(crate) id: u32,
    pub(crate) value: Option<Vec<u8>>,
    pub(crate) negated: bool,
}

/// `args[i]` where C has a NULL terminator: `None` past the end.
fn at(args: &[Vec<u8>], i: i64) -> Option<&Vec<u8>> {
    usize::try_from(i).ok().and_then(|i| args.get(i))
}

/// `s[i]` of a C string: the byte, or NUL past the end.
fn byte(s: &[u8], i: i64) -> u8 {
    usize::try_from(i)
        .ok()
        .and_then(|i| s.get(i))
        .copied()
        .unwrap_or(0)
}

/// `args[j] = v`, ignoring an index outside the array (the C's indices are
/// all inside it; this keeps a hostile command line from ever panicking).
fn set(args: &mut [Vec<u8>], j: i64, v: Vec<u8>) {
    if let Some(slot) = usize::try_from(j).ok().and_then(|j| args.get_mut(j)) {
        *slot = v;
    }
}

/// fileio.c:optionerr: `err` (a format with one `%s`) filled with the
/// option's name and, when it has one, its description.
fn optionerr(err: &str, spec: &OptionSpec, islong: bool) -> Vec<u8> {
    let mut optname = Vec::new();
    let nm = if islong { spec.long } else { spec.short };
    if !spec.name.is_empty() {
        printf(
            &mut optname,
            m::OPTION_NAME_DESC,
            &[nm.as_bytes(), spec.name.as_bytes()],
        );
    } else {
        printf(&mut optname, m::OPTION_NAME, &[nm.as_bytes()]);
    }
    let mut buf = Vec::new();
    printf(&mut buf, err, &[&optname]);
    buf
}

/// fileio.c:insert_arg: `arg` before the argument at `at_arg`.
fn insert_arg(args: &mut Vec<Vec<u8>>, arg: &[u8], at_arg: i64) {
    let at = usize::try_from(at_arg).unwrap_or(0).min(args.len());
    args.insert(at, arg.to_vec());
}

/// fileio.c:get_shortopt: the next short option of `args[argnum]`.
// port: fileio.c:get_shortopt
fn get_shortopt(
    table: &[OptionSpec],
    args: &[Vec<u8>],
    argnum: i64,
    optchar: &mut i64,
    negated: &mut bool,
    value: &mut Option<Vec<u8>>,
    option_num: &mut i64,
) -> Result<u32, Vec<u8>> {
    let arg: &[u8] = at(args, argnum).map_or(&[], |a| a.as_slice());
    // the current character is consumed
    *optchar += 1;
    let shortopt = *optchar;
    *value = None;
    if byte(arg, shortopt) == 0 {
        // no more options in arg
        *optchar = 0;
        *option_num = NO_OPTION_MATCH;
        return Ok(0);
    }
    let mut matched: Option<usize> = None;
    for (op, o) in table.iter().enumerate() {
        let s = o.short.as_bytes();
        if !s.is_empty() && s[0] == byte(arg, shortopt) {
            if s.len() == 1 {
                // single char match
                matched = Some(op);
            } else if s[1] == byte(arg, shortopt + 1) {
                // 2 char short opt
                matched = Some(op);
                *optchar += 1;
                break;
            }
        }
    }
    let Some(mi) = matched else {
        let mut e = Vec::new();
        printf(&mut e, m::SH_OP_NOT_SUP_ERR, &[&[byte(arg, shortopt)]]);
        return Err(e);
    };
    let mo = &table[mi];
    // a trailing dash negates the option
    if byte(arg, *optchar + 1) == b'-' {
        if !mo.negatable {
            if mo.value == ValueType::No {
                return Err(optionerr(m::OP_NOT_NEG_ERR, mo, false));
            }
        } else {
            *negated = true;
            // skip the negating dash
            *optchar += 1;
        }
    }
    let after = *optchar + 1;
    match mo.value {
        ValueType::OneChar => {
            if byte(arg, after) != 0 {
                *value = Some(vec![byte(arg, after)]);
                *optchar += 1;
            } else {
                return Err(optionerr(m::OCO_REQ_VAL_ERR, mo, false));
            }
        }
        ValueType::Number => {
            let mut start = after;
            if matches!(byte(arg, start), b'+' | b'-') {
                start += 1;
            }
            let mut s = start;
            while byte(arg, s).is_ascii_digit() {
                s += 1;
            }
            if s == start {
                return Err(optionerr(m::NUM_REQ_VAL_ERR, mo, false));
            }
            let from = usize::try_from(after).unwrap_or(0);
            let to = usize::try_from(s).unwrap_or(0);
            *value = Some(arg[from..to].to_vec());
            *optchar += s - after;
        }
        ValueType::Optional => {
            if byte(arg, after) != 0 {
                let mut clen = 1;
                if byte(arg, *optchar + clen) == b'=' {
                    clen += 1;
                }
                if byte(arg, *optchar + clen) != 0 {
                    let from = usize::try_from(*optchar + clen).unwrap_or(0);
                    *value = Some(arg[from..].to_vec());
                }
                *optchar = THIS_ARG_DONE;
            } else if let Some(next) = at(args, argnum + 1)
                && next.first() != Some(&b'-')
            {
                *value = Some(next.clone());
                *optchar = SKIP_VALUE_ARG;
            }
        }
        ValueType::Required | ValueType::List => {
            if byte(arg, after) != 0 {
                // the value follows the option, as -ovalue or -o=value
                let mut clen = 1;
                if byte(arg, *optchar + clen) == b'=' {
                    clen += 1;
                }
                let from = usize::try_from(*optchar + clen).unwrap_or(0);
                *value = Some(arg[from..].to_vec());
                *optchar = THIS_ARG_DONE;
            } else if let Some(next) = at(args, argnum + 1) {
                *value = Some(next.clone());
                *optchar = if mo.value == ValueType::List {
                    START_VALUE_LIST
                } else {
                    SKIP_VALUE_ARG
                };
            } else {
                return Err(optionerr(m::OP_REQ_VAL_ERR, mo, false));
            }
        }
        ValueType::No => {}
    }
    *option_num = i64::try_from(mi).unwrap_or(NO_OPTION_MATCH);
    Ok(mo.id)
}

/// fileio.c:get_longopt: the long option in `args[argnum]`.
// port: fileio.c:get_longopt
fn get_longopt(
    table: &[OptionSpec],
    args: &[Vec<u8>],
    argnum: i64,
    optchar: &mut i64,
    negated: &mut bool,
    value: &mut Option<Vec<u8>>,
    option_num: &mut i64,
) -> Result<u32, Vec<u8>> {
    *value = None;
    let Some(arg) = at(args, argnum) else {
        *option_num = NO_OPTION_MATCH;
        return Ok(0);
    };
    let body = &arg[2.min(arg.len())..];
    // `=value`
    let (mut longopt, valuestart) = match body.iter().position(|&b| b == b'=') {
        Some(i) => (body[..i].to_vec(), Some(body[i + 1..].to_vec())),
        None => (body.to_vec(), None),
    };
    // a trailing dash negates
    *negated = longopt.last() == Some(&b'-');
    if *negated {
        longopt.pop();
    }
    let mut matched: Option<usize> = None;
    for (op, o) in table.iter().enumerate() {
        let l = o.long.as_bytes();
        if l == longopt.as_slice() {
            // exact match
            matched = Some(op);
            break;
        }
        if l.starts_with(&longopt) {
            if matched.is_some() {
                let mut e = Vec::new();
                printf(&mut e, m::LONG_OP_AMBIG_ERR, &[&longopt]);
                return Err(e);
            }
            matched = Some(op);
        }
    }
    let Some(mi) = matched else {
        let mut e = Vec::new();
        printf(&mut e, m::LONG_OP_NOT_SUP_ERR, &[&longopt]);
        return Err(e);
    };
    let mo = &table[mi];
    // one long option an argument
    *optchar = THIS_ARG_DONE;
    if *negated && !mo.negatable {
        return Err(optionerr(m::OP_NOT_NEG_ERR, mo, true));
    }
    match mo.value {
        ValueType::Optional => {
            if let Some(v) = valuestart {
                *value = Some(v);
            }
        }
        ValueType::Required | ValueType::Number | ValueType::OneChar | ValueType::List => {
            if let Some(v) = valuestart {
                *value = Some(v);
            } else if let Some(next) = at(args, argnum + 1) {
                *value = Some(next.clone());
                *optchar = if mo.value == ValueType::List {
                    START_VALUE_LIST
                } else {
                    SKIP_VALUE_ARG
                };
            } else {
                return Err(optionerr(m::OP_REQ_VAL_ERR, mo, true));
            }
        }
        ValueType::No => {
            if valuestart.is_some() {
                return Err(optionerr(m::OP_NO_ALLOW_VAL_ERR, mo, true));
            }
        }
    }
    *option_num = i64::try_from(mi).unwrap_or(NO_OPTION_MATCH);
    Ok(mo.id)
}

/// fileio.c:get_option, at recursion depth 0 with permuting on and `--`
/// ending the options (the only settings zip uses). `args` includes
/// `argv[0]`; the returned `id` is 0 when nothing is left.
// port: fileio.c:get_option
pub(crate) fn get_option(
    table: &[OptionSpec],
    args: &mut Vec<Vec<u8>>,
    st: &mut GetOpt,
) -> Result<Got, Vec<u8>> {
    let mut value: Option<Vec<u8>> = None;
    let mut negated = false;
    let mut argcnt = args.len() as i64;
    // if no provided args then nothing to do
    if argcnt < 2 {
        return Ok(Got {
            id: 0,
            value,
            negated,
        });
    }
    let mut first_nonoption_arg = st.first_nonopt_arg;
    let mut argn = st.argnum;
    let mut optc = st.optchar;
    let mut option_num = st.option_num;
    let mut read_rest_args_verbatim = optc == READ_REST_ARGS_VERBATIM;

    if argn == -1 || argn == 0 {
        // first call: args[0] is argv[0]
        option_num = NO_OPTION_MATCH;
        optc = THIS_ARG_DONE;
        first_nonoption_arg = -1;
    }
    // if option_num is set then restore the last option's ID in case of a
    // value list continuing
    let mut option_id: u32 = 0;
    if option_num != NO_OPTION_MATCH
        && let Some(s) = usize::try_from(option_num).ok().and_then(|i| table.get(i))
    {
        option_id = s.id;
    }

    loop {
        if read_rest_args_verbatim {
            // the rest after `--` are non-option arguments
            argn += 1;
            if argn > argcnt || at(args, argn).is_none() {
                option_id = 0;
                break;
            }
            value = at(args, argn).cloned();
            option_num = NO_OPTION_MATCH;
            option_id = o::NON_OPTION_ARG;
            break;
        }
        // permute non-option args after option args
        if matches!(
            optc,
            SKIP_VALUE_ARG | THIS_ARG_DONE | START_VALUE_LIST | IN_VALUE_LIST | STOP_VALUE_LIST
        ) && first_nonoption_arg > -1
            && at(args, first_nonoption_arg).is_some()
        {
            // move the non-options after this option (and its value)
            let v = i64::from(optc == SKIP_VALUE_ARG || optc == START_VALUE_LIST);
            for _ in first_nonoption_arg..argn {
                let moved = at(args, first_nonoption_arg).cloned().unwrap_or_default();
                for j in first_nonoption_arg..argn + v {
                    let next = at(args, j + 1).cloned().unwrap_or_default();
                    set(args, j, next);
                }
                set(args, argn + v, moved);
            }
            first_nonoption_arg += 1 + v;
        }

        // value lists
        if optc == STOP_VALUE_LIST {
            optc = THIS_ARG_DONE;
        }
        if optc == START_VALUE_LIST || optc == IN_VALUE_LIST {
            if optc == START_VALUE_LIST {
                // already returned the first value
                argn += 1;
                optc = IN_VALUE_LIST;
            }
            argn += 1;
            // at the end of the args, still in the list, with non-option
            // args to come: end the list with `@` (also what `-sc` shows)
            if at(args, argn).is_none() && first_nonoption_arg > -1 {
                insert_arg(args, b"@", first_nonoption_arg);
                argcnt = args.len() as i64;
                argn += 1;
                first_nonoption_arg += 1;
            }
            match at(args, argn) {
                Some(a) if a.as_slice() == b"@" => {
                    // inserted arguments terminator
                    optc = STOP_VALUE_LIST;
                    continue;
                }
                Some(a) if a.first() != Some(&b'-') => {
                    // another value in the value list
                    value = Some(a.clone());
                    break;
                }
                _ => {
                    argn -= 1;
                    optc = THIS_ARG_DONE;
                }
            }
        }

        // move to the next arg
        if optc == SKIP_VALUE_ARG {
            argn += 2;
            optc = 0;
        } else if optc == THIS_ARG_DONE {
            argn += 1;
            optc = 0;
        }
        if argn > argcnt {
            break;
        }
        if at(args, argn).is_none() {
            // done unless permuting and non-option args are left
            if first_nonoption_arg > -1 && at(args, first_nonoption_arg).is_some() {
                // return the non-option arguments at the end
                if optc == NON_OPTION_ARG {
                    first_nonoption_arg += 1;
                }
                std::mem::swap(&mut argn, &mut first_nonoption_arg);
            }
            if argn > argcnt || at(args, argn).is_none() {
                option_id = 0;
                break;
            }
        }
        // after the swap first_nonoption_arg points at the end
        if first_nonoption_arg > -1 && at(args, first_nonoption_arg).is_none() {
            // only non-option args left
            if optc == NON_OPTION_ARG {
                argn += 1;
            }
            if argn > argcnt || at(args, argn).is_none() {
                option_id = 0;
                break;
            }
            value = at(args, argn).cloned();
            optc = NON_OPTION_ARG;
            option_id = o::NON_OPTION_ARG;
            break;
        }

        let arg = at(args, argn).cloned().unwrap_or_default();
        if arg.first() == Some(&b'-') {
            if arg.len() == 1 {
                // `-` is a non-option argument
                option_num = NO_OPTION_MATCH;
                if first_nonoption_arg < 0 {
                    first_nonoption_arg = argn;
                }
                argn += 1;
            } else if arg[1] == b'-' {
                if arg.len() == 2 {
                    // `--`: what follows is read verbatim
                    if first_nonoption_arg < 1 {
                        // `--` is the first non-option argument
                        argn -= 1;
                    } else {
                        // go back to the start of the non-option args
                        argn = first_nonoption_arg - 1;
                    }
                    read_rest_args_verbatim = true;
                    optc = READ_REST_ARGS_VERBATIM;
                } else {
                    option_id = get_longopt(
                        table,
                        args,
                        argn,
                        &mut optc,
                        &mut negated,
                        &mut value,
                        &mut option_num,
                    )?;
                    break;
                }
            } else {
                option_id = get_shortopt(
                    table,
                    args,
                    argn,
                    &mut optc,
                    &mut negated,
                    &mut value,
                    &mut option_num,
                )?;
                if optc == 0 {
                    // ran out of short options in this arg
                    optc = THIS_ARG_DONE;
                } else {
                    break;
                }
            }
        } else {
            // a non-option: permute
            if first_nonoption_arg < 0 {
                first_nonoption_arg = argn;
            }
            argn += 1;
        }
    }

    st.first_nonopt_arg = first_nonoption_arg;
    st.argnum = argn;
    st.optchar = optc;
    st.option_num = option_num;
    Ok(Got {
        id: option_id,
        value,
        negated,
    })
}

// ---- small ports ----

/// C's `isspace` in the C locale.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// util.c:envargs: the words of `$ZIPOPT`, else `$ZIP`, go between the
/// program name and the rest of the command line. A blank or unset
/// `ZIPOPT` falls back to `ZIP`. Words are split at blanks; a word that
/// begins with `"` runs to the closing `"` and loses its backslashes (each
/// protects the next character).
// port: util.c:envargs
pub(crate) fn envargs(
    args: Vec<Vec<u8>>,
    env: &dyn Fn(&str) -> Option<OsString>,
    first: &str,
    second: &str,
) -> Vec<Vec<u8>> {
    let get = |name: &str| -> Option<Vec<u8>> {
        let v = env(name)?.as_encoded_bytes().to_vec();
        let skip = v.iter().take_while(|&&b| is_space(b)).count();
        Some(v[skip..].to_vec())
    };
    let mut envptr = get(first);
    if envptr.as_ref().is_none_or(|v| v.is_empty()) {
        envptr = get(second);
    }
    let Some(s) = envptr.filter(|v| !v.is_empty()) else {
        return args;
    };
    let mut out = Vec::with_capacity(args.len() + 4);
    let mut rest = args.into_iter();
    out.extend(rest.next());
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut p = 0usize;
    loop {
        if at(p) == b'"' {
            p += 1;
            let start = p;
            let mut ch = at(p);
            while ch != 0 && ch != b'"' {
                if ch == b'\\' && at(p + 1) != 0 {
                    p += 1;
                }
                p += 1;
                ch = at(p);
            }
            let mut word = s[start..p.min(s.len())].to_vec();
            if ch != 0 {
                // the closing quote
                p += 1;
            }
            // remove escape characters
            let mut i = 0;
            while i < word.len() {
                if word[i] == b'\\' {
                    word.remove(i);
                    if i < word.len() {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(word);
        } else {
            let start = p;
            while at(p) != 0 && !is_space(at(p)) {
                p += 1;
            }
            out.push(s[start..p].to_vec());
            if at(p) != 0 {
                p += 1;
            }
        }
        while at(p) != 0 && is_space(at(p)) {
            p += 1;
        }
        if at(p) == 0 {
            break;
        }
    }
    out.extend(rest);
    out
}

/// util.c:abbrevmatch: whether `abbrev` is an abbreviation of
/// `matchstring` (at least `minmatch` characters, case-insensitive unless
/// `case_sensitive`).
// port: util.c:abbrevmatch
pub(crate) fn abbrevmatch(
    matchstring: &[u8],
    abbrev: &[u8],
    case_sensitive: bool,
    minmatch: usize,
) -> bool {
    let mut cnt = 0;
    let (mut mi, mut ai) = (0, 0);
    while mi < matchstring.len() && ai < abbrev.len() {
        cnt += 1;
        let (a, b) = (matchstring[mi], abbrev[ai]);
        let same = if case_sensitive {
            a == b
        } else {
            a.eq_ignore_ascii_case(&b)
        };
        if !same {
            return false;
        }
        mi += 1;
        ai += 1;
    }
    if cnt < minmatch {
        return false;
    }
    // an abbreviation longer than the match string is no match
    ai >= abbrev.len()
}

/// util.c:ReadNumString: a number with an optional `K`, `M`, `G` or `T`
/// multiplier. `(u64::MAX, warning)` is the C's `(uzoff_t)-1` with the text
/// its `zipwarn` gives (a missing multiplier letter or digits after one are
/// `-1` without a warning).
// port: util.c:ReadNumString
pub(crate) fn read_num_string(numstring: &[u8]) -> (u64, Option<&'static str>) {
    if numstring.first().is_none_or(|b| !b.is_ascii_digit()) {
        return (u64::MAX, Some(m::NUM_NOT_DIGIT));
    }
    if numstring.len() > 8 {
        return (u64::MAX, Some(m::NUM_TOO_LONG));
    }
    // atoi of at most eight digits
    let digits = numstring.iter().take_while(|b| b.is_ascii_digit()).count();
    let num: u64 = numstring[..digits]
        .iter()
        .fold(0, |n, &d| n * 10 + u64::from(d - b'0'));
    if digits == numstring.len() {
        return (num, None);
    }
    // nothing may follow the multiplier
    if numstring.len() > digits + 1 {
        return (u64::MAX, None);
    }
    let mult: u64 = match numstring[digits].to_ascii_uppercase() {
        b'K' => 1 << 10,
        b'M' => 1 << 20,
        b'G' => 1 << 30,
        b'T' => 1 << 40,
        _ => return (u64::MAX, None),
    };
    (num.wrapping_mul(mult), None)
}

/// fileio.c:dostime: a date and time as a four-byte DOS date and time
/// (date in the high two bytes), 1980 at the earliest.
// port: fileio.c:dostime
pub(crate) fn dostime(y: i64, n: i64, d: i64, h: i64, mi: i64, s: i64) -> u64 {
    if y < 1980 {
        // DOSTIME_MINIMUM
        return 0x0021_0000;
    }
    (((y - 1980) as u64) << 25)
        | ((n as u64) << 21)
        | ((d as u64) << 16)
        | ((h as u64) << 11)
        | ((mi as u64) << 5)
        | ((s as u64) >> 1)
}

/// What `sscanf(s, "%<w1>d<sep>%<w2>d<sep>%<w3>d")` makes of `s`: how many
/// conversions succeeded and their values (C's `%d` skips leading blanks,
/// takes an optional sign and at most `width` characters in all; a literal
/// in the format must match at once).
fn scan_date(s: &[u8], fmt: [(usize, Option<u8>); 3]) -> (usize, [i64; 3]) {
    let mut vals = [0i64; 3];
    let mut p = 0usize;
    for (i, &(width, sep)) in fmt.iter().enumerate() {
        while p < s.len() && is_space(s[p]) {
            p += 1;
        }
        let mut neg = false;
        let mut n = 0usize;
        if p < s.len() && matches!(s[p], b'+' | b'-') && n < width {
            neg = s[p] == b'-';
            p += 1;
            n += 1;
        }
        let digits_from = p;
        let mut v: i64 = 0;
        while p < s.len() && s[p].is_ascii_digit() && n < width {
            v = v * 10 + i64::from(s[p] - b'0');
            p += 1;
            n += 1;
        }
        if p == digits_from {
            return (i, vals);
        }
        vals[i] = if neg { -v } else { v };
        if let Some(c) = sep {
            if p < s.len() && s[p] == c {
                p += 1;
            } else {
                return (i + 1, vals);
            }
        }
    }
    (3, vals)
}

/// zip.c:main's `-t` and `-tt`: `yyyy-mm-dd` or `mmddyyyy` to a DOS time,
/// `None` for the date it refuses.
fn read_date(value: &[u8]) -> Option<u64> {
    let iso = scan_date(value, [(4, Some(b'-')), (2, Some(b'-')), (2, None)]);
    let (yyyy, mm, dd);
    if iso.0 == 3 {
        (yyyy, mm, dd) = (iso.1[0], iso.1[1], iso.1[2]);
    } else {
        let us = scan_date(value, [(2, None), (2, None), (4, None)]);
        if us.0 != 3 {
            return None;
        }
        (mm, dd, yyyy) = (us.1[0], us.1[1], us.1[2]);
    }
    if !(1..=12).contains(&mm) || !(1..=31).contains(&dd) {
        return None;
    }
    Some(dostime(yyyy, mm, dd, 0, 0, 0))
}

/// zipfile.c:ziptyp: `.zip` is appended to a name whose last component has
/// no dot (unless `-A`).
// port: zipfile.c:ziptyp
pub(crate) fn ziptyp(s: &[u8], adjust: bool) -> Vec<u8> {
    let mut t = s.to_vec();
    if adjust {
        return t;
    }
    let comp = s.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
    if !s[comp..].contains(&b'.') {
        t.extend_from_slice(b".zip");
    }
    t
}

/// fileio.c:getnam: one `\n`- or `\r`-delimited name (`None` at the end of
/// input, or for a name over 9000 bytes).
// port: fileio.c:getnam
pub(crate) fn getnam(r: &mut dyn BufRead) -> Option<Vec<u8>> {
    const GETNAM_MAX: usize = 9000;
    let mut bytes = r.bytes().map_while(Result::ok);
    let mut c = bytes.next();
    while matches!(c, Some(b'\n' | b'\r')) {
        c = bytes.next();
    }
    c?;
    let mut name = Vec::new();
    while let Some(b) = c {
        if b == b'\n' || b == b'\r' {
            break;
        }
        if name.len() >= GETNAM_MAX {
            return None;
        }
        name.push(b);
        c = bytes.next();
    }
    Some(name)
}

// ---- zip's options ----

/// zip.c:ADD ... ARCHIVE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// `DELETE` (-d)
    Delete,
    /// `ADD`
    Add,
    /// `UPDATE` (-u)
    Update,
    /// `FRESHEN` (-f)
    Freshen,
    /// `ARCHIVE` (-U, or -O without names)
    Archive,
}

/// zip.h:BEST, DEFLATE, STORE, BZIP2: the `-0` and `-Z` choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    /// BEST, the default: each file stored or deflated as it pays.
    Best,
    /// STORE
    Store,
    /// DEFLATE
    Deflate,
    /// BZIP2 (ubuntu)
    Bzip2,
}

/// One `-i`, `-x` or `-R` pattern as the command line gave it (zip.c's
/// `filterlist_struct` before its names are converted: Task 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Filter {
    /// `i`, `x` or `R`.
    pub(crate) flag: u8,
    pub(crate) pattern: Vec<u8>,
}

/// Every zip.c option and the state the command line sets (the globals of
/// zip.c and globals.c that `main()` writes, with the C's names).
#[derive(Debug, Clone)]
pub(crate) struct Options {
    pub(crate) action: Action,
    pub(crate) comadd: bool,
    pub(crate) zipedit: bool,
    pub(crate) latest: bool,
    pub(crate) before: u64,
    pub(crate) after: u64,
    pub(crate) test: bool,
    pub(crate) unzip_path: Option<Vec<u8>>,
    pub(crate) tempdir: bool,
    pub(crate) tempath: Option<Vec<u8>>,
    pub(crate) junk_sfx: bool,
    /// 1 `-r`, 2 `-R`.
    pub(crate) recurse: u8,
    pub(crate) dispose: bool,
    pub(crate) pathput: bool,
    pub(crate) method: Method,
    pub(crate) dosify: bool,
    pub(crate) verbose: u32,
    /// 1 `-F`, 2 `-FF`.
    pub(crate) fix: u8,
    pub(crate) filesync: bool,
    pub(crate) adjust: bool,
    pub(crate) level: u8,
    /// 1 `-l`, 2 `-ll`.
    pub(crate) translate_eol: u8,
    pub(crate) no_wild: bool,
    pub(crate) allow_regex: bool,
    pub(crate) wild_stop_at_dir: bool,
    pub(crate) dot_size: i64,
    pub(crate) dot_count: i64,
    pub(crate) display_counts: bool,
    pub(crate) display_bytes: bool,
    pub(crate) display_globaldots: bool,
    pub(crate) display_volume: bool,
    pub(crate) display_usize: bool,
    pub(crate) logall: bool,
    pub(crate) logfile_path: Option<Vec<u8>>,
    pub(crate) logfile_append: bool,
    pub(crate) dirnames: bool,
    pub(crate) diff_mode: bool,
    pub(crate) linkput: bool,
    pub(crate) noisy: bool,
    /// 0 `-X`, 1 default, 2 `-X-`.
    pub(crate) extra_fields: u8,
    pub(crate) use_descriptors: bool,
    pub(crate) zip_to_stdout: bool,
    pub(crate) allow_empty_archive: bool,
    pub(crate) copy_only: bool,
    pub(crate) allow_fifo: bool,
    pub(crate) show_files: u8,
    /// -1 default, 0 `-fz-`, 1 `-fz`.
    pub(crate) force_zip64: i8,
    pub(crate) utf8_force: bool,
    pub(crate) unicode_escape_all: bool,
    /// 0 quit, 1 warn, 2 ignore, 3 no.
    pub(crate) unicode_mismatch: u8,
    pub(crate) special: Option<Vec<u8>>,
    pub(crate) key: Option<Vec<u8>>,
    pub(crate) key_needed: bool,
    pub(crate) bad_open_is_error: bool,
    pub(crate) zipfile: Option<Vec<u8>>,
    pub(crate) in_path: Option<Vec<u8>>,
    pub(crate) out_path: Option<Vec<u8>>,
    pub(crate) have_out: bool,
    /// 0 none, 1 seekable, 2 data descriptors, -1 `-s-`.
    pub(crate) split_method: i8,
    pub(crate) split_size: u64,
    pub(crate) split_bell: bool,
    pub(crate) noisy_splits: bool,
    pub(crate) show_what_doing: bool,
    pub(crate) show_args: bool,
    pub(crate) show_options: bool,
    /// The `-i`, `-x` and `-R` patterns, in command-line order.
    pub(crate) filters: Vec<Filter>,
    /// The file arguments (and `-@` names), in command-line order.
    pub(crate) names: Vec<Vec<u8>>,
    /// `-g`: add to the archive rather than replace it (zip.c's `d`).
    pub(crate) grow: bool,
    /// `-@` was given (zip.c's `s`).
    pub(crate) names_from_stdin: bool,
    /// zip.c's `comment_stream` is NULL (`-@`, or zip as a filter): `-c`
    /// and `-z` read standard error, not standard input.
    pub(crate) comment_from_stderr: bool,
    /// zip.c's `kk`: 0 expecting the archive name, 3 after it, 4 after a
    /// name, 6 reading `-R` patterns.
    pub(crate) kk: u8,
    /// Whether any name or pattern came after the archive name
    /// (`first_listarg != 0`).
    pub(crate) first_listarg: i64,
    /// No names: zip is a filter and `procname("-")` makes standard input
    /// the one name ([`scan::collect`]).
    pub(crate) filter_mode: bool,
    /// The arguments after the environment's were put in front (zip.c's
    /// `args`, `argv[0]` first): `-R`'s "try: zip ..." hint repeats them.
    pub(crate) args: Vec<Vec<u8>>,
}

impl Options {
    /// The defaults globals.c, zip.c and `main()` start from.
    pub(crate) fn new() -> Options {
        Options {
            action: Action::Add,
            comadd: false,
            zipedit: false,
            latest: false,
            before: 0,
            after: 0,
            test: false,
            unzip_path: None,
            tempdir: false,
            tempath: None,
            junk_sfx: false,
            recurse: 0,
            dispose: false,
            pathput: true,
            method: Method::Best,
            dosify: false,
            verbose: 0,
            fix: 0,
            filesync: false,
            adjust: false,
            level: 6,
            translate_eol: 0,
            no_wild: false,
            allow_regex: true,
            wild_stop_at_dir: false,
            dot_size: 0,
            dot_count: 0,
            display_counts: false,
            display_bytes: false,
            display_globaldots: false,
            display_volume: false,
            display_usize: false,
            logall: false,
            logfile_path: None,
            logfile_append: false,
            dirnames: true,
            diff_mode: false,
            linkput: false,
            noisy: true,
            extra_fields: 1,
            use_descriptors: false,
            zip_to_stdout: false,
            allow_empty_archive: false,
            copy_only: false,
            allow_fifo: false,
            show_files: 0,
            force_zip64: -1,
            utf8_force: false,
            unicode_escape_all: false,
            unicode_mismatch: 1,
            special: Some(b".Z:.zip:.zoo:.arc:.lzh:.arj".to_vec()),
            key: None,
            key_needed: false,
            bad_open_is_error: false,
            zipfile: None,
            in_path: None,
            out_path: None,
            have_out: false,
            split_method: 0,
            split_size: 0,
            split_bell: false,
            noisy_splits: false,
            show_what_doing: false,
            show_args: false,
            show_options: false,
            filters: Vec::new(),
            names: Vec::new(),
            grow: false,
            names_from_stdin: false,
            comment_from_stderr: false,
            kk: 0,
            first_listarg: 0,
            filter_mode: false,
            args: Vec::new(),
        }
    }
}

/// zip.c:help.
pub(crate) fn help(z: &mut Zr) {
    let origin = flavour::origin(z.flavour);
    let version = env!("CARGO_PKG_VERSION");
    let mut text = Vec::new();
    text.extend_from_slice(m::ZIP_HELP_PRE.as_bytes());
    printf(
        &mut text,
        m::ZIP_HELP_HEADER,
        &[version.as_bytes(), origin.as_bytes()],
    );
    text.extend_from_slice(m::ZIP_HELP_POST.as_bytes());
    z.stdout_write(&text);
}

/// zip.c:help_extended.
fn help_extended(z: &mut Zr) {
    let mut text = String::from(m::ZIP_HELP2_HEAD);
    // ubuntu: the `{}` line Apple comments out
    if flavour::help2_brace_line(z.flavour) {
        text.push_str(m::ZIP_HELP2_UBUNTU_LINE);
    }
    text.push_str(m::ZIP_HELP2_TAIL);
    z.stdout_write(text.as_bytes());
}

/// zip.c:license.
fn license(z: &mut Zr) {
    z.stdout_write(m::ZIP_LICENSE.as_bytes());
}

/// The text of `-v` up to the environment section, for `name` (the
/// banner line names stuffr).
fn version_text(f: Flavour, name: &str, program: &str) -> Vec<u8> {
    let version = env!("CARGO_PKG_VERSION");
    let mut text = Vec::new();
    text.extend_from_slice(flavour::version_pre(f, name).as_bytes());
    printf(
        &mut text,
        m::VERSION_BANNER,
        &[
            program.as_bytes(),
            version.as_bytes(),
            flavour::origin(f).as_bytes(),
        ],
    );
    text.extend_from_slice(flavour::version_post(f, name).as_bytes());
    text
}

/// zip.c:version_info: what `zip -v` prints, the environment options
/// included.
// port: zip.c:version_info
pub(crate) fn version_info(z: &mut Zr) {
    let mut text = version_text(z.flavour, "zip", "Zip");
    text.extend_from_slice(m::ENV_HEADER.as_bytes());
    for name in m::ENV_NAMES {
        let v = (z.env)(name)
            .map(|v| v.as_encoded_bytes().to_vec())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| m::ENV_NONE.as_bytes().to_vec());
        // `%16s:  %s`
        text.extend(std::iter::repeat_n(
            b' ',
            16usize.saturating_sub(name.len()),
        ));
        text.extend_from_slice(name.as_bytes());
        text.extend_from_slice(b":  ");
        text.extend_from_slice(&v);
        text.push(b'\n');
    }
    z.stdout_write(&text);
}

/// The `-so` listing of `table`, as `main()` prints it.
fn show_options(z: &mut Zr, table: &[OptionSpec]) {
    fn pad(out: &mut Vec<u8>, s: &str, width: usize) {
        out.extend_from_slice(s.as_bytes());
        for _ in s.len()..width {
            out.push(b' ');
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(m::AVAILABLE_OPTIONS.as_bytes());
    for words in [m::SO_HEADINGS, m::SO_UNDERLINES] {
        out.push(b' ');
        pad(&mut out, words[0], 2);
        out.extend_from_slice(b"  ");
        pad(&mut out, words[1], 18);
        out.push(b' ');
        pad(&mut out, words[2], 4);
        out.push(b' ');
        pad(&mut out, words[3], 3);
        out.push(b' ');
        pad(&mut out, words[4], 30);
        out.push(b'\n');
    }
    for s in table {
        out.push(b' ');
        pad(&mut out, s.short, 2);
        out.extend_from_slice(b"  ");
        pad(&mut out, s.long, 18);
        out.push(b' ');
        pad(
            &mut out,
            match s.value {
                ValueType::No => "",
                ValueType::Required => m::SO_REQ,
                ValueType::Optional => m::SO_OPT,
                ValueType::List => m::SO_LIST,
                ValueType::OneChar => m::SO_CHAR,
                ValueType::Number => m::SO_NUM,
            },
            4,
        );
        out.push(b' ');
        pad(&mut out, if s.negatable { m::SO_NEG } else { "" }, 3);
        out.push(b' ');
        pad(&mut out, s.name, 30);
        out.push(b'\n');
    }
    z.stdout_write(&out);
}

/// zip.c:finish for the paths `main()` leaves through `RETURN(finish(e))`
/// before any archive is read: `-o` finds an empty archive, so says so
/// (`-m` has nothing to delete yet).
pub(crate) fn finish(z: &mut Zr, e: i32) -> Exit {
    if z.o.latest && z.o.zipfile.as_deref().is_some_and(|f| f != b"-") {
        z.zipwarn(m::ZIP_EMPTY_NO_LATEST.as_bytes(), b"");
    }
    Exit { code: e }
}

/// zip.c:add_filter: one `-i`/`-x`/`-R` pattern, or the lines of the file
/// `@name` names (each a pattern).
// port: zip.c:add_filter
fn add_filter(z: &mut Zr, flag: u8, pattern: Vec<u8>) -> Result<(), Exit> {
    if pattern.first() == Some(&b'@') {
        // read a file with one pattern per line
        if pattern.len() == 1 {
            return Err(z.ziperr(ZE_PARMS, m::MISSING_FILE_AFTER_AT.as_bytes()));
        }
        let path = z.host.path(&pattern[1..]);
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                let mut why = Vec::new();
                printf(&mut why, m::PATTERN_FILE, &[&[flag], &pattern]);
                return Err(z.ziperr_os(ZE_OPEN, &why, &e));
            }
        };
        let mut r = io::BufReader::new(file);
        while let Some(p) = getnam(&mut r) {
            let Some(pattern) = scan::ex2in(&p, z.o.pathput, z.o.dosify) else {
                return Err(scan::crashed(z));
            };
            z.o.filters.push(Filter { flag, pattern });
        }
    } else {
        // the pattern is converted as a name is (`in2ex(ex2in(...))`), with
        // the options in force at this point of the command line
        let Some(pattern) = scan::ex2in(&pattern, z.o.pathput, z.o.dosify) else {
            return Err(scan::crashed(z));
        };
        z.o.filters.push(Filter { flag, pattern });
    }
    Ok(())
}

/// zip.c:zipstdout: the archive goes to standard output, so messages go to
/// standard error.
fn zipstdout(z: &mut Zr) -> Result<(), Exit> {
    z.mesg_err = true;
    if z.host.stdout_is_tty() {
        return Err(z.ziperr(ZE_PARMS, m::CANNOT_WRITE_TO_TERMINAL.as_bytes()));
    }
    z.o.zipfile = Some(b"-".to_vec());
    Ok(())
}

/// A `ziperr(ZE_PARMS, text)` from a `get_option` error.
fn parms(z: &mut Zr, text: &[u8]) -> Exit {
    z.ziperr(ZE_PARMS, text)
}

/// `value` of an option that always has one.
fn val(v: Option<Vec<u8>>) -> Vec<u8> {
    v.unwrap_or_default()
}

/// zip.c:main: the command line of `zip` itself, through the checks that
/// precede reading the archive. `Err` ends the run with its code (`-h`,
/// `-v`, `-so` and every `ziperr` do); `Ok` is a command line that would
/// go on to archive.
// port: zip.c:main
pub(crate) fn parse_zip(z: &mut Zr, argv0: &[u8], rest: &[Vec<u8>]) -> Result<(), Exit> {
    let table = table(z.flavour);
    let mut args: Vec<Vec<u8>> = Vec::with_capacity(rest.len() + 1);
    args.push(argv0.to_vec());
    args.extend(rest.iter().cloned());

    // First, check if just the help or version screen should be displayed.
    if args.len() == 1 && z.host.stdout_is_tty() {
        // no arguments, and output screen available
        help(z);
        return Err(Exit { code: ZE_OK });
    } else if args.len() == 2
        && args[1] == b"-v"
        && (z.host.stdout_is_tty() || z.host.stdin_is_tty())
    {
        // only "-v" as argument, and stdout or stdin is a console
        version_info(z);
        return Err(Exit { code: ZE_OK });
    }
    // get options from the environment
    let mut args = envargs(args, z.env, "ZIPOPT", "ZIP");
    z.o.args = args.clone();

    let mut st = GetOpt::new();
    loop {
        let got = match get_option(&table, &mut args, &mut st) {
            Ok(g) => g,
            Err(text) => return Err(parms(z, &text)),
        };
        if got.id == 0 {
            break;
        }
        let negated = got.negated;
        let value = got.value;
        match (u8::try_from(got.id).ok(), got.id) {
            // -0
            (Some(b'0'), _) => {
                z.o.method = Method::Store;
                z.o.level = 0;
            }
            // -1 to -9: the compression efficacy
            (Some(c @ b'1'..=b'9'), _) => z.o.level = c - b'0',
            // -A
            (Some(b'A'), _) => z.o.adjust = true,
            // -b
            (Some(b'b'), _) => {
                z.o.tempdir = true;
                z.o.tempath = value;
            }
            // -c
            (Some(b'c'), _) => z.o.comadd = true,
            // -d
            (Some(b'd'), _) => {
                if z.o.action != Action::Add {
                    return Err(z.ziperr(ZE_PARMS, m::JUST_ONE_ACTION.as_bytes()));
                }
                z.o.action = Action::Delete;
            }
            (_, o::DB) => z.o.display_bytes = !negated,
            (_, o::DC) => z.o.display_counts = !negated,
            (_, o::DD) => {
                // display dots
                z.o.display_globaldots = false;
                if negated {
                    z.o.dot_count = 0;
                } else {
                    // default to 10 MB when no size is set
                    if z.o.dot_count == 0 {
                        z.o.dot_size = 10 * 0x10_0000;
                    }
                    z.o.dot_count = -1;
                }
            }
            (_, o::DG) => {
                // dots for the archive instead of each file
                if negated {
                    z.o.display_globaldots = false;
                } else {
                    z.o.display_globaldots = true;
                    if z.o.dot_count == 0 {
                        z.o.dot_size = 10 * 0x10_0000;
                    }
                    z.o.dot_count = -1;
                }
            }
            (_, o::DS) => {
                // the input is the actual dot size
                let v = val(value);
                if v.is_empty() {
                    z.o.dot_size = 10 * 0x10_0000;
                } else {
                    let (n, warn) = read_num_string(&v);
                    if let Some(w) = warn {
                        z.zipwarn(w.as_bytes(), &v);
                    }
                    let mut size = n as i64;
                    if size == -1 {
                        let mut e = Vec::new();
                        printf(&mut e, m::DS_BAD_SIZE, &[&v]);
                        return Err(z.ziperr(ZE_PARMS, &e));
                    }
                    if size < 0x400 {
                        // < 1 KB: no multiplier, assume MB
                        size = size.wrapping_mul(0x10_0000);
                    } else if size < 0x400 * 32 {
                        let mut e = Vec::new();
                        printf(&mut e, m::DS_TOO_SMALL, &[&v]);
                        return Err(z.ziperr(ZE_PARMS, &e));
                    }
                    z.o.dot_size = size;
                }
                z.o.dot_count = -1;
            }
            (_, o::DU) => z.o.display_usize = !negated,
            (_, o::DV) => z.o.display_volume = !negated,
            // -D
            (Some(b'D'), _) => z.o.dirnames = false,
            (_, o::DF_CAP) => {
                z.o.diff_mode = true;
                z.o.allow_empty_archive = true;
            }
            // -e
            (Some(b'e'), _) => {
                z.o.key = None;
                z.o.key_needed = true;
            }
            // -F
            (Some(b'F'), _) => z.o.fix = 1,
            (_, o::FF) => z.o.fix = 2,
            (_, o::FI) => z.o.allow_fifo = !negated,
            (_, o::FS) => z.o.filesync = true,
            // -f
            (Some(b'f'), _) => {
                if z.o.action != Action::Add {
                    return Err(z.ziperr(ZE_PARMS, m::JUST_ONE_ACTION.as_bytes()));
                }
                z.o.action = Action::Freshen;
            }
            // -g
            (Some(b'g'), _) => z.o.grow = true,
            // -h, -H, -?
            (Some(b'h'), _) => {
                help(z);
                return Err(finish(z, ZE_OK));
            }
            (_, o::H2) => {
                help_extended(z);
                return Err(finish(z, ZE_OK));
            }
            // -j
            (Some(b'j'), _) => z.o.pathput = false,
            // -J
            (Some(b'J'), _) => z.o.junk_sfx = true,
            // -k
            (Some(b'k'), _) => z.o.dosify = true,
            // -l
            (Some(b'l'), _) => z.o.translate_eol = 1,
            (_, o::LL) => z.o.translate_eol = 2,
            (_, o::LF) => z.o.logfile_path = value,
            (_, o::LA) => z.o.logfile_append = !negated,
            (_, o::LI) => z.o.logall = !negated,
            // -L
            (Some(b'L'), _) => {
                license(z);
                return Err(finish(z, ZE_OK));
            }
            // -m
            (Some(b'm'), _) => z.o.dispose = true,
            (_, o::MM) => return Err(z.ziperr(ZE_PARMS, m::MM_NOT_SUPPORTED.as_bytes())),
            (_, o::MM_CAP) => z.o.bad_open_is_error = true,
            // -n
            (Some(b'n'), _) => z.o.special = value,
            (_, o::NW) => z.o.no_wild = true,
            // -o
            (Some(b'o'), _) => z.o.latest = true,
            // -O
            (Some(b'O'), _) => {
                z.o.out_path = Some(ziptyp(&val(value), z.o.adjust));
                z.o.have_out = true;
            }
            // -p: nothing
            (Some(b'p'), _) => {}
            // -P
            (Some(b'P'), _) => {
                z.o.key = value;
                z.o.key_needed = false;
            }
            // -q
            (Some(b'q'), _) => {
                z.o.noisy = false;
                if z.o.verbose > 0 {
                    z.o.verbose -= 1;
                }
            }
            // -r
            (Some(b'r'), _) => {
                if z.o.recurse == 2 {
                    return Err(z.ziperr(ZE_PARMS, m::NOT_BOTH_R.as_bytes()));
                }
                z.o.recurse = 1;
            }
            // -R
            (Some(b'R'), _) => {
                if z.o.recurse == 1 {
                    return Err(z.ziperr(ZE_PARMS, m::NOT_BOTH_R.as_bytes()));
                }
                z.o.recurse = 2;
            }
            (_, o::RE) => z.o.allow_regex = true,
            (_, o::SC) => z.o.show_args = true,
            (_, o::SD) => z.o.show_what_doing = true,
            (_, o::SF) => z.o.show_files = if negated { 2 } else { 1 },
            (_, o::SO) => z.o.show_options = true,
            // ubuntu: -DUNICODE_SUPPORT
            (_, o::SU) => z.o.show_files = if negated { 4 } else { 3 },
            (_, o::SU_CAP) => z.o.show_files = if negated { 6 } else { 5 },
            // -s
            (Some(b's'), _) => {
                let v = val(value);
                if v == b"-" {
                    // -s- do not allow splits
                    z.o.split_method = -1;
                } else {
                    let (n, warn) = read_num_string(&v);
                    if let Some(w) = warn {
                        z.zipwarn(w.as_bytes(), &v);
                    }
                    z.o.split_size = n;
                    if z.o.split_size == u64::MAX {
                        let mut e = Vec::new();
                        printf(&mut e, m::BAD_SPLIT_SIZE, &[&v]);
                        return Err(z.ziperr(ZE_PARMS, &e));
                    }
                    if z.o.split_size == 0 {
                        // do not allow splits
                        z.o.split_method = -1;
                    } else {
                        if z.o.split_method == 0 {
                            z.o.split_method = 1;
                        }
                        if z.o.split_size < 0x400 {
                            // < 1 KB: no multiplier, assume MB
                            z.o.split_size = z.o.split_size.wrapping_mul(0x10_0000);
                        }
                        // at least 64 KB so a header always fits unsplit
                        if z.o.split_size < 0x400 * 64 {
                            let mut e = Vec::new();
                            printf(&mut e, m::SPLIT_TOO_SMALL, &[&v]);
                            return Err(z.ziperr(ZE_PARMS, &e));
                        }
                    }
                }
            }
            (_, o::SB) => z.o.split_bell = true,
            (_, o::SP) => {
                z.o.use_descriptors = true;
                z.o.split_method = 2;
            }
            (_, o::SV) => z.o.noisy_splits = true,
            // -t
            (Some(b't'), _) => match read_date(&val(value)) {
                Some(t) => z.o.before = t,
                None => return Err(z.ziperr(ZE_PARMS, m::BAD_T_DATE.as_bytes())),
            },
            (_, o::TT) => match read_date(&val(value)) {
                Some(t) => z.o.after = t,
                None => return Err(z.ziperr(ZE_PARMS, m::BAD_TT_DATE.as_bytes())),
            },
            // -T
            (Some(b'T'), _) => z.o.test = true,
            (_, o::TT_CAP) => z.o.unzip_path = value,
            // -U
            (Some(b'U'), _) => {
                if z.o.action != Action::Add {
                    return Err(z.ziperr(ZE_PARMS, m::JUST_ONE_ACTION.as_bytes()));
                }
                z.o.action = Action::Archive;
            }
            // ubuntu: -DUNICODE_SUPPORT, -UN
            (_, o::UN) => {
                let v = val(value);
                if abbrevmatch(b"quit", &v, false, 1) {
                    z.o.unicode_mismatch = 0;
                } else if abbrevmatch(b"warn", &v, false, 1) {
                    z.o.unicode_mismatch = 1;
                } else if abbrevmatch(b"ignore", &v, false, 1) {
                    z.o.unicode_mismatch = 2;
                } else if abbrevmatch(b"no", &v, false, 1) {
                    z.o.unicode_mismatch = 3;
                } else if abbrevmatch(b"escape", &v, false, 1) {
                    z.o.unicode_escape_all = true;
                } else if abbrevmatch(b"UTF8", &v, false, 1) {
                    z.o.utf8_force = true;
                } else {
                    z.zipwarn(m::UN_MUST_BE.as_bytes(), &v);
                    return Err(z.ziperr(ZE_PARMS, m::UN_BAD_VALUE.as_bytes()));
                }
            }
            // -u
            (Some(b'u'), _) => {
                if z.o.action != Action::Add {
                    return Err(z.ziperr(ZE_PARMS, m::JUST_ONE_ACTION.as_bytes()));
                }
                z.o.action = Action::Update;
            }
            // -v and --version
            (Some(b'v'), _) | (_, o::VE) => {
                if got.id == o::VE || (args.len() == 2 && args[1].len() == 2) {
                    // display version (--version, or -v alone)
                    version_info(z);
                    return Err(finish(z, ZE_OK));
                }
                z.o.noisy = true;
                z.o.verbose += 1;
            }
            (_, o::WS) => z.o.wild_stop_at_dir = true,
            // -i, then as -x
            (Some(b'i' | b'x'), _) => {
                if got.id == u32::from(b'i') {
                    z.o.allow_empty_archive = true;
                }
                add_filter(z, got.id as u8, val(value))?;
            }
            // -y
            (Some(b'y'), _) => z.o.linkput = true,
            // -z
            (Some(b'z'), _) => z.o.zipedit = true,
            // -Z
            (Some(b'Z'), _) => {
                let v = val(value);
                if abbrevmatch(b"deflate", &v, false, 1) {
                    z.o.method = Method::Deflate;
                } else if abbrevmatch(b"store", &v, false, 1) {
                    z.o.method = Method::Store;
                } else if abbrevmatch(b"bzip2", &v, false, 1) {
                    // ubuntu: -DBZIP2_SUPPORT
                    if flavour::bzip2_support(z.flavour) {
                        z.o.method = Method::Bzip2;
                    } else {
                        return Err(z.ziperr(ZE_COMPERR, m::Z_BZIP2_NOT_ENABLED.as_bytes()));
                    }
                } else {
                    let methods = if flavour::bzip2_support(z.flavour) {
                        m::Z_METHODS_BZIP2
                    } else {
                        m::Z_METHODS_PLAIN
                    };
                    z.zipwarn(methods.as_bytes(), b"");
                    z.zipwarn(m::Z_UNKNOWN_FOUND.as_bytes(), &v);
                    return Err(z.ziperr(ZE_PARMS, m::Z_UNKNOWN.as_bytes()));
                }
            }
            // -@: defer reading names until the archive name is known
            (Some(b'@'), _) => {
                z.o.names_from_stdin = true;
                z.o.comment_from_stderr = true;
            }
            // -X
            (Some(b'X'), _) => z.o.extra_fields = if negated { 2 } else { 0 },
            (_, o::DES) => z.o.use_descriptors = true,
            (_, o::Z64) => z.o.force_zip64 = if negated { 0 } else { 1 },
            (_, o::NON_OPTION_ARG) => {
                non_option_arg(z, val(value), st.argnum)?;
            }
            // every ID in the table has an arm (a unit test pins it); an
            // unknown one is the C's `no such option ID` ziperr
            (_, id) => {
                let mut e = Vec::new();
                printf(&mut e, m::NO_SUCH_OPTION_ID, &[id.to_string().as_bytes()]);
                return Err(z.ziperr(ZE_PARMS, &e));
            }
        }
    }

    // Key not yet specified. If needed, get/verify it now.
    if z.o.key_needed {
        // ttyio.c:getp finds no terminal to prompt on: encr_passwd's error.
        // A terminal is Task 11's.
        if z.host.stderr_is_tty() {
            return Err(z.not_built());
        }
        return Err(z.ziperr(ZE_PARMS, m::STDERR_NOT_TTY.as_bytes()));
    }
    if let Some(key) = &z.o.key
        && key.is_empty()
    {
        // if -P "" could get here
        return Err(z.ziperr(ZE_PARMS, m::ZERO_LENGTH_PASSWORD.as_bytes()));
    }

    if z.o.show_what_doing {
        z.mesg_write(m::SD_COMMAND_LINE_READ.as_bytes());
    }

    // show command line args
    if z.o.show_args {
        z.mesg_write(m::COMMAND_LINE.as_bytes());
        for a in &args {
            let mut line = Vec::new();
            printf(&mut line, m::COMMAND_LINE_ARG, &[a]);
            z.mesg_write(&line);
        }
        z.mesg_write(b"\n");
        return Err(z.ziperr(ZE_ABORT, m::SHOW_COMMAND_LINE.as_bytes()));
    }

    // show all options
    if z.o.show_options {
        show_options(z, &table);
        return Err(finish(z, ZE_OK));
    }

    open_log(z, &args)?;
    checks(z)
}

/// zip.c:main, `case o_NON_OPTION_ARG`: the archive name first, then the
/// names (or, with `-R`, patterns) to archive.
fn non_option_arg(z: &mut Zr, value: Vec<u8>, argnum: i64) -> Result<(), Exit> {
    // "--" stops arg processing for remaining args; ignore only the first
    if value == b"--" && !z.seen_doubledash {
        z.seen_doubledash = true;
        if z.o.kk == 0 {
            return Err(z.ziperr(ZE_PARMS, m::DOUBLEDASH_BEFORE_NAME.as_bytes()));
        }
        // just marks what follows as non-option arguments
        return Ok(());
    }
    if z.o.kk == 6 {
        // value is an -R pattern
        add_filter(z, b'R', value)?;
        if z.o.first_listarg == 0 {
            z.o.first_listarg = argnum;
        }
        return Ok(());
    }
    match z.o.kk {
        0 => {
            // first non-option arg is the zipfile name
            if value == b"-" {
                // the output zipfile is a dash
                zipstdout(z)?;
            } else {
                z.o.zipfile = Some(ziptyp(&value, z.o.adjust));
            }
            let zipfile = z.o.zipfile.clone().unwrap_or_default();
            if z.o.show_what_doing {
                let mut line = Vec::new();
                printf(&mut line, m::SD_ZIPFILE_NAME, &[&zipfile]);
                z.mesg_write(&line);
            }
            // in_path is the base path to find splits, out_path where the
            // output archive is written
            if z.o.in_path.is_none() {
                z.o.in_path = Some(zipfile.clone());
            }
            if z.o.out_path.is_none() {
                z.o.out_path = Some(zipfile);
            }
            z.o.kk = 3;
            if z.o.names_from_stdin {
                // do -@ and get names from stdin
                let mut input = z.host.stdin();
                while let Some(pp) = getnam(&mut input) {
                    z.o.kk = 4;
                    if z.o.recurse == 2 {
                        // reading patterns from stdin
                        add_filter(z, b'R', pp)?;
                    } else {
                        z.o.names.push(pp);
                    }
                }
                z.o.names_from_stdin = false;
            }
            if z.o.recurse == 2 {
                // the rest are -R patterns
                z.o.kk = 6;
            }
        }
        _ => {
            // 3 or 4: no recurse and -r file names. Can't read filenames
            // (-@) and input - from stdin at the same time.
            if z.o.names_from_stdin && value == b"-" {
                return Err(z.ziperr(ZE_PARMS, m::STDIN_BOTH.as_bytes()));
            }
            // add the name to the list for later processing
            z.o.names.push(value);
            if z.o.kk == 3 {
                z.o.first_listarg = argnum;
                z.o.kk = 4;
            }
        }
    }
    Ok(())
}

/// zip.c:main, opening the log file (`-lf`).
fn open_log(z: &mut Zr, args: &[Vec<u8>]) -> Result<(), Exit> {
    let Some(mut path) = z.o.logfile_path.clone() else {
        // only set logall if a log file is open
        z.o.logall = false;
        return Ok(());
    };
    // if no extension add .log
    let lastp = path.iter().rposition(|&b| b == b'/').unwrap_or(0);
    if !path[lastp..].contains(&b'.') {
        path.extend_from_slice(b".log");
        z.o.logfile_path = Some(path.clone());
    }
    let mut opts = std::fs::OpenOptions::new();
    if z.o.logfile_append {
        opts.append(true).create(true);
    } else {
        opts.write(true).create(true).truncate(true);
    }
    let file = match opts.open(z.host.path(&path)) {
        Ok(f) => f,
        Err(_) => {
            let mut e = Vec::new();
            printf(&mut e, m::COULD_NOT_OPEN_LOG, &[&path]);
            return Err(z.ziperr(ZE_PARMS, &e));
        }
    };
    z.log = Some(Box::new(file));
    // at the top: the start time and the command line
    let mut head = Vec::new();
    head.extend_from_slice(m::LOG_SEPARATOR.as_bytes());
    printf(
        &mut head,
        m::LOG_OPENED,
        &[super::asctime_now(z).as_bytes()],
    );
    head.extend_from_slice(m::LOG_COMMAND_LINE.as_bytes());
    for a in args.iter().skip(1) {
        let fmt = if a.iter().any(|&b| is_space(b)) {
            m::LOG_ARG_QUOTED
        } else {
            m::LOG_ARG
        };
        printf(&mut head, fmt, &[a]);
    }
    head.extend_from_slice(m::LOG_ARGS_END.as_bytes());
    z.log_write(&head);
    Ok(())
}

/// zip.c:main, after the log file: the checks on the options as a whole.
fn checks(z: &mut Zr) -> Result<(), Exit> {
    if z.o.split_method != 0
        && let Some(out) = &z.o.out_path
    {
        // if splitting, the archive name must have a .zip extension
        let ext_ok = out.len() >= 4 && out[out.len() - 4..].eq_ignore_ascii_case(b".zip");
        if !ext_ok {
            return Err(z.ziperr(ZE_PARMS, m::SPLIT_NEEDS_ZIP.as_bytes()));
        }
    }

    if z.o.verbose > 0 && z.o.dot_size == 0 && z.o.dot_count == 0 {
        // now default to a 10 MB dot size
        z.o.dot_size = 10 * 0x10_0000;
    }

    if z.o.have_out && z.o.kk == 3 {
        z.o.copy_only = true;
        z.o.action = Action::Archive;
    }

    if z.o.have_out && z.o.in_path.is_none() {
        // ruling: `-O` without an archive name. The C's `namecmp(in_path,
        // out_path)` compares a NULL `in_path` and dies of SIGSEGV, which
        // zip's handler turns into this exit (deviation 5): the reference's
        // observable, without the dereference.
        z.mesg_write(b"\n");
        return Err(z.ziperr(ZE_ABORT, m::ABORTING.as_bytes()));
    }
    if z.o.have_out && z.o.in_path == z.o.out_path {
        let mut e = Vec::new();
        printf(
            &mut e,
            m::OUT_PATH_DIFFERENT,
            &[z.o.out_path.as_deref().unwrap_or_default()],
        );
        return Err(z.ziperr(ZE_PARMS, &e));
    }
    // ruling Z21 (deviation 20): -F/-FF never replace the damaged archive
    // with what they salvage, whatever --out spells it as (the C compares
    // the names only)
    if z.o.fix != 0
        && z.o.have_out
        && let (Some(i), Some(o)) = (&z.o.in_path, &z.o.out_path)
        && let (Ok(a), Ok(b)) = (
            std::fs::metadata(z.host.path(i)),
            std::fs::metadata(z.host.path(o)),
        )
        && crate::compat::host::same_file(&a, &b) == Some(true)
    {
        let mut e = Vec::new();
        printf(&mut e, m::OUT_PATH_DIFFERENT, &[o]);
        return Err(z.ziperr(ZE_PARMS, &e));
    }

    if z.o.fix != 0 && z.o.diff_mode {
        return Err(z.ziperr(ZE_PARMS, m::DIFF_WITH_FIX.as_bytes()));
    }
    if z.o.action == Action::Archive && !z.o.have_out && z.o.show_files == 0 {
        return Err(z.ziperr(ZE_PARMS, m::COPY_NEEDS_OUT.as_bytes()));
    }
    if z.o.fix != 0 && !z.o.have_out {
        z.zipwarn(
            m::FIX_NEEDS_OUT_WARN.as_bytes(),
            m::FIX_NEEDS_OUT_EXAMPLE.as_bytes(),
        );
        return Err(z.ziperr(ZE_PARMS, m::FIX_NEEDS_OUT.as_bytes()));
    }
    if z.o.fix != 0 && !z.o.copy_only {
        return Err(z.ziperr(ZE_PARMS, m::FIX_NO_OTHER_ACTIONS.as_bytes()));
    }
    if !z.o.have_out && z.o.diff_mode {
        return Err(z.ziperr(ZE_PARMS, m::DIFF_NEEDS_OUT.as_bytes()));
    }
    if z.o.diff_mode && matches!(z.o.action, Action::Archive | Action::Delete) {
        return Err(z.ziperr(ZE_PARMS, m::DIFF_WITH_D_OR_U.as_bytes()));
    }
    if z.o.action != Action::Archive
        && (z.o.recurse == 2 || !z.o.filters.is_empty())
        && z.o.first_listarg == 0
        && z.o.names.is_empty()
        && (z.o.kk < 3 || !matches!(z.o.action, Action::Update | Action::Freshen))
    {
        return Err(z.ziperr(ZE_PARMS, m::NOTHING_TO_SELECT.as_bytes()));
    }

    // no names: zip is used as a filter, on standard input
    if z.o.kk < 3 {
        zipstdout(z)?;
        // procname("-"): `scan::collect` makes standard input the one name
        z.o.filter_mode = true;
        z.o.kk = 4;
        if z.o.names_from_stdin {
            return Err(z.ziperr(ZE_PARMS, m::DASH_AND_AT.as_bytes()));
        }
    }

    if z.o.zipfile.as_deref() == Some(b"-") {
        if z.o.show_what_doing {
            z.mesg_write(m::SD_ZIPPING_TO_STDOUT.as_bytes());
        }
        z.o.zip_to_stdout = true;
    }

    // Check option combinations
    if z.o.special.is_none() {
        // `-n` always has a value, so this is the C's unreachable check
        return Err(z.ziperr(ZE_PARMS, m::MISSING_SUFFIX_LIST.as_bytes()));
    }
    if z.o.level == 9
        || z.o.special.as_deref() == Some(b";")
        || z.o.special.as_deref() == Some(b":")
    {
        // compress everything
        z.o.special = None;
    }

    if z.o.action == Action::Delete
        && (z.o.method != Method::Best
            || z.o.dispose
            || z.o.recurse != 0
            || z.o.key.is_some()
            || z.o.comadd
            || z.o.zipedit)
    {
        z.zipwarn(m::D_INVALID_OPTIONS.as_bytes(), b"");
        z.o.method = Method::Best;
        z.o.dispose = false;
        z.o.recurse = 0;
        z.o.key = None;
        z.o.comadd = false;
        z.o.zipedit = false;
    }
    if z.o.action == Action::Archive
        && (z.o.method != Method::Best
            || z.o.dispose
            || z.o.recurse != 0
            || z.o.comadd
            || z.o.zipedit)
    {
        z.zipwarn(m::COPY_MODE_OPTIONS.as_bytes(), b"");
        z.o.method = Method::Best;
        z.o.dispose = false;
        z.o.recurse = 0;
        z.o.comadd = false;
        z.o.zipedit = false;
    }
    if z.o.linkput && z.o.dosify {
        z.zipwarn(m::Y_WITH_K.as_bytes(), b"");
        z.o.linkput = false;
    }
    if z.o.fix == 1 && z.o.adjust {
        z.zipwarn(m::F_WITH_A.as_bytes(), b"");
        z.o.fix = 0;
    }
    if z.o.fix == 2 && z.o.adjust {
        z.zipwarn(m::FF_WITH_A.as_bytes(), b"");
        z.o.fix = 0;
    }
    if z.o.test && z.o.zip_to_stdout {
        z.o.test = false;
        z.zipwarn(m::T_ON_STDOUT.as_bytes(), b"");
    }
    if z.o.split_method != 0 && (z.o.fix != 0 || z.o.adjust) {
        return Err(z.ziperr(ZE_PARMS, m::SPLIT_WITH_FIX.as_bytes()));
    }
    if z.o.split_method != 0 && (z.o.grow || z.o.zip_to_stdout) {
        return Err(z.ziperr(ZE_PARMS, m::SPLIT_WITH_D_OR_STDOUT.as_bytes()));
    }
    if (z.o.action != Action::Add || z.o.grow) && z.o.filesync {
        return Err(z.ziperr(ZE_PARMS, m::FILESYNC_WITH_ACTION.as_bytes()));
    }
    if (z.o.action != Action::Add || z.o.grow) && z.o.zip_to_stdout {
        return Err(z.ziperr(ZE_PARMS, m::ACTION_ON_STDOUT.as_bytes()));
    }

    if z.o.noisy {
        if z.o.fix == 1 {
            z.zipmessage(m::FIX_ARCHIVE_F.as_bytes(), b"");
        } else if z.o.fix == 2 {
            z.zipmessage(m::FIX_ARCHIVE_FF.as_bytes(), b"");
        }
    }
    // The old archive is read next (Task 8 and the tasks after it).
    Ok(())
}

// ---- the helpers ----

/// What `zipcloak`'s command line leaves (zipcloak.c:main).
#[derive(Debug, Clone, Default)]
pub(crate) struct CloakOptions {
    pub(crate) zipfile: Vec<u8>,
    pub(crate) out_path: Option<Vec<u8>>,
    pub(crate) tempath: Option<Vec<u8>>,
    pub(crate) decrypt: bool,
}

/// zipcloak.c:help_info. `Err` is the run's end.
fn cloak_help(z: &mut Zr) {
    let mut text = Vec::new();
    text.extend_from_slice(m::ZIPCLOAK_HELP_PRE.as_bytes());
    printf(
        &mut text,
        m::ZIPCLOAK_HELP_HEADER,
        &[
            env!("CARGO_PKG_VERSION").as_bytes(),
            flavour::origin(z.flavour).as_bytes(),
        ],
    );
    text.extend_from_slice(m::ZIPCLOAK_HELP_POST.as_bytes());
    z.stdout_write(&text);
}

/// The help of `zipnote` or `zipsplit`.
fn helper_help(z: &mut Zr, name: &str) {
    let (pre, header, post) = if name == "zipnote" {
        (
            m::ZIPNOTE_HELP_PRE,
            m::ZIPNOTE_HELP_HEADER,
            m::ZIPNOTE_HELP_POST,
        )
    } else {
        (
            m::ZIPSPLIT_HELP_PRE,
            m::ZIPSPLIT_HELP_HEADER,
            m::ZIPSPLIT_HELP_POST,
        )
    };
    let mut text = Vec::new();
    text.extend_from_slice(pre.as_bytes());
    printf(
        &mut text,
        header,
        &[
            env!("CARGO_PKG_VERSION").as_bytes(),
            flavour::origin(z.flavour).as_bytes(),
        ],
    );
    text.extend_from_slice(post.as_bytes());
    z.stdout_write(&text);
}

/// A helper's `-v`: its recorded text with the banner line of stuffr's.
fn helper_version(z: &mut Zr, name: &str) {
    let program = match name {
        "zipcloak" => "ZipCloak",
        "zipnote" => "ZipNote",
        _ => "ZipSplit",
    };
    let text = version_text(z.flavour, name, program);
    z.stdout_write(&text);
}

/// A helper's `-L`: zip's licence (zipcloak adds the export notice).
fn helper_license(z: &mut Zr, name: &str) {
    let mut text = String::from(m::ZIP_LICENSE);
    if name == "zipcloak" {
        text.push_str(m::ZIPCLOAK_LICENSE_EXTRA);
    }
    z.stdout_write(text.as_bytes());
}

/// zipcloak.c:main, through the arguments: help for no arguments, the
/// `get_option` loop with zipcloak's own table, the archive's name.
// port: zipcloak.c:main
pub(crate) fn parse_cloak(
    z: &mut Zr,
    argv0: &[u8],
    rest: &[Vec<u8>],
) -> Result<CloakOptions, Exit> {
    // If no args, show help
    if rest.is_empty() {
        cloak_help(z);
        return Err(Exit { code: ZE_OK });
    }
    // Informational messages are written to stdout.
    z.mesg_err = false;
    let table = cloak_table();
    let mut args: Vec<Vec<u8>> = vec![argv0.to_vec()];
    args.extend(rest.iter().cloned());
    let mut o = CloakOptions::default();
    let mut zipfile: Option<Vec<u8>> = None;
    let mut temp_path = false;
    let mut st = GetOpt::new();
    loop {
        let got = match get_option(&table, &mut args, &mut st) {
            Ok(g) => g,
            Err(text) => return Err(z.helper_err(ZE_PARMS, &text)),
        };
        if got.id == 0 {
            break;
        }
        match (u8::try_from(got.id).ok(), got.id) {
            // -b
            (Some(b'b'), _) => {
                if temp_path {
                    return Err(z.helper_err(ZE_PARMS, m::CLOAK_MORE_THAN_ONE_TEMP.as_bytes()));
                }
                temp_path = true;
                o.tempath = got.value;
            }
            // -d
            (Some(b'd'), _) => o.decrypt = true,
            // -h
            (Some(b'h'), _) => {
                cloak_help(z);
                return Err(Exit { code: ZE_OK });
            }
            // -l, -L
            (Some(b'L'), _) => {
                helper_license(z, "zipcloak");
                return Err(Exit { code: ZE_OK });
            }
            // -O
            (Some(b'O'), _) => o.out_path = Some(ziptyp(&val(got.value), false)),
            // -v
            (Some(b'v'), _) => {
                helper_version(z, "zipcloak");
                return Err(Exit { code: ZE_OK });
            }
            (_, o::NON_OPTION_ARG) => {
                let value = val(got.value);
                if value == b"-" {
                    return Err(z.helper_err(ZE_PARMS, m::ZIP_FILE_STDIN.as_bytes()));
                } else if zipfile.is_some() {
                    return Err(z.helper_err(ZE_PARMS, m::ONLY_ONE_ZIP_FILE.as_bytes()));
                }
                zipfile = Some(ziptyp(&value, false));
            }
            _ => return Err(z.helper_err(ZE_PARMS, m::UNKNOWN_OPTION.as_bytes())),
        }
    }
    let Some(zipfile) = zipfile else {
        return Err(z.helper_err(ZE_PARMS, m::NEED_ZIP_FILE.as_bytes()));
    };
    o.zipfile = zipfile;
    Ok(o)
}

/// What `zipnote`'s command line leaves (zipnote.c:main).
#[derive(Debug, Clone, Default)]
pub(crate) struct NoteOptions {
    pub(crate) zipfile: Vec<u8>,
    pub(crate) tempath: Option<Vec<u8>>,
    /// `-w`: update the comments from standard input.
    pub(crate) write: bool,
}

/// zipnote.c:main, through the arguments: its own loop over `argv`.
// port: zipnote.c:main
pub(crate) fn parse_note(z: &mut Zr, rest: &[Vec<u8>]) -> Result<NoteOptions, Exit> {
    // If no args, show help
    if rest.is_empty() {
        helper_help(z, "zipnote");
        return Err(Exit { code: ZE_OK });
    }
    // Direct info messages to stderr; stdout is used for data output.
    z.mesg_err = true;
    let mut o = NoteOptions::default();
    let mut zipfile: Option<Vec<u8>> = None;
    let mut k = false;
    for arg in rest {
        if arg.first() == Some(&b'-') {
            if arg.len() == 1 {
                return Err(z.helper_err(ZE_PARMS, m::ZIP_FILE_STDIN.as_bytes()));
            }
            for &c in &arg[1..] {
                match c {
                    // specify path for the temporary file
                    b'b' => {
                        if k {
                            return Err(z.helper_err(ZE_PARMS, m::USE_B_BEFORE_NAME.as_bytes()));
                        }
                        k = true;
                    }
                    b'h' => {
                        helper_help(z, "zipnote");
                        return Err(Exit { code: ZE_OK });
                    }
                    b'l' | b'L' => {
                        helper_license(z, "zipnote");
                        return Err(Exit { code: ZE_OK });
                    }
                    b'q' => z.o.noisy = false,
                    b'v' => {
                        helper_version(z, "zipnote");
                        return Err(Exit { code: ZE_OK });
                    }
                    b'w' => o.write = true,
                    _ => return Err(z.helper_err(ZE_PARMS, m::UNKNOWN_OPTION.as_bytes())),
                }
            }
        } else if !k {
            if zipfile.is_none() {
                zipfile = Some(ziptyp(arg, false));
            } else {
                return Err(z.helper_err(ZE_PARMS, m::ONLY_ONE_ZIP_FILE.as_bytes()));
            }
        } else {
            o.tempath = Some(arg.clone());
            k = false;
        }
    }
    let Some(zipfile) = zipfile else {
        return Err(z.helper_err(ZE_PARMS, m::NEED_ZIP_FILE.as_bytes()));
    };
    o.zipfile = zipfile;
    Ok(o)
}

/// What `zipsplit`'s command line leaves (zipsplit.c:main).
#[derive(Debug, Clone)]
pub(crate) struct SplitOptions {
    pub(crate) zipfile: Vec<u8>,
    pub(crate) tempath: Option<Vec<u8>>,
    /// `-n`: the capacity of each part (zipsplit.c:DEFSIZ, 36000).
    pub(crate) capacity: u64,
    /// `-r`: room to leave on the first disk.
    pub(crate) room: i64,
    /// `-t`
    pub(crate) report_only: bool,
    /// `-i`
    pub(crate) index: bool,
    /// `-p`
    pub(crate) pause: bool,
    /// `-s`
    pub(crate) simple: bool,
}

/// C's `atol`: leading blanks, a sign, digits (clamped like `strtol`).
fn atol(s: &[u8]) -> i64 {
    let mut p = 0;
    while p < s.len() && is_space(s[p]) {
        p += 1;
    }
    let neg = s.get(p) == Some(&b'-');
    if matches!(s.get(p), Some(b'-' | b'+')) {
        p += 1;
    }
    let mut v: i64 = 0;
    while p < s.len() && s[p].is_ascii_digit() {
        let d = i64::from(s[p] - b'0');
        v = match v.checked_mul(10).and_then(|v| v.checked_add(d)) {
            Some(v) => v,
            None => return if neg { i64::MIN } else { i64::MAX },
        };
        p += 1;
    }
    if neg { -v } else { v }
}

/// zipsplit.c:main, through the arguments: its own loop over `argv`.
// port: zipsplit.c:main
pub(crate) fn parse_split(z: &mut Zr, rest: &[Vec<u8>]) -> Result<SplitOptions, Exit> {
    // If no args, show help
    if rest.is_empty() {
        helper_help(z, "zipsplit");
        return Err(Exit { code: ZE_OK });
    }
    // Informational messages are written to stdout.
    z.mesg_err = false;
    let mut o = SplitOptions {
        zipfile: Vec::new(),
        tempath: None,
        capacity: 36000,
        room: 0,
        report_only: false,
        index: false,
        pause: false,
        simple: false,
    };
    let mut zipfile: Option<Vec<u8>> = None;
    let mut k = 0u8;
    for arg in rest {
        if arg.first() == Some(&b'-') {
            if arg.len() == 1 {
                return Err(z.helper_err(ZE_PARMS, m::ZIP_FILE_STDIN.as_bytes()));
            }
            for &c in &arg[1..] {
                match c {
                    // b, n and r take the next argument
                    b'b' | b'n' | b'r' => {
                        if k != 0 {
                            return Err(z.helper_err(ZE_PARMS, m::OPTIONS_SEPARATE.as_bytes()));
                        }
                        k = match c {
                            b'b' => 1,
                            b'n' => 2,
                            _ => 3,
                        };
                    }
                    b'h' => {
                        helper_help(z, "zipsplit");
                        return Err(Exit { code: ZE_OK });
                    }
                    b'i' => o.index = true,
                    b'l' | b'L' => {
                        helper_license(z, "zipsplit");
                        return Err(Exit { code: ZE_OK });
                    }
                    b'p' => o.pause = true,
                    b'q' => z.o.noisy = false,
                    b's' => o.simple = true,
                    b't' => o.report_only = true,
                    b'v' => {
                        helper_version(z, "zipsplit");
                        return Err(Exit { code: ZE_OK });
                    }
                    _ => return Err(z.helper_err(ZE_PARMS, m::USE_H_FOR_HELP.as_bytes())),
                }
            }
        } else {
            match k {
                0 => {
                    if zipfile.is_none() {
                        zipfile = Some(ziptyp(arg, false));
                    } else {
                        return Err(z.helper_err(ZE_PARMS, m::ONLY_ONE_ZIP_FILE.as_bytes()));
                    }
                }
                1 => {
                    o.tempath = Some(arg.clone());
                    k = 0;
                }
                2 => {
                    // 100 is the smallest zip file
                    o.capacity = atol(arg) as u64;
                    if o.capacity < 100 {
                        return Err(z.helper_err(ZE_PARMS, m::INVALID_SIZE.as_bytes()));
                    }
                    k = 0;
                }
                _ => {
                    o.room = atol(arg);
                    k = 0;
                }
            }
        }
    }
    let Some(zipfile) = zipfile else {
        return Err(z.helper_err(ZE_PARMS, m::NEED_ZIP_FILE.as_bytes()));
    };
    o.zipfile = zipfile;
    Ok(o)
}

#[cfg(test)]
mod tests;
