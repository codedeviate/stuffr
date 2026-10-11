//! Filter options: `options.c` (`--lzma1=`, `--lzma2=`, the BCJ filters'
//! `=OPTS`, `--delta=`) and the liblzma filter-string syntax of
//! `--filters=` and `--filters1=`..`--filters9=`
//! (`string_conversion.c`'s `lzma_str_to_filters`), from XZ Utils 5.8.4
//! (0BSD, `LICENSE-xz`).
//!
//! The filter-string parser is liblzma's, ported rather than called, so
//! both tiers parse the same way and the pure tier needs no liblzma. Only
//! the filters this liblzma build knows are in the name table (no
//! `lzma1ext`), and only the encoder-side uses are needed: the strings it
//! returns are the ones `xz` prints after "Error in --filters=FILTERS
//! option:", with the error position under them.

use std::io::Write;

use stuffr::xz_opts::{Bcj, Filter, Lzma, MatchFinder, Mode};

use super::args::str_to_uint64;
use super::message::{Messages, mask_nonprint};
use super::messages as m;

/// `LZMA_PRESET_DEFAULT`.
pub(crate) const PRESET_DEFAULT: u32 = 6;

/// The options of `lzma_lzma_preset(PRESET_DEFAULT)`.
fn default_lzma() -> Lzma {
    Lzma::preset(PRESET_DEFAULT, false).expect("6 is a preset")
}

// ---- options.c ----

/// What an options.c option's value is.
enum Value {
    /// One of these names, mapped to an id.
    Map(&'static [(&'static str, u32)]),
    /// A string the setter parses itself (`preset=`).
    Special,
    /// An integer in `[min, max]`, through `str_to_uint64`.
    Range(u64, u64),
}

/// parse_options' setter: the option's index, its integer, the value as
/// typed and the error stream.
type Setter<'a> = dyn FnMut(usize, u64, &[u8], &mut dyn Write) -> Result<(), u8> + 'a;

/// options.c: parse_options. `str` is the whole option string (`None` and
/// empty both mean no options); `set` gets each option's index in `opts`,
/// its integer, the value as typed and the error stream, and may fail
/// with an exit code.
fn parse_options(
    str: Option<&[u8]>,
    opts: &[(&str, Value)],
    set: &mut Setter,
    msg: &Messages,
    err: &mut dyn Write,
) -> Result<(), u8> {
    let Some(str) = str.filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let mut rest = str;
    while !rest.is_empty() {
        if rest[0] == b',' {
            rest = &rest[1..];
            continue;
        }
        let (item, next) = match rest.iter().position(|&b| b == b',') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        let (name, value) = match item.iter().position(|&b| b == b'=') {
            Some(i) => (&item[..i], Some(&item[i + 1..])),
            None => (item, None),
        };
        let Some(value) = value.filter(|v| !v.is_empty()) else {
            return Err(msg.fatal(
                err,
                m::NAME_AND_REASON,
                &[&mask_nonprint(str), m::NAME_VALUE_PAIRS.as_bytes()],
            ));
        };
        let Some(i) = opts.iter().position(|(n, _)| n.as_bytes() == name) else {
            return Err(msg.fatal(err, m::INVALID_OPTION_NAME, &[&mask_nonprint(name)]));
        };
        match &opts[i].1 {
            Value::Map(map) => {
                let Some(&(_, id)) = map.iter().find(|(n, _)| n.as_bytes() == value) else {
                    return Err(msg.fatal(
                        err,
                        m::NAME_AND_REASON,
                        &[&mask_nonprint(value), m::INVALID_OPTION_VALUE.as_bytes()],
                    ));
                };
                set(i, u64::from(id), value, err)?;
            }
            Value::Special => set(i, 0, value, err)?,
            &Value::Range(min, max) => {
                let v = str_to_uint64(opts[i].0, value, min, max, msg, err)?;
                set(i, v, value, err)?;
            }
        }
        match next {
            Some(n) => rest = n,
            None => break,
        }
    }
    Ok(())
}

/// options.c: options_delta (`--delta[=OPTS]`).
pub(crate) fn options_delta(
    str: Option<&[u8]>,
    msg: &Messages,
    err: &mut dyn Write,
) -> Result<Filter, u8> {
    let opts = [("dist", Value::Range(1, 256))];
    let mut dist = 1;
    parse_options(
        str,
        &opts,
        &mut |_, v, _, _| {
            dist = v as u32;
            Ok(())
        },
        msg,
        err,
    )?;
    Ok(Filter::Delta { dist })
}

/// options.c: options_bcj (`--x86[=OPTS]` and the other BCJ filters).
pub(crate) fn options_bcj(
    kind: Bcj,
    str: Option<&[u8]>,
    msg: &Messages,
    err: &mut dyn Write,
) -> Result<Filter, u8> {
    let opts = [("start", Value::Range(0, u64::from(u32::MAX)))];
    let mut start = 0;
    parse_options(
        str,
        &opts,
        &mut |_, v, _, _| {
            start = v as u32;
            Ok(())
        },
        msg,
        err,
    )?;
    Ok(Filter::Bcj { kind, start })
}

const MODES: &[(&str, u32)] = &[("fast", 1), ("normal", 2)];
const MFS: &[(&str, u32)] = &[
    ("hc3", 0x03),
    ("hc4", 0x04),
    ("bt2", 0x12),
    ("bt3", 0x13),
    ("bt4", 0x14),
];

fn mode_of(id: u64) -> Mode {
    if id == 1 { Mode::Fast } else { Mode::Normal }
}

fn mf_of(id: u64) -> MatchFinder {
    match id {
        0x03 => MatchFinder::Hc3,
        0x04 => MatchFinder::Hc4,
        0x12 => MatchFinder::Bt2,
        0x13 => MatchFinder::Bt3,
        _ => MatchFinder::Bt4,
    }
}

/// options.c: options_lzma (`--lzma1[=OPTS]`, `--lzma2[=OPTS]`), as the
/// filter `lzma1` or not says.
pub(crate) fn options_lzma(
    lzma1: bool,
    str: Option<&[u8]>,
    msg: &Messages,
    err: &mut dyn Write,
) -> Result<Filter, u8> {
    let opts = [
        ("preset", Value::Special),
        ("dict", Value::Range(4096, (1 << 30) + (1 << 29))),
        ("lc", Value::Range(0, 4)),
        ("lp", Value::Range(0, 4)),
        ("pb", Value::Range(0, 4)),
        ("mode", Value::Map(MODES)),
        ("nice", Value::Range(2, 273)),
        ("mf", Value::Map(MFS)),
        ("depth", Value::Range(0, u64::from(u32::MAX))),
    ];
    let mut o = default_lzma();
    parse_options(
        str,
        &opts,
        &mut |key, v, valuestr, err| {
            match key {
                0 => o = lzma_preset_from(valuestr, msg, err)?,
                1 => o.dict_size = v as u32,
                2 => o.lc = v as u32,
                3 => o.lp = v as u32,
                4 => o.pb = v as u32,
                5 => o.mode = mode_of(v),
                6 => o.nice_len = v as u32,
                7 => o.mf = mf_of(v),
                _ => o.depth = v as u32,
            }
            Ok(())
        },
        msg,
        err,
    )?;
    if o.lc + o.lp > 4 {
        return Err(msg.fatal(err, m::LC_LP, &[]));
    }
    Ok(if lzma1 {
        Filter::Lzma1(o)
    } else {
        Filter::Lzma2(o)
    })
}

/// options.c: set_lzma's `preset=` (a digit, optionally `e`).
fn lzma_preset_from(valuestr: &[u8], msg: &Messages, err: &mut dyn Write) -> Result<Lzma, u8> {
    let bad =
        |err: &mut dyn Write| msg.fatal(err, m::UNSUPPORTED_PRESET, &[&mask_nonprint(valuestr)]);
    let Some(&d @ b'0'..=b'9') = valuestr.first() else {
        return Err(bad(err));
    };
    let extreme = match &valuestr[1..] {
        [] => false,
        [b'e'] => true,
        _ => return Err(bad(err)),
    };
    Lzma::preset(u32::from(d - b'0'), extreme).ok_or_else(|| bad(err))
}

// ---- string_conversion.c ----

/// `lzma_str_to_filters`'s failure: the message and the error position.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StrError {
    pub(crate) pos: usize,
    pub(crate) msg: &'static str,
}

/// `NAME_LEN_MAX`.
const NAME_LEN_MAX: usize = 11;

/// A filter string's bytes, with C's terminating NUL past the end.
struct Cursor<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn at(&self, i: usize) -> u8 {
        self.s.get(i).copied().unwrap_or(0)
    }

    fn fail<T>(&self, msg: &'static str) -> Result<T, StrError> {
        Err(StrError { pos: self.pos, msg })
    }
}

/// How an option of the string syntax takes its value.
#[derive(Clone, Copy)]
enum StrValue {
    /// `preset=` (`OPTMAP_TYPE_LZMA_PRESET`).
    Preset,
    /// A name from the map (`OPTMAP_USE_NAME_VALUE_MAP`).
    Map(&'static [(&'static str, u32)]),
    /// An integer in `[min, max]`; `true` allows `KiB`/`MiB`/`GiB`
    /// (`OPTMAP_USE_BYTE_SUFFIX`).
    Range(u32, u32, bool),
}

const LZMA12_OPTMAP: &[(&str, StrValue)] = &[
    ("preset", StrValue::Preset),
    ("dict", StrValue::Range(4096, (1 << 30) + (1 << 29), true)),
    ("lc", StrValue::Range(0, 4, false)),
    ("lp", StrValue::Range(0, 4, false)),
    ("pb", StrValue::Range(0, 4, false)),
    ("mode", StrValue::Map(MODES)),
    ("nice", StrValue::Range(2, 273, false)),
    ("mf", StrValue::Map(MFS)),
    ("depth", StrValue::Range(0, u32::MAX, false)),
];

const BCJ_OPTMAP: &[(&str, StrValue)] = &[("start", StrValue::Range(0, u32::MAX, true))];

const DELTA_OPTMAP: &[(&str, StrValue)] = &[("dist", StrValue::Range(1, 256, false))];

/// What a filter of the name table builds.
#[derive(Clone, Copy)]
enum Kind {
    Lzma1,
    Lzma2,
    Bcj(Bcj),
    Delta,
}

/// string_conversion.c: filter_name_map, in its order.
const FILTER_NAMES: &[(&str, Kind)] = &[
    ("lzma1", Kind::Lzma1),
    ("lzma2", Kind::Lzma2),
    ("x86", Kind::Bcj(Bcj::X86)),
    ("arm", Kind::Bcj(Bcj::Arm)),
    ("armthumb", Kind::Bcj(Bcj::ArmThumb)),
    ("arm64", Kind::Bcj(Bcj::Arm64)),
    ("riscv", Kind::Bcj(Bcj::RiscV)),
    ("powerpc", Kind::Bcj(Bcj::PowerPc)),
    ("ia64", Kind::Bcj(Bcj::Ia64)),
    ("sparc", Kind::Bcj(Bcj::Sparc)),
    ("delta", Kind::Delta),
];

/// string_conversion.c: parse_lzma12_preset, over `c.pos..end`.
fn parse_lzma12_preset(c: &mut Cursor, end: usize) -> Result<Lzma, StrError> {
    let d = c.at(c.pos);
    if !d.is_ascii_digit() {
        return c.fail(m::SC_UNSUPPORTED_PRESET);
    }
    let mut extreme = false;
    c.pos += 1;
    while c.pos < end {
        if c.at(c.pos) != b'e' {
            return c.fail(m::SC_PRESET_FLAG);
        }
        extreme = true;
        c.pos += 1;
    }
    match Lzma::preset(u32::from(d - b'0'), extreme) {
        Some(l) => Ok(l),
        None => c.fail(m::SC_UNSUPPORTED_PRESET),
    }
}

/// An option value's setter target.
enum Target<'a> {
    Lzma(&'a mut Lzma),
    U32(&'a mut u32),
}

/// string_conversion.c: parse_options, over `c.pos..end`.
fn parse_str_options(
    c: &mut Cursor,
    end: usize,
    optmap: &[(&str, StrValue)],
    target: &mut Target,
) -> Result<(), StrError> {
    while c.pos < end && c.at(c.pos) != 0 {
        if c.at(c.pos) == b',' {
            c.pos += 1;
            continue;
        }
        let item_end = (c.pos..end).find(|&i| c.at(i) == b',').unwrap_or(end);
        let eq = (c.pos..item_end).find(|&i| c.at(i) == b'=');
        let Some(eq) = eq.filter(|_| c.at(c.pos) != b'=') else {
            return c.fail(m::SC_PAIRS);
        };
        let name = &c.s[c.pos..eq];
        if name.len() > NAME_LEN_MAX {
            return c.fail(m::SC_UNKNOWN_OPTION);
        }
        let Some(i) = optmap.iter().position(|(n, _)| n.as_bytes() == name) else {
            return c.fail(m::SC_UNKNOWN_OPTION);
        };
        c.pos = eq + 1;
        let value = &c.s[c.pos..item_end];
        if value.is_empty() {
            return c.fail(m::SC_EMPTY_VALUE);
        }
        let v = match optmap[i].1 {
            StrValue::Preset => {
                let preset = parse_lzma12_preset(c, item_end)?;
                if let Target::Lzma(o) = target {
                    **o = preset;
                }
                continue;
            }
            StrValue::Map(map) => {
                if value.len() > NAME_LEN_MAX {
                    return c.fail(m::SC_INVALID_VALUE);
                }
                match map.iter().find(|(n, _)| n.as_bytes() == value) {
                    Some(&(_, id)) => id,
                    None => return c.fail(m::SC_INVALID_VALUE),
                }
            }
            StrValue::Range(min, max, suffixes) => {
                if !c.at(c.pos).is_ascii_digit() {
                    return c.fail(m::SC_NOT_INTEGER);
                }
                let mut p = c.pos;
                let mut v: u32 = 0;
                loop {
                    let Some(nv) = v
                        .checked_mul(10)
                        .and_then(|x| x.checked_add(u32::from(c.at(p) - b'0')))
                    else {
                        return c.fail(m::SC_OUT_OF_RANGE);
                    };
                    v = nv;
                    p += 1;
                    if !(p < item_end && c.at(p).is_ascii_digit()) {
                        break;
                    }
                }
                if p < item_end {
                    let multiplier_start = p;
                    if !suffixes {
                        c.pos = multiplier_start;
                        return c.fail(m::SC_NO_SUFFIX);
                    }
                    let shift = match c.at(p) {
                        b'k' | b'K' => 10,
                        b'm' | b'M' => 20,
                        b'g' | b'G' => 30,
                        _ => {
                            c.pos = multiplier_start;
                            return c.fail(m::SC_BAD_SUFFIX);
                        }
                    };
                    p += 1;
                    if p < item_end && c.at(p) == b'i' {
                        p += 1;
                    }
                    if p < item_end && c.at(p) == b'B' {
                        p += 1;
                    }
                    if p < item_end {
                        c.pos = multiplier_start;
                        return c.fail(m::SC_BAD_SUFFIX);
                    }
                    if v > (u32::MAX >> shift) {
                        return c.fail(m::SC_OUT_OF_RANGE);
                    }
                    v <<= shift;
                }
                if v < min || v > max {
                    return c.fail(m::SC_OUT_OF_RANGE);
                }
                v
            }
        };
        match target {
            Target::Lzma(o) => match i {
                1 => o.dict_size = v,
                2 => o.lc = v,
                3 => o.lp = v,
                4 => o.pb = v,
                5 => o.mode = mode_of(u64::from(v)),
                6 => o.nice_len = v,
                7 => o.mf = mf_of(u64::from(v)),
                _ => o.depth = v,
            },
            Target::U32(x) => **x = v,
        }
        c.pos = item_end;
    }
    Ok(())
}

/// string_conversion.c: parse_filter, over `c.pos..end`.
fn parse_filter(c: &mut Cursor, end: usize, only_xz: bool) -> Result<Filter, StrError> {
    let (name_end, opts_start) = (c.pos..end)
        .find(|&p| matches!(c.at(p), b':' | b'='))
        .map_or((end, end), |p| (p, p + 1));
    let name = &c.s[c.pos..name_end];
    if name.len() > NAME_LEN_MAX {
        return c.fail(m::SC_UNKNOWN_FILTER);
    }
    let Some(&(_, kind)) = FILTER_NAMES.iter().find(|(n, _)| n.as_bytes() == name) else {
        return c.fail(m::SC_UNKNOWN_FILTER);
    };
    // LZMA1's ID is past LZMA_FILTER_RESERVED_START.
    if only_xz && matches!(kind, Kind::Lzma1) {
        return c.fail(m::SC_NOT_IN_XZ);
    }
    c.pos = opts_start;
    Ok(match kind {
        Kind::Lzma1 | Kind::Lzma2 => {
            let mut o = default_lzma();
            parse_str_options(c, end, LZMA12_OPTMAP, &mut Target::Lzma(&mut o))?;
            if o.lc + o.lp > 4 {
                return c.fail(m::SC_LC_LP);
            }
            if matches!(kind, Kind::Lzma1) {
                Filter::Lzma1(o)
            } else {
                Filter::Lzma2(o)
            }
        }
        Kind::Bcj(kind) => {
            let mut start = 0;
            parse_str_options(c, end, BCJ_OPTMAP, &mut Target::U32(&mut start))?;
            Filter::Bcj { kind, start }
        }
        Kind::Delta => {
            let mut dist = 1;
            parse_str_options(c, end, DELTA_OPTMAP, &mut Target::U32(&mut dist))?;
            Filter::Delta { dist }
        }
    })
}

/// filter_common.c: lzma_validate_chain: 1-4 filters, nothing after an
/// LZMA filter, an LZMA filter last, at most three that change the size.
pub(crate) fn chain_is_valid(chain: &[Filter]) -> bool {
    let lz = |f: &Filter| matches!(f, Filter::Lzma1(_) | Filter::Lzma1Ext(_) | Filter::Lzma2(_));
    let Some(last) = chain.last() else {
        return false;
    };
    chain.len() <= 4
        && chain[..chain.len() - 1].iter().all(|f| !lz(f))
        && lz(last)
        && chain.iter().filter(|f| lz(f)).count() <= 3
}

/// string_conversion.c: lzma_str_to_filters with `LZMA_STR_ALL_FILTERS`
/// when `all_filters` (`--filters`, which also serves `--format=raw`) and
/// without (`--filters1`..`--filters9`, `.xz` only).
pub(crate) fn str_to_filters(s: &[u8], all_filters: bool) -> Result<Vec<Filter>, StrError> {
    let mut c = Cursor { s, pos: 0 };
    while c.at(c.pos) == b' ' {
        c.pos += 1;
    }
    if c.at(c.pos) == 0 {
        return c.fail(m::SC_EMPTY);
    }
    let digit = |b: u8| b.is_ascii_digit();
    if digit(c.at(c.pos)) || (c.at(c.pos) == b'-' && digit(c.at(c.pos + 1))) {
        if c.at(c.pos) == b'-' {
            c.pos += 1;
        }
        let end = match (c.pos..s.len()).find(|&i| s[i] == b' ') {
            Some(sp) => {
                if s[sp + 1..].iter().any(|&b| b != b' ') {
                    return c.fail(m::SC_UNSUPPORTED_PRESET);
                }
                sp
            }
            None => s.len(),
        };
        return Ok(vec![Filter::Lzma2(parse_lzma12_preset(&mut c, end)?)]);
    }
    let only_xz = !all_filters;
    let mut chain = Vec::new();
    loop {
        if chain.len() == 4 {
            return c.fail(m::SC_MAX_FILTERS);
        }
        if c.at(c.pos) == b'-' && c.at(c.pos + 1) == b'-' {
            c.pos += 2;
        }
        let mut end = c.pos;
        while c.at(end) != 0 {
            if (c.at(end) == b'-' && c.at(end + 1) == b'-') || c.at(end) == b' ' {
                break;
            }
            end += 1;
        }
        if end == c.pos {
            return c.fail(m::SC_NAME_MISSING);
        }
        chain.push(parse_filter(&mut c, end, only_xz)?);
        while c.at(c.pos) == b' ' {
            c.pos += 1;
        }
        if c.at(c.pos) == 0 {
            break;
        }
    }
    if !chain_is_valid(&chain) {
        return c.fail(m::SC_INVALID_CHAIN);
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run<T>(f: impl FnOnce(&Messages, &mut Vec<u8>) -> Result<T, u8>) -> Result<T, String> {
        let msg = Messages::new(b"xz");
        let mut err = Vec::new();
        f(&msg, &mut err).map_err(|code| {
            assert_eq!(code, 1);
            String::from_utf8(err).unwrap()
        })
    }

    #[test]
    fn lzma_options_parse_as_options_c_does() {
        let f = run(|msg, err| {
            options_lzma(false, Some(b"preset=1e,,dict=64KiB,lc=1,mf=bt2"), msg, err)
        })
        .unwrap();
        let mut want = Lzma::preset(1, true).unwrap();
        want.dict_size = 64 << 10;
        want.lc = 1;
        want.mf = MatchFinder::Bt2;
        assert_eq!(f, Filter::Lzma2(want));
        assert_eq!(
            run(|msg, err| options_lzma(true, None, msg, err)).unwrap(),
            Filter::Lzma1(default_lzma())
        );
        // Recorded from xz 5.8.4 (`xz --lzma2=... -h`).
        for (opts, want) in [
            (
                "x",
                "xz: x: Options must be 'name=value' pairs separated with commas\n",
            ),
            (
                "dict=",
                "xz: dict=: Options must be 'name=value' pairs separated with commas\n",
            ),
            (
                "dict=1",
                "xz: Value of the option 'dict' must be in the range [4096, 1610612736]\n",
            ),
            ("preset=9ee", "xz: Unsupported LZMA1/LZMA2 preset: 9ee\n"),
            ("lc=4,lp=1", "xz: The sum of lc and lp must not exceed 4\n"),
            ("mode=slow", "xz: slow: Invalid option value\n"),
            ("=1", "xz: : Invalid option name\n"),
            ("foo=1", "xz: foo: Invalid option name\n"),
        ] {
            let e =
                run(|msg, err| options_lzma(false, Some(opts.as_bytes()), msg, err)).unwrap_err();
            assert_eq!(e, want, "{opts}");
        }
    }

    #[test]
    fn bcj_and_delta_options() {
        assert_eq!(
            run(|msg, err| options_bcj(Bcj::Arm64, Some(b"start=4096"), msg, err)).unwrap(),
            Filter::Bcj {
                kind: Bcj::Arm64,
                start: 4096
            }
        );
        assert_eq!(
            run(|msg, err| options_delta(Some(b"dist=256"), msg, err)).unwrap(),
            Filter::Delta { dist: 256 }
        );
        assert_eq!(
            run(|msg, err| options_delta(Some(b"dist=0"), msg, err)).unwrap_err(),
            "xz: Value of the option 'dist' must be in the range [1, 256]\n"
        );
    }

    /// The error positions and messages recorded from xz 5.8.4
    /// (`xz --filters=STRING -h`).
    #[test]
    fn filter_strings_fail_where_liblzma_says() {
        for (s, pos, msg) in [
            ("", 0, m::SC_EMPTY),
            ("x86", 3, m::SC_INVALID_CHAIN),
            ("lzma2 x86", 9, m::SC_INVALID_CHAIN),
            ("foo", 0, m::SC_UNKNOWN_FILTER),
            ("lzma2:dict=1", 11, m::SC_OUT_OF_RANGE),
            ("lzma2:dict=1x", 12, m::SC_BAD_SUFFIX),
            ("lzma2:dict=4Kq", 12, m::SC_BAD_SUFFIX),
            ("lzma2:lc=1k", 10, m::SC_NO_SUFFIX),
            ("x86 x86 x86 x86 lzma2", 16, m::SC_MAX_FILTERS),
            ("9x", 1, m::SC_PRESET_FLAG),
            ("9 x", 0, m::SC_UNSUPPORTED_PRESET),
            ("lzma2--x86", 10, m::SC_INVALID_CHAIN),
            ("lzma2:mode=fast,mf=hc9", 19, m::SC_INVALID_VALUE),
            ("lzma2:preset=", 13, m::SC_EMPTY_VALUE),
            ("lzma2:=4", 6, m::SC_PAIRS),
            ("lzma2:dicta=4", 6, m::SC_UNKNOWN_OPTION),
            ("delta:dist=0", 11, m::SC_OUT_OF_RANGE),
            ("x86:start=4294967296", 10, m::SC_OUT_OF_RANGE),
            ("lzma2::", 6, m::SC_PAIRS),
            ("x86 --", 6, m::SC_NAME_MISSING),
            ("abcdefghijklm", 0, m::SC_UNKNOWN_FILTER),
            ("lzma2:dict=99999999999", 11, m::SC_OUT_OF_RANGE),
        ] {
            assert_eq!(
                str_to_filters(s.as_bytes(), true),
                Err(StrError { pos, msg }),
                "{s:?}"
            );
        }
        assert_eq!(
            str_to_filters(" ".repeat(3).as_bytes(), true),
            Err(StrError {
                pos: 3,
                msg: m::SC_EMPTY
            })
        );
        assert_eq!(
            str_to_filters(b"lzma1", false),
            Err(StrError {
                pos: 0,
                msg: m::SC_NOT_IN_XZ
            })
        );
    }

    #[test]
    fn filter_strings_build_chains() {
        let p9e = Lzma::preset(9, true).unwrap();
        assert_eq!(
            str_to_filters(b"-9e", true),
            Ok(vec![Filter::Lzma2(p9e.clone())])
        );
        assert_eq!(str_to_filters(b"9e  ", true), Ok(vec![Filter::Lzma2(p9e)]));
        assert_eq!(
            str_to_filters(b"--delta:dist=4 x86=start=1KiB lzma1=preset=0", true),
            Ok(vec![
                Filter::Delta { dist: 4 },
                Filter::Bcj {
                    kind: Bcj::X86,
                    start: 1024
                },
                Filter::Lzma1(Lzma::preset(0, false).unwrap()),
            ])
        );
        assert_eq!(
            str_to_filters(b"lzma2:", false),
            Ok(vec![Filter::Lzma2(default_lzma())])
        );
    }
}
