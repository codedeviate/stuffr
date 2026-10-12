//! `list.c` (`--list`: the plain table, `-v`'s and `-vv`'s reports and the
//! `--robot` forms, with the totals after several files) and util.c's
//! number formatting, from XZ Utils 5.8.4 (0BSD, `LICENSE-xz`).
//!
//! The Indexes and Block Headers are read by `index.rs`, this port's own
//! pure-Rust decoder, so listing is the same on both tiers. "Memory
//! needed" is liblzma's decoder memusage for the reference build
//! (`Profile::Reference`, Ruling P5), whichever liblzma this build has.
//!
//! Numbers are printed as the C locale prints them: no thousands
//! separators, and only the C locale's column widths (every string here
//! is ASCII, so tuklib_mbstr_fw pads to the column).

use std::io::Write;

use stuffr::xz_opts::{Bcj, Filter, Lzma, MatchFinder, Mode, Profile, decoder_memusage_with};

use super::args::{Args, FormatChoice, OpMode};
use super::file_io::FilePair;
use super::hardware::round_up_to_mib;
use super::index::{
    self, Block, CHECK_SIZES, Error, FILTER_ARM, FILTER_ARM64, FILTER_ARMTHUMB, FILTER_IA64,
    FILTER_POWERPC, FILTER_RISCV, FILTER_SPARC, FILTER_X86, HeaderFilter, Index,
};
use super::message::{self, Messages, Status, Verbosity, mask_nonprint};
use super::messages::{self as m, printf};
use super::options::str_from_filters_decoder;
use crate::compat::host::Host;

/// `XZ_FILE_INFO_INIT`'s and the totals' starting minimum version, 5.0.0.
const MIN_VERSION: u32 = 50_000_002;

/// list.c's `totals`, and print_info_basic's `headings_displayed`: what
/// list_file keeps across files for list_totals.
#[derive(Debug)]
pub(crate) struct ListTotals {
    files: u64,
    streams: u64,
    blocks: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    stream_padding: u64,
    memusage_max: u64,
    checks: u32,
    min_version: u32,
    all_have_sizes: bool,
    headings_displayed: bool,
}

impl Default for ListTotals {
    fn default() -> Self {
        ListTotals {
            files: 0,
            streams: 0,
            blocks: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            stream_padding: 0,
            memusage_max: 0,
            checks: 0,
            min_version: MIN_VERSION,
            all_have_sizes: true,
            headings_displayed: false,
        }
    }
}

/// list.c's `xz_file_info`.
struct FileInfo {
    idx: Index,
    stream_padding: u64,
    stats: Stats,
}

/// What parse_block_header gathers into `xz_file_info` at `-vv`.
struct Stats {
    memusage_max: u64,
    all_have_sizes: bool,
    min_version: u32,
}

/// list.c's `block_header_info`, with parse_check_value's `check_value`.
struct BlockInfo {
    header_size: u32,
    flags: [u8; 2],
    compressed_size: u64,
    memusage: u64,
    filter_chain: Vec<u8>,
    check_value: Vec<u8>,
}

// ---- util.c ----

/// util.c: uint64_to_str (no thousands separators in the C locale).
fn num(n: u64) -> Vec<u8> {
    n.to_string().into_bytes()
}

/// util.c: uint64_to_nicestr with `NICESTR_B` to `NICESTR_TIB`.
fn nicestr(value: u64, always_also_bytes: bool) -> Vec<u8> {
    message::nicestr(value, message::NICESTR_B, always_also_bytes)
}

// ---- list.c ----

/// `%*s`: `s` right-aligned in `w` columns.
fn right(s: &[u8], w: usize) -> Vec<u8> {
    let mut v = vec![b' '; w.saturating_sub(s.len())];
    v.extend_from_slice(s);
    v
}

/// `%-*s`: `s` left-aligned in `w` columns.
fn left(s: &[u8], w: usize) -> Vec<u8> {
    let mut v = s.to_vec();
    v.resize(w.max(s.len()), b' ');
    v
}

/// The `headings[]` indices.
const H_STREAM: usize = 0;
const H_BLOCK: usize = 1;
const H_BLOCKS: usize = 2;
const H_COMPOFFSET: usize = 3;
const H_UNCOMPOFFSET: usize = 4;
const H_COMPSIZE: usize = 5;
const H_UNCOMPSIZE: usize = 6;
const H_TOTALSIZE: usize = 7;
const H_RATIO: usize = 8;
const H_CHECK: usize = 9;
const H_CHECKVAL: usize = 10;
const H_PADDING: usize = 11;
const H_HEADERSIZE: usize = 12;
const H_HEADERFLAGS: usize = 13;
const H_MEMUSAGE: usize = 14;
const H_FILTERS: usize = 15;

/// The `colon_strs[]` indices.
const C_STREAMS: usize = 0;
const C_BLOCKS: usize = 1;
const C_COMPRESSED: usize = 2;
const C_UNCOMPRESSED: usize = 3;
const C_RATIO: usize = 4;
const C_CHECK: usize = 5;
const C_PADDING: usize = 6;
const C_MEMORY: usize = 7;
const C_SIZES: usize = 8;
const C_FILES: usize = 9;

/// init_headings: a column's width, widened to its heading (and Check's to
/// the widest check name).
fn columns(h: usize) -> usize {
    let (name, min) = m::HEADINGS[h];
    let mut w = min.max(name.len());
    if h == H_CHECK {
        w = m::CHECK_NAMES.iter().map(|n| n.len()).fold(w, usize::max);
    }
    w
}

/// A heading padded to its column (`HEADING_STR`, right-aligned).
fn heading(h: usize) -> Vec<u8> {
    right(m::HEADINGS[h].0.as_bytes(), columns(h))
}

/// init_colon_strs: a colon string padded to the longest
/// (`COLON_STR`, left-aligned).
fn colon(c: usize) -> Vec<u8> {
    let w = m::COLON_STRS.iter().map(|s| s.len()).max().unwrap_or(0);
    left(m::COLON_STRS[c].as_bytes(), w)
}

/// list.c: xz_ver_to_str.
fn xz_ver_to_str(ver: u32) -> Vec<u8> {
    let major = ver / 10_000_000;
    let minor = ver % 10_000_000 / 10_000;
    let patch = ver % 10_000 / 10;
    let stability = match ver % 10 {
        0 => m::VERSION_ALPHA,
        1 => m::VERSION_BETA,
        _ => "",
    };
    let mut out = Vec::new();
    printf(
        &mut out,
        m::VERSION,
        &[
            major.to_string().as_bytes(),
            minor.to_string().as_bytes(),
            patch.to_string().as_bytes(),
            stability.as_bytes(),
        ],
    );
    out
}

/// list.c: get_ratio.
fn ratio(compressed: u64, uncompressed: u64) -> Vec<u8> {
    if uncompressed == 0 {
        return m::NO_VALUE.as_bytes().to_vec();
    }
    let r = compressed as f64 / uncompressed as f64;
    if r > 9.999 {
        return m::NO_VALUE.as_bytes().to_vec();
    }
    format!("{r:.3}").into_bytes()
}

/// list.c: get_check_names: the names of the checks in `checks`, "None"
/// for none.
fn check_names(checks: u32, space_after_comma: bool) -> Vec<u8> {
    let checks = if checks == 0 { 1 } else { checks };
    let sep = if space_after_comma {
        m::CHECK_SEP_SPACE
    } else {
        m::CHECK_SEP
    };
    let mut out = Vec::new();
    for (i, name) in m::CHECK_NAMES.iter().enumerate() {
        if checks & 1 << i != 0 {
            if !out.is_empty() {
                out.extend_from_slice(sep.as_bytes());
            }
            out.extend_from_slice(name.as_bytes());
        }
    }
    out
}

fn check_name(check: u8) -> &'static [u8] {
    m::CHECK_NAMES[usize::from(check)].as_bytes()
}

fn check_size(check: u8) -> u64 {
    u64::from(CHECK_SIZES[usize::from(check)])
}

/// The `--list` reader over a file's input, for `index.rs`.
struct PairSource<'a> {
    pair: &'a mut FilePair,
    msg: &'a mut Messages,
    err: &'a mut dyn Write,
}

impl index::Source for PairSource<'_> {
    fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> Result<(), Error> {
        if !self.pair.seek_src(pos, self.msg, self.err) {
            return Err(Error::Said);
        }
        match self.pair.read(buf, self.msg, self.err) {
            None => Err(Error::Said),
            // The file shrank: lzma_code runs out of input.
            Some(n) if n < buf.len() => Err(Error::Buf),
            Some(_) => Ok(()),
        }
    }
}

/// message.c: message_strm, for the codes the walk ends with.
fn strm(e: Error) -> &'static str {
    match e {
        Error::Format => m::STRM_FORMAT,
        Error::Data => m::STRM_DATA,
        Error::Options => m::STRM_OPTIONS,
        Error::MemLimit { .. } => m::STRM_MEMLIMIT,
        Error::Buf | Error::Said => m::STRM_BUF,
    }
}

/// list.c: parse_indexes. `None` once an error is said.
fn parse_indexes(
    a: &Args,
    pair: &mut FilePair,
    msg: &mut Messages,
    err: &mut dyn Write,
) -> Option<FileInfo> {
    let shown = mask_nonprint(&pair.src_name);
    let size = pair.src_size();
    if size == 0 {
        msg.error(err, m::LIST_EMPTY, &[&shown]);
        return None;
    }
    if size < 2 * index::HEADER_SIZE {
        msg.error(err, m::LIST_TOO_SMALL, &[&shown]);
        return None;
    }
    let memlimit = a.coder.limits.memlimit_get(OpMode::List);
    let result = {
        let mut src = PairSource {
            pair,
            msg: &mut *msg,
            err: &mut *err,
        };
        index::decode(&mut src, size, memlimit)
    };
    match result {
        Ok(idx) => Some(FileInfo {
            stream_padding: idx.stream_padding(),
            idx,
            stats: Stats {
                memusage_max: 0,
                all_have_sizes: true,
                min_version: MIN_VERSION,
            },
        }),
        Err(Error::Said) => None,
        Err(e) => {
            msg.error(err, m::NAME_COLON, &[&shown, strm(e).as_bytes()]);
            if let Error::MemLimit { needed } = e {
                msg.mem_needed(err, Verbosity::Error, needed, memlimit);
            }
            None
        }
    }
}

/// A Block Header's filters as `xz_opts` chains them, for the memusage
/// and the string.
fn chain(filters: &[HeaderFilter]) -> Vec<Filter> {
    filters
        .iter()
        .map(|f| match *f {
            // Only the dictionary size is decoded; the rest is never read
            // by the decoder's memusage or its string.
            HeaderFilter::Lzma2 { dict_size } => Filter::Lzma2(Lzma {
                dict_size,
                lc: 0,
                lp: 0,
                pb: 0,
                mode: Mode::Normal,
                nice_len: 0,
                mf: MatchFinder::Bt4,
                depth: 0,
                preset_dict: None,
            }),
            HeaderFilter::Bcj { id, start } => Filter::Bcj {
                kind: match id {
                    FILTER_X86 => Bcj::X86,
                    FILTER_POWERPC => Bcj::PowerPc,
                    FILTER_IA64 => Bcj::Ia64,
                    FILTER_ARM => Bcj::Arm,
                    FILTER_ARMTHUMB => Bcj::ArmThumb,
                    FILTER_ARM64 => Bcj::Arm64,
                    FILTER_SPARC => Bcj::Sparc,
                    _ => Bcj::RiscV,
                },
                start,
            },
            HeaderFilter::Delta { dist } => Filter::Delta { dist },
        })
        .collect()
}

/// list.c: parse_block_header then parse_check_value (parse_details) for
/// `b`, a Block of a Stream with check `check`. `None` once an error is
/// said.
fn parse_details(
    pair: &mut FilePair,
    b: &Block,
    check: u8,
    xfi: &mut Stats,
    msg: &mut Messages,
    err: &mut dyn Write,
) -> Option<BlockInfo> {
    let shown = mask_nonprint(&pair.src_name);
    let data_error = |msg: &mut Messages, err: &mut dyn Write| {
        msg.error(err, m::NAME_COLON, &[&shown, m::STRM_DATA.as_bytes()]);
        None
    };
    // The whole Block Header in one read, not past the Check field (the
    // C code's subtraction wraps, then the minimum takes 1024).
    let size = b.total_size.wrapping_sub(check_size(check)).min(1024) as usize;
    let mut buf = vec![0u8; size];
    if !pair.pread(&mut buf, b.compressed_file_offset, msg, err) {
        return None;
    }
    // A Total Size equal to the check's size leaves nothing to read: the
    // C code tests an uninitialised byte there (undefined behaviour, not
    // reproduced; Ruling P14). xz 5.8.4 is observed to say the data is
    // corrupt, as an Index Indicator here would.
    if buf.first().is_none_or(|&b| b == 0) {
        return data_error(msg, err);
    }
    let header_size = (usize::from(buf[0]) + 1) * 4;
    if header_size > size {
        return data_error(msg, err);
    }
    let header = match index::block_header_decode(&buf[..header_size], check) {
        Ok(h) => h,
        Err(Error::Options) => {
            msg.error(err, m::NAME_COLON, &[&shown, m::STRM_OPTIONS.as_bytes()]);
            return None;
        }
        Err(_) => return data_error(msg, err),
    };
    let flags = [
        if header.compressed_size.is_some() {
            b'c'
        } else {
            b'-'
        },
        if header.uncompressed_size.is_some() {
            b'u'
        } else {
            b'-'
        },
    ];
    xfi.all_have_sizes &= header.compressed_size.is_some() && header.uncompressed_size.is_some();
    // lzma_block_compressed_size, then the Uncompressed Size if present.
    let container = u64::from(header.header_size) + check_size(check);
    if b.unpadded_size <= container {
        return data_error(msg, err);
    }
    let compressed_size = b.unpadded_size - container;
    if header.compressed_size.is_some_and(|c| c != compressed_size)
        || header
            .uncompressed_size
            .is_some_and(|u| u != b.uncompressed_size)
    {
        return data_error(msg, err);
    }
    let filters = chain(&header.filters);
    // lzma_raw_decoder_memusage: UINT64_MAX for a chain it refuses.
    let memusage = decoder_memusage_with(Profile::Reference, &filters).unwrap_or(u64::MAX);
    xfi.memusage_max = xfi.memusage_max.max(memusage);
    let has = |id: u64| {
        header
            .filters
            .iter()
            .any(|f| matches!(*f, HeaderFilter::Bcj { id: i, .. } if i == id))
    };
    if xfi.min_version < 50_060_002 && has(FILTER_RISCV) {
        xfi.min_version = 50_060_002;
    }
    if xfi.min_version < 50_040_002 && has(FILTER_ARM64) {
        xfi.min_version = 50_040_002;
    }
    if xfi.min_version < 50_000_022
        && matches!(header.filters.last(), Some(HeaderFilter::Lzma2 { .. }))
        && b.uncompressed_size == 0
    {
        xfi.min_version = 50_000_022;
    }
    let filter_chain = str_from_filters_decoder(&filters);
    let check_value = parse_check_value(pair, b, check, msg, err)?;
    Some(BlockInfo {
        header_size: header.header_size,
        flags,
        compressed_size,
        memusage,
        filter_chain,
        check_value,
    })
}

/// list.c: parse_check_value: the Check field in hexadecimal, a 4- or
/// 8-byte one as a little-endian integer.
fn parse_check_value(
    pair: &mut FilePair,
    b: &Block,
    check: u8,
    msg: &mut Messages,
    err: &mut dyn Write,
) -> Option<Vec<u8>> {
    if check == 0 {
        return Some(m::NO_VALUE.as_bytes().to_vec());
    }
    let size = check_size(check) as usize;
    let mut buf = vec![0u8; size];
    let at = b.compressed_file_offset + b.total_size - size as u64;
    if !pair.pread(&mut buf, at, msg, err) {
        return None;
    }
    let hex = match size {
        4 => format!(
            "{:08x}",
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
        ),
        8 => {
            let mut w = [0u8; 8];
            w.copy_from_slice(&buf);
            format!("{:016x}", u64::from_le_bytes(w))
        }
        _ => buf.iter().map(|x| format!("{x:02x}")).collect(),
    };
    Some(hex.into_bytes())
}

/// list.c: print_info_basic.
fn print_info_basic(
    xfi: &FileInfo,
    name: &[u8],
    totals: &mut ListTotals,
    out: &mut dyn Write,
) -> bool {
    if !totals.headings_displayed {
        totals.headings_displayed = true;
        printf(out, m::BASIC_HEADINGS, &[]);
    }
    let idx = &xfi.idx;
    printf(
        out,
        m::BASIC_ROW,
        &[
            &right(&num(idx.stream_count()), 5),
            &right(&num(idx.block_count()), 7),
            &right(&nicestr(idx.file_size(), false), 11),
            &right(&nicestr(idx.uncompressed_size(), false), 11),
            &right(&ratio(idx.file_size(), idx.uncompressed_size()), 5),
            &left(&check_names(idx.checks(), false), 7),
            &mask_nonprint(name),
        ],
    );
    false
}

/// list.c: print_adv_helper.
fn print_adv_helper(
    out: &mut dyn Write,
    streams: u64,
    blocks: u64,
    compressed: u64,
    uncompressed: u64,
    checks: u32,
    padding: u64,
) {
    let rows: [(usize, Vec<u8>); 7] = [
        (C_STREAMS, num(streams)),
        (C_BLOCKS, num(blocks)),
        (C_COMPRESSED, nicestr(compressed, true)),
        (C_UNCOMPRESSED, nicestr(uncompressed, true)),
        (C_RATIO, ratio(compressed, uncompressed)),
        (C_CHECK, check_names(checks, true)),
        (C_PADDING, nicestr(padding, true)),
    ];
    for (c, v) in rows {
        printf(out, m::ADV_ROW, &[&colon(c), &v]);
    }
}

/// The `-vv` summary lines of print_info_adv and print_totals_adv.
fn print_adv_debug(out: &mut dyn Write, memusage_max: u64, all_have_sizes: bool, version: u32) {
    printf(
        out,
        m::ADV_ROW_MIB,
        &[&colon(C_MEMORY), &num(round_up_to_mib(memusage_max))],
    );
    let sizes = if all_have_sizes { m::YES } else { m::NO };
    printf(out, m::ADV_ROW, &[&colon(C_SIZES), sizes.as_bytes()]);
    printf(out, m::ADV_MIN_VERSION, &[&xz_ver_to_str(version)]);
}

/// list.c: print_info_adv. True when a Block Header fails (said).
fn print_info_adv(
    xfi: &mut FileInfo,
    pair: &mut FilePair,
    msg: &mut Messages,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> bool {
    let FileInfo {
        idx,
        stream_padding,
        stats,
    } = xfi;
    print_adv_helper(
        out,
        idx.stream_count(),
        idx.block_count(),
        idx.file_size(),
        idx.uncompressed_size(),
        idx.checks(),
        *stream_padding,
    );
    printf(
        out,
        m::ADV_STREAMS_HEADINGS,
        &[
            m::COLON_STRS[C_STREAMS].as_bytes(),
            &heading(H_STREAM),
            &heading(H_BLOCKS),
            &heading(H_COMPOFFSET),
            &heading(H_UNCOMPOFFSET),
            &heading(H_COMPSIZE),
            &heading(H_UNCOMPSIZE),
            &heading(H_RATIO),
            &left(m::HEADINGS[H_CHECK].0.as_bytes(), columns(H_CHECK)),
            &heading(H_PADDING),
        ],
    );
    let mut check_max = 0;
    for s in &idx.streams {
        printf(
            out,
            m::ADV_STREAM_ROW,
            &[
                &right(&num(s.number), columns(H_STREAM)),
                &right(&num(s.block_count()), columns(H_BLOCKS)),
                &right(&num(s.compressed_offset), columns(H_COMPOFFSET)),
                &right(&num(s.uncompressed_offset), columns(H_UNCOMPOFFSET)),
                &right(&num(s.compressed_size()), columns(H_COMPSIZE)),
                &right(&num(s.uncompressed_size()), columns(H_UNCOMPSIZE)),
                &right(
                    &ratio(s.compressed_size(), s.uncompressed_size()),
                    columns(H_RATIO),
                ),
                &left(check_name(s.check), columns(H_CHECK)),
                &right(&num(s.padding), columns(H_PADDING)),
            ],
        );
        check_max = check_max.max(check_size(s.check) as usize);
    }
    let detailed = msg.verbosity >= Verbosity::Debug;
    if idx.block_count() > 0 {
        let checkval_width = columns(H_CHECKVAL).max(2 * check_max);
        let check_width = if detailed { columns(H_CHECK) } else { 1 };
        printf(
            out,
            m::ADV_BLOCKS_HEADINGS,
            &[
                m::COLON_STRS[C_BLOCKS].as_bytes(),
                &heading(H_STREAM),
                &heading(H_BLOCK),
                &heading(H_COMPOFFSET),
                &heading(H_UNCOMPOFFSET),
                &heading(H_TOTALSIZE),
                &heading(H_UNCOMPSIZE),
                &heading(H_RATIO),
                &left(m::HEADINGS[H_CHECK].0.as_bytes(), check_width),
            ],
        );
        if detailed {
            printf(
                out,
                m::ADV_BLOCKS_HEADINGS_DEBUG,
                &[
                    &left(m::HEADINGS[H_CHECKVAL].0.as_bytes(), checkval_width),
                    &heading(H_HEADERSIZE),
                    &left(
                        m::HEADINGS[H_HEADERFLAGS].0.as_bytes(),
                        columns(H_HEADERFLAGS),
                    ),
                    &heading(H_COMPSIZE),
                    &heading(H_MEMUSAGE),
                    m::HEADINGS[H_FILTERS].0.as_bytes(),
                ],
            );
        }
        printf(out, m::NEWLINE, &[]);
        for b in idx.blocks() {
            let s = &idx.streams[b.stream];
            let check = s.check;
            let bhi = if detailed {
                match parse_details(pair, &b, check, stats, msg, err) {
                    Some(bhi) => Some(bhi),
                    None => return true,
                }
            } else {
                None
            };
            printf(
                out,
                m::ADV_BLOCK_ROW,
                &[
                    &right(&num(s.number), columns(H_STREAM)),
                    &right(&num(b.number_in_stream), columns(H_BLOCK)),
                    &right(&num(b.compressed_file_offset), columns(H_COMPOFFSET)),
                    &right(&num(b.uncompressed_file_offset), columns(H_UNCOMPOFFSET)),
                    &right(&num(b.total_size), columns(H_TOTALSIZE)),
                    &right(&num(b.uncompressed_size), columns(H_UNCOMPSIZE)),
                    &right(&ratio(b.total_size, b.uncompressed_size), columns(H_RATIO)),
                    &left(check_name(s.check), check_width),
                ],
            );
            if let Some(bhi) = bhi {
                // `unpadded_size - header_size - check size`, which
                // parse_details has already checked is positive.
                let compressed = bhi.compressed_size;
                printf(
                    out,
                    m::ADV_BLOCK_ROW_DEBUG,
                    &[
                        &left(&bhi.check_value, checkval_width),
                        &right(&num(u64::from(bhi.header_size)), columns(H_HEADERSIZE)),
                        &left(&bhi.flags, columns(H_HEADERFLAGS)),
                        &right(&num(compressed), columns(H_COMPSIZE)),
                        &right(&num(round_up_to_mib(bhi.memusage)), columns(H_MEMUSAGE) - 4),
                        &bhi.filter_chain,
                    ],
                );
            }
            printf(out, m::NEWLINE, &[]);
        }
    }
    if detailed {
        print_adv_debug(
            out,
            stats.memusage_max,
            stats.all_have_sizes,
            stats.min_version,
        );
    }
    false
}

/// list.c: print_info_robot. True when a Block Header fails (said).
fn print_info_robot(
    xfi: &mut FileInfo,
    pair: &mut FilePair,
    msg: &mut Messages,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> bool {
    let FileInfo {
        idx,
        stream_padding,
        stats,
    } = xfi;
    printf(out, m::ROBOT_NAME, &[&mask_nonprint(&pair.src_name)]);
    printf(
        out,
        m::ROBOT_FILE,
        &[
            &num(idx.stream_count()),
            &num(idx.block_count()),
            &num(idx.file_size()),
            &num(idx.uncompressed_size()),
            &ratio(idx.file_size(), idx.uncompressed_size()),
            &check_names(idx.checks(), false),
            &num(*stream_padding),
        ],
    );
    let debug = msg.verbosity >= Verbosity::Debug;
    if msg.verbosity >= Verbosity::Verbose {
        for s in &idx.streams {
            printf(
                out,
                m::ROBOT_STREAM,
                &[
                    &num(s.number),
                    &num(s.block_count()),
                    &num(s.compressed_offset),
                    &num(s.uncompressed_offset),
                    &num(s.compressed_size()),
                    &num(s.uncompressed_size()),
                    &ratio(s.compressed_size(), s.uncompressed_size()),
                    check_name(s.check),
                    &num(s.padding),
                ],
            );
        }
        for b in idx.blocks() {
            let s = &idx.streams[b.stream];
            let check = s.check;
            let bhi = if debug {
                match parse_details(pair, &b, check, stats, msg, err) {
                    Some(bhi) => Some(bhi),
                    None => return true,
                }
            } else {
                None
            };
            printf(
                out,
                m::ROBOT_BLOCK,
                &[
                    &num(s.number),
                    &num(b.number_in_stream),
                    &num(b.number_in_file),
                    &num(b.compressed_file_offset),
                    &num(b.uncompressed_file_offset),
                    &num(b.total_size),
                    &num(b.uncompressed_size),
                    &ratio(b.total_size, b.uncompressed_size),
                    check_name(s.check),
                ],
            );
            if let Some(bhi) = bhi {
                printf(
                    out,
                    m::ROBOT_BLOCK_DEBUG,
                    &[
                        &bhi.check_value,
                        &num(u64::from(bhi.header_size)),
                        &bhi.flags,
                        &num(bhi.compressed_size),
                        &num(bhi.memusage),
                        &bhi.filter_chain,
                    ],
                );
            }
            printf(out, m::NEWLINE, &[]);
        }
    }
    if debug {
        let sizes = if stats.all_have_sizes {
            m::ROBOT_YES
        } else {
            m::ROBOT_NO
        };
        printf(
            out,
            m::ROBOT_SUMMARY,
            &[
                &num(stats.memusage_max),
                sizes.as_bytes(),
                &num(u64::from(stats.min_version)),
            ],
        );
    }
    false
}

/// list.c: update_totals. `Err` is message_fatal's exit code.
fn update_totals(
    totals: &mut ListTotals,
    xfi: &FileInfo,
    msg: &Messages,
    err: &mut dyn Write,
) -> Result<(), u8> {
    let idx = &xfi.idx;
    let (streams, blocks) = (idx.stream_count(), idx.block_count());
    let (compressed, uncompressed) = (idx.file_size(), idx.uncompressed_size());
    if totals.files == u64::MAX
        || u64::MAX - totals.streams < streams
        || u64::MAX - totals.blocks < blocks
        || u64::MAX - totals.compressed_size < compressed
        || u64::MAX - totals.uncompressed_size < uncompressed
        || u64::MAX - totals.stream_padding < xfi.stream_padding
    {
        return Err(msg.fatal(err, m::LIST_TOTALS_TOO_LARGE, &[]));
    }
    totals.files += 1;
    totals.streams += streams;
    totals.blocks += blocks;
    totals.compressed_size += compressed;
    totals.uncompressed_size += uncompressed;
    totals.stream_padding += xfi.stream_padding;
    totals.checks |= idx.checks();
    totals.memusage_max = totals.memusage_max.max(xfi.stats.memusage_max);
    totals.min_version = totals.min_version.max(xfi.stats.min_version);
    totals.all_have_sizes &= xfi.stats.all_have_sizes;
    Ok(())
}

/// list.c: list_file, for one input (`None`: standard input). `Err` is
/// the exit code of a run that ends here: a format other than `.xz`, or
/// totals that overflow.
pub(crate) fn list_file(
    a: &Args,
    name: Option<&[u8]>,
    host: &mut Host,
    msg: &mut Messages,
    out: &mut dyn Write,
    err: &mut dyn Write,
    totals: &mut ListTotals,
) -> Result<(), u8> {
    if !matches!(a.format, FormatChoice::Xz | FormatChoice::Auto) {
        // message() twice, then tuklib_exit(E_ERROR, E_ERROR, false).
        msg.message(err, Verbosity::Error, m::LIST_XZ_ONLY, &[]);
        if a.format == FormatChoice::Lzma {
            msg.message(err, Verbosity::Error, m::LIST_LZMAINFO, &[]);
        }
        return Err(Status::Error as u8);
    }
    msg.filename(out, name);
    let Some(name) = name else {
        msg.error(err, m::LIST_STDIN, &[]);
        return Ok(());
    };
    let Some(mut pair) = FilePair::open_src_for_list(a, name, host, msg, err) else {
        return Ok(());
    };
    let mut result = Ok(());
    if let Some(mut xfi) = parse_indexes(a, &mut pair, msg, err) {
        let fail = if a.robot {
            print_info_robot(&mut xfi, &mut pair, msg, out, err)
        } else if msg.verbosity <= Verbosity::Warning {
            print_info_basic(&xfi, name, totals, out)
        } else {
            print_info_adv(&mut xfi, &mut pair, msg, out, err)
        };
        if !fail {
            result = update_totals(totals, &xfi, msg, err);
        }
    }
    // io_close(pair, false): the input is closed, nothing else. Standard
    // output goes out a file at a time, much as a terminal's lines would.
    drop(pair);
    let _ = out.flush();
    result
}

/// list.c: list_totals: under `--robot` always, else only after more than
/// one file.
pub(crate) fn list_totals(a: &Args, msg: &Messages, totals: &ListTotals, out: &mut dyn Write) {
    let t = totals;
    if a.robot {
        printf(
            out,
            m::ROBOT_TOTALS,
            &[
                &num(t.streams),
                &num(t.blocks),
                &num(t.compressed_size),
                &num(t.uncompressed_size),
                &ratio(t.compressed_size, t.uncompressed_size),
                &check_names(t.checks, false),
                &num(t.stream_padding),
                &num(t.files),
            ],
        );
        if msg.verbosity >= Verbosity::Debug {
            let sizes = if t.all_have_sizes {
                m::ROBOT_YES
            } else {
                m::ROBOT_NO
            };
            printf(
                out,
                m::ROBOT_TOTALS_DEBUG,
                &[
                    &num(t.memusage_max),
                    sizes.as_bytes(),
                    &num(u64::from(t.min_version)),
                ],
            );
        }
        printf(out, m::NEWLINE, &[]);
    } else if t.files > 1 {
        if msg.verbosity <= Verbosity::Warning {
            printf(out, m::BASIC_TOTALS_LINE, &[]);
            printf(
                out,
                m::BASIC_TOTALS,
                &[
                    &right(&num(t.streams), 5),
                    &right(&num(t.blocks), 7),
                    &right(&nicestr(t.compressed_size, false), 11),
                    &right(&nicestr(t.uncompressed_size, false), 11),
                    &right(&ratio(t.compressed_size, t.uncompressed_size), 5),
                    &left(&check_names(t.checks, false), 7),
                    &num(t.files),
                ],
            );
        } else {
            printf(out, m::ADV_TOTALS, &[]);
            printf(out, m::ADV_ROW, &[&colon(C_FILES), &num(t.files)]);
            print_adv_helper(
                out,
                t.streams,
                t.blocks,
                t.compressed_size,
                t.uncompressed_size,
                t.checks,
                t.stream_padding,
            );
            if msg.verbosity >= Verbosity::Debug {
                print_adv_debug(out, t.memusage_max, t.all_have_sizes, t.min_version);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: Vec<u8>) -> String {
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn nicestr_scales_as_util_c_does() {
        assert_eq!(s(nicestr(0, true)), "0 B");
        assert_eq!(s(nicestr(9999, true)), "9999 B");
        assert_eq!(s(nicestr(10000, false)), "9.8 KiB");
        assert_eq!(s(nicestr(10000, true)), "9.8 KiB (10000 B)");
        assert_eq!(s(nicestr(200_000, false)), "195.3 KiB");
        // Ties round to even, as glibc's and macOS's printf do.
        assert_eq!(s(nicestr(10496, false)), "10.2 KiB");
        assert_eq!(s(nicestr(1 << 50, false)), "1024.0 TiB");
        assert_eq!(s(nicestr(u64::MAX, false)), "16777216.0 TiB");
    }

    #[test]
    fn ratios_and_versions() {
        assert_eq!(s(ratio(1, 0)), "---");
        assert_eq!(s(ratio(10000, 1000)), "---");
        assert_eq!(s(ratio(9999, 1000)), "9.999");
        assert_eq!(s(ratio(1, 16)), "0.062");
        assert_eq!(s(xz_ver_to_str(50_000_002)), "5.0.0");
        assert_eq!(s(xz_ver_to_str(50_060_002)), "5.6.0");
        assert_eq!(s(xz_ver_to_str(50_000_022)), "5.0.2");
        assert_eq!(s(xz_ver_to_str(50_080_041)), "5.8.4beta");
        assert_eq!(s(xz_ver_to_str(50_080_040)), "5.8.4alpha");
    }

    #[test]
    fn check_names_and_columns() {
        assert_eq!(s(check_names(0, false)), "None");
        assert_eq!(s(check_names(1 << 4 | 1 << 10, false)), "CRC64,SHA-256");
        assert_eq!(s(check_names(1 << 1 | 1 << 15, true)), "CRC32, Unknown-15");
        assert_eq!(columns(H_CHECK), 10);
        assert_eq!(columns(H_CHECKVAL), 8);
        assert_eq!(columns(H_HEADERSIZE), 6);
        assert_eq!(columns(H_HEADERFLAGS), 5);
        assert_eq!(columns(H_MEMUSAGE), 11);
        assert_eq!(s(colon(C_FILES)), "Number of files:  ");
        assert_eq!(m::BASIC_TOTALS_LINE.len(), 80);
    }
}
