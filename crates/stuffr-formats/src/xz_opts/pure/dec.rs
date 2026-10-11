//! The pure tier's [`Decoder`]: liblzma 5.8.4's container decoders
//! (`stream_decoder.c`/`stream_decoder_mt.c`, `block_decoder.c`,
//! `block_header_decoder.c`, `filter_flags_decoder.c`, `index_hash.c`,
//! `alone_decoder.c`, `lzip_decoder.c`) ported over `lzma-rust2`'s LZMA1
//! and LZMA2 decoders and its BCJ and delta filters.

use std::collections::VecDeque;

use lzma_rust2::filter::StreamFilter;
use lzma_rust2::{Action, FilterConfig, FilterType, Lzma2Stream, LzmaStream, Status};

use super::super::check::{self, Running, Sha256, crc32};
use super::super::memusage::{MEMUSAGE_BASE, decoder_memusage, lzma_decoder_memusage_nocheck};
use super::super::{DecodeOptions, Filter, Format, Lzma, MatchFinder, Mode, Progress, XzError};
use super::{FOOTER_MAGIC, HEADER_MAGIC, bcj_aligned, bcj_type, coder_error, limit_of, vli_size};

/// Output scratch per coder call.
const OUT_CHUNK: usize = 64 * 1024;

/// `LZMA_VLI_MAX`.
const VLI_MAX: u64 = u64::MAX / 2;
/// `UNPADDED_SIZE_MIN`/`UNPADDED_SIZE_MAX` (`common/index.h`).
const UNPADDED_SIZE_MIN: u64 = 5;
const UNPADDED_SIZE_MAX: u64 = VLI_MAX & !3;
/// `LZMA_BACKWARD_SIZE_MAX` (`api/lzma/stream_flags.h`).
const BACKWARD_SIZE_MAX: u64 = 1 << 34;
/// `LZMA_FILTER_RESERVED_START` (`api/lzma/filter.h`).
const FILTER_RESERVED_START: u64 = 1 << 62;
/// `.lz`'s magic.
const LZIP_MAGIC: [u8; 4] = *b"LZIP";

/// Copies from `input[*pos..]` into `buf` until it holds `need` bytes;
/// whether it does.
fn fill(buf: &mut Vec<u8>, need: usize, input: &[u8], pos: &mut usize) -> bool {
    let take = need.saturating_sub(buf.len()).min(input.len() - *pos);
    buf.extend_from_slice(&input[*pos..*pos + take]);
    *pos += take;
    buf.len() >= need
}

fn read32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn read64le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// An LZMA [`Lzma`] carrying only what a decoder needs from it.
fn lzma_with(dict_size: u32, lc: u32, lp: u32, pb: u32) -> Lzma {
    Lzma {
        dict_size,
        lc,
        lp,
        pb,
        mode: Mode::Normal,
        nice_len: 64,
        mf: MatchFinder::Bt4,
        depth: 0,
        preset_dict: None,
    }
}

/// One pre-filter of a decoder chain and the bytes it holds back.
struct Pipe {
    f: StreamFilter,
    pending: Vec<u8>,
}

/// Runs `data` through `pipes` (the one nearest the LZ decoder first) into
/// `out`.
fn pipe_out(pipes: &mut [Pipe], data: &[u8], out: &mut Vec<u8>) {
    match pipes.split_first_mut() {
        None => out.extend_from_slice(data),
        Some((p, rest)) => {
            p.pending.extend_from_slice(data);
            let n = p.f.decode(&mut p.pending);
            if rest.is_empty() {
                out.extend_from_slice(&p.pending[..n]);
            } else {
                let settled: Vec<u8> = p.pending[..n].to_vec();
                pipe_out(rest, &settled, out);
            }
            p.pending.drain(..n);
        }
    }
}

/// The end of the data: every filter lets go of what it held back.
fn pipe_end(pipes: &mut [Pipe], out: &mut Vec<u8>) {
    if let Some((p, rest)) = pipes.split_first_mut() {
        p.f.finish();
        let held = std::mem::take(&mut p.pending);
        pipe_out(rest, &held, out);
        pipe_end(rest, out);
    }
}

enum Lz {
    Lzma2(Box<Lzma2Stream>),
    Lzma1(Box<LzmaStream>),
}

/// A raw filter chain's decoder (`lzma_raw_decoder`), also each `.xz`
/// Block's payload.
struct RawDec {
    lz: Lz,
    pipes: Vec<Pipe>,
    tmp: Vec<u8>,
    ended: bool,
    /// After an LZMA1 stream's end: bytes taken in by earlier calls that
    /// follow the stream (`LzmaStream` reads ahead up to 40 bytes).
    leftover: Vec<u8>,
}

impl RawDec {
    /// The decoder for a validated chain.
    fn new(chain: &[Filter]) -> Result<RawDec, XzError> {
        let (last, pre) = chain.split_last().ok_or(XzError::Options)?;
        let lz = match last {
            Filter::Lzma2(l) => {
                if l.preset_dict.is_some() {
                    return Err(XzError::Options);
                }
                Lz::Lzma2(Box::new(Lzma2Stream::new(l.dict_size)))
            }
            Filter::Lzma1(l) | Filter::Lzma1Ext(l) => {
                return RawDec::lzma1(u64::MAX, l, pre, l.preset_dict.as_deref());
            }
            _ => return Err(XzError::Options),
        };
        RawDec::with(lz, pre)
    }

    /// LZMA1 of `size` (`u64::MAX`: unknown, ended by its marker).
    fn lzma1(
        size: u64,
        l: &Lzma,
        pre: &[Filter],
        preset_dict: Option<&[u8]>,
    ) -> Result<RawDec, XzError> {
        let s = LzmaStream::new(
            size,
            l.lc,
            l.lp,
            l.pb,
            l.dict_size.min(lzma_rust2::DICT_SIZE_MAX),
            preset_dict,
        )
        .map_err(|_| XzError::Options)?;
        RawDec::with(Lz::Lzma1(Box::new(s)), pre)
    }

    fn with(lz: Lz, pre: &[Filter]) -> Result<RawDec, XzError> {
        let mut pipes = Vec::new();
        for f in pre.iter().rev() {
            let config = match *f {
                Filter::Delta { dist } => FilterConfig {
                    filter_type: FilterType::Delta,
                    property: dist,
                },
                Filter::Bcj { kind, start } => {
                    if !bcj_aligned(kind, start) {
                        return Err(XzError::Options);
                    }
                    FilterConfig {
                        filter_type: bcj_type(kind),
                        property: start,
                    }
                }
                _ => return Err(XzError::Options),
            };
            pipes.push(Pipe {
                f: StreamFilter::new(&config).map_err(|_| XzError::Options)?,
                pending: Vec::new(),
            });
        }
        Ok(RawDec {
            lz,
            pipes,
            tmp: vec![0; OUT_CHUNK],
            ended: false,
            leftover: Vec::new(),
        })
    }

    /// Decodes from `input` into `out`: the bytes of `input` the stream
    /// used, and whether it ended. `finish` says nothing follows `input`.
    ///
    /// `lzma-rust2` starts a symbol only with 20 bytes in hand, and at the
    /// end decodes what it holds against zero padding, which can let a
    /// stream cut short look whole. So the end is found the way liblzma —
    /// which never reads past its input — finds it: the decoder is handed
    /// 64 more bytes of `0xFF` in place of the end, and a stream that ends
    /// without touching them ended in the input; one that reads them, fails
    /// in them or is still going is the input running out
    /// ([`XzError::BufError`]), and what it made of them is dropped. `.xz`
    /// Blocks never get here: the container finds their end.
    fn run(
        &mut self,
        input: &[u8],
        finish: bool,
        out: &mut Vec<u8>,
    ) -> Result<(usize, bool), XzError> {
        if self.ended {
            return Ok((0, true));
        }
        let mut pos = 0;
        if self.step(input, Action::Run, &mut pos, out)? || !finish {
            return Ok((pos, self.ended));
        }
        let real = out.len();
        let mut spos = 0;
        let ended = self.step(&[0xFF; 64], Action::Run, &mut spos, out);
        if matches!(ended, Ok(true)) && spos == 0 {
            return Ok((pos, true));
        }
        out.truncate(real);
        self.ended = false;
        Err(XzError::BufError)
    }

    /// `process` until the stream ends (`true`) or stalls.
    fn step(
        &mut self,
        input: &[u8],
        action: Action,
        pos: &mut usize,
        out: &mut Vec<u8>,
    ) -> Result<bool, XzError> {
        loop {
            let r = match &mut self.lz {
                Lz::Lzma2(s) => s.process(&input[*pos..], &mut self.tmp, action),
                Lz::Lzma1(s) => s.process(&input[*pos..], &mut self.tmp, action),
            }
            .map_err(|e| coder_error(&e))?;
            *pos += r.bytes_consumed;
            pipe_out(&mut self.pipes, &self.tmp[..r.bytes_produced], out);
            if r.status == Status::StreamEnd {
                pipe_end(&mut self.pipes, out);
                if let Lz::Lzma1(s) = &self.lz {
                    let unused = s.unused_input();
                    let here = unused.len().min(*pos);
                    self.leftover = unused[..unused.len() - here].to_vec();
                    *pos -= here;
                }
                self.ended = true;
                return Ok(true);
            }
            if r.bytes_consumed == 0 && r.bytes_produced == 0 {
                return Ok(false);
            }
        }
    }
}

/// `lzma_index_hash_info`: what a list of Blocks adds up to.
struct HashInfo {
    blocks_size: u64,
    uncompressed_size: u64,
    count: u64,
    index_list_size: u64,
    sha: Sha256,
}

impl HashInfo {
    fn new() -> HashInfo {
        HashInfo {
            blocks_size: 0,
            uncompressed_size: 0,
            count: 0,
            index_list_size: 0,
            sha: Sha256::new(),
        }
    }

    /// `hash_append` (`common/index_hash.c`).
    fn append(&mut self, unpadded: u64, uncompressed: u64) {
        self.blocks_size = self.blocks_size.wrapping_add((unpadded + 3) & !3);
        self.uncompressed_size = self.uncompressed_size.wrapping_add(uncompressed);
        self.index_list_size += vli_size(unpadded) + vli_size(uncompressed);
        self.count += 1;
        let mut sizes = [0u8; 16];
        sizes[..8].copy_from_slice(&unpadded.to_ne_bytes());
        sizes[8..].copy_from_slice(&uncompressed.to_ne_bytes());
        self.sha.update(&sizes);
    }
}

/// `index_size_unpadded` and `index_size` (`common/index.h`).
fn index_size_unpadded(count: u64, list_size: u64) -> u64 {
    1 + vli_size(count) + list_size
}

fn index_size(count: u64, list_size: u64) -> u64 {
    ((index_size_unpadded(count, list_size) + 3) & !3) + 4
}

/// `lzma_vli_decode` with a position (the streaming form): one byte;
/// whether the integer is complete.
fn vli_step(vli: &mut u64, pos: &mut u32, b: u8) -> Result<bool, XzError> {
    if *pos == 0 {
        *vli = 0;
    }
    *vli += u64::from(b & 0x7F) << (*pos * 7);
    *pos += 1;
    if b & 0x80 == 0 {
        if b == 0 && *pos > 1 {
            return Err(XzError::Data);
        }
        return Ok(true);
    }
    if *pos == 9 {
        return Err(XzError::Data);
    }
    Ok(false)
}

/// `lzma_vli_decode` without a position: a whole integer from
/// `buf[*pos..end]`, or `LZMA_DATA_ERROR`.
fn vli_whole(buf: &[u8], pos: &mut usize, end: usize) -> Result<u64, XzError> {
    let (mut vli, mut n) = (0, 0);
    while *pos < end {
        let b = buf[*pos];
        *pos += 1;
        if vli_step(&mut vli, &mut n, b)? {
            return Ok(vli);
        }
    }
    Err(XzError::Data)
}

#[derive(Clone, Copy)]
enum IndexSeq {
    Indicator,
    Count,
    Unpadded,
    Uncompressed,
    PaddingInit,
    Padding,
    Crc32,
}

/// `lzma_index_hash_decode`'s state.
struct IndexDec {
    seq: IndexSeq,
    vli: u64,
    vli_pos: u32,
    remaining: u64,
    unpadded: u64,
    records: HashInfo,
    pad: u64,
    crc: u32,
    crc_pos: u32,
}

impl IndexDec {
    fn new() -> IndexDec {
        IndexDec {
            seq: IndexSeq::Indicator,
            vli: 0,
            vli_pos: 0,
            remaining: 0,
            unpadded: 0,
            records: HashInfo::new(),
            pad: 0,
            crc: 0,
            crc_pos: 0,
        }
    }

    /// Bytes used and whether the Index is complete.
    fn run(&mut self, input: &[u8], blocks: &HashInfo) -> Result<(usize, bool), XzError> {
        let mut pos = 0;
        let mut crc_from = 0;
        while pos < input.len() {
            match self.seq {
                IndexSeq::Indicator => {
                    if input[pos] != 0 {
                        return Err(XzError::Data);
                    }
                    pos += 1;
                    self.seq = IndexSeq::Count;
                }
                IndexSeq::Count => {
                    let b = input[pos];
                    pos += 1;
                    if vli_step(&mut self.vli, &mut self.vli_pos, b)? {
                        if self.vli != blocks.count {
                            return Err(XzError::Data);
                        }
                        self.remaining = self.vli;
                        self.vli_pos = 0;
                        self.seq = if self.remaining == 0 {
                            IndexSeq::PaddingInit
                        } else {
                            IndexSeq::Unpadded
                        };
                    }
                }
                IndexSeq::Unpadded | IndexSeq::Uncompressed => {
                    let b = input[pos];
                    pos += 1;
                    if vli_step(&mut self.vli, &mut self.vli_pos, b)? {
                        self.vli_pos = 0;
                        if matches!(self.seq, IndexSeq::Unpadded) {
                            if !(UNPADDED_SIZE_MIN..=UNPADDED_SIZE_MAX).contains(&self.vli) {
                                return Err(XzError::Data);
                            }
                            self.unpadded = self.vli;
                            self.seq = IndexSeq::Uncompressed;
                        } else {
                            self.records.append(self.unpadded, self.vli);
                            let r = &self.records;
                            if blocks.blocks_size < r.blocks_size
                                || blocks.uncompressed_size < r.uncompressed_size
                                || blocks.index_list_size < r.index_list_size
                            {
                                return Err(XzError::Data);
                            }
                            self.remaining -= 1;
                            self.seq = if self.remaining == 0 {
                                IndexSeq::PaddingInit
                            } else {
                                IndexSeq::Unpadded
                            };
                        }
                    }
                }
                IndexSeq::PaddingInit => {
                    // (4 - size) & 3, in liblzma's unsigned arithmetic.
                    self.pad = 4u64.wrapping_sub(index_size_unpadded(
                        self.records.count,
                        self.records.index_list_size,
                    )) & 3;
                    self.seq = IndexSeq::Padding;
                }
                IndexSeq::Padding => {
                    if self.pad > 0 {
                        self.pad -= 1;
                        if input[pos] != 0 {
                            return Err(XzError::Data);
                        }
                        pos += 1;
                        continue;
                    }
                    let r = &self.records;
                    if blocks.blocks_size != r.blocks_size
                        || blocks.uncompressed_size != r.uncompressed_size
                        || blocks.index_list_size != r.index_list_size
                        || blocks.sha.clone().finish() != r.sha.clone().finish()
                    {
                        return Err(XzError::Data);
                    }
                    self.crc = crc32(&input[crc_from..pos], self.crc);
                    crc_from = pos;
                    self.seq = IndexSeq::Crc32;
                }
                IndexSeq::Crc32 => {
                    if ((self.crc >> (self.crc_pos * 8)) & 0xFF) as u8 != input[pos] {
                        return Err(XzError::Data);
                    }
                    pos += 1;
                    self.crc_pos += 1;
                    if self.crc_pos == 4 {
                        return Ok((pos, true));
                    }
                    crc_from = pos;
                }
            }
        }
        if !matches!(self.seq, IndexSeq::Crc32) {
            self.crc = crc32(&input[crc_from..pos], self.crc);
        }
        Ok((pos, false))
    }
}

/// `lzma_properties_decode` for a `.xz` Filter ID.
fn props_decode(id: u64, props: &[u8]) -> Result<Filter, XzError> {
    let bcj = |kind| -> Result<Filter, XzError> {
        // `lzma_simple_props_decode`.
        match props.len() {
            0 => Ok(Filter::Bcj { kind, start: 0 }),
            4 => Ok(Filter::Bcj {
                kind,
                start: read32le(props),
            }),
            _ => Err(XzError::Options),
        }
    };
    use super::super::Bcj as B;
    match id {
        // `lzma_lzma2_props_decode`.
        0x21 => {
            if props.len() != 1 || props[0] & 0xC0 != 0 || props[0] > 40 {
                return Err(XzError::Options);
            }
            let p = u32::from(props[0]);
            let dict = if p == 40 {
                u32::MAX
            } else {
                (2 | (p & 1)) << (p / 2 + 11)
            };
            Ok(Filter::Lzma2(lzma_with(dict, 3, 0, 2)))
        }
        // `lzma_delta_props_decode`.
        0x03 => {
            if props.len() != 1 {
                return Err(XzError::Options);
            }
            Ok(Filter::Delta {
                dist: u32::from(props[0]) + 1,
            })
        }
        0x04 => bcj(B::X86),
        0x05 => bcj(B::PowerPc),
        0x06 => bcj(B::Ia64),
        0x07 => bcj(B::Arm),
        0x08 => bcj(B::ArmThumb),
        0x09 => bcj(B::Sparc),
        0x0A => bcj(B::Arm64),
        0x0B => bcj(B::RiscV),
        _ => Err(XzError::Options),
    }
}

/// What `lzma_block_header_decode` makes of a Block Header.
struct BlockHeader {
    filters: Vec<Filter>,
    compressed: Option<u64>,
    uncompressed: Option<u64>,
}

/// `lzma_block_header_decode` (`common/block_header_decoder.c`) with
/// `lzma_filter_flags_decode`.
fn block_header_decode(h: &[u8], check_id: u32) -> Result<BlockHeader, XzError> {
    let in_size = h.len() - 4;
    if crc32(&h[..in_size], 0) != read32le(&h[in_size..]) {
        return Err(XzError::Data);
    }
    let flags = h[1];
    if flags & 0x3C != 0 {
        return Err(XzError::Options);
    }
    let mut pos = 2;
    let mut compressed = None;
    if flags & 0x40 != 0 {
        let c = vli_whole(h, &mut pos, in_size)?;
        // `lzma_block_unpadded_size`'s validation.
        let unpadded = c.saturating_add(h.len() as u64 + check::check_size(check_id) as u64);
        if c == 0 || c > VLI_MAX || unpadded > UNPADDED_SIZE_MAX {
            return Err(XzError::Data);
        }
        compressed = Some(c);
    }
    let mut uncompressed = None;
    if flags & 0x80 != 0 {
        uncompressed = Some(vli_whole(h, &mut pos, in_size)?);
    }
    let mut filters = Vec::new();
    for _ in 0..(flags & 3) + 1 {
        let id = vli_whole(h, &mut pos, in_size)?;
        if id >= FILTER_RESERVED_START {
            return Err(XzError::Data);
        }
        let props_size = vli_whole(h, &mut pos, in_size)?;
        if ((in_size - pos) as u64) < props_size {
            return Err(XzError::Data);
        }
        let props = &h[pos..pos + props_size as usize];
        filters.push(props_decode(id, props)?);
        pos += props_size as usize;
    }
    if h[pos..in_size].iter().any(|&b| b != 0) {
        return Err(XzError::Options);
    }
    Ok(BlockHeader {
        filters,
        compressed,
        uncompressed,
    })
}

enum BlockPhase {
    Code,
    Padding,
    Check(Vec<u8>),
}

/// `block_decoder.c`'s coder for one Block.
struct BlockDec {
    raw: RawDec,
    phase: BlockPhase,
    check: Running,
    check_id: u32,
    header_size: u64,
    declared_compressed: Option<u64>,
    declared_uncompressed: Option<u64>,
    compressed: u64,
    uncompressed: u64,
    compressed_limit: u64,
    uncompressed_limit: u64,
    /// The Compressed Size, without the Block Padding, once known.
    payload: u64,
}

impl BlockDec {
    /// Bytes used and whether the Block is complete.
    fn run(
        &mut self,
        input: &[u8],
        ignore_check: bool,
        out: &mut Vec<u8>,
    ) -> Result<(usize, bool), XzError> {
        let mut pos = 0;
        if matches!(self.phase, BlockPhase::Code) {
            let room = (self.compressed_limit - self.compressed).min(input.len() as u64);
            let start = out.len();
            let (used, ended) = self.raw.run(&input[..room as usize], false, out)?;
            pos += used;
            self.compressed += used as u64;
            let made = (out.len() - start) as u64;
            if made > self.uncompressed_limit - self.uncompressed {
                out.truncate(start + (self.uncompressed_limit - self.uncompressed) as usize);
                return Err(XzError::Data);
            }
            self.uncompressed += made;
            if !ignore_check {
                self.check.update(&out[start..]);
            }
            if !ended {
                let comp_done = Some(self.compressed) == self.declared_compressed;
                let uncomp_done = Some(self.uncompressed) == self.declared_uncompressed;
                if comp_done || (uncomp_done && pos < input.len()) {
                    return Err(XzError::Data);
                }
                return Ok((pos, false));
            }
            if self
                .declared_compressed
                .is_some_and(|c| c != self.compressed)
                || self
                    .declared_uncompressed
                    .is_some_and(|u| u != self.uncompressed)
            {
                return Err(XzError::Data);
            }
            self.payload = self.compressed;
            self.phase = BlockPhase::Padding;
        }
        if matches!(self.phase, BlockPhase::Padding) {
            while self.compressed & 3 != 0 {
                if pos >= input.len() {
                    return Ok((pos, false));
                }
                self.compressed += 1;
                pos += 1;
                if input[pos - 1] != 0 {
                    return Err(XzError::Data);
                }
            }
            if self.check_id == 0 {
                return Ok((pos, true));
            }
            self.phase = BlockPhase::Check(Vec::new());
        }
        if let BlockPhase::Check(buf) = &mut self.phase {
            if !fill(buf, check::check_size(self.check_id), input, &mut pos) {
                return Ok((pos, false));
            }
            if !ignore_check && check::is_supported(self.check_id) {
                let want = std::mem::replace(&mut self.check, Running::None).finish();
                if *buf != want {
                    return Err(XzError::Data);
                }
            }
        }
        Ok((pos, true))
    }

    /// `lzma_block_unpadded_size` of the finished Block.
    fn unpadded_size(&self) -> u64 {
        self.header_size + self.payload + check::check_size(self.check_id) as u64
    }
}

enum XzSeq {
    StreamHeader,
    BlockHeader,
    Block(Box<BlockDec>),
    Index(Box<IndexDec>),
    Footer,
    Padding,
    End,
}

/// `.xz`: `stream_decoder_mt.c` as `xz` runs it (every Block in its direct
/// mode), or with `single` the single-threaded `stream_decoder.c` that
/// `lzma_auto_decoder` uses. The two differ only in the `needed` a
/// refused Block reports.
struct XzDec {
    seq: XzSeq,
    buf: Vec<u8>,
    first_stream: bool,
    concatenated: bool,
    ignore_check: bool,
    memlimit: u64,
    single: bool,
    /// `mem_direct_mode`: the memusage of the last Block decoded.
    mem_direct: u64,
    /// The Stream Flags of the current Stream.
    flags: [u8; 2],
    blocks: HashInfo,
    pad_pos: u32,
}

impl XzDec {
    fn new(o: &DecodeOptions, single: bool) -> XzDec {
        XzDec {
            seq: XzSeq::StreamHeader,
            buf: Vec::new(),
            first_stream: true,
            concatenated: !o.single_stream,
            ignore_check: o.ignore_check,
            memlimit: limit_of(o.memlimit),
            single,
            mem_direct: 0,
            flags: [0; 2],
            blocks: HashInfo::new(),
            pad_pos: 0,
        }
    }

    fn check_id(&self) -> u32 {
        u32::from(self.flags[1] & 0x0F)
    }

    /// `lzma_stream_header_decode`, then the check warning.
    fn stream_header(&mut self, warnings: &mut VecDeque<u32>) -> Result<(), XzError> {
        let h = std::mem::take(&mut self.buf);
        if h[..6] != HEADER_MAGIC {
            return Err(if self.first_stream {
                XzError::Format
            } else {
                XzError::Data
            });
        }
        if crc32(&h[6..8], 0) != read32le(&h[8..12]) {
            return Err(XzError::Data);
        }
        if h[6] != 0 || h[7] & 0xF0 != 0 {
            return Err(XzError::Options);
        }
        self.first_stream = false;
        self.flags = [h[6], h[7]];
        self.blocks = HashInfo::new();
        if !self.ignore_check && !check::is_supported(self.check_id()) {
            warnings.push_back(self.check_id());
        }
        Ok(())
    }

    /// The Block Header in `buf`, the memory limit, the Block's decoder.
    fn block_init(&mut self) -> Result<BlockDec, XzError> {
        let h = std::mem::take(&mut self.buf);
        let check_id = self.check_id();
        let header = block_header_decode(&h, check_id)?;
        let mem = decoder_memusage(&header.filters).ok_or(XzError::Options)?;
        if mem > self.memlimit {
            let needed = if self.single {
                mem
            } else {
                self.mem_direct.max(MEMUSAGE_BASE)
            };
            return Err(XzError::MemLimit {
                needed,
                limit: self.memlimit,
            });
        }
        let raw = RawDec::new(&header.filters)?;
        self.mem_direct = mem;
        let check_size = check::check_size(check_id) as u64;
        Ok(BlockDec {
            raw,
            phase: BlockPhase::Code,
            check: Running::new(check_id),
            check_id,
            header_size: h.len() as u64,
            declared_compressed: header.compressed,
            declared_uncompressed: header.uncompressed,
            compressed: 0,
            uncompressed: 0,
            compressed_limit: header
                .compressed
                .unwrap_or((VLI_MAX & !3) - h.len() as u64 - check_size),
            uncompressed_limit: header.uncompressed.unwrap_or(VLI_MAX),
            payload: 0,
        })
    }

    /// `lzma_index_hash_append`'s limits.
    fn append(&mut self, unpadded: u64, uncompressed: u64) -> Result<(), XzError> {
        let b = &mut self.blocks;
        b.append(unpadded, uncompressed);
        let isize = index_size(b.count, b.index_list_size);
        if b.blocks_size > VLI_MAX
            || b.uncompressed_size > VLI_MAX
            || isize > BACKWARD_SIZE_MAX
            || b.blocks_size.saturating_add(24 + isize) > VLI_MAX
        {
            return Err(XzError::Data);
        }
        Ok(())
    }

    /// `lzma_stream_footer_decode` and the comparisons after it.
    fn footer(&mut self) -> Result<(), XzError> {
        let f = std::mem::take(&mut self.buf);
        if f[10..12] != FOOTER_MAGIC {
            return Err(XzError::Data);
        }
        if crc32(&f[4..10], 0) != read32le(&f[..4]) {
            return Err(XzError::Data);
        }
        if f[8] != 0 || f[9] & 0xF0 != 0 {
            return Err(XzError::Options);
        }
        let backward = (u64::from(read32le(&f[4..8])) + 1) * 4;
        if index_size(self.blocks.count, self.blocks.index_list_size) != backward {
            return Err(XzError::Data);
        }
        if f[9] != self.flags[1] {
            return Err(XzError::Data);
        }
        Ok(())
    }

    fn run(
        &mut self,
        input: &[u8],
        finish: bool,
        out: &mut Vec<u8>,
        warnings: &mut VecDeque<u32>,
    ) -> Result<(usize, bool), XzError> {
        let mut pos = 0;
        loop {
            match &mut self.seq {
                XzSeq::End => return Ok((pos, true)),
                XzSeq::StreamHeader => {
                    if !fill(&mut self.buf, 12, input, &mut pos) {
                        break;
                    }
                    self.stream_header(warnings)?;
                    self.seq = XzSeq::BlockHeader;
                }
                XzSeq::BlockHeader => {
                    let size_byte = match self.buf.first() {
                        Some(&b) => b,
                        None => {
                            let Some(&b) = input.get(pos) else { break };
                            if b == 0 {
                                self.seq = XzSeq::Index(Box::new(IndexDec::new()));
                                continue;
                            }
                            b
                        }
                    };
                    // `lzma_block_header_size_decode`.
                    let need = (usize::from(size_byte) + 1) * 4;
                    if !fill(&mut self.buf, need, input, &mut pos) {
                        break;
                    }
                    self.seq = XzSeq::Block(Box::new(self.block_init()?));
                }
                XzSeq::Block(b) => {
                    let (used, done) = b.run(&input[pos..], self.ignore_check, out)?;
                    pos += used;
                    if !done {
                        break;
                    }
                    let (unpadded, uncompressed) = (b.unpadded_size(), b.uncompressed);
                    self.append(unpadded, uncompressed)?;
                    self.seq = XzSeq::BlockHeader;
                }
                XzSeq::Index(ix) => {
                    if pos >= input.len() {
                        break;
                    }
                    let (used, done) = ix.run(&input[pos..], &self.blocks)?;
                    pos += used;
                    if !done {
                        break;
                    }
                    self.seq = XzSeq::Footer;
                }
                XzSeq::Footer => {
                    if !fill(&mut self.buf, 12, input, &mut pos) {
                        break;
                    }
                    self.footer()?;
                    if !self.concatenated {
                        self.seq = XzSeq::End;
                        continue;
                    }
                    self.pad_pos = 0;
                    self.seq = XzSeq::Padding;
                }
                XzSeq::Padding => {
                    loop {
                        let Some(&b) = input.get(pos) else {
                            if !finish {
                                return Ok((pos, false));
                            }
                            if self.pad_pos != 0 {
                                return Err(XzError::Data);
                            }
                            self.seq = XzSeq::End;
                            return Ok((pos, true));
                        };
                        if b != 0 {
                            break;
                        }
                        pos += 1;
                        self.pad_pos = (self.pad_pos + 1) & 3;
                    }
                    if self.pad_pos != 0 {
                        return Err(XzError::Data);
                    }
                    self.seq = XzSeq::StreamHeader;
                }
            }
        }
        if finish {
            return Err(XzError::BufError);
        }
        Ok((pos, false))
    }
}

/// `lzma_lzma_lclppb_decode`: `(lc, lp, pb)`, or `None` where liblzma
/// refuses the byte.
fn lclppb_decode(byte: u8) -> Option<(u32, u32, u32)> {
    if byte > (4 * 5 + 4) * 9 + 8 {
        return None;
    }
    let byte = u32::from(byte);
    let pb = byte / (9 * 5);
    let lp = (byte - pb * 9 * 5) / 9;
    let lc = byte - pb * 9 * 5 - lp * 9;
    (lc + lp <= 4).then_some((lc, lp, pb))
}

/// `.lzma` (`alone_decoder.c`); `picky` is `lzma_auto_decoder`'s.
struct AloneDec {
    picky: bool,
    memlimit: u64,
    header: Vec<u8>,
    raw: Option<RawDec>,
}

impl AloneDec {
    fn run(
        &mut self,
        input: &[u8],
        finish: bool,
        out: &mut Vec<u8>,
    ) -> Result<(usize, bool), XzError> {
        let mut pos = 0;
        while self.raw.is_none() {
            let Some(&b) = input.get(pos) else {
                return if finish {
                    Err(XzError::BufError)
                } else {
                    Ok((pos, false))
                };
            };
            pos += 1;
            self.header.push(b);
            let h = &self.header;
            match h.len() {
                1 if lclppb_decode(b).is_none() => return Err(XzError::Format),
                5 if self.picky => {
                    let dict = read32le(&h[1..5]);
                    if dict != u32::MAX {
                        let mut d = dict.wrapping_sub(1);
                        d |= d >> 2;
                        d |= d >> 3;
                        d |= d >> 4;
                        d |= d >> 8;
                        d |= d >> 16;
                        if d.wrapping_add(1) != dict {
                            return Err(XzError::Format);
                        }
                    }
                }
                13 => {
                    let size = read64le(&h[5..13]);
                    if self.picky && size != u64::MAX && size >= 1 << 38 {
                        return Err(XzError::Format);
                    }
                    let dict = read32le(&h[1..5]);
                    let needed = lzma_decoder_memusage_nocheck(dict) + MEMUSAGE_BASE;
                    if needed > self.memlimit {
                        return Err(XzError::MemLimit {
                            needed,
                            limit: self.memlimit,
                        });
                    }
                    let (lc, lp, pb) = lclppb_decode(h[0]).expect("checked at byte 1");
                    self.raw = Some(RawDec::lzma1(
                        size,
                        &lzma_with(dict, lc, lp, pb),
                        &[],
                        None,
                    )?);
                }
                _ => {}
            }
        }
        let raw = self.raw.as_mut().expect("built above");
        let (used, ended) = raw.run(&input[pos..], finish, out)?;
        if finish && !ended {
            return Err(XzError::BufError);
        }
        Ok((pos + used, ended))
    }

    fn returned(&self) -> usize {
        self.raw.as_ref().map_or(0, |r| r.leftover.len())
    }
}

enum LzipSeq {
    Magic,
    Version,
    Dict,
    Lzma(Box<RawDec>),
    Footer,
    End,
}

/// `.lz` (`lzip_decoder.c`).
struct LzipDec {
    seq: LzipSeq,
    first_member: bool,
    concatenated: bool,
    ignore_check: bool,
    memlimit: u64,
    magic_pos: usize,
    version: u8,
    crc: u32,
    uncompressed: u64,
    member_size: u64,
    buf: Vec<u8>,
    /// Bytes counted as used by earlier calls that the member's LZMA data
    /// did not use: parsed before any new input.
    pending: Vec<u8>,
}

impl LzipDec {
    fn new(o: &DecodeOptions) -> LzipDec {
        LzipDec {
            seq: LzipSeq::Magic,
            first_member: true,
            concatenated: !o.single_stream,
            ignore_check: o.ignore_check,
            memlimit: limit_of(o.memlimit),
            magic_pos: 0,
            version: 0,
            crc: 0,
            uncompressed: 0,
            member_size: 0,
            buf: Vec::new(),
            pending: Vec::new(),
        }
    }

    fn run(
        &mut self,
        input: &[u8],
        finish: bool,
        out: &mut Vec<u8>,
    ) -> Result<(usize, bool), XzError> {
        let mut ipos = 0;
        loop {
            while !self.pending.is_empty() {
                let p = std::mem::take(&mut self.pending);
                let (used, ended) = self.step(&p, false, out)?;
                let mut rest = std::mem::take(&mut self.pending);
                rest.extend_from_slice(&p[used..]);
                self.pending = rest;
                if ended {
                    return Ok((ipos, true));
                }
            }
            let (used, ended) = self.step(&input[ipos..], finish, out)?;
            ipos += used;
            if ended || self.pending.is_empty() {
                return Ok((ipos, ended));
            }
        }
    }

    /// One pass over `input`: bytes used, whether the stream ended. Stops
    /// early when a member's LZMA data hands bytes back (`pending`).
    fn step(
        &mut self,
        input: &[u8],
        finish: bool,
        out: &mut Vec<u8>,
    ) -> Result<(usize, bool), XzError> {
        let mut pos = 0;
        loop {
            match &mut self.seq {
                LzipSeq::End => return Ok((pos, true)),
                LzipSeq::Magic => {
                    while self.magic_pos < LZIP_MAGIC.len() {
                        let Some(&b) = input.get(pos) else {
                            if !self.first_member && finish {
                                self.seq = LzipSeq::End;
                                return Ok((pos, true));
                            }
                            return Self::more(pos, finish);
                        };
                        if b != LZIP_MAGIC[self.magic_pos] {
                            if self.first_member {
                                return Err(XzError::Format);
                            }
                            self.seq = LzipSeq::End;
                            return Ok((pos, true));
                        }
                        pos += 1;
                        self.magic_pos += 1;
                    }
                    self.magic_pos = 0;
                    self.crc = 0;
                    self.uncompressed = 0;
                    self.member_size = LZIP_MAGIC.len() as u64;
                    self.seq = LzipSeq::Version;
                }
                LzipSeq::Version => {
                    let Some(&b) = input.get(pos) else {
                        return Self::more(pos, finish);
                    };
                    pos += 1;
                    if b > 1 {
                        return Err(XzError::Options);
                    }
                    self.version = b;
                    self.member_size += 1;
                    self.seq = LzipSeq::Dict;
                }
                LzipSeq::Dict => {
                    let Some(&ds) = input.get(pos) else {
                        return Self::more(pos, finish);
                    };
                    pos += 1;
                    self.member_size += 1;
                    let b2log = u32::from(ds & 0x1F);
                    let fracnum = u32::from(ds >> 5);
                    if !(12..=29).contains(&b2log) || (b2log == 12 && fracnum > 0) {
                        return Err(XzError::Data);
                    }
                    let dict = (1 << b2log) - (fracnum << (b2log - 4));
                    let needed = lzma_decoder_memusage_nocheck(dict) + MEMUSAGE_BASE;
                    if needed > self.memlimit {
                        return Err(XzError::MemLimit {
                            needed,
                            limit: self.memlimit,
                        });
                    }
                    let raw = RawDec::lzma1(u64::MAX, &lzma_with(dict, 3, 0, 2), &[], None)?;
                    self.seq = LzipSeq::Lzma(Box::new(raw));
                }
                LzipSeq::Lzma(raw) => {
                    let start = out.len();
                    let (used, ended) = raw.run(&input[pos..], finish, out)?;
                    pos += used;
                    self.member_size += used as u64;
                    self.uncompressed += (out.len() - start) as u64;
                    if !self.ignore_check {
                        self.crc = crc32(&out[start..], self.crc);
                    }
                    if !ended {
                        return Self::more(pos, finish);
                    }
                    let leftover = std::mem::take(&mut raw.leftover);
                    self.member_size -= leftover.len() as u64;
                    self.buf.clear();
                    self.seq = LzipSeq::Footer;
                    if !leftover.is_empty() {
                        self.pending = leftover;
                        return Ok((pos, false));
                    }
                }
                LzipSeq::Footer => {
                    let size = if self.version == 0 { 12 } else { 20 };
                    if !fill(&mut self.buf, size, input, &mut pos) {
                        return Self::more(pos, finish);
                    }
                    self.member_size += size as u64;
                    let f = &self.buf;
                    if !self.ignore_check && self.crc != read32le(&f[..4]) {
                        return Err(XzError::Data);
                    }
                    if self.uncompressed != read64le(&f[4..12]) {
                        return Err(XzError::Data);
                    }
                    if self.version > 0 && self.member_size != read64le(&f[12..20]) {
                        return Err(XzError::Data);
                    }
                    if !self.concatenated {
                        self.seq = LzipSeq::End;
                        return Ok((pos, true));
                    }
                    self.first_member = false;
                    self.seq = LzipSeq::Magic;
                }
            }
        }
    }

    /// Out of input: wait for more, or, at the end, `LZMA_BUF_ERROR`.
    fn more(pos: usize, finish: bool) -> Result<(usize, bool), XzError> {
        if finish {
            Err(XzError::BufError)
        } else {
            Ok((pos, false))
        }
    }
}

/// [`Format::Raw`]: a raw chain alone.
struct RawOnly(RawDec);

impl RawOnly {
    fn run(
        &mut self,
        input: &[u8],
        finish: bool,
        out: &mut Vec<u8>,
    ) -> Result<(usize, bool), XzError> {
        let (used, ended) = self.0.run(input, finish, out)?;
        if finish && !ended {
            return Err(XzError::BufError);
        }
        Ok((used, ended))
    }
}

enum Machine {
    /// `auto`, before the format is known.
    None,
    Xz(Box<XzDec>),
    Alone(Box<AloneDec>),
    Lzip(Box<LzipDec>),
    Raw(Box<RawOnly>),
}

/// Where a [`Decoder`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DState {
    Sniffing,
    Running,
    Ended,
    Failed,
}

/// A streaming decoder over [`DecodeOptions`]: the pure tier's
/// counterpart of `c::Decoder`, with the same contract and
/// liblzma's verdicts (see the module doc for the known differences).
pub struct Decoder {
    opts: DecodeOptions,
    machine: Machine,
    state: DState,
    sniff: Vec<u8>,
    allow_trailing: bool,
    warnings: VecDeque<u32>,
    /// Bytes of input the decoder reported using.
    used: u64,
    out_bytes: u64,
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decoder")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Decoder {
    /// Initialises the decoder (for `auto`, once four bytes are in). A raw
    /// chain whose [`super::decoder_memusage`] exceeds the limit is
    /// [`XzError::MemLimit`]; `auto` with [`Format::Raw`] is
    /// [`XzError::Options`].
    pub fn new(o: &DecodeOptions) -> Result<Decoder, XzError> {
        let mut d = Decoder {
            opts: o.clone(),
            machine: Machine::None,
            state: DState::Sniffing,
            sniff: Vec::new(),
            allow_trailing: o.single_stream,
            warnings: VecDeque::new(),
            used: 0,
            out_bytes: 0,
        };
        if o.auto {
            if o.format == Format::Raw {
                return Err(XzError::Options);
            }
        } else {
            d.init(o.format, false)?;
        }
        Ok(d)
    }

    /// `coder_init`'s decoder for `format`; `auto` is `lzma_auto_decoder`'s
    /// choice (the single-threaded `.xz` decoder, the picky `.lzma` one).
    fn init(&mut self, format: Format, auto: bool) -> Result<(), XzError> {
        let o = &self.opts;
        self.machine = match format {
            Format::Xz => Machine::Xz(Box::new(XzDec::new(o, auto))),
            Format::Lzma => Machine::Alone(Box::new(AloneDec {
                picky: auto,
                memlimit: limit_of(o.memlimit),
                header: Vec::new(),
                raw: None,
            })),
            Format::Lzip => {
                self.allow_trailing = true;
                Machine::Lzip(Box::new(LzipDec::new(o)))
            }
            Format::Raw => {
                let limit = limit_of(o.memlimit);
                let failed = |d: &mut Decoder, e| {
                    d.state = DState::Failed;
                    Err(e)
                };
                let Some(needed) = decoder_memusage(&o.raw_filters) else {
                    return failed(self, XzError::Options);
                };
                if needed > limit {
                    return failed(self, XzError::MemLimit { needed, limit });
                }
                match RawDec::new(&o.raw_filters) {
                    Ok(r) => Machine::Raw(Box::new(RawOnly(r))),
                    Err(e) => return failed(self, e),
                }
            }
        };
        self.state = DState::Running;
        Ok(())
    }

    /// `auto` with the first bytes in: `.lz` by its magic, then
    /// `lzma_auto_decoder`'s rule (`0xFD` is `.xz`, anything else `.lzma`).
    fn init_auto(&mut self) -> Result<Vec<u8>, XzError> {
        let format = if self.sniff.starts_with(&LZIP_MAGIC) {
            Format::Lzip
        } else if self.sniff.first() == Some(&0xFD) {
            Format::Xz
        } else {
            Format::Lzma
        };
        self.init(format, true)?;
        Ok(std::mem::take(&mut self.sniff))
    }

    /// Decompresses `input`, appending the output to `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), XzError> {
        if self.state != DState::Sniffing {
            return self.code(input, false, out);
        }
        self.sniff.extend_from_slice(input);
        if self.sniff.len() < LZIP_MAGIC.len() {
            return Ok(());
        }
        let held = self.init_auto()?;
        self.code(&held, false, out)
    }

    /// The input is over. A stream cut short is [`XzError::BufError`].
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), XzError> {
        let held = if self.state == DState::Sniffing {
            self.init_auto()?
        } else {
            Vec::new()
        };
        self.code(&held, true, out)
    }

    /// Bytes the machine reported using that it has since handed back.
    fn returned(&self) -> u64 {
        (match &self.machine {
            Machine::Alone(a) => a.returned(),
            Machine::Lzip(l) => l.pending.len(),
            Machine::Raw(r) => r.0.leftover.len(),
            Machine::None | Machine::Xz(_) => 0,
        }) as u64
    }

    fn code(&mut self, input: &[u8], finish: bool, out: &mut Vec<u8>) -> Result<(), XzError> {
        match self.state {
            DState::Failed | DState::Sniffing => return Err(XzError::Prog),
            DState::Ended => {
                if !input.is_empty() && !self.allow_trailing {
                    self.state = DState::Failed;
                    return Err(XzError::Data);
                }
                return Ok(());
            }
            DState::Running => {}
        }
        let start = out.len();
        let r = match &mut self.machine {
            Machine::Xz(x) => x.run(input, finish, out, &mut self.warnings),
            Machine::Alone(a) => a.run(input, finish, out),
            Machine::Lzip(l) => l.run(input, finish, out),
            Machine::Raw(r) => r.run(input, finish, out),
            Machine::None => Err(XzError::Prog),
        };
        self.out_bytes += (out.len() - start) as u64;
        match r {
            Ok((used, ended)) => {
                self.used += used as u64;
                if ended {
                    let trailing = used < input.len() || self.returned() > 0;
                    if trailing && !self.allow_trailing {
                        self.state = DState::Failed;
                        return Err(XzError::Data);
                    }
                    self.state = DState::Ended;
                }
                Ok(())
            }
            Err(e) => {
                self.state = DState::Failed;
                Err(e)
            }
        }
    }

    /// Bytes in and out so far: `in_bytes` is what the stream used, so
    /// input left after it is not counted.
    pub fn progress(&self) -> Progress {
        Progress {
            in_bytes: self.used - self.returned(),
            out_bytes: self.out_bytes,
        }
    }

    /// The check ID of the oldest unsupported-check warning not yet taken
    /// (`LZMA_UNSUPPORTED_CHECK`, once per Stream that has one).
    pub fn take_unsupported_check_warning(&mut self) -> Option<u32> {
        self.warnings.pop_front()
    }
}
