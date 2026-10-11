//! Apple gzip's lzip decoder, ported from `file_cmds-479` `gzip/unlz.c`
//! (NetBSD's, by Christos Zoulas, from Antonio Diaz Diaz's Lzd; both
//! notices are in `LICENSE-gzip-bsd`).
//!
//! It is its own LZMA decoder, not liblzma, and its oddities are what
//! `gunzip` prints, so they are kept:
//!
//! - only the first member is decoded; whatever follows it is ignored;
//! - the input is read through stdio's `getc`, so past its end the range
//!   decoder takes `0xff` bytes until the loop next checks `feof`: a
//!   cut-short member decodes a few more bytes from them, and they are
//!   output;
//! - a match reaching before the start of the data, or past the
//!   dictionary, ends the member as a failure, after what was decoded is
//!   output; nothing is said (`gunzip` adds "uncompress failed").
//!
//! The dictionary buffer grows with the output instead of being allocated
//! whole (`malloc(dict_size)`, up to 512 MiB): before it wraps, `lz_peek`
//! never reads past what was written, so the bytes are the same.

use std::io::{self, Read, Write};

const LZ_STATES: usize = 12;
const LITERAL_CONTEXT_BITS: u32 = 3;
const POS_STATE_BITS: u32 = 2;
const POS_STATES: usize = 1 << POS_STATE_BITS;
const POS_STATE_MASK: u64 = POS_STATES as u64 - 1;
const STATES: usize = 4;
const DIS_SLOT_BITS: u32 = 6;
const DIS_MODEL_START: u32 = 4;
const DIS_MODEL_END: u32 = 14;
const MODELED_DISTANCES: usize = 1 << (DIS_MODEL_END / 2);
const DIS_ALIGN_BITS: u32 = 4;
const DIS_ALIGN_SIZE: usize = 1 << DIS_ALIGN_BITS;
const LOW_BITS: u32 = 3;
const MID_BITS: u32 = 3;
const HIGH_BITS: u32 = 8;
const LOW_SYMBOLS: usize = 1 << LOW_BITS;
const MID_SYMBOLS: usize = 1 << MID_BITS;
const HIGH_SYMBOLS: usize = 1 << HIGH_BITS;
const MIN_MATCH_LEN: u32 = 2;
const BIT_MODEL_MOVE_BITS: u32 = 5;
const BIT_MODEL_TOTAL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: i32 = 1 << BIT_MODEL_TOTAL_BITS;
const BIT_MODEL_INIT: i32 = BIT_MODEL_TOTAL / 2;

const HDR_SIZE: usize = 6;
const TRAILER_SIZE: usize = 20;
const MIN_DICTIONARY_SIZE: u32 = 1 << 12;
const MAX_DICTIONARY_SIZE: u32 = 1 << 29;
const HDRMAGIC: [u8; 5] = *b"LZIP\x01";

const ST_NEXT: [usize; LZ_STATES] = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5];

/// What [`unlz`] did: `Ok(Some((data_size, member_size)))`, or `Ok(None)`
/// where unlz.c returns -1. `Err` is a failed write of the output, which
/// unlz.c ignores (stdio remembers it) and stuffr does not (see
/// [`unlz`]).
pub(super) type Outcome = io::Result<Option<(u64, u64)>>;

/// stdio's `getc` over a reader: `0xff` (`(uint8_t)EOF`) past the end or
/// on an error, with `feof`/`ferror` set.
struct Getc<'r> {
    r: &'r mut dyn Read,
    buf: Box<[u8; 4096]>,
    pos: usize,
    len: usize,
    eof: bool,
    err: bool,
}

impl Getc<'_> {
    fn getc(&mut self) -> u8 {
        if self.pos == self.len {
            if self.eof || self.err {
                return 0xff;
            }
            loop {
                match self.r.read(&mut self.buf[..]) {
                    Ok(0) => {
                        self.eof = true;
                        return 0xff;
                    }
                    Ok(n) => {
                        self.pos = 0;
                        self.len = n;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        self.err = true;
                        return 0xff;
                    }
                }
            }
        }
        self.pos += 1;
        self.buf[self.pos - 1]
    }
}

struct RangeDecoder<'r> {
    fp: Getc<'r>,
    code: u32,
    range: u32,
}

impl RangeDecoder<'_> {
    fn normalize(&mut self) {
        if self.range <= 0x00ff_ffff {
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(self.fp.getc());
        }
    }

    fn decode(&mut self, num_bits: u32) -> u32 {
        let mut symbol = 0u32;
        for _ in 0..num_bits {
            self.range >>= 1;
            symbol <<= 1;
            if self.code >= self.range {
                self.code = self.code.wrapping_sub(self.range);
                symbol |= 1;
            }
            self.normalize();
        }
        symbol
    }

    /// The range coder's arithmetic is unsigned and wraps, as in C (a
    /// corrupt stream can leave `code` past `range`).
    fn decode_bit(&mut self, bm: &mut i32) -> u32 {
        let bound = (self.range >> BIT_MODEL_TOTAL_BITS).wrapping_mul(*bm as u32);
        let symbol = if self.code < bound {
            self.range = bound;
            *bm += (BIT_MODEL_TOTAL - *bm) >> BIT_MODEL_MOVE_BITS;
            0
        } else {
            self.range = self.range.wrapping_sub(bound);
            self.code = self.code.wrapping_sub(bound);
            *bm -= *bm >> BIT_MODEL_MOVE_BITS;
            1
        };
        self.normalize();
        symbol
    }

    fn decode_tree(&mut self, bm: &mut [i32], num_bits: u32) -> u32 {
        let mut symbol = 1u32;
        for _ in 0..num_bits {
            symbol = (symbol << 1) | self.decode_bit(&mut bm[symbol as usize]);
        }
        symbol - (1 << num_bits)
    }

    fn decode_tree_reversed(&mut self, bm: &mut [i32], num_bits: u32) -> u32 {
        let mut symbol = self.decode_tree(bm, num_bits);
        let mut reversed = 0;
        for _ in 0..num_bits {
            reversed = (reversed << 1) | (symbol & 1);
            symbol >>= 1;
        }
        reversed
    }

    fn decode_matched(&mut self, bm: &mut [i32], match_byte: u32) -> u32 {
        let mut symbol = 1u32;
        for i in (0..8).rev() {
            let match_bit = (match_byte >> i) & 1;
            let bit = self.decode_bit(&mut bm[(symbol + (match_bit << 8) + 0x100) as usize]);
            symbol = (symbol << 1) | bit;
            if match_bit != bit {
                while symbol < 0x100 {
                    symbol = (symbol << 1) | self.decode_bit(&mut bm[symbol as usize]);
                }
                break;
            }
        }
        symbol & 0xff
    }

    fn decode_len(&mut self, lm: &mut LenModel, pos_state: usize) -> u32 {
        if self.decode_bit(&mut lm.choice1) == 0 {
            return self.decode_tree(&mut lm.bm_low[pos_state], LOW_BITS);
        }
        if self.decode_bit(&mut lm.choice2) == 0 {
            return LOW_SYMBOLS as u32 + self.decode_tree(&mut lm.bm_mid[pos_state], MID_BITS);
        }
        (LOW_SYMBOLS + MID_SYMBOLS) as u32 + self.decode_tree(&mut lm.bm_high, HIGH_BITS)
    }
}

struct LenModel {
    choice1: i32,
    choice2: i32,
    bm_low: [[i32; LOW_SYMBOLS]; POS_STATES],
    bm_mid: [[i32; MID_SYMBOLS]; POS_STATES],
    bm_high: [i32; HIGH_SYMBOLS],
}

impl LenModel {
    fn new() -> Self {
        LenModel {
            choice1: BIT_MODEL_INIT,
            choice2: BIT_MODEL_INIT,
            bm_low: [[BIT_MODEL_INIT; LOW_SYMBOLS]; POS_STATES],
            bm_mid: [[BIT_MODEL_INIT; MID_SYMBOLS]; POS_STATES],
            bm_high: [BIT_MODEL_INIT; HIGH_SYMBOLS],
        }
    }
}

/// `struct lz_decoder`, the dictionary as a buffer that grows to
/// `dict_size`.
struct Decoder<'r, 'w> {
    rd: RangeDecoder<'r>,
    out: &'w mut dyn Write,
    /// Where the first failed write went (`ferror(fout)`).
    failed: Option<io::Error>,
    pos: u64,
    ppos: u64,
    spos: u64,
    dict_size: u64,
    wrapped: bool,
    crc: flate2::Crc,
    obuf: Vec<u8>,
    /// The most the dictionary buffer may grow to before it wraps.
    max_buffer: u64,
}

impl Decoder<'_, '_> {
    /// `lz_flush`: the bytes since the last flush, to the CRC and out.
    fn flush(&mut self) {
        if self.pos <= self.spos {
            return;
        }
        let chunk = &self.obuf[self.spos as usize..self.pos as usize];
        self.crc.update(chunk);
        if self.failed.is_none()
            && let Err(e) = self.out.write_all(chunk)
        {
            self.failed = Some(e);
        }
        self.wrapped = self.pos >= self.dict_size;
        if self.wrapped {
            self.ppos += self.pos;
            self.pos = 0;
        }
        self.spos = self.pos;
    }

    /// `lz_peek`.
    fn peek(&self, ahead: u32) -> u8 {
        let diff = self.pos as i64 - i64::from(ahead) - 1;
        if diff >= 0 {
            return self.obuf[diff as usize];
        }
        if self.wrapped {
            return self.obuf[(self.dict_size as i64 + diff) as usize];
        }
        0
    }

    /// `lz_put`.
    fn put(&mut self, b: u8) {
        let at = self.pos as usize;
        if at == self.obuf.len() {
            if self.obuf.len() as u64 >= self.max_buffer {
                self.failed = Some(io::Error::from(io::ErrorKind::OutOfMemory));
                return;
            }
            self.obuf.push(b);
        } else {
            self.obuf[at] = b;
        }
        self.pos += 1;
        if self.pos == self.dict_size {
            self.flush();
        }
    }

    fn data_position(&self) -> u64 {
        self.ppos + self.pos
    }

    /// `lz_decode_member`: true at a well-formed end-of-stream marker.
    fn decode_member(&mut self) -> bool {
        let mut bm_literal = vec![[BIT_MODEL_INIT; 0x300]; 1 << LITERAL_CONTEXT_BITS];
        let mut bm_match = [[BIT_MODEL_INIT; POS_STATES]; LZ_STATES];
        let mut bm_rep = [[BIT_MODEL_INIT; LZ_STATES]; 4];
        let mut bm_len = [[BIT_MODEL_INIT; POS_STATES]; LZ_STATES];
        let mut bm_dis_slot = [[BIT_MODEL_INIT; 1 << DIS_SLOT_BITS]; STATES];
        let mut bm_dis = [BIT_MODEL_INIT; MODELED_DISTANCES - DIS_MODEL_END as usize + 1];
        let mut bm_align = [BIT_MODEL_INIT; DIS_ALIGN_SIZE];
        let mut match_len_model = LenModel::new();
        let mut rep_len_model = LenModel::new();
        let mut rep = [0u32; 4];
        let mut state = 0usize;

        // stuffr stops at a failed write (see `unlz`); unlz.c decodes on.
        while !self.rd.fp.eof && !self.rd.fp.err && self.failed.is_none() {
            let pos_state = (self.data_position() & POS_STATE_MASK) as usize;
            // bit 1
            if self.rd.decode_bit(&mut bm_match[state][pos_state]) == 0 {
                let prev_byte = self.peek(0);
                let literal_state = usize::from(prev_byte >> (8 - LITERAL_CONTEXT_BITS));
                let bm = &mut bm_literal[literal_state];
                let b = if state < 7 {
                    self.rd.decode_tree(bm, 8)
                } else {
                    let peek = u32::from(self.peek(rep[0]));
                    self.rd.decode_matched(bm, peek)
                };
                self.put(b as u8);
                state = ST_NEXT[state];
                continue;
            }
            let len;
            // bit 2
            if self.rd.decode_bit(&mut bm_rep[0][state]) != 0 {
                // bit 3
                if self.rd.decode_bit(&mut bm_rep[1][state]) == 0 {
                    // bit 4
                    if self.rd.decode_bit(&mut bm_len[state][pos_state]) == 0 {
                        state = if state < 7 { 9 } else { 11 };
                        let b = self.peek(rep[0]);
                        self.put(b);
                        continue;
                    }
                } else {
                    let distance;
                    // bit 4
                    if self.rd.decode_bit(&mut bm_rep[2][state]) == 0 {
                        distance = rep[1];
                    } else {
                        // bit 5
                        if self.rd.decode_bit(&mut bm_rep[3][state]) == 0 {
                            distance = rep[2];
                        } else {
                            distance = rep[3];
                            rep[3] = rep[2];
                        }
                        rep[2] = rep[1];
                    }
                    rep[1] = rep[0];
                    rep[0] = distance;
                }
                state = if state < 7 { 8 } else { 11 };
                len = MIN_MATCH_LEN + self.rd.decode_len(&mut rep_len_model, pos_state);
            } else {
                rep[3] = rep[2];
                rep[2] = rep[1];
                rep[1] = rep[0];
                len = MIN_MATCH_LEN + self.rd.decode_len(&mut match_len_model, pos_state);
                let len_state = ((len - MIN_MATCH_LEN) as usize).min(STATES - 1);
                rep[0] = self
                    .rd
                    .decode_tree(&mut bm_dis_slot[len_state], DIS_SLOT_BITS);
                if rep[0] >= DIS_MODEL_START {
                    let dis_slot = rep[0];
                    let direct_bits = (dis_slot >> 1) - 1;
                    rep[0] = (2 | (dis_slot & 1)) << direct_bits;
                    if dis_slot < DIS_MODEL_END {
                        let base = (rep[0] - dis_slot) as usize;
                        rep[0] = rep[0].wrapping_add(
                            self.rd
                                .decode_tree_reversed(&mut bm_dis[base..], direct_bits),
                        );
                    } else {
                        let high = self.rd.decode(direct_bits - DIS_ALIGN_BITS);
                        rep[0] = rep[0].wrapping_add(high.wrapping_shl(DIS_ALIGN_BITS));
                        rep[0] = rep[0].wrapping_add(
                            self.rd.decode_tree_reversed(&mut bm_align, DIS_ALIGN_BITS),
                        );
                        if rep[0] == 0xffff_ffff {
                            self.flush();
                            return len == MIN_MATCH_LEN;
                        }
                    }
                }
                state = if state < 7 { 7 } else { 10 };
                if u64::from(rep[0]) >= self.dict_size
                    || (u64::from(rep[0]) >= self.pos && !self.wrapped)
                {
                    self.flush();
                    return false;
                }
            }
            for _ in 0..len {
                let b = self.peek(rep[0]);
                self.put(b);
            }
        }
        self.flush();
        false
    }
}

/// `lz_get_dict_size`: 0 when out of range. The fraction is quarters
/// (`dict_size >> 2`), where the lzip format's is sixteenths: a header
/// with fraction bits gets a smaller dictionary than its writer meant
/// (defined, so kept: a stream reaching past it fails).
fn dict_size(c: u8) -> u32 {
    let d: u32 = 1 << (c & 0x1f);
    // Unsigned, as in C: five to seven quarters wrap, and the range check
    // below refuses the result.
    let d = d.wrapping_sub((d >> 2).wrapping_mul(u32::from((c >> 5) & 0x7)));
    if !(MIN_DICTIONARY_SIZE..=MAX_DICTIONARY_SIZE).contains(&d) {
        return 0;
    }
    d
}

/// `unlz`: the first member of `input` (after `pre`, the bytes already
/// read) to `out`. A write that fails ends the decode here and is the
/// `Err`: unlz.c ignores it, decodes to the end and reports success, which
/// would then say nothing about the lost output (Implementer ruling). So
/// does a dictionary buffer that would pass `max_buffer` bytes (the
/// sandbox's bound; a real run passes `u64::MAX`, the dictionary's own
/// 512 MiB limit then holding).
pub(super) fn unlz(
    input: &mut dyn Read,
    pre: &[u8],
    out: &mut dyn Write,
    max_buffer: u64,
) -> Outcome {
    let mut header = [0u8; HDR_SIZE];
    header[..pre.len()].copy_from_slice(pre);
    // One `read` of the rest of the header: short is a failure.
    let want = HDR_SIZE - pre.len();
    let mut got = 0;
    while got < want {
        match input.read(&mut header[pre.len() + got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Ok(None),
        }
    }
    if got != want || header[..5] != HDRMAGIC {
        return Ok(None);
    }
    let ds = dict_size(header[5]);
    if ds == 0 {
        return Ok(None);
    }
    let mut fp = Getc {
        r: input,
        buf: Box::new([0; 4096]),
        pos: 0,
        len: 0,
        eof: false,
        err: false,
    };
    let mut code = 0u32;
    for _ in 0..5 {
        code = (code << 8) | u32::from(fp.getc());
    }
    if fp.err {
        return Ok(None);
    }
    let mut lz = Decoder {
        rd: RangeDecoder {
            fp,
            code,
            range: u32::MAX,
        },
        out,
        failed: None,
        pos: 0,
        ppos: 0,
        spos: 0,
        dict_size: u64::from(ds),
        wrapped: false,
        crc: flate2::Crc::new(),
        obuf: Vec::new(),
        max_buffer,
    };
    let ok = lz.decode_member();
    if let Some(e) = lz.failed.take() {
        return Err(e);
    }
    if !ok {
        return Ok(None);
    }
    let mut trailer = [0u8; TRAILER_SIZE];
    for b in &mut trailer {
        *b = lz.rd.fp.getc();
    }
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let data_size = u64::from_le_bytes(trailer[4..12].try_into().unwrap_or([0; 8]));
    if crc != lz.crc.sum() || data_size != lz.data_position() {
        return Ok(None);
    }
    let member_size = u64::from_le_bytes(trailer[12..20].try_into().unwrap_or([0; 8]));
    Ok(Some((data_size, member_size)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_sizes_are_lzips() {
        assert_eq!(dict_size(12), 4096);
        assert_eq!(dict_size(23), 8 << 20);
        assert_eq!(dict_size(29), 1 << 29);
        assert_eq!(dict_size(30), 0);
        assert_eq!(dict_size(11), 0);
        // unlz.c takes quarters off where lzip takes sixteenths: 2^20
        // minus 3/4, and four quarters leave nothing (refused).
        assert_eq!(dict_size(20 | (3 << 5)), (1 << 20) - 3 * (1 << 18));
        assert_eq!(dict_size(20 | (4 << 5)), 0);
        // Five to seven quarters take more than there is: unlz.c's
        // unsigned subtraction wraps, and the range check refuses it.
        for frac in 5u8..=7 {
            assert_eq!(dict_size(20 | (frac << 5)), 0, "fraction {frac}");
            assert_eq!(dict_size(12 | (frac << 5)), 0, "fraction {frac}");
        }
        assert_eq!(dict_size(31 | (7 << 5)), 0);
        assert_eq!(dict_size(0xff), 0);
        // Every header byte is judged without a panic.
        for c in 0..=255u8 {
            let _ = dict_size(c);
        }
    }

    #[test]
    fn a_header_that_is_not_lzip_fails() {
        let mut out = Vec::new();
        assert!(matches!(
            unlz(&mut &b"LZIP\x02\x14"[..], &[], &mut out, u64::MAX),
            Ok(None)
        ));
        assert!(matches!(
            unlz(&mut &b"LZI"[..], &[], &mut out, u64::MAX),
            Ok(None)
        ));
        assert!(matches!(
            unlz(&mut &b"\x1e"[..], b"LZIP\x01", &mut out, u64::MAX),
            Ok(None)
        ));
    }
}
