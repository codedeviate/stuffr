//! Apple's `zopen.c` (file_cmds-479 `compress/`, the Regents of the
//! University of California, BSD-3-Clause, `LICENSE-compress-bsd`): the
//! LZW coder `compress` writes and reads through stdio's `funopen`.
//!
//! [`Encoder`] is `zwrite`, `output`, `cl_block`, `cl_hash` and `zclose`'s
//! write half, state for state: the hash (`hsize` 69001, so `hshift` 8),
//! the 16-byte code buffer whose stale bytes a width change writes out
//! whole, the ratio check every 10 000 input bytes once the table is full
//! (`rat > ratio` keeps the table, anything else is a CLEAR), the maxbits-9
//! table that widens to 10-bit codes when entry 512 would be next, and a
//! header of `maxbits | 0x80` for any maxbits from 1 to 16 (ruling E1: Apple's
//! `-b 1` to `-b 8` bytes are reproduced; no entry ever fits below 2^9, so
//! the stream is 9-bit literals and CLEARs). An empty input writes nothing,
//! not even the header: `zwrite` is never called and `zclose` outputs a
//! code of width 0 (ruling E2).
//!
//! [`Decoder`] is `zread` and `getcode`: the first code is written as its
//! low byte without any check (`*bp++ = (u_char)finchar`); codes are read
//! in groups of `n_bits` bytes, a short last group rounded down to whole
//! codes and still yielding one from whatever its buffer held before; a
//! code past the next free entry is `EINVAL`, a bad magic `EFTYPE`, and a
//! read error ends the input like its end. Two changes, both deviations of
//! `apple/mod.rs`: the header's maxbits may be anything up to 16 (Apple
//! refuses below 12: A1, with ruling E1 widening it to every maxbits
//! ncompress's decoder accepts), and a table chain longer than the stack
//! (only reachable through the unchecked first code; C overflows its
//! stack there) is `EINVAL`.
//!
//! This is not gzip's `zread.rs`: that ports `gzip/zuncompress.c`, which
//! checks the first code like the rest and answers `EFTYPE` for a bad
//! code, and keeps Apple's refusal below 12 bits.

use std::io::{self, Read, Write};

/// `BITS`: the most bits a code may have.
const BITS: u32 = 16;
/// `HSIZE`: the hash table's size (95% occupancy at 16 bits).
const HSIZE: usize = 69001;
/// `hshift` for `HSIZE`: `zwrite` counts how often 69001 must double to
/// reach 65536 (never), and takes 8 minus that.
const HSHIFT: u32 = 8;
const BIT_MASK: u8 = 0x1f;
const BLOCK_MASK: u8 = 0x80;
const INIT_BITS: u32 = 9;
/// `CHECK_GAP`: the ratio check interval, in input bytes.
const CHECK_GAP: i64 = 10000;
const FIRST: i64 = 257;
const CLEAR: i64 = 256;
const MAGIC: [u8; 2] = [0x1f, 0x9d];
const LMASK: [u8; 9] = [0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80, 0x00];
const RMASK: [u8; 9] = [0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];

fn maxcode(n_bits: u32) -> i64 {
    (1i64 << n_bits) - 1
}

/// `zopen`'s check of its `bits` argument: `bits < 0 || bits > BITS` is
/// `EINVAL`, before anything is opened; 0 means [`BITS`].
pub(super) fn bits_in_range(bits: i32) -> bool {
    (0..=BITS as i32).contains(&bits)
}

/// The compressing half of `struct s_zstate`, writing to `fp`.
pub(super) struct Encoder<W: Write> {
    fp: W,
    /// `state != S_START`: the header is out.
    started: bool,
    n_bits: u32,
    maxbits: u32,
    maxcode: i64,
    maxmaxcode: i64,
    htab: Vec<i64>,
    codetab: Vec<u16>,
    free_ent: i64,
    clear_flg: bool,
    ratio: i64,
    checkpoint: i64,
    offset: u32,
    in_count: i64,
    bytes_out: i64,
    buf: [u8; BITS as usize],
    ent: i64,
    /// A write to `fp` failed: `output` returned before resetting `offset`,
    /// so another code would land past `buf` (C writes over the rest of
    /// its state there). Nothing more is encoded.
    broken: bool,
}

impl<W: Write> Encoder<W> {
    /// `zopen(fname, "w", bits)` once the file is open; `bits` passed
    /// [`bits_in_range`].
    pub(super) fn new(fp: W, bits: i32) -> Self {
        let maxbits = if bits == 0 { BITS } else { bits as u32 };
        Encoder {
            fp,
            started: false,
            n_bits: 0,
            maxbits,
            maxcode: 0,
            maxmaxcode: 1i64 << maxbits,
            htab: vec![-1; HSIZE],
            codetab: vec![0; HSIZE],
            free_ent: 0,
            clear_flg: false,
            ratio: 0,
            checkpoint: CHECK_GAP,
            offset: 0,
            in_count: 1,
            bytes_out: 0,
            buf: [0; BITS as usize],
            ent: 0,
            broken: false,
        }
    }

    /// `zwrite`.
    pub(super) fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let mut bp = data;
        if bp.is_empty() {
            return Ok(());
        }
        if self.broken {
            return Err(io::Error::other("an earlier write failed"));
        }
        if !self.started {
            self.started = true;
            self.maxmaxcode = 1i64 << self.maxbits;
            let header = [MAGIC[0], MAGIC[1], self.maxbits as u8 | BLOCK_MASK];
            self.put(&header)?;
            self.offset = 0;
            self.bytes_out = 3;
            self.clear_flg = false;
            self.ratio = 0;
            self.in_count = 1;
            self.checkpoint = CHECK_GAP;
            self.n_bits = INIT_BITS;
            self.maxcode = maxcode(INIT_BITS);
            self.free_ent = FIRST;
            self.ent = i64::from(bp[0]);
            bp = &bp[1..];
            self.htab.fill(-1);
        }
        'next: for &c in bp {
            self.in_count += 1;
            let fcode = (i64::from(c) << self.maxbits) + self.ent;
            // Xor hashing; below 65536, so inside the table.
            let mut i = ((i64::from(c) << HSHIFT) ^ self.ent) as usize;
            if self.htab[i] == fcode {
                self.ent = i64::from(self.codetab[i]);
                continue;
            }
            if self.htab[i] >= 0 {
                // Secondary hash (after G. Knott).
                let disp = if i == 0 { 1 } else { HSIZE - i };
                loop {
                    i = if i >= disp {
                        i - disp
                    } else {
                        i + HSIZE - disp
                    };
                    if self.htab[i] == fcode {
                        self.ent = i64::from(self.codetab[i]);
                        continue 'next;
                    }
                    if self.htab[i] < 0 {
                        break;
                    }
                }
            }
            // nomatch:
            self.output(self.ent)?;
            self.ent = i64::from(c);
            if self.free_ent < self.maxmaxcode {
                self.codetab[i] = self.free_ent as u16;
                self.free_ent += 1;
                self.htab[i] = fcode;
            } else if self.in_count >= self.checkpoint {
                self.cl_block()?;
            }
        }
        Ok(())
    }

    /// `zclose` of a stream opened for writing: the last code and the
    /// buffer's rest, then the file flushed. An empty input writes nothing
    /// (see the module doc).
    pub(super) fn finish(&mut self) -> io::Result<()> {
        if self.started && !self.broken {
            self.output(self.ent)?;
            self.output_eof()?;
        }
        self.fp.flush()
    }

    /// The writer, for a caller that must close it itself.
    pub(super) fn get_mut(&mut self) -> &mut W {
        &mut self.fp
    }

    /// `fwrite(.., fp)`, remembering a failure.
    fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        let r = self.fp.write_all(bytes);
        self.broken |= r.is_err();
        r
    }

    /// `output(zs, ocode)` for a code (`ocode >= 0`).
    fn output(&mut self, ocode: i64) -> io::Result<()> {
        let n_bits = self.n_bits as usize;
        let mut r_off = self.offset as usize;
        let mut bits = n_bits;
        let mut bp = r_off >> 3;
        r_off &= 7;
        // The first byte keeps its low `r_off` bits.
        self.buf[bp] = (self.buf[bp] & RMASK[r_off]) | ((ocode << r_off) as u8 & LMASK[r_off]);
        bp += 1;
        bits -= 8 - r_off;
        let mut oc = ocode >> (8 - r_off);
        if bits >= 8 {
            self.buf[bp] = oc as u8;
            bp += 1;
            oc >>= 8;
            bits -= 8;
        }
        if bits > 0 {
            self.buf[bp] = oc as u8;
        }
        self.offset += self.n_bits;
        if self.offset == self.n_bits << 3 {
            let group = self.buf;
            self.put(&group[..n_bits])?;
            self.bytes_out += n_bits as i64;
            self.offset = 0;
        }
        // The next entry would not fit: the whole buffer goes out, stale
        // bytes and all, because the reader only learns of the new width
        // after reading it.
        if self.free_ent > self.maxcode || self.clear_flg {
            if self.offset > 0 {
                let group = self.buf;
                self.put(&group[..n_bits])?;
                self.bytes_out += n_bits as i64;
            }
            self.offset = 0;
            if self.clear_flg {
                self.n_bits = INIT_BITS;
                self.maxcode = maxcode(INIT_BITS);
                self.clear_flg = false;
            } else {
                self.n_bits += 1;
                self.maxcode = if self.n_bits == self.maxbits {
                    self.maxmaxcode
                } else {
                    maxcode(self.n_bits)
                };
            }
        }
        Ok(())
    }

    /// `output(zs, -1)`: the rest of the buffer, rounded up to whole bytes.
    fn output_eof(&mut self) -> io::Result<()> {
        if self.offset > 0 {
            let n = self.offset.div_ceil(8) as usize;
            let group = self.buf;
            self.put(&group[..n])?;
            self.bytes_out += n as i64;
        }
        self.offset = 0;
        Ok(())
    }

    /// `cl_block`: the table is full; keep it while the ratio improves,
    /// else clear it and say so.
    fn cl_block(&mut self) -> io::Result<()> {
        self.checkpoint = self.in_count + CHECK_GAP;
        let rat = if self.in_count > 0x007f_ffff {
            // The shift below would overflow.
            let r = self.bytes_out >> 8;
            if r == 0 {
                0x7fff_ffff
            } else {
                self.in_count / r
            }
        } else {
            // 8 fractional bits.
            (self.in_count << 8) / self.bytes_out
        };
        if rat > self.ratio {
            self.ratio = rat;
        } else {
            self.ratio = 0;
            self.htab.fill(-1);
            self.free_ent = FIRST;
            self.clear_flg = true;
            self.output(CLEAR)?;
        }
        Ok(())
    }
}

/// Why [`Decoder::zread`] failed: the `errno` `zread` sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ZFail {
    /// `EFTYPE`: the input does not start with a `.Z` header.
    Format,
    /// `EINVAL`: a code past the next free entry ("bad stream").
    Code,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Middle,
    Eof,
}

/// The decompressing half of `struct s_zstate`, reading `fp`.
pub(super) struct Decoder<R: Read> {
    fp: R,
    state: State,
    n_bits: u32,
    maxbits: u32,
    maxcode: i64,
    maxmaxcode: i64,
    free_ent: i64,
    block_compress: bool,
    clear_flg: bool,
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    stack: Vec<u8>,
    finchar: u8,
    oldcode: i64,
    incode: i64,
    roffset: i64,
    size: i64,
    /// One past `BITS`: a code ending on the group's last bit reads the
    /// byte after it, masked to nothing.
    gbuf: [u8; BITS as usize + 1],
    /// The stream held its header and nothing else.
    empty: bool,
}

/// `fread(buf, 1, n, fp)`: as many bytes as there are, up to `buf.len()`;
/// an error ends it like the end of the input.
fn fread(fp: &mut dyn Read, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        match fp.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    got
}

impl<R: Read> Decoder<R> {
    /// `zopen(fname, "r", bits)` once the file is open.
    pub(super) fn new(fp: R) -> Self {
        Decoder {
            fp,
            state: State::Start,
            n_bits: 0,
            maxbits: 0,
            maxcode: 0,
            maxmaxcode: 0,
            free_ent: 0,
            block_compress: true,
            clear_flg: false,
            prefix: vec![0; 1 << BITS],
            suffix: vec![0; 1 << BITS],
            stack: Vec::with_capacity(1 << BITS),
            finchar: 0,
            oldcode: -1,
            incode: 0,
            roffset: 0,
            size: 0,
            gbuf: [0; BITS as usize + 1],
            empty: false,
        }
    }

    /// Whether the stream was a header and nothing more: `zread`'s first
    /// call returned 0 without an error (deviation A3's case).
    pub(super) fn was_empty(&self) -> bool {
        self.empty
    }

    /// `zread`: up to `out.len()` bytes, 0 at the end. A failing call's
    /// bytes are lost with it, as stdio loses them.
    pub(super) fn zread(&mut self, out: &mut [u8]) -> Result<usize, ZFail> {
        let num = out.len();
        if num == 0 {
            return Ok(0);
        }
        let mut count = num;
        let mut bp = 0;
        let mut resume = match self.state {
            State::Eof => return Ok(0),
            State::Middle => true,
            State::Start => {
                self.state = State::Middle;
                self.start()?;
                // The first code is a character, unchecked.
                let code = self.getcode();
                if code == -1 {
                    // "EOF already?" Apple leaves the state in the middle,
                    // its stack unset; nothing reads it again.
                    self.state = State::Eof;
                    self.empty = true;
                    return Ok(0);
                }
                self.oldcode = code;
                self.finchar = code as u8;
                out[0] = code as u8;
                bp = 1;
                count -= 1;
                self.stack.clear();
                false
            }
        };
        loop {
            if !resume {
                let mut code = self.getcode();
                if code < 0 {
                    break;
                }
                if code == CLEAR && self.block_compress {
                    self.prefix[..256].fill(0);
                    self.clear_flg = true;
                    self.free_ent = FIRST;
                    self.oldcode = -1;
                    continue;
                }
                self.incode = code;
                // The KwKwK case.
                if code >= self.free_ent {
                    if code > self.free_ent || self.oldcode == -1 {
                        return Err(ZFail::Code);
                    }
                    self.stack.push(self.finchar);
                    code = self.oldcode;
                }
                // In order, each step lowers the code, so the stack stays
                // under 64 KiB; the unchecked first code can start a chain
                // that does not, where C overflows its stack.
                while code >= 256 {
                    if self.stack.len() >= 1 << BITS {
                        return Err(ZFail::Code);
                    }
                    self.stack.push(self.suffix[code as usize]);
                    code = i64::from(self.prefix[code as usize]);
                }
                self.finchar = self.suffix[code as usize];
                self.stack.push(self.finchar);
            }
            resume = false;
            // Out in forward order; a full `out` keeps the rest for the
            // next call (`middle:`).
            loop {
                if count == 0 {
                    return Ok(num);
                }
                count -= 1;
                out[bp] = self.stack.pop().unwrap_or(0);
                bp += 1;
                if self.stack.is_empty() {
                    break;
                }
            }
            // The new entry.
            let code = self.free_ent;
            if code < self.maxmaxcode && self.oldcode != -1 {
                self.prefix[code as usize] = self.oldcode as u16;
                self.suffix[code as usize] = self.finchar;
                self.free_ent = code + 1;
            }
            self.oldcode = self.incode;
        }
        self.state = State::Eof;
        Ok(num - count)
    }

    /// `zread`'s `S_START` part: the magic, the bit count, the table.
    fn start(&mut self) -> Result<(), ZFail> {
        let mut header = [0u8; 3];
        if fread(&mut self.fp, &mut header) != 3 || header[..2] != MAGIC {
            return Err(ZFail::Format);
        }
        self.block_compress = header[2] & BLOCK_MASK != 0;
        self.maxbits = u32::from(header[2] & BIT_MASK);
        self.maxmaxcode = 1i64 << self.maxbits;
        // Apple: `maxbits > BITS || maxbits < 12` (deviation A1).
        if self.maxbits > BITS {
            return Err(ZFail::Format);
        }
        self.n_bits = INIT_BITS;
        self.maxcode = maxcode(INIT_BITS);
        for c in 0..256usize {
            self.prefix[c] = 0;
            self.suffix[c] = c as u8;
        }
        self.free_ent = if self.block_compress { FIRST } else { 256 };
        Ok(())
    }

    /// `getcode`: the next code, or -1 at the end of the input.
    fn getcode(&mut self) -> i64 {
        if self.clear_flg || self.roffset >= self.size || self.free_ent > self.maxcode {
            // The next entry needs more bits: a new group, read whole.
            if self.free_ent > self.maxcode {
                self.n_bits += 1;
                self.maxcode = if self.n_bits == self.maxbits {
                    self.maxmaxcode
                } else {
                    maxcode(self.n_bits)
                };
            }
            if self.clear_flg {
                self.n_bits = INIT_BITS;
                self.maxcode = maxcode(INIT_BITS);
                self.clear_flg = false;
            }
            let n = self.n_bits as usize;
            let got = fread(&mut self.fp, &mut self.gbuf[..n]);
            if got == 0 {
                return -1;
            }
            self.roffset = 0;
            // Rounded down to a whole number of codes.
            self.size = ((got as i64) << 3) - (i64::from(self.n_bits) - 1);
        }
        let mut r_off = self.roffset as usize;
        let mut bits = self.n_bits as usize;
        let mut bp = r_off >> 3;
        r_off &= 7;
        let mut gcode = i64::from(self.gbuf[bp] >> r_off);
        bp += 1;
        bits -= 8 - r_off;
        r_off = 8 - r_off;
        if bits >= 8 {
            gcode |= i64::from(self.gbuf[bp]) << r_off;
            bp += 1;
            r_off += 8;
            bits -= 8;
        }
        gcode |= i64::from(self.gbuf[bp] & RMASK[bits]) << r_off;
        self.roffset += i64::from(self.n_bits);
        gcode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(data: &[u8], bits: i32) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new(), bits);
        // Pieces of odd sizes: `zwrite` keeps its state between calls.
        for piece in data.chunks(777) {
            e.write(piece).unwrap();
        }
        e.finish().unwrap();
        e.fp
    }

    fn decode(z: &[u8]) -> Result<Vec<u8>, ZFail> {
        let mut d = Decoder::new(z);
        let mut out = Vec::new();
        loop {
            let mut buf = [0u8; 1024];
            match d.zread(&mut buf)? {
                0 => return Ok(out),
                n => out.extend_from_slice(&buf[..n]),
            }
        }
    }

    fn sample(n: usize) -> Vec<u8> {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        (0..n)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                // Mostly text-like, with runs, so the table fills and clears.
                if i % 3000 < 1000 {
                    b'a' + (x % 7) as u8
                } else {
                    (x >> 32) as u8
                }
            })
            .collect()
    }

    /// Every bit count Apple accepts reads back, `-b 1` to `-b 8` (header
    /// below 9, 9-bit literals) included, at a size that fills every table.
    #[test]
    fn every_bit_count_reads_back() {
        let data = sample(300_000);
        for bits in 0..=16 {
            let z = encode(&data, bits);
            let want = if bits == 0 { 16 } else { bits as u8 };
            assert_eq!(z[..3], [0x1f, 0x9d, 0x80 | want], "-b {bits}");
            assert_eq!(decode(&z).unwrap(), data, "-b {bits}");
        }
    }

    /// Ruling E2: no input, no bytes; and `zopen`'s range.
    #[test]
    fn an_empty_input_writes_nothing() {
        assert!(encode(b"", 16).is_empty());
        assert!(bits_in_range(0) && bits_in_range(16));
        assert!(!bits_in_range(-1) && !bits_in_range(17));
    }

    /// Hand-checked: `A` alone is the header and one 9-bit code; `AAAA`
    /// is `A`, entry 257 (`AA`), `A`.
    #[test]
    fn small_streams_are_bit_exact() {
        assert_eq!(encode(b"A", 16), [0x1f, 0x9d, 0x90, 0x41, 0x00]);
        assert_eq!(
            encode(b"AAAA", 16),
            [0x1f, 0x9d, 0x90, 0x41, 0x02, 0x06, 0x01]
        );
    }

    /// The decoder's quirks: the first code is written unchecked as its low
    /// byte; a lone short group still yields a code; a header and nothing
    /// is an empty stream; a bad code is `EINVAL`, a bad magic `EFTYPE`,
    /// and a header asking for more than 16 bits `EFTYPE`.
    #[test]
    fn the_decoder_reads_as_zopen_c_does() {
        // 0x1ff, then 0x1ff again: past free_ent (257).
        assert_eq!(
            decode(&[0x1f, 0x9d, 0x90, 0xff, 0xff, 0x03]),
            Err(ZFail::Code)
        );
        assert_eq!(decode(&[0x1f, 0x9d, 0x90, 0xff, 0x01]), Ok(vec![0xff]));
        assert_eq!(decode(&[0x1f, 0x9d, 0x90, 0x41]), Ok(b"A".to_vec()));
        let mut d = Decoder::new(&[0x1f, 0x9d, 0x90][..]);
        assert_eq!(d.zread(&mut [0; 16]), Ok(0));
        assert!(d.was_empty());
        assert_eq!(decode(&[0x1f, 0x9d]), Err(ZFail::Format));
        assert_eq!(decode(b"plain text"), Err(ZFail::Format));
        assert_eq!(decode(&[0x1f, 0x9d, 0x91, 0x41, 0x00]), Err(ZFail::Format));
        // Header maxbits 1 and 9 (Apple refuses both; deviation A1).
        assert_eq!(decode(&[0x1f, 0x9d, 0x81, 0x41, 0x00]), Ok(b"A".to_vec()));
        assert_eq!(decode(&[0x1f, 0x9d, 0x89, 0x41, 0x00]), Ok(b"A".to_vec()));
    }
}
