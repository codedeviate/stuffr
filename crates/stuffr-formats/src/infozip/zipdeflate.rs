//! Info-ZIP Zip 3.0's deflate encoder, `deflate.c` and `trees.c` (identical
//! in Apple's zip-33 tree and upstream), for the `zip` compatibility
//! family, whose archives must equal the references' byte for byte.
//!
//! The stream depends on more than the deflate format: on the window and
//! buffer sizes (`WSIZE` 32 KiB, `HASH_BITS` 15, `LIT_BUFSIZE` and
//! `DIST_BUFSIZE` 0x8000), on the order of reads (`lm_init` asks for 64 KiB,
//! `fill_window` for the free space), on the lazy and fast match loops, on
//! `ct_tally`'s early block cut, and on `flush_block`'s choice between a
//! stored, static or dynamic block. Everything here is ported line by line
//! from the non-ASM C (`longest_match` without `UNALIGNED_OK`, which is the
//! build on both references: Apple's arm64 build runs no `configure`, and
//! `unix/configure`'s `match.S` probe fails on anything but i386, so neither
//! aarch64 nor x86_64 Ubuntu defines `ASMV`). Neither reference defines
//! `MMAP`, `BIG_MEM`, `SMALL_MEM`, `MEDIUM_MEM`, `FORCE_METHOD`, `FILTERED`
//! or `DEFL_UNDETERM`, so neither does this port.
//!
//! The input is read as `zipup.c`'s `file_read` reads a regular file
//! (`translate_eol` 0): every request is filled until the end of the input,
//! whatever the reader returns per call; or, with
//! [`ZipDeflater::set_one_read`], one `read` per request, as `zread` does
//! (the zip family's own reader then does `-l`/`-ll`'s translation and
//! the short reads of a pipe). The CRC-32 and the byte count are taken over
//! what is read, as there. The output is written in the C's pieces (each
//! `flush_outbuf`), which zip's `-dg` dots count.
//!
//! **Stored fallback.** `flush_block` rewrites an entry that is one block
//! which does not pay as a stored entry (method 0) when the archive is
//! seekable and descriptors are not in use; [`ZipDeflater::set_store_fallback`]
//! is that condition, and [`DeflateSummary::stored`] says it happened (the
//! output is then the input).

use std::io::{self, Read, Write};

use super::crypt::crc32;

// zip.h
const MIN_MATCH: u32 = 3;
const MAX_MATCH: u32 = 258;
const WSIZE: u32 = 0x8000;
const MIN_LOOKAHEAD: u32 = MAX_MATCH + MIN_MATCH + 1;
const MAX_DIST: u32 = WSIZE - MIN_LOOKAHEAD;

// deflate.c
const HASH_BITS: u32 = 15;
const HASH_SIZE: u32 = 1 << HASH_BITS;
const HASH_MASK: u32 = HASH_SIZE - 1;
const WMASK: u32 = WSIZE - 1;
const NIL: u32 = 0;
const FAST: u16 = 4;
const SLOW: u16 = 2;
const TOO_FAR: u32 = 4096;
/// `(HASH_BITS+MIN_MATCH-1)/MIN_MATCH`.
const H_SHIFT: u32 = HASH_BITS.div_ceil(MIN_MATCH);
/// `window_size` with `sliding` set: neither reference maps the input.
const WINDOW_SIZE: u32 = 2 * WSIZE;

/// `configuration_table`: good, lazy, nice, chain per level 0..=9.
const CONFIGURATION_TABLE: [(u32, u32, i32, u32); 10] = [
    (0, 0, 0, 0),
    (4, 4, 8, 4),
    (4, 5, 16, 8),
    (4, 6, 32, 32),
    (4, 4, 16, 16),
    (8, 16, 32, 32),
    (8, 16, 128, 128),
    (8, 32, 128, 256),
    (32, 128, 258, 1024),
    (32, 258, 258, 4096),
];

// trees.c
const MAX_BITS: usize = 15;
const MAX_BL_BITS: usize = 7;
const LENGTH_CODES: usize = 29;
const LITERALS: usize = 256;
const END_BLOCK: usize = 256;
const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
const D_CODES: usize = 30;
const BL_CODES: usize = 19;
const EXTRA_LBITS: [u32; LENGTH_CODES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const EXTRA_DBITS: [u32; D_CODES] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const EXTRA_BLBITS: [u32; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];
const STORED_BLOCK: u32 = 0;
const STATIC_TREES: u32 = 1;
const DYN_TREES: u32 = 2;
const LIT_BUFSIZE: usize = 0x8000;
const DIST_BUFSIZE: usize = LIT_BUFSIZE;
const REP_3_6: usize = 16;
const REPZ_3_10: usize = 17;
const REPZ_11_138: usize = 18;
const HEAP_SIZE: usize = 2 * L_CODES + 1;
const BL_ORDER: [usize; BL_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
const SMALLEST: usize = 1;
/// `Buf_size`: the bits of `bi_buf` in use.
const BUF_SIZE: u32 = 16;

/// `ct_data`: `fc` is the union of `Freq` and `Code`, `dl` of `Dad` and
/// `Len`. The C relies on the aliasing (`gen_bitlen` overwrites `Dad` with
/// `Len`; `scan_tree`'s guard writes a `Len`), so the port keeps one field
/// for each union.
#[derive(Clone, Copy, Default)]
struct CtData {
    fc: u16,
    dl: u16,
}

/// Which of `l_desc`, `d_desc`, `bl_desc`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Desc {
    L,
    D,
    Bl,
}

impl Desc {
    /// (`elems`, `max_length`, `extra_bits`, `extra_base`).
    fn shape(self) -> (usize, usize, &'static [u32], usize) {
        match self {
            Desc::L => (L_CODES, MAX_BITS, &EXTRA_LBITS, LITERALS + 1),
            Desc::D => (D_CODES, MAX_BITS, &EXTRA_DBITS, 0),
            Desc::Bl => (BL_CODES, MAX_BL_BITS, &EXTRA_BLBITS, 0),
        }
    }
}

/// What one [`ZipDeflater::compress`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateSummary {
    /// Bytes read (zip's `isize`).
    pub in_bytes: u64,
    /// Bytes written (`flush_block`'s return, zip's `s`).
    pub out_bytes: u64,
    /// CRC-32 of the bytes read.
    pub crc32: u32,
    /// General-purpose flag bits 1–2 as `lm_init` sets them: 4 (`FAST`) at
    /// levels 1–2, 2 (`SLOW`) at 8–9, else 0.
    pub gp_flags: u16,
    /// `flush_block` rewrote the entry as stored (`*file_method = STORE`):
    /// the output is the input. Only with the stored fallback allowed.
    pub stored: bool,
    /// `set_file_type`'s verdict on the first block: `ASCII` (true) or
    /// `BINARY`, the internal file attributes' bit 0.
    pub text: bool,
    /// How many times `fill_window` slid the window: zip prints its `-dd`
    /// progress dots there.
    pub slides: u64,
}

/// Where [`ZipDeflater::compress_to`] writes: the archive, which
/// `flush_block` asks once per entry whether it can be rewound (trees.c's
/// `seekable()`, zip's `fseekable(y)`), when an entry is one block that does
/// not pay.
pub trait ZipOut: Write {
    /// `seekable()`.
    fn seekable(&mut self) -> bool;
}

/// A plain `Write`, always seekable ([`ZipDeflater::compress`]).
struct Seekable<'a>(&'a mut dyn Write);

impl Write for Seekable<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl ZipOut for Seekable<'_> {
    fn seekable(&mut self) -> bool {
        true
    }
}

/// The C's `error("block vanished")` (`ZE_LOGIC`): a stored entry's only
/// block has left the window. The error [`ZipDeflater::compress`] returns
/// for it carries this, so a caller can tell it from a read or write error
/// (`e.get_ref().is_some_and(|i| i.is::<BlockVanished>())`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockVanished;

impl std::fmt::Display for BlockVanished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("block vanished")
    }
}

impl std::error::Error for BlockVanished {}

/// trees.c's `out_size` for file compression: zipup's `file_outbuf[1024]`.
const OUT_SIZE: usize = 1024;

/// `zipup.c`'s I/O for one entry: `file_read` (with its CRC and `isize`),
/// the bit buffer of `bi_init`, and `flush_outbuf`.
///
/// The output is handed on in the C's pieces: each `flush_outbuf` of the
/// 1024-byte `out_buf` (when `PUTSHORT` or `PUTBYTE` finds it full, at
/// `bi_windup`, around a stored block) is one `write_all` of `out`, and a
/// stored block's data is one more. The bytes are the same either way; zip's
/// `-dg` counts its dots by those writes.
struct Io<'a> {
    input: &'a mut dyn Read,
    out: &'a mut dyn ZipOut,
    /// The running CRC register (inverted, as `crc32()` keeps it inside).
    crc: u32,
    isize: u64,
    bi_buf: u32,
    bi_valid: u32,
    buf: Vec<u8>,
    /// Where the C's `out_buf` begins in `buf` (`out_offset` is
    /// `buf.len() - seg`).
    seg: usize,
    /// The ends in `buf` of the `flush_outbuf` calls not yet handed on.
    cuts: Vec<usize>,
    written: u64,
    /// One `read` per request (zipup's `zread`), not a filled request.
    one_read: bool,
}

impl Io<'_> {
    /// `file_read` with `translate_eol` 0: one `read()` of the input per
    /// request with [`ZipDeflater::set_one_read`], else the request filled
    /// unless the input ends first (what `read()` gives on a regular file);
    /// 0 is the end.
    // port: zipup.c:file_read
    fn read_buf(&mut self, dst: &mut [u8]) -> io::Result<u32> {
        let mut n = 0;
        while n < dst.len() {
            match self.input.read(&mut dst[n..]) {
                Ok(0) => break,
                Ok(k) => {
                    n += k;
                    if self.one_read {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        for &b in &dst[..n] {
            self.crc = crc32(self.crc, b);
        }
        self.isize += n as u64;
        Ok(n as u32)
    }

    /// `flush_outbuf(out_buf, &out_offset)`: the bytes since the last one
    /// make one piece (none when `out_buf` is empty).
    fn cut(&mut self) {
        if self.buf.len() > self.seg {
            self.cuts.push(self.buf.len());
            self.seg = self.buf.len();
        }
    }

    /// `PUTSHORT`.
    fn put_short(&mut self, w: u16) {
        if self.buf.len() - self.seg >= OUT_SIZE - 1 {
            self.cut();
        }
        self.buf.extend_from_slice(&w.to_le_bytes());
    }

    /// `PUTBYTE`.
    fn put_byte(&mut self, b: u8) {
        if self.buf.len() - self.seg >= OUT_SIZE {
            self.cut();
        }
        self.buf.push(b);
    }

    // port: trees.c:send_bits
    fn send_bits(&mut self, value: u32, length: u32) {
        self.bi_buf |= value << self.bi_valid;
        self.bi_valid += length;
        if self.bi_valid > BUF_SIZE {
            self.put_short(self.bi_buf as u16);
            self.bi_valid -= BUF_SIZE;
            self.bi_buf = value >> (length - self.bi_valid);
        }
    }

    /// `send_code(c, tree)`.
    fn send_code(&mut self, c: usize, tree: &[CtData]) {
        self.send_bits(u32::from(tree[c].fc), u32::from(tree[c].dl));
    }

    // port: trees.c:bi_windup (`flush_flg` is set for file compression)
    fn bi_windup(&mut self) {
        if self.bi_valid > 8 {
            self.put_short(self.bi_buf as u16);
        } else if self.bi_valid > 0 {
            self.put_byte(self.bi_buf as u8);
        }
        self.cut();
        self.bi_buf = 0;
        self.bi_valid = 0;
    }

    /// Hands the finished pieces to the archive, one `write_all` each (the
    /// C's `flush_outbuf` calls); the part of `out_buf` not yet flushed
    /// stays, unless `all`.
    // port: zipup.c:flush_outbuf
    fn flush(&mut self, all: bool) -> io::Result<()> {
        if all {
            self.cut();
        }
        let mut from = 0;
        for &to in &self.cuts {
            self.out.write_all(&self.buf[from..to])?;
            self.written += (to - from) as u64;
            from = to;
        }
        self.cuts.clear();
        self.buf.drain(..from);
        self.seg -= from;
        Ok(())
    }
}

/// The heap and counters `build_tree` and `gen_bitlen` share (`heap`,
/// `heap_len`, `heap_max`, `depth`, `bl_count`, `opt_len`, `static_len`).
struct Heap {
    heap: [usize; 2 * L_CODES + 1],
    heap_len: usize,
    heap_max: usize,
    depth: [u8; 2 * L_CODES + 1],
    bl_count: [u16; MAX_BITS + 1],
    /// `ulg`, 64 bits on both references; `build_tree` can take it below 0,
    /// so it wraps as the C's does.
    opt_len: u64,
    static_len: u64,
}

/// `smaller(tree, n, m)`.
fn smaller(tree: &[CtData], depth: &[u8], n: usize, m: usize) -> bool {
    tree[n].fc < tree[m].fc || (tree[n].fc == tree[m].fc && depth[n] <= depth[m])
}

// port: trees.c:pqdownheap
fn pqdownheap(h: &mut Heap, tree: &[CtData], mut k: usize) {
    let v = h.heap[k];
    let mut j = k << 1;
    while j <= h.heap_len {
        if j < h.heap_len && smaller(tree, &h.depth, h.heap[j + 1], h.heap[j]) {
            j += 1;
        }
        let htemp = h.heap[j];
        if smaller(tree, &h.depth, v, htemp) {
            break;
        }
        h.heap[k] = htemp;
        k = j;
        j <<= 1;
    }
    h.heap[k] = v;
}

// port: trees.c:gen_bitlen
fn gen_bitlen(
    h: &mut Heap,
    tree: &mut [CtData],
    desc: Desc,
    max_code: usize,
    stree: Option<&[CtData]>,
) {
    let (_, max_length, extra, base) = desc.shape();
    let mut overflow = 0i32;
    h.bl_count = [0; MAX_BITS + 1];

    tree[h.heap[h.heap_max]].dl = 0;
    let mut hh = h.heap_max + 1;
    while hh < HEAP_SIZE {
        let n = h.heap[hh];
        let mut bits = usize::from(tree[usize::from(tree[n].dl)].dl) + 1;
        if bits > max_length {
            bits = max_length;
            overflow += 1;
        }
        tree[n].dl = bits as u16;
        hh += 1;
        if n > max_code {
            continue;
        }
        h.bl_count[bits] = h.bl_count[bits].wrapping_add(1);
        let xbits = if n >= base {
            extra[n - base] as usize
        } else {
            0
        };
        let f = u64::from(tree[n].fc);
        h.opt_len = h.opt_len.wrapping_add(f * (bits + xbits) as u64);
        if let Some(st) = stree {
            h.static_len = h
                .static_len
                .wrapping_add(f * (usize::from(st[n].dl) + xbits) as u64);
        }
    }
    if overflow == 0 {
        return;
    }
    loop {
        let mut bits = max_length - 1;
        while h.bl_count[bits] == 0 {
            bits -= 1;
        }
        h.bl_count[bits] = h.bl_count[bits].wrapping_sub(1);
        h.bl_count[bits + 1] = h.bl_count[bits + 1].wrapping_add(2);
        h.bl_count[max_length] = h.bl_count[max_length].wrapping_sub(1);
        overflow -= 2;
        if overflow <= 0 {
            break;
        }
    }
    let mut hh = HEAP_SIZE;
    for bits in (1..=max_length).rev() {
        let mut n = h.bl_count[bits];
        while n != 0 {
            hh -= 1;
            let m = h.heap[hh];
            if m > max_code {
                continue;
            }
            if usize::from(tree[m].dl) != bits {
                let delta = (bits as i64 - i64::from(tree[m].dl)) * i64::from(tree[m].fc);
                h.opt_len = h.opt_len.wrapping_add(delta as u64);
                tree[m].dl = bits as u16;
            }
            n -= 1;
        }
    }
}

// port: trees.c:bi_reverse
fn bi_reverse(mut code: u32, mut len: u32) -> u32 {
    let mut res = 0;
    loop {
        res |= code & 1;
        code >>= 1;
        res <<= 1;
        len -= 1;
        if len == 0 {
            break;
        }
    }
    res >> 1
}

// port: trees.c:gen_codes
fn gen_codes(tree: &mut [CtData], max_code: usize, bl_count: &[u16; MAX_BITS + 1]) {
    let mut next_code = [0u16; MAX_BITS + 1];
    let mut code = 0u16;
    for bits in 1..=MAX_BITS {
        code = code.wrapping_add(bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }
    for t in &mut tree[..=max_code] {
        let len = usize::from(t.dl);
        if len == 0 {
            continue;
        }
        t.fc = bi_reverse(u32::from(next_code[len]), len as u32) as u16;
        next_code[len] = next_code[len].wrapping_add(1);
    }
}

/// `build_tree`; returns the `max_code` it stores in the descriptor.
// port: trees.c:build_tree
fn build_tree(h: &mut Heap, tree: &mut [CtData], desc: Desc, stree: Option<&[CtData]>) -> usize {
    let (elems, ..) = desc.shape();
    let mut max_code: isize = -1;
    let mut node = elems;
    h.heap_len = 0;
    h.heap_max = HEAP_SIZE;
    for (n, t) in tree[..elems].iter_mut().enumerate() {
        if t.fc != 0 {
            h.heap_len += 1;
            h.heap[h.heap_len] = n;
            max_code = n as isize;
            h.depth[n] = 0;
        } else {
            t.dl = 0;
        }
    }
    while h.heap_len < 2 {
        let new = if max_code < 2 {
            max_code += 1;
            max_code as usize
        } else {
            0
        };
        h.heap_len += 1;
        h.heap[h.heap_len] = new;
        tree[new].fc = 1;
        h.depth[new] = 0;
        h.opt_len = h.opt_len.wrapping_sub(1);
        if let Some(st) = stree {
            h.static_len = h.static_len.wrapping_sub(u64::from(st[new].dl));
        }
    }
    let max_code = max_code as usize;
    for n in (1..=h.heap_len / 2).rev() {
        pqdownheap(h, tree, n);
    }
    loop {
        // pqremove(tree, n)
        let n = h.heap[SMALLEST];
        h.heap[SMALLEST] = h.heap[h.heap_len];
        h.heap_len -= 1;
        pqdownheap(h, tree, SMALLEST);
        let m = h.heap[SMALLEST];
        h.heap_max -= 1;
        h.heap[h.heap_max] = n;
        h.heap_max -= 1;
        h.heap[h.heap_max] = m;
        tree[node].fc = tree[n].fc.wrapping_add(tree[m].fc);
        h.depth[node] = h.depth[n].max(h.depth[m]).wrapping_add(1);
        tree[n].dl = node as u16;
        tree[m].dl = node as u16;
        h.heap[SMALLEST] = node;
        node += 1;
        pqdownheap(h, tree, SMALLEST);
        if h.heap_len < 2 {
            break;
        }
    }
    h.heap_max -= 1;
    h.heap[h.heap_max] = h.heap[SMALLEST];
    gen_bitlen(h, tree, desc, max_code, stree);
    gen_codes(tree, max_code, &h.bl_count);
    max_code
}

/// The `(max_count, min_count)` after a run, in `scan_tree`/`send_tree`.
fn next_counts(curlen: u32, nextlen: u32) -> (u32, u32) {
    if nextlen == 0 {
        (138, 3)
    } else if curlen == nextlen {
        (6, 3)
    } else {
        (7, 4)
    }
}

// port: trees.c:scan_tree
fn scan_tree(tree: &mut [CtData], max_code: usize, bl_tree: &mut [CtData]) {
    let mut prevlen: i64 = -1;
    let mut nextlen = u32::from(tree[0].dl);
    let mut count = 0u32;
    let (mut max_count, mut min_count) = (7, 4);
    if nextlen == 0 {
        (max_count, min_count) = (138, 3);
    }
    tree[max_code + 1].dl = 0xffff; // guard
    for n in 0..=max_code {
        let curlen = nextlen;
        nextlen = u32::from(tree[n + 1].dl);
        count += 1;
        if count < max_count && curlen == nextlen {
            continue;
        } else if count < min_count {
            let f = &mut bl_tree[curlen as usize].fc;
            *f = f.wrapping_add(count as u16);
        } else if curlen != 0 {
            if i64::from(curlen) != prevlen {
                let f = &mut bl_tree[curlen as usize].fc;
                *f = f.wrapping_add(1);
            }
            bl_tree[REP_3_6].fc = bl_tree[REP_3_6].fc.wrapping_add(1);
        } else if count <= 10 {
            bl_tree[REPZ_3_10].fc = bl_tree[REPZ_3_10].fc.wrapping_add(1);
        } else {
            bl_tree[REPZ_11_138].fc = bl_tree[REPZ_11_138].fc.wrapping_add(1);
        }
        count = 0;
        prevlen = i64::from(curlen);
        (max_count, min_count) = next_counts(curlen, nextlen);
    }
}

// port: trees.c:send_tree
fn send_tree(io: &mut Io, tree: &[CtData], max_code: usize, bl_tree: &[CtData]) {
    let mut prevlen: i64 = -1;
    let mut nextlen = u32::from(tree[0].dl);
    let mut count = 0u32;
    let (mut max_count, mut min_count) = (7, 4);
    if nextlen == 0 {
        (max_count, min_count) = (138, 3);
    }
    for n in 0..=max_code {
        let curlen = nextlen;
        nextlen = u32::from(tree[n + 1].dl);
        count += 1;
        if count < max_count && curlen == nextlen {
            continue;
        } else if count < min_count {
            loop {
                io.send_code(curlen as usize, bl_tree);
                count -= 1;
                if count == 0 {
                    break;
                }
            }
        } else if curlen != 0 {
            if i64::from(curlen) != prevlen {
                io.send_code(curlen as usize, bl_tree);
                count -= 1;
            }
            io.send_code(REP_3_6, bl_tree);
            io.send_bits(count - 3, 2);
        } else if count <= 10 {
            io.send_code(REPZ_3_10, bl_tree);
            io.send_bits(count - 3, 3);
        } else {
            io.send_code(REPZ_11_138, bl_tree);
            io.send_bits(count - 11, 7);
        }
        count = 0;
        prevlen = i64::from(curlen);
        (max_count, min_count) = next_counts(curlen, nextlen);
    }
}

/// Zip 3.0's deflate encoder: `deflate.c` and `trees.c` with their
/// globals as fields. One deflater may compress many entries in turn, as
/// zip's globals do.
pub struct ZipDeflater {
    level: u32,
    store_fallback: bool,
    one_read: bool,
    /// zip's `key != NULL`: `copy_block` hands a stored block on in
    /// `out_size` pieces (trees.c's copy for encryption in place).
    encrypting: bool,
    slides: u64,

    // deflate.c
    window: Vec<u8>,
    prev: Vec<u16>,
    head: Vec<u16>,
    block_start: i64,
    ins_h: u32,
    prev_length: u32,
    strstart: u32,
    match_start: u32,
    eofile: bool,
    lookahead: u32,
    max_chain_length: u32,
    max_lazy_match: u32,
    good_match: u32,
    nice_match: i32,
    gp_flags: u16,

    // trees.c
    dyn_ltree: Vec<CtData>,
    dyn_dtree: Vec<CtData>,
    static_ltree: Vec<CtData>,
    static_dtree: Vec<CtData>,
    bl_tree: Vec<CtData>,
    l_max_code: usize,
    d_max_code: usize,
    heap: Heap,
    length_code: [u8; (MAX_MATCH - MIN_MATCH + 1) as usize],
    dist_code: [u8; 512],
    base_length: [u32; LENGTH_CODES],
    base_dist: [u32; D_CODES],
    l_buf: Vec<u8>,
    d_buf: Vec<u16>,
    flag_buf: Vec<u8>,
    last_lit: usize,
    last_dist: usize,
    last_flags: usize,
    flags: u8,
    flag_bit: u8,
    cmpr_bytelen: u64,
    cmpr_len_bits: u64,
    /// `*file_type`: `None` is `UNKNOWN`, else `ASCII`.
    file_type: Option<bool>,
    stored: bool,
}

impl ZipDeflater {
    /// A deflater for `level` (1..=9), with the stored fallback allowed (a
    /// named, seekable archive without `-fd`).
    ///
    /// # Panics
    ///
    /// When `level` is outside 1..=9 (`lm_init`'s "bad pack level").
    // port: trees.c:ct_init (the one-time part)
    pub fn new(level: u8) -> ZipDeflater {
        assert!((1..=9).contains(&level), "bad pack level {level}");
        let mut d = ZipDeflater {
            level: u32::from(level),
            store_fallback: true,
            one_read: false,
            encrypting: false,
            slides: 0,
            window: vec![0; WINDOW_SIZE as usize],
            prev: vec![0; WSIZE as usize],
            head: vec![0; HASH_SIZE as usize],
            block_start: 0,
            ins_h: 0,
            prev_length: 0,
            strstart: 0,
            match_start: 0,
            eofile: false,
            lookahead: 0,
            max_chain_length: 0,
            max_lazy_match: 0,
            good_match: 0,
            nice_match: 0,
            gp_flags: 0,
            dyn_ltree: vec![CtData::default(); HEAP_SIZE],
            dyn_dtree: vec![CtData::default(); 2 * D_CODES + 1],
            static_ltree: vec![CtData::default(); L_CODES + 2],
            static_dtree: vec![CtData::default(); D_CODES],
            bl_tree: vec![CtData::default(); 2 * BL_CODES + 1],
            l_max_code: 0,
            d_max_code: 0,
            heap: Heap {
                heap: [0; 2 * L_CODES + 1],
                heap_len: 0,
                heap_max: 0,
                depth: [0; 2 * L_CODES + 1],
                bl_count: [0; MAX_BITS + 1],
                opt_len: 0,
                static_len: 0,
            },
            length_code: [0; (MAX_MATCH - MIN_MATCH + 1) as usize],
            dist_code: [0; 512],
            base_length: [0; LENGTH_CODES],
            base_dist: [0; D_CODES],
            l_buf: vec![0; LIT_BUFSIZE],
            d_buf: vec![0; DIST_BUFSIZE],
            flag_buf: vec![0; LIT_BUFSIZE / 8],
            last_lit: 0,
            last_dist: 0,
            last_flags: 0,
            flags: 0,
            flag_bit: 1,
            cmpr_bytelen: 0,
            cmpr_len_bits: 0,
            file_type: None,
            stored: false,
        };
        let mut length = 0usize;
        let mut code = 0usize;
        while code < LENGTH_CODES - 1 {
            d.base_length[code] = length as u32;
            for _ in 0..(1u32 << EXTRA_LBITS[code]) {
                d.length_code[length] = code as u8;
                length += 1;
            }
            code += 1;
        }
        d.length_code[length - 1] = code as u8;
        let mut dist = 0usize;
        code = 0;
        while code < 16 {
            d.base_dist[code] = dist as u32;
            for _ in 0..(1u32 << EXTRA_DBITS[code]) {
                d.dist_code[dist] = code as u8;
                dist += 1;
            }
            code += 1;
        }
        dist >>= 7;
        while code < D_CODES {
            d.base_dist[code] = (dist << 7) as u32;
            for _ in 0..(1u32 << (EXTRA_DBITS[code] - 7)) {
                d.dist_code[256 + dist] = code as u8;
                dist += 1;
            }
            code += 1;
        }
        let mut bl_count = [0u16; MAX_BITS + 1];
        for (n, t) in d.static_ltree.iter_mut().enumerate() {
            let len = match n {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
            t.dl = len;
            bl_count[usize::from(len)] += 1;
        }
        gen_codes(&mut d.static_ltree, L_CODES + 1, &bl_count);
        for (n, t) in d.static_dtree.iter_mut().enumerate() {
            t.dl = 5;
            t.fc = bi_reverse(n as u32, 5) as u16;
        }
        d.init_block();
        d
    }

    /// Whether `flush_block` may rewrite a one-block entry that does not
    /// pay as stored: the `!use_descriptors` half of zip's `seekable() &&
    /// !use_descriptors` (the other half is [`ZipOut::seekable`], asked
    /// first). True by default; false for an archive on a pipe or under
    /// `-fd`.
    pub fn set_store_fallback(&mut self, allowed: bool) {
        self.store_fallback = allowed;
    }

    /// Whether each of the C's read requests is one `read` of the input
    /// (zipup's `zread`, which a pipe answers short and a regular file in
    /// full), or filled until the input ends (the default). zip's own
    /// reads are the former; `-l`'s translation and standard input depend
    /// on it.
    pub fn set_one_read(&mut self, one: bool) {
        self.one_read = one;
    }

    /// Whether the entry is encrypted (zip's `key != NULL`). The bytes are
    /// the same either way; a stored block's data is then handed on in
    /// pieces of `out_size` (1024) bytes, as trees.c's `copy_block` copies
    /// it into `out_buf` so that zip's in-place encryption leaves the
    /// window alone. The caller encrypts what it is given.
    pub fn set_encrypting(&mut self, encrypting: bool) {
        self.encrypting = encrypting;
    }

    /// Deflates all of `input` into `out` as zip's `filecompress` does
    /// (`bi_init`, `ct_init`, `lm_init`, `deflate`).
    ///
    /// # Errors
    ///
    /// A read or write error, unchanged; or `Other` "block vanished", the
    /// C's `error()` (ZE_LOGIC) when a stored entry's block has left the
    /// window, which no input of the references' builds is known to reach.
    // port: zipup.c:filecompress (the !USE_ZLIB part)
    pub fn compress(
        &mut self,
        input: &mut dyn Read,
        out: &mut dyn Write,
    ) -> io::Result<DeflateSummary> {
        self.compress_to(input, &mut Seekable(out))
    }

    /// [`ZipDeflater::compress`] into an archive `flush_block` asks whether
    /// it can be rewound (zip's `seekable()`, which flushes its stdio
    /// buffer: a write can fail there).
    pub fn compress_to(
        &mut self,
        input: &mut dyn Read,
        out: &mut dyn ZipOut,
    ) -> io::Result<DeflateSummary> {
        let mut io = Io {
            input,
            out,
            crc: !0,
            isize: 0,
            bi_buf: 0,
            bi_valid: 0,
            buf: Vec::with_capacity(1 << 16),
            seg: 0,
            cuts: Vec::new(),
            written: 0,
            one_read: self.one_read,
        };
        // ct_init's per-file part; init_block as the previous file's last
        // flush_block left it (a no-op unless that file failed).
        self.file_type = None;
        self.stored = false;
        self.slides = 0;
        self.cmpr_bytelen = 0;
        self.cmpr_len_bits = 0;
        self.init_block();
        self.lm_init(&mut io)?;
        if self.level <= 3 {
            self.deflate_fast(&mut io)?;
        } else {
            self.deflate(&mut io)?;
        }
        io.flush(true)?;
        Ok(DeflateSummary {
            in_bytes: io.isize,
            out_bytes: io.written,
            crc32: !io.crc,
            gp_flags: self.gp_flags,
            stored: self.stored,
            text: self.file_type == Some(true),
            slides: self.slides,
        })
    }

    // ----- deflate.c -----

    /// `UPDATE_HASH(ins_h, c)`.
    fn update_hash(&mut self, c: u8) {
        self.ins_h = ((self.ins_h << H_SHIFT) ^ u32::from(c)) & HASH_MASK;
    }

    /// `INSERT_STRING(s, match_head)`: returns the new `match_head`.
    fn insert_string(&mut self, s: u32) -> u32 {
        self.update_hash(self.window[(s + MIN_MATCH - 1) as usize]);
        let match_head = u32::from(self.head[self.ins_h as usize]);
        self.prev[(s & WMASK) as usize] = match_head as u16;
        self.head[self.ins_h as usize] = s as u16;
        match_head
    }

    // port: deflate.c:lm_init
    fn lm_init(&mut self, io: &mut Io) -> io::Result<()> {
        self.head.fill(NIL as u16);
        let (good, lazy, nice, chain) = CONFIGURATION_TABLE[self.level as usize];
        self.max_lazy_match = lazy;
        self.good_match = good;
        self.nice_match = nice;
        self.max_chain_length = chain;
        self.gp_flags = 0;
        if self.level <= 2 {
            self.gp_flags |= FAST;
        } else if self.level >= 8 {
            self.gp_flags |= SLOW;
        }
        self.strstart = 0;
        self.block_start = 0;
        // sizeof(int) > 2: "Can read 64K in one step".
        let j = (WSIZE << 1) as usize;
        self.lookahead = io.read_buf(&mut self.window[..j])?;
        if self.lookahead == 0 {
            self.eofile = true;
            self.lookahead = 0;
            return Ok(());
        }
        self.eofile = false;
        if self.lookahead < MIN_LOOKAHEAD {
            self.fill_window(io)?;
        }
        self.ins_h = 0;
        for j in 0..(MIN_MATCH - 1) as usize {
            self.update_hash(self.window[j]);
        }
        Ok(())
    }

    // port: deflate.c:longest_match (the C version, no UNALIGNED_OK)
    fn longest_match(&mut self, mut cur_match: u32) -> u32 {
        let w = &self.window;
        let mut chain_length = self.max_chain_length;
        let scan = self.strstart as usize;
        let mut best_len = self.prev_length as usize;
        let limit = if self.strstart > MAX_DIST {
            self.strstart - MAX_DIST
        } else {
            NIL
        };
        let strend = scan + MAX_MATCH as usize;
        let mut scan_end1 = w[scan + best_len - 1];
        let mut scan_end = w[scan + best_len];
        if self.prev_length >= self.good_match {
            chain_length >>= 2;
        }
        loop {
            let m = cur_match as usize;
            if !(w[m + best_len] != scan_end
                || w[m + best_len - 1] != scan_end1
                || w[m] != w[scan]
                || w[m + 1] != w[scan + 1])
            {
                // scan[2] and match[2] are not compared: equal hash keys
                // make them equal (the C's own assumption, kept).
                let mut s = scan + 2;
                let mut mm = m + 2;
                loop {
                    let mut all = true;
                    for _ in 0..8 {
                        s += 1;
                        mm += 1;
                        if w[s] != w[mm] {
                            all = false;
                            break;
                        }
                    }
                    if !all || s >= strend {
                        break;
                    }
                }
                let len = MAX_MATCH as usize - (strend - s);
                if len > best_len {
                    self.match_start = cur_match;
                    best_len = len;
                    if len as i32 >= self.nice_match {
                        break;
                    }
                    scan_end1 = w[scan + best_len - 1];
                    scan_end = w[scan + best_len];
                }
            }
            cur_match = u32::from(self.prev[(cur_match & WMASK) as usize]);
            if cur_match <= limit {
                break;
            }
            chain_length -= 1;
            if chain_length == 0 {
                break;
            }
        }
        best_len as u32
    }

    /// `FLUSH_BLOCK(eof)`.
    fn flush_now(&mut self, io: &mut Io, eof: bool) -> io::Result<()> {
        let buf = (self.block_start >= 0).then_some(self.block_start as usize);
        let stored_len = u64::from(self.strstart).wrapping_sub(self.block_start as u64);
        self.flush_block(io, buf, stored_len, eof)
    }

    // port: deflate.c:fill_window
    fn fill_window(&mut self, io: &mut Io) -> io::Result<()> {
        loop {
            let mut more = WINDOW_SIZE
                .wrapping_sub(self.lookahead)
                .wrapping_sub(self.strstart);
            if more == u32::MAX {
                more -= 1;
            } else if self.strstart >= WSIZE + MAX_DIST {
                let w = WSIZE as usize;
                self.window.copy_within(w..2 * w, 0);
                self.match_start = self.match_start.wrapping_sub(WSIZE);
                self.strstart -= WSIZE;
                self.block_start -= i64::from(WSIZE);
                for p in self.head.iter_mut().chain(self.prev.iter_mut()) {
                    let m = u32::from(*p);
                    *p = if m >= WSIZE {
                        (m - WSIZE) as u16
                    } else {
                        NIL as u16
                    };
                }
                more += WSIZE;
                self.slides += 1;
            }
            if self.eofile {
                return Ok(());
            }
            let at = (self.strstart + self.lookahead) as usize;
            let n = io.read_buf(&mut self.window[at..at + more as usize])?;
            if n == 0 {
                self.eofile = true;
            } else {
                self.lookahead += n;
            }
            // while (lookahead < MIN_LOOKAHEAD && !eofile)
            if self.lookahead >= MIN_LOOKAHEAD || self.eofile {
                return Ok(());
            }
        }
    }

    /// `if ((unsigned)nice_match > lookahead) nice_match = lookahead;`
    fn clamp_nice_match(&mut self) {
        if self.nice_match as u32 > self.lookahead {
            self.nice_match = self.lookahead as i32;
        }
    }

    // port: deflate.c:deflate_fast
    fn deflate_fast(&mut self, io: &mut Io) -> io::Result<()> {
        let mut hash_head = NIL;
        let mut flush;
        let mut match_length = 0u32;
        self.prev_length = MIN_MATCH - 1;
        while self.lookahead != 0 {
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }
            if hash_head != NIL && self.strstart.wrapping_sub(hash_head) <= MAX_DIST {
                self.clamp_nice_match();
                match_length = self.longest_match(hash_head);
                if match_length > self.lookahead {
                    match_length = self.lookahead;
                }
            }
            if match_length >= MIN_MATCH {
                flush = self.ct_tally(
                    self.strstart.wrapping_sub(self.match_start),
                    match_length - MIN_MATCH,
                );
                self.lookahead -= match_length;
                if match_length <= self.max_lazy_match && self.lookahead >= MIN_MATCH {
                    match_length -= 1;
                    loop {
                        self.strstart += 1;
                        hash_head = self.insert_string(self.strstart);
                        match_length -= 1;
                        if match_length == 0 {
                            break;
                        }
                    }
                    self.strstart += 1;
                } else {
                    self.strstart += match_length;
                    match_length = 0;
                    self.ins_h = u32::from(self.window[self.strstart as usize]);
                    self.update_hash(self.window[self.strstart as usize + 1]);
                }
            } else {
                flush = self.ct_tally(0, u32::from(self.window[self.strstart as usize]));
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if flush {
                self.flush_now(io, false)?;
                self.block_start = i64::from(self.strstart);
            }
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(io)?;
            }
        }
        self.flush_now(io, true)
    }

    // port: deflate.c:deflate
    fn deflate(&mut self, io: &mut Io) -> io::Result<()> {
        let mut hash_head = NIL;
        let mut match_available = false;
        let mut match_length = MIN_MATCH - 1;
        while self.lookahead != 0 {
            if self.lookahead >= MIN_MATCH {
                hash_head = self.insert_string(self.strstart);
            }
            self.prev_length = match_length;
            let prev_match = self.match_start;
            match_length = MIN_MATCH - 1;

            if hash_head != NIL
                && self.prev_length < self.max_lazy_match
                && self.strstart.wrapping_sub(hash_head) <= MAX_DIST
            {
                self.clamp_nice_match();
                match_length = self.longest_match(hash_head);
                if match_length > self.lookahead {
                    match_length = self.lookahead;
                }
                if match_length == MIN_MATCH
                    && self.strstart.wrapping_sub(self.match_start) > TOO_FAR
                {
                    match_length = MIN_MATCH - 1;
                }
            }
            if self.prev_length >= MIN_MATCH && match_length <= self.prev_length {
                let max_insert = (self.strstart + self.lookahead).wrapping_sub(MIN_MATCH);
                let flush = self.ct_tally(
                    self.strstart.wrapping_sub(1).wrapping_sub(prev_match),
                    self.prev_length - MIN_MATCH,
                );
                self.lookahead -= self.prev_length - 1;
                self.prev_length -= 2;
                loop {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        hash_head = self.insert_string(self.strstart);
                    }
                    self.prev_length -= 1;
                    if self.prev_length == 0 {
                        break;
                    }
                }
                self.strstart += 1;
                match_available = false;
                match_length = MIN_MATCH - 1;
                if flush {
                    self.flush_now(io, false)?;
                    self.block_start = i64::from(self.strstart);
                }
            } else if match_available {
                let c = self.window[self.strstart as usize - 1];
                if self.ct_tally(0, u32::from(c)) {
                    self.flush_now(io, false)?;
                    self.block_start = i64::from(self.strstart);
                }
                self.strstart += 1;
                self.lookahead -= 1;
            } else {
                match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(io)?;
            }
        }
        if match_available {
            let c = self.window[self.strstart as usize - 1];
            self.ct_tally(0, u32::from(c));
        }
        self.flush_now(io, true)
    }

    // ----- trees.c -----

    // port: trees.c:init_block
    fn init_block(&mut self) {
        for t in &mut self.dyn_ltree[..L_CODES] {
            t.fc = 0;
        }
        for t in &mut self.dyn_dtree[..D_CODES] {
            t.fc = 0;
        }
        for t in &mut self.bl_tree[..BL_CODES] {
            t.fc = 0;
        }
        self.dyn_ltree[END_BLOCK].fc = 1;
        self.heap.opt_len = 0;
        self.heap.static_len = 0;
        self.last_lit = 0;
        self.last_dist = 0;
        self.last_flags = 0;
        self.flags = 0;
        self.flag_bit = 1;
    }

    /// `d_code(dist)`.
    fn d_code(&self, dist: usize) -> usize {
        usize::from(if dist < 256 {
            self.dist_code[dist]
        } else {
            self.dist_code[256 + (dist >> 7)]
        })
    }

    // port: trees.c:build_bl_tree
    fn build_bl_tree(&mut self) -> usize {
        scan_tree(&mut self.dyn_ltree, self.l_max_code, &mut self.bl_tree);
        scan_tree(&mut self.dyn_dtree, self.d_max_code, &mut self.bl_tree);
        build_tree(&mut self.heap, &mut self.bl_tree, Desc::Bl, None);
        let mut max_blindex = BL_CODES - 1;
        while max_blindex >= 3 {
            if self.bl_tree[BL_ORDER[max_blindex]].dl != 0 {
                break;
            }
            max_blindex -= 1;
        }
        self.heap.opt_len = self
            .heap
            .opt_len
            .wrapping_add((3 * (max_blindex + 1) + 5 + 5 + 4) as u64);
        max_blindex
    }

    // port: trees.c:send_all_trees
    fn send_all_trees(&self, io: &mut Io, lcodes: usize, dcodes: usize, blcodes: usize) {
        io.send_bits((lcodes - 257) as u32, 5);
        io.send_bits((dcodes - 1) as u32, 5);
        io.send_bits((blcodes - 4) as u32, 4);
        for &o in &BL_ORDER[..blcodes] {
            io.send_bits(u32::from(self.bl_tree[o].dl), 3);
        }
        send_tree(io, &self.dyn_ltree, lcodes - 1, &self.bl_tree);
        send_tree(io, &self.dyn_dtree, dcodes - 1, &self.bl_tree);
    }

    // port: trees.c:flush_block
    fn flush_block(
        &mut self,
        io: &mut Io,
        buf: Option<usize>,
        stored_len: u64,
        eof: bool,
    ) -> io::Result<()> {
        self.flag_buf[self.last_flags] = self.flags;
        if self.file_type.is_none() {
            self.set_file_type();
        }
        let st = std::mem::take(&mut self.static_ltree);
        self.l_max_code = build_tree(&mut self.heap, &mut self.dyn_ltree, Desc::L, Some(&st));
        self.static_ltree = st;
        let st = std::mem::take(&mut self.static_dtree);
        self.d_max_code = build_tree(&mut self.heap, &mut self.dyn_dtree, Desc::D, Some(&st));
        self.static_dtree = st;
        let max_blindex = self.build_bl_tree();

        let mut opt_lenb = self.heap.opt_len.wrapping_add(3 + 7) >> 3;
        let static_lenb = self.heap.static_len.wrapping_add(3 + 7) >> 3;
        if static_lenb <= opt_lenb {
            opt_lenb = static_lenb;
        }
        let eofb = u32::from(eof);
        if stored_len <= opt_lenb
            && eof
            && self.cmpr_bytelen == 0
            && self.cmpr_len_bits == 0
            && io.out.seekable()
            && self.store_fallback
        {
            let Some(at) = buf else {
                return Err(io::Error::other(BlockVanished));
            };
            self.copy_block(io, at, stored_len as usize, false);
            self.cmpr_bytelen = stored_len;
            self.stored = true;
        } else if stored_len + 4 <= opt_lenb
            && let Some(at) = buf
        {
            io.send_bits((STORED_BLOCK << 1) + eofb, 3);
            self.cmpr_bytelen += ((self.cmpr_len_bits + 3 + 7) >> 3) + stored_len + 4;
            self.cmpr_len_bits = 0;
            self.copy_block(io, at, stored_len as usize, true);
        } else if static_lenb == opt_lenb {
            io.send_bits((STATIC_TREES << 1) + eofb, 3);
            self.compress_block(io, true);
            self.cmpr_len_bits = self
                .cmpr_len_bits
                .wrapping_add(3)
                .wrapping_add(self.heap.static_len);
            self.cmpr_bytelen += self.cmpr_len_bits >> 3;
            self.cmpr_len_bits &= 7;
        } else {
            io.send_bits((DYN_TREES << 1) + eofb, 3);
            self.send_all_trees(
                io,
                self.l_max_code + 1,
                self.d_max_code + 1,
                max_blindex + 1,
            );
            self.compress_block(io, false);
            self.cmpr_len_bits = self
                .cmpr_len_bits
                .wrapping_add(3)
                .wrapping_add(self.heap.opt_len);
            self.cmpr_bytelen += self.cmpr_len_bits >> 3;
            self.cmpr_len_bits &= 7;
        }
        self.init_block();
        if eof {
            io.bi_windup();
            self.cmpr_len_bits += 7;
        }
        io.flush(false)
    }

    // port: trees.c:ct_tally
    fn ct_tally(&mut self, dist: u32, lc: u32) -> bool {
        self.l_buf[self.last_lit] = lc as u8;
        self.last_lit += 1;
        if dist == 0 {
            let f = &mut self.dyn_ltree[lc as usize].fc;
            *f = f.wrapping_add(1);
        } else {
            let dist = (dist - 1) as usize;
            let l = usize::from(self.length_code[lc as usize]) + LITERALS + 1;
            self.dyn_ltree[l].fc = self.dyn_ltree[l].fc.wrapping_add(1);
            let d = self.d_code(dist);
            self.dyn_dtree[d].fc = self.dyn_dtree[d].fc.wrapping_add(1);
            self.d_buf[self.last_dist] = dist as u16;
            self.last_dist += 1;
            self.flags |= self.flag_bit;
        }
        self.flag_bit = self.flag_bit.wrapping_shl(1);
        if self.last_lit & 7 == 0 {
            self.flag_buf[self.last_flags] = self.flags;
            self.last_flags += 1;
            self.flags = 0;
            self.flag_bit = 1;
        }
        if self.level > 2 && self.last_lit & 0xfff == 0 {
            let mut out_length = self.last_lit as u64 * 8;
            let in_length = u64::from(self.strstart).wrapping_sub(self.block_start as u64);
            for (dcode, extra) in EXTRA_DBITS.iter().enumerate() {
                out_length += u64::from(self.dyn_dtree[dcode].fc) * (5 + u64::from(*extra));
            }
            out_length >>= 3;
            if self.last_dist < self.last_lit / 2 && out_length < in_length / 2 {
                return true;
            }
        }
        self.last_lit == LIT_BUFSIZE - 1 || self.last_dist == DIST_BUFSIZE
    }

    // port: trees.c:compress_block
    fn compress_block(&self, io: &mut Io, static_trees: bool) {
        let (ltree, dtree) = if static_trees {
            (&self.static_ltree[..], &self.static_dtree[..])
        } else {
            (&self.dyn_ltree[..], &self.dyn_dtree[..])
        };
        let (mut lx, mut dx, mut fx) = (0usize, 0usize, 0usize);
        let mut flag = 0u8;
        if self.last_lit != 0 {
            loop {
                if lx & 7 == 0 {
                    flag = self.flag_buf[fx];
                    fx += 1;
                }
                let lc = usize::from(self.l_buf[lx]);
                lx += 1;
                if flag & 1 == 0 {
                    io.send_code(lc, ltree);
                } else {
                    let code = usize::from(self.length_code[lc]);
                    io.send_code(code + LITERALS + 1, ltree);
                    let extra = EXTRA_LBITS[code];
                    if extra != 0 {
                        io.send_bits(lc as u32 - self.base_length[code], extra);
                    }
                    let dist = usize::from(self.d_buf[dx]);
                    dx += 1;
                    let code = self.d_code(dist);
                    io.send_code(code, dtree);
                    let extra = EXTRA_DBITS[code];
                    if extra != 0 {
                        io.send_bits(dist as u32 - self.base_dist[code], extra);
                    }
                }
                flag >>= 1;
                if lx >= self.last_lit {
                    break;
                }
            }
        }
        io.send_code(END_BLOCK, ltree);
    }

    // port: trees.c:set_file_type
    fn set_file_type(&mut self) {
        let mut mask: u32 = 0xf3ff_c07f;
        for n in 0..=31 {
            if mask & 1 != 0 && self.dyn_ltree[n].fc != 0 {
                self.file_type = Some(false);
                return;
            }
            mask >>= 1;
        }
        self.file_type = Some(true);
        if self.dyn_ltree[9].fc != 0 || self.dyn_ltree[10].fc != 0 || self.dyn_ltree[13].fc != 0 {
            return;
        }
        if self.dyn_ltree[32..LITERALS].iter().any(|t| t.fc != 0) {
            return;
        }
        self.file_type = Some(false);
    }

    // port: trees.c:copy_block
    fn copy_block(&self, io: &mut Io, at: usize, len: usize, header: bool) {
        io.bi_windup();
        if header {
            io.put_short(len as u16);
            io.put_short(!(len as u16));
        }
        // flush_flg: out_buf is flushed, then the block is written as is
        io.cut();
        if self.encrypting {
            // copied through out_buf, out_size bytes at a time
            for piece in self.window[at..at + len].chunks(OUT_SIZE) {
                io.buf.extend_from_slice(piece);
                io.cut();
            }
        } else {
            io.buf.extend_from_slice(&self.window[at..at + len]);
        }
        io.cut();
    }
}
