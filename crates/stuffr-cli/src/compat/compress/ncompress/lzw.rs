//! ncompress 5.0's coder, `compress()` and `decompress()` of `compress.c`
//! (the Unlicense, `LICENSE-ncompress`), as Ubuntu's 5.0-1 builds it:
//! `-DUSERMEM=800000`, so `FAST` (a 2^17-entry hash with `primetab`'s
//! secondary probe), and glibc's `BUFSIZ` for `IBUFSIZ` and `OBUFSIZ`
//! (8192).
//!
//! **Encoder** ([`compress`]): state for state, the read loop included,
//! since where it stops to check decides where the codes widen and where a
//! CLEAR goes: the width grows only while the current prefix is a single
//! byte, the table fills to 2^maxbits - 1, the ratio check runs every
//! 10 000 input bytes once it is full (`rat >= ratio` keeps the table) and
//! again only at a single-byte prefix, and the output is written in
//! `OBUFSIZ` pieces. The bytes do not depend on how the input arrives (a
//! pipe's short reads), as the C's do not.
//!
//! One change, deviation N1 (ruling of 0.18.0): at maxbits 9 ncompress adds
//! entry 512 in 9 bits and never widens (`extcode` ignores maxbits, and
//! `n_bits < maxbits` is already false), so its stream is broken from the
//! first code after the table fills, for its own decoder too. stuffr writes
//! the compress 4.0 stream there instead: the table stops at entry 511, the
//! next code is the last 9-bit one, and the codes after it are 10 bits,
//! which every decoder (ncompress's included) expects at maxbits 9. The
//! bytes before the table fills are unchanged.
//!
//! **Decoder** ([`decompress`]): state for state too, because a corrupt
//! stream's debug line prints the input buffer's state: `IBUFSIZ` reads
//! into a buffer of `IBUFSIZ + 64`, another read only when fewer than 64
//! bytes are left, whole `n_bits`-byte groups decoded until the end of the
//! input, output in `OBUFSIZ` pieces (a failure loses the unwritten rest).
//! Any header maxbits up to 16 is accepted (ruling E1: below 9 no entry
//! fits, and the codes stay 9-bit literals). The buffers persist across
//! the inputs of one run, as the C's globals do, so stale bytes show where
//! the C's would; the one place the C reads before its buffer (`p[-1]` of
//! the debug line, a code at the buffer's first byte) prints 0.
//!
//! **Undefined behaviour, not reproduced:** a chain of entries longer than
//! the table, which only a stale entry 256 reused across inputs could make
//! (the C's stack then runs through its hash table), is a corrupt input.

use std::io::{self, Read, Write};

/// `IBUFSIZ`: glibc's `BUFSIZ`.
pub(super) const IBUFSIZ: usize = 8192;
/// `OBUFSIZ`: glibc's `BUFSIZ`.
pub(super) const OBUFSIZ: usize = 8192;
/// `sizeof(inbuf)`: `IBUFSIZ + 64`.
const INBUF: usize = IBUFSIZ + 64;
/// `sizeof(outbuf)`: `OBUFSIZ + 2048`.
const OUTBUF: usize = OBUFSIZ + 2048;
/// The shared input buffer's length: `inbuf` and a few bytes past it, which
/// the decoder's three-byte reads and the debug line may touch (zeros).
pub(super) const INBUF_ALLOC: usize = INBUF + 4;

/// `BITS`.
const BITS: i64 = 16;
/// `HBITS` (FAST): the hash's size is 2^17.
const HBITS: i64 = 17;
const HSIZE: usize = 1 << HBITS;
const HMASK: i64 = (1 << HBITS) - 1;
const FIRST: i64 = 257;
const CLEAR: i64 = 256;
const INIT_BITS: i64 = 9;
const CHECK_GAP: i64 = 10000;
const MAGIC_1: u8 = 0x1f;
const MAGIC_2: u8 = 0x9d;
const BIT_MASK: u8 = 0x1f;
const BLOCK_MODE: u8 = 0x80;

/// `primetab` (FAST): the secondary probe's step for each byte.
#[rustfmt::skip]
const PRIMETAB: [i64; 256] = [
    1013, -1061, 1109, -1181, 1231, -1291, 1361, -1429,
    1481, -1531, 1583, -1627, 1699, -1759, 1831, -1889,
    1973, -2017, 2083, -2137, 2213, -2273, 2339, -2383,
    2441, -2531, 2593, -2663, 2707, -2753, 2819, -2887,
    2957, -3023, 3089, -3181, 3251, -3313, 3361, -3449,
    3511, -3557, 3617, -3677, 3739, -3821, 3881, -3931,
    4013, -4079, 4139, -4219, 4271, -4349, 4423, -4493,
    4561, -4639, 4691, -4783, 4831, -4931, 4973, -5023,
    5101, -5179, 5261, -5333, 5413, -5471, 5521, -5591,
    5659, -5737, 5807, -5857, 5923, -6029, 6089, -6151,
    6221, -6287, 6343, -6397, 6491, -6571, 6659, -6709,
    6791, -6857, 6917, -6983, 7043, -7129, 7213, -7297,
    7369, -7477, 7529, -7577, 7643, -7703, 7789, -7873,
    7933, -8017, 8093, -8171, 8237, -8297, 8387, -8461,
    8543, -8627, 8689, -8741, 8819, -8867, 8963, -9029,
    9109, -9181, 9241, -9323, 9397, -9439, 9511, -9613,
    9677, -9743, 9811, -9871, 9941, -10061, 10111, -10177,
    10259, -10321, 10399, -10477, 10567, -10639, 10711, -10789,
    10867, -10949, 11047, -11113, 11173, -11261, 11329, -11423,
    11491, -11587, 11681, -11777, 11827, -11903, 11959, -12041,
    12109, -12197, 12263, -12343, 12413, -12487, 12541, -12611,
    12671, -12757, 12829, -12917, 12979, -13043, 13127, -13187,
    13291, -13367, 13451, -13523, 13619, -13691, 13751, -13829,
    13901, -13967, 14057, -14153, 14249, -14341, 14419, -14489,
    14557, -14633, 14717, -14767, 14831, -14897, 14983, -15083,
    15149, -15233, 15289, -15359, 15427, -15497, 15583, -15649,
    15733, -15791, 15881, -15937, 16057, -16097, 16189, -16267,
    16363, -16447, 16529, -16619, 16691, -16763, 16879, -16937,
    17021, -17093, 17183, -17257, 17341, -17401, 17477, -17551,
    17623, -17713, 17791, -17891, 17957, -18041, 18097, -18169,
    18233, -18307, 18379, -18451, 18523, -18637, 18731, -18803,
    18919, -19031, 19121, -19211, 19273, -19381, 19429, -19477,
];

/// `MAXCODE(n)`: `1L << n`.
fn maxcode(n: i64) -> i64 {
    1i64 << n
}

/// Why a coder stopped: the C calls `read_error()`, `write_error()` or
/// prints the corrupt-input lines, then `abort_compress()`.
#[derive(Debug)]
pub(super) enum Fail {
    Read(io::Error),
    Write(io::Error),
    Corrupt(Corrupt),
}

/// A stream `decompress` refuses part-way: what its debug line shows.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Corrupt {
    /// The first code is past 255 (`oldcode:-1 code:%i`).
    FirstCode(i64),
    /// A code past the next free entry: `insize`, `posbits` (already moved
    /// back to the code), the five bytes from `p[-1]`, `posbits & 7`.
    Code {
        insize: usize,
        posbits: i64,
        bytes: [u8; 5],
    },
    /// A table chain longer than the table (not reproduced: see the module
    /// doc).
    Chain,
}

/// One `read(fd, buf, n)`: whatever one read gives, retried only when a
/// signal interrupted it before any byte.
pub(super) fn read_once(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match r.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// One `write(fd, buf, n) != n` check: the bytes reach the descriptor now,
/// so a failure is reported where the C's would be.
fn put(out: &mut dyn Write, b: &[u8]) -> Result<(), Fail> {
    out.write_all(b)
        .and_then(|()| out.flush())
        .map_err(Fail::Write)
}

/// The `output()` macro: OR `code` into `buf` at bit `o`, then advance.
fn output(buf: &mut [u8], o: &mut i64, code: i64, n: i64) {
    let p = (*o >> 3) as usize;
    let i = code << (*o & 7);
    buf[p] |= i as u8;
    buf[p + 1] |= (i >> 8) as u8;
    buf[p + 2] |= (i >> 16) as u8;
    *o += n;
}

/// `boff = outbits = ...`: `outbits` rounded up to the next whole group of
/// `n_bits` bytes counted from `boff`, where a reader changes width.
fn pad(outbits: i64, boff: i64, n_bits: i64) -> i64 {
    let g = n_bits << 3;
    (outbits - 1) + (g - (outbits - boff - 1 + g) % g)
}

/// The encoder's tables (`htab`, `codetab`), kept across the inputs of a
/// run so they are allocated once.
pub(super) struct EncTables {
    htab: Vec<i64>,
    codetab: Vec<u16>,
}

impl EncTables {
    pub(super) fn new() -> Self {
        EncTables {
            htab: vec![-1; HSIZE],
            codetab: vec![0; HSIZE],
        }
    }
}

/// What a finished `compress()` counted: `bytes_in`, `bytes_out`.
pub(super) struct Counts {
    pub(super) bytes_in: i64,
    pub(super) bytes_out: i64,
}

/// `compress(fdin, fdout)` at `maxbits` (9..=16), reading `IBUFSIZ` at a
/// time into `inbuf` (the run's shared input buffer).
pub(super) fn compress(
    input: &mut dyn Read,
    out: &mut dyn Write,
    inbuf: &mut [u8],
    maxbits: i64,
    t: &mut EncTables,
) -> Result<Counts, Fail> {
    // Deviation N1: at maxbits 9 the table stops at entry 511 (`extcode`
    // 512 while it grows), one more 9-bit code follows (`widen_after`
    // counts it), then the codes are 10 bits.
    let nine = maxbits == 9;
    let grow_extcode = |n_bits: i64| {
        if nine {
            maxcode(INIT_BITS)
        } else {
            maxcode(n_bits) + 1
        }
    };
    let mut widen_after: Option<u64> = None;
    let mut outputs: u64 = 0;

    let mut ratio: i64 = 0;
    let mut checkpoint = CHECK_GAP;
    let mut n_bits = INIT_BITS;
    let mut extcode = grow_extcode(n_bits);
    let mut stcode = true;
    let mut free_ent = FIRST;
    // Three spare bytes for the `output()` macro's reach.
    let mut outbuf = vec![0u8; OUTBUF + 3];
    let mut bytes_out: i64 = 0;
    let mut bytes_in: i64 = 0;
    outbuf[0] = MAGIC_1;
    outbuf[1] = MAGIC_2;
    outbuf[2] = maxbits as u8 | BLOCK_MODE;
    let mut outbits: i64 = 3 << 3;
    let mut boff: i64 = outbits;
    // `fcode.e.ent`: the current prefix's code.
    let mut ent: i64 = 0;
    t.htab.fill(-1);

    loop {
        let rsize = read_once(input, &mut inbuf[..IBUFSIZ]).map_err(Fail::Read)? as i64;
        if rsize == 0 {
            break;
        }
        let mut rpos: i64 = if bytes_in == 0 {
            ent = i64::from(inbuf[0]);
            1
        } else {
            0
        };
        let mut rlop: i64 = 0;
        loop {
            if nine && n_bits == INIT_BITS {
                if ent < FIRST {
                    if stcode && free_ent >= extcode {
                        // The table is full at entry 511: no entry 512.
                        stcode = false;
                        extcode = free_ent + 1;
                        widen_after = Some(outputs);
                    } else if widen_after.is_some_and(|at| outputs > at) {
                        // The last 9-bit code is out: 10 bits from here.
                        outbits = pad(outbits, boff, n_bits);
                        boff = outbits;
                        n_bits += 1;
                        extcode = maxcode(16) + OBUFSIZ as i64;
                        widen_after = None;
                    }
                }
            } else if free_ent >= extcode && ent < FIRST {
                if n_bits < maxbits {
                    outbits = pad(outbits, boff, n_bits);
                    boff = outbits;
                    n_bits += 1;
                    extcode = if n_bits < maxbits {
                        maxcode(n_bits) + 1
                    } else {
                        maxcode(n_bits)
                    };
                } else {
                    extcode = maxcode(16) + OBUFSIZ as i64;
                    stcode = false;
                }
            }

            if !stcode && bytes_in >= checkpoint && ent < FIRST {
                checkpoint = bytes_in + CHECK_GAP;
                let rat = if bytes_in > 0x007f_ffff {
                    // The shift would overflow.
                    let r = (bytes_out + (outbits >> 3)) >> 8;
                    if r == 0 { 0x7fff_ffff } else { bytes_in / r }
                } else {
                    // 8 fractional bits.
                    (bytes_in << 8) / (bytes_out + (outbits >> 3))
                };
                if rat >= ratio {
                    ratio = i64::from(rat as i32);
                } else {
                    ratio = 0;
                    t.htab.fill(-1);
                    output(&mut outbuf, &mut outbits, CLEAR, n_bits);
                    outbits = pad(outbits, boff, n_bits);
                    boff = outbits;
                    n_bits = INIT_BITS;
                    extcode = grow_extcode(n_bits);
                    free_ent = FIRST;
                    stcode = true;
                    widen_after = None;
                }
            }

            if outbits >= (OBUFSIZ << 3) as i64 {
                put(out, &outbuf[..OBUFSIZ])?;
                outbits -= (OBUFSIZ << 3) as i64;
                boff = -(((OBUFSIZ << 3) as i64 - boff) % (n_bits << 3));
                bytes_out += OBUFSIZ as i64;
                let keep = ((outbits >> 3) + 1) as usize;
                outbuf.copy_within(OBUFSIZ..OBUFSIZ + keep, 0);
                outbuf[keep..keep + OBUFSIZ].fill(0);
            }

            {
                let mut i = rsize - rlop;
                if i > extcode - free_ent {
                    i = extcode - free_ent;
                }
                // `sizeof(outbuf)` makes this unsigned in the C; it is
                // never negative here, so a plain minimum.
                let room = ((OUTBUF - 32) as i64 * 8 - outbits) / n_bits;
                if i > room {
                    i = room;
                }
                if !stcode && i > checkpoint - bytes_in {
                    i = checkpoint - bytes_in;
                }
                rlop += i;
                bytes_in += i;
            }

            loop {
                // next:
                if rpos >= rlop && !(ent >= FIRST && rpos < rsize) {
                    // endlop, nothing to finish.
                    break;
                }
                // next2:
                let c = inbuf[rpos as usize];
                rpos += 1;
                let fc = (ent << 16) | i64::from(c);
                let mut hp = (i64::from(c) << (HBITS - 8)) ^ ent;
                let mut found = t.htab[hp as usize] == fc;
                if !found && t.htab[hp as usize] != -1 {
                    let p = PRIMETAB[c as usize];
                    loop {
                        hp = (hp + p) & HMASK;
                        let v = t.htab[hp as usize];
                        if v == fc {
                            found = true;
                            break;
                        }
                        if v == -1 {
                            break;
                        }
                    }
                }
                if found {
                    // hfound:
                    ent = i64::from(t.codetab[hp as usize]);
                    continue;
                }
                output(&mut outbuf, &mut outbits, ent, n_bits);
                outputs += 1;
                ent = i64::from(c);
                if stcode {
                    t.codetab[hp as usize] = free_ent as u16;
                    free_ent += 1;
                    t.htab[hp as usize] = fc;
                }
            }
            if rpos > rlop {
                bytes_in += rpos - rlop;
                rlop = rpos;
            }
            if rlop >= rsize {
                break;
            }
        }
    }

    if bytes_in > 0 {
        output(&mut outbuf, &mut outbits, ent, n_bits);
    }
    let n = ((outbits + 7) >> 3) as usize;
    put(out, &outbuf[..n])?;
    bytes_out += n as i64;
    Ok(Counts {
        bytes_in,
        bytes_out,
    })
}

/// The decoder's tables (`tab_prefix`, `tab_suffix`), kept across the
/// inputs of a run, stale entries and all, as the C's globals are.
pub(super) struct DecTables {
    prefix: Vec<u16>,
    suffix: Vec<u8>,
}

impl DecTables {
    pub(super) fn new() -> Self {
        DecTables {
            prefix: vec![0; 1 << BITS],
            suffix: vec![0; 1 << BITS],
        }
    }
}

/// How `decompress()` ended without aborting.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum End {
    /// The stream was read to its end.
    Done,
    /// No input at all: nothing said, nothing written (`bytes_in` 0).
    Empty,
    /// Not a `.Z` header: `not in compressed format`, exit code 1.
    NotCompressed,
    /// A header asking for these many bits: exit code 4.
    TooManyBits(u8),
}

/// `decompress(fdin, fdout)`: how it ended and `bytes_in` (0 unless a
/// header was read; the C adds every read's size again each time round).
pub(super) fn decompress(
    input: &mut dyn Read,
    out: &mut dyn Write,
    inbuf: &mut [u8],
    t: &mut DecTables,
) -> Result<(End, i64), Fail> {
    let mut insize: usize = 0;
    let mut rsize: i64 = 0;
    let mut read_failed = None;
    while insize < 3 {
        match read_once(input, &mut inbuf[insize..insize + IBUFSIZ]) {
            Ok(0) => {
                rsize = 0;
                break;
            }
            Ok(n) => {
                rsize = n as i64;
                insize += n;
            }
            Err(e) => {
                read_failed = Some(e);
                break;
            }
        }
    }
    if insize < 3 || inbuf[0] != MAGIC_1 || inbuf[1] != MAGIC_2 {
        if let Some(e) = read_failed {
            return Err(Fail::Read(e));
        }
        let end = if insize > 0 {
            End::NotCompressed
        } else {
            End::Empty
        };
        return Ok((end, 0));
    }
    let maxbits = i64::from(inbuf[2] & BIT_MASK);
    let block_mode = inbuf[2] & BLOCK_MODE != 0;
    if maxbits > BITS {
        return Ok((End::TooManyBits(maxbits as u8), 0));
    }
    let maxmaxcode = maxcode(maxbits);
    let mut bytes_in = insize as i64;
    let mut n_bits = INIT_BITS;
    let mut maxcode_ = maxcode(n_bits) - 1;
    let mut bitmask: i64 = (1 << n_bits) - 1;
    let mut oldcode: i64 = -1;
    let mut finchar: i64 = 0;
    let mut outpos: usize = 0;
    let mut posbits: i64 = 3 << 3;
    let mut free_ent = if block_mode { FIRST } else { 256 };
    t.prefix[..256].fill(0);
    for code in 0..256 {
        t.suffix[code] = code as u8;
    }
    let mut outbuf = vec![0u8; OUTBUF];
    // `de_stack`, filled backwards in the C; here in push order, read
    // backwards.
    let mut stack: Vec<u8> = Vec::with_capacity(1 << BITS);

    loop {
        // resetbuf:
        let o = (posbits >> 3) as usize;
        let e = insize.saturating_sub(o);
        if e > 0 {
            inbuf.copy_within(o..o + e, 0);
        }
        insize = e;
        posbits = 0;
        if insize < INBUF - IBUFSIZ {
            rsize =
                read_once(input, &mut inbuf[insize..insize + IBUFSIZ]).map_err(Fail::Read)? as i64;
            insize += rsize as usize;
        }
        let n = n_bits as usize;
        let inbits: i64 = if rsize > 0 {
            ((insize - insize % n) << 3) as i64
        } else {
            ((insize << 3) as i64) - (n_bits - 1)
        };
        let mut reset = false;
        while inbits > posbits {
            if free_ent > maxcode_ {
                posbits = pad(posbits, 0, n_bits);
                n_bits += 1;
                maxcode_ = if n_bits == maxbits {
                    maxmaxcode
                } else {
                    maxcode(n_bits) - 1
                };
                bitmask = (1 << n_bits) - 1;
                reset = true;
                break;
            }
            let mut code = {
                let p = (posbits >> 3) as usize;
                let w = i64::from(inbuf[p])
                    | (i64::from(inbuf[p + 1]) << 8)
                    | (i64::from(inbuf[p + 2]) << 16);
                (w >> (posbits & 7)) & bitmask
            };
            posbits += n_bits;

            if oldcode == -1 {
                if code >= 256 {
                    return Err(Fail::Corrupt(Corrupt::FirstCode(code)));
                }
                oldcode = code;
                finchar = code;
                outbuf[outpos] = code as u8;
                outpos += 1;
                continue;
            }

            if code == CLEAR && block_mode {
                t.prefix[..256].fill(0);
                free_ent = FIRST - 1;
                posbits = pad(posbits, 0, n_bits);
                n_bits = INIT_BITS;
                maxcode_ = maxcode(n_bits) - 1;
                bitmask = (1 << n_bits) - 1;
                reset = true;
                break;
            }

            let incode = code;
            stack.clear();
            if code >= free_ent {
                // The KwKwK case.
                if code > free_ent {
                    posbits -= n_bits;
                    let p = (posbits >> 3) as usize;
                    let before = if p == 0 { 0 } else { inbuf[p - 1] };
                    return Err(Fail::Corrupt(Corrupt::Code {
                        insize,
                        posbits,
                        bytes: [before, inbuf[p], inbuf[p + 1], inbuf[p + 2], inbuf[p + 3]],
                    }));
                }
                stack.push(finchar as u8);
                code = oldcode;
            }
            while code >= 256 {
                if stack.len() > 1 << BITS {
                    return Err(Fail::Corrupt(Corrupt::Chain));
                }
                stack.push(t.suffix[code as usize]);
                code = i64::from(t.prefix[code as usize]);
            }
            finchar = i64::from(t.suffix[code as usize]);
            stack.push(finchar as u8);

            // Out in forward order, in OBUFSIZ pieces.
            let mut left = stack.len();
            if outpos + left >= OBUFSIZ {
                loop {
                    let i = left.min(OBUFSIZ - outpos);
                    for k in 0..i {
                        outbuf[outpos + k] = stack[left - 1 - k];
                    }
                    outpos += i;
                    if outpos >= OBUFSIZ {
                        put(out, &outbuf[..outpos])?;
                        outpos = 0;
                    }
                    left -= i;
                    if left == 0 {
                        break;
                    }
                }
            } else {
                for k in 0..left {
                    outbuf[outpos + k] = stack[left - 1 - k];
                }
                outpos += left;
            }

            if free_ent < maxmaxcode {
                t.prefix[free_ent as usize] = oldcode as u16;
                t.suffix[free_ent as usize] = finchar as u8;
                free_ent += 1;
            }
            oldcode = incode;
        }
        if reset {
            // `goto resetbuf`: neither the count nor the loop's test.
            continue;
        }
        bytes_in += rsize;
        if rsize <= 0 {
            break;
        }
    }
    if outpos > 0 {
        put(out, &outbuf[..outpos])?;
    }
    Ok((End::Done, bytes_in))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader handing out at most `n` bytes per read, as a pipe may.
    struct Dribble<'a>(&'a [u8], usize);
    impl Read for Dribble<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let k = buf.len().min(self.1).min(self.0.len());
            buf[..k].copy_from_slice(&self.0[..k]);
            self.0 = &self.0[k..];
            Ok(k)
        }
    }

    fn encode_with(data: &[u8], maxbits: i64, chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut inbuf = vec![0u8; INBUF_ALLOC];
        compress(
            &mut Dribble(data, chunk),
            &mut out,
            &mut inbuf,
            maxbits,
            &mut EncTables::new(),
        )
        .unwrap();
        out
    }

    fn encode(data: &[u8], maxbits: i64) -> Vec<u8> {
        encode_with(data, maxbits, IBUFSIZ)
    }

    fn decode(z: &[u8]) -> Result<Vec<u8>, Fail> {
        let mut out = Vec::new();
        let mut inbuf = vec![0u8; INBUF_ALLOC];
        decompress(&mut &z[..], &mut out, &mut inbuf, &mut DecTables::new())?;
        Ok(out)
    }

    fn sample(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                // Text-like stretches between random ones, so tables fill,
                // ratios drop and CLEARs come.
                if i % 30000 < 20000 {
                    b"the quick brown fox jumps "[(x % 26) as usize]
                } else {
                    (x >> 32) as u8
                }
            })
            .collect()
    }

    /// Every bit count reads back, at a size that fills every table and
    /// clears it, maxbits 9 included (deviation N1: the codes widen).
    #[test]
    fn every_bit_count_reads_back() {
        let data = sample(400_000, 0x2545_f491_4f6c_dd1d);
        for bits in 9..=16 {
            let z = encode(&data, bits);
            assert_eq!(z[..3], [0x1f, 0x9d, 0x80 | bits as u8], "-b {bits}");
            assert_eq!(decode(&z).unwrap(), data, "-b {bits}");
        }
    }

    /// The bytes do not depend on how the input arrives: a pipe's short
    /// reads give the stream a file's whole ones give.
    #[test]
    fn short_reads_write_the_same_bytes() {
        let data = sample(200_000, 0x9e37_79b9_7f4a_7c15);
        for bits in [9, 12, 16] {
            let whole = encode(&data, bits);
            for chunk in [1, 7, 1000, 4096] {
                assert!(
                    encode_with(&data, bits, chunk) == whole,
                    "-b {bits}, {chunk}"
                );
            }
        }
    }

    /// Hand-checked: `A` alone is the header and one 9-bit code; empty
    /// input is the header alone.
    #[test]
    fn small_streams_are_bit_exact() {
        assert_eq!(encode(b"A", 16), [0x1f, 0x9d, 0x90, 0x41, 0x00]);
        assert_eq!(encode(b"", 16), [0x1f, 0x9d, 0x90]);
        assert_eq!(
            encode(b"AAAA", 16),
            [0x1f, 0x9d, 0x90, 0x41, 0x02, 0x06, 0x01]
        );
    }

    /// N1: the maxbits-9 table stops at entry 511; the stream before that
    /// is the C's (a short input is unchanged), and after it the codes are
    /// 10 bits wide.
    #[test]
    fn maxbits_9_stops_at_511_and_widens() {
        // 300 bytes of text never fill the table: the C's stream exactly
        // (the 9-bit codes of the 16-bit run, bar the header byte).
        let short = &sample(300, 7)[..];
        let mut z16 = encode(short, 16);
        z16[2] = 0x89;
        assert_eq!(encode(short, 9), z16);
        // Random bytes: each code makes one entry, so the 256th code is the
        // last 9-bit one, the 257th starts 10-bit codes on a fresh group.
        let data: Vec<u8> = (0..2000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let z = encode(&data, 9);
        assert_eq!(decode(&z).unwrap(), data);
    }

    /// A `Read` that gives `n` bytes of `data`, then fails with `EIO`.
    struct FailsAfter<'a> {
        data: &'a [u8],
        n: usize,
    }

    impl Read for FailsAfter<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.n == 0 {
                return Err(io::Error::from_raw_os_error(5));
            }
            let k = buf.len().min(self.n).min(self.data.len());
            buf[..k].copy_from_slice(&self.data[..k]);
            self.data = &self.data[k..];
            self.n -= k;
            Ok(k)
        }
    }

    /// Ruling E7's case: a read error part-way is `read_error()` in both
    /// coders, never taken for the end of the input, so the caller aborts
    /// (removing the output, keeping the input) instead of publishing a
    /// cut-short result.
    #[test]
    fn a_read_error_part_way_fails_both_coders() {
        let data = sample(100_000, 3);
        let z = encode(&data, 16);
        let mut inbuf = vec![0u8; INBUF_ALLOC];
        let mut src = FailsAfter {
            data: &z,
            n: z.len() / 2,
        };
        let r = decompress(&mut src, &mut Vec::new(), &mut inbuf, &mut DecTables::new());
        assert!(matches!(r, Err(Fail::Read(e)) if e.raw_os_error() == Some(5)));
        let mut src = FailsAfter {
            data: &data,
            n: data.len() / 2,
        };
        let r = compress(
            &mut src,
            &mut Vec::new(),
            &mut inbuf,
            16,
            &mut EncTables::new(),
        );
        assert!(matches!(r, Err(Fail::Read(e)) if e.raw_os_error() == Some(5)));
        // In the header: the same, not "not in compressed format".
        let mut src = FailsAfter { data: &z, n: 2 };
        let r = decompress(&mut src, &mut Vec::new(), &mut inbuf, &mut DecTables::new());
        assert!(matches!(r, Err(Fail::Read(_))));
    }

    /// The decoder's quirks: the first code must be below 256; a code past
    /// the next free entry reports the buffer; a header past 16 bits, a bad
    /// magic, nothing at all; a header and nothing else is empty; header
    /// maxbits below 9 are 9-bit literals (ruling E1).
    #[test]
    fn the_decoder_reads_as_compress_c_does() {
        assert!(matches!(
            decode(&[0x1f, 0x9d, 0x90, 0xff, 0x03, 0x00]),
            Err(Fail::Corrupt(Corrupt::FirstCode(511)))
        ));
        match decode(&[0x1f, 0x9d, 0x90, 0x41, 0xfe, 0x07, 0x00]) {
            Err(Fail::Corrupt(Corrupt::Code {
                insize,
                posbits,
                bytes,
            })) => {
                assert_eq!((insize, posbits), (4, 9));
                // The fifth byte is stale: the header's shift left it there
                // (Homebrew's 5.0 prints `41 FE 07 00 FE (1)`).
                assert_eq!(bytes, [0x41, 0xfe, 0x07, 0x00, 0xfe]);
            }
            other => panic!("{other:?}"),
        }
        let mut inbuf = vec![0u8; INBUF_ALLOC];
        let mut t = DecTables::new();
        let mut end =
            |z: &[u8]| decompress(&mut &z[..], &mut Vec::new(), &mut inbuf, &mut t).unwrap();
        assert_eq!(end(&[0x1f, 0x9d, 0x91, 0x41]), (End::TooManyBits(17), 0));
        assert_eq!(end(b"plain"), (End::NotCompressed, 0));
        assert_eq!(end(&[0x1f, 0x9d]), (End::NotCompressed, 0));
        assert_eq!(end(b""), (End::Empty, 0));
        assert_eq!(end(&[0x1f, 0x9d, 0x90]), (End::Done, 3));
        assert_eq!(decode(&[0x1f, 0x9d, 0x88, 0x41, 0x00]).unwrap(), b"A");
        assert_eq!(decode(&[0x1f, 0x9d, 0x80, 0x41, 0x00]).unwrap(), b"A");
    }
}
