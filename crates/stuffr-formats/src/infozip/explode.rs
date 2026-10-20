//! Info-ZIP's own exploder, implode (method 6), ported from UnZip 6.0's
//! `explode.c` (Mark Adler, version c17d; Info-ZIP licence, see the parent
//! module), with its tables built by `inflate.c`'s `huft_build`, as the C
//! builds them. Apple's
//! `explode.c` is byte-identical to upstream's and Ubuntu's patch series
//! does not touch it, so this one port is both flavours'. `DLL` (slide
//! redirection) and `INT_16BIT` are off on both references, so the window
//! is `WSIZE` (64 KiB with `USE_DEFLATE64`), not the 4K or 8K the method
//! needs: the C uses inflate's `slide[]` and masks the window position with
//! `WSIZE - 1`.
//!
//! **Stopping.** The C stops on the entry's uncompressed size
//! (`G.lrec.ucsize`), never on the end of the compressed data: its
//! `NEEDBITS` has no end-of-data check, and an EOF reads as `EOF` (-1), all
//! one bits, so a cut-short stream decodes on until `ucsize` bytes are out
//! (a match may overshoot it: the whole match is copied). Only then does it
//! compare what it consumed with the compressed size, and returns 5 when
//! they differ ([`Stop::Length`]).
//!
//! **The window.** Explode reads no stale bytes from it: until its first
//! flush (`u`, "unflushed"), a match reaching at or past the write position
//! (before this entry's first byte) is filled with zeros (`memzero`), not
//! copied. The window is still the caller's (unzip's `slide[]`), so what it
//! holds afterwards is what unzip's holds.

use super::inflate::{Huft, INVALID_CODE, MASK_BITS, WSIZE, huft_build};
use super::{ByteSource, Stop};

/// `cplen2[]`: copy lengths for the length codes, no literal tree.
const CPLEN2: [u16; 64] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
];
/// `cplen3[]`: copy lengths for the length codes, with a literal tree.
const CPLEN3: [u16; 64] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
];
/// `extra[]`: extra bits for the length codes (the last, 63, takes eight).
/// The C passes it for the distance trees too, where the decoders never
/// read the `e` it sets.
const EXTRA: [u8; 64] = {
    let mut e = [0u8; 64];
    e[63] = 8;
    e
};
/// `cpdist4[]`: distance bases for the 4K window's high six bits.
const CPDIST4: [u16; 64] = [
    1, 65, 129, 193, 257, 321, 385, 449, 513, 577, 641, 705, 769, 833, 897, 961, 1025, 1089, 1153,
    1217, 1281, 1345, 1409, 1473, 1537, 1601, 1665, 1729, 1793, 1857, 1921, 1985, 2049, 2113, 2177,
    2241, 2305, 2369, 2433, 2497, 2561, 2625, 2689, 2753, 2817, 2881, 2945, 3009, 3073, 3137, 3201,
    3265, 3329, 3393, 3457, 3521, 3585, 3649, 3713, 3777, 3841, 3905, 3969, 4033,
];
/// `cpdist8[]`: distance bases for the 8K window's high six bits.
const CPDIST8: [u16; 64] = [
    1, 129, 257, 385, 513, 641, 769, 897, 1025, 1153, 1281, 1409, 1537, 1665, 1793, 1921, 2049,
    2177, 2305, 2433, 2561, 2689, 2817, 2945, 3073, 3201, 3329, 3457, 3585, 3713, 3841, 3969, 4097,
    4225, 4353, 4481, 4609, 4737, 4865, 4993, 5121, 5249, 5377, 5505, 5633, 5761, 5889, 6017, 6145,
    6273, 6401, 6529, 6657, 6785, 6913, 7041, 7169, 7297, 7425, 7553, 7681, 7809, 7937, 8065,
];

/// `wszimpl`: `WSIZE` (no `DLL`, no `INT_16BIT`).
const WS: u32 = WSIZE as u32;

/// `EOF` as unzip's `NEXTBYTE` returns it.
const EOF: i32 = -1;

/// `NEEDBITS(n)` of `explode.c`: no end-of-data check. An EOF is `(ulg)EOF`,
/// all one bits, shifted in like a byte.
macro_rules! needbits {
    ($self:ident, $b:ident, $k:ident, $n:expr) => {
        while $k < ($n as u32) {
            // `(ulg)NEXTBYTE << k`: k < n <= 16 here, so no shift overflows
            $b |= ($self.next_byte() as i64 as u64) << $k;
            $k += 8;
        }
    };
}

/// `DUMPBITS(n)`.
macro_rules! dumpbits {
    ($b:ident, $k:ident, $n:expr) => {{
        let n: u32 = $n;
        $b >>= n;
        $k -= n;
    }};
}

/// `DECODEHUFT(htab, bits, mask)`: implode's codes are sent inverted, so the
/// table is indexed by `~b`. Evaluates to the final entry and leaves its
/// `e` in `$e`; returns 1 on an invalid code, as the C's macro does.
macro_rules! decodehuft {
    ($self:ident, $b:ident, $k:ident, $e:ident, $htab:expr, $bits:expr, $mask:expr) => {{
        needbits!($self, $b, $k, $bits);
        let htab: &[Huft] = $htab;
        let mut t = htab[(!($b as u32) & $mask) as usize];
        loop {
            dumpbits!($b, $k, u32::from(t.b));
            $e = u32::from(t.e);
            if $e <= 32 {
                break;
            }
            if t.e == INVALID_CODE {
                return Err(Stop::Code(1));
            }
            $e &= 31;
            needbits!($self, $b, $k, $e);
            t = htab[t.t as usize + (!($b as u32) & MASK_BITS[$e as usize]) as usize];
        }
        t
    }};
}

/// The C's explode state for one entry.
struct Explode<'a, S, E> {
    src: &'a mut S,
    /// `redirSlide`: the caller's window, its first `WSIZE` bytes.
    slide: &'a mut [u8],
    flush: &'a mut dyn FnMut(&[u8]) -> Result<(), E>,
    /// EOFs read after the entry's last byte: `readbyte()` decrements
    /// `G.csize` once for each ("for tests done after exploding").
    eofs: i64,
}

impl<S: ByteSource, E> Explode<'_, S, E> {
    /// `NEXTBYTE`: the byte, or `EOF`. At the end of the entry's data
    /// (`G.csize <= 0`) `readbyte()` also decrements `G.csize`; a read that
    /// comes up short before that (a truncated archive, `read()` returning
    /// 0) does not, and leaves `G.csize` as it is.
    fn next_byte(&mut self) -> i32 {
        match self.src.next_byte() {
            Some(c) => i32::from(c),
            None => {
                if self.src.remaining() == 0 {
                    self.eofs += 1;
                }
                EOF
            }
        }
    }

    /// `G.csize + G.incnt`: the entry's compressed bytes not yet read,
    /// negative once EOFs have been read past its end.
    fn unread(&self) -> i64 {
        // A compressed size is a zoff_t; a source past i64::MAX is not one.
        i64::try_from(self.src.remaining()).unwrap_or(i64::MAX) - self.eofs
    }

    /// `flush(__G__ redirSlide, (ulg)w, 0)`.
    fn flush(&mut self, w: u32) -> Result<(), Stop<E>> {
        (self.flush)(&self.slide[..w as usize]).map_err(Stop::Flush)
    }

    /// Gets the bit lengths for a code representation from the compressed
    /// stream into `l[..n]`: 0, or 4 when the data is in error.
    // port: explode.c:get_tree
    fn get_tree(&mut self, l: &mut [u32; 256], n: u32) -> i32 {
        // get bit lengths: `NEXTBYTE + 1` in unsigned, so an EOF is 0 pairs,
        // which the do-while reads as 2^32 (and stops on the overflow test)
        let mut i = (self.next_byte() + 1) as u32; // length/count pairs to read
        let mut k: u32 = 0; // next code
        loop {
            let mut j = self.next_byte() as u32;
            let b = (j & 0xf) + 1; // bits in code (1..16)
            j = ((j & 0xf0) >> 4) + 1; // codes with those bits (1..16)
            if k + j > n {
                return 4; // don't overflow l[]
            }
            loop {
                l[k as usize] = b;
                k += 1;
                j -= 1;
                if j == 0 {
                    break;
                }
            }
            i = i.wrapping_sub(1);
            if i == 0 {
                break;
            }
        }
        if k != n { 4 } else { 0 } // should have read n of them
    }

    /// The match copy both decoders share (the C repeats it verbatim):
    /// `n` bytes from window index `d`, `u` being "not yet flushed".
    ///
    /// The C's `memcpy` branch (`w - d >= e`, unsigned; not in Ubuntu's
    /// `-DNOMEMCPY` build) and its byte loop agree here: with `d < w` the
    /// ranges cannot overlap, and with `d > w` (reaching back across the
    /// window's wrap) the source lies `WSIZE - dist` (at least 57344) bytes
    /// past the destination while the copy runs at most `dist` (at most
    /// 127 + 8065 = 8192) bytes before the window's end. So the byte loop
    /// is the one port.
    fn copy(&mut self, w: &mut u32, u: &mut bool, mut d: u32, mut n: u32) -> Result<(), Stop<E>> {
        loop {
            d &= WS - 1;
            let mut e = WS - if d > *w { d } else { *w };
            if e > n {
                e = n;
            }
            n -= e;
            if *u && *w <= d {
                // before the entry's first byte: memzero, not the window
                self.slide[*w as usize..(*w + e) as usize].fill(0);
                *w += e;
                d += e;
            } else {
                loop {
                    self.slide[*w as usize] = self.slide[d as usize];
                    *w += 1;
                    d += 1;
                    e -= 1;
                    if e == 0 {
                        break;
                    }
                }
            }
            if *w == WS {
                self.flush(*w)?;
                *w = 0;
                *u = false;
            }
            if n == 0 {
                return Ok(());
            }
        }
    }

    /// The end both decoders share: flush the window's tail (even when it
    /// is empty), then check that exactly the compressed size was consumed.
    fn finish(&mut self, w: u32, k: u32) -> Result<(), Stop<E>> {
        // flush out redirSlide
        self.flush(w)?;
        // should have read csize bytes, but sometimes read one too many:
        // k>>3 compensates
        let unused = self.unread() + i64::from(k >> 3);
        if unused != 0 {
            return Err(Stop::Length { unused });
        }
        Ok(())
    }

    /// Decompresses imploded data with coded literals.
    #[allow(clippy::too_many_arguments)]
    // port: explode.c:explode_lit
    fn explode_lit(
        &mut self,
        ucsize: u64,
        tb: &[Huft],
        tl: &[Huft],
        td: &[Huft],
        bb: u32,
        bl: u32,
        bd: u32,
        bdl: u32,
    ) -> Result<(), Stop<E>> {
        // explode the coded data
        let mut b: u64 = 0; // bit buffer
        let mut k: u32 = 0; // number of bits in bit buffer
        let mut w: u32 = 0; // current window position
        let mut u = true; // buffer unflushed
        let mb = MASK_BITS[bb as usize]; // precompute masks for speed
        let ml = MASK_BITS[bl as usize];
        let md = MASK_BITS[bd as usize];
        let mdl = MASK_BITS[bdl as usize];
        let mut e: u32;
        let mut s = ucsize;
        while s > 0 {
            // do until ucsize bytes uncompressed
            needbits!(self, b, k, 1);
            if b & 1 != 0 {
                // then literal--decode it
                dumpbits!(b, k, 1);
                s -= 1;
                let t = decodehuft!(self, b, k, e, tb, bb, mb); // get coded literal
                self.slide[w as usize] = t.n as u8;
                w += 1;
                if w == WS {
                    self.flush(w)?;
                    w = 0;
                    u = false;
                }
            } else {
                // else distance/length
                dumpbits!(b, k, 1);
                needbits!(self, b, k, bdl); // get distance low bits
                let mut d = b as u32 & mdl;
                dumpbits!(b, k, bdl);
                let t = decodehuft!(self, b, k, e, td, bd, md); // get coded distance high bits
                d = w.wrapping_sub(d).wrapping_sub(u32::from(t.n)); // construct offset
                let t = decodehuft!(self, b, k, e, tl, bl, ml); // get coded length
                let mut n = u32::from(t.n);
                if e != 0 {
                    // get length extra bits
                    needbits!(self, b, k, 8);
                    n += b as u32 & 0xff;
                    dumpbits!(b, k, 8);
                }

                // do the copy
                s = s.saturating_sub(u64::from(n));
                self.copy(&mut w, &mut u, d, n)?;
            }
        }
        self.finish(w, k)
    }

    /// Decompresses imploded data with uncoded literals.
    // port: explode.c:explode_nolit
    fn explode_nolit(
        &mut self,
        ucsize: u64,
        tl: &[Huft],
        td: &[Huft],
        bl: u32,
        bd: u32,
        bdl: u32,
    ) -> Result<(), Stop<E>> {
        // explode the coded data
        let mut b: u64 = 0; // bit buffer
        let mut k: u32 = 0; // number of bits in bit buffer
        let mut w: u32 = 0; // current window position
        let mut u = true; // buffer unflushed
        let ml = MASK_BITS[bl as usize]; // precompute masks for speed
        let md = MASK_BITS[bd as usize];
        let mdl = MASK_BITS[bdl as usize];
        let mut e: u32;
        let mut s = ucsize;
        while s > 0 {
            // do until ucsize bytes uncompressed
            needbits!(self, b, k, 1);
            if b & 1 != 0 {
                // then literal--get eight bits
                dumpbits!(b, k, 1);
                s -= 1;
                needbits!(self, b, k, 8);
                self.slide[w as usize] = b as u8;
                w += 1;
                if w == WS {
                    self.flush(w)?;
                    w = 0;
                    u = false;
                }
                dumpbits!(b, k, 8);
            } else {
                // else distance/length
                dumpbits!(b, k, 1);
                needbits!(self, b, k, bdl); // get distance low bits
                let mut d = b as u32 & mdl;
                dumpbits!(b, k, bdl);
                let t = decodehuft!(self, b, k, e, td, bd, md); // get coded distance high bits
                d = w.wrapping_sub(d).wrapping_sub(u32::from(t.n)); // construct offset
                let t = decodehuft!(self, b, k, e, tl, bl, ml); // get coded length
                let mut n = u32::from(t.n);
                if e != 0 {
                    // get length extra bits
                    needbits!(self, b, k, 8);
                    n += b as u32 & 0xff;
                    dumpbits!(b, k, 8);
                }

                // do the copy
                s = s.saturating_sub(u64::from(n));
                self.copy(&mut w, &mut u, d, n)?;
            }
        }
        self.finish(w, k)
    }
}

/// Explodes one imploded entry, reading through `src`, decoding into
/// `window` (unzip's `slide[]`), and writing through `flush` in exactly the
/// chunks `explode()` passes to unzip's `flush()`: every full 64 KiB
/// window, then the final `w` bytes, an empty slice when the output is
/// empty or a multiple of 64 KiB.
///
/// `flags` is the entry's general-purpose bit flag: bit 1 selects the 8K
/// window (seven uncoded low distance bits, else the 4K window's six), bit 2
/// a literal tree (three trees, minimum match 3, else two and 2).
/// `ucsize` is the entry's uncompressed size (`G.lrec.ucsize`), which is
/// what stops the decoder (see the module notes): the output is at least
/// `ucsize` bytes, more when the last match runs past it.
///
/// `window` is the caller's and must hold at least [`WSIZE`] bytes (only the
/// first `WSIZE` are used; a shorter one panics). It is not cleared, but
/// explode never reads what it held before (the module notes say why).
///
/// Stops as `explode()` returns: `Stop::Code(1)` for an incomplete tree or
/// an invalid code, `Stop::Code(2)` for an oversubscribed tree,
/// `Stop::Code(4)` for a bad tree description (`get_tree`),
/// [`Stop::Length`] (the C's 5) when the stream did not end exactly at the
/// compressed size, after everything was flushed, and `Stop::Flush` with
/// `flush`'s own error. The C's 3 (out of memory) never happens: the
/// tables are bounded by the 256 codes of a tree.
// port: explode.c:explode
pub fn explode<S: ByteSource, E>(
    src: &mut S,
    flags: u16,
    ucsize: u64,
    window: &mut [u8],
    flush: &mut dyn FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), Stop<E>> {
    assert!(
        window.len() >= WSIZE,
        "explode: window of {} bytes, under WSIZE",
        window.len()
    );
    let mut g = Explode {
        src,
        slide: &mut window[..WSIZE],
        flush,
        eofs: 0,
    };
    let mut tb: Vec<Huft> = Vec::new(); // literal code table
    let mut tl: Vec<Huft> = Vec::new(); // length code table
    let mut td: Vec<Huft> = Vec::new(); // distance code table
    let mut bb: u32 = 0; // bits for tb
    let mut l = [0u32; 256]; // bit lengths for codes

    // Tune base table sizes.
    let mut bl: u32 = 7; // bits for tl
    let mut bd: u32 = if g.unread() > 200_000 { 8 } else { 7 }; // bits for td

    let lit = flags & 4 != 0;
    if lit {
        // With literal tree--minimum match length is 3
        bb = 9; // base table size for literals
        let r = g.get_tree(&mut l, 256);
        if r != 0 {
            return Err(Stop::Code(r));
        }
        let r = huft_build(&l, 256, &[], &[], &mut tb, &mut bb);
        if r != 0 {
            return Err(Stop::Code(r));
        }
        let r = g.get_tree(&mut l, 64);
        if r != 0 {
            return Err(Stop::Code(r));
        }
        let r = huft_build(&l[..64], 0, &CPLEN3, &EXTRA, &mut tl, &mut bl);
        if r != 0 {
            return Err(Stop::Code(r));
        }
    } else {
        // No literal tree--minimum match length is 2
        let r = g.get_tree(&mut l, 64);
        if r != 0 {
            return Err(Stop::Code(r));
        }
        let r = huft_build(&l[..64], 0, &CPLEN2, &EXTRA, &mut tl, &mut bl);
        if r != 0 {
            return Err(Stop::Code(r));
        }
    }

    let r = g.get_tree(&mut l, 64);
    if r != 0 {
        return Err(Stop::Code(r));
    }
    let bdl: u32; // number of uncoded lower distance bits
    let r = if flags & 2 != 0 {
        // true if 8K
        bdl = 7;
        huft_build(&l[..64], 0, &CPDIST8, &EXTRA, &mut td, &mut bd)
    } else {
        // else 4K
        bdl = 6;
        huft_build(&l[..64], 0, &CPDIST4, &EXTRA, &mut td, &mut bd)
    };
    if r != 0 {
        return Err(Stop::Code(r));
    }

    if lit {
        g.explode_lit(ucsize, &tb, &tl, &td, bb, bl, bd, bdl)
    } else {
        g.explode_nolit(ucsize, &tl, &td, bl, bd, bdl)
    }
}
