//! Info-ZIP's own inflater, deflate (method 8) and deflate64 (method 9),
//! ported from UnZip 6.0's `inflate.c` (Mark Adler, version c17e;
//! Info-ZIP licence, see the parent module): the non-`USE_ZLIB` path, with
//! `USE_DEFLATE64`, `CHECK_EOF` and `PKZIP_BUG_WORKAROUND` on, `DLL`,
//! `FIX_PAST_EOB_BY_TABLEADJUST` and `ASM_INFLATECODES` off — the options
//! both references build with. Apple's `inflate.c` and `inflate.h` are
//! byte-identical to upstream's, and Ubuntu's patch series touches only the
//! zlib path (`26-cve-2019-13232-fix-bug-in-uzinflate.patch`), so this one
//! port is both flavours'. Ubuntu's `-DNOMEMCPY` changes nothing observable
//! (see [`Inflate::inflate_codes`]).
//!
//! **The window is 64 KiB for both methods.** `unzpriv.h:884` makes
//! `WSIZE` 65536 whenever `USE_DEFLATE64` is defined, which it is by
//! default (`unzpriv.h:65`), and `inflate()` uses that one `slide[]` for
//! plain deflate too. So output is flushed in 65536-byte slides whatever the
//! method. Probed: a 60000-byte deflate entry damaged at about 45000 bytes
//! of output gives `unzip -p` 0 bytes on both references, where a 32 KiB
//! window would give 32768.
//!
//! The C's globals (`G.wp`, `G.bb`, `G.bk`, `G.fixed_*`,
//! `G.cplens`/`cplext`/`cpdext`) are one [`Inflate`] per call, borrowing the
//! caller's window for `G.slide`. Each function
//! keeps the C's local copies of the bit buffer (`b`, `k`) and window
//! position (`w`), restored to the struct where the C restores them.
//!
//! **The caller's window.** `slide[]` is the caller's: in unzip it is
//! `G.area.Slide`, one per run, holding the previous entry's output and the
//! messages unzip formats into it (`Info(slide, ...)`, `fnfilter`). A
//! distance reaching back past the start of this entry's output is never
//! rejected (`d &= wsize-1`, inflate.c:1012) and reads whatever is there, so
//! [`inflate`] takes the window rather than making one.

use super::{ByteSource, Stop};

/// `WSIZE` with `USE_DEFLATE64` (`unzpriv.h:886`): the window and flush
/// size, for deflate and deflate64 alike.
pub const WSIZE: usize = 0x10000;

/// `INVALID_CODE`: marks an unused `huft` entry.
pub(crate) const INVALID_CODE: u8 = 99;

/// `BMAX`: the longest code `huft_build` accepts (16, for explode).
const BMAX: usize = 16;

/// `N_MAX`: the most codes in any set.
const N_MAX: usize = 288;

/// consts.h `mask_bits[]`: and'ing with `MASK_BITS[n]` keeps the low `n` bits.
pub(crate) const MASK_BITS: [u32; 17] = [
    0x0000, 0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff, 0x01ff, 0x03ff, 0x07ff,
    0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff,
];

/// Order of the bit length code lengths (`border[]`).
const BORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Copy lengths for literal codes 257..285, deflate64 (`cplens64[]`): code
/// 285 is 3 plus 16 extra bits.
const CPLENS64: [u16; 31] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 3, 0, 0,
];
/// Copy lengths for literal codes 257..285, deflate (`cplens32[]`).
const CPLENS32: [u16; 31] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258, 0, 0,
];
/// Extra bits for literal codes 257..285, deflate64 (`cplext64[]`).
#[rustfmt::skip]
const CPLEXT64: [u8; 31] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16, INVALID_CODE, INVALID_CODE,
];
/// Extra bits for literal codes 257..285, deflate (`cplext32[]`).
#[rustfmt::skip]
const CPLEXT32: [u8; 31] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, INVALID_CODE, INVALID_CODE,
];
/// Copy offsets for distance codes 0..31 (`cpdist[]`, 32 entries under
/// `USE_DEFLATE64`).
const CPDIST: [u16; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];
/// Extra bits for distance codes 0..31, deflate64 (`cpdext64[]`).
const CPDEXT64: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];
/// Extra bits for distance codes 0..31, deflate (`cpdext32[]` with
/// `PKZIP_BUG_WORKAROUND`): codes 30 and 31 are invalid.
#[rustfmt::skip]
const CPDEXT32: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
    12, 12, 13, 13, INVALID_CODE, INVALID_CODE,
];

/// `MAXLITLENS` with `PKZIP_BUG_WORKAROUND`.
const MAXLITLENS: usize = 288;
/// `MAXDISTS` with `USE_DEFLATE64`.
const MAXDISTS: usize = 32;

/// Bits in the base literal/length lookup table (`lbits`).
const LBITS: u32 = 9;
/// Bits in the base distance lookup table (`dbits`).
const DBITS: u32 = 6;

/// The message `inflate_dynamic` prints for an incomplete literal/length
/// tree: `MESSAGE((uch *)"(incomplete l-tree)  ", 21L, 1)`.
pub const INCOMPLETE_L_TREE: &str = "(incomplete l-tree)  ";
/// The message `inflate_dynamic` prints for an incomplete distance tree:
/// `MESSAGE((uch *)"(incomplete d-tree)  ", 21L, 1)`.
pub const INCOMPLETE_D_TREE: &str = "(incomplete d-tree)  ";

/// One `struct huft` entry (`unzpriv.h:2199`).
///
/// `e` is the C's operation: 32 a literal, 31 end-of-block, below 31 a
/// length or distance base with `e` extra bits, 33..48 a link to a
/// subtable of `e & 31` bits, [`INVALID_CODE`] an unused code. The C's
/// union `v` is two fields here: `n` (`v.n`, the value or base) and `t`
/// (`v.t`, the subtable's start in the same [`huft_build`] arena).
///
/// In the C, setting `v.t` on the reused `r` overwrites `v.n` with pointer
/// bits, so a later invalid entry copied from `r` carries them. Those are
/// never read: every decoder returns on `e == 99` before it reads `v`, and
/// the one place `v.n` of an invalid entry is read (the bit-length tree in
/// `inflate_dynamic`) is a single-level table with no links. So `n` keeps
/// the last value assigned, which is exactly what the C reads there.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct Huft {
    pub(crate) e: u8,
    pub(crate) b: u8,
    pub(crate) n: u16,
    pub(crate) t: u32,
}

/// Given code lengths `b` (all `<= BMAX`, at most `N_MAX` of them) and a
/// maximum lookup width `*m`, builds the decoding tables into `t`: the root
/// table first, at index 0, then each subtable, linked by index where the C
/// links by pointer. Codes `0..s` are simple (their value is the code);
/// the rest take their base from `d` and extra bits from `e`, indexed by
/// `code - s`.
///
/// Returns as the C does: 0 on success, 1 if the code set is incomplete
/// (the tables are still built, with the missing codes [`INVALID_CODE`]),
/// 2 if the lengths are oversubscribed. An all-zero set returns 0 with `t`
/// empty (the C's `*t = NULL`) and `*m` 0. The C's 3 (out of memory) is
/// never returned: `t` is a `Vec`, and its size is bounded by `N_MAX` and
/// `BMAX` as the C's mallocs are. On 2, `*m` has been bounded already and
/// `t` is empty, as the C's `*t` is untouched.
///
/// The C's `huft_free` is `Drop` on `t`.
// port: inflate.c:huft_build
pub(crate) fn huft_build(
    b: &[u32],
    s: u32,
    d: &[u16],
    e: &[u8],
    t: &mut Vec<Huft>,
    m: &mut u32,
) -> i32 {
    let n = b.len() as u32;
    debug_assert!(n as usize <= N_MAX);
    t.clear();

    // Generate counts for each bit length.
    let el: u32 = if n > 256 { b[256] } else { BMAX as u32 };
    let mut c = [0u32; BMAX + 1];
    for &len in b {
        c[len as usize] += 1;
    }
    if c[0] == n {
        // null input--all zero length codes
        *m = 0;
        return 0;
    }

    // Find minimum and maximum length, bound *m by those.
    let mut j: u32 = 1;
    while j as usize <= BMAX {
        if c[j as usize] != 0 {
            break;
        }
        j += 1;
    }
    let mut k: i32 = j as i32; // minimum code length
    if *m < j {
        *m = j;
    }
    let mut i: u32 = BMAX as u32;
    while i != 0 {
        if c[i as usize] != 0 {
            break;
        }
        i -= 1;
    }
    let g: i32 = i as i32; // maximum code length
    if *m > i {
        *m = i;
    }

    // Adjust last length count to fill out codes, if needed.
    let mut y: i32 = 1 << j;
    while j < i {
        y -= c[j as usize] as i32;
        if y < 0 {
            return 2; // bad input: more codes than bits
        }
        j += 1;
        y <<= 1;
    }
    y -= c[i as usize] as i32;
    if y < 0 {
        return 2;
    }
    c[i as usize] += y as u32;

    // Generate starting offsets into the value table for each length.
    let mut x = [0u32; BMAX + 1];
    x[1] = 0;
    j = 0;
    let mut pc = 1usize;
    let mut xp = 2usize;
    loop {
        // while (--i): i == g here
        i -= 1;
        if i == 0 {
            break;
        }
        j += c[pc];
        pc += 1;
        x[xp] = j;
        xp += 1;
    }

    // Make a table of values in order of bit lengths.
    let mut v = [0u32; N_MAX];
    for (idx, &len) in b.iter().enumerate() {
        if len != 0 {
            v[x[len as usize] as usize] = idx as u32;
            x[len as usize] += 1;
        }
    }
    let n = x[g as usize]; // set n to length of v

    // Generate the Huffman codes and for each, make the table entries.
    x[0] = 0;
    i = 0; // first Huffman code is zero
    let mut p = 0usize; // grab values in bit order
    let mut h: i32 = -1; // no tables yet--level -1
    // `lx[h + 1]` is the C's `l[h]`: bits per table, from `l[-1]`.
    let mut lx = [0i32; BMAX + 1];
    let mut w: i32 = 0; // bits before this table == (l * h)
    let mut u = [0usize; BMAX]; // table stack
    let mut q = 0usize; // current table
    let mut z: u32 = 0; // number of entries in current table
    let mut r = Huft::default(); // table entry for structure assignment

    // go through the bit lengths (k already is bits in shortest code)
    while k <= g {
        let mut a = c[k as usize];
        while a > 0 {
            a -= 1;
            // here i is the Huffman code of length k bits for value v[p];
            // make tables up to required level
            while k > w + lx[(h + 1) as usize] {
                w += lx[(h + 1) as usize];
                h += 1; // add bits already decoded

                // compute minimum size table less than or equal to *m bits
                z = (g - w) as u32;
                if z > *m {
                    z = *m; // upper limit
                }
                j = (k - w) as u32;
                let mut f: u32 = 1 << j;
                if f > a + 1 {
                    // try a k-w bit table: too few codes for it
                    f -= a + 1; // deduct codes from patterns left
                    let mut xi = k as usize;
                    loop {
                        j += 1;
                        if j >= z {
                            break; // try smaller tables up to z bits
                        }
                        f <<= 1;
                        xi += 1;
                        if f <= c[xi] {
                            break; // enough codes to use up j bits
                        }
                        f -= c[xi]; // else deduct codes from patterns
                    }
                }
                if (w as u32) + j > el && (w as u32) < el {
                    j = el - w as u32; // make EOB code end at table
                }
                z = 1 << j; // table entries for j-bit table
                lx[(h + 1) as usize] = j as i32; // set table size in stack

                // allocate and link in new table
                q = t.len();
                t.resize(q + z as usize, Huft::default());
                u[h as usize] = q;

                // connect to last table, if there is one
                if h != 0 {
                    x[h as usize] = i; // save pattern for backing up
                    let lprev = lx[h as usize];
                    r.b = lprev as u8; // bits to dump before this table
                    r.e = (32 + j) as u8; // bits in this table
                    r.t = q as u32; // pointer to this table
                    let jj = (i & ((1u32 << w) - 1)) >> (w - lprev);
                    t[u[(h - 1) as usize] + jj as usize] = r; // connect to last table
                }
            }

            // set up table entry in r
            r.b = (k - w) as u8;
            if p >= n as usize {
                r.e = INVALID_CODE; // out of values--invalid code
            } else if v[p] < s {
                r.e = if v[p] < 256 { 32 } else { 31 }; // 256 is end-of-block code
                r.n = v[p] as u16; // simple code is just the value
                p += 1;
            } else {
                r.e = e[(v[p] - s) as usize]; // non-simple--look up in lists
                r.n = d[(v[p] - s) as usize];
                p += 1;
            }

            // fill code-like entries with r
            let f: u32 = 1 << (k - w);
            let mut jj = i >> w;
            while jj < z {
                t[q + jj as usize] = r;
                jj += f;
            }

            // backwards increment the k-bit code i
            let mut jb: u32 = 1 << (k - 1);
            while i & jb != 0 {
                i ^= jb;
                jb >>= 1;
            }
            i ^= jb;

            // backup over finished tables
            while (i & ((1u32 << w) - 1)) != x[h as usize] {
                h -= 1;
                w -= lx[(h + 1) as usize]; // don't need to update q
            }
        }
        k += 1;
    }

    // return actual size of base table
    *m = lx[1] as u32;

    // Return true (1) if we were given an incomplete table
    i32::from(y != 0 && g != 1)
}

/// `NEEDBITS(n)` with `CHECK_EOF` and without
/// `FIX_PAST_EOB_BY_TABLEADJUST`: makes sure `$b` holds at least `$n` bits,
/// but at EOF carries on with what it has while `$k` is not negative (the
/// C's "read beyond EOF" tolerance), and returns 1 once it is.
macro_rules! needbits {
    ($self:ident, $b:ident, $k:ident, $n:expr) => {
        while ($k as i32) < ($n as i32) {
            match $self.src.next_bits() {
                None => {
                    if ($k as i32) >= 0 {
                        break;
                    }
                    return Err(Stop::Code(1));
                }
                // unzip's EOF is sticky, so it shifts by a `k` that is never
                // negative here. funzip's encrypted `NEXTBYTE` is not
                // ([`ByteSource::next_bits`]): after its `EOF` it can give a
                // value again, with `k` "negative", and `(ulg)c << k` is
                // then undefined in C.
                // ruling: T12-2. The shift is taken modulo 64
                // (`wrapping_shl`), as the AArch64 `lsl` and x86-64 `shl`
                // both references run on take it.
                Some(c) => {
                    $b |= c.wrapping_shl($k);
                    $k = $k.wrapping_add(8);
                }
            }
        }
    };
}

/// `DUMPBITS(n)`: `b >>= n; k -= n`, `k` an unsigned that may wrap
/// "negative" after the EOF tolerance in [`needbits`].
macro_rules! dumpbits {
    ($b:ident, $k:ident, $n:expr) => {{
        let n: u32 = $n;
        $b >>= n;
        $k = $k.wrapping_sub(n);
    }};
}

/// The fixed-block tables, built on first use (`G.fixed_tl`, `G.fixed_bl`,
/// `G.fixed_td`, `G.fixed_bd`).
struct Fixed {
    tl: Vec<Huft>,
    bl: u32,
    td: Vec<Huft>,
    bd: u32,
}

/// The C's inflate globals for one entry.
struct Inflate<'a, S, E> {
    src: &'a mut S,
    /// `redirSlide`: the caller's window, its first `WSIZE` bytes.
    slide: &'a mut [u8],
    flush: &'a mut dyn FnMut(&[u8]) -> Result<(), E>,
    message: &'a mut dyn FnMut(&'static str),
    /// `G.wp`: current position in `slide`.
    wp: u32,
    /// `G.bb`: bit buffer (`ulg`, 64 bits on both references).
    bb: u64,
    /// `G.bk`: bits in the bit buffer.
    bk: u32,
    cplens: &'static [u16; 31],
    cplext: &'static [u8; 31],
    cpdext: &'static [u8; 32],
    fixed: Option<Fixed>,
    /// Test-only: the longest match distance decoded, for ruling P6.
    #[cfg(test)]
    max_distance: u32,
}

impl<S: ByteSource, E> Inflate<'_, S, E> {
    /// `FLUSH(w)`: hands `slide[..w]` to the caller's flush.
    fn flush(&mut self, w: u32) -> Result<(), Stop<E>> {
        (self.flush)(&self.slide[..w as usize]).map_err(Stop::Flush)
    }

    /// Inflates the codes of one compressed block until end-of-block.
    ///
    /// The match copy is the C's byte loop, which is all an `-DNOMEMCPY`
    /// build (Ubuntu's) has. Apple's build takes `memcpy` when
    /// `w - d >= e` (unsigned): with `d < w` the two ranges do not overlap
    /// and the results agree; with `d > w` (the source after the
    /// destination, the window having wrapped) they may overlap, which is
    /// undefined behaviour in C, and the byte loop gives what a forward
    /// `memcpy` gives there, `memmove`'s result.
    // port: inflate.c:inflate_codes
    fn inflate_codes(&mut self, tl: &[Huft], td: &[Huft], bl: u32, bd: u32) -> Result<(), Stop<E>> {
        const WS: u32 = WSIZE as u32;
        // make local copies of globals
        let mut b = self.bb; // initialize bit buffer
        let mut k = self.bk;
        let mut w = self.wp; // initialize window position

        // inflate the coded data
        let ml = MASK_BITS[bl as usize]; // precompute masks for speed
        let md = MASK_BITS[bd as usize];
        loop {
            // do until end of block
            needbits!(self, b, k, bl);
            let mut t = tl[(b as u32 & ml) as usize];
            loop {
                dumpbits!(b, k, u32::from(t.b));

                let mut e = u32::from(t.e);
                if e == 32 {
                    // then it's a literal
                    self.slide[w as usize] = t.n as u8;
                    w += 1;
                    if w == WS {
                        self.flush(w)?;
                        w = 0;
                    }
                    break;
                }

                if e < 31 {
                    // then it's a length; get length of block to copy
                    needbits!(self, b, k, e);
                    let mut n: u32 = u32::from(t.n) + (b as u32 & MASK_BITS[e as usize]);
                    dumpbits!(b, k, e);

                    // decode distance of block to copy
                    needbits!(self, b, k, bd);
                    // `td` is empty (the C's NULL) only when `bd` is 0 with
                    // 257 literal/length codes, a tree with no length
                    // codes, so this lookup is never reached then; the C
                    // would dereference NULL.
                    let Some(&first) = td.get((b as u32 & md) as usize) else {
                        return Err(Stop::Code(1));
                    };
                    t = first;
                    loop {
                        dumpbits!(b, k, u32::from(t.b));
                        e = u32::from(t.e);
                        if e < 32 {
                            break;
                        }
                        if t.e == INVALID_CODE {
                            return Err(Stop::Code(1));
                        }
                        e &= 31;
                        needbits!(self, b, k, e);
                        t = td[t.t as usize + (b as u32 & MASK_BITS[e as usize]) as usize];
                    }
                    needbits!(self, b, k, e);
                    let dist = u32::from(t.n) + (b as u32 & MASK_BITS[e as usize]);
                    #[cfg(test)]
                    {
                        self.max_distance = self.max_distance.max(dist);
                    }
                    let mut d: u32 = w.wrapping_sub(dist);
                    dumpbits!(b, k, e);

                    // do the copy
                    loop {
                        d &= WS - 1;
                        e = WS - if d > w { d } else { w };
                        if e > n {
                            e = n;
                        }
                        n -= e;
                        loop {
                            self.slide[w as usize] = self.slide[d as usize];
                            w += 1;
                            d += 1;
                            e -= 1;
                            if e == 0 {
                                break;
                            }
                        }
                        if w == WS {
                            self.flush(w)?;
                            w = 0;
                        }
                        if n == 0 {
                            break;
                        }
                    }
                    break;
                }

                if e == 31 {
                    // it's the EOB signal; restore the globals from the locals
                    self.wp = w;
                    self.bb = b;
                    self.bk = k;
                    return Ok(());
                }

                if t.e == INVALID_CODE {
                    return Err(Stop::Code(1));
                }

                e &= 31;
                needbits!(self, b, k, e);
                t = tl[t.t as usize + (b as u32 & MASK_BITS[e as usize]) as usize];
            }
        }
    }

    /// "Decompresses" a stored (type 0) block.
    // port: inflate.c:inflate_stored
    fn inflate_stored(&mut self) -> Result<(), Stop<E>> {
        const WS: u32 = WSIZE as u32;
        // make local copies of globals
        let mut b = self.bb;
        let mut k = self.bk;
        let mut w = self.wp;

        // go to byte boundary
        let mut n: u32 = k & 7;
        dumpbits!(b, k, n);

        // get the length and its complement
        needbits!(self, b, k, 16);
        n = b as u32 & 0xffff;
        dumpbits!(b, k, 16);
        needbits!(self, b, k, 16);
        if n != (!b & 0xffff) as u32 {
            return Err(Stop::Code(1)); // error in compressed data
        }
        dumpbits!(b, k, 16);

        // read and output the compressed data
        while n > 0 {
            n -= 1;
            needbits!(self, b, k, 8);
            self.slide[w as usize] = b as u8;
            w += 1;
            if w == WS {
                self.flush(w)?;
                w = 0;
            }
            dumpbits!(b, k, 8);
        }

        // restore the globals from the locals
        self.wp = w;
        self.bb = b;
        self.bk = k;
        Ok(())
    }

    /// Decompresses a fixed-Huffman (type 1) block, building the fixed
    /// tables first if this call has not yet.
    // port: inflate.c:inflate_fixed
    fn inflate_fixed(&mut self) -> Result<(), Stop<E>> {
        // if first time, set up tables for fixed blocks
        if self.fixed.is_none() {
            let mut l = [0u32; 288]; // length list for huft_build

            // literal table
            l[..144].fill(8);
            l[144..256].fill(9);
            l[256..280].fill(7);
            l[280..].fill(8); // make a complete, but wrong code set
            let mut tl = Vec::new();
            let mut bl = 7;
            let i = huft_build(&l, 257, self.cplens, self.cplext, &mut tl, &mut bl);
            if i != 0 {
                return Err(Stop::Code(i));
            }

            // distance table
            l[..MAXDISTS].fill(5); // make an incomplete code set
            let mut td = Vec::new();
            let mut bd = 5;
            let i = huft_build(&l[..MAXDISTS], 0, &CPDIST, self.cpdext, &mut td, &mut bd);
            if i > 1 {
                return Err(Stop::Code(i));
            }
            self.fixed = Some(Fixed { tl, bl, td, bd });
        }

        // decompress until an end-of-block code
        let fixed = self.fixed.take().expect("built above");
        let r = self.inflate_codes(&fixed.tl, &fixed.td, fixed.bl, fixed.bd);
        self.fixed = Some(fixed);
        r
    }

    /// Decompresses a dynamic-Huffman (type 2) block.
    // port: inflate.c:inflate_dynamic
    fn inflate_dynamic(&mut self) -> Result<(), Stop<E>> {
        let mut ll = [0u32; MAXLITLENS + MAXDISTS]; // lit./length and distance code lengths
        let mut tl: Vec<Huft> = Vec::new(); // literal/length code table
        let mut td: Vec<Huft> = Vec::new(); // distance code table

        // make local bit buffer
        let mut b = self.bb;
        let mut k = self.bk;

        // read in table lengths
        needbits!(self, b, k, 5);
        let nl = 257 + (b as u32 & 0x1f); // number of literal/length codes
        dumpbits!(b, k, 5);
        needbits!(self, b, k, 5);
        let nd = 1 + (b as u32 & 0x1f); // number of distance codes
        dumpbits!(b, k, 5);
        needbits!(self, b, k, 4);
        let nb = 4 + (b as u32 & 0xf); // number of bit length codes
        dumpbits!(b, k, 4);
        if nl as usize > MAXLITLENS || nd as usize > MAXDISTS {
            return Err(Stop::Code(1)); // bad lengths
        }

        // read in bit-length-code lengths
        let mut j: u32 = 0;
        while j < nb {
            needbits!(self, b, k, 3);
            ll[BORDER[j as usize]] = b as u32 & 7;
            dumpbits!(b, k, 3);
            j += 1;
        }
        while j < 19 {
            ll[BORDER[j as usize]] = 0;
            j += 1;
        }

        // build decoding table for trees--single level, 7 bit lookup
        let mut bl: u32 = 7;
        let mut retval = huft_build(&ll[..19], 19, &[], &[], &mut tl, &mut bl);
        if bl == 0 {
            retval = 1; // no bit lengths
        }
        if retval != 0 {
            return Err(Stop::Code(retval)); // incomplete code set
        }

        // read in literal and distance code lengths
        let n = nl + nd;
        let m = MASK_BITS[bl as usize];
        let mut i: u32 = 0;
        let mut l: u32 = 0; // last length
        while i < n {
            needbits!(self, b, k, bl);
            let th = tl[(b as u32 & m) as usize];
            dumpbits!(b, k, u32::from(th.b));
            j = u32::from(th.n);
            if j < 16 {
                // length of code in bits (0..15)
                l = j; // save last length in l
                ll[i as usize] = l;
                i += 1;
            } else if j == 16 {
                // repeat last length 3 to 6 times
                needbits!(self, b, k, 2);
                j = 3 + (b as u32 & 3);
                dumpbits!(b, k, 2);
                if i + j > n {
                    return Err(Stop::Code(1));
                }
                for _ in 0..j {
                    ll[i as usize] = l;
                    i += 1;
                }
            } else if j == 17 {
                // 3 to 10 zero length codes
                needbits!(self, b, k, 3);
                j = 3 + (b as u32 & 7);
                dumpbits!(b, k, 3);
                if i + j > n {
                    return Err(Stop::Code(1));
                }
                for _ in 0..j {
                    ll[i as usize] = 0;
                    i += 1;
                }
                l = 0;
            } else {
                // j == 18: 11 to 138 zero length codes
                needbits!(self, b, k, 7);
                j = 11 + (b as u32 & 0x7f);
                dumpbits!(b, k, 7);
                if i + j > n {
                    return Err(Stop::Code(1));
                }
                for _ in 0..j {
                    ll[i as usize] = 0;
                    i += 1;
                }
                l = 0;
            }
        }

        // restore the global bit buffer
        self.bb = b;
        self.bk = k;

        // build the decoding tables for literal/length and distance codes
        let nl = nl as usize;
        let mut bl = LBITS;
        let mut retval = huft_build(&ll[..nl], 257, self.cplens, self.cplext, &mut tl, &mut bl);
        if bl == 0 {
            retval = 1; // no literals or lengths
        }
        if retval != 0 {
            if retval == 1 {
                // the C tests `!uO.qflag` here; the caller's `message` does
                (self.message)(INCOMPLETE_L_TREE);
            }
            return Err(Stop::Code(retval)); // incomplete code set
        }
        let mut bd = DBITS;
        let mut retval = huft_build(
            &ll[nl..nl + nd as usize],
            0,
            &CPDIST,
            self.cpdext,
            &mut td,
            &mut bd,
        );
        // PKZIP_BUG_WORKAROUND
        if retval == 1 {
            retval = 0;
        }
        if bd == 0 && nl > 257 {
            retval = 1; // lengths but no distances
        }
        if retval != 0 {
            if retval == 1 {
                (self.message)(INCOMPLETE_D_TREE);
            }
            return Err(Stop::Code(retval));
        }

        // decompress until an end-of-block code
        self.inflate_codes(&tl, &td, bl, bd)
    }

    /// Decompresses one block; `Ok(true)` when it was the last.
    // port: inflate.c:inflate_block
    fn inflate_block(&mut self) -> Result<bool, Stop<E>> {
        // make local bit buffer
        let mut b = self.bb;
        let mut k = self.bk;

        // read in last block bit
        needbits!(self, b, k, 1);
        let e = b & 1 != 0;
        dumpbits!(b, k, 1);

        // read in block type
        needbits!(self, b, k, 2);
        let t = b as u32 & 3;
        dumpbits!(b, k, 2);

        // restore the global bit buffer
        self.bb = b;
        self.bk = k;

        // inflate that block type
        match t {
            2 => self.inflate_dynamic()?,
            0 => self.inflate_stored()?,
            1 => self.inflate_fixed()?,
            _ => return Err(Stop::Code(2)), // bad block type
        }
        Ok(e)
    }
}

/// Inflates one entry, deflate or (with `deflate64`) deflate64, reading
/// through `src`, decoding into `window` (unzip's `slide[]`), and writing
/// through `flush` in exactly the chunks
/// `inflate()` passes to unzip's `flush()`: every full 64 KiB window, then
/// the final `G.wp` bytes, which is an empty slice when the output is empty
/// or a multiple of 64 KiB. Partial output after an error is what was
/// flushed before it: the window's unflushed tail is dropped, as the C
/// drops it.
///
/// `window` is the caller's and must hold at least [`WSIZE`] bytes (only the
/// first `WSIZE` are used; a shorter one panics). It is not cleared: a
/// match distance reaching before this entry's first byte copies what the
/// window already holds there, as unzip copies from its persistent
/// `slide[]`. A caller emulating a fresh `G` passes zeros.
///
/// `message` receives the text `inflate_dynamic` passes to `MESSAGE` with
/// flag 1 (stderr), [`INCOMPLETE_L_TREE`] or [`INCOMPLETE_D_TREE`], just
/// before it stops with code 1. The C prints it only `if (!uO.qflag)`, and
/// through `UzpMessagePrnt` (stdout under `-t`); both are the caller's.
///
/// Stops with `Stop::Code(1)` for an incomplete or invalid code, a bad
/// stored-block length or EOF; `Stop::Code(2)` for a bad block type or an
/// oversubscribed tree; `Stop::Flush` with `flush`'s own error.
// port: inflate.c:inflate
pub fn inflate<S: ByteSource, E>(
    src: &mut S,
    deflate64: bool,
    window: &mut [u8],
    flush: &mut dyn FnMut(&[u8]) -> Result<(), E>,
    message: &mut dyn FnMut(&'static str),
) -> Result<(), Stop<E>> {
    inflate_state(src, deflate64, window, flush, message).0
}

/// [`inflate`], also returning the state for the tests.
fn inflate_state<'a, S: ByteSource, E>(
    src: &'a mut S,
    deflate64: bool,
    window: &'a mut [u8],
    flush: &'a mut dyn FnMut(&[u8]) -> Result<(), E>,
    message: &'a mut dyn FnMut(&'static str),
) -> (Result<(), Stop<E>>, Inflate<'a, S, E>) {
    assert!(
        window.len() >= WSIZE,
        "inflate: window of {} bytes, under WSIZE",
        window.len()
    );
    // initialize window position, bit buffer
    let mut g = Inflate {
        src,
        slide: &mut window[..WSIZE],
        flush,
        message,
        wp: 0,
        bb: 0,
        bk: 0,
        cplens: if deflate64 { &CPLENS64 } else { &CPLENS32 },
        cplext: if deflate64 { &CPLEXT64 } else { &CPLEXT32 },
        cpdext: if deflate64 { &CPDEXT64 } else { &CPDEXT32 },
        fixed: None,
        #[cfg(test)]
        max_distance: 0,
    };

    // decompress until the last block
    let r = (|| {
        while !g.inflate_block()? {}
        // flush out redirSlide and return (success, unless final FLUSH failed)
        let wp = g.wp;
        g.flush(wp)
    })();
    (r, g)
}

/// Test-only: [`inflate`] over a zeroed window, returning the longest match
/// distance decoded.
#[cfg(test)]
pub(super) fn inflate_max_distance<S: ByteSource, E>(
    src: &mut S,
    deflate64: bool,
    flush: &mut dyn FnMut(&[u8]) -> Result<(), E>,
) -> (Result<(), Stop<E>>, u32) {
    let mut quiet = |_| {};
    let mut window = vec![0; WSIZE];
    let (r, g) = inflate_state(src, deflate64, &mut window, flush, &mut quiet);
    (r, g.max_distance)
}
