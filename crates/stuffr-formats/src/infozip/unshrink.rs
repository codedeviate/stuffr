//! Info-ZIP's own unshrinker, shrink (method 1: dynamic LZW of 9 to 13 bit
//! codes with partial clearing), ported from UnZip 6.0's `unshrink.c`
//! (Greg Roelofs, version 1.22; Info-ZIP licence, see the parent module).
//! Both references build it (`USE_UNSHRINK`, `LZW_CLEAN` undefined); Apple's
//! `unshrink.c` is byte-identical to upstream's and Ubuntu's patch series
//! does not touch it, so this one port is both flavours'.
//!
//! **Stopping.** Unlike explode, the C never looks at the uncompressed
//! size: it stops when `READBITS` finds the compressed data exhausted
//! (`G.zipeof`), so [`unshrink`] takes no `ucsize` (probed: both references
//! give all 26001 bytes of `shrink-full-table.zip` declared as 10). A final
//! code with only some of its bits present is still decoded, its missing
//! bits zero, when the refill it needed got at least one byte (`G.zipeof`
//! is set only when none came); bits left over with no byte to follow are
//! dropped.
//!
//! **The work area.** The C keeps its tables in `G.area.shrink` — `Parent`
//! (8192 `shrint`s, an `int` on both references), `value` and `Stack` (8192
//! bytes each) — a union with inflate's and explode's `slide[]`. The port
//! keeps them at the same offsets in the caller's window, as native-endian
//! `i32`s and bytes, for two reasons. The C initialises only part of them
//! (`value[0..256]`, and all of `Parent[]` but `Parent[256]`), and a crafted stream
//! can read `value[]` of a code it never defined: a partial clear marks an
//! undefined parent code as having a child (`HAS_CHILD`), which makes it
//! look defined (see `partial_clear`). That byte is whatever the window
//! held, as in unzip. And the next entry's inflate or explode then finds
//! these tables in its window, as it does in unzip.
//!
//! The output goes through `G.outbuf`, unzip's own `OUTBUFSIZ` (64 KiB on
//! both references, text mode or not: `lenEOL * WSIZE`) buffer, which
//! unshrink only writes; that one is the port's own.

use super::inflate::{MASK_BITS, WSIZE};
use super::{ByteSource, Stop};

/// `MAX_BITS`: the longest code.
const MAX_BITS: i32 = 13;
/// `HSIZE`: codes in the table.
const HSIZE: usize = 1 << MAX_BITS;
/// `BOGUSCODE`: the escape code (and the root's parent).
const BOGUSCODE: i32 = 256;
/// `CODE_MASK`: the parent's index in `Parent[]`.
const CODE_MASK: i32 = HSIZE as i32 - 1;
/// `FREE_CODE`: the code is unused or was cleared.
const FREE_CODE: i32 = HSIZE as i32;
/// `HAS_CHILD`: the code has a child (do not clear).
const HAS_CHILD: i32 = (HSIZE as i32) << 1;
/// `OUTBUFSIZ` (`lenEOL * WSIZE`), also `RAWBUFSIZ`: the flush size.
const OUTBUFSIZ: usize = WSIZE;

/// Byte offset of `G.area.shrink.Parent` in the window.
const PARENT_AT: usize = 0;
/// Byte offset of `G.area.shrink.value`.
const VALUE_AT: usize = PARENT_AT + HSIZE * 4;
/// Byte offset of `G.area.shrink.Stack`.
const STACK_AT: usize = VALUE_AT + HSIZE;
/// `stacktop`'s index in `Stack`.
const STACKTOP: isize = HSIZE as isize - 1;

/// The C's unshrink state for one entry.
struct Unshrink<'a, S, E> {
    src: &'a mut S,
    /// `G.area`: the caller's window, holding `Parent`, `value` and `Stack`.
    area: &'a mut [u8],
    flush: &'a mut dyn FnMut(&[u8]) -> Result<(), E>,
    /// `G.outbuf` and `G.outcnt`.
    outbuf: Vec<u8>,
    /// `G.bitbuf`, zeroed for each entry by `extract_or_test_member`.
    bitbuf: u64,
    /// `G.bits_left`; negative after a short final code.
    bits_left: i32,
    /// `G.zipeof`.
    zipeof: bool,
    /// Test-only: partial clears performed.
    #[cfg(test)]
    partial_clears: u32,
}

impl<S: ByteSource, E> Unshrink<'_, S, E> {
    /// `parent[code]`.
    fn parent(&self, code: i32) -> i32 {
        let at = PARENT_AT + code as usize * 4;
        i32::from_ne_bytes(self.area[at..at + 4].try_into().expect("four bytes"))
    }

    /// `parent[code] = v`.
    fn set_parent(&mut self, code: i32, v: i32) {
        let at = PARENT_AT + code as usize * 4;
        self.area[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    }

    /// `Value[code]`.
    fn value(&self, code: i32) -> u8 {
        self.area[VALUE_AT + code as usize]
    }

    /// `Value[code] = v`.
    fn set_value(&mut self, code: i32, v: u8) {
        self.area[VALUE_AT + code as usize] = v;
    }

    /// `READBITS(nbits, zdest)`: refills `G.bitbuf` up to its last byte only
    /// when it holds fewer than `nbits` bits, setting `G.zipeof` when not
    /// one byte came. The code is taken whatever was refilled, so a final
    /// partial code decodes with zeros for its missing bits, and
    /// `bits_left` goes negative.
    fn readbits(&mut self, nbits: i32) -> i32 {
        if nbits > self.bits_left {
            self.zipeof = true;
            while self.bits_left <= 8 * (8 - 1) {
                let Some(temp) = self.src.next_byte() else {
                    break;
                };
                // The C shifts by a negative `bits_left` only if a byte
                // follows an EOF, which a sticky source never gives;
                // `wrapping_shl` keeps a source that does from panicking.
                self.bitbuf |= u64::from(temp).wrapping_shl(self.bits_left as u32);
                self.bits_left += 8;
                self.zipeof = false;
            }
        }
        let zdest = (self.bitbuf as u32 & MASK_BITS[nbits as usize]) as i32;
        self.bitbuf >>= nbits;
        self.bits_left -= nbits;
        zdest
    }

    /// `*G.outptr++ = c`, flushing a full `G.outbuf`.
    fn put(&mut self, c: u8) -> Result<(), Stop<E>> {
        self.outbuf.push(c);
        if self.outbuf.len() == OUTBUFSIZ {
            (self.flush)(&self.outbuf).map_err(Stop::Flush)?;
            self.outbuf.clear();
        }
        Ok(())
    }

    // port: unshrink.c:unshrink
    fn unshrink(&mut self) -> Result<(), Stop<E>> {
        let mut codesize = 9;
        let mut lastfreecode = BOGUSCODE;

        // (the C's PK_MEM3, when the text-mode `G.outbuf2` cannot be
        // allocated, is the front end's: the port allocates nothing there)

        for code in 0..BOGUSCODE {
            self.set_value(code, code as u8);
            self.set_parent(code, BOGUSCODE);
        }
        for code in BOGUSCODE + 1..HSIZE as i32 {
            self.set_parent(code, FREE_CODE);
        }

        // Get and output first code, then loop over remaining ones.
        let mut oldcode = self.readbits(codesize);
        if self.zipeof {
            return Ok(());
        }

        let mut finalval = oldcode as u8;
        self.put(finalval)?;

        loop {
            let mut code = self.readbits(codesize);
            if self.zipeof {
                break;
            }
            if code == BOGUSCODE {
                // possible to have consecutive escapes?
                code = self.readbits(codesize);
                if self.zipeof {
                    break;
                }
                if code == 1 {
                    codesize += 1;
                    if codesize > MAX_BITS {
                        return Err(Stop::Code(2)); // PK_ERR
                    }
                } else if code == 2 {
                    // clear leafs (nodes with no children)
                    self.partial_clear(lastfreecode);
                    lastfreecode = BOGUSCODE; // reset start of free-node search
                }
                continue;
            }

            // Translate code: traverse tree from leaf back to root.
            let mut newstr = STACKTOP;
            let curcode = code;

            if self.parent(code) == FREE_CODE {
                // a KwKwK code
                self.area[STACK_AT + newstr as usize] = finalval;
                newstr -= 1;
                code = oldcode;
            }

            while code != BOGUSCODE {
                if newstr < 0 {
                    // Bogus compression stream caused buffer underflow!
                    return Err(Stop::Code(2)); // PK_ERR
                }
                if self.parent(code) == FREE_CODE {
                    // a KwKwK code
                    self.area[STACK_AT + newstr as usize] = finalval;
                    newstr -= 1;
                    code = oldcode;
                } else {
                    self.area[STACK_AT + newstr as usize] = self.value(code);
                    newstr -= 1;
                    code = self.parent(code) & CODE_MASK;
                }
            }

            let len = (STACKTOP - newstr) as usize;
            newstr += 1;
            finalval = self.area[STACK_AT + newstr as usize];

            // Write expanded string in reverse order to output buffer.
            let from = STACK_AT + newstr as usize;
            for p in from..from + len {
                let c = self.area[p];
                self.put(c)?;
            }

            // Add new leaf (first character of newstr) to tree as child of
            // oldcode: search for freecode.
            code = lastfreecode + 1;
            while (code as usize) < HSIZE && self.parent(code) != FREE_CODE {
                code += 1;
            }
            lastfreecode = code;
            if code as usize >= HSIZE {
                // invalid compressed data caused max-code overflow!
                return Err(Stop::Code(2)); // PK_ERR
            }

            self.set_value(code, finalval);
            self.set_parent(code, oldcode);
            oldcode = curcode;
        }

        // Flush any remaining data and return to sender...
        if !self.outbuf.is_empty() {
            (self.flush)(&self.outbuf).map_err(Stop::Flush)?;
        }
        Ok(())
    }

    /// Clears every leaf (a code no other code names as its parent) among
    /// `BOGUSCODE + 1 ..= lastcodeused`.
    ///
    /// A code's parent may be a code that is itself free (never defined, or
    /// cleared before the child was added: the C's "orphans"). The first
    /// loop still sets that parent's `HAS_CHILD`, so its `Parent[]` is no
    /// longer `FREE_CODE`; when it lies past `lastcodeused` the second loop
    /// never resets it, and the code then reads as defined, with whatever
    /// `value[]` holds and `Parent[] & CODE_MASK` = 0. Ported as the C has it.
    // port: unshrink.c:partial_clear
    fn partial_clear(&mut self, lastcodeused: i32) {
        #[cfg(test)]
        {
            self.partial_clears += 1;
        }
        // first loop: mark each parent as such
        for code in BOGUSCODE + 1..=lastcodeused {
            let cparent = self.parent(code) & CODE_MASK;
            if cparent > BOGUSCODE {
                let p = self.parent(cparent);
                self.set_parent(cparent, p | HAS_CHILD); // set parent's child-bit
            }
        }

        // second loop: clear all nodes *not* marked as parents; reset flag bits
        for code in BOGUSCODE + 1..=lastcodeused {
            let p = self.parent(code);
            if p & HAS_CHILD != 0 {
                self.set_parent(code, p & !HAS_CHILD); // just clear child-bit
            } else {
                self.set_parent(code, FREE_CODE); // leaf: lose it
            }
        }
    }
}

/// Unshrinks one shrunk entry, reading through `src` until its compressed
/// data is exhausted, and writing through `flush` in exactly the chunks
/// `unshrink()` passes to unzip's `flush()`: every full 64 KiB `G.outbuf`,
/// then the rest, if any. Unlike [`inflate`](super::inflate()) and
/// [`explode`](super::explode()) there is no final empty flush: an empty
/// output flushes nothing.
///
/// `window` is the caller's (unzip's `G.area`, the `slide[]` the other
/// decoders use) and must hold at least [`WSIZE`] bytes; a shorter one
/// panics. The first 48 KiB take the C's tables, at the C's offsets (the
/// module notes say why); unshrink reads one stale byte from them only
/// where the C does.
///
/// Stops with `Stop::Code(2)` (`PK_ERR`) for a code size past 13 bits, a
/// string longer than the 8 KiB stack, or a full code table, and with
/// `Stop::Flush` with `flush`'s own error. It never returns the C's
/// `PK_MEM3`.
pub fn unshrink<S: ByteSource, E>(
    src: &mut S,
    window: &mut [u8],
    flush: &mut dyn FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), Stop<E>> {
    Unshrink::new(src, window, flush).unshrink()
}

impl<'a, S: ByteSource, E> Unshrink<'a, S, E> {
    /// The state `extract_or_test_member` and `unshrink()` set up.
    fn new(
        src: &'a mut S,
        window: &'a mut [u8],
        flush: &'a mut dyn FnMut(&[u8]) -> Result<(), E>,
    ) -> Self {
        assert!(
            window.len() >= WSIZE,
            "unshrink: window of {} bytes, under WSIZE",
            window.len()
        );
        Unshrink {
            src,
            area: &mut window[..STACK_AT + HSIZE],
            flush,
            outbuf: Vec::with_capacity(OUTBUFSIZ),
            bitbuf: 0,
            bits_left: 0,
            zipeof: false,
            #[cfg(test)]
            partial_clears: 0,
        }
    }
}

/// Test-only: [`unshrink`], also returning the partial clears it performed.
#[cfg(test)]
pub(super) fn unshrink_counted<S: ByteSource, E>(
    src: &mut S,
    window: &mut [u8],
    flush: &mut dyn FnMut(&[u8]) -> Result<(), E>,
) -> (Result<(), Stop<E>>, u32) {
    let mut g = Unshrink::new(src, window, flush);
    let r = g.unshrink();
    (r, g.partial_clears)
}
