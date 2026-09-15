//! The least-significant-bit-first bit reader the legacy LZW and Huffman
//! decoders share.
//!
//! Extracted for the reason `legacy::dos` was, and deliberately NOT for the
//! reason `legacy::arc`'s and `legacy::compress_z`'s LZW engines were left
//! duplicated: those are different DIALECTS, so a shared abstraction would
//! have to be parameterised over the disagreement. This is the **same
//! computation** — pack bits into a `u32` accumulator low-end first, in
//! byte order, and answer `None` the moment the stream cannot supply the
//! full width asked for.
//!
//! Three readers want exactly that and each was independently correct about
//! it: ARC's squeeze Huffman layer, ARC's Crunched/Squashed LZW, and — as
//! of Phase 3c Task 4 — ZOO's `lzd` LZW, which is what made the
//! duplication real rather than hypothetical. zoo 2.10's own `rd_dcode`
//! (`lzd.c`) assembles its code out of `word = byte | (next << 8)` shifted
//! right by the offset within the byte, which is this same order arrived at
//! from a different direction.

/// Reads bits least-significant-first within each byte, in byte order.
///
/// [`Self::read_bits`] answers `None` the moment the stream cannot supply
/// the full width asked for, which is how every decoder built on this
/// detects a clean end of stream. A partial tail is therefore discarded
/// rather than zero-extended — the encoders that wrote these formats pad
/// the final byte with whatever was left in their own accumulator, so a
/// short read at the end is end-of-stream, never a code.
pub(super) struct LsbBitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    bits: u32,
}

impl<'a> LsbBitReader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        LsbBitReader {
            data,
            pos: 0,
            buf: 0,
            bits: 0,
        }
    }

    pub(super) fn read_bits(&mut self, n: u32) -> Option<u16> {
        debug_assert!(n <= 16);
        while self.bits < n {
            let byte = *self.data.get(self.pos)?;
            self.pos += 1;
            self.buf |= u32::from(byte) << self.bits;
            self.bits += 8;
        }
        let value = (self.buf & ((1u32 << n) - 1)) as u16;
        self.buf >>= n;
        self.bits -= n;
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one property both callers depend on and neither can see from the
    /// other's tests: bits come out low end first, and a code may straddle a
    /// byte boundary.
    #[test]
    fn nine_bit_codes_are_read_low_end_first_across_byte_boundaries() {
        // Two nine-bit codes, 257 and 258, packed low end first: 257
        // fills byte 0 and leaves its top bit as bit 0 of byte 1; 258 then
        // starts at bit 1 of byte 1 and spills its top two bits into byte
        // 2. That is 0x01, 0x05, 0x02 — and a reader that packed most
        // significant bit first, or that started each code on a byte
        // boundary, would give different answers for both.
        let mut br = LsbBitReader::new(&[0x01, 0x05, 0x02]);
        assert_eq!(br.read_bits(9), Some(257));
        assert_eq!(br.read_bits(9), Some(258));
        assert_eq!(br.read_bits(9), None, "six bits left cannot supply nine");
    }

    #[test]
    fn a_width_the_stream_cannot_supply_is_none_rather_than_a_short_code() {
        let mut br = LsbBitReader::new(&[0xFF]);
        assert_eq!(br.read_bits(8), Some(0xFF));
        assert_eq!(br.read_bits(1), None);
    }
}
