//! What a zip entry's decoder will allocate on the entry's own say-so, read
//! from the head of its compressed payload before the `zip` crate builds the
//! decoder (bug hunt 2026-11-15, finding 3).
//!
//! zip 9.4.0 builds each entry's decoder itself, from the payload's first
//! bytes: PPMd (method 98) a model of `((word >> 4) & 0xff) + 1` MiB,
//! allocated and touched before any output; LZMA (14) a dictionary of the
//! 4-byte size in its property header, which `lzma-rust2` cuts to the
//! entry's declared uncompressed size; xz (95) an LZMA2 dictionary per
//! block, with no memory limit (`XzReader::new`); zstd (93, C tier) the
//! frame's window, up to libzstd's default 128 MiB cap. None of that saw
//! `--memory-limit`, which a standalone `.lzma`, `.xz`, `.zst` or `.br`
//! honours by declaration — a 1 KB zip cost 276 MB, a 151 KB one 1 GiB.
//!
//! [`declared`] reads the same declaration; `zip.rs` refuses an entry whose
//! declaration exceeds the limit ([`Error::ResourceLimit`], exit 6) on both
//! rungs before the decoder exists. The limit is `OpenOpts::memory_limit`,
//! or, when a library caller passes none, `default_memory_limit()` — the
//! CLI's own default (25% of RAM, never below 256 MiB), so no archive a real
//! tool writes is refused without a limit asking for it: 7-Zip and WinZip's
//! largest PPMd model is 256 MiB, inside the floor.
//!
//! What a declaration cannot cover: an xz entry's LATER blocks (and a zstd
//! entry's later frames) each declare again, and only the first is in the
//! head; finding them means decoding. Those stay bounded as before — by
//! `lzma-rust2`'s and libzstd's own maxima, and by the read budget, since
//! an LZ dictionary is touched only as far as output reaches it. Real xz
//! writers use one dictionary for every block.

use stuffr_core::{Error, Result};

/// The payload bytes [`declared`] may need: an xz stream header (12) plus
/// its first block header (at most 1024).
pub(crate) const HEAD_LEN: u64 = 12 + 1024;

/// Compression methods whose decoder sizes itself from the payload's head.
pub(crate) const METHODS: [u16; 4] = [14, 93, 95, 98];

/// `(what, bytes)`: the memory `method`'s decoder will size itself to, from
/// `head` (the payload's first bytes) and the entry's declared uncompressed
/// size. `None` when the head declares nothing this can read — the decoder
/// then reports whatever is wrong with it.
pub(crate) fn declared(
    method: u16,
    uncompressed: Option<u64>,
    head: &[u8],
) -> Option<(&'static str, u64)> {
    match method {
        98 => {
            let word = u16::from_le_bytes([*head.first()?, *head.get(1)?]);
            Some(("a PPMd model", (u64::from((word >> 4) & 0xff) + 1) << 20))
        }
        14 => {
            // Version (2), properties size (2) = 5, then lc/lp/pb and the
            // dictionary size.
            if head.get(2..4)? != [5, 0] {
                return None;
            }
            let dict = u64::from(u32::from_le_bytes(head.get(5..9)?.try_into().ok()?));
            // `lzma-rust2` (`construct2_recover`) never sizes the dictionary
            // past the declared output, nor below 4 KiB.
            let mut need = dict.max(4096);
            if let Some(size) = uncompressed
                && size <= u64::MAX / 2
            {
                need = need.min(size.max(4096));
            }
            Some(("an LZMA dictionary", need))
        }
        95 => xz_first_dictionary(head).map(|d| ("an xz LZMA2 dictionary", d)),
        93 => zstd_window(head).map(|w| ("a zstd window", w)),
        _ => None,
    }
}

/// The refusal, or `Ok` when the declaration fits `limit`.
pub(crate) fn check(
    method: u16,
    uncompressed: Option<u64>,
    head: &[u8],
    limit: u64,
    name: &str,
) -> Result<()> {
    match declared(method, uncompressed, head) {
        Some((what, need)) if need > limit => Err(Error::ResourceLimit(format!(
            "zip entry `{name}` declares {what} of {need} bytes, but --memory-limit \
             allows only {limit} — raise --memory-limit to read it"
        ))),
        _ => Ok(()),
    }
}

/// An xz stream's first block's LZMA2 dictionary.
fn xz_first_dictionary(head: &[u8]) -> Option<u64> {
    if head.get(..6)? != [0xfd, b'7', b'z', b'X', b'Z', 0] {
        return None;
    }
    let size_byte = *head.get(12)?;
    if size_byte == 0 {
        // The index: a stream with no block.
        return None;
    }
    let header = head.get(12..12 + (usize::from(size_byte) + 1) * 4)?;
    let flags = header[1];
    let mut at = 2;
    if flags & 0x40 != 0 {
        varint(header, &mut at)?;
    }
    if flags & 0x80 != 0 {
        varint(header, &mut at)?;
    }
    for _ in 0..=(flags & 3) {
        let id = varint(header, &mut at)?;
        let props_len = usize::try_from(varint(header, &mut at)?).ok()?;
        let props = header.get(at..at.checked_add(props_len)?)?;
        at += props_len;
        if id == 0x21 && props_len == 1 {
            let bits = u32::from(props[0] & 0x3f);
            return match bits {
                0..=39 => Some((2 | u64::from(bits & 1)) << (bits / 2 + 11)),
                40 => Some(u64::from(u32::MAX)),
                _ => None,
            };
        }
    }
    None
}

/// An xz multibyte integer (at most 9 bytes).
fn varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..9 {
        let b = *bytes.get(*at)?;
        *at += 1;
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// A zstd frame's window: the Window_Descriptor, or the content size of a
/// single-segment frame.
fn zstd_window(head: &[u8]) -> Option<u64> {
    if head.get(..4)? != [0x28, 0xb5, 0x2f, 0xfd] {
        return None;
    }
    let fhd = *head.get(4)?;
    if fhd & 0x20 == 0 {
        let wd = *head.get(5)?;
        let base = 1u64 << (10 + u32::from(wd >> 3));
        return Some(base + (base / 8) * u64::from(wd & 7));
    }
    let dict_id = [0usize, 1, 2, 4][usize::from(fhd & 3)];
    let fcs_len = [1usize, 2, 4, 8][usize::from(fhd >> 6)];
    let field = head.get(5 + dict_id..5 + dict_id + fcs_len)?;
    let mut bytes = [0u8; 8];
    bytes[..fcs_len].copy_from_slice(field);
    let fcs = u64::from_le_bytes(bytes);
    Some(if fcs_len == 2 { fcs + 256 } else { fcs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppmd_declares_its_model_in_the_parameter_word() {
        let word: u16 = 7 | (255 << 4);
        assert_eq!(
            declared(98, None, &word.to_le_bytes()),
            Some(("a PPMd model", 256 << 20))
        );
        let word: u16 = 5 | (15 << 4);
        assert_eq!(
            declared(98, None, &word.to_le_bytes()),
            Some(("a PPMd model", 16 << 20))
        );
        assert_eq!(declared(98, None, &[1]), None);
    }

    #[test]
    fn lzma_is_cut_to_the_declared_output_as_the_decoder_cuts_it() {
        let mut head = vec![9, 20, 5, 0, 0x5d];
        head.extend((1u32 << 30).to_le_bytes());
        assert_eq!(
            declared(14, Some(1 << 30), &head),
            Some(("an LZMA dictionary", 1 << 30))
        );
        assert_eq!(
            declared(14, Some(100), &head),
            Some(("an LZMA dictionary", 4096))
        );
        assert_eq!(
            declared(14, None, &head),
            Some(("an LZMA dictionary", 1 << 30))
        );
        head[2] = 6;
        assert_eq!(declared(14, None, &head), None);
    }

    #[test]
    fn xz_reads_the_first_block_dictionary() {
        // A real `xz -9` stream header and first block header (64 MiB).
        let mut head = vec![
            0xfd, b'7', b'z', b'X', b'Z', 0, 0, 4, 0xe6, 0xd6, 0xb4, 0x46,
        ];
        head.extend([0x02, 0x00, 0x21, 0x01, 0x1c, 0x00, 0x00, 0x00, 0, 0, 0, 0]);
        assert_eq!(
            declared(95, None, &head),
            Some(("an xz LZMA2 dictionary", 64 << 20))
        );
        head[16] = 40;
        assert_eq!(
            declared(95, None, &head),
            Some(("an xz LZMA2 dictionary", u64::from(u32::MAX)))
        );
        head[16] = 41;
        assert_eq!(declared(95, None, &head), None);
        assert_eq!(declared(95, None, &head[..14]), None);
    }

    #[test]
    fn zstd_reads_the_window_descriptor_or_the_single_segment_size() {
        // Window_Descriptor 0x58: exponent 11, mantissa 0 -> 2 MiB.
        assert_eq!(
            declared(93, None, &[0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58]),
            Some(("a zstd window", 2 << 20))
        );
        // Single segment, 2-byte FCS of 1000 (+256).
        let mut head = vec![0x28, 0xb5, 0x2f, 0xfd, 0x60];
        head.extend(1000u16.to_le_bytes());
        assert_eq!(declared(93, None, &head), Some(("a zstd window", 1256)));
    }

    #[test]
    fn a_declaration_over_the_limit_is_a_resource_limit() {
        let word: u16 = 7 | (255 << 4);
        let err = check(98, None, &word.to_le_bytes(), 1 << 20, "m").unwrap_err();
        assert!(matches!(err, Error::ResourceLimit(ref m) if m.contains("--memory-limit")));
        check(98, None, &word.to_le_bytes(), 256 << 20, "m").unwrap();
        check(8, None, &[], 0, "deflate").unwrap();
    }
}
