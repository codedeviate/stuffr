//! Skippable frames, the one framing zstd and lz4 share: a little-endian
//! magic `0x184D2A50`..=`0x184D2A5F` (`5X 2A 4D 18` on the wire), a
//! little-endian `u32` payload length, then that many bytes nobody reads.
//! Both formats' decoders step over any number of them, so a stream may
//! begin with one — and then begins with neither format's own magic.
//!
//! Both formats register all sixteen magics ([`skippable_rules!`]); which of
//! the two a hit belongs to is decided by each one's confirm function, which
//! walks the skippable frames inside the probe prefix with [`next_frame`] and
//! judges the real frame behind them. A prefix holding nothing but skippable
//! frames confirms neither, so a nameless one is ambiguous (exit 2, as it was
//! unknown before) and a named one resolves by its extension.

/// The sixteen skippable-frame magic rules for `$format`, for splicing into a
/// format's `&[MagicRule]` table.
macro_rules! skippable_rules {
    ($format:expr) => {
        $crate::skippable::skippable_rules!(
            @ $format;
            0x50 0x51 0x52 0x53 0x54 0x55 0x56 0x57 0x58 0x59 0x5a 0x5b 0x5c 0x5d 0x5e 0x5f
        )
    };
    (@ $format:expr; $($first:literal)*) => {
        [$(::stuffr_core::MagicRule {
            offset: 0,
            bytes: &[$first, 0x2a, 0x4d, 0x18],
            format: $format,
        }),*]
    };
}
pub(crate) use skippable_rules;

/// `true` when `bytes` begins with one of the sixteen skippable magics.
pub(crate) fn starts_skippable(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] & 0xf0 == 0x50 && bytes[1..4] == [0x2a, 0x4d, 0x18]
}

/// Where the first frame that is not skippable begins in `prefix`, stepping
/// over every skippable frame before it; `None` when no byte of such a frame
/// is inside `prefix` — the prefix is empty, or ends inside (or exactly at
/// the end of) a run of skippable frames, a skippable magic cut short
/// included. `Some(at)` guarantees
/// `at < prefix.len()`, so at least one byte of the real frame is visible.
pub(crate) fn next_frame(prefix: &[u8]) -> Option<usize> {
    let mut at = 0usize;
    loop {
        let rest = prefix.get(at..).filter(|r| !r.is_empty())?;
        if rest.len() < 4 && rest[0] & 0xf0 == 0x50 && magic_agrees(&rest[1..], &[0x2a, 0x4d, 0x18])
        {
            // A skippable magic cut short: still no byte of a real frame.
            return None;
        }
        if !starts_skippable(rest) {
            return Some(at);
        }
        let len = rest.get(4..8)?;
        let len = u32::from_le_bytes([len[0], len[1], len[2], len[3]]) as usize;
        // `checked_add` keeps a 32-bit target from wrapping past the end.
        at = at.checked_add(8)?.checked_add(len)?;
    }
}

/// `true` when the bytes of `frame` that are visible agree with `magic`: a
/// frame cut short inside its magic is still that frame.
pub(crate) fn magic_agrees(frame: &[u8], magic: &[u8]) -> bool {
    let n = frame.len().min(magic.len());
    frame[..n] == magic[..n]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skippable(nibble: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x50 | nibble, 0x2a, 0x4d, 0x18];
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn steps_over_every_skippable_frame_to_the_real_one() {
        let mut bytes = skippable(0, &[7; 16]);
        bytes.extend(skippable(0xf, &[]));
        let real = bytes.len();
        bytes.extend_from_slice(b"REAL");
        assert_eq!(next_frame(&bytes), Some(real));
        assert_eq!(next_frame(b"REAL"), Some(0));
    }

    #[test]
    fn a_prefix_of_skippable_frames_alone_has_no_real_frame() {
        let whole = skippable(3, &[0; 32]);
        for cut in 0..=whole.len() {
            assert_eq!(next_frame(&whole[..cut]), None, "cut at {cut}");
        }
        // A declared length past the prefix, and one that would overflow.
        let mut huge = vec![0x5a, 0x2a, 0x4d, 0x18];
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        huge.extend_from_slice(&[0; 64]);
        assert_eq!(next_frame(&huge), None);
    }

    #[test]
    fn the_rules_cover_exactly_the_sixteen_magics() {
        const ID: stuffr_core::FormatId = stuffr_core::FormatId::new("probe");
        let rules = skippable_rules!(ID);
        for (n, rule) in rules.iter().enumerate() {
            let magic = (0x184D_2A50u32 + n as u32).to_le_bytes();
            assert_eq!(rule.bytes, magic);
            assert!(starts_skippable(rule.bytes));
        }
        assert!(!starts_skippable(&0x184D_2A60u32.to_le_bytes()));
        assert!(!starts_skippable(&0x184D_2A4Fu32.to_le_bytes()));
    }

    #[test]
    fn a_magic_cut_short_agrees_with_itself() {
        assert!(magic_agrees(&[0x28, 0xb5], &[0x28, 0xb5, 0x2f, 0xfd]));
        assert!(!magic_agrees(&[0x28, 0xb6], &[0x28, 0xb5, 0x2f, 0xfd]));
        assert!(magic_agrees(
            &[0x28, 0xb5, 0x2f, 0xfd, 0],
            &[0x28, 0xb5, 0x2f, 0xfd]
        ));
    }
}
