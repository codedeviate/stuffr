//! Identity shared by both zstd backends: the C one (`zstd_c`, Task 2 of
//! Phase 1e) and the pure `ruzstd` fallback (`zstd_pure`, Task 3).
//!
//! The two backends are alternatives for the same format, never both at
//! once — Task 3 gates them mutually exclusive — but whichever one is
//! compiled in must alone still expose the identical [`FormatId`], magic
//! rule and [`FormatMeta`], because that identity is what makes `--format
//! zstd`, magic detection, and `stuffr formats`' single `zstd` row work the
//! same regardless of which backend produced the binary. Neither backend
//! module can own it: a `zstd-pure`-only build has no `zstd_c` module at
//! all, and vice versa, so the shared pieces live here instead and each
//! backend re-exports them under its own name.
//!
//! Gated on `any(feature = "zstd-c", feature = "zstd-pure")` so this module
//! does not exist — and cannot produce a dead-code warning — in a build
//! with neither.

use stuffr_core::{FormatId, FormatMeta, MagicRule};

/// The identity both backends register under.
pub const ZSTD: FormatId = FormatId::new("zstd");

/// The zstd frame magic, `0xFD2FB528` little-endian — `28 b5 2f fd` on the
/// wire — reused by both backends' registration metadata for magic
/// detection.
///
/// Followed by the sixteen skippable-frame magics zstd shares with lz4
/// (see [`crate::skippable`]): a stream may begin with any number of
/// skippable frames, and [`confirm`] looks behind them.
pub(crate) const ZSTD_MAGIC: &[MagicRule] = &{
    let frame = [MagicRule {
        offset: 0,
        bytes: &[0x28, 0xb5, 0x2f, 0xfd],
        format: ZSTD,
    }];
    let skippable = crate::skippable::skippable_rules!(ZSTD);
    let mut all = [frame[0]; 17];
    let mut i = 0;
    while i < 16 {
        all[i + 1] = skippable[i];
        i += 1;
    }
    all
};

/// Registration metadata for zstd, shared by both backends.
pub fn zstd_meta() -> FormatMeta {
    FormatMeta::codec(ZSTD, &["zst"], ZSTD_MAGIC).with_confirm(confirm)
}

/// Behind any skippable frames inside `prefix`, a zstd frame: its magic,
/// then a frame header descriptor whose reserved bit (bit 3) is clear. A
/// prefix holding only skippable frames confirms nothing.
///
/// A whole stream must hold the frame header its descriptor announces and
/// the first block's three-byte header after it: every frame has a block.
fn confirm(prefix: &[u8], whole: bool) -> bool {
    let Some(at) = crate::skippable::next_frame(prefix) else {
        return false;
    };
    let frame = &prefix[at..];
    if !crate::skippable::magic_agrees(frame, ZSTD_MAGIC[0].bytes) {
        return false;
    }
    let Some(&fhd) = frame.get(4) else {
        return !whole;
    };
    if fhd & 0x08 != 0 {
        return false;
    }
    !whole || frame.len() >= frame_header_len(fhd) + 3
}

/// A zstd frame header's length from its descriptor byte: magic, the
/// descriptor, the window byte (absent for a single segment), the
/// dictionary id and the content size (RFC 8878 §3.1.1.1).
fn frame_header_len(fhd: u8) -> usize {
    let single = fhd & 0x20 != 0;
    let dict = [0, 1, 2, 4][usize::from(fhd & 3)];
    let size = match fhd >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    4 + 1 + usize::from(!single) + dict + size
}

#[cfg(test)]
mod confirm_tests {
    use super::*;
    use crate::confirm_test::{assert_every_cut_confirms, assert_never_panics};
    use stuffr_core::ConfirmFn;

    fn confirm_fn() -> ConfirmFn {
        zstd_meta()
            .confirm
            .expect("zstd registers a confirm function")
    }

    /// The registered function judging a window (`whole` false): what
    /// every test below that cuts a stream short means.
    fn confirm() -> impl Fn(&[u8]) -> bool {
        |p| confirm_fn()(p, false)
    }

    /// A whole stream that stops inside the header the check reads is
    /// refused; the same bytes as a window onto a longer stream are not.
    #[test]
    fn confirm_refuses_a_whole_stream_cut_inside_its_header() {
        use crate::confirm_test::assert_whole_cuts_refused as refused;
        let end = frame_header_len(HELLO[4]) + 3;
        refused("zstd", confirm_fn(), &HELLO[..end], 0);
        assert!(confirm_fn()(&HELLO[..end], true));
        assert!(confirm_fn()(&HELLO[..5], false));
        // Skippable frames that end the whole stream hold no real frame.
        assert!(!confirm_fn()(&skippable(0, 8), true));
    }

    /// A small real frame: zstd 1.5.7 writing `hello` (a window
    /// descriptor, a checksum).
    const HELLO: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x29, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xa3,
        0x6d, 0x9f, 0x88,
    ];

    fn skippable(nibble: u8, payload: usize) -> Vec<u8> {
        let mut out = vec![0x50 | nibble, 0x2a, 0x4d, 0x18];
        out.extend_from_slice(&(payload as u32).to_le_bytes());
        out.resize(8 + payload, 0xa5);
        out
    }

    #[test]
    fn confirm_walks_skippable_frames_to_the_real_one() {
        let mut stream = skippable(0, 16);
        stream.extend(skippable(0xf, 0));
        let real = stream.len();
        stream.extend_from_slice(HELLO);
        assert_every_cut_confirms("skippable + zstd", confirm_fn(), &stream, real + 1);
        assert_every_cut_confirms("zstd", confirm_fn(), HELLO, 4);
        // Every FHD a writer can set: bits 0-1 dictionary ID size, 2
        // checksum, 4 unused, 5 single segment, 6-7 content size size.
        for fhd in (0u8..=255).filter(|b| b & 0x08 == 0) {
            assert!(confirm()(&[0x28, 0xb5, 0x2f, 0xfd, fhd]), "FHD {fhd:#04x}");
        }
    }

    #[test]
    fn confirm_rejects_magic_plus_noise() {
        let mut bad = HELLO.to_vec();
        bad[4] |= 0x08; // the reserved bit
        assert!(!confirm()(&bad));
        // Skippable frames, then something else.
        let mut lz4_next = skippable(0, 16);
        lz4_next.extend_from_slice(&[0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7]);
        assert!(!confirm()(&lz4_next));
        let mut noise = skippable(5, 3);
        noise.extend_from_slice(b"ordinary text");
        assert!(!confirm()(&noise));
        // Nothing but skippable frames inside the prefix.
        assert!(!confirm()(&skippable(0, 16)));
        assert!(!confirm()(&skippable(0, 5000)[..4096]));
    }

    #[test]
    fn confirm_never_panics_on_short_input() {
        assert_never_panics(confirm_fn(), HELLO);
        let mut stream = skippable(1, 4);
        stream.extend_from_slice(HELLO);
        assert_never_panics(confirm_fn(), &stream);
    }
}
