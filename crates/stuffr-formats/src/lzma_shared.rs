//! Identity shared by both LZMA1 backends: the C one (`lzma_c`, this task —
//! Task 7 of Phase 1e, via `liblzma`) and the pure `lzma-rust2` counterpart
//! (`lzma_pure`, Task 6, which runs *after* this one despite the number:
//! its `#[cfg(not(feature = "lzma-c"))]` registration guard needs the
//! `lzma-c` feature to already exist, or referencing it trips rustc's
//! `unexpected_cfgs` lint under `-D warnings`).
//!
//! Same shape as `xz_shared.rs`: whichever backend is compiled in must alone
//! still expose the identical [`FormatId`] and [`FormatMeta`], because that
//! identity is what makes `--format lzma` and `stuffr formats`' single `lzma`
//! row work the same regardless of which backend produced the binary.
//! Neither backend module can own it: an `lzma-pure`-only build has no
//! `lzma_c` module at all, and vice versa, so the shared pieces live here
//! instead and each backend re-exports them under its own name.
//!
//! Gated on `any(feature = "lzma-c", feature = "lzma-pure")` so this module
//! does not exist — and cannot produce a dead-code warning — in a build with
//! neither.

use stuffr_core::{FormatId, FormatMeta};

/// The identity both backends register under.
pub const LZMA: FormatId = FormatId::new("lzma");

/// Registration metadata for LZMA1, shared by both backends.
///
/// No magic rules: unlike gzip, zlib, bzip2, lz4, snappy and xz, the `.lzma`
/// "alone" format's first byte encodes lc/lp/pb (commonly `0x5d`, but not
/// fixed by the format) and the next four the dictionary size — there is no
/// fixed signature to register. Registering `5d` alone would false-positive
/// on arbitrary binary data carrying that byte for unrelated reasons, so
/// detection is by extension only, and a `.lzma` stream arriving on a pipe
/// with no filename needs `--format lzma` — the same limitation this
/// project already documents for brotli and raw deflate.
///
/// Its confirm function grades only an extension's claim, since there is no
/// magic to hit.
pub fn lzma_meta() -> FormatMeta {
    FormatMeta::codec(LZMA, &["lzma"], &[]).with_confirm(confirm)
}

/// The 13-byte `.lzma` header: a properties byte encoding lc/lp/pb
/// (`(pb * 5 + lp) * 9 + lc`, so below 225), a little-endian dictionary
/// size of at least 4 KiB (liblzma's minimum), and a little-endian
/// uncompressed size that is either unknown (all `FF`) or at most 2^48 —
/// no writer records more, and liblzma refuses it.
///
/// A whole stream must hold the thirteen-byte header.
fn confirm(prefix: &[u8], whole: bool) -> bool {
    if whole && prefix.len() < 13 {
        return false;
    }
    if prefix.first().is_some_and(|&props| props >= 225) {
        return false;
    }
    if let Some(d) = prefix.get(1..5)
        && u32::from_le_bytes([d[0], d[1], d[2], d[3]]) < 4096
    {
        return false;
    }
    match prefix.get(5..13) {
        Some(s) => {
            let size = u64::from_le_bytes(s.try_into().unwrap_or([0; 8]));
            size == u64::MAX || size <= 1 << 48
        }
        None => true,
    }
}

#[cfg(test)]
mod confirm_tests {
    use super::*;
    use crate::confirm_test::{assert_every_cut_confirms, assert_never_panics};
    use stuffr_core::ConfirmFn;

    fn confirm_fn() -> ConfirmFn {
        lzma_meta()
            .confirm
            .expect("lzma registers a confirm function")
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
        let h = header(0x5d, 1 << 23, u64::MAX);
        refused("lzma", confirm_fn(), &h[..13], 0);
        assert!(confirm_fn()(&h[..12], false));
    }

    /// `props`, a dictionary size and an uncompressed size, as a header.
    fn header(props: u8, dict: u32, size: u64) -> Vec<u8> {
        let mut out = vec![props];
        out.extend_from_slice(&dict.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&[0x00, 0x34, 0x19, 0x49]);
        out
    }

    #[test]
    fn confirm_accepts_every_header_a_writer_emits() {
        for (props, dict, size) in [
            (0x5d, 1 << 23, u64::MAX),
            (0x5d, 4096, 0),
            (0x00, 1 << 16, 12),
            (224, u32::MAX, 1 << 48),
        ] {
            let what = format!("props {props:#04x} dict {dict} size {size}");
            assert_every_cut_confirms(&what, confirm_fn(), &header(props, dict, size), 0);
        }
    }

    #[test]
    fn confirm_rejects_magic_plus_noise() {
        assert!(!confirm()(&header(225, 1 << 23, u64::MAX)));
        assert!(!confirm()(&header(0xff, 1 << 23, u64::MAX)));
        assert!(!confirm()(&header(0x5d, 4095, u64::MAX)));
        assert!(!confirm()(&header(0x5d, 0, u64::MAX)));
        assert!(!confirm()(&header(0x5d, 1 << 23, (1 << 48) + 1)));
        assert!(!confirm()(&header(0x5d, 1 << 23, u64::MAX - 1)));
        assert!(!confirm()(b"ordinary text, not an LZMA header"));
    }

    #[test]
    fn confirm_never_panics_on_short_input() {
        assert_never_panics(confirm_fn(), &header(0x5d, 1 << 23, u64::MAX));
    }
}
