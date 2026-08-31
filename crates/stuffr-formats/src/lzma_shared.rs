//! Identity shared by both LZMA1 backends: the C one (`lzma_c`, this task —
//! Task 7 of Phase 1e, via `liblzma`) and the pure `lzma-rust2` counterpart
//! (`lzma_pure`, Task 6, which runs *after* this one despite the number:
//! its `#[cfg(not(feature = "lzma-c"))]` registration guard needs the
//! `lzma-c` feature to already exist, or referencing it trips rustc's
//! `unexpected_cfgs` lint under `-D warnings`).
//!
//! Same shape as `xz_shared.rs`: whichever backend is compiled in must alone
//! still expose the identical [`FormatId`] and [`FormatMeta`], because that
//! identity is what makes `--format lzma` and `stf formats`' single `lzma`
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
pub fn lzma_meta() -> FormatMeta {
    FormatMeta::codec(LZMA, &["lzma"], &[])
}
