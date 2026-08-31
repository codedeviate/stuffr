//! Identity shared by both xz backends: the C one (`xz_c`, Task 4 of Phase
//! 1e, via `liblzma`) and the pure `lzma-rust2` counterpart (`xz_pure`, Task
//! 5).
//!
//! Unlike zstd's pair, xz's pure backend is not a weaker fallback — Task 5's
//! brief describes it as a full codec at ratio parity, so `c-backed` is a
//! speed choice for xz rather than a capability one. That does not change
//! the shape here: whichever backend is compiled in must alone still expose
//! the identical [`FormatId`], magic rule and [`FormatMeta`], because that
//! identity is what makes `--format xz`, magic detection, and `stf formats`'
//! single `xz` row work the same regardless of which backend produced the
//! binary. Neither backend module can own it: an `xz-pure`-only build has no
//! `xz_c` module at all, and vice versa, so the shared pieces live here
//! instead and each backend re-exports them under its own name.
//!
//! Gated on `any(feature = "xz-c", feature = "xz-pure")` so this module does
//! not exist — and cannot produce a dead-code warning — in a build with
//! neither.

use stuffr_core::{FormatId, FormatMeta, MagicRule};

/// The identity both backends register under.
pub const XZ: FormatId = FormatId::new("xz");

/// The xz stream header magic, `FD 37 7A 58 5A 00` at offset 0 — reused by
/// both backends' registration metadata for magic detection.
pub(crate) const XZ_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
    format: XZ,
}];

/// Registration metadata for xz, shared by both backends.
pub fn xz_meta() -> FormatMeta {
    FormatMeta::codec(XZ, &["xz"], XZ_MAGIC)
}
