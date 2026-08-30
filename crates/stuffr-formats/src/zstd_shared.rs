//! Identity shared by both zstd backends: the C one (`zstd_c`, Task 2 of
//! Phase 1e) and the pure `ruzstd` fallback (`zstd_pure`, Task 3).
//!
//! The two backends are alternatives for the same format, never both at
//! once — Task 3 gates them mutually exclusive — but whichever one is
//! compiled in must alone still expose the identical [`FormatId`], magic
//! rule and [`FormatMeta`], because that identity is what makes `--format
//! zstd`, magic detection, and `stf formats`' single `zstd` row work the
//! same regardless of which backend produced the binary. Neither backend
//! module can own it: a `zstd-pure`-only build has no `zstd_c` module at
//! all, and vice versa, so the shared pieces live here instead and each
//! backend re-exports them under its own name.
//!
//! Gated on `any(feature = "zstd-c", feature = "zstd-pure")` so this module
//! does not exist — and cannot produce a dead-code warning — in a build
//! with neither.

use stuffr_core::{FormatId, FormatMeta, MagicRule};

/// The zstd frame magic, `0xFD2FB528` little-endian — `28 b5 2f fd` on the
/// wire — reused by both backends' `check_encode_opts`-free magic detection.
pub const ZSTD: FormatId = FormatId::new("zstd");

pub(crate) const ZSTD_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: &[0x28, 0xb5, 0x2f, 0xfd],
    format: ZSTD,
}];

/// Registration metadata for zstd, shared by both backends.
pub fn zstd_meta() -> FormatMeta {
    FormatMeta::codec(ZSTD, &["zst"], ZSTD_MAGIC)
}
