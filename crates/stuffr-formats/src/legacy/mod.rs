//! Legacy, read-only formats: ARC/PAK, LHA/LZH, ARJ and Unix `compress`.
//!
//! Grouped under one module because all four share a shape the rest of
//! `stuffr-formats` does not: read-only, no encoder, proven against a
//! fixture whose expected output is known by construction or borrowed with
//! its provenance written down, rather than produced by this project's own
//! (nonexistent) encoder. See
//! `crates/stuffr-formats/fixtures/legacy/MANIFEST.md` for how each
//! fixture was made.

#[cfg(feature = "arc")]
pub mod arc;
#[cfg(feature = "arj")]
pub mod arj;
#[cfg(feature = "compress")]
pub mod compress_z;
// ZOO (Phase 3c Task 4) will need this too; widen the `cfg` when it lands
// rather than gating on formats that do not use it.
#[cfg(any(feature = "lha", feature = "arc"))]
mod crc;
// The DOS packed-timestamp helper both date-carrying legacy containers use.
#[cfg(any(feature = "arj", feature = "arc"))]
mod dos;
#[cfg(feature = "lha")]
pub mod lha;
