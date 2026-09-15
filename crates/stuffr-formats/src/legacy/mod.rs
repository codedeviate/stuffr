//! Legacy, read-only formats: ARC/PAK, ZOO, LHA/LZH, ARJ and Unix `compress`.
//!
//! Grouped under one module because all five share a shape the rest of
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
// The least-significant-bit-first bit reader ARC's two bitstreams and ZOO's
// `lzd` all read through. See its own module doc for why THIS is shared
// where the LZW engines built on it are deliberately not.
#[cfg(any(feature = "arc", feature = "zoo"))]
mod bits;
#[cfg(feature = "compress")]
pub mod compress_z;
#[cfg(any(feature = "lha", feature = "arc", feature = "zoo"))]
mod crc;
// The DOS packed-timestamp helper every date-carrying legacy container uses.
#[cfg(any(feature = "arj", feature = "arc", feature = "zoo"))]
mod dos;
#[cfg(feature = "lha")]
pub mod lha;
#[cfg(feature = "zoo")]
pub mod zoo;
