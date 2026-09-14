//! Legacy, read-only formats: LHA/LZH, ARJ and Unix `compress`.
//!
//! Grouped under one module because all three share a shape the rest of
//! `stuffr-formats` does not: read-only, no encoder, proven against a
//! fixture whose expected output is known by construction rather than
//! produced by this project's own (nonexistent) encoder. See
//! `crates/stuffr-formats/fixtures/legacy/MANIFEST.md` for how each
//! fixture was made.

#[cfg(feature = "compress")]
pub mod compress_z;
#[cfg(feature = "lha")]
pub mod lha;
