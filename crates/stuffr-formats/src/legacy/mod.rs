//! Legacy, read-only formats: LHA/LZH, ARJ and Unix `compress`.
//!
//! Grouped under one module because all three share a shape the rest of
//! `stuffr-formats` does not: read-only, no encoder, proven against a
//! fixture whose expected output is known by construction rather than
//! produced by this project's own (nonexistent) encoder. See
//! `crates/stuffr-formats/fixtures/legacy/MANIFEST.md` for how each
//! fixture was made.

#[cfg(feature = "arj")]
pub mod arj;
#[cfg(feature = "compress")]
pub mod compress_z;
// ARC and ZOO (Phase 3c) will need this too; gated on `lha` alone for now
// because `lha` is the only format that currently calls into it — widen the
// `cfg` when ARC/ZOO land rather than gating on formats that do not use it.
#[cfg(feature = "lha")]
mod crc;
#[cfg(feature = "lha")]
pub mod lha;
