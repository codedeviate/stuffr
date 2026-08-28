//! Universal compression and archive toolkit — the library behind the `stf`
//! command.
//!
//! Re-exports [`stuffr_core`] and owns the feature taxonomy: `pure` (default),
//! `c-backed`, `legacy`, `full`, plus one granular feature per format.

pub use stuffr_core as core;
pub use stuffr_core::*;

/// A registry containing every format this build was compiled with.
///
/// `stf formats` renders this, which is how a user tells a missing feature flag
/// from a corrupt file.
pub fn registry() -> stuffr_core::Registry {
    let mut r = stuffr_core::Registry::new();
    stuffr_formats::register_all(&mut r);
    r
}
