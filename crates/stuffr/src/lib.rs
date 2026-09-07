//! Universal compression and archive toolkit — the library behind the `stuffr`
//! command.
//!
//! Re-exports [`stuffr_core`] and owns the feature taxonomy: `pure` (default),
//! `c-backed`, `legacy`, `full`, plus one granular feature per format.

pub use stuffr_core as core;
pub use stuffr_core::*;

pub mod entries;
pub mod ops;

/// Builds a registry containing every format this build was compiled with.
fn build_registry() -> stuffr_core::Registry {
    let mut r = stuffr_core::Registry::new();
    stuffr_formats::register_all(&mut r);
    r
}

/// The registry this build ships, built once.
///
/// `stuffr formats` renders this, which is how a user tells a missing feature flag
/// from a corrupt file.
///
/// Returns a shared reference rather than a fresh value: it was rebuilding five
/// HashMaps on every ops call. A consumer wanting a different set — an
/// out-of-tree format, or a deliberately reduced one — builds their own and
/// passes it to the `_with` variants.
pub fn registry() -> &'static stuffr_core::Registry {
    static REG: std::sync::OnceLock<stuffr_core::Registry> = std::sync::OnceLock::new();
    REG.get_or_init(build_registry)
}
