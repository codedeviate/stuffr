//! Format implementations, each behind its own Cargo feature.
//!
//! `stuffr-core` deliberately carries no format dependency; this is where they
//! live. [`register_all`] is the single extension point — a codec not
//! registered there is invisible to `stf formats` and to detection.

use stuffr_core::Registry;

mod normalize;

#[cfg(feature = "deflate")]
pub mod deflate;
#[cfg(feature = "gzip")]
pub mod gzip;
#[cfg(feature = "zlib")]
pub mod zlib;

/// Registers every format enabled in this build.
pub fn register_all(registry: &mut Registry) {
    // Silences an unused-parameter warning when no format feature is on.
    // Unconditional rather than gated on `not(any(...))`: with each later
    // task adding another format, a guard listing every feature would need
    // widening every time and would fail the `--no-default-features` floor
    // the moment one was missed. A no-op when a format IS enabled costs
    // nothing.
    let _ = &registry;

    #[cfg(feature = "gzip")]
    registry.register_codec(std::sync::Arc::new(gzip::Gzip), gzip::meta());

    #[cfg(feature = "zlib")]
    registry.register_codec(std::sync::Arc::new(zlib::Zlib), zlib::meta());

    #[cfg(feature = "deflate")]
    registry.register_codec(std::sync::Arc::new(deflate::Deflate), deflate::meta());
}

/// How many formats this build contains. Useful for smoke tests.
pub fn count() -> usize {
    let mut r = Registry::new();
    register_all(&mut r);
    r.matrix().len()
}
