//! Format implementations, each behind its own Cargo feature.
//!
//! `stuffr-core` deliberately carries no format dependency; this is where they
//! live. [`register_all`] is the single extension point — a codec not
//! registered there is invisible to `stf formats` and to detection.

use stuffr_core::Registry;

#[cfg(feature = "gzip")]
pub mod gzip;

/// Registers every format enabled in this build.
pub fn register_all(registry: &mut Registry) {
    #[cfg(not(feature = "gzip"))]
    let _ = &registry;

    #[cfg(feature = "gzip")]
    registry.register_codec(std::sync::Arc::new(gzip::Gzip), gzip::meta());
}

/// How many formats this build contains. Useful for smoke tests.
pub fn count() -> usize {
    let mut r = Registry::new();
    register_all(&mut r);
    r.matrix().len()
}
