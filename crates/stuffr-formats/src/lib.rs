//! Format implementations.
//!
//! Phase 0 registers nothing: `stuffr-core` is validated against mock formats.
//! Phase 1 adds codecs here, each behind its own Cargo feature, and extends
//! [`register_all`].

use stuffr_core::Registry;

/// Registers every format enabled in this build.
///
/// The single extension point for new formats — a codec that is not registered
/// here is invisible to `stf formats` and to detection.
pub fn register_all(_registry: &mut Registry) {
    // Phase 1 populates this.
}

/// How many formats this build contains. Useful for smoke tests.
pub fn count() -> usize {
    let mut r = Registry::new();
    register_all(&mut r);
    r.matrix().len()
}
