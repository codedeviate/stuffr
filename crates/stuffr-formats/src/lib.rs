//! Format implementations, each behind its own Cargo feature.
//!
//! `stuffr-core` deliberately carries no format dependency; this is where they
//! live. [`register_all`] is the single extension point — a codec not
//! registered there is invisible to `stf formats` and to detection.

use stuffr_core::Registry;

mod normalize;
#[cfg(any(feature = "zstd-c", feature = "zstd-pure"))]
mod zstd_shared;

#[cfg(feature = "brotli")]
pub mod brotli;
#[cfg(feature = "bzip2")]
pub mod bzip2;
#[cfg(feature = "deflate")]
pub mod deflate;
#[cfg(feature = "gzip")]
pub mod gzip;
#[cfg(feature = "lz4")]
pub mod lz4;
#[cfg(feature = "snappy")]
pub mod snappy;
#[cfg(feature = "zlib")]
pub mod zlib;
#[cfg(feature = "zstd-c")]
pub mod zstd_c;

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

    #[cfg(feature = "bzip2")]
    registry.register_codec(std::sync::Arc::new(bzip2::Bzip2), bzip2::meta());

    #[cfg(feature = "brotli")]
    registry.register_codec(std::sync::Arc::new(brotli::Brotli), brotli::meta());

    #[cfg(feature = "lz4")]
    registry.register_codec(std::sync::Arc::new(lz4::Lz4), lz4::meta());

    #[cfg(feature = "snappy")]
    registry.register_codec(std::sync::Arc::new(snappy::Snappy), snappy::meta());

    // Task 3 adds the mutually exclusive `zstd-pure` arm here (`cfg(all(
    // feature = "zstd-pure", not(feature = "zstd-c")))`), so a build with
    // neither C toolchain nor `zstd-c` still opens `.zst` at a lower rung.
    #[cfg(feature = "zstd-c")]
    registry.register_codec(std::sync::Arc::new(zstd_c::Zstd), zstd_c::meta());
}

/// How many formats this build contains. Useful for smoke tests.
pub fn count() -> usize {
    let mut r = Registry::new();
    register_all(&mut r);
    r.matrix().len()
}
