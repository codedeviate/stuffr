//! Format implementations, each behind its own Cargo feature.
//!
//! `stuffr-core` deliberately carries no format dependency; this is where they
//! live. [`register_all`] is the single extension point — a codec not
//! registered there is invisible to `stf formats` and to detection.

use stuffr_core::Registry;

mod normalize;
#[cfg(any(feature = "xz-c", feature = "xz-pure"))]
mod xz_shared;
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
#[cfg(feature = "xz-c")]
pub mod xz_c;
#[cfg(feature = "xz-pure")]
pub mod xz_pure;
#[cfg(feature = "zlib")]
pub mod zlib;
#[cfg(feature = "zstd-c")]
pub mod zstd_c;
#[cfg(feature = "zstd-pure")]
pub mod zstd_pure;

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

    // Mutually exclusive, same shape as zstd's pair below: both arms
    // register the same FormatId (see `xz_shared`), and `not(feature =
    // "xz-c")` is what makes the C backend win when both are compiled.
    #[cfg(feature = "xz-c")]
    registry.register_codec(std::sync::Arc::new(xz_c::Xz), xz_c::meta());
    #[cfg(all(feature = "xz-pure", not(feature = "xz-c")))]
    registry.register_codec(std::sync::Arc::new(xz_pure::Xz), xz_pure::meta());

    // Mutually exclusive: both arms register the same FormatId (see
    // `zstd_shared`), so only one may ever be active. `not(feature =
    // "zstd-c")` is what makes the C backend win when both are compiled —
    // without it, a build with both features on would register `zstd` twice
    // and silently keep whichever happened to register last. A build with
    // neither feature has no `zstd` row at all.
    #[cfg(feature = "zstd-c")]
    registry.register_codec(std::sync::Arc::new(zstd_c::Zstd), zstd_c::meta());
    #[cfg(all(feature = "zstd-pure", not(feature = "zstd-c")))]
    registry.register_codec(std::sync::Arc::new(zstd_pure::Zstd), zstd_pure::meta());
}

/// How many formats this build contains. Useful for smoke tests.
pub fn count() -> usize {
    let mut r = Registry::new();
    register_all(&mut r);
    r.matrix().len()
}
