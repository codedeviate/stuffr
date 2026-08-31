//! Format implementations, each behind its own Cargo feature.
//!
//! `stuffr-core` deliberately carries no format dependency; this is where they
//! live. [`register_all`] is the single extension point — a codec not
//! registered there is invisible to `stf formats` and to detection.

use stuffr_core::Registry;

#[cfg(any(feature = "lzma-c", feature = "lzma-pure"))]
mod lzma_shared;
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
#[cfg(feature = "lzip")]
pub mod lzip;
#[cfg(feature = "lzma-c")]
pub mod lzma_c;
#[cfg(feature = "lzma-pure")]
pub mod lzma_pure;
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

    // No mutual-exclusion dance here: unlike xz/lzma/zstd, LZIP has only
    // one backend, so there is nothing else it could collide with.
    #[cfg(feature = "lzip")]
    registry.register_codec(std::sync::Arc::new(lzip::Lzip), lzip::meta());

    // Mutually exclusive, same shape as xz's and zstd's pairs below: both
    // arms register the same FormatId (see `lzma_shared`), and `not(feature =
    // "lzma-c")` is what makes the C backend win when both are compiled.
    #[cfg(feature = "lzma-c")]
    registry.register_codec(std::sync::Arc::new(lzma_c::Lzma), lzma_c::meta());
    #[cfg(all(feature = "lzma-pure", not(feature = "lzma-c")))]
    registry.register_codec(std::sync::Arc::new(lzma_pure::Lzma), lzma_pure::meta());

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

#[cfg(test)]
mod backend_selection {
    //! Why only zstd has a backend-selection test, and why that is honest
    //! rather than a gap.
    //!
    //! The test that used to guard selection counted registry rows per
    //! `FormatId` and asserted `<= 1`. It could never fail: `Registry` is keyed
    //! by `FormatId`, so a duplicate registration silently overwrites and the
    //! count is 1 either way. The final review proved it by mutation — deleting
    //! every `not(feature = "x-c")` guard left the whole suite green while a
    //! `c-backed` binary quietly selected the PURE backends.
    //!
    //! Detecting misselection needs something observably different between the
    //! two backends. Measured, for each pair:
    //!
    //! - **zstd** — the backends differ in *capability*: the pure encoder is
    //!   `weak_encoder`, the C one is not. That is a real discriminator, and
    //!   `crates/stuffr/tests/ops_compress.rs` asserts selection with it. Its
    //!   failure was verified by deleting the guard.
    //! - **xz** and **LZMA1** — the backends are **indistinguishable through
    //!   the `Codec` interface**: identical `CodecCaps` (both declare
    //!   `memory_per_worker: Some(8 MiB)` and `WhenPresent`), identical level
    //!   ranges and rejection messages, identical `io::ErrorKind` folding since
    //!   the final review's fix, and byte-identical encoder output on ordinary
    //!   payloads — verified below, and for LZMA1 also by
    //!   `lzma_pure::tests::both_backends_write_an_identical_stream_for_the_same_input`.
    //!
    //! For those two, misselection is not an untested risk but an *unobservable*
    //! one: if no caller can tell which backend ran, selecting the wrong one
    //! cannot produce a wrong answer. C is preferred there for speed, which is
    //! not a correctness property. Interchangeability was an explicit goal of
    //! Phase 1e, and achieving it is what removed the discriminator.
    //!
    //! That argument rests on the premise, so the premise is what gets tested.
    //! If the backends ever diverge, the test below fails, and at that moment
    //! selection becomes observable and needs a real assertion — the failure
    //! message says so. All three formats use the identical `cfg` pattern, so
    //! zstd's test also exercises the mechanism itself.

    use super::*;
    use stuffr_core::{Codec, EncodeOpts};

    fn encode_with(codec: &dyn Codec, plain: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut sink = codec
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    /// The premise that makes xz's missing selection test acceptable: whichever
    /// backend `register_all` picked, a caller cannot tell.
    #[test]
    #[cfg(all(feature = "xz-c", feature = "xz-pure"))]
    fn the_two_xz_backends_are_interchangeable_so_selection_is_unobservable() {
        let plain = b"backend interchangeability payload ".repeat(4096);

        let via_c = encode_with(&xz_c::Xz, &plain);
        let via_pure = encode_with(&xz_pure::Xz, &plain);
        assert_eq!(
            via_c, via_pure,
            "the xz backends no longer emit identical bytes. Misselection has just \
             become observable, so this module's argument for having no selection \
             test is void: add one discriminating on this difference, the way \
             ops_compress.rs does for zstd using weak_encoder."
        );

        assert_eq!(
            xz_c::Xz.caps(),
            xz_pure::Xz.caps(),
            "declared caps diverged"
        );

        let mut reg = Registry::new();
        register_all(&mut reg);
        let registered = reg.codec(xz_shared::XZ).expect("xz must be registered");
        assert_eq!(
            encode_with(registered.as_ref(), &plain),
            via_c,
            "the registered xz codec must behave like both backends"
        );
    }
}
