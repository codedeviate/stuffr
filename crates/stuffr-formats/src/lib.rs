//! Format implementations, each behind its own Cargo feature.
//!
//! `stuffr-core` deliberately carries no format dependency; this is where they
//! live. [`register_all`] is the single extension point — a codec not
//! registered there is invisible to `stuffr formats` and to detection.

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
#[cfg(feature = "tar")]
pub mod tar;
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

    // The first container. Registering it is also what switches on
    // `probe.rs`'s dormant `.tar.gz` / `.tgz` resolution, which was gated on
    // `reg.container(id).is_some()` and returned `Chain::Raw` until now —
    // `tar.rs`'s `tar_gz_and_tgz_now_resolve_to_tar_over_gzip` pins that.
    #[cfg(feature = "tar")]
    registry.register_container(std::sync::Arc::new(tar::Tar), tar::meta());

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
    //! - **LZMA1** — the backends are **indistinguishable through the `Codec`
    //!   interface**: identical `CodecCaps` (both declare `memory_per_worker:
    //!   Some(8 MiB)` and `WhenPresent`), identical level ranges and
    //!   rejection messages, identical `io::ErrorKind` folding since the
    //!   final review's fix, and byte-identical encoder output on ordinary
    //!   payloads — verified by
    //!   `lzma_pure::tests::both_backends_write_an_identical_stream_for_the_same_input`.
    //!
    //! For that pair, misselection is not an untested risk but an
    //! *unobservable* one: if no caller can tell which backend ran, selecting
    //! the wrong one cannot produce a wrong answer. C is preferred there for
    //! speed, which is not a correctness property. Interchangeability was an
    //! explicit goal of Phase 1e, and achieving it is what removed the
    //! discriminator.
    //!
    //! - **xz** — indistinguishable through Phase 1e. Phase 1f's Task 5 briefly
    //!   broke that: the C backend gained `MtStreamBuilder`-driven parallel
    //!   encode without a matching change to the pure `lzma-rust2` backend, so
    //!   `caps().parallel_encode` read `true` for `xz_c` and `false` for
    //!   `xz_pure` for one task's duration. Task 6 closed that gap the way
    //!   Phase 1e closed LZMA1's — giving `xz_pure` its own `XzWriterMt` — so
    //!   `parallel_encode` is `true` for BOTH backends again and `CodecCaps`
    //!   is once more fully identical between them, exactly like LZMA1's pair
    //!   above. `the_two_xz_backends_are_interchangeable_so_selection_is_unobservable`
    //!   below asserts that directly, with no field excluded.
    //!
    //!   **This is NOT a return to full interchangeability, though — it moved,
    //!   rather than closed.** `CodecCaps` and an ordinary (non-parallel,
    //!   no-governor) encode's bytes agree again, but a genuinely PARALLEL
    //!   encode's output bytes do not: liblzma's `MtStreamBuilder` and
    //!   lzma-rust2's `XzWriterMt` write different multi-threaded container
    //!   framing for the same governed encode, measured different at every
    //!   size checked, including one byte of input. That is a real,
    //!   observable difference the `Codec` interface's capabilities cannot
    //!   see (it is not a `CodecCaps` field, and `encode_with` below never
    //!   passes a governor), so it is not something this test — which only
    //!   exercises `Codec` — could assert even if it wanted to.
    //!   `crates/stuffr/tests/ops_compress.rs`'s
    //!   `the_c_backend_wins_when_both_xz_features_are_compiled` carries the
    //!   real selection test on that difference instead, mirroring zstd's
    //!   selection test on `weak_encoder` in shape but not in the field it
    //!   reads.
    //!
    //! That argument rests on the premise, so the premise is what gets tested.
    //! If a backend pair still assumed interchangeable ever diverges further —
    //! through `CodecCaps`, or through an ordinary encode's bytes — the test
    //! below fails, and at that moment selection becomes observable through
    //! THAT channel and needs a real assertion there too — the failure
    //! message says so. All three formats use the identical `cfg` pattern, so
    //! zstd's test also exercises the mechanism itself.

    // Gated identically to the one test that uses them below
    // (`the_two_xz_backends_are_interchangeable_so_selection_is_unobservable`,
    // `#[cfg(all(feature = "xz-c", feature = "xz-pure"))]`): every OTHER
    // build — including the default `pure` tier, and a plain `cargo
    // install` — has no caller left for `encode_with`, and `make lint`
    // only denies warnings under `--all-features` (where both features
    // are on and this compiles live), so an unguarded `use`/`fn` here
    // compiled dead on every build the lint leg cannot see. Whole-branch
    // review LOW-4 (2026-09-02).
    #[cfg(all(feature = "xz-c", feature = "xz-pure"))]
    use super::*;
    #[cfg(all(feature = "xz-c", feature = "xz-pure"))]
    use stuffr_core::{Codec, EncodeOpts};

    #[cfg(all(feature = "xz-c", feature = "xz-pure"))]
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

    /// The premise that used to make xz's missing selection test acceptable:
    /// whichever backend `register_all` picked, a caller could not tell.
    ///
    /// Phase 1f's Task 5 broke that premise for one task's duration (`xz_c`
    /// gained `parallel_encode: true` via `MtStreamBuilder` without a
    /// matching change to `xz_pure`), and Task 6 closed it again by giving
    /// `xz_pure` its own `XzWriterMt` — see the module doc's "xz" bullet for
    /// the full history, including why this is a partial return: `CodecCaps`
    /// and an ordinary encode's bytes are interchangeable again (asserted
    /// here, with NO field excluded, unlike the version of this test Task 5
    /// left behind), but a genuinely parallel encode's output bytes are not,
    /// and that difference lives outside what `Codec` alone can observe — see
    /// `crates/stuffr/tests/ops_compress.rs`'s
    /// `the_c_backend_wins_when_both_xz_features_are_compiled` for the real
    /// selection test on that difference.
    #[test]
    #[cfg(all(feature = "xz-c", feature = "xz-pure"))]
    fn the_two_xz_backends_are_interchangeable_so_selection_is_unobservable() {
        let plain = b"backend interchangeability payload ".repeat(4096);

        let via_c = encode_with(&xz_c::Xz, &plain);
        let via_pure = encode_with(&xz_pure::Xz, &plain);
        assert_eq!(
            via_c, via_pure,
            "the xz backends no longer emit identical bytes on an ordinary, \
             non-parallel encode. Misselection has just become observable through \
             a second channel, so this module's argument for having no selection \
             test is void: add one discriminating on this difference, the way \
             ops_compress.rs does for zstd using weak_encoder."
        );

        // Re-widened: Task 6 gave `xz_pure` `parallel_encode: true` too, so
        // the field that used to need excluding here agrees again — see the
        // module doc. No carve-out remains; if any field diverges, this
        // fails outright rather than silently accepting a known gap.
        assert_eq!(
            xz_c::Xz.caps(),
            xz_pure::Xz.caps(),
            "declared caps diverged — if this is `parallel_encode` specifically, \
             the two xz backends have stopped agreeing on it again, and this \
             module's doc (and its premise for having no `CodecCaps`-level \
             selection test) needs revisiting rather than this assertion \
             relaxing"
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
