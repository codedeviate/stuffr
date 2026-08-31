//! xz, via the C `liblzma` crate (bindings over the reference `liblzma`,
//! vendored and built from C source by `liblzma-sys` — see `Cargo.toml`'s
//! `xz-c` feature and its exact dependency line, which matters: a plain
//! `liblzma = "0.4"` would default to a `bindgen` build needing libclang, or
//! a pkg-config link against whatever system liblzma happens to be
//! installed, neither of which this crate wants).
//!
//! `XZ`, the magic rule and `meta()` live in `crate::xz_shared`, not here:
//! Task 5's pure `lzma-rust2` counterpart registers the very same
//! `FormatId`, and an `xz-pure`-only build has no `xz_c` module to hang them
//! off. This module re-exports them under its own name so callers see
//! `xz_c::{XZ, meta}` exactly as if they were defined here.
//!
//! ## Concatenated streams must not be silently truncated
//!
//! `liblzma::read::XzDecoder` has two constructors that look similar and are
//! not: `new` decodes exactly one xz stream and stops, silently discarding
//! anything concatenated after it; `new_multi_decoder` decodes every stream
//! concatenated in the input. Measured directly: two real xz streams
//! totalling 8,600 plain bytes decode to 4,300 bytes via `new` — `Ok`, no
//! error, half the data missing — and to the full 8,600 via
//! `new_multi_decoder`. `decoder` below uses `new_multi_decoder` for exactly
//! this reason; `cat a.xz b.xz` produces ordinary concatenated xz, and
//! multi-threaded xz emits multi-stream output natively, so this is not an
//! edge case. See `concatenated_streams_decode_completely_not_just_the_first`
//! for the regression test, and the sibling module doc comments on
//! `zstd_pure.rs` and `lz4.rs` for the same defect class caught elsewhere in
//! this project.
//!
//! ## The integrity check needs no intervention, unlike zstd's
//!
//! `encoder` below constructs a `liblzma::write::XzEncoder::new`, which
//! selects `Check::Crc64` unconditionally — unlike `zstd::stream::write::
//! Encoder`, which writes no content checksum unless told to (see
//! `zstd_c.rs`'s module doc). Measured with the same sweep methodology
//! (flip every byte position of a real 4 KiB payload): 4,154 of 4,156
//! positions detected as `InvalidData`, the remaining 2 as `UnexpectedEof`,
//! zero silently wrong and zero silently unchanged — full detection. See
//! `crate::normalize`'s `XZ_MALFORMED_AS_INVALID_DATA_EOF` doc for the full
//! measurement and the source-level reasoning behind folding both kinds
//! onto `InvalidData`.
//!
//! **This still does not make `caps().detects_corruption` a format-wide
//! guarantee.** The check is a per-writer field in the xz stream header —
//! `Check::None` is a legal value the format permits, even though every xz
//! encoder measured in this project (this one and, per its own brief,
//! Task 5's `lzma-rust2`) selects CRC64 without being asked. A `.xz` written
//! by some hypothetical other tool with the check turned off is still valid
//! xz, and this decoder cannot tell ahead of reading whether an incoming
//! stream carries one — see `format.rs`'s `detects_corruption` doc for why
//! this is a real, general distinction and not specific to this codec.

use std::io::Write;

use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, Result, Sink, Source, StreamOnly,
};

use crate::normalize::{NormalizeDecodeErrors, XZ_MALFORMED_AS_INVALID_DATA_EOF};
pub use crate::xz_shared::{XZ, xz_meta as meta};

#[derive(Debug)]
pub struct Xz;

impl Codec for Xz {
    fn id(&self) -> FormatId {
        XZ
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // Honest for streams THIS codec writes: `encoder` always selects
            // `Check::Crc64`. See the module doc for the measured sweep and
            // the caveat about a foreign stream with the check turned off —
            // legal in the format, just not what this encoder ever produces.
            detects_corruption: true,
            // Not measured: derived from xz's preset-6 dictionary size (8
            // MiB — see `lzma_encoder_presets.c`'s `dict_pow2` table, index
            // 6 is 2^23 = 8 MiB), the SINGLE-WORKER figure for this build's
            // default level. This is NOT the figure Phase 1f's parallel
            // encode will need for `-9` multi-threaded, which the project
            // design doc puts at roughly 700 MiB per worker (preset 9's 64
            // MiB dictionary plus multithreaded liblzma's per-block
            // overhead) — a different, much larger number for a different
            // level and a different encode mode.
            memory_per_worker: Some(8 * 1024 * 1024),
            weak_encoder: false,
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `StreamOnly`: this binding exposes no frame/block index,
    /// so decoded output must not claim random access even though the xz
    /// format itself carries one (see `StreamOnly`'s own doc, which names
    /// "an xz block index" as the kind of thing a future, seek-aware codec
    /// could expose instead).
    ///
    /// Wrapped in `NormalizeDecodeErrors` — see `crate::normalize`'s
    /// `XZ_MALFORMED_AS_INVALID_DATA_EOF` doc for the measurement backing
    /// the kinds folded here.
    ///
    /// **`new_multi_decoder`, not `new`.** See the module doc: `new` stops
    /// after the first concatenated stream and returns `Ok`, silently
    /// discarding the rest — the exact defect class that made lz4 lose
    /// every frame after the first in Phase 1d.
    ///
    /// **Reading a foreign stream.** [`CodecCaps::detects_corruption`] is
    /// `true` for this codec, and the doc on that field requires every
    /// optional-check format to say here what that is worth on a stream this
    /// build did not write. xz's check type is a per-writer choice — the
    /// format permits `CheckType::None` — so a `.xz` carrying no check is
    /// legal and would decode with far weaker detection.
    ///
    /// In practice that is rare, and measurably so: every xz encoder tested
    /// selects CRC64 without being asked — liblzma's and `lzma-rust2`'s both
    /// write check byte `0x04`, and all four cross-backend combinations
    /// detected 66 of 66 swept corruptions. That is the opposite of zstd,
    /// where the crate-level encoder omits the checksum by default and
    /// checkless streams are routine (see `zstd_c.rs`'s `decoder`). So the
    /// honest statement is narrower than zstd's: a checkless `.xz` is
    /// possible but unusual, where a checkless `.zst` is ordinary.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let dec = liblzma::read::XzDecoder::new_multi_decoder(src);
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            dec,
            XZ_MALFORMED_AS_INVALID_DATA_EOF,
        ))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        // xz's preset range, verified against `liblzma-sys`'s vendored C
        // source (`lzma_encoder_presets.c`'s `lzma_lzma_preset`, which
        // rejects `level > 9` outright) rather than assumed by analogy with
        // gzip's 0..=9. `liblzma::write::XzEncoder::new` does not validate
        // this itself — it calls `Stream::new_easy_encoder(level, ..)
        // .unwrap()` internally, which would PANIC on an invalid preset
        // rather than return an error, so this check running first, before
        // any destination is opened, is what keeps an out-of-range level a
        // `Usage` error instead of a panic.
        match o.level {
            Some(n) if !(0..=9).contains(&n) => Err(Error::Usage(format!(
                "xz compression level must be 0-9, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        // Not redundant with `ops`'s own pre-flight call, and not removable:
        // the next line PANICS on an out-of-range preset rather than
        // returning an error, and `encoder` is a public trait method any
        // caller can reach directly without going through `ops`. Conformance
        // property 6 exists to keep this in step with `check_encode_opts`.
        self.check_encode_opts(o)?;
        let level = o.level.unwrap_or(6) as u32;
        // PANICS on an invalid preset — guarded above. See `check_encode_opts`.
        let enc = liblzma::write::XzEncoder::new(dst, level);
        Ok(Box::new(XzSink(enc)))
    }
}

struct XzSink(liblzma::write::XzEncoder<Box<dyn Write + Send>>);

impl Write for XzSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for XzSink {
    /// Writes the closing block, index and stream footer.
    ///
    /// `liblzma::write::XzEncoder::finish` already propagates a destination
    /// write error genuinely encountered during finalisation (its internal
    /// `dump()` helper forwards `write_all`'s `Result` with `?`, never
    /// discarding it the way brotli's `into_inner` does — see
    /// `crate::normalize`'s `CaptureWriteError` doc for the contrasting
    /// case), so no such adapter is needed here.
    fn finish(self: Box<Self>) -> Result<()> {
        let XzSink(encoder) = *self;
        let mut w = encoder.finish()?;
        w.flush()?;
        Ok(())
    }
}

/// Compresses `plain` with this codec's default options, for tests only.
///
/// Mirrors `zstd_c.rs`'s helper of the same name: not exercised by this
/// file's own tests (which go through `Codec::encoder` like every other
/// codec's test module), but present for Task 5's pure `lzma-rust2`
/// counterpart and any cross-backend agreement tests it adds.
#[cfg(test)]
pub(crate) fn encode_for_test(plain: &[u8]) -> Vec<u8> {
    let buf = stuffr_core::testing::SharedBuf::new();
    let mut sink = Xz
        .encoder(Box::new(buf.clone()), &EncodeOpts::default())
        .unwrap();
    sink.write_all(plain).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use stuffr_core::ReaderSource;
    use stuffr_core::testing::SharedBuf;

    fn compress(plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = Xz
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = compress(&plain);
        assert!(packed.len() < plain.len(), "xz must actually compress this");
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_xz_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..6], &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]);
    }

    #[test]
    fn encode_for_test_helper_produces_a_decodable_stream() {
        let packed = encode_for_test(b"cross-backend payload");
        assert_eq!(decompress(packed), b"cross-backend payload");
    }

    /// RULING R20's regression test. `cat a.xz b.xz` is ordinary xz — not a
    /// pathological input — and multi-threaded xz emits multi-stream output
    /// natively, so a decoder that stops after the first stream silently
    /// truncates real files. This is the same defect class that made lz4
    /// lose every frame after the first in Phase 1d and that a reviewer
    /// caught in `zstd_pure` this cycle: proven directly against
    /// `liblzma::read::XzDecoder::new` in `xz_c.rs`'s own dev-only probe
    /// during this task (measured: 4,300 of 8,600 bytes, `Ok`) before this
    /// codec ever used `new_multi_decoder` instead.
    #[test]
    fn concatenated_streams_decode_completely_not_just_the_first() {
        let mut two = compress(b"first-stream-");
        two.extend_from_slice(&compress(b"second-stream"));
        assert_eq!(decompress(two), b"first-stream-second-stream");
    }

    /// Confirms the claim in the module doc's "concatenated streams" section
    /// stays true against a real build of this crate: `XzDecoder::new`
    /// (single-stream) truncates silently — `Ok`, not an error — while
    /// `new_multi_decoder` (what `decoder` actually uses) reads all of it.
    /// A regression turning this false is exactly RULING R20's failure mode.
    #[test]
    fn new_single_stream_decoder_would_silently_truncate_concatenated_input() {
        let mut two = compress(b"first-stream-");
        two.extend_from_slice(&compress(b"second-stream"));
        let full_len = b"first-stream-second-stream".len();

        let mut single = liblzma::read::XzDecoder::new(std::io::Cursor::new(two));
        let mut out = Vec::new();
        let result = single.read_to_end(&mut out);
        assert!(result.is_ok(), "new() must not error, just truncate");
        assert!(
            out.len() < full_len,
            "expected new() to silently drop the second stream; got the full {} bytes — if this \
             changed upstream, `decoder` could switch back to `new()`, but until then \
             `new_multi_decoder` stays load-bearing",
            out.len()
        );
    }

    #[test]
    fn level_zero_through_nine_are_all_accepted() {
        // Verified against `liblzma-sys`'s vendored `lzma_encoder_presets.c`:
        // `lzma_lzma_preset` rejects `level > 9`, so 0..=9 is the real range,
        // not assumed by analogy with gzip.
        for n in 0..=9 {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            assert!(
                Xz.check_encode_opts(&opts).is_ok(),
                "level {n} must be accepted"
            );
            assert!(
                Xz.encoder(Box::new(SharedBuf::new()), &opts).is_ok(),
                "level {n} must be accepted by encoder() too"
            );
        }
    }

    #[test]
    fn an_out_of_range_level_is_a_usage_error_not_a_panic() {
        for n in [-1, 10, i32::MIN, i32::MAX] {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            match Xz.check_encode_opts(&opts) {
                Err(err) => {
                    assert!(matches!(err, stuffr_core::Error::Usage(_)));
                    assert_eq!(err.exit_code(), 2);
                    assert!(
                        err.to_string().contains("0-9"),
                        "the error must name the real range: {err}"
                    );
                }
                Ok(_) => panic!("level {n} is out of range and must be rejected"),
            }
            match Xz.encoder(Box::new(SharedBuf::new()), &opts) {
                Err(err) => assert!(matches!(err, stuffr_core::Error::Usage(_))),
                Ok(_) => panic!("encoder() must agree with check_encode_opts() and reject {n}"),
            }
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Xz.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        assert!(!c.weak_encoder, "the C backend is the real encoder");
        let m = meta();
        assert_eq!(m.id, XZ);
        assert_eq!(m.extensions, &["xz"]);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn xz_declares_an_integrity_check_and_a_memory_figure() {
        let c = Xz.caps();
        assert!(
            c.detects_corruption,
            "this codec always selects Check::Crc64; see the module doc"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    /// Sweeps every byte position of a real encoded payload rather than
    /// flipping one, mirroring `snappy.rs`'s and `zstd_pure.rs`'s probes.
    /// Backs `detects_corruption: true` with direct measurement instead of
    /// leaving it aspirational: see `crate::normalize`'s
    /// `XZ_MALFORMED_AS_INVALID_DATA_EOF` doc for the same figures quoted
    /// there.
    #[test]
    fn corruption_sweep_is_detected_at_every_position() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let packed = compress(&plain);

        let mut invalid_data = 0usize;
        let mut other_kind = 0usize;
        let mut silently_wrong = 0usize;
        let mut silently_unchanged = 0usize;
        for i in 0..packed.len() {
            let mut corrupted = packed.clone();
            corrupted[i] ^= 0xFF;
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(corrupted)));
            let mut dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) if out == plain => silently_unchanged += 1,
                Ok(_) => silently_wrong += 1,
                Err(e) => match e.kind() {
                    std::io::ErrorKind::InvalidData => invalid_data += 1,
                    _ => other_kind += 1,
                },
            }
        }

        assert_eq!(
            silently_wrong, 0,
            "every flipped position must be caught; measured {silently_wrong} silently wrong"
        );
        assert_eq!(
            silently_unchanged, 0,
            "every flipped position must be caught; measured {silently_unchanged} silently \
             unchanged"
        );
        assert_eq!(
            other_kind, 0,
            "NormalizeDecodeErrors folds both InvalidData and UnexpectedEof from this backend \
             onto InvalidData; {other_kind} positions reported neither"
        );
        assert!(
            invalid_data > 0,
            "expected at least one position to be detected; measured 0"
        );
    }

    /// The truncation counterpart, at several cut lengths rather than one —
    /// conformance property 10 already covers this codec through the shared
    /// harness, but this documents the measured kind directly against this
    /// backend rather than only through the harness's classification.
    #[test]
    fn truncation_is_detected_at_every_cut() {
        let plain = stuffr_core::testing::incompressible(4 * 1024);
        let packed = compress(&plain);

        for cut in [1, packed.len() / 4, packed.len() / 2, packed.len() - 1] {
            let truncated = packed[..cut].to_vec();
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
            let mut dec = Xz.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) => panic!(
                    "cut to {cut} of {} bytes decoded without error",
                    packed.len()
                ),
                Err(e) => assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidData,
                    "cut to {cut}: expected InvalidData after normalisation, got {:?}",
                    e.kind()
                ),
            }
        }
    }

    #[test]
    fn xz_c_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Xz, &meta());
    }
}
