//! LZMA1 (the `.lzma` "alone" format), via the C `liblzma` crate — same
//! dependency `xz_c.rs` uses, and the same vendoring rationale (see that
//! module's doc for why the exact dependency line in `Cargo.toml` matters).
//!
//! `LZMA`, and `meta()` live in `crate::lzma_shared`, not here: Task 6's pure
//! `lzma-rust2` counterpart registers the very same `FormatId`, and an
//! `lzma-pure`-only build has no `lzma_c` module to hang them off. This
//! module re-exports them under its own name so callers see
//! `lzma_c::{LZMA, meta}` exactly as if they were defined here.
//!
//! ## The API is confusingly named
//!
//! `liblzma` exposes only `XzEncoder`/`XzDecoder` at the read/write level —
//! there is no `LzmaEncoder`. LZMA1 is reached instead by building a
//! `Stream` with `Stream::new_lzma_encoder(&LzmaOptions)` (which calls the
//! C library's `lzma_alone_encoder` internally) and handing that stream to
//! `write::XzEncoder::new_stream`. **The type is named `XzEncoder` but with
//! an alone-stream it writes LZMA1, not xz.** Decode is the mirror:
//! `Stream::new_lzma_decoder(memlimit)` into a `XzDecoder::new_stream`.
//!
//! Verified this produces a real `.lzma` file, not just something this
//! binding round-trips with itself: the header this codec writes is `5d 00
//! 00 80 00 ff ff ff ff ff ff ff ff` — properties byte, 4-byte dictionary
//! size, then the 8-byte "uncompressed size unknown" sentinel, all `ff` —
//! and both `xz --format=lzma -dc` and `lzma -dc` (XZ Utils 5.8.3) decode a
//! file this codec wrote byte-for-byte, and this codec decodes a file
//! written by `lzma` (the system tool) byte-for-byte. `lzma-rust2` (Task
//! 6's pure counterpart) round-trips against this backend's output too.
//!
//! ## No magic bytes — see `lzma_shared`'s doc
//!
//! Detection is by extension only. A `.lzma` stream arriving on a pipe needs
//! `--format lzma`.
//!
//! ## No concatenation convention — trailing bytes are corruption, not more data
//!
//! Unlike gzip and xz, the LZMA1 alone format has no notion of concatenated
//! streams: `cat a.lzma b.lzma` is not "two streams to decode in sequence",
//! it is one stream followed by garbage. Measured directly: feeding
//! `liblzma::bufread::XzDecoder`'s `read()` such a file does NOT raise an
//! error — it decodes the first stream's payload, then keeps returning
//! `Ok(0)` (EOF) forever after, silently discarding the second stream's
//! bytes with no indication anything is wrong. This is the SAME defect
//! class that made xz's single-stream decoder and lz4's frame decoder lose
//! data silently (see `xz_c.rs`'s module doc), except here there is no
//! `new_multi_decoder` to switch to — the format has no concatenation
//! convention for such a mode to mean anything.
//!
//! The reference tools disagree with the naive binding, and side with
//! "error": both `lzma -dc` and `xz --format=lzma -dc` (XZ Utils 5.8.3),
//! given the same two-streams-concatenated file, print `Compressed data is
//! corrupt` and exit nonzero — after having already written the first
//! stream's decoded bytes to stdout. So the reference tool's behavior is:
//! decode as far as the embedded end-of-payload marker, then treat anything
//! left over in the input as corruption. [`decoder`] below matches that:
//! [`RejectTrailingGarbage`] checks, once the inner decoder reports it has
//! reached the LZMA1 end marker, whether the buffered reader still holds
//! any unconsumed bytes — via one `BufRead::fill_buf` call, which returns
//! whatever is already buffered without necessarily doing more I/O — and
//! raises `InvalidData` if so. Measured to have no false positives on a
//! genuine single stream with nothing appended.
//!
//! ## Corruption detection: no checksum field, but far from undetected
//!
//! LZMA1 carries no CRC, Adler-32 or any other designed integrity check —
//! unlike gzip/zlib/bzip2/snappy's mandatory checksums or even xz's
//! per-writer check type. A naive reading of that fact alone would suggest
//! `CorruptionDetection::Never`, the same as raw deflate or brotli. Measured
//! instead, with the same sweep methodology used throughout this project
//! (flip every byte position of a real compressed 4 KiB incompressible
//! payload, not one flip; then separately truncate at every prefix length):
//! corruption was detected at 4,166 of 4,170 positions — 4,080 `InvalidData`
//! / 86 `UnexpectedEof`, zero silently wrong, zero silently unchanged except
//! four. Those four undetected positions are every byte of the header's
//! declared dictionary-size field (bytes 1-4): this decoder never validates
//! output against that field, only sizes an internal buffer with it, so
//! corrupting it is invisible for a payload much smaller than either the
//! true or the corrupted declared size. Truncation was detected at all
//! 4,169 cuts swept, entirely `UnexpectedEof`. See
//! `crate::normalize`'s `LZMA_MALFORMED_AS_INVALID_DATA_EOF` doc for the
//! full measurement and the tracing behind folding both kinds onto
//! `InvalidData`.
//!
//! This is not a checksum's kind of guarantee — it comes from the LZMA
//! range coder's own structural sensitivity (a corrupted byte desyncs the
//! coder's probability model, producing either an invalid match distance or
//! a decode that runs past or short of the embedded end-of-payload marker)
//! plus this codec's own trailing-garbage check above, not from a
//! deliberately added check bit. It is nonetheless real and measured, so
//! `caps().detects_corruption` reports [`CorruptionDetection::Structural`]
//! here rather than declaring a structural absence the data does not
//! support. The one honest carve-out is the dictionary-size field named
//! above.

use std::io::{BufRead, BufReader, Read, Write};

use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FormatId, Result, Sink,
    Source, StreamOnly,
};

pub use crate::lzma_shared::{LZMA, lzma_meta as meta};
use crate::normalize::{LZMA_MALFORMED_AS_INVALID_DATA_EOF, NormalizeDecodeErrors};

#[derive(Debug)]
pub struct Lzma;

impl Codec for Lzma {
    fn id(&self) -> FormatId {
        LZMA
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // Measured, not the format-carries-no-check assumption a reader
            // might reach for by analogy with raw deflate/brotli. See the
            // module doc's "Corruption detection" section for the sweep.
            detects_corruption: CorruptionDetection::Structural,
            // Not measured: derived the same way `xz_c.rs` derives its
            // figure, from LZMA1's preset-6 dictionary size (8 MiB — see
            // `lzma_encoder_presets.c`'s `dict_pow2` table, index 6 is 2^23
            // = 8 MiB), the SINGLE-WORKER figure for this build's default
            // level. Not the figure a future parallel/multi-preset encode
            // would need at a higher level.
            memory_per_worker: Some(8 * 1024 * 1024),
            weak_encoder: false,
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `StreamOnly`: this binding exposes no index, so decoded
    /// output must not claim random access.
    ///
    /// Wrapped in `RejectTrailingGarbage` before `NormalizeDecodeErrors`:
    /// see the module doc's "No concatenation convention" section. Wrapped
    /// in `NormalizeDecodeErrors` — see `crate::normalize`'s
    /// `LZMA_MALFORMED_AS_INVALID_DATA_EOF` doc for the measurement backing
    /// the kinds folded here.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let stream = liblzma::stream::Stream::new_lzma_decoder(u64::MAX)
            .expect("a memlimit of u64::MAX is always a valid decoder configuration");
        let dec = liblzma::bufread::XzDecoder::new_stream(BufReader::new(src), stream);
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            RejectTrailingGarbage::new(dec),
            LZMA_MALFORMED_AS_INVALID_DATA_EOF,
        ))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        // LZMA1's preset range, verified against `liblzma-sys`'s vendored C
        // source (`lzma_encoder_presets.c`'s `lzma_lzma_preset`, which
        // rejects `level > 9`) and measured directly:
        // `LzmaOptions::new_preset(10)` and `LzmaOptions::new_preset(99)`
        // both return `Err(Error::Program)` rather than panicking —
        // `new_preset` is fallible by design, unlike `xz_c.rs`'s
        // `XzEncoder::new`, which calls an internal constructor and
        // `.unwrap()`s it. This check still runs first and independently,
        // before any destination is opened, so an out-of-range level is a
        // `Usage` error regardless of what the backend would have done.
        match o.level {
            Some(n) if !(0..=9).contains(&n) => Err(Error::Usage(format!(
                "lzma compression level must be 0-9, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        // Not redundant with `ops`'s own pre-flight call, and not removable:
        // `encoder` is a public trait method any caller can reach directly
        // without going through `ops`. Conformance property 6 exists to
        // keep this in step with `check_encode_opts`.
        self.check_encode_opts(o)?;
        let level = o.level.unwrap_or(6) as u32;
        // Both `.expect()`s are safe: the preset range was already
        // validated above, and `LzmaOptions::new_preset` returning `Ok`
        // means `Stream::new_lzma_encoder` has nothing left to reject.
        let opts = liblzma::stream::LzmaOptions::new_preset(level)
            .expect("check_encode_opts already validated the preset range");
        let stream = liblzma::stream::Stream::new_lzma_encoder(&opts)
            .expect("a valid LzmaOptions always builds an encoder stream");
        let enc = liblzma::write::XzEncoder::new_stream(dst, stream);
        Ok(Box::new(LzmaSink(enc)))
    }
}

/// Detects unconsumed bytes left over after the LZMA1 decoder reaches its
/// embedded end-of-payload marker — see the module doc's "No concatenation
/// convention" section for why this, not silent truncation, is what matches
/// the reference `xz`/`lzma` tools.
///
/// Needs `liblzma::bufread::XzDecoder` rather than the higher-level
/// `read::XzDecoder` `xz_c.rs` uses: only the `bufread` type is generic over
/// the exact `BufRead` implementation, so `get_mut()` here hands back the
/// concrete `BufReader<R>` this module constructed, and `fill_buf()` on it
/// answers "is anything left, buffered or not" without forcing a `read()`
/// call the underlying `Stream` might reinterpret as more decode work.
struct RejectTrailingGarbage<R: Read> {
    inner: liblzma::bufread::XzDecoder<BufReader<R>>,
    finished: bool,
}

impl<R: Read> RejectTrailingGarbage<R> {
    fn new(inner: liblzma::bufread::XzDecoder<BufReader<R>>) -> Self {
        Self {
            inner,
            finished: false,
        }
    }
}

impl<R: Read> Read for RejectTrailingGarbage<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.finished {
            return Ok(0);
        }
        let n = self.inner.read(buf)?;
        if n == 0 {
            let leftover = self.inner.get_mut().fill_buf()?;
            if !leftover.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} trailing byte(s) after the LZMA1 stream's end marker — the alone \
                         format has no concatenation convention, so this is not valid \
                         additional data",
                        leftover.len()
                    ),
                ));
            }
            self.finished = true;
        }
        Ok(n)
    }
}

struct LzmaSink(liblzma::write::XzEncoder<Box<dyn Write + Send>>);

impl Write for LzmaSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for LzmaSink {
    /// Writes the closing chunk and the end-of-payload marker.
    ///
    /// `liblzma::write::XzEncoder::finish` already propagates a destination
    /// write error genuinely encountered during finalisation — see
    /// `xz_c.rs`'s `Sink::finish` doc for the same claim about this same
    /// crate's `finish`, and `crate::normalize`'s `CaptureWriteError` doc
    /// for the contrasting case (brotli) this crate does not need.
    fn finish(self: Box<Self>) -> Result<()> {
        let LzmaSink(encoder) = *self;
        let mut w = encoder.finish()?;
        w.flush()?;
        Ok(())
    }
}

/// Compresses `plain` with this codec's default options, for tests only.
///
/// Mirrors `xz_c.rs`'s helper of the same name: Task 6's pure `lzma-rust2`
/// counterpart cannot encode its own LZMA1 test input (it is the newer,
/// less-trusted backend of the pair — see that task's own brief), so its
/// cross-backend agreement test consumes this instead.
#[cfg(test)]
pub(crate) fn encode_for_test(plain: &[u8]) -> Vec<u8> {
    let buf = stuffr_core::testing::SharedBuf::new();
    let mut sink = Lzma
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
        let mut sink = Lzma
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn lzma_c_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Lzma, &meta());
    }

    #[test]
    fn lzma_registers_no_magic_because_its_header_is_not_a_signature() {
        // The .lzma header's first byte encodes lc/lp/pb and the next four
        // the dictionary size — commonly 5d 00 00 80 00 but not fixed.
        // Registering 5d alone would false-positive on arbitrary binary
        // data, so detection is by extension, and a .lzma stream on a pipe
        // needs --format lzma.
        assert!(meta().magics.is_empty());
        assert_eq!(meta().extensions, &["lzma"]);
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = compress(&plain);
        assert!(
            packed.len() < plain.len(),
            "lzma must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_lzma_alone_header() {
        // Properties byte, 4-byte dictionary size, 8-byte "size unknown"
        // sentinel — see the module doc's verification against the system
        // `xz`/`lzma` tools for why this exact header is a real .lzma file
        // and not just something this binding round-trips with itself.
        let packed = compress(b"payload");
        assert_eq!(
            &packed[..13],
            &[
                0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ]
        );
    }

    #[test]
    fn encode_for_test_helper_produces_a_decodable_stream() {
        let packed = encode_for_test(b"cross-backend payload");
        assert_eq!(decompress(packed), b"cross-backend payload");
    }

    /// RULING R... 's regression test for the concatenation question: LZMA1
    /// has no concatenation convention, so trailing bytes after a valid
    /// stream are corruption, not more data to decode — matching what the
    /// system `xz`/`lzma` tools do with the same input (see the module doc).
    #[test]
    fn concatenated_streams_are_reported_as_corrupt_not_silently_truncated() {
        let mut two = compress(b"first-stream-");
        two.extend_from_slice(&compress(b"second-stream"));

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(two)));
        let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        match dec.read_to_end(&mut out) {
            Ok(_) => panic!(
                "expected trailing data after the first stream's end marker to be reported as \
                 corrupt, matching the system xz/lzma tools; got Ok with {} bytes",
                out.len()
            ),
            Err(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::InvalidData,
                "expected InvalidData after normalisation, got {:?}",
                e.kind()
            ),
        }
    }

    /// A single stream with nothing appended must decode cleanly — the
    /// trailing-garbage check must not false-positive on a genuine,
    /// complete stream.
    #[test]
    fn a_single_stream_with_nothing_appended_decodes_cleanly() {
        let packed = compress(b"just one stream, nothing after it");
        assert_eq!(decompress(packed), b"just one stream, nothing after it");
    }

    #[test]
    fn level_zero_through_nine_are_all_accepted() {
        for n in 0..=9 {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            assert!(
                Lzma.check_encode_opts(&opts).is_ok(),
                "level {n} must be accepted"
            );
            assert!(
                Lzma.encoder(Box::new(SharedBuf::new()), &opts).is_ok(),
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
            match Lzma.check_encode_opts(&opts) {
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
            match Lzma.encoder(Box::new(SharedBuf::new()), &opts) {
                Err(err) => assert!(matches!(err, stuffr_core::Error::Usage(_))),
                Ok(_) => panic!("encoder() must agree with check_encode_opts() and reject {n}"),
            }
        }
    }

    /// Measured directly, not assumed: `LzmaOptions::new_preset` returns
    /// `Err(Error::Program)` for both an out-of-range level (10) and one
    /// with stray flag bits set (99, whose low 5 bits alone would be a
    /// valid level but whose other bits are not `LZMA_PRESET_EXTREME`) —
    /// it never panics, unlike `xz_c.rs`'s `XzEncoder::new`.
    #[test]
    fn new_preset_rejects_out_of_range_levels_without_panicking() {
        assert!(liblzma::stream::LzmaOptions::new_preset(10).is_err());
        assert!(liblzma::stream::LzmaOptions::new_preset(99).is_err());
        assert!(liblzma::stream::LzmaOptions::new_preset(0).is_ok());
        assert!(liblzma::stream::LzmaOptions::new_preset(9).is_ok());
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Lzma.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        assert!(!c.weak_encoder, "the C backend is the real encoder");
        let m = meta();
        assert_eq!(m.id, LZMA);
        assert_eq!(m.extensions, &["lzma"]);
        assert!(m.magics.is_empty());
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn lzma_declares_corruption_detection_and_a_memory_figure() {
        let c = Lzma.caps();
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::Structural,
            "measured at 4,166 of 4,170 swept positions; see the module doc"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    /// Sweeps every byte position of a real encoded payload rather than
    /// flipping one, mirroring `xz_c.rs`'s and `snappy.rs`'s probes. Backs
    /// `detects_corruption: CorruptionDetection::Structural` with direct
    /// measurement, and documents the one honest exception: the
    /// dictionary-size field.
    #[test]
    fn corruption_sweep_is_detected_almost_everywhere() {
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
            let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
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
            "every flipped position must decode either to an error or to the exact original; \
             measured {silently_wrong} silently wrong"
        );
        assert_eq!(
            other_kind, 0,
            "NormalizeDecodeErrors folds both InvalidData and UnexpectedEof from this backend \
             onto InvalidData; {other_kind} positions reported neither"
        );
        // Exactly the dictionary-size field (4 bytes) is expected to be
        // silently unchanged — see the module doc. A different count means
        // this measurement needs redoing, not that the assertion is wrong.
        assert_eq!(
            silently_unchanged, 4,
            "expected exactly the 4-byte dictionary-size field to be unchecked; measured \
             {silently_unchanged}"
        );
        assert!(invalid_data > 0);
    }

    /// The truncation counterpart — conformance property 10 already covers
    /// this codec through the shared harness, but this documents the
    /// measured kind directly against this backend rather than only through
    /// the harness's classification.
    #[test]
    fn truncation_is_detected_at_every_cut() {
        let plain = stuffr_core::testing::incompressible(4 * 1024);
        let packed = compress(&plain);

        for cut in [1, packed.len() / 4, packed.len() / 2, packed.len() - 1] {
            let truncated = packed[..cut].to_vec();
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
            let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
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
}
