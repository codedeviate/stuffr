//! brotli (RFC 7932), via the `brotli` crate's pure-Rust encoder/decoder.
//!
//! Unlike every other codec in this tree, brotli defines no magic bytes at
//! all — there is no header byte sequence a detector could look for. `meta()`
//! reflects that honestly with an empty magic list; detection is by the `.br`
//! extension alone, and conformance property 3 (magic agreement) skips on
//! that evidence rather than being forced to invent a signature that does not
//! exist.

use std::io::Write;

use brotli::CompressorWriter;
use brotli::Decompressor;
use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, FormatMeta, Result, Sink, Source,
    StreamOnly,
};

use crate::normalize::CaptureWriteError;

pub const BROTLI: FormatId = FormatId::new("brotli");

/// No magic bytes: brotli's own format has none, so the only detection route
/// is the `.br` extension. A brotli stream arriving on a pipe (no filename to
/// go by) cannot be detected and needs an explicit `--format brotli`.
pub fn meta() -> FormatMeta {
    FormatMeta::codec(BROTLI, &["br"], &[])
}

#[derive(Debug)]
pub struct Brotli;

impl Codec for Brotli {
    fn id(&self) -> FormatId {
        BROTLI
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // Measured, and NOT what the brief expected going in: brotli
            // carries no checksum, so whether a flipped byte surfaces as an
            // error depends on where it lands, not on some guaranteed
            // structural check. A flip inside compressible, back-reference-
            // heavy data breaks Huffman/back-reference parsing and IS caught
            // (confirmed directly against this crate: InvalidData). But
            // conformance property 9 flips a byte in the MIDDLE of a 64 KiB
            // INCOMPRESSIBLE payload — measured directly against this exact
            // scenario, the flip lands in essentially-literal data and
            // decodes to different bytes with no error at all. This is the
            // same gap raw deflate already declares honestly (see
            // deflate.rs): no checksum over content that decoded fine is not
            // a contradiction with detecting truncation just fine (below).
            detects_corruption: false,
            // Not measured: derived from the window size, not profiled.
            // Quality 11 (this codec's default) uses lgwin 22, a 4 MiB
            // window; the encoder's working set is a small multiple of that
            // for its match-finder structures. 16 MiB is a defensible round
            // figure for "several times a 4 MiB window", not a measured peak.
            memory_per_worker: Some(16 * 1024 * 1024),
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped only in `StreamOnly` (brotli carries no seek table) — NOT in
    /// `NormalizeDecodeErrors`, unlike every flate2/bzip2-backed codec in this
    /// tree.
    ///
    /// Measured directly: whenever `brotli::Decompressor` DOES reject
    /// malformed input (a corrupted, back-reference-heavy stream; any
    /// truncated stream, including the unconditional property-10 case below)
    /// it reports `io::ErrorKind::InvalidData` natively, with no translation
    /// needed — brotli already speaks this project's convention for the
    /// cases it does catch. This absence of a `NormalizeDecodeErrors` wrapper
    /// is deliberate, not an oversight: there is no other kind this backend
    /// raises for malformed input that would need folding onto
    /// `InvalidData`. It is a separate question from `caps().
    /// detects_corruption` (`false`, see above) — that capability is about
    /// whether EVERY corruption is caught, which brotli's checksum-less
    /// format cannot promise; this comment is only about what kind is used
    /// on the occasions it does.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(Decompressor::new(src, 4096))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        match o.level {
            Some(n) if !(0..=11).contains(&n) => Err(Error::Usage(format!(
                "brotli compression quality must be 0-11, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        // Unlike the gzip family's 0-9 default 6, brotli's quality range is
        // 0-11 and its own default is 11 — the slowest setting it has.
        let quality = o.level.unwrap_or(11) as u32;
        // 22 is the standard lgwin (a 4 MiB window), matched by the
        // memory_per_worker comment above.
        let captured = CaptureWriteError::new(dst);
        Ok(Box::new(BrotliSink(CompressorWriter::new(
            captured, 4096, quality, 22,
        ))))
    }
}

struct BrotliSink(CompressorWriter<CaptureWriteError<Box<dyn Write + Send>>>);

impl Write for BrotliSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for BrotliSink {
    /// Finalises through `into_inner()`, then recovers whatever
    /// `CaptureWriteError` saw during that call.
    ///
    /// `CompressorWriter::into_inner` writes brotli's final block and
    /// returns the destination directly — `W`, not `Result<W, _>` — so a
    /// write failure at that exact point is normally silently discarded (see
    /// `crate::normalize::CaptureWriteError`'s doc comment). Wrapping the
    /// destination beforehand is what makes that failure observable here:
    /// the wrapped writer still saw the real `Err` before brotli dropped it,
    /// and `take_error` hands it back.
    fn finish(self: Box<Self>) -> Result<()> {
        let BrotliSink(compressor) = *self;
        let mut w = compressor.into_inner();
        if let Some(e) = w.take_error() {
            return Err(e.into());
        }
        w.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use stuffr_core::ReaderSource;
    use stuffr_core::testing::SharedBuf;

    fn compress(plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = Brotli
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Brotli.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = compress(&plain);
        assert!(
            packed.len() < plain.len(),
            "brotli must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn an_out_of_range_quality_is_a_usage_error_not_a_silent_clamp() {
        let opts = EncodeOpts {
            level: Some(12),
            ..Default::default()
        };
        match Brotli.encoder(Box::new(SharedBuf::new()), &opts) {
            Err(err) => {
                assert!(matches!(err, stuffr_core::Error::Usage(_)));
                assert_eq!(err.exit_code(), 2);
                assert!(err.to_string().contains("0-11"));
            }
            Ok(_) => panic!("encoder should reject out-of-range quality"),
        }

        let opts = EncodeOpts {
            level: Some(-1),
            ..Default::default()
        };
        let Err(err) = Brotli.check_encode_opts(&opts) else {
            panic!("quality -1 must be rejected");
        };
        assert!(matches!(err, stuffr_core::Error::Usage(_)), "got {err:?}");

        for n in [0, 11] {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            assert!(
                Brotli.check_encode_opts(&opts).is_ok(),
                "quality {n} must be accepted"
            );
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        // brotli carries no frame index, so its output must not claim random
        // access. A container above it would otherwise read wrong bytes.
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Brotli.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Brotli.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until cycle 1c");
        let m = meta();
        assert_eq!(m.id, BROTLI);
        assert_eq!(m.extensions, &["br"]);
        assert!(m.magics.is_empty(), "brotli defines no magic bytes");
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn brotli_declares_no_integrity_check_but_a_memory_figure() {
        let c = Brotli.caps();
        assert!(
            !c.detects_corruption,
            "brotli carries no checksum; a byte flipped in the middle of an incompressible \
             payload decodes to different bytes with no error, measured directly against this \
             crate — see caps()'s doc comment"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    /// Pins the exact discrepancy against the brief's expectation: a
    /// corrupted brotli stream is NOT always reported as an error. Uses this
    /// codec's real encoder at its own default quality over a 64 KiB
    /// incompressible payload — the same shape conformance property 9 would
    /// use — flips the midpoint byte, and shows the decode succeeds anyway
    /// (producing wrong bytes, silently). This is why `caps().
    /// detects_corruption` is `false`, not `true`.
    #[test]
    fn corruption_in_incompressible_data_can_decode_without_error() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(64 * 1024);
        let packed = compress(&plain);
        let mid = packed.len() / 2;
        let mut corrupted = packed.clone();
        corrupted[mid] ^= 0xFF;

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(corrupted)));
        let mut dec = Brotli.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        let result = dec.read_to_end(&mut out);

        assert!(
            result.is_ok(),
            "if this ever starts erroring, brotli's corruption detection changed — recheck \
             whether detects_corruption should flip back to true: {result:?}"
        );
        assert_ne!(
            out, plain,
            "the flipped byte should still have changed the decoded output even though no \
             error was raised"
        );
    }

    /// The finalisation-risk regression test: without `CaptureWriteError`,
    /// `Sink::finish` reports success even though the destination's write
    /// failed during `into_inner()`'s discarded finalisation step. Property 5
    /// in `stuffr_core::testing::assert_codec_conforms` exercises this same
    /// shape end to end; this test pins the RED/GREEN distinction directly so
    /// a regression here is unambiguous about which half broke.
    #[test]
    fn finish_surfaces_a_write_error_that_into_inner_would_otherwise_swallow() {
        struct FailAfter {
            budget: usize,
            written: usize,
        }
        impl Write for FailAfter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.written >= self.budget {
                    return Err(std::io::Error::other("probe: writer failed"));
                }
                let n = buf.len().min(self.budget - self.written);
                self.written += n;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // RED, demonstrated directly against the raw crate (no adapter):
        // write_all reports success, and into_inner silently drops the
        // finalisation write failure.
        let payload = b"conformance probe payload for the finalisation risk, repeated. \
                         conformance probe payload for the finalisation risk, repeated."
            .repeat(4);

        // Measure the byte budget the real Sink path needs for write_all
        // ALONE -- no explicit flush() in between, matching exactly what
        // `BrotliSink`'s `Write` impl does before `finish()` is ever called.
        // Everything beyond this budget is emitted only by into_inner()'s
        // FINISH call. Shared via Arc so the count can be read without
        // fighting the borrow checker over `comp`'s ownership of the
        // destination.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counting(Arc<AtomicUsize>);
        impl Write for Counting {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.fetch_add(b.len(), Ordering::Relaxed);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let budget = {
            let count = Arc::new(AtomicUsize::new(0));
            let mut comp = CompressorWriter::new(Counting(Arc::clone(&count)), 4096, 11, 22);
            comp.write_all(&payload).unwrap();
            count.load(Ordering::Relaxed)
        };

        {
            let dst = FailAfter { budget, written: 0 };
            let mut comp = CompressorWriter::new(dst, 4096, 11, 22);
            comp.write_all(&payload).unwrap();
            let inner: FailAfter = comp.into_inner();
            assert_eq!(
                inner.written, budget,
                "RED baseline: into_inner must not have advanced past the failing budget"
            );
            // No Result to inspect here at all -- that is exactly the bug.
        }

        // GREEN: the same shape, through this codec's real Sink::finish,
        // which wraps the destination in CaptureWriteError first.
        let dst = FailAfter { budget, written: 0 };
        let mut sink = Brotli
            .encoder(Box::new(dst), &EncodeOpts::default())
            .unwrap();
        sink.write_all(&payload).unwrap();
        assert!(
            sink.finish().is_err(),
            "GREEN: Sink::finish must surface the write failure CaptureWriteError recovered, \
             not report success the way raw into_inner() would"
        );
    }

    #[test]
    fn brotli_conforms() {
        // No magic: brotli defines none, so conformance property 3 skips on
        // evidence. Detection is by `.br` alone.
        stuffr_core::testing::assert_codec_conforms(&Brotli, &meta());
    }
}
