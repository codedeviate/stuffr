//! brotli (RFC 7932), via the `brotli` crate's pure-Rust encoder/decoder.
//!
//! Unlike every other codec in this tree, brotli defines no magic bytes at
//! all — there is no header byte sequence a detector could look for. `meta()`
//! reflects that honestly with an empty magic list; detection is by the `.br`
//! extension alone, and conformance property 3 (magic agreement) skips on
//! that evidence rather than being forced to invent a signature that does not
//! exist.

use std::io::{Read, Write};

use brotli::CompressorWriter;
use brotli::{BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc, HuffmanCode};
use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FormatId, FormatMeta,
    Result, Sink, Source, StreamOnly,
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
            detects_corruption: CorruptionDetection::Never,
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
    /// Measured directly: whenever the backend DOES reject malformed input (a
    /// corrupted, back-reference-heavy stream; any truncated stream, including
    /// the unconditional property-10 case below; trailing data, below) it
    /// reports `io::ErrorKind::InvalidData` natively, with no translation
    /// needed — brotli already speaks this project's convention for the cases
    /// it does catch. This absence of a `NormalizeDecodeErrors` wrapper is
    /// deliberate, not an oversight: there is no other kind this backend
    /// raises for malformed input that would need folding onto `InvalidData`.
    /// It is a separate question from `caps().detects_corruption`
    /// (`CorruptionDetection::Never`, see above) — that capability is about
    /// whether EVERY corruption is caught, which brotli's checksum-less
    /// format cannot promise; this comment is only about what kind is used on
    /// the occasions it does.
    ///
    /// ## Trailing data is rejected, matching the reference tool
    ///
    /// RFC 7932 defines a single brotli stream, so bytes after a complete one
    /// are malformed, and the reference `brotli` CLI treats them that way: on
    /// `cat a.br b.br` it emits the first stream's output and then **fails
    /// with "corrupt input", exit 1**. `BrotliStreamDecoder` below matches
    /// that: it reports `InvalidData` instead of silently stopping at the
    /// first stream and exiting 0.
    ///
    /// This is NOT the same as zlib and deflate, which also stop at the first
    /// stream — there the reference does too (Python's one-shot
    /// `zlib.decompress` returns only the first stream), so stopping there
    /// (not erroring) is what matches. Brotli's reference errors, so this
    /// decoder does too.
    ///
    /// Three fixes over the high-level `brotli::Decompressor` were measured
    /// and rejected before this one: checking the source for leftover bytes
    /// after decode reports EOF cannot work, because `Decompressor::new(src,
    /// 4096)` reads ahead — on a 29-byte concatenated fixture it pulled all 29
    /// bytes from the source while decoding only the first 14-byte stream, so
    /// the trailing bytes sit in the decompressor's own buffer and the source
    /// looks exhausted (`get_mut()`/`into_inner()` inherit the same
    /// blindness); giving the decompressor a 1-byte input buffer over our own
    /// `BufReader` does work, by making it consume exactly what it needs, but
    /// costs **60x** throughput — 8 MiB in 1.92 s against 32 ms, measured;
    /// and parsing the stream's length ourselves is writing a brotli decoder,
    /// which this module exists not to do.
    ///
    /// `BrotliStreamDecoder` below avoids all three problems by driving the
    /// low-level `BrotliDecompressStream` directly: its `available_in` and
    /// `input_offset` are `&mut`, so after a `ResultSuccess` the exact
    /// consumed/unconsumed boundary is known without any read-ahead guesswork
    /// — the accounting the high-level reader never exposes — at the same
    /// buffer size (4096 bytes) the high-level reader used, so there is no
    /// throughput cost to pay for it.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(BrotliStreamDecoder::new(src))))
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

/// Input buffer size for [`BrotliStreamDecoder`]. Matches the buffer size the
/// former high-level `brotli::Decompressor` used — chosen for parity, not
/// re-tuned, since the whole point of this adapter is that it costs nothing
/// extra over that baseline.
const DECODE_BUF_SIZE: usize = 4096;

type DecoderState = BrotliState<HeapAlloc<u8>, HeapAlloc<u32>, HeapAlloc<HuffmanCode>>;

/// A `Read` adapter over the low-level `BrotliDecompressStream`, in place of
/// the high-level `brotli::Decompressor` — see the trailing-data section of
/// `Codec::decoder`'s doc comment above for why. Reports malformed input,
/// truncation, and trailing data as `io::ErrorKind::InvalidData`.
struct BrotliStreamDecoder {
    src: Box<dyn Source>,
    dec: DecoderState,
    in_buf: [u8; DECODE_BUF_SIZE],
    /// Start of the unconsumed region of `in_buf`.
    in_pos: usize,
    /// End of the valid region of `in_buf` (bytes actually filled by the last read).
    in_len: usize,
    /// `src` has reported EOF at least once; do not call `read` on it again.
    src_eof: bool,
    /// The stream has concluded — successfully or with an error — and every
    /// further call to `read` must return `Ok(0)` without touching `src` or
    /// `dec` again.
    done: bool,
}

impl BrotliStreamDecoder {
    fn new(src: Box<dyn Source>) -> Self {
        Self {
            src,
            dec: BrotliState::new(
                HeapAlloc::<u8>::default(),
                HeapAlloc::<u32>::default(),
                HeapAlloc::<HuffmanCode>::default(),
            ),
            in_buf: [0u8; DECODE_BUF_SIZE],
            in_pos: 0,
            in_len: 0,
            src_eof: false,
            done: false,
        }
    }

    /// Refills `in_buf` from `src`, starting at index 0. Only called once the
    /// current buffer is fully consumed (`in_pos == in_len`), so nothing
    /// unconsumed is ever overwritten.
    fn refill(&mut self) -> std::io::Result<()> {
        if self.src_eof {
            self.in_pos = 0;
            self.in_len = 0;
            return Ok(());
        }
        let n = self.src.read(&mut self.in_buf)?;
        self.in_pos = 0;
        self.in_len = n;
        if n == 0 {
            self.src_eof = true;
        }
        Ok(())
    }

    /// Reached `ResultSuccess` with nothing left to serve from this call.
    /// Any bytes still sitting in `in_buf`, or arriving from one more
    /// physical read of `src`, are trailing data RFC 7932 does not allow —
    /// checked right here, before ever reporting `Ok(0)`, so the standard
    /// `Read` contract (stop at the first zero-length read) cannot skip past
    /// it the way `read_to_end` skipped past the high-level reader's
    /// equivalent check.
    fn finish_after_success(&mut self) -> std::io::Result<usize> {
        self.done = true;
        if self.in_pos < self.in_len {
            return Err(trailing_data_error());
        }
        if !self.src_eof {
            self.refill()?;
            if self.in_len > 0 {
                return Err(trailing_data_error());
            }
        }
        Ok(0)
    }
}

fn trailing_data_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "trailing data after a complete brotli stream",
    )
}

fn truncated_stream_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "brotli stream truncated: input ended mid-stream",
    )
}

fn corrupt_stream_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "brotli stream is corrupt")
}

impl Read for BrotliStreamDecoder {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.done {
            return Ok(0);
        }
        loop {
            if self.in_pos >= self.in_len {
                self.refill()?;
            }

            let mut available_in = self.in_len - self.in_pos;
            let mut input_offset = self.in_pos;
            let mut available_out = buf.len();
            let mut output_offset = 0usize;
            let mut total_out = 0usize;

            let result = BrotliDecompressStream(
                &mut available_in,
                &mut input_offset,
                &self.in_buf[..self.in_len],
                &mut available_out,
                &mut output_offset,
                buf,
                &mut total_out,
                &mut self.dec,
            );
            self.in_pos = input_offset;

            match result {
                BrotliResult::NeedsMoreOutput => return Ok(output_offset),
                BrotliResult::ResultSuccess if output_offset > 0 => return Ok(output_offset),
                BrotliResult::ResultSuccess => return self.finish_after_success(),
                BrotliResult::NeedsMoreInput if output_offset > 0 => return Ok(output_offset),
                BrotliResult::NeedsMoreInput if self.src_eof => {
                    self.done = true;
                    return Err(truncated_stream_error());
                }
                // Genuinely needs more input and none was produced this call:
                // loop back around, the top-of-loop refill picks it up.
                BrotliResult::NeedsMoreInput => {}
                BrotliResult::ResultFailure => {
                    self.done = true;
                    return Err(corrupt_stream_error());
                }
            }
        }
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
    fn trailing_data_after_a_complete_stream_is_rejected() {
        // The reference brotli CLI prints the first stream and then exits 1
        // with "corrupt input" (verified directly against the installed
        // binary: `cat a.br b.br | brotli -d` behaves exactly this way). We
        // used to exit 0 with half the data.
        let mut two = compress(b"first-stream-payload");
        two.extend_from_slice(&compress(b"second-stream-payload"));
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(two)));
        let mut dec = Brotli.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        match dec.read_to_end(&mut out) {
            Ok(_) => panic!(
                "trailing data must be rejected; got Ok with {} bytes",
                out.len()
            ),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
        }
    }

    #[test]
    fn trailing_nul_padding_is_rejected_too() {
        // Whatever the reference does is the answer. Phase 1e learned not to
        // generalise one format's padding answer to another: reference lzip
        // ACCEPTS trailing padding while reference xz/lzma REJECT it. Verified
        // directly against the installed `brotli` 1.2.0 binary: NUL-padding a
        // stream and running `brotli -d` on it prints the first stream's
        // output, then fails with "corrupt input", exit 1 — same as
        // concatenated streams, so this is not inverted.
        let mut padded = compress(b"payload-with-padding");
        padded.extend_from_slice(&[0u8; 32]);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(padded)));
        let mut dec = Brotli.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        assert!(dec.read_to_end(&mut out).is_err());
    }

    #[test]
    fn a_single_stream_with_nothing_appended_still_decodes() {
        let plain = b"ordinary payload ".repeat(4096);
        assert_eq!(decompress(compress(&plain)), plain);
    }

    #[test]
    fn truncation_is_still_reported_as_invalid_data() {
        // NeedsMoreInput at genuine EOF is truncation, not trailing data.
        // Both are InvalidData, and conformance property 10 is unconditional,
        // so this must not regress while the trailing-data check is added.
        let packed = compress(&b"payload ".repeat(4096));
        let cut = packed[..packed.len() / 2].to_vec();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(cut)));
        let mut dec = Brotli.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        match dec.read_to_end(&mut out) {
            Ok(_) => panic!("a truncated stream must not decode cleanly"),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
        }
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
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        let m = meta();
        assert_eq!(m.id, BROTLI);
        assert_eq!(m.extensions, &["br"]);
        assert!(m.magics.is_empty(), "brotli defines no magic bytes");
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn brotli_declares_no_integrity_check_but_a_memory_figure() {
        let c = Brotli.caps();
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::Never,
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
    /// detects_corruption` is `CorruptionDetection::Never`, not `Always`.
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
             whether detects_corruption should flip away from Never: {result:?}"
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
