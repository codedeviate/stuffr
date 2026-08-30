//! lz4, frame format (not block), via the `lz4_flex` crate's pure-Rust
//! encoder/decoder.
//!
//! `lz4_flex::block` is a one-shot API over a whole buffer with no streaming
//! type at all — it cannot satisfy conformance property 8 (incremental
//! decode) by construction, since there is no incremental decoder to test.
//! It waits for Phase 2, where a container knows each entry's length up
//! front and a whole-buffer API becomes usable again.
//! `lz4_flex::frame::{FrameEncoder, FrameDecoder}` are the streaming types,
//! and `.lz4` files are frame-format streams — this is the only lz4 shape in
//! scope this cycle.
//!
//! ## The EndMark fix
//!
//! Measured directly against the release binary (Phase 1d's final fix wave,
//! item 1): a truncated `.lz4` frame — cut at ANY 64 KiB block boundary, or
//! in the last 4 bytes — decoded with exit 0 and a shorter-than-expected but
//! otherwise correct-looking output. Root cause, confirmed directly against
//! `lz4_flex` 0.14's own source (`frame/decompress.rs::read_block`):
//! `FrameDecoder` reads the next block's 4-byte size word via `read_exact`,
//! and if THAT `read_exact` itself fails with `UnexpectedEof` — which
//! `read_exact` raises identically whether zero bytes were available or a
//! partial 1-3 were — the code treats it exactly like a legitimate
//! `BlockInfo::EndMark` (a block-size word that was actually read in full,
//! and found to be all zero) and returns `Ok(0)` either way. A stream
//! truncated precisely at a block boundary hits the first path; a complete
//! stream hits the second; `FrameDecoder`'s own `Read` impl cannot tell them
//! apart, and neither can any `FrameInfo` configuration — content and block
//! checksums are validated, if at all, only for bytes already accepted as
//! real, and this bug fires before any of that runs.
//!
//! [`EndMarkTracker`]/[`TrackedRead`]/[`EnforceEndMark`] close this from
//! outside the crate, since the defect is internal to `read_block` and not
//! reachable through any public `FrameInfo` knob (verified: the reviewer
//! swept `content_checksum`, `block_checksums`, both, and `content_size`,
//! all five configurations identical). `TrackedRead` wraps the raw
//! compressed-byte SOURCE and keeps a rolling 8-byte window of the last
//! bytes it actually served to `FrameDecoder`. `EnforceEndMark` wraps
//! `FrameDecoder`'s output and, the instant it reports `Ok(0)`, asks the
//! tracker whether the source truly ended with the frame's own EndMark (4
//! zero bytes, optionally followed by a 4-byte content checksum — the only
//! thing the format ever permits after it; nothing else does, since a
//! per-block checksum is consumed inside `read_block` before the loop ever
//! asks for the next block's size word). If not, `Ok(0)` becomes
//! `InvalidData` instead: the exact classification every other truncation in
//! this codec already uses via [`NormalizeDecodeErrors`].
//!
//! This depends on one fact about `FrameDecoder` that is not part of its
//! public contract: that reading a genuine EndMark actually consumes those 4
//! (or 8) bytes from its source before its own `read()` call returns `Ok(0)`
//! — not merely that the frame is logically exhausted. Confirmed directly in
//! `read_block`'s `BlockInfo::EndMark` arm, which performs its own
//! `read_exact` for the block-size word (and, if `content_checksum` is set,
//! `read_checksum` right after) before returning `Ok(0)`, all within the same
//! outer `read()` call — see
//! `lz4_frame_decoder_actually_consumes_the_endmark_on_a_complete_stream`
//! below, which pins this directly rather than trusting the source reading.

use std::io::Write;
use std::sync::{Arc, Mutex};

use lz4_flex::frame::{BlockSize, FrameDecoder, FrameEncoder, FrameInfo};
use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, FormatId, FormatMeta, MagicRule, Result, Sink,
    Source, StreamOnly,
};

use crate::normalize::{MALFORMED_AS_INVALID_INPUT_EOF, NormalizeDecodeErrors};

/// A rolling window over the last 8 bytes a [`TrackedRead`] has actually
/// served to `FrameDecoder`, used by [`EnforceEndMark`] to tell a genuine
/// EndMark from `FrameDecoder`'s own EOF-swallowing bug (see the module doc).
///
/// 8 bytes, not 4: the frame format permits an optional 4-byte content
/// checksum to trail the 4-byte EndMark itself (never anything else — see
/// the module doc for why per-block checksums cannot land here). Checking
/// only the last 4 bytes would wrongly reject a legitimately-checksummed
/// stream produced by another encoder, since its true last 4 bytes are the
/// checksum, not the EndMark. This codec's own encoder never turns
/// checksums on, so this only matters for decoding another implementation's
/// output — which this decoder is otherwise built to accept (see `caps()`'s
/// memory-sizing rationale for the same "must handle input we didn't
/// produce" argument).
struct EndMarkTracker {
    window: [u8; 8],
    filled: u8,
}

impl EndMarkTracker {
    fn new() -> Self {
        Self {
            window: [0; 8],
            filled: 0,
        }
    }

    fn record(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.window.copy_within(1..8, 0);
            self.window[7] = b;
        }
        self.filled = self
            .filled
            .saturating_add(bytes.len().min(u8::MAX as usize) as u8);
    }

    /// True once the stream's real EndMark was actually read: either the
    /// last 4 bytes served are all zero (no trailing checksum), or the 4
    /// bytes before those are all zero and at least 8 bytes total have been
    /// served (a trailing 4-byte content checksum, whatever its value).
    /// `filled` gates both arms so the window's zero-initialised bytes
    /// before anything real has been read can never masquerade as an
    /// EndMark on a very short stream.
    fn is_end_mark(&self) -> bool {
        (self.filled >= 4 && self.window[4..8] == [0, 0, 0, 0])
            || (self.filled >= 8 && self.window[0..4] == [0, 0, 0, 0])
    }
}

/// Feeds every byte a source actually serves to `FrameDecoder` into a shared
/// [`EndMarkTracker`]. Errors pass through unchanged and are never recorded
/// (nothing was actually served).
struct TrackedRead {
    inner: Box<dyn Source>,
    tracker: Arc<Mutex<EndMarkTracker>>,
}

impl std::io::Read for TrackedRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.tracker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .record(&buf[..n]);
        }
        Ok(n)
    }
}

/// Wraps `FrameDecoder`'s (normalized) output and, the moment it reports
/// clean `Ok(0)`, checks the shared tracker for whether the source it read
/// from actually ended with the frame's EndMark. See the module doc for the
/// full defect this closes.
struct EnforceEndMark<R> {
    inner: R,
    tracker: Arc<Mutex<EndMarkTracker>>,
    /// `None`: not yet checked. `Some(false)`: already found truncated —
    /// every further call keeps reporting the same error rather than
    /// falling back to `Ok(0)`, the same idempotence
    /// `conformance::framed_mock`'s reference double uses for its own
    /// truncated-or-corrupted state.
    truncated: bool,
}

const LZ4_TRUNCATED_NO_ENDMARK: &str =
    "lz4 frame ended without its EndMark; the stream is truncated";

impl<R: std::io::Read> std::io::Read for EnforceEndMark<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.truncated {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                LZ4_TRUNCATED_NO_ENDMARK,
            ));
        }
        let n = self.inner.read(buf)?;
        if n == 0 {
            let ok = self
                .tracker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_end_mark();
            if !ok {
                self.truncated = true;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    LZ4_TRUNCATED_NO_ENDMARK,
                ));
            }
        }
        Ok(n)
    }
}

pub const LZ4: FormatId = FormatId::new("lz4");

const LZ4_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: &[0x04, 0x22, 0x4d, 0x18],
    format: LZ4,
}];

/// Registration metadata for lz4 (frame format only — see the module docs).
pub fn meta() -> FormatMeta {
    FormatMeta::codec(LZ4, &["lz4"], LZ4_MAGIC)
}

#[derive(Debug)]
pub struct Lz4;

impl Codec for Lz4 {
    fn id(&self) -> FormatId {
        LZ4
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // Measured, and NOT what the brief (or the design doc) expected
            // going in: the LZ4 frame's content checksum is OPTIONAL, and
            // `lz4_flex::frame::FrameEncoder::new` — via `FrameInfo::default`
            // — turns both it and the per-block checksum off. Swept every
            // byte position of a real encoded 4 KiB incompressible payload
            // (see the `lz4_conformance_probe` test below): all but a
            // handful of positions near the frame header decode WITHOUT
            // error and with DIFFERENT bytes than the original — silent
            // corruption, not detected corruption. The same probe run
            // against a 64 KiB payload found this scales exactly the same
            // way (65536 of 65551 positions silently wrong). This is the
            // same gap raw deflate and brotli already declare honestly (see
            // deflate.rs and brotli.rs) — no checksum over content that
            // decoded fine is not a contradiction with detecting truncation
            // just fine (below).
            detects_corruption: false,
            // Item 6 of Phase 1d's final fix wave: this field's own contract
            // (see `format.rs`) is "cost of one ENCODE worker", and this is
            // now that — not the earlier figure, which was measurably the
            // DECODE side's cost instead (a 64x disagreement with the field's
            // contract, since the governor sizes ENCODE workers off it).
            // `encoder` below pins the block size this codec ever PRODUCES to
            // `Max64KB` (see its own doc comment) — independent block mode
            // sizes both the encoder's `src` and `dst` buffers to roughly the
            // block size each, so every stream this codec writes works a
            // ~128 KiB region. That is the number this field declares now.
            //
            // The decode side is real and larger, but belongs in prose, not
            // in this field: `decoder` below accepts any conformant `.lz4`
            // file, including one produced by another encoder entirely —
            // lz4_flex itself at default settings, or another implementation
            // altogether — which is free to use up to `BlockSize::Max4MB` (4
            // MiB), the frame format's own ceiling. A decoder sized for only
            // this codec's own ~128 KiB output would under-allocate for such
            // a file. 8 MiB — "two buffers around a 4 MiB block" — is a
            // defensible round figure for THAT side, not a profiled number,
            // but Phase 1f's governor sizes ENCODE workers off this field
            // (see its own doc comment), and a decode figure here would
            // under-parallelise encode by up to 64x for the one codec chosen
            // specifically for throughput. Option (b) — splitting the field
            // into separate encode/decode costs, with all seven codecs
            // declaring both — was considered and rejected for this wave:
            // three more codecs join in Phase 1e, so the meaning needed
            // settling now, and (a) is a one-line, one-codec fix while (b)
            // touches `CodecCaps` and every codec's `caps()`. Revisit (b) if
            // a decode-side figure turns out to matter to the governor too.
            memory_per_worker: Some(128 * 1024),
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `NormalizeDecodeErrors`: measured directly against this
    /// crate (see `lz4_conformance_probe` below), a truncated lz4 frame
    /// stream — cut anywhere past its first few header bytes — surfaces as
    /// `UnexpectedEof`, the same kind flate2 and bzip2 raise for their own
    /// truncated streams, so reusing `MALFORMED_AS_INVALID_INPUT_EOF` is
    /// correct. lz4_flex never raises `InvalidInput` itself; folding that
    /// unused kind onto `InvalidData` alongside `UnexpectedEof` is harmless,
    /// same as it is for zlib and raw deflate.
    ///
    /// Also wrapped, outermost, in [`EnforceEndMark`] — over a source first
    /// wrapped in [`TrackedRead`] — closing the truncation gap this module's
    /// doc comment describes: without it, `FrameDecoder` itself reports a
    /// stream cut at a block boundary (or missing its final EndMark) as a
    /// clean `Ok(0)`, indistinguishable from a real one. Every truncation
    /// `EnforceEndMark` catches raises `InvalidData` directly — already the
    /// correct classification `NormalizeDecodeErrors` would have produced
    /// from `UnexpectedEof` regardless, so this does not introduce a new
    /// error vocabulary, only reaches truncations that were reaching neither
    /// path before.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let tracker = Arc::new(Mutex::new(EndMarkTracker::new()));
        let tracked = TrackedRead {
            inner: src,
            tracker: Arc::clone(&tracker),
        };
        let normalized =
            NormalizeDecodeErrors::new(FrameDecoder::new(tracked), MALFORMED_AS_INVALID_INPUT_EOF);
        Ok(Box::new(StreamOnly::new(EnforceEndMark {
            inner: normalized,
            tracker,
            truncated: false,
        })))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        // lz4_flex exposes no compression level at all — the frame encoder
        // takes no such knob — so every level is rejected the same way an
        // absent knob should be: nothing here to validate, and `encoder`
        // below ignores `o.level` entirely. Property 6 confirms `encoder`
        // agrees with this by never rejecting on the strength of a level.
        let _ = o;
        Ok(())
    }

    /// Deliberately NOT `FrameEncoder::new(dst)` (the default `FrameInfo`),
    /// which leaves `block_size` at `BlockSize::Auto` — sized from the
    /// length of whichever `write` call happens to be first. Measured
    /// directly against conformance property 8: encoding `assert_codec_
    /// conforms`'s own 4 MiB payload in the ONE `write_all` call its harness
    /// makes lets `Auto` pick `Max4MB`, so the entire payload becomes a
    /// single block that cannot be written — and therefore cannot be
    /// decoded — until it is wholly buffered, which is indistinguishable
    /// from a read-to-end decoder and fails property 8 outright. Pinning
    /// `Max64KB` — the size the frame format's own docs call "the default
    /// block size" — makes block boundaries fall well inside any payload
    /// property 8 uses, regardless of how many bytes the caller hands to one
    /// `write` call. Content and block checksums stay off either way — this
    /// only changes the block-size field, not the ones `caps()`'s corruption
    /// measurement depends on.
    ///
    /// `Max64KB` specifically, not merely "small enough to pass property
    /// 8" — property 8's threshold is `big_len / 4`, a full 1 MiB against
    /// its 4 MiB payload, so anything up to `Max1MB` would ALSO have
    /// satisfied the test; the test did not force this particular value.
    /// lz4 is chosen in this tree for streaming latency rather than
    /// compression ratio, and `Max64KB` is the streaming argument taken to
    /// its natural size: a container reading this codec's own output
    /// incrementally — `stf cat huge.lz4 | head`, say — sees its first
    /// bytes after one 64 KiB block decodes, not after a 1 MiB (or 4 MiB)
    /// block does. The flip side is real and worth naming rather than
    /// hiding: a smaller block also shrinks the LZ77 match window, so data
    /// with redundancy spread out further than 64 KiB compresses worse here
    /// than it would at a larger block size — a real ratio cost this codec
    /// accepts deliberately, for latency, not a free choice.
    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        let frame_info = FrameInfo::new().block_size(BlockSize::Max64KB);
        Ok(Box::new(Lz4Sink(FrameEncoder::with_frame_info(
            frame_info, dst,
        ))))
    }
}

struct Lz4Sink(FrameEncoder<Box<dyn Write + Send>>);

impl Write for Lz4Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for Lz4Sink {
    /// `FrameEncoder::finish` returns `Result<W, lz4_flex::frame::Error>`, not
    /// `io::Result<W>` — but that error type converts to `std::io::Error`
    /// (lz4_flex provides the impl), so a write failure surfaces directly
    /// through the ordinary `?` conversion into `stuffr_core::Error` once
    /// routed through `io::Error`. No `CaptureWriteError` adapter is needed
    /// here the way brotli's `into_inner` (which returns `W` with no
    /// `Result` at all) required one.
    fn finish(self: Box<Self>) -> Result<()> {
        let Lz4Sink(encoder) = *self;
        let mut w = encoder.finish().map_err(std::io::Error::from)?;
        w.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use stuffr_core::Error;
    use stuffr_core::ReaderSource;
    use stuffr_core::testing::SharedBuf;

    fn compress(plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = Lz4
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Lz4.decoder(src, &DecodeOpts::default()).unwrap();
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
            "lz4 must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_frame_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..4], &[0x04, 0x22, 0x4d, 0x18]);
    }

    #[test]
    fn any_level_is_accepted_because_lz4_flex_exposes_none() {
        for level in [i32::MIN, -1, 0, 1, i32::MAX] {
            let opts = EncodeOpts {
                level: Some(level),
                ..Default::default()
            };
            assert!(
                Lz4.check_encode_opts(&opts).is_ok(),
                "level {level} must be accepted: lz4_flex has no level knob to reject on"
            );
            assert!(
                Lz4.encoder(Box::new(SharedBuf::new()), &opts).is_ok(),
                "encoder must agree with check_encode_opts for level {level}"
            );
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        // lz4's frame carries no seek table in this codec's usage, so its
        // output must not claim random access. A container above it would
        // otherwise read wrong bytes.
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Lz4.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn a_genuine_read_error_stays_io_not_corrupt() {
        struct AlwaysPermissionDenied;
        impl Read for AlwaysPermissionDenied {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "simulated disk error",
                ))
            }
        }
        impl Source for AlwaysPermissionDenied {
            fn caps(&self) -> stuffr_core::SourceCaps {
                stuffr_core::SourceCaps {
                    seekable: false,
                    len: None,
                }
            }
            fn as_seek(&mut self) -> Option<&mut dyn stuffr_core::SeekRead> {
                None
            }
        }

        let src: Box<dyn Source> = Box::new(AlwaysPermissionDenied);
        let mut dec = Lz4.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        let io_err = dec.read_to_end(&mut out).unwrap_err();
        assert_eq!(
            io_err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "the adapter must not fold a real disk error onto InvalidData"
        );

        let err = Error::from_decode_io(io_err);
        assert!(
            matches!(err, Error::Io(_)),
            "a genuine disk error must classify as Error::Io, not Error::Corrupt: got {err:?}"
        );
        assert_eq!(err.exit_code(), 1, "Error::Io is exit 1, not 5");
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Lz4.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until cycle 1c");
        let m = meta();
        assert_eq!(m.id, LZ4);
        assert_eq!(m.extensions, &["lz4"]);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn lz4_declares_no_integrity_check_but_a_memory_figure() {
        let c = Lz4.caps();
        assert!(
            !c.detects_corruption,
            "lz4_flex's FrameEncoder turns off both the content checksum and the per-block \
             checksum by default; a byte flipped almost anywhere in the frame decodes to \
             different bytes with no error, measured directly against this crate — see \
             caps()'s doc comment and lz4_conformance_probe below"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    /// Pins the exact discrepancy against the brief's (and the design doc's)
    /// expectation that lz4 detects corruption: it measurably does not, for
    /// the vast majority of byte positions.
    ///
    /// A single flipped byte proves almost nothing on its own — this cycle's
    /// brotli measurement was disputed twice, and the first attempt at it was
    /// wrong for exactly that reason (see brotli.rs). So this sweeps EVERY
    /// byte position of a real encoded payload, not one, and counts outcomes:
    /// silently-wrong decode vs. a real error. If corruption detection here
    /// were real rather than incidental, the overwhelming majority of flips
    /// would error; measured directly, the overwhelming majority instead
    /// decode successfully with different bytes.
    ///
    /// 4 KiB rather than the 64 KiB conformance property 9 itself would use:
    /// this test's job is to justify the capability declaration with a wide
    /// sweep, not to duplicate property 9's own probe, and the outcome
    /// distribution is the same shape at both sizes (independently checked
    /// during this measurement: 65536 of 65551 byte positions in a 64 KiB
    /// payload also decoded silently wrong).
    #[test]
    fn lz4_conformance_probe_corruption_is_silent_at_almost_every_position() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let packed = compress(&plain);

        let mut silently_wrong = 0usize;
        let mut errored = 0usize;
        let mut silently_unchanged = 0usize;
        for i in 0..packed.len() {
            let mut corrupted = packed.clone();
            corrupted[i] ^= 0xFF;
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(corrupted)));
            let mut dec = Lz4.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) if out == plain => silently_unchanged += 1,
                Ok(_) => silently_wrong += 1,
                Err(_) => errored += 1,
            }
        }

        assert_eq!(
            silently_unchanged,
            0,
            "every one of {} flipped positions changed exactly one output byte; a flip landing \
             with zero effect would be a probe bug, not a codec property",
            packed.len()
        );
        assert!(
            silently_wrong * 2 > packed.len(),
            "expected a clear majority of {} byte positions to decode silently wrong \
             (measured: {silently_wrong} silent, {errored} errored) — if this ever flips, \
             detects_corruption should become true instead of staying false",
            packed.len()
        );
    }

    /// Verifies the one fact the EndMark fix depends on, directly, before
    /// trusting anything built on it: that `FrameDecoder` actually reads the
    /// frame's real EndMark bytes from its source before reporting a clean
    /// `Ok(0)`, rather than merely inferring completion some other way. If a
    /// future `lz4_flex` upgrade ever stopped doing this, this test — not
    /// the truncation test below it — is the one that would fail, and it
    /// would fail by naming exactly this assumption instead of by the fix
    /// silently going inert.
    #[test]
    fn lz4_frame_decoder_actually_consumes_the_endmark_on_a_complete_stream() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let packed = compress(&plain);

        let tracker = Arc::new(Mutex::new(EndMarkTracker::new()));
        let tracked = TrackedRead {
            inner: Box::new(ReaderSource::new(std::io::Cursor::new(packed))),
            tracker: Arc::clone(&tracker),
        };
        let mut dec = FrameDecoder::new(tracked);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(
            out, plain,
            "sanity: this must still be a real, valid round trip"
        );
        assert!(
            tracker.lock().unwrap().is_end_mark(),
            "FrameDecoder reported clean EOF without the tracker ever observing the frame's \
             real EndMark bytes — the whole fix in this module's EnforceEndMark depends on \
             this being true, and it no longer is"
        );
    }

    /// Reproduces the exact defect measured in Phase 1d's final fix brief and
    /// proves it is closed: a 1 MiB incompressible payload, packed with this
    /// codec's own encoder (pinned to `Max64KB` blocks — see `encoder`'s doc
    /// comment), used to decode successfully from a truncated 65,547-byte
    /// prefix (6.25% of the packed size) with exit 0 and exactly 65,536
    /// silently-short bytes. Every 64 KiB block boundary in the same file
    /// had the identical defect, plus the final EndMark itself — 22 clean
    /// truncations total, measured directly against the release binary.
    ///
    /// The boundary offsets below are DERIVED from the packed output, not
    /// hardcoded: `incompressible()` guarantees each 64 KiB block fails to
    /// shrink (see `write_block` in `lz4_flex`'s own source — it falls back
    /// to storing a block raw whenever compression does not strictly help),
    /// so every block is stored as exactly 65536 raw bytes plus its own
    /// 4-byte size word, and the one unknown left — the frame header's own
    /// length — falls out of the arithmetic below rather than being assumed.
    /// This keeps the test self-correcting against a header layout change,
    /// rather than silently testing the wrong byte position if one occurs.
    #[test]
    fn truncated_lz4_frame_is_rejected_at_every_block_boundary() {
        use stuffr_core::testing::incompressible;

        const PLAIN_LEN: usize = 1024 * 1024;
        const BLOCK_PLAIN_LEN: usize = 64 * 1024;
        const BLOCK_STORED_LEN: usize = BLOCK_PLAIN_LEN + 4; // + this block's own size word
        const END_MARK_LEN: usize = 4;

        let plain = incompressible(PLAIN_LEN);
        let packed = compress(&plain);
        let num_blocks = PLAIN_LEN / BLOCK_PLAIN_LEN;
        assert_eq!(
            PLAIN_LEN % BLOCK_PLAIN_LEN,
            0,
            "fixture must divide evenly into blocks"
        );

        // Derived, not assumed: total overhead minus every block's own size
        // word minus the EndMark is exactly the frame header's length, IF
        // every block really did store raw (asserted below, not just hoped).
        let overhead = packed.len() - plain.len();
        let header_len = overhead
            .checked_sub(num_blocks * 4 + END_MARK_LEN)
            .expect("packed output smaller than the raw-block-storage lower bound");

        let boundary_of_block = |k: usize| header_len + k * BLOCK_STORED_LEN;
        let end_mark_starts_at = boundary_of_block(num_blocks);
        assert_eq!(
            end_mark_starts_at + END_MARK_LEN,
            packed.len(),
            "derived boundary arithmetic does not land on the packed output's actual length — \
             a block must have compressed after all, invalidating this test's assumption"
        );

        // The brief's own exact measured cut: right after block 1's raw
        // payload and its own size word, before block 2's size word begins.
        let brief_cut = boundary_of_block(1);
        assert_eq!(
            brief_cut, 65_547,
            "must match the brief's own measured cut exactly"
        );

        for k in 1..=num_blocks {
            let cut = boundary_of_block(k);
            let truncated = packed[..cut].to_vec();
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
            let mut dec = Lz4.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            let result = dec.read_to_end(&mut out);
            assert!(
                result.is_err(),
                "block boundary {k}/{num_blocks} (cut at byte {cut}) decoded without error — \
                 the EndMark fix did not close this boundary"
            );
            let err = result.unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidData,
                "block boundary {k}/{num_blocks}: expected InvalidData, got {:?}",
                err.kind()
            );
        }

        // The final EndMark's own last byte: cutting it off by one byte must
        // still be rejected, not just a cut at its very first byte (already
        // covered by k == num_blocks above).
        let cut = packed.len() - 1;
        let truncated = packed[..cut].to_vec();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
        let mut dec = Lz4.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        assert!(
            dec.read_to_end(&mut out).is_err(),
            "truncating just the final EndMark byte (cut at {cut}) decoded without error"
        );
    }

    #[test]
    fn lz4_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Lz4, &meta());
    }
}
