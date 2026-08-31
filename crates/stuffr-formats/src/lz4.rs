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
//! **First attempt, since reverted: a byte-pattern heuristic.** The first
//! version of this fix kept a rolling window of the last bytes served to
//! `FrameDecoder` and accepted completion only when that window held the
//! literal EndMark bytes (four zeros). A second review pass broke it: cuts
//! made at every 64 KiB boundary of a 256 KiB zero-PADDED text file — tar
//! members, disk images, ELF/PE section padding, anything page-aligned, none
//! of it exotic — decoded cleanly too, because ordinary zero-padded content
//! reproduces the same four-zero-byte pattern the check was looking for. It
//! also cost 160-180 ms per 64 MiB of input for the per-byte window shift,
//! against ~34 microseconds for the mechanism below — on the codec chosen
//! specifically for throughput, that made the guard the dominant cost of
//! decoding. Both problems trace to the same design error: matching a byte
//! PATTERN can never be data-independent, and no fixed window size is immune
//! to content that happens to look like the pattern.
//!
//! **The fix: an EOF discriminator, not a byte pattern.** Instrumented
//! directly against `lz4_flex`: a complete stream never causes the
//! underlying SOURCE's own `read` to return `Ok(0)` while `FrameDecoder` is
//! still processing the CURRENT frame — `read_block`'s `BlockInfo::EndMark`
//! arm reads its block-size word (and optional checksum) as ordinary,
//! successful, nonzero-length reads. A stream truncated at a block boundary
//! is different in exactly one way that matters: the source's own `read`
//! genuinely returns `Ok(0)` — a real "I have nothing left" signal — at the
//! moment `read_block`'s `read_exact` tries to fetch that word, and
//! `read_exact` folds that into the same swallowed `UnexpectedEof` described
//! above. So [`TrackedRead`] records one fact per read attempt — did the
//! wrapped source's `read` return `Ok(0)` — and [`EnforceEndMark`] checks
//! that fact, not stream content, when `FrameDecoder` reports `Ok(0)`: a
//! genuine EndMark was read using ordinary nonzero reads (fact is `false`);
//! a stream cut anywhere the parser still expected more hit real source
//! exhaustion getting there (fact is `true`). This is O(1) per read attempt,
//! not O(bytes) — no window, no byte comparison, nothing content-dependent.
//!
//! **Concatenation composes with this, and had to be fixed alongside it.**
//! `FrameDecoder` already supports concatenated frames internally — after one
//! frame's `Ok(0)`, calling `read()` again resumes into a following frame's
//! header if more data exists — but a bare `Ok(0)` from `EnforceEndMark`
//! itself would stop `read_to_end` right there, silently losing every frame
//! after the first (verified: prepending one complete frame to a truncated
//! one used to exit 0 with only the first frame's bytes — the same failure
//! shape gzip's and bzip2's multi-stream decoders already solve for their own
//! formats). `EnforceEndMark` closes this the same way: after a CLEAN `Ok(0)`
//! (fact `false` — a real EndMark was read), it does not report completion
//! yet. It asks `FrameDecoder` to read again, which either resumes a
//! following frame (real bytes come back, served transparently) or hits a
//! GENUINE source exhaustion while checking for one (`FrameDecoder`'s own
//! frame-header parse returns `Ok(0)` only when its own read of the next
//! frame's magic bytes gets nothing at all — never via the swallowed-error
//! path above, which is specific to `read_block`'s mid-frame position) — and
//! that combination is the one place a `true` fact is NOT truncation: it is
//! "no more frames, the whole stream — one member or several — is genuinely
//! done." The two states are kept apart by tracking whether a frame has ever
//! ended cleanly since the last time real bytes were served; see
//! `EnforceEndMark::read`'s own comments for the exact state transitions.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lz4_flex::frame::{BlockSize, FrameDecoder, FrameEncoder, FrameInfo};
use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, FormatId, FormatMeta, MagicRule,
    Result, Sink, Source, StreamOnly,
};

use crate::normalize::{MALFORMED_AS_INVALID_INPUT_EOF, NormalizeDecodeErrors};

/// Wraps the raw compressed-byte SOURCE and records, in `hit_eof`, whether
/// its most recent read attempt returned a genuine `Ok(0)` — the source had
/// nothing left at all, not merely fewer bytes than asked for. Shared with
/// [`EnforceEndMark`], which resets this flag before each attempt it makes
/// and inspects it immediately after, so the flag always answers "did the
/// source run dry DURING THIS SPECIFIC attempt" rather than accumulating
/// across the whole decode. See the module doc for why this — not a
/// byte-content window — is the right discriminator.
struct TrackedRead {
    inner: Box<dyn Source>,
    hit_eof: Arc<AtomicBool>,
}

impl std::io::Read for TrackedRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            self.hit_eof.store(true, Ordering::Relaxed);
        }
        Ok(n)
    }
}

/// Wraps `FrameDecoder`'s (normalized) output. See the module doc for the
/// full mechanism and the defect this closes.
struct EnforceEndMark<R> {
    inner: R,
    hit_eof: Arc<AtomicBool>,
    /// Set once a frame has ended cleanly (its `Ok(0)` involved no source
    /// exhaustion) and we are now checking whether a concatenated frame
    /// follows. Reset to `false` the instant real decoded bytes arrive —
    /// from this frame's own continuation, or transparently from a
    /// newly-discovered concatenated one — so that frame's eventual ending
    /// is judged by the same rule again, never waved through just because
    /// an earlier frame completed cleanly.
    awaiting_concat_probe: bool,
    /// Latches truncation so every further call keeps reporting the same
    /// error, the same idempotence `conformance::framed_mock`'s reference
    /// double uses for its own truncated-or-corrupted state.
    truncated: bool,
}

const LZ4_TRUNCATED_NO_ENDMARK: &str =
    "lz4 frame ended without its EndMark; the stream is truncated";

impl<R: std::io::Read> std::io::Read for EnforceEndMark<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // A zero-length buffer conventionally yields Ok(0) with no I/O
        // attempted at all (nothing calls this with one today, but nothing
        // stops a future caller from doing so) — it says nothing about the
        // stream's real state, and running it through the state machine
        // below would latch a false "truncated" the instant one arrived
        // mid-stream.
        if buf.is_empty() {
            return Ok(0);
        }
        if self.truncated {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                LZ4_TRUNCATED_NO_ENDMARK,
            ));
        }
        loop {
            self.hit_eof.store(false, Ordering::Relaxed);
            let n = self.inner.read(buf)?;
            if n > 0 {
                self.awaiting_concat_probe = false;
                return Ok(n);
            }
            // n == 0: did the wrapped source genuinely run dry reaching this
            // result, or did FrameDecoder read a real EndMark in full?
            if self.hit_eof.load(Ordering::Relaxed) {
                if self.awaiting_concat_probe {
                    // This Ok(0) came from FrameDecoder checking for a
                    // concatenated next frame (its own frame-header parse),
                    // not from mid-frame block processing — a genuine
                    // source exhaustion here means "no more frames", not
                    // truncation. See the module doc for why these two
                    // Ok(0)-with-exhaustion cases are distinguishable at
                    // all.
                    return Ok(0);
                }
                self.truncated = true;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    LZ4_TRUNCATED_NO_ENDMARK,
                ));
            }
            // Clean Ok(0): a real EndMark (and optional checksum) was read
            // in full, no source exhaustion involved. Do not report
            // completion yet — loop back and ask again, in case a
            // concatenated frame follows. If none does, the next iteration
            // resolves through the branch above; if one does, its bytes are
            // served like any other and this flag resets on that return.
            self.awaiting_concat_probe = true;
        }
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
            detects_corruption: CorruptionDetection::Never,
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
    /// path before. `EnforceEndMark` also transparently continues into a
    /// concatenated next frame rather than stopping at the first `Ok(0)` —
    /// see the module doc's note on concatenation.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let hit_eof = Arc::new(AtomicBool::new(false));
        let tracked = TrackedRead {
            inner: src,
            hit_eof: Arc::clone(&hit_eof),
        };
        let normalized =
            NormalizeDecodeErrors::new(FrameDecoder::new(tracked), MALFORMED_AS_INVALID_INPUT_EOF);
        Ok(Box::new(StreamOnly::new(EnforceEndMark {
            inner: normalized,
            hit_eof,
            awaiting_concat_probe: false,
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
    fn decodes_concatenated_frames_not_just_the_first() {
        // Concatenated lz4 frames are valid lz4 (the frame format spec calls
        // this out explicitly — see snappy.rs's own module doc for the same
        // property in a different format), and `FrameDecoder` supports it
        // internally: after one frame's Ok(0), reading again resumes into a
        // following frame's header if more data exists. Verified previously
        // via the CLI directly against the gzip control (which already
        // handles this): prepending a second complete frame used to be lost
        // entirely, exiting 0 with only the first frame's bytes, because
        // EnforceEndMark stopped at the first Ok(0) instead of checking for
        // more. See the module doc's note on concatenation for why the fix
        // for this and the EndMark fix compose in one mechanism.
        let mut two = compress(b"first-");
        two.extend_from_slice(&compress(b"second"));
        assert_eq!(decompress(two), b"first-second");
    }

    #[test]
    fn a_truncated_second_frame_in_a_concatenated_stream_is_rejected() {
        // The concatenation fix must not reopen item 1's own hole: a
        // complete first frame followed by a TRUNCATED second one must
        // still be rejected, not silently accepted as "just the first
        // frame, nothing more" — the two frames are handled by the exact
        // same state machine, and this pins that the truncation half of it
        // still fires once concatenation is in play.
        let complete = compress(b"first-");
        let second_full = compress(b"second-frame-payload");
        let mut two = complete.clone();
        two.extend_from_slice(&second_full[..second_full.len() - 1]);

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(two)));
        let mut dec = Lz4.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        assert!(
            dec.read_to_end(&mut out).is_err(),
            "a complete frame followed by a truncated second one must not decode cleanly"
        );
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
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::Never,
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
             detects_corruption should move off Never instead of staying there",
            packed.len()
        );
    }

    /// Verifies the one fact the EndMark fix depends on, directly, before
    /// trusting anything built on it: that a COMPLETE, single (non-
    /// concatenated) frame never causes the wrapped source's own `read` to
    /// return a genuine `Ok(0)` while `FrameDecoder` is still processing it
    /// — `FrameDecoder` reads the real EndMark (and any trailing checksum)
    /// as ordinary, successful, nonzero-length reads, and stops asking
    /// before ever touching true source exhaustion. If a future `lz4_flex`
    /// upgrade ever changed this, this test — not the truncation test below
    /// it — is the one that would fail, and it would fail by naming exactly
    /// this assumption instead of by the fix silently going inert.
    ///
    /// Mirrors the reviewer's own instrumentation against `padded.lz4`
    /// directly: `saw_eof=false` with `served == packed.len()` for a
    /// complete stream, `saw_eof=true` for every truncated cut (see the
    /// sweep test below).
    #[test]
    fn lz4_frame_decoder_never_touches_source_eof_on_a_complete_stream() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let packed = compress(&plain);
        let packed_len = packed.len();

        let hit_eof = Arc::new(AtomicBool::new(false));
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        struct CountingSource {
            inner: std::io::Cursor<Vec<u8>>,
            served: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl std::io::Read for CountingSource {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = std::io::Read::read(&mut self.inner, buf)?;
                self.served.fetch_add(n, Ordering::Relaxed);
                Ok(n)
            }
        }
        impl Source for CountingSource {
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

        let tracked = TrackedRead {
            inner: Box::new(CountingSource {
                inner: std::io::Cursor::new(packed),
                served: Arc::clone(&served),
            }),
            hit_eof: Arc::clone(&hit_eof),
        };
        let mut dec = FrameDecoder::new(tracked);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(
            out, plain,
            "sanity: this must still be a real, valid round trip"
        );
        assert!(
            !hit_eof.load(Ordering::Relaxed),
            "FrameDecoder touched genuine source exhaustion decoding a COMPLETE stream — the \
             whole EOF-based discriminator in this module's EnforceEndMark depends on this \
             never happening for a well-formed frame"
        );
        assert_eq!(
            served.load(Ordering::Relaxed),
            packed_len,
            "expected FrameDecoder to have consumed exactly the packed stream's own bytes, no \
             fewer and no more, without ever probing past its real end"
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

    /// The specific payload shape that defeated the first (reverted)
    /// EndMark fix: `incompressible()` never produces zero bytes at a
    /// block's tail, so neither this file's other truncation test nor
    /// property 10's own fixture ever exercised the case a second review
    /// pass found — ordinary zero-padded content (tar members, disk images,
    /// ELF/PE section padding, anything page-aligned) reproduces the
    /// EndMark's own four-zero-byte pattern inside real block data, which a
    /// byte-pattern check cannot tell apart from the genuine article. The
    /// EOF-based discriminator this module now uses does not look at
    /// content at all, so this sweeps the exact shape that broke the old
    /// approach and confirms the new one does not share the defect.
    #[test]
    fn truncated_lz4_frame_with_zero_padded_content_is_still_rejected() {
        const BLOCK_LEN: usize = 64 * 1024;
        const NUM_BLOCKS: usize = 4;

        // Each 64 KiB block: real, repeating text, then zero padding to
        // fill out the rest of the block — the page/tar/ELF-alignment shape
        // the review named, not an artificial worst case.
        let text = b"the quick brown fox jumps over the lazy dog
"
        .repeat(400);
        let mut plain = Vec::with_capacity(BLOCK_LEN * NUM_BLOCKS);
        for _ in 0..NUM_BLOCKS {
            let mut block = vec![0u8; BLOCK_LEN];
            let take = text.len().min(BLOCK_LEN);
            block[..take].copy_from_slice(&text[..take]);
            plain.extend_from_slice(&block);
        }
        assert_eq!(plain.len(), BLOCK_LEN * NUM_BLOCKS);

        let packed = compress(&plain);
        assert_eq!(
            decompress(packed.clone()),
            plain,
            "sanity: this must still be a real, valid round trip"
        );

        let boundaries = lz4_block_boundaries(&packed);
        assert!(
            boundaries.len() >= NUM_BLOCKS,
            "expected at least {NUM_BLOCKS} block boundaries (one per block, plus the \
             EndMark), found {}: {boundaries:?}",
            boundaries.len()
        );

        for &boundary in &boundaries {
            for cut in [
                boundary.saturating_sub(2),
                boundary.saturating_sub(1),
                boundary,
                boundary + 1,
                boundary + 2,
            ] {
                if cut == 0 || cut >= packed.len() {
                    continue;
                }
                let truncated = packed[..cut].to_vec();
                let src: Box<dyn Source> =
                    Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
                let mut dec = Lz4.decoder(src, &DecodeOpts::default()).unwrap();
                let mut out = Vec::new();
                assert!(
                    dec.read_to_end(&mut out).is_err(),
                    "zero-padded fixture: cut at byte {cut} (near boundary {boundary}) decoded \
                     without error — a byte-pattern EndMark check would have accepted this \
                     (real content reproducing the EndMark's own zero-byte pattern); the \
                     EOF-based one must not"
                );
            }
        }
    }

    /// Walks a stream produced by THIS codec's own encoder (no checksums, no
    /// content size, no dictionary — see `encoder`'s own `FrameInfo`) and
    /// returns the byte offset of every block's own size-word, including the
    /// final EndMark's. General over whether each block ended up stored raw
    /// or compressed, unlike the arithmetic
    /// `truncated_lz4_frame_is_rejected_at_every_block_boundary` uses —
    /// that test's fixture is guaranteed raw (`incompressible()`), the
    /// zero-padded one above is not.
    fn lz4_block_boundaries(packed: &[u8]) -> Vec<usize> {
        // FLG (byte 4) bit 3 is content_size, bit 0 is dict_id — neither is
        // set by this codec's own encoder, but computed here rather than
        // assumed, so a future FrameInfo change to `encoder` cannot silently
        // desync this helper from the bytes it is parsing.
        let flg = packed[4];
        let mut header_len = 4 + 2 + 1; // magic + FLG/BD + HC
        if flg & 0x08 != 0 {
            header_len += 8; // content_size
        }
        if flg & 0x01 != 0 {
            header_len += 4; // dictionary ID
        }

        let mut boundaries = Vec::new();
        let mut pos = header_len;
        loop {
            assert!(
                pos + 4 <= packed.len(),
                "ran off the end of the stream while walking blocks"
            );
            boundaries.push(pos);
            let word = u32::from_le_bytes(packed[pos..pos + 4].try_into().unwrap());
            if word == 0 {
                break; // EndMark
            }
            let len = (word & 0x7FFF_FFFF) as usize;
            pos += 4 + len; // block_checksums off in this codec's own output
        }
        boundaries
    }

    #[test]
    fn lz4_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Lz4, &meta());
    }
}
