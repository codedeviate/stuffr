//! snappy, frame format (not raw), via the `snap` crate's pure-Rust
//! encoder/decoder.
//!
//! `snap::raw` is a one-shot API over a whole buffer with no streaming type
//! at all — it cannot satisfy conformance property 8 (incremental decode) by
//! construction, since there is no incremental decoder to test. It waits for
//! Phase 2, the same way `lz4_flex::block` does (see `lz4.rs`), where a
//! container knows each entry's length up front and a whole-buffer API
//! becomes usable again.
//! `snap::read::FrameDecoder` and `snap::write::FrameEncoder` are the
//! streaming types, and `.sz` files are frame-format streams — this is the
//! only snappy shape in scope this cycle.
//!
//! A genuine, structural finding from sweeping truncation at every byte
//! position (see `snappy_conformance_probe_truncation_is_detected_at_almost_
//! every_position` below): a stream cut at ANY chunk boundary decodes
//! cleanly to a truncated-but-unerrored result, not just the one right
//! after the 10-byte stream identifier. A single-chunk (4 KiB) payload only
//! ever exercises that first boundary, which is why an earlier version of
//! this doc and its probe both claimed "exactly one" clean cut — true only
//! as an artifact of a payload smaller than one chunk (`MAX_BLOCK_SIZE`, 64
//! KiB); a payload spanning several chunks shows every chunk boundary
//! behaves the same way. This is not a detection gap to paper over — the
//! frame format is explicitly a sequence of independent chunks designed to
//! support concatenation, so a reader genuinely cannot distinguish "this is
//! the whole stream, and it happens to end right here" from "more chunks
//! were meant to follow but got cut off" at any chunk boundary, with
//! nothing left unread from the chunk before it. It does not touch
//! conformance property 10, which cuts at the payload's midpoint, deep
//! inside a single chunk's payload bytes, nowhere near any chunk boundary.

use std::io::Write;

use snap::read::FrameDecoder;
use snap::write::FrameEncoder;
use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, FormatId, FormatMeta, MagicRule,
    Result, Sink, Source, StreamOnly,
};

use crate::normalize::{NormalizeDecodeErrors, SNAPPY_MALFORMED_AS_OTHER_EOF};

pub const SNAPPY: FormatId = FormatId::new("snappy");

/// The framing format's stream identifier chunk: chunk type `0xff` (Stream),
/// a little-endian 24-bit length of 6 (`0x06 0x00 0x00`), followed by the
/// literal body `sNaPpY`. Every frame-format stream begins with exactly
/// these ten bytes — `snap::frame::STREAM_IDENTIFIER`, measured directly
/// against the crate's own source rather than assumed from the spec.
const SNAPPY_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: &[0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59],
    format: SNAPPY,
}];

/// Registration metadata for snappy (frame format only — see the module
/// docs).
pub fn meta() -> FormatMeta {
    FormatMeta::codec(SNAPPY, &["sz"], SNAPPY_MAGIC)
}

#[derive(Debug)]
pub struct Snappy;

impl Codec for Snappy {
    fn id(&self) -> FormatId {
        SNAPPY
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // Measured (see snappy_conformance_probe_corruption_is_detected_
            // at_almost_every_position below), and — unlike lz4's frame
            // format — genuinely mandatory rather than optional: `snap`'s
            // `compress_frame` computes a CRC32C over every chunk's
            // UNCOMPRESSED bytes unconditionally (see `frame.rs::
            // compress_frame` in the `snap` source; there is no knob to turn
            // it off), and the reader verifies it on every chunk it decodes
            // (`read.rs`'s `Error::Checksum` check), whether the chunk ended
            // up stored `Compressed` or `Uncompressed`. Sweeping every byte
            // position of a real encoded incompressible payload finds the
            // checksum catches the corruption at every position but ONE: the
            // data chunk's own TYPE byte, which the checksum does not cover
            // at all — it protects a chunk's CONTENT, not the framing byte
            // that says what kind of chunk this is. XORing that one byte
            // with 0xFF turns `Uncompressed` (0x01) into `Padding` (0xFE) —
            // both are chunk types the format defines — so the reader
            // correctly treats the "corrupted" chunk as padding to be
            // skipped, and cleanly reaches EOF having decoded nothing, no
            // error raised. This is real and structural, not a probe
            // artifact: any corruption that lands the type byte on another
            // DEFINED type (0xFF/0x00/0x01/0xFE, or the 0x80-0xFD skippable
            // range) is unprotected by construction. It does not threaten
            // conformance property 9, which flips a byte at the payload's
            // MIDPOINT, nowhere near this one structural byte. Measured in
            // Phase 1d at exactly 1 of 4,114 swept positions — see
            // `snappy_conformance_probe_corruption_is_detected_at_almost_
            // every_position` below for the sweep and the exact count;
            // `Always` here means "the format mandates a check", not "no
            // silent failure is possible" — this one framing-byte position
            // is the documented exception.
            detects_corruption: CorruptionDetection::Always,
            // Measured from the crate's own fixed buffer sizes, not
            // profiled: `write::FrameEncoder` allocates a `src` buffer of
            // `MAX_BLOCK_SIZE` (2^16 = 65536 bytes) plus an `Inner::dst`
            // buffer of `MAX_COMPRESS_BLOCK_SIZE` (76490 bytes, `snap`'s own
            // `max_compress_len(MAX_BLOCK_SIZE)`) plus an 8-byte chunk
            // header — about 142 KiB. `read::FrameDecoder` allocates the same
            // two buffers in the opposite roles (a `MAX_COMPRESS_BLOCK_SIZE`
            // `src` and a `MAX_BLOCK_SIZE` `dst`) — also about 142 KiB.
            // Unlike lz4_flex, `snap` exposes no block-size knob at all: both
            // directions are pinned to these exact constants regardless of
            // how this codec is used, so there is no "Auto" mode to avoid in
            // the first place (see `encoder` below). 256 KiB — a quarter
            // MiB — is a defensible round figure with headroom over the
            // measured ~142 KiB either direction actually allocates.
            memory_per_worker: Some(256 * 1024),
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `NormalizeDecodeErrors` with [`SNAPPY_MALFORMED_AS_OTHER_
    /// EOF`], NOT the shared [`crate::normalize::MALFORMED_AS_INVALID_INPUT_
    /// EOF`] every flate2/bzip2-backed codec in this tree reuses — snappy's
    /// vocabulary is measurably different (`Other` + `UnexpectedEof`, not
    /// `InvalidInput` + `UnexpectedEof`) and widening the shared constant to
    /// include `Other` would apply that generic kind to every codec sharing
    /// it. See that constant's doc comment in `normalize.rs` for the full
    /// measurement and the argument for why folding `Other` onto
    /// `InvalidData` is safe specifically for this backend.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            FrameDecoder::new(src),
            SNAPPY_MALFORMED_AS_OTHER_EOF,
        ))))
    }

    // `check_encode_opts` stays the trait default (accept everything): `snap`
    // exposes no compression level at all, the same shape as lz4 — see
    // `examples.txt`, which says so alongside lz4's identical case. Property
    // 6 confirms `encoder` below agrees by never rejecting on the strength of
    // a level.

    /// `snap::write::FrameEncoder` pins its block size to a fixed
    /// `MAX_BLOCK_SIZE` (64 KiB) with no configurable "Auto" mode at all —
    /// unlike `lz4_flex`, there is no larger block a big single `write_all`
    /// call could trigger (see `caps()` above), so this needs none of the
    /// `BlockSize::Max64KB` pinning lz4.rs's `encoder` does. `FrameEncoder::
    /// new` is already exactly what conformance property 8 needs.
    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        Ok(Box::new(SnappySink(FrameEncoder::new(dst))))
    }
}

struct SnappySink(FrameEncoder<Box<dyn Write + Send>>);

impl Write for SnappySink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for SnappySink {
    /// `FrameEncoder::into_inner` returns `Result<W, snap::write::
    /// IntoInnerError<FrameEncoder<W>>>` — a finalisation failure IS
    /// recoverable here, unlike brotli's `CompressorWriter::into_inner`
    /// (which returns `W` with no `Result` at all and needs the
    /// `CaptureWriteError` adapter — see `brotli.rs`). `IntoInnerError::
    /// into_error` hands back the `io::Error` that caused the internal
    /// flush to fail, which `?` then converts into `stuffr_core::Error`
    /// exactly the way a bare `io::Error` from `zlib.rs`'s or `lz4.rs`'s own
    /// `finish` does. Losing this conversion (discarding it in favour of
    /// treating `into_inner`'s `Err` as unconditional success) is precisely
    /// what conformance property 5 exists to catch.
    fn finish(self: Box<Self>) -> Result<()> {
        let SnappySink(encoder) = *self;
        let mut w = encoder.into_inner().map_err(|e| e.into_error())?;
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
        let mut sink = Snappy
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Snappy.decoder(src, &DecodeOpts::default()).unwrap();
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
            "snappy must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_frame_magic() {
        let packed = compress(b"payload");
        assert_eq!(
            &packed[..10],
            &[0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59]
        );
    }

    #[test]
    fn any_level_is_accepted_because_snap_exposes_none() {
        for level in [i32::MIN, -1, 0, 1, i32::MAX] {
            let opts = EncodeOpts {
                level: Some(level),
                ..Default::default()
            };
            assert!(
                Snappy.check_encode_opts(&opts).is_ok(),
                "level {level} must be accepted: snap has no level knob to reject on"
            );
            assert!(
                Snappy.encoder(Box::new(SharedBuf::new()), &opts).is_ok(),
                "encoder must agree with check_encode_opts for level {level}"
            );
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        // snappy's frame carries no seek table in this codec's usage, so its
        // output must not claim random access. A container above it would
        // otherwise read wrong bytes.
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Snappy.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Snappy.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        let m = meta();
        assert_eq!(m.id, SNAPPY);
        assert_eq!(m.extensions, &["sz"]);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn snappy_declares_an_integrity_check_and_a_memory_figure() {
        let c = Snappy.caps();
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::Always,
            "the frame format CRC32Cs every chunk's uncompressed bytes unconditionally — \
             measured directly against this crate, see caps()'s doc comment and the probe test \
             below"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    /// Measures snappy's error vocabulary directly against `snap`, sweeping
    /// EVERY byte position of a real encoded payload rather than flipping
    /// one — a single flip proved unreliable for brotli earlier this cycle
    /// (see brotli.rs) and gave the wrong answer there. Confirms both halves
    /// of the pair `SNAPPY_MALFORMED_AS_OTHER_EOF` declares: a corrupted
    /// stream reports `Other` at almost every position, and — because a
    /// corrupted length field can make the reader try to read past the end
    /// of the (unchanged-length) stream — a couple of positions instead
    /// report `UnexpectedEof`, which is exactly why the constant carries
    /// both kinds, not just `Other` alone. Almost no position decodes to
    /// silently wrong bytes: the checksum is unconditional (see `caps()`),
    /// so this doubles as the direct evidence backing `detects_corruption:
    /// CorruptionDetection::Always` — with exactly ONE measured, documented
    /// exception, asserted precisely below rather than papered over.
    ///
    /// 4 KiB rather than the 64 KiB conformance property 9 itself uses — same
    /// reasoning as `lz4_conformance_probe_corruption_is_silent_at_almost_
    /// every_position` in `lz4.rs`: this test's job is to justify the
    /// capability declaration with a wide sweep, not to duplicate property
    /// 9's own probe, and a full byte-for-byte sweep of a real payload this
    /// crate's checksum path is otherwise O(n) over is O(n^2) in a debug
    /// build — independently confirmed the outcome distribution is the same
    /// shape at 64 KiB, just far slower to demonstrate it.
    ///
    /// Measured against the RAW `snap::read::FrameDecoder`, NOT this codec's
    /// own `Snappy::decoder` — `Snappy::decoder` already wraps it in
    /// `NormalizeDecodeErrors`, which folds both `Other` and `UnexpectedEof`
    /// onto `InvalidData` before this test could ever see which one a given
    /// position actually raised. Measuring through the wrapper measures the
    /// wrapper's own behaviour, not the backend's — the first version of
    /// this probe made exactly that mistake and reported zero `UnexpectedEof`
    /// even under truncation (see the sibling test below), because both
    /// kinds look identical once folded.
    #[test]
    fn snappy_conformance_probe_corruption_is_detected_at_almost_every_position() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let packed = compress(&plain);

        let mut other = 0usize;
        let mut unexpected_eof = 0usize;
        let mut other_kind = 0usize;
        let mut silently_unchanged = 0usize;
        let mut silently_wrong = Vec::new();
        for i in 0..packed.len() {
            let mut corrupted = packed.clone();
            corrupted[i] ^= 0xFF;
            let mut dec = FrameDecoder::new(std::io::Cursor::new(corrupted));
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) if out == plain => silently_unchanged += 1,
                Ok(_) => silently_wrong.push(i),
                Err(e) => match e.kind() {
                    std::io::ErrorKind::Other => other += 1,
                    std::io::ErrorKind::UnexpectedEof => unexpected_eof += 1,
                    _ => other_kind += 1,
                },
            }
        }

        assert_eq!(
            silently_unchanged,
            0,
            "every one of {} flipped positions changed exactly one output byte; a flip landing \
             with zero effect would be a probe bug, not a codec property",
            packed.len()
        );
        // The ONE genuine, measured exception: index 10 is the data chunk's
        // own TYPE byte (offset 0 of its 4-byte header, right after the
        // 10-byte stream identifier — see caps()'s doc comment for why this
        // byte specifically is unprotected). XORing it with 0xFF turns
        // `Uncompressed` (0x01) into `Padding` (0xFE), both defined chunk
        // types, so the reader accepts the corrupted chunk as padding and
        // reaches a clean, silently-empty EOF. Every other byte in the
        // stream — every other framing byte, every checksum byte, every
        // payload byte — IS covered and must still error; any OTHER silent
        // position here would be a genuine, undocumented detection gap.
        assert_eq!(
            silently_wrong,
            vec![10],
            "expected exactly one silently-wrong position: index 10, the data chunk's type \
             byte (see this test's comment for why). Any other silent position would be a \
             genuine, undocumented corruption-detection gap — measured: {silently_wrong:?}"
        );
        assert_eq!(
            other_kind, 0,
            "every error this backend raises for malformed input must be either Other or \
             UnexpectedEof — SNAPPY_MALFORMED_AS_OTHER_EOF's whole premise — but {other_kind} \
             positions raised something else"
        );
        assert!(
            other > 0,
            "expected corruption to raise Other at least once across the sweep — measured 0"
        );
        assert!(
            unexpected_eof > 0,
            "expected at least one corrupted position to raise UnexpectedEof too — a corrupted \
             length field pushing the reader past the real end of the stream — measured 0; if \
             this is genuinely 0 now, SNAPPY_MALFORMED_AS_OTHER_EOF may be carrying a kind \
             corruption itself never raises (truncation still would, see the sibling test)"
        );
    }

    /// The truncation counterpart to the corruption probe above: cuts a real
    /// encoded payload short at many prefix lengths and confirms every
    /// truncation is rejected, with the reported kind always inside
    /// `SNAPPY_MALFORMED_AS_OTHER_EOF` — except at a chunk boundary, where
    /// the format is genuinely ambiguous (see below and the module doc).
    /// `FrameDecoder` uses `read_exact` internally, so this is expected to be
    /// almost entirely `UnexpectedEof` — measured directly rather than
    /// assumed.
    ///
    /// 200 KiB, spanning several chunks (`MAX_BLOCK_SIZE` is 64 KiB) — NOT
    /// the 4 KiB single-chunk payload the corruption probe above uses. Item
    /// 4 of Phase 1d's final fix wave: a single-chunk payload can only ever
    /// exercise the ONE chunk boundary it has, which understated the clean
    /// cuts below as "exactly one" when the true shape is "every chunk
    /// boundary".
    ///
    /// Unlike the corruption probe (and unlike this test's own previous
    /// version), this does NOT sweep every one of ~200,000 byte positions:
    /// each decode attempt processes up to the full payload, so an
    /// exhaustive sweep at this size is quadratic over 200 KiB — measured
    /// directly, over a minute and still running in a debug build, not the
    /// few seconds the 4 KiB corruption probe takes. Sweeping only a
    /// generous local window around each candidate boundary (every chunk
    /// header and checksum is 8 bytes; the window below is 32) still
    /// exercises every byte position where the format's own framing could
    /// plausibly turn a truncation clean, and a handful of deep-interior
    /// samples (each chunk's own midpoint) confirm ordinary mid-chunk
    /// truncation is untouched by this change — without re-doing the
    /// original full byte-for-byte sweep this test itself already ran at 4
    /// KiB, where it remains cheap.
    ///
    /// Measured against the RAW `snap::read::FrameDecoder`, for the same
    /// reason as the corruption probe above: this codec's own decoder folds
    /// `Other` and `UnexpectedEof` to the same `InvalidData`, which would
    /// hide exactly the distinction this test exists to confirm.
    ///
    /// What this test itself establishes is "no clean cut among the swept
    /// positions other than the boundaries" — the local windows plus
    /// midpoint samples, not literally every byte. A Phase 1d final-fix-wave
    /// review ran the full exhaustive sweep this test declines to run (for
    /// the timing reason above) and got exactly this same boundary set with
    /// no additional clean cuts, confirming the stronger claim independently
    /// — but that verification lives in the review record, not in this
    /// file, so the assertion message below claims only what this test
    /// itself can prove.
    #[test]
    fn snappy_conformance_probe_truncation_is_detected_at_almost_every_position() {
        use stuffr_core::testing::incompressible;

        // Measured directly against the `snap` crate's own source
        // (`frame.rs`): `CHUNK_HEADER_AND_CRC_SIZE` and `MAX_BLOCK_SIZE`,
        // also cited in `caps()`'s own memory-sizing doc comment above.
        // Neither is `pub` from the crate, so they are pinned here as local
        // constants rather than imported.
        const CHUNK_HEADER_AND_CRC_SIZE: usize = 8;
        const MAX_BLOCK_SIZE: usize = 64 * 1024;
        const WINDOW: usize = 32;
        let stream_identifier_len = SNAPPY_MAGIC[0].bytes.len();

        let plain = incompressible(200 * 1024);
        let packed = compress(&plain);
        assert_eq!(&packed[..stream_identifier_len], SNAPPY_MAGIC[0].bytes);

        // Every chunk boundary, DERIVED from the encoded output's own length
        // rather than hardcoded, so this self-corrects against anything that
        // would change the chunk layout (a different payload size, a future
        // `snap` whose chunking changed) rather than silently sweeping the
        // wrong positions.
        let full_chunk_len = CHUNK_HEADER_AND_CRC_SIZE + MAX_BLOCK_SIZE;
        let num_full_chunks = (packed.len() - stream_identifier_len) / full_chunk_len;
        assert!(
            num_full_chunks >= 3,
            "fixture must span several full chunks, not one, or this test regresses back to \
             the single-chunk artifact item 4 fixed — measured {num_full_chunks} full chunks \
             in a {} byte payload",
            packed.len()
        );
        let boundaries: Vec<usize> = std::iter::once(stream_identifier_len)
            .chain((1..=num_full_chunks).map(|k| stream_identifier_len + k * full_chunk_len))
            .collect();

        // Cuts to actually try: a window of WINDOW bytes on each side of
        // every boundary above, plus one deep-interior sample per full chunk
        // (its own midpoint) as a sanity check that ordinary mid-chunk
        // truncation is untouched. A `BTreeSet` both de-duplicates (the
        // stream-identifier boundary's window and block 1's window would
        // otherwise overlap) and gives a stable, sorted iteration order.
        let mut cuts_to_try: std::collections::BTreeSet<usize> = boundaries
            .iter()
            .flat_map(|&b| b.saturating_sub(WINDOW)..=(b + WINDOW).min(packed.len() - 1))
            .filter(|&c| c >= 1)
            .collect();
        for k in 1..=num_full_chunks {
            let chunk_start = stream_identifier_len + (k - 1) * full_chunk_len;
            cuts_to_try.insert(chunk_start + full_chunk_len / 2);
        }

        let mut unexpected_eof = 0usize;
        let mut other = 0usize;
        let mut other_kind = 0usize;
        let mut clean_cuts = Vec::new();
        for cut in cuts_to_try {
            let truncated = packed[..cut].to_vec();
            let mut dec = FrameDecoder::new(std::io::Cursor::new(truncated));
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) => clean_cuts.push(cut),
                Err(e) => match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => unexpected_eof += 1,
                    std::io::ErrorKind::Other => other += 1,
                    _ => other_kind += 1,
                },
            }
        }

        // Exactly the boundaries themselves are clean, nothing in the
        // windows around them and nothing at any chunk's midpoint. This is
        // not a codec defect to paper over: the frame format is an explicit
        // sequence of independent chunks, designed so complete streams can
        // be concatenated (the format spec calls this out directly), so a
        // reader has no way to tell "this is genuinely the whole stream, and
        // it happens to end right here" from "more chunks were meant to
        // follow but got cut off" at any such boundary, with nothing left
        // unread from the chunk before it. Every OTHER position — inside a
        // chunk header, inside a checksum, inside a chunk's payload bytes —
        // has no such ambiguity and is rejected, which is exactly what
        // conformance property 10 exercises: it cuts at `len/2` (among other
        // lengths), deep inside a single chunk's payload, nowhere near any
        // chunk boundary.
        assert_eq!(
            clean_cuts, boundaries,
            "expected a clean truncation cut at exactly the stream identifier boundary and \
             every full chunk boundary after it, and no others AMONG THE POSITIONS SWEPT HERE \
             (see this test's comment for why this sweep is local, not exhaustive, and for the \
             independent exhaustive verification that found the same set). Any other clean cut \
             within these windows would be a genuine truncation-detection gap, not this \
             documented one — measured: {clean_cuts:?}, expected: {boundaries:?}"
        );
        assert_eq!(
            other_kind, 0,
            "every truncation error must be either Other or UnexpectedEof — measured: {other} \
             Other, {unexpected_eof} UnexpectedEof, {other_kind} other kinds"
        );
        assert!(
            unexpected_eof > 0,
            "expected at least some truncation cuts to surface as UnexpectedEof — read_exact's \
             own kind — measured 0"
        );
    }

    #[test]
    fn snappy_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Snappy, &meta());
    }
}
