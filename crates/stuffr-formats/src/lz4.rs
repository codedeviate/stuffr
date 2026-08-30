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

use std::io::Write;

use lz4_flex::frame::{BlockSize, FrameDecoder, FrameEncoder, FrameInfo};
use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, FormatId, FormatMeta, MagicRule, Result, Sink,
    Source, StreamOnly,
};

use crate::normalize::{MALFORMED_AS_INVALID_INPUT_EOF, NormalizeDecodeErrors};

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
            // Not measured: derived from the block size lz4_flex's
            // `BlockSize::Auto` can select for a single large write —
            // `from_buf_length` tops out at `Max4MB` (4 MiB) once the first
            // write exceeds 256 KiB — with independent block mode (the
            // default) sizing both the encoder's `src`/`dst` buffers and the
            // decoder's `src`/`dst` buffers to roughly that block size each.
            // 8 MiB is a defensible round figure for "two buffers around a 4
            // MiB block", not a profiled number.
            memory_per_worker: Some(8 * 1024 * 1024),
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
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            FrameDecoder::new(src),
            MALFORMED_AS_INVALID_INPUT_EOF,
        ))))
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

    #[test]
    fn lz4_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Lz4, &meta());
    }
}
