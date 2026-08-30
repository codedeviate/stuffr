//! bzip2, via the `bzip2` crate's pure-Rust `libbz2-rs-sys` backend.
//!
//! Despite the `-sys` name, `libbz2-rs-sys` is pure Rust — it is what plain
//! `bzip2 = "0.6"` (default features, no `default-features = false`, no
//! nonexistent `libbz2-rs-sys` feature flag) actually pulls in. No C
//! toolchain is required to build this codec.

use std::io::Write;

use bzip2::Compression;
use bzip2::read::MultiBzDecoder;
use bzip2::write::BzEncoder;
use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, FormatMeta, MagicRule, Result, Sink,
    Source, StreamOnly,
};

use crate::normalize::{MALFORMED_AS_INVALID_INPUT_EOF, NormalizeDecodeErrors};

pub const BZIP2: FormatId = FormatId::new("bzip2");

const BZIP2_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: &[0x42, 0x5a, 0x68],
    format: BZIP2,
}];

/// Registration metadata for bzip2.
pub fn meta() -> FormatMeta {
    FormatMeta::codec(BZIP2, &["bz2"], BZIP2_MAGIC)
}

#[derive(Debug)]
pub struct Bzip2;

impl Codec for Bzip2 {
    fn id(&self) -> FormatId {
        BZIP2
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // bzip2 carries a per-block CRC32 plus a whole-stream combined
            // CRC32, so both a flipped byte and a truncated stream are
            // detected rather than silently decoded into different bytes.
            detects_corruption: true,
            // Not measured: derived from the level-9 block size. bzip2's
            // block is 100 KiB * level, so 900 KiB at level 9; the encoder's
            // working set is several multiples of that for its Burrows-
            // Wheeler transform buffers. 4 MiB is a defensible round figure
            // for "several times 900 KiB", not a profiled number.
            memory_per_worker: Some(4 * 1024 * 1024),
            ..CodecCaps::round_trip()
        }
    }

    /// Decodes with `MultiBzDecoder`, never `BzDecoder`, for the same reason
    /// gzip uses `MultiGzDecoder`: concatenated bzip2 streams are valid
    /// bzip2, `pbzip2` produces them, and the single-stream decoder stops
    /// after the first stream without erroring — silently truncating exactly
    /// the files a parallel bzip2 encoder produces.
    ///
    /// Wrapped in `StreamOnly` (a bzip2 stream carries no seek table) and in
    /// `NormalizeDecodeErrors` — see `crate::normalize` for why, and for the
    /// measurement backing the kinds reused here from flate2's list: bzip2's
    /// own vocabulary for malformed input turned out to be the same pair,
    /// `InvalidInput` and `UnexpectedEof`, independently measured against
    /// this crate rather than assumed from gzip's.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            MultiBzDecoder::new(src),
            MALFORMED_AS_INVALID_INPUT_EOF,
        ))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        // Unlike gzip and zlib, bzip2 has no level 0: 1-9 is the whole valid
        // range, so this range is NOT the 0..=9 those codecs use. Rejecting
        // here, before any destination is opened, is what check_encode_opts
        // exists for.
        match o.level {
            Some(n) if !(1..=9).contains(&n) => Err(Error::Usage(format!(
                "bzip2 compression level must be 1-9, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        let level = Compression::new(o.level.unwrap_or(6) as u32);
        Ok(Box::new(Bzip2Sink(BzEncoder::new(dst, level))))
    }
}

struct Bzip2Sink(BzEncoder<Box<dyn Write + Send>>);

impl Write for Bzip2Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for Bzip2Sink {
    /// Writes the closing block and stream trailer.
    ///
    /// Without this the output is a truncated bzip2 stream, which is why
    /// `Sink` has a fallible completion step rather than relying on `Drop`.
    fn finish(self: Box<Self>) -> Result<()> {
        let Bzip2Sink(encoder) = *self;
        let mut w = encoder.finish()?;
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
        let mut sink = Bzip2
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Bzip2.decoder(src, &DecodeOpts::default()).unwrap();
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
            "bzip2 must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_bzip2_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..3], &[0x42, 0x5a, 0x68]);
    }

    #[test]
    fn decodes_concatenated_members_not_just_the_first() {
        // Concatenated bzip2 streams are valid bzip2 — pbzip2 produces them —
        // and BzDecoder stops after the first stream without erroring, so a
        // regression here truncates silently.
        let mut two = compress(b"first-");
        two.extend_from_slice(&compress(b"second"));
        assert_eq!(decompress(two), b"first-second");
    }

    #[test]
    fn level_zero_is_rejected_because_bzip2_starts_at_one() {
        // Unlike gzip, bzip2 has no level 0 — it is invalid, not "store".
        // A range copied from gzip would accept this and fail later, at encode
        // time, with the destination already open.
        let opts = EncodeOpts {
            level: Some(0),
            ..Default::default()
        };
        let Err(err) = Bzip2.check_encode_opts(&opts) else {
            panic!("level 0 must be rejected");
        };
        assert!(matches!(err, stuffr_core::Error::Usage(_)), "got {err:?}");
        assert!(
            err.to_string().contains("1-9"),
            "the error must name the real range: {err}"
        );

        // And the valid extremes are accepted.
        for n in [1, 9] {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            assert!(
                Bzip2.check_encode_opts(&opts).is_ok(),
                "level {n} must be accepted"
            );
        }
    }

    #[test]
    fn an_out_of_range_level_is_a_usage_error_not_a_silent_clamp() {
        let opts = EncodeOpts {
            level: Some(12),
            ..Default::default()
        };
        match Bzip2.encoder(Box::new(SharedBuf::new()), &opts) {
            Err(err) => {
                assert!(matches!(err, stuffr_core::Error::Usage(_)));
                assert_eq!(err.exit_code(), 2);
                assert!(err.to_string().contains("1-9"));
            }
            Ok(_) => panic!("encoder should reject out-of-range level"),
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        // bzip2 carries no frame index, so its output must not claim random
        // access. A container above it would otherwise read wrong bytes.
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Bzip2.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Bzip2.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until cycle 1c");
        let m = meta();
        assert_eq!(m.id, BZIP2);
        assert_eq!(m.extensions, &["bz2"]);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn bzip2_declares_an_integrity_check_and_a_memory_figure() {
        let c = Bzip2.caps();
        assert!(
            c.detects_corruption,
            "bzip2 carries per-block and stream CRCs, so corrupt input is detectable"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    #[test]
    fn bzip2_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Bzip2, &meta());
    }
}
