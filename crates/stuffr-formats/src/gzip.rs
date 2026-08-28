//! gzip, via `flate2`'s pure-Rust backend.

use std::io::Write;

use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, FormatMeta, MagicRule, Result, Sink,
    Source, StreamOnly,
};

pub const GZIP: FormatId = FormatId::new("gzip");

const GZIP_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: &[0x1f, 0x8b],
    format: GZIP,
}];

/// Registration metadata for gzip.
pub fn meta() -> FormatMeta {
    FormatMeta::codec(GZIP, &["gz"], GZIP_MAGIC)
}

#[derive(Debug)]
pub struct Gzip;

impl Codec for Gzip {
    fn id(&self) -> FormatId {
        GZIP
    }

    fn caps(&self) -> CodecCaps {
        // Parallel encode and a frame index arrive in cycle 1c.
        CodecCaps::round_trip()
    }

    /// Decodes with `MultiGzDecoder`, never `GzDecoder`.
    ///
    /// Concatenated gzip members are valid gzip, and every parallel encoder
    /// produces them. `GzDecoder` stops after the first member and returns a
    /// short read *without an error*, silently truncating exactly the files
    /// this project will generate itself once 1c lands multi-member encode.
    ///
    /// The result is wrapped in `StreamOnly`: a gzip stream carries no seek
    /// table, so its decoded output must not claim random access.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(MultiGzDecoder::new(src))))
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        let level = match o.level {
            Some(n) if !(0..=9).contains(&n) => {
                return Err(Error::Usage(format!(
                    "gzip compression level must be 0-9, got {n}"
                )));
            }
            Some(n) => Compression::new(n as u32),
            None => Compression::default(),
        };
        Ok(Box::new(GzSink(GzEncoder::new(dst, level))))
    }
}

struct GzSink(GzEncoder<Box<dyn Write + Send>>);

impl Write for GzSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for GzSink {
    /// Writes the CRC32 and length trailer.
    ///
    /// Without this the output is a truncated gzip stream that most decoders
    /// reject and some accept with garbage — which is why `Sink` has a fallible
    /// completion step rather than relying on `Drop`.
    fn finish(self: Box<Self>) -> Result<()> {
        let GzSink(encoder) = *self;
        encoder.finish()?;
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
        let mut sink = Gzip
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Gzip.decoder(src, &DecodeOpts::default()).unwrap();
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
            "gzip must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_gzip_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn decodes_concatenated_members_not_just_the_first() {
        // Concatenated gzip members are valid gzip, and every parallel encoder
        // produces them — including the multi-member encode this project adds
        // in cycle 1c. GzDecoder stops after the first member and returns a
        // short read WITHOUT an error, so a regression here truncates silently.
        let mut two = compress(b"first-");
        two.extend_from_slice(&compress(b"second"));
        assert_eq!(decompress(two), b"first-second");
    }

    #[test]
    fn finish_surfaces_a_write_error_that_drop_would_swallow() {
        // GzEncoder::drop calls finish() and discards the error. This drives
        // the failure through this project's own types — Gzip::encoder and
        // Sink::finish — rather than flate2's inherent GzEncoder::finish, so
        // a regression that swallows the error (e.g. `let _ = e.finish();`
        // instead of `e.finish()?;` in `impl Sink for GzSink`) is actually
        // caught by this test.
        //
        // Threshold, MEASURED (not assumed): a `GzEncoder` writes exactly a
        // 10-byte gzip header to the underlying writer on the very first
        // `write` call, regardless of chunk size, and nothing else reaches
        // the underlying writer until `finish()` pushes the compressed body
        // and the CRC32+size trailer. Confirmed with an instrumented
        // counting writer plus a sweep of `FailAfterN` limits: limits below
        // 10 make `write_all` itself fail (the wrong subject — that would
        // be testing `Write::write`, not `Sink::finish`); a limit of exactly
        // 10 lets `write_all` succeed (it only pushes the header) while
        // `finish()` fails (it must push body + trailer), isolating the
        // failure to `finish()` specifically. That is why 10 is used below,
        // not some other N.
        struct FailAfterN {
            limit: usize,
            written: usize,
        }

        impl Write for FailAfterN {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.written >= self.limit {
                    return Err(std::io::Error::other("intentional test failure"));
                }
                let to_write = std::cmp::min(buf.len(), self.limit - self.written);
                self.written += to_write;
                Ok(to_write)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut sink = Gzip
            .encoder(
                Box::new(FailAfterN {
                    limit: 10,
                    written: 0,
                }),
                &EncodeOpts::default(),
            )
            .unwrap();

        // Consumes only the header budget (measured above); Sink::finish is
        // the step that must fail.
        sink.write_all(b"this is test data that should compress")
            .unwrap();

        let result = sink.finish();
        assert!(
            result.is_err(),
            "Sink::finish should surface the underlying writer's error instead of swallowing it"
        );
    }

    #[test]
    fn an_out_of_range_level_is_a_usage_error_not_a_silent_clamp() {
        let opts = EncodeOpts {
            level: Some(12),
            ..Default::default()
        };
        match Gzip.encoder(Box::new(SharedBuf::new()), &opts) {
            Err(err) => {
                assert!(matches!(err, stuffr_core::Error::Usage(_)));
                assert_eq!(err.exit_code(), 2);
                assert!(err.to_string().contains("0-9"));
            }
            Ok(_) => panic!("encoder should reject out-of-range level"),
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        // gzip carries no frame index, so its output must not claim random
        // access. A container above it would otherwise read wrong bytes.
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Gzip.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Gzip.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until cycle 1c");
        let m = meta();
        assert_eq!(m.id, GZIP);
        assert_eq!(m.extensions, &["gz"]);
        assert_eq!(m.priority, 0);
    }
}
