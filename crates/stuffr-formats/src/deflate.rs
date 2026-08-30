//! Raw deflate (RFC 1951, no header or trailer), via `flate2`'s pure-Rust
//! backend.

use std::io::Write;

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, FormatMeta, Result, Sink, Source,
    StreamOnly,
};

use crate::normalize::{FLATE2_MALFORMED, NormalizeDecodeErrors};

pub const DEFLATE: FormatId = FormatId::new("deflate");

/// No magic, no conventional extension: a raw deflate stream is exactly the
/// compressed bits, with no header or trailer to identify it or a length to
/// bound it. Registering an empty rule slice tells detection there is nothing
/// here to try — `--format deflate` is the only way in.
pub fn meta() -> FormatMeta {
    FormatMeta::codec(DEFLATE, &[], &[])
}

#[derive(Debug)]
pub struct Deflate;

impl Codec for Deflate {
    fn id(&self) -> FormatId {
        DEFLATE
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // Raw deflate carries no checksum, so a flipped byte among the
            // compressed bits decodes to different output rather than an
            // error: corruption is not detectable here.
            //
            // Truncation is a different question, and this codec still
            // passes conformance property 10 despite `detects_corruption:
            // false`: the final block's `BFINAL` bit means a stream cut short
            // ends mid-block, which flate2 surfaces as `UnexpectedEof` — the
            // adapter folds that onto `InvalidData` the same as any other
            // codec here. "No integrity check" and "truncation is still
            // detectable" are not a contradiction: one is a missing checksum
            // over content that decoded fine, the other is a stream that
            // never finished decoding at all.
            detects_corruption: false,
            memory_per_worker: Some(256 * 1024),
            ..CodecCaps::round_trip()
        }
    }

    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            DeflateDecoder::new(src),
            FLATE2_MALFORMED,
        ))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        match o.level {
            Some(n) if !(0..=9).contains(&n) => Err(Error::Usage(format!(
                "deflate compression level must be 0-9, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        let level = match o.level {
            Some(n) => Compression::new(n as u32),
            None => Compression::default(),
        };
        Ok(Box::new(DeflateSink(DeflateEncoder::new(dst, level))))
    }
}

struct DeflateSink(DeflateEncoder<Box<dyn Write + Send>>);

impl Write for DeflateSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for DeflateSink {
    fn finish(self: Box<Self>) -> Result<()> {
        let DeflateSink(encoder) = *self;
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

    fn encode_with(codec: &Deflate, plain: &[u8], opts: &EncodeOpts) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = codec.encoder(Box::new(buf.clone()), opts).unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Deflate.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = encode_with(&Deflate, &plain, &EncodeOpts::default());
        assert!(
            packed.len() < plain.len(),
            "deflate must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn deflate_conforms() {
        // Raw deflate has no magic at all, so conformance property 3 skips on
        // evidence — meta() registers an empty rule slice.
        stuffr_core::testing::assert_codec_conforms(&Deflate, &meta());
    }

    #[test]
    fn deflate_registers_no_magic_and_no_extension() {
        // Both are deliberate: a raw deflate stream is undetectable, which is
        // exactly why `--format` had to land first. If either grows a value,
        // detection would start guessing at streams it cannot identify.
        let m = meta();
        assert!(m.magics.is_empty(), "raw deflate has no magic to register");
        assert!(
            m.extensions.is_empty(),
            "raw deflate has no conventional extension"
        );
    }
}
