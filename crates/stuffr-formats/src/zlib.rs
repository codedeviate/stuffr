//! zlib (RFC 1950), via `flate2`'s pure-Rust backend.

use std::io::Write;

use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, FormatMeta, MagicRule, Result, Sink,
    Source, StreamOnly,
};

use crate::normalize::{MALFORMED_AS_INVALID_INPUT_EOF, NormalizeDecodeErrors};

pub const ZLIB: FormatId = FormatId::new("zlib");

/// The zlib header's second byte encodes the compression level, so one rule
/// cannot cover every stream. Measured through this CLI across all ten
/// levels against `flate2`'s own backend (not read off the RFC 1950 spec,
/// which does not pin exact byte values to levels) — 0x01 is level 0-1, 0x5e
/// is 2-3, 0x9c is 4-8 (which includes the default, 6), and 0xda is level 9
/// alone:
///
/// ```text
/// 0→7801  1→7801  2→785e  3→785e  4→789c  5→789c  6→789c  7→789c  8→789c  9→78da
/// ```
///
/// All four rules do cover every level and all ten levels are magic-detected
/// correctly either way; this is a correction to the comment, not to a live
/// defect. Conformance property 3 requires ANY registered rule to match, not
/// EVERY one, which is what makes registering all four work.
pub(crate) const ZLIB_MAGIC: &[MagicRule] = &[
    MagicRule {
        offset: 0,
        bytes: &[0x78, 0x01],
        format: ZLIB,
    },
    MagicRule {
        offset: 0,
        bytes: &[0x78, 0x5e],
        format: ZLIB,
    },
    MagicRule {
        offset: 0,
        bytes: &[0x78, 0x9c],
        format: ZLIB,
    },
    MagicRule {
        offset: 0,
        bytes: &[0x78, 0xda],
        format: ZLIB,
    },
];

/// `.zz`, deliberately not `.z`: lowercase `.z` is one case-fold from `.Z`,
/// which is LZW `compress(1)` — a Phase 3 legacy format. Colliding them would
/// be painful to undo once 0.1.0 pins the extension map.
pub fn meta() -> FormatMeta {
    FormatMeta::codec(ZLIB, &["zz"], ZLIB_MAGIC)
}

#[derive(Debug)]
pub struct Zlib;

impl Codec for Zlib {
    fn id(&self) -> FormatId {
        ZLIB
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // zlib's trailer carries an Adler-32 over the uncompressed data.
            detects_corruption: true,
            memory_per_worker: Some(256 * 1024),
            ..CodecCaps::round_trip()
        }
    }

    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            ZlibDecoder::new(src),
            MALFORMED_AS_INVALID_INPUT_EOF,
        ))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        match o.level {
            Some(n) if !(0..=9).contains(&n) => Err(Error::Usage(format!(
                "zlib compression level must be 0-9, got {n}"
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
        Ok(Box::new(ZlibSink(ZlibEncoder::new(dst, level))))
    }
}

struct ZlibSink(ZlibEncoder<Box<dyn Write + Send>>);

impl Write for ZlibSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for ZlibSink {
    fn finish(self: Box<Self>) -> Result<()> {
        let ZlibSink(encoder) = *self;
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

    fn encode_with(codec: &Zlib, plain: &[u8], opts: &EncodeOpts) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = codec.encoder(Box::new(buf.clone()), opts).unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Zlib.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = encode_with(&Zlib, &plain, &EncodeOpts::default());
        assert!(
            packed.len() < plain.len(),
            "zlib must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn zlib_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Zlib, &meta());
    }

    #[test]
    fn zlib_output_matches_one_of_its_registered_magics() {
        // The zlib header's second byte encodes the compression level, so no
        // single magic rule covers every stream. Registering all four is only
        // viable because conformance property 3 requires ANY rule to match,
        // not every one.
        //
        // Levels 0, 2, 6, 9 — not the earlier 0, 6, 9 — so every registered
        // rule in ZLIB_MAGIC is exercised by at least one case: 0x01 (levels
        // 0-1), 0x5e (levels 2-3), 0x9c (levels 4-8, the default among them),
        // and 0xda (level 9 alone) — see ZLIB_MAGIC's own doc comment for the
        // measurement. The old set of three skipped 0x5e entirely.
        for level in [0, 2, 6, 9] {
            let opts = EncodeOpts {
                level: Some(level),
                ..Default::default()
            };
            let packed = encode_with(&Zlib, b"conformance", &opts);
            assert!(
                ZLIB_MAGIC.iter().any(|r| packed.starts_with(r.bytes)),
                "level {level} produced {:02x?}, matching none of the registered magics",
                &packed[..2]
            );
        }
    }
}
