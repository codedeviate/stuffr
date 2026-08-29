//! gzip, via `flate2`'s pure-Rust backend.

use std::io::{Read, Write};

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
        CodecCaps {
            // gzip's trailer carries a CRC32 over the uncompressed data, so a
            // flipped byte anywhere in the stream is detected rather than
            // silently decoded into different bytes.
            detects_corruption: true,
            // deflate's window is 32 KiB; miniz_oxide's encoder state plus our
            // 64 KiB copy buffer puts one worker comfortably under 256 KiB.
            memory_per_worker: Some(256 * 1024),
            ..CodecCaps::round_trip()
        }
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
    ///
    /// `MultiGzDecoder` is wrapped again in `NormalizeDecodeErrors` first: see
    /// that type for why.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors(
            MultiGzDecoder::new(src),
        ))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        // A `match` with a guard, not a let-chain: MSRV is 1.85 and let-chains
        // are stable only from 1.88. This is the idiom the tree already uses.
        match o.level {
            Some(n) if !(0..=9).contains(&n) => Err(Error::Usage(format!(
                "gzip compression level must be 0-9, got {n}"
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
        Ok(Box::new(GzSink(GzEncoder::new(dst, level))))
    }
}

/// Maps flate2's error-kind vocabulary onto this project's decode-corruption
/// convention.
///
/// `stuffr_core::Error::from_decode_io` classifies `io::ErrorKind::InvalidData`
/// as `Error::Corrupt` (exit 5) and leaves everything else as `Error::Io`
/// (exit code 1) — that is the one rule, and it stays one rule only if every
/// codec's decoder actually speaks `InvalidData` for malformed input.
///
/// The pure-Rust backend of the `flate2` crate does not: measured directly
/// against its source (`zio.rs`, `gz/mod.rs`), every decode-time failure —
/// malformed deflate data, an invalid gzip header, a trailer CRC mismatch —
/// is raised as `InvalidInput`, and a stream that runs out mid-member
/// surfaces as `UnexpectedEof`. Both are folded into `InvalidData` here: a
/// truncated archive is no better formed than a corrupted one, and "archive
/// is corrupt" is more useful to a caller than "i/o error". Every other kind
/// — a genuine failure reading the underlying source — passes through
/// untouched, so a real disk error stays `Error::Io`, not `Error::Corrupt`.
struct NormalizeDecodeErrors<R>(R);

impl<R: Read> Read for NormalizeDecodeErrors<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::UnexpectedEof => {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            }
            _ => e,
        })
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
        // `GzEncoder::finish` hands the wrapped writer back; the caller gave
        // it to us by value at `Codec::encoder` and has no other handle left
        // to flush it, so that is done here — see the contract on `Sink`.
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
    fn finish_flushes_the_underlying_writer() {
        // `Codec::encoder` takes the destination by value, so once `finish`
        // consumes the sink, nothing outside it holds a handle to flush the
        // writer — `finish` is the only place left that can. This matters for
        // buffered destinations (stdout's LineWriter, notably), which may
        // hold trailer bytes unflushed indefinitely otherwise.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct FlushSpy {
            buf: Vec<u8>,
            flushed: Arc<AtomicBool>,
        }

        impl Write for FlushSpy {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.buf.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.flushed.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let flushed = Arc::new(AtomicBool::new(false));
        let mut sink = Gzip
            .encoder(
                Box::new(FlushSpy {
                    buf: Vec::new(),
                    flushed: Arc::clone(&flushed),
                }),
                &EncodeOpts::default(),
            )
            .unwrap();

        sink.write_all(b"payload").unwrap();
        sink.finish().unwrap();

        assert!(
            flushed.load(Ordering::SeqCst),
            "Sink::finish must flush the underlying writer before returning"
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

    #[test]
    fn gzip_declares_an_integrity_check_and_a_memory_figure() {
        let c = Gzip.caps();
        assert!(
            c.detects_corruption,
            "gzip carries a CRC32, so corrupt input is detectable and Error::Corrupt is reachable"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    #[test]
    fn gzip_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Gzip, &meta());
    }

    #[test]
    fn decoding_is_incremental_not_read_to_end() {
        // Deferred here from Phase 1a: no mock ever streamed, so nothing had
        // shown that a forward-only read is incremental rather than
        // read-everything-then-parse. Peak heap is not observable from a unit
        // test, so the measurable property is that output begins long before
        // the input is exhausted.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        struct Metered {
            inner: std::io::Cursor<Vec<u8>>,
            served: Arc<AtomicU64>,
        }
        impl Read for Metered {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.inner.read(buf)?;
                self.served.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            }
        }
        impl Source for Metered {
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

        // 16 MiB of pseudo-random data from a small LCG, not the periodic
        // `(i % 251)` pattern the brief originally specified: that pattern
        // compresses to ~65,411 bytes (below the 64 KiB assertion below) and
        // makes the whole stream small enough that a read-to-end decoder
        // would still pass the `consumed` assertion. An LCG is deterministic
        // (no `rand` dependency) but its output is incompressible, so both
        // assertions below are load-bearing rather than decorative.
        let mut s: u32 = 1;
        let plain: Vec<u8> = (0..16 * 1024 * 1024u32)
            .map(|_| {
                s = s.wrapping_mul(1103515245).wrapping_add(12345);
                (s >> 16) as u8
            })
            .collect();
        let packed = compress(&plain);
        assert!(
            packed.len() > 64 * 1024,
            "the compressed stream must exceed one read buffer"
        );

        let served = Arc::new(AtomicU64::new(0));
        let src: Box<dyn Source> = Box::new(Metered {
            inner: std::io::Cursor::new(packed),
            served: Arc::clone(&served),
        });

        let mut dec = Gzip.decoder(src, &DecodeOpts::default()).unwrap();
        let mut first = [0u8; 1024];
        let n = dec.read(&mut first).unwrap();
        assert!(n > 0, "the decoder must produce output");

        let consumed = served.load(Ordering::Relaxed);
        assert!(
            consumed < 1024 * 1024,
            "first output arrived only after reading {consumed} bytes; a read-to-end \
             implementation would consume the whole stream before emitting anything"
        );
    }
}
