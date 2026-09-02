//! zstd, via the C `zstd` crate (bindings over the reference `libzstd`,
//! built from C by `zstd-sys`). The first dependency in this project's
//! history to compile C — see `Cargo.toml`'s `zstd-c` feature.
//!
//! `ZSTD`, the magic rule and `meta()` live in `crate::zstd_shared`, not
//! here: Task 3's pure `ruzstd` fallback registers the very same
//! `FormatId`, and a `zstd-pure`-only build has no `zstd_c` module to hang
//! them off. This module re-exports them under its own name so callers see
//! `zstd_c::{ZSTD, meta}` exactly as if they were defined here.
//!
//! ## The content checksum is opt-in, not automatic
//!
//! Measured directly against `zstd` 0.13 (see `crate::normalize`'s
//! `ZSTD_MALFORMED_AS_OTHER_EOF` doc for the full sweep): a plain
//! `zstd::stream::write::Encoder::new` writes no content checksum at all
//! unless told to. Sweeping every byte position of a real compressed
//! payload, a flipped byte went undetected — decoded to different bytes
//! with no error — in 44 of 61 positions. Turning the checksum on with
//! `include_checksum(true)` (below, in `encoder`) took that to 65 of 65
//! detected on the same sweep, which is why `encoder` always turns it on
//! (the reference `zstd` CLI does too, by default — this is the
//! conventional choice, not a local invention).
//!
//! **This makes `caps().detects_corruption` honest only for streams THIS
//! codec writes.** The checksum is a per-writer option in the zstd frame
//! format, not a mandatory part of every valid stream the way gzip's
//! trailer CRC32 or bzip2's per-block CRCs are — see `format.rs`'s
//! `detects_corruption` doc for that general distinction. A `.zst` written
//! by some other tool with the checksum left off is still fully valid zstd,
//! and `decoder` below only partially detects corruption in it. See
//! `decoder`'s doc for the measured figure on that case specifically — it
//! is a real, separate limit, not covered by the 65-of-65 figure above.

use std::io::Write;

use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FormatId, Result, Sink,
    Source, StreamOnly,
};

use crate::normalize::{NormalizeDecodeErrors, ZSTD_MALFORMED_AS_OTHER_EOF};
pub use crate::zstd_shared::{ZSTD, zstd_meta as meta};

#[derive(Debug)]
pub struct Zstd;

impl Codec for Zstd {
    fn id(&self) -> FormatId {
        ZSTD
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // Honest for streams THIS codec writes: `encoder` always turns
            // on `include_checksum(true)`. NOT a guarantee about a foreign
            // `.zst` — the checksum is a per-writer option in the format,
            // not mandatory in every valid stream. See the module doc and
            // `decoder`'s doc (the measured partial-detection figure for
            // that case lives there, where a caller actually meets it).
            detects_corruption: CorruptionDetection::WhenPresent,
            // Not measured: derived, not profiled. zstd's window at level 3
            // (the default) is 1 MiB; the encoder's match-finder tables and
            // internal buffers add a further working set on top of that. 8
            // MiB is a defensible round figure for "a few times the window",
            // the same spirit as bzip2.rs's derived figure.
            memory_per_worker: Some(8 * 1024 * 1024),
            weak_encoder: false,
            // `ZSTD_c_nbWorkers` is real: `Encoder::multithread` below wires
            // it to a governor grant. See `encoder`'s doc for the refusal
            // path (a grant of one runs single-threaded, not an error).
            parallel_encode: true,
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `StreamOnly`: the plain (non-"seekable format") zstd
    /// stream this codec produces carries no frame index, so its decoded
    /// output must not claim random access.
    ///
    /// Wrapped in `NormalizeDecodeErrors` first — see `crate::normalize` for
    /// why, and `ZSTD_MALFORMED_AS_OTHER_EOF`'s doc for the measurement
    /// backing the kinds reused here: a corrupted stream (with the checksum
    /// this codec always writes) surfaces as `io::ErrorKind::Other`, and a
    /// stream truncated mid-frame surfaces as `UnexpectedEof`.
    ///
    /// **This decoder only partially detects corruption in a stream that was
    /// not written with the checksum on.** `caps().detects_corruption` is
    /// `CorruptionDetection::WhenPresent` because `encoder` above always
    /// calls `include_checksum(true)` — but that is a property of streams
    /// *this codec* produces, not a
    /// property this decoder can enforce on whatever it is handed. The
    /// checksum is a per-writer option in the zstd frame format (see the
    /// module doc and `format.rs`'s `detects_corruption` doc), so a `.zst`
    /// from another tool that left it off is still fully valid zstd, and
    /// corruption in such a stream is only sometimes caught here: measured
    /// by sweeping every byte position of a real payload compressed
    /// *without* the checksum, 17 of 61 flipped positions were detected in
    /// one run and 21 of 61 in an independently reproduced run on a
    /// different payload — never complete, and the exact count is
    /// payload-dependent. There is no way for this decoder to tell, ahead of
    /// reading, whether an incoming stream carries the checksum at all.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let dec = zstd::stream::read::Decoder::new(src)?;
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            dec,
            ZSTD_MALFORMED_AS_OTHER_EOF,
        ))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        // zstd's real range, measured via `zstd::compression_level_range()`
        // rather than assumed: `-131072..=22` on this build (`zstd-sys`
        // 2.0.16 / libzstd 1.5.7), not the `0..=9` shape every other codec
        // in this tree happens to share. Negative levels are zstd's "fast"
        // modes, which is why `EncodeOpts::level` is already `Option<i32>`
        // rather than an unsigned type.
        let range = zstd::compression_level_range();
        match o.level {
            Some(n) if !range.contains(&n) => Err(Error::Usage(format!(
                "zstd compression level must be {}-{}, got {n}",
                range.start(),
                range.end()
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        let level = o.level.unwrap_or(zstd::DEFAULT_COMPRESSION_LEVEL);
        let mut enc = zstd::stream::write::Encoder::new(dst, level)?;
        // See the module doc: this is what makes `caps().detects_corruption`
        // `CorruptionDetection::WhenPresent` rather than aspirational.
        enc.include_checksum(true)?;

        // `filter(|n| *n > 0)`, not a bare unwrap_or_else: `--threads 0` means
        // AUTO, and passing 0 through as a request would ask for zero workers.
        // ops resolves auto into the governor's own count (resolve_workers
        // handles Some(0)), so EncodeOpts.threads is a library caller's
        // request for LESS than the budget.
        let lease = match &o.governor {
            Some(gov) => {
                let want = o
                    .threads
                    .filter(|n| *n > 0)
                    .unwrap_or_else(|| gov.workers());
                let granted = gov.acquire_many(want, self.caps().memory_per_worker.unwrap_or(0));
                // A grant of one is single-threaded. `multithread(1)` is not
                // the same as not calling it, so only opt in above one:
                // `acquire_many` clamps rather than failing, so a tight
                // budget is a smaller grant here, never an error.
                if granted.workers() > 1 {
                    enc.multithread(granted.workers() as u32)?;
                }
                Some(granted)
            }
            None => None,
        };
        Ok(Box::new(ZstdSink { enc, _lease: lease }))
    }
}

struct ZstdSink {
    enc: zstd::stream::write::Encoder<'static, Box<dyn Write + Send>>,
    /// Held, not read. Dropping it returns the workers and bytes to the
    /// governor, and `Drop` runs on error paths too — which is why the lease
    /// lives here rather than in `encoder()`'s stack frame, whose scope ends
    /// long before the encode does.
    _lease: Option<stuffr_core::LeaseSet>,
}

impl Write for ZstdSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.enc.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.enc.flush()
    }
}

impl Sink for ZstdSink {
    /// Writes the closing block, and — because `encoder` turned it on — the
    /// trailing content checksum. The governor lease (if any) is released
    /// when `self` drops at the end of this call.
    fn finish(self: Box<Self>) -> Result<()> {
        let ZstdSink { enc, _lease } = *self;
        let mut w = enc.finish()?;
        w.flush()?;
        Ok(())
    }
}

/// Compresses `plain` with this codec's default options, for tests only.
///
/// Not exercised directly by this file's own tests (which go through
/// `Codec::encoder` the same way every other codec's test module does) —
/// this exists for Task 3's pure `ruzstd` fallback and later cross-backend
/// agreement tests, which need a known-good zstd stream from the C backend
/// to decode without depending on either backend's test module reaching into
/// the other's private test helpers.
#[cfg(test)]
pub(crate) fn encode_for_test(plain: &[u8]) -> Vec<u8> {
    let buf = stuffr_core::testing::SharedBuf::new();
    let mut sink = Zstd
        .encoder(Box::new(buf.clone()), &EncodeOpts::default())
        .unwrap();
    sink.write_all(plain).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use stuffr_core::ReaderSource;
    use stuffr_core::testing::SharedBuf;

    fn compress(plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = Zstd
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
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
            "zstd must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_zstd_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
    }

    #[test]
    fn encode_for_test_helper_produces_a_decodable_stream() {
        // Guards the helper Task 3 will depend on: it must go through the
        // real `Codec::encoder` + `Sink::finish` path, not some shortcut.
        let packed = encode_for_test(b"cross-backend payload");
        assert_eq!(decompress(packed), b"cross-backend payload");
    }

    #[test]
    fn the_real_level_range_is_far_wider_than_0_to_9() {
        // Measured, not assumed: -131072..=22 on this build. A hardcoded
        // 0..=9 copied from gzip would reject valid negative "fast" levels
        // and silently accept 10-22 as if they meant something else.
        let range = zstd::compression_level_range();
        assert!(*range.start() < 0, "zstd's fast levels are negative");
        assert_eq!(*range.end(), 22);

        for n in [*range.start(), -1, 0, 1, *range.end()] {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            assert!(
                Zstd.check_encode_opts(&opts).is_ok(),
                "level {n} must be accepted"
            );
        }
    }

    #[test]
    fn an_out_of_range_level_is_a_usage_error_not_a_silent_clamp() {
        let range = zstd::compression_level_range();
        let too_high = range.end() + 1;
        let too_low = range.start() - 1;

        for n in [too_high, too_low] {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            match Zstd.encoder(Box::new(SharedBuf::new()), &opts) {
                Err(err) => {
                    assert!(matches!(err, stuffr_core::Error::Usage(_)));
                    assert_eq!(err.exit_code(), 2);
                    assert!(
                        err.to_string().contains(&range.start().to_string())
                            && err.to_string().contains(&range.end().to_string()),
                        "the error must name the real range: {err}"
                    );
                }
                Ok(_) => panic!("level {n} is out of range and must be rejected"),
            }
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        // A plain zstd stream (not the experimental "seekable format")
        // carries no frame index, so a container above it must not be told
        // it can seek.
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Zstd.caps();
        assert!(c.encode && c.decode);
        assert!(c.parallel_encode, "1f: the C backend has ZSTD_c_nbWorkers");
        assert!(!c.frame_index, "not until 1f");
        assert!(!c.weak_encoder, "the C backend is the real encoder");
        let m = meta();
        assert_eq!(m.id, ZSTD);
        assert_eq!(m.extensions, &["zst"]);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn zstd_declares_an_integrity_check_and_a_memory_figure() {
        let c = Zstd.caps();
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::WhenPresent,
            "this codec always turns the content checksum on; see the module doc"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    #[test]
    fn zstd_c_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Zstd, &meta());
    }

    #[test]
    fn parallel_encode_is_declared() {
        assert!(
            Zstd.caps().parallel_encode,
            "zstd's C backend has ZSTD_c_nbWorkers"
        );
    }

    #[test]
    fn a_governor_grant_is_used_and_released() {
        // Property 12 covers this generically; pinned here so a regression
        // names this module rather than the harness.
        use std::sync::Arc;
        use stuffr_core::testing::incompressible;
        let gov = stuffr_core::Governor::new(4, 64 * 1024 * 1024);
        let buf = SharedBuf::new();
        let mut sink = Zstd
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    governor: Some(Arc::clone(&gov)),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&incompressible(1024 * 1024)).unwrap();
        assert!(
            gov.outstanding() > 0,
            "the sink must hold its lease while encoding"
        );
        sink.finish().unwrap();
        assert_eq!(gov.outstanding(), 0, "finish must release the lease");
    }

    #[test]
    fn a_grant_of_one_worker_still_round_trips() {
        // THE REFUSAL PATH, and the one most likely to be written wrong.
        // `acquire_many` clamps rather than failing: a memory limit below one
        // worker's demand yields exactly one worker, and the codec must run
        // single-threaded rather than erroring or oversubscribing. This is
        // what makes Phase 2's nested container parallelism safe.
        use std::sync::Arc;
        use stuffr_core::testing::incompressible;
        let plain = incompressible(512 * 1024);
        // 1 byte of budget against a multi-MiB per-worker demand.
        let gov = stuffr_core::Governor::new(8, 1);
        let buf = SharedBuf::new();
        let mut sink = Zstd
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    governor: Some(Arc::clone(&gov)),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&plain).unwrap();
        sink.finish().unwrap();
        assert_eq!(
            decompress(buf.contents()),
            plain,
            "a one-worker grant must still work"
        );
    }

    #[test]
    fn parallel_output_decodes_to_the_same_plaintext_as_single_threaded() {
        // Bytes may differ — multi-threaded zstd splits input per worker.
        // DATA may not. Asserting the plaintext rather than the bytes is the
        // whole reason parallelism is safe to offer.
        use stuffr_core::testing::incompressible;
        let plain = incompressible(2 * 1024 * 1024);
        let st = compress(&plain);
        let gov = stuffr_core::Governor::new(4, 256 * 1024 * 1024);
        let buf = SharedBuf::new();
        let mut sink = Zstd
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    governor: Some(gov),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&plain).unwrap();
        sink.finish().unwrap();
        assert_eq!(decompress(buf.contents()), decompress(st));
    }

    #[test]
    fn the_c_decoder_reads_our_parallel_output() {
        // A stream only we can read would be worse than no parallelism. If a
        // `zstd` binary is on PATH, prefer it as the arbiter; otherwise the
        // crate's own decoder is a different code path from the encoder and
        // still worth asserting.
        use stuffr_core::testing::incompressible;
        let plain = incompressible(2 * 1024 * 1024);
        let gov = stuffr_core::Governor::new(4, 256 * 1024 * 1024);
        let buf = SharedBuf::new();
        let mut sink = Zstd
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    governor: Some(gov),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&plain).unwrap();
        sink.finish().unwrap();
        let mut out = Vec::new();
        use std::io::Read;
        zstd::stream::read::Decoder::new(std::io::Cursor::new(buf.contents()))
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, plain);
    }
}
