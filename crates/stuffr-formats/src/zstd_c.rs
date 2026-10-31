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
            // Task 7 measurement (release build, `/usr/bin/time -l`, a
            // streamed tiled-repetitive payload, 1/2/4/8 workers): level 22
            // (the highest this build accepts) derives a per-worker delta of
            // ~897 MiB — see `per_worker_bytes`'s doc for the full table and
            // the plateau this figure had to correct for. THIS FIELD is the
            // STATIC, conservative figure for the highest level, rounded up
            // to 1 GiB for headroom — a static advertisement for callers
            // that introspect `caps()` without ever calling `encoder`.
            // `encoder` below calls `per_worker_bytes(level)` instead, which
            // is level-aware and uses a much smaller figure (16 MiB) at the
            // default level 3: declaring the highest-level figure here would
            // needlessly limit a default-level encode to a fraction of the
            // workers it can safely use.
            memory_per_worker: Some(1024 * 1024 * 1024),
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
    ///
    /// **`DecodeOpts::memory_limit` bounds the window** (the 2026-10-31
    /// audit, T13): see [`window_log_max`] and [`WindowLimit`]. Under a
    /// limit, a frame declaring a larger window is refused before libzstd
    /// allocates it, as `Error::ResourceLimit` (exit 6). Without a limit the
    /// cap stays libzstd's own default (`ZSTD_WINDOWLOG_LIMIT_DEFAULT`, 27:
    /// 128 MiB), exactly as before.
    fn decoder<'a>(
        &self,
        src: Box<dyn Source + 'a>,
        o: &DecodeOpts,
    ) -> Result<Box<dyn Source + 'a>> {
        let mut dec = zstd::stream::read::Decoder::new(src)?;
        let cap = o.memory_limit.map(|limit| (window_log_max(limit), limit));
        if let Some((log, _)) = cap {
            dec.window_log_max(log)?;
        }
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            WindowLimit { inner: dec, cap },
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
                let granted = gov.acquire_many(want, per_worker_bytes(level));
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

/// The `ZSTD_d_windowLogMax` a `memory_limit` allows: the largest `log`
/// with `2^log <= limit`, clamped to what libzstd accepts for the parameter
/// (`ZSTD_WINDOWLOG_ABSOLUTEMIN` 10 up to `ZSTD_WINDOWLOG_MAX`, 31 on a
/// 64-bit target and 30 on a 32-bit one). A limit below 1 KiB still sets
/// 10: every frame declaring more than 1 KiB is then refused.
///
/// libzstd refuses a frame whose window exceeds `2^windowLogMax`, so the
/// bound has power-of-two granularity: under a limit of 100 MiB the cap is
/// 64 MiB, and a frame declaring 96 MiB is refused although it is under the
/// limit (the pure tier, which judges the declaration itself, accepts it).
/// The error is on the safe side; raising the limit to the next power of two
/// lets such a file through.
///
/// A limit above libzstd's own default of 128 MiB RAISES the cap, up to
/// 2 GiB: a `--long=31` file decodes under a large enough limit, as it does
/// with `zstd -d --memory=2048MB`. The CLI's default limit (a quarter of the
/// available memory) therefore admits windows the old fixed 128 MiB cap
/// refused; the cost is the declared window, which the limit allows.
fn window_log_max(limit: u64) -> u32 {
    use crate::zstd_opts::{WINDOWLOG_ABSOLUTEMIN, WINDOWLOG_MAX};
    let floor_log2 = 63 - limit.max(1).leading_zeros();
    floor_log2.clamp(WINDOWLOG_ABSOLUTEMIN, WINDOWLOG_MAX)
}

/// The decoder, with libzstd's `frameParameter_windowTooLarge` turned into a
/// resource refusal. The `zstd` crate reports every libzstd error as
/// `io::ErrorKind::Other` carrying `ZSTD_getErrorName`'s text, which
/// `ZSTD_MALFORMED_AS_OTHER_EOF` folds onto "corrupt" (exit 5); a window
/// over `ZSTD_d_windowLogMax` is not damage, so it is re-kinded here as
/// `OutOfMemory`, which `Error::from_decode_io` classifies as
/// `Error::ResourceLimit` (exit 6) — the shape `xz_pure.rs` and
/// `zstd_pure.rs` use.
///
/// The error is recognised by its text, compared with libzstd's own name for
/// the code at run time (the same library produced both), so no message is
/// hard-coded here. libzstd does not say how large the declared window was,
/// so the message names the cap and the limit, not the declaration.
struct WindowLimit<R> {
    inner: R,
    /// `(windowLogMax, memory_limit)` when a limit was set.
    cap: Option<(u32, u64)>,
}

impl<R: std::io::Read> std::io::Read for WindowLimit<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf).map_err(|e| match self.cap {
            Some((log, limit)) if is_window_too_large(&e) => window_refusal(log, limit),
            _ => e,
        })
    }
}

/// Whether `e` is the `zstd` crate's rendering of libzstd's
/// `ZSTD_error_frameParameter_windowTooLarge`.
fn is_window_too_large(e: &std::io::Error) -> bool {
    use zstd::zstd_safe::zstd_sys::ZSTD_ErrorCode;
    let code = ZSTD_ErrorCode::ZSTD_error_frameParameter_windowTooLarge as usize;
    // libzstd's `ERROR(x)` is `(size_t)-ZSTD_error_x`.
    let name = zstd::zstd_safe::get_error_name(0usize.wrapping_sub(code));
    e.kind() == std::io::ErrorKind::Other && e.to_string() == name
}

/// The resource refusal for a window over `2^log`, the cap `limit` set.
fn window_refusal(log: u32, limit: u64) -> std::io::Error {
    use stuffr_core::format_size;
    let cap = 1u64 << log;
    let text = if cap < limit && log == crate::zstd_opts::WINDOWLOG_MAX {
        // The limit is not what refused it: libzstd decodes no larger window
        // on this platform.
        format!(
            "zstd: frame header declares a window larger than {}, the most libzstd \
             decodes on this platform",
            format_size(cap)
        )
    } else if cap < limit {
        // A limit between two powers of two: name the cap it rounds down to.
        format!(
            "zstd: frame header declares a window larger than {}, the largest power \
             of two within --memory-limit {} — raise --memory-limit to decode this file",
            format_size(cap),
            format_size(limit)
        )
    } else {
        format!(
            "zstd: frame header declares a window larger than {}, but --memory-limit \
             allows only {} — raise --memory-limit to decode this file",
            format_size(cap),
            format_size(limit)
        )
    };
    std::io::Error::new(std::io::ErrorKind::OutOfMemory, text)
}

/// This codec's per-worker demand for `acquire_many` — level-aware, unlike
/// `caps().memory_per_worker`, which is a static, conservative figure for
/// callers that introspect `caps()` without ever calling `encoder`. `o.level`
/// is available right here, which `caps()` cannot see.
///
/// Measured directly (release build, `/usr/bin/time -l` on macOS, a
/// streamed, tiled-repetitive payload — content does not change the
/// encoder's window/match-finder memory, only its speed, which is why a
/// large payload is affordable to measure at all), at 1, 2, 4 and 8 workers,
/// deriving the per-worker delta as `(rss_at_n - rss_at_1) / (n - 1)`:
///
/// | level | payload | 1w | 2w | 4w | 8w |
/// |---|---|---|---|---|---|
/// | 3 (default) | 256 MiB | 5.3 MB | 46.1 MB | 64.8 MB | 102.2 MB |
/// | 22 ("ultra", highest accepted) | 1536 MiB | 875.9 MB | 3025.4 MB | 3697.7 MB | 3697.8 MB |
///
/// Level 3's `(rss_8 - rss_1) / 7` derives to 13.2 MiB, declared as 16 MiB.
///
/// **Level 22's RSS PLATEAUS between 4 and 8 workers** — 3697.7 MB and
/// 3697.8 MB, functionally identical. This build's zstd did not run 8 real
/// concurrent jobs for this payload/level, so `(rss_8 - rss_1) / 7` (only
/// 384.5 MiB) silently folds four idle "workers" into the denominator and
/// UNDER-counts the true marginal cost. The pre-plateau `(rss_4 - rss_1) / 3`
/// derives to 897.0 MiB and is what this function returns for the ultra
/// tier, rounded up to 1 GiB for headroom — trust the measurement that
/// contradicts the naive "divide by however many workers were asked for"
/// arithmetic, per the brief.
///
/// Two tiers, not a continuous formula: zstd's levels 20-22 are its "ultra"
/// tier (the reference CLI gates them behind `--ultra` for the same
/// reason — a materially larger window than every level below), and only
/// two points were measured, so a step at that boundary is honest where an
/// unverified interpolation across the other 25 levels would not be.
fn per_worker_bytes(level: i32) -> u64 {
    if level >= 20 {
        1024 * 1024 * 1024 // 1 GiB: headroom over the measured ~897 MiB.
    } else {
        16 * 1024 * 1024 // 16 MiB: headroom over the measured ~13.2 MiB.
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

    fn skippable(magic: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = magic.to_le_bytes().to_vec();
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// RUSTSEC-2026-0403: a 5 or 6 byte frame starting with a legacy magic
    /// (v0.4 to v0.7) then garbage must be an error and expose no output
    /// through the codec decoder (`zstd::stream::read::Decoder`).
    #[test]
    fn a_corrupt_legacy_frame_exposes_no_output() {
        for magic in 0xFD2F_B524u32..=0xFD2F_B527 {
            for tail in [&[0xFFu8][..], &[0xFF, 0x00], &[0x00, 0x00]] {
                let mut bytes = magic.to_le_bytes().to_vec();
                bytes.extend_from_slice(tail);
                let src: Box<dyn Source> =
                    Box::new(ReaderSource::new(std::io::Cursor::new(bytes.clone())));
                let mut dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
                let mut out = Vec::new();
                let r = dec.read_to_end(&mut out);
                assert!(r.is_err(), "{magic:#x} {tail:?}: decoded without error");
                assert!(out.is_empty(), "{magic:#x} {tail:?}: leaked {out:?}");
            }
        }
    }

    /// RUSTSEC-2026-0391: the codec makes one decoder per stream
    /// (`Decoder::new` above, never `with_context`), so an abandoned
    /// stream cannot reach the next; pinned by decoding a cut stream and
    /// then a whole one.
    #[test]
    fn an_abandoned_stream_leaves_nothing_in_the_next() {
        let first = b"first stream, line after line. ".repeat(5000);
        let second = b"second stream is different. ".repeat(3000);
        let a = compress(&first);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(
            a[..a.len() / 2].to_vec(),
        )));
        let mut dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
        let mut part = vec![0u8; 1000];
        let _ = dec.read(&mut part);
        drop(dec);
        assert_eq!(decompress(compress(&second)), second);
    }

    #[test]
    fn zstd_c_skips_a_trailing_skippable_frame() {
        let plain = b"blender-like text, line after line of it. ".repeat(2500);
        let mut bytes = compress(&plain);
        bytes.extend(skippable(0x184D_2A5E, &[7; 33]));
        assert_eq!(decompress(bytes), plain);
    }

    #[test]
    fn zstd_c_only_skippable_frames_decode_to_nothing() {
        let mut bytes = skippable(0x184D_2A5E, &[7; 33]);
        bytes.extend(skippable(0x184D_2A50, &[]));
        assert_eq!(decompress(bytes), b"");
    }

    #[test]
    fn zstd_c_skips_skippable_frames_before_between_and_after() {
        let (a, b) = (b"first frame ".repeat(500), b"second frame".repeat(50));
        let mut bytes = skippable(0x184D_2A50, &[1; 5]);
        bytes.extend(compress(&a));
        bytes.extend(skippable(0x184D_2A5F, &[]));
        bytes.extend(compress(&b));
        bytes.extend(skippable(0x184D_2A5E, &[7; 33]));
        let mut want = a;
        want.extend(b);
        assert_eq!(decompress(bytes), want);
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
    fn a_tight_memory_limit_clamps_the_worker_count() {
        // The declared figure is what the governor divides by, so a limit of
        // three workers' worth must yield at most three however many CPUs
        // the budget allows. Reads memory_per_worker rather than repeating
        // it: a test with its own copy of the constant stops tracking it.
        let per = Zstd
            .caps()
            .memory_per_worker
            .expect("a parallel codec must declare one");
        let gov = stuffr_core::Governor::new(16, per * 3);
        assert!(
            gov.workers_for(per) <= 3,
            "16 CPU workers but only three workers' worth of memory: got {}",
            gov.workers_for(per)
        );
    }

    #[test]
    fn per_worker_bytes_is_level_aware() {
        // Guards against `per_worker_bytes` silently regressing to a
        // constant: the highest accepted level must demand more memory per
        // worker than the default, matching Task 7's measurement (~897 MiB
        // derived at level 22 against ~13.2 MiB at level 3).
        let highest = *zstd::compression_level_range().end();
        assert!(
            per_worker_bytes(highest) > per_worker_bytes(zstd::DEFAULT_COMPRESSION_LEVEL),
            "the highest accepted level must demand more memory per worker than the default"
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

        // AND the bytes must match a no-governor encode exactly.
        //
        // This is what makes the `granted.workers() > 1` guard testable at all.
        // A review mutation-tested that guard by deleting it and found every
        // test still passed, because a one-worker grant round-trips whether or
        // not `multithread(1)` is called. Measured, the call IS observable —
        // but only in a narrow window:
        //
        //   payload        none      mt(1)     mt(4)
        //   2 MiB       2097213    2097210   2097210   <- differs
        //   8/32/64 MiB identical  identical identical <- does not
        //
        // So a 2 MiB incompressible payload is the size at which "did we call
        // multithread?" is visible in the output. Above ~8 MiB the worker count
        // stops changing the bytes entirely, which is also why no byte
        // comparison anywhere in this module can prove that parallel work
        // actually happened.
        assert_eq!(
            decompress(buf.contents()),
            plain,
            "a one-worker grant must still work"
        );
        assert_eq!(
            buf.contents(),
            compress(&plain),
            "a one-worker grant must produce byte-identical output to a \
             single-threaded encode. If this differs by a few bytes, the \
             `granted.workers() > 1` guard has been removed and multithread(1) \
             is being called for a grant with nothing to parallelise."
        );
    }

    #[test]
    fn a_payload_large_enough_to_split_round_trips_under_four_workers() {
        // Every other parallel test here uses 512 KiB to 2 MiB, and a review
        // measured that at those sizes multi-threaded zstd is no faster — it is
        // sometimes SLOWER (2 MiB: 968us multi-threaded against 760us single).
        // Real speedup starts around 32 MiB (512 MiB: 253ms against 442ms).
        // So those tests prove the lease and governor wiring, not parallel
        // compute, and this one covers a size where the work is genuinely split.
        //
        // It asserts CORRECTNESS only, deliberately. Two things it cannot do:
        // assert timing, because the measurements above are noisy enough to
        // flake in CI; and assert bytes, because above roughly 8 MiB the output
        // is byte-identical regardless of worker count (measured: 8, 32 and 64
        // MiB all produce the same bytes at 1 and 4 workers). What it does prove
        // is that a stream produced by genuinely parallel encoding decodes back
        // to exactly the input, which is the property a user depends on.
        use std::sync::Arc;
        use stuffr_core::testing::incompressible;
        let plain = incompressible(16 * 1024 * 1024);
        let gov = stuffr_core::Governor::new(4, 512 * 1024 * 1024);
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
        assert_eq!(
            gov.outstanding(),
            4,
            "four workers must be held while encoding"
        );
        sink.finish().unwrap();
        assert_eq!(gov.outstanding(), 0, "finish must release all four");
        assert_eq!(decompress(buf.contents()), plain);
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
        // A stream only we can read would be worse than no parallelism.
        //
        // The arbiter here is the crate's own `stream::read::Decoder`, which is
        // a genuinely different code path from the encoder — not the `zstd`
        // binary. An earlier version of this comment claimed to prefer the
        // binary when one is on PATH; it never checked, and describing a check
        // that does not exist is worse than admitting there is none. If
        // binary-level arbitration is wanted, add it and say so.
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

#[cfg(test)]
mod window_tests {
    use super::*;
    use std::io::Read;
    use stuffr_core::ReaderSource;

    const MIB: u64 = 1024 * 1024;

    /// Window_Descriptor bytes (RFC 8878 §3.1.1.1.2: window =
    /// 2^(10+e) · (1 + m/8), e the top five bits, m the low three).
    const WD_1_MIB: u8 = 10 << 3;
    const WD_96_MIB: u8 = (16 << 3) | 4;
    const WD_144_MIB: u8 = (17 << 3) | 1;
    /// 2^(10+22) = 4 GiB: above `ZSTD_WINDOWLOG_MAX` on every platform.
    const WD_4_GIB: u8 = 22 << 3;

    /// One frame of `payload` from this codec's encoder, its
    /// Window_Descriptor rewritten. The streaming encoder pledges no size, so
    /// the header is never single-segment and always carries the
    /// descriptor at byte 5; declaring a larger window than the encoder used
    /// leaves a valid frame.
    fn frame_declaring(window_descriptor: u8, payload: &[u8]) -> Vec<u8> {
        let buf = stuffr_core::testing::SharedBuf::new();
        let mut sink = Zstd
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(payload).unwrap();
        sink.finish().unwrap();
        let mut frame = buf.contents();
        assert_eq!(
            frame[4] & 0x20,
            0,
            "the encoder wrote a single-segment header"
        );
        frame[5] = window_descriptor;
        frame
    }

    fn decode(bytes: Vec<u8>, memory_limit: Option<u64>) -> std::result::Result<Vec<u8>, Error> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Zstd
            .decoder(
                src,
                &DecodeOpts {
                    memory_limit,
                    ..Default::default()
                },
            )
            .unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).map_err(Error::from_decode_io)?;
        Ok(out)
    }

    fn payload() -> Vec<u8> {
        b"window bound payload ".repeat(40)
    }

    #[test]
    fn the_window_log_is_the_largest_power_of_two_within_the_limit() {
        use crate::zstd_opts::WINDOWLOG_MAX;
        assert_eq!(window_log_max(0), 10);
        assert_eq!(window_log_max(512), 10);
        assert_eq!(window_log_max(1024), 10);
        assert_eq!(window_log_max(2047), 10);
        assert_eq!(window_log_max(MIB), 20);
        assert_eq!(window_log_max(100 * MIB), 26);
        assert_eq!(window_log_max(128 * MIB), 27);
        assert_eq!(window_log_max(256 * MIB), 28);
        assert_eq!(window_log_max(1 << 40), WINDOWLOG_MAX);
        assert_eq!(window_log_max(u64::MAX), WINDOWLOG_MAX);
    }

    #[test]
    fn a_window_over_the_memory_limit_is_a_resource_limit() {
        let err = decode(frame_declaring(WD_96_MIB, &payload()), Some(MIB)).unwrap_err();
        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "a window over --memory-limit is exit 6, not {err:?}"
        );
        assert_eq!(err.exit_code(), 6);
        let text = err.to_string();
        assert!(
            text.contains("--memory-limit") && text.contains("1 MiB"),
            "the refusal names the limit: {text}"
        );
    }

    #[test]
    fn a_window_under_the_memory_limit_decodes() {
        let got = decode(frame_declaring(WD_96_MIB, &payload()), Some(256 * MIB)).unwrap();
        assert_eq!(got, payload());
        // Exactly at the limit is allowed: libzstd refuses only "exceeds".
        let got = decode(frame_declaring(WD_1_MIB, &payload()), Some(MIB)).unwrap();
        assert_eq!(got, payload());
        // No limit: libzstd's own 128 MiB default, as before.
        let got = decode(frame_declaring(WD_96_MIB, &payload()), None).unwrap();
        assert_eq!(got, payload());
    }

    #[test]
    fn a_large_limit_raises_the_cap_above_libzstds_default() {
        // 144 MiB is over libzstd's default `windowLogMax` (27): refused
        // without a limit (as before, by libzstd), decoded under 256 MiB.
        assert!(decode(frame_declaring(WD_144_MIB, &payload()), None).is_err());
        let got = decode(frame_declaring(WD_144_MIB, &payload()), Some(256 * MIB)).unwrap();
        assert_eq!(got, payload());
    }

    #[test]
    fn a_limit_between_powers_of_two_rounds_down_and_says_so() {
        // 100 MiB rounds down to a 64 MiB cap, so 96 MiB is refused (the
        // pure tier, which judges the declaration, would accept it).
        let err = decode(frame_declaring(WD_96_MIB, &payload()), Some(100 * MIB)).unwrap_err();
        assert!(matches!(err, Error::ResourceLimit(_)), "{err:?}");
        let text = err.to_string();
        assert!(
            text.contains("64 MiB") && text.contains("100 MiB") && text.contains("power of two"),
            "{text}"
        );
    }

    #[test]
    fn a_later_frame_declaring_a_larger_window_is_refused() {
        let mut two = frame_declaring(WD_1_MIB, &payload());
        two.extend_from_slice(&frame_declaring(WD_96_MIB, &payload()));
        let mut both = payload();
        both.extend_from_slice(&payload());
        assert_eq!(decode(two.clone(), None).unwrap(), both);

        let err = decode(two, Some(8 * MIB)).unwrap_err();
        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "the second frame's window is bounded too, got {err:?}"
        );
    }

    #[test]
    fn a_window_above_libzstds_maximum_names_libzstd_not_the_limit() {
        let err = decode(frame_declaring(WD_4_GIB, &payload()), Some(1 << 40)).unwrap_err();
        assert!(matches!(err, Error::ResourceLimit(_)), "{err:?}");
        let text = err.to_string();
        assert!(
            text.contains("libzstd") && !text.contains("--memory-limit"),
            "{text}"
        );
    }

    #[test]
    fn corruption_is_still_corrupt_under_a_limit() {
        // The re-kinding is for the window error only.
        let mut frame = frame_declaring(WD_1_MIB, &payload());
        let n = frame.len();
        frame[n - 2] ^= 0xff; // the content checksum
        let err = decode(frame, Some(MIB)).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err:?}");
    }
}

#[cfg(test)]
mod confirm_tests {
    use super::*;
    use crate::confirm_test::{assert_every_cut_confirms, encode, inputs};

    #[test]
    fn confirm_accepts_own_output() {
        let confirm = meta().confirm.expect("zstd registers a confirm function");
        for plain in inputs() {
            for level in [
                Some(*zstd::compression_level_range().start()),
                Some(-5),
                Some(1),
                None,
                Some(19),
                Some(22),
            ] {
                let stream = encode(&Zstd, &plain, level);
                let what = format!("zstd_c level {level:?}, {} bytes in", plain.len());
                assert_every_cut_confirms(&what, confirm, &stream, 4);
            }
        }
    }
}
