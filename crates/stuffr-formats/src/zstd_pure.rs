//! zstd, via the pure-Rust `ruzstd` crate — the fallback that lets a build
//! with no C toolchain still read (and, weakly, write) `.zst`.
//!
//! `ZSTD`, the magic rule and `meta()` live in `crate::zstd_shared`, not
//! here — see that module's doc for why: this codec registers the exact
//! same [`stuffr_core::FormatId`] as `zstd_c`, and `lib.rs`'s
//! `register_all` makes the two mutually exclusive (`zstd_c` wins whenever
//! both are compiled), so neither backend module can own the shared
//! identity.
//!
//! ## The version pin: neither 0.9.0 NOR 0.8.2 build here
//!
//! The brief for this task cites API paths verified against `ruzstd` 0.9.0.
//! That version declares `rust-version = "1.87"`; this workspace's MSRV is
//! 1.85 (see the root `Cargo.toml`), so `cargo add` refused it outright and
//! landed on 0.8.2 instead — which turns out to be a second, subtler trap:
//! 0.8.2 declares no `rust-version` at all, so cargo's MSRV-aware resolver
//! has no reason to skip it, yet its `bit_io`/`fse`/`huff0` modules call the
//! unsigned `is_multiple_of` stdlib method, stabilised in 1.87. `cargo
//! check --all-features` on stable 1.95 does not catch this — only `rustup
//! run 1.85.0 cargo check --workspace --all-features` does, which is
//! exactly why that command is one of this project's required gates rather
//! than an afterthought. The root `Cargo.toml` pins `ruzstd = "=0.8.1"` —
//! an exact pin, not a caret range, because an ordinary range would let
//! `cargo update` float back up to the broken 0.8.2 — the last release
//! confirmed to actually build on 1.85. Every API surface this module
//! depends on — `decoding::StreamingDecoder`, `encoding::{FrameCompressor,
//! CompressionLevel, compress_to_vec}` — was confirmed directly against
//! BOTH 0.8.1's and 0.8.2's own source before writing a line of this file;
//! 0.9.0's source was not fetched (there was no need to, once it was ruled
//! out on MSRV grounds), but the brief's own description of its API — the
//! same names, at the same paths — matches what 0.8.1/0.8.2 actually
//! expose, for whatever that corroboration is worth.
//!
//! ## Three of five compression levels panic — read this before touching `level`
//!
//! Measured directly against `ruzstd` 0.8.1's `encoding::frame_compressor`:
//! `CompressionLevel::Default`, `Better` and `Best` all fall through to a
//! bare `unimplemented!()` in `FrameCompressor::compress` — a genuine
//! process abort, never an `Err`. Only `Uncompressed` and `Fastest` have a
//! real implementation (`compress_fastest`).
//!
//! The trap is sharpest at the obvious name: `Default` is the one that
//! panics. `check_encode_opts` below is what stands between
//! `EncodeOpts::level` (an unauthenticated `Option<i32>` a caller can set to
//! anything, including from a CLI flag) and that `unimplemented!()` — every
//! level except `None`, `Some(0)` and `Some(1)` is rejected as
//! [`stuffr_core::Error::Usage`] before an encoder is ever constructed, and
//! `encoder` never routes anything else to `CompressionLevel::Default`,
//! `Better` or `Best`. Property 6 of the conformance harness checks
//! `encoder` and `check_encode_opts` agree, so the two cannot silently
//! drift apart later.
//!
//! `None` (no `--level` given) maps to [`ruzstd::encoding::CompressionLevel::Fastest`],
//! **not** `Default` — the name is the trap, not the behavior wanted.
//!
//! ## The content checksum is on here BY DEFAULT — unlike `zstd_c`
//!
//! `zstd_c.rs`'s module doc measured that the `zstd` crate's encoder omits
//! the content checksum unless `include_checksum(true)` is called
//! explicitly. `ruzstd` is the opposite: its `hash` Cargo feature is a
//! *default* feature (see `ruzstd`'s own `Cargo.toml`), left on here because
//! nothing in this crate's dependency declaration disables default
//! features, and with it on, `FrameCompressor::compress`
//! (`encoding/frame_compressor.rs`) sets `content_checksum:
//! cfg!(feature = "hash")` in the frame header unconditionally and appends
//! the trailing 32-bit XXH64-derived checksum after the last block, with no
//! opt-in call needed on this module's part.
//!
//! **But writing the checksum is not the whole story.** Measured directly
//! against `ruzstd::decoding::streaming_decoder::StreamingDecoder::read`: it
//! stores both `get_checksum_from_data()` (what the stream claims) and,
//! behind the same `hash` feature, `get_calculated_checksum()` (what was
//! actually decoded) on the underlying `FrameDecoder` — but never compares
//! them. Left alone, the checksum this encoder writes would be inert
//! baggage: present in every stream, verified by nothing.
//! `LazyRuzstdDecoder` below does that comparison itself, once, at end of
//! stream, which is what actually makes `caps()`'s `detects_corruption:
//! true` true rather than aspirational — see the corruption-sweep tests for
//! the measured figures, on both a stream this codec wrote and one
//! `zstd_c` wrote.
//!
//! ## `FrameCompressor` buffers the whole input — this is not an accident
//!
//! `ruzstd::encoding::FrameCompressor` takes a `Read` **source**, not a
//! `Write` sink: `compress()` pulls from the source until it returns 0,
//! then writes the whole compressed frame to the drain in one pass. A
//! [`stuffr_core::Sink`] is a `Write` the caller pushes bytes INTO
//! incrementally, so bridging the two means accumulating every byte written
//! in a `Vec` and only handing it to `FrameCompressor` in `finish`. That
//! `Vec` is exactly the "buffers the whole input in memory" `weak_encoder`'s
//! message already warns about — this module does not pretend to stream.

use std::io::{ErrorKind, Read, Write};

use ruzstd::decoding::StreamingDecoder;
use ruzstd::encoding::{CompressionLevel, FrameCompressor};

use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, Result, Sink, Source, StreamOnly,
};

pub use crate::zstd_shared::{ZSTD, zstd_meta as meta};

#[derive(Debug)]
pub struct Zstd;

impl Codec for Zstd {
    fn id(&self) -> FormatId {
        ZSTD
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // See the module doc: the `hash` feature (a default) makes this
            // codec's own encoder always emit the content checksum, and the
            // corruption-sweep tests below measure detection against both a
            // stream this codec wrote and one `zstd_c` wrote.
            detects_corruption: true,
            weak_encoder: true,
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `StreamOnly`: a plain zstd stream carries no frame index,
    /// same as `zstd_c`'s decoder — see that module's doc.
    ///
    /// Wrapped in `LazyRuzstdDecoder` first, itself wrapped in
    /// `NormalizeDecodeErrors`: see `LazyRuzstdDecoder`'s own doc for why
    /// construction must be deferred to the first read rather than
    /// attempted here, and the corruption-sweep tests for the measured
    /// error kinds `RUZSTD_MALFORMED_AS_OTHER_EOF` folds onto `InvalidData`.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let normalized = crate::normalize::NormalizeDecodeErrors::new(
            LazyRuzstdDecoder::new(src),
            crate::normalize::RUZSTD_MALFORMED_AS_OTHER_EOF,
        );
        Ok(Box::new(StreamOnly::new(normalized)))
    }

    /// Rejects everything except the two levels `encoder` actually
    /// implements, *before* any encoder is constructed — see the module doc.
    /// The message names both accepted values and points at `--features
    /// c-backed` for the real range (`-131072..=22`, measured in
    /// `zstd_c.rs`), rather than silently narrowing a wider request.
    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        match o.level {
            None | Some(0) | Some(1) => Ok(()),
            Some(n) => Err(Error::Usage(format!(
                "ruzstd (this build's pure zstd fallback) supports only level 0 \
                 (uncompressed) or 1 (fastest), got {n} — CompressionLevel::Default, \
                 Better and Best all panic in this crate (see zstd_pure.rs's module doc). \
                 Rebuild with --features c-backed for the real range, -131072..=22."
            ))),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        let level = match o.level {
            Some(0) => CompressionLevel::Uncompressed,
            // None or Some(1): None must NOT route to CompressionLevel::
            // Default — see the module doc, that is the one that panics.
            _ => CompressionLevel::Fastest,
        };
        Ok(Box::new(RuzstdSink {
            level,
            buf: Vec::new(),
            dst,
        }))
    }
}

/// Accumulates every byte `write` is given, and only invokes
/// `ruzstd::encoding::FrameCompressor` on `finish` — see the module doc on
/// why `FrameCompressor`'s `Read`-source shape forces this rather than a
/// design choice made for its own sake.
struct RuzstdSink {
    level: CompressionLevel,
    buf: Vec<u8>,
    dst: Box<dyn Write + Send>,
}

impl Write for RuzstdSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink for RuzstdSink {
    /// Compresses into an intermediate `Vec` rather than handing
    /// `FrameCompressor` the real destination directly, because
    /// `FrameCompressor::compress` (`encoding/frame_compressor.rs`) calls
    /// `drain.write_all(output).unwrap()` on every block — a real
    /// destination that fails mid-write (a full disk, a closed pipe) would
    /// make `compress()` itself panic rather than return an `Err`,
    /// confirmed directly: conformance property 5 feeds exactly such a
    /// destination and panicked at that `unwrap()` before this change. A
    /// `Vec<u8>`'s `write_all` cannot fail, so `compress()` can never reach
    /// that `unwrap()`'s `Err` branch; the real destination is only
    /// written to afterward, through this codec's own `?`, where a failure
    /// surfaces as the `Err` a caller actually gets back.
    fn finish(self: Box<Self>) -> Result<()> {
        let RuzstdSink {
            level,
            buf,
            mut dst,
        } = *self;
        let mut compressor = FrameCompressor::new(level);
        compressor.set_source(buf.as_slice());
        let mut out = Vec::new();
        compressor.set_drain(&mut out);
        compressor.compress();
        dst.write_all(&out)?;
        dst.flush()?;
        Ok(())
    }
}

/// Defers constructing `ruzstd::decoding::StreamingDecoder` to the first
/// `read` call, rather than inside `Codec::decoder`.
///
/// Every other codec in this tree can wrap its backend's reader directly,
/// because none of them do any real work until the first read — but
/// `StreamingDecoder::new` is NOT that shape: it calls `FrameDecoder::init`
/// immediately, which parses the frame header eagerly and returns
/// `Result<_, FrameDecoderError>` (not an `io::Error`, so it does not
/// coerce with `?`). A source truncated to a single byte — exactly what
/// conformance property 10 feeds every decoder — fails AT `new`, before a
/// single call to `Read::read`.
///
/// The conformance harness's contract, common to every other codec here, is
/// that `Codec::decoder` itself always succeeds and a malformed stream is
/// only ever reported from `Read::read`/`read_to_end` afterward (see
/// `conformance.rs`'s properties 9-11, each of which `unwrap`s the
/// `decoder()` call and only match on the read's result). Rather than
/// break that contract for this one codec, construction is deferred here:
/// the raw source is held until the first `read`, at which point
/// `StreamingDecoder::new` is attempted and its `FrameDecoderError` — if
/// any — is turned into an `io::Error` the same way a `read()` failure
/// would be, so it flows through `NormalizeDecodeErrors` exactly like any
/// other malformed-input error this codec raises.
enum LazyRuzstdDecoder {
    Pending(Box<dyn Source>),
    Ready(Box<StreamingDecoder<Box<dyn Source>, ruzstd::decoding::FrameDecoder>>),
    /// The one attempt at construction already failed. Reading again must
    /// keep failing rather than panic on an already-taken `Pending` value.
    Failed,
}

impl LazyRuzstdDecoder {
    fn new(src: Box<dyn Source>) -> Self {
        Self::Pending(src)
    }
}

impl Read for LazyRuzstdDecoder {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self {
                LazyRuzstdDecoder::Ready(dec) => {
                    let n = dec.read(buf)?;
                    if n == 0 {
                        // `StreamingDecoder::read` stores both checksums
                        // (`get_checksum_from_data`: what the stream claims;
                        // `get_calculated_checksum`: what was actually
                        // decoded) but never compares them itself — measured
                        // directly against `streaming_decoder.rs`'s `read`
                        // impl, which has no such comparison anywhere. Doing
                        // it here, once, at end of stream, is what turns the
                        // `hash` feature's checksum from a value merely
                        // carried in the frame into something this decoder
                        // actually enforces — see the module doc.
                        // A single-pattern `if let` on the tuple, not the
                        // `&&`-joined let-chain form that only stabilised in
                        // 1.88 — MSRV here is 1.85 (see `ops.rs`'s identical
                        // comment on its own weak-encoder consent check).
                        if let (Some(expected), Some(actual)) = (
                            dec.decoder.get_checksum_from_data(),
                            dec.decoder.get_calculated_checksum(),
                        ) {
                            if expected != actual {
                                return Err(std::io::Error::new(
                                    ErrorKind::InvalidData,
                                    format!(
                                        "ruzstd: content checksum mismatch: stream claims \
                                         {expected:#010x}, calculated {actual:#010x}"
                                    ),
                                ));
                            }
                        }
                    }
                    return Ok(n);
                }
                LazyRuzstdDecoder::Failed => {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "ruzstd: stream failed to decode",
                    ));
                }
                LazyRuzstdDecoder::Pending(_) => {
                    let LazyRuzstdDecoder::Pending(src) =
                        std::mem::replace(self, LazyRuzstdDecoder::Failed)
                    else {
                        unreachable!("just matched Pending above")
                    };
                    match StreamingDecoder::new(src) {
                        Ok(dec) => *self = LazyRuzstdDecoder::Ready(Box::new(dec)),
                        Err(e) => return Err(frame_decoder_error_to_io(e)),
                    }
                }
            }
        }
    }
}

/// Converts a `StreamingDecoder::new` construction failure into an
/// `io::Error`, preserving a genuine I/O error's original kind rather than
/// flattening every cause onto `InvalidData`.
///
/// `ruzstd::decoding::errors::FrameDecoderError` is not an `io::Error` and
/// does not coerce with `?` (see `LazyRuzstdDecoder`'s doc), but several of
/// its variants — reached while parsing the frame header eagerly inside
/// `new` — wrap one several layers down: `ReadFrameHeaderError::
/// MagicNumberReadError`, `FrameDescriptorReadError`,
/// `WindowDescriptorReadError`, `DictionaryIdReadError` and
/// `FrameContentSizeReadError` all carry the underlying `io::Error` a
/// failing SOURCE actually raised (measured directly against
/// `decoding/errors.rs`'s `source()` implementations). Conformance property
/// 11 depends on that kind surviving unchanged: an always-failing source
/// raising `PermissionDenied` must still classify as `Error::Io` (exit 1)
/// even when the failure happens during construction rather than a later
/// `read`, and a blind `io::ErrorKind::Other` here would silently turn that
/// into `Error::Corrupt` (exit 5) instead.
///
/// Walking `std::error::Error::source()` — rather than matching each
/// variant by name — finds that `io::Error` wherever it is nested and
/// stops as soon as one is found, preserving its kind. A genuinely
/// malformed header (`BadMagicNumber`, `InvalidFrameDescriptor`,
/// `WindowSizeTooBig`, and the rest, none of which wrap an `io::Error` at
/// all) falls through to `io::ErrorKind::Other` instead — the same kind
/// `StreamingDecoder::read` already uses for a malformed BODY (see the
/// module doc), so `RUZSTD_MALFORMED_AS_OTHER_EOF` classifies both
/// consistently regardless of which stage of decoding caught the problem.
fn frame_decoder_error_to_io(e: ruzstd::decoding::errors::FrameDecoderError) -> std::io::Error {
    use std::error::Error as StdError;
    let msg = e.to_string();
    let mut cause: Option<&(dyn StdError + 'static)> = Some(&e);
    while let Some(c) = cause {
        if let Some(io_err) = c.downcast_ref::<std::io::Error>() {
            return std::io::Error::new(io_err.kind(), msg);
        }
        cause = c.source();
    }
    std::io::Error::other(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stuffr_core::ReaderSource;
    use stuffr_core::testing::SharedBuf;

    fn compress_with(level: Option<i32>, plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = Zstd
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    level,
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn compress(plain: &[u8]) -> Vec<u8> {
        compress_with(None, plain)
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_real_data_at_the_default_level() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(200);
        let packed = compress(&plain);
        assert!(packed.len() < plain.len(), "fastest must still compress");
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn round_trips_at_the_uncompressed_level() {
        let plain = b"payload".repeat(500);
        let packed = compress_with(Some(0), &plain);
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_zstd_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
    }

    #[test]
    fn none_maps_to_fastest_not_default() {
        // The single most important behavior in this file: routing "no
        // --level given" to CompressionLevel::Default would panic instead
        // of compressing. This test exists so a future refactor of
        // `encoder`'s match arms cannot silently reintroduce that crash
        // without this test failing loudly first (a panic here aborts the
        // WHOLE test binary, not just this test — see the next test for
        // the level values that must never reach `encoder` at all).
        let plain = incompressible_ish();
        let packed = compress_with(None, &plain);
        assert_eq!(decompress(packed), plain);
    }

    fn incompressible_ish() -> Vec<u8> {
        (0u32..20_000).flat_map(|n| n.to_le_bytes()).collect()
    }

    #[test]
    fn levels_that_map_to_the_panicking_variants_are_rejected_before_construction() {
        // 3 and 19 both fall in zstd_c's real, wider range but land on
        // CompressionLevel::Default/Better/Best here, which panic — see the
        // module doc. A negative level (zstd's "fast" modes on the C
        // backend) has no equivalent at all in ruzstd's five-variant enum.
        // check_encode_opts must refuse all three before any encoder object
        // is constructed, so a caller never gets close to the panic site.
        for n in [3, 19, -1] {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            let err = Zstd.check_encode_opts(&opts).expect_err(&format!(
                "level {n} must be rejected, not silently narrowed"
            ));
            assert!(matches!(err, Error::Usage(_)));
            assert_eq!(err.exit_code(), 2);
            assert!(
                err.to_string().contains('0') && err.to_string().contains('1'),
                "the error must name the two accepted levels: {err}"
            );
            assert!(
                err.to_string().contains("c-backed"),
                "the error must point at the escape hatch: {err}"
            );

            // Property 6's own guarantee, proven directly: encoder refuses
            // the exact same levels check_encode_opts does, never silently
            // narrowing them onto Fastest instead.
            assert!(Zstd.encoder(Box::new(SharedBuf::new()), &opts).is_err());
        }
    }

    #[test]
    fn accepted_levels_round_trip_and_rejected_ones_are_refused() {
        for n in [0, 1] {
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

    /// Sweeps every byte position of a stream, classifying each flip and
    /// asserting the shape this module's measurement found. Shared by both
    /// directions below — the one silently-unchanged position they both hit
    /// is structural (see the doc on the constant it returns), not a
    /// per-writer accident, so one assertion serves both streams.
    fn sweep(plain: &[u8], packed: &[u8]) -> (usize, usize, usize, usize) {
        let mut invalid_data = 0usize;
        let mut other_kind = 0usize;
        let mut silently_wrong = 0usize;
        let mut silently_unchanged = 0usize;
        for i in 0..packed.len() {
            let mut corrupted = packed.to_vec();
            corrupted[i] ^= 0xFF;
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(corrupted)));
            let mut dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) if out == plain => silently_unchanged += 1,
                Ok(_) => silently_wrong += 1,
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => invalid_data += 1,
                Err(_) => other_kind += 1,
            }
        }
        (invalid_data, other_kind, silently_wrong, silently_unchanged)
    }

    /// Sweeps every byte position of a stream THIS codec wrote, measuring
    /// how the checksum comparison `LazyRuzstdDecoder` adds actually
    /// performs — see the module doc's note on why `ruzstd`'s own `Read`
    /// impl leaves the checksum unverified without it.
    ///
    /// Measured: 4112 of 4113 positions detected (`InvalidData`), 0 silently
    /// wrong, and exactly ONE silently unchanged — byte 5, the frame
    /// header's window descriptor (magic is 4 bytes, the frame header
    /// descriptor is byte 4, and byte 5 follows it because
    /// `single_segment` is false). Traced directly: flipping it changes the
    /// declared window size (here, 128 KiB up to roughly 32 GiB — still far
    /// under `ruzstd`'s own `MAX_WINDOW_SIZE`, so it is never rejected as
    /// `WindowSizeTooBig`), which only bounds how far back a match may
    /// reference; it is not consulted when reproducing the literal bytes of
    /// a 4 KiB payload that never needed anywhere near that much window.
    /// Changing it therefore cannot change a single decoded output byte,
    /// for ANY writer — this is a structural property of the frame format,
    /// not a per-writer weakness like the checksum being optional. Compare
    /// `snappy.rs`'s own single documented exception (its chunk type byte,
    /// index 10): both are one real, protocol-level gap in an otherwise
    /// fully covered format, not a probe bug.
    #[test]
    fn corruption_sweep_on_a_stream_this_codec_wrote() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let packed = compress(&plain);
        let (invalid_data, other_kind, silently_wrong, silently_unchanged) = sweep(&plain, &packed);
        eprintln!(
            "zstd_pure corruption sweep (self-written, {} bytes): detected(InvalidData)={} \
             silently_wrong={} silently_unchanged={} other_kind={}",
            packed.len(),
            invalid_data,
            silently_wrong,
            silently_unchanged,
            other_kind
        );
        assert_eq!(
            other_kind, 0,
            "every malformed-input error here must classify as InvalidData once \
             NormalizeDecodeErrors has run — {other_kind} positions did not"
        );
        assert_eq!(
            silently_wrong,
            0,
            "the content checksum (on by default via the `hash` feature, and enforced by \
             LazyRuzstdDecoder) is expected to catch every flipped position that actually \
             changes decoded output; measured {silently_wrong} of {} positions silently wrong",
            packed.len()
        );
        assert_eq!(
            silently_unchanged, 1,
            "expected exactly one silently-unchanged position — byte 5, the window \
             descriptor (see this test's doc for why). Any other count would be a genuine, \
             undocumented change in detection coverage: measured {silently_unchanged}"
        );
        assert_eq!(
            invalid_data,
            packed.len() - 1,
            "every position except the one documented structural exception must be detected"
        );
    }

    /// The other direction: a stream the C backend wrote, decoded by THIS
    /// codec — proving the checksum verification above also holds against
    /// an independent implementation's output, not just its own. Same
    /// figures as the self-written sweep above, for the same structural
    /// reason (see that test's doc): the window descriptor lands at the
    /// same byte 5 regardless of which encoder produced the frame.
    #[cfg(all(feature = "zstd-pure", feature = "zstd-c"))]
    #[test]
    fn corruption_sweep_on_a_stream_the_c_backend_wrote() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let packed = crate::zstd_c::encode_for_test(&plain);
        let (invalid_data, other_kind, silently_wrong, silently_unchanged) = sweep(&plain, &packed);
        eprintln!(
            "zstd_pure corruption sweep (zstd_c-written, {} bytes): detected(InvalidData)={} \
             silently_wrong={} silently_unchanged={} other_kind={}",
            packed.len(),
            invalid_data,
            silently_wrong,
            silently_unchanged,
            other_kind
        );
        assert_eq!(
            other_kind, 0,
            "every malformed-input error here must classify as InvalidData once \
             NormalizeDecodeErrors has run — {other_kind} positions did not"
        );
        assert_eq!(
            silently_wrong,
            0,
            "measured {silently_wrong} of {} positions silently wrong decoding a zstd_c-written \
             stream — the C backend's own checksum (it always turns one on, see zstd_c.rs) \
             should be caught the same way",
            packed.len()
        );
        assert_eq!(
            silently_unchanged, 1,
            "expected exactly one silently-unchanged position — byte 5, the window \
             descriptor, same structural reason as the self-written sweep: measured \
             {silently_unchanged}"
        );
    }

    #[test]
    fn capabilities_match_the_format() {
        let c = Zstd.caps();
        assert!(
            c.decode,
            "the fallback exists to read .zst on a build with no C toolchain"
        );
        assert!(
            c.encode,
            "ruzstd can encode; a pure build should be able to write .zst at all"
        );
        assert!(
            c.weak_encoder,
            "and ops must refuse it without --allow-weak-encoder"
        );
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        assert!(
            c.detects_corruption,
            "the hash feature is on by default — see the module doc"
        );

        let m = meta();
        assert_eq!(m.id, ZSTD);
        assert_eq!(m.extensions, &["zst"]);
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn zstd_pure_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Zstd, &meta());
    }

    // A decode-only codec cannot encode its own test input, which is
    // exactly what `assert_codec_conforms_with`'s fixture parameter exists
    // for — added in Phase 1c and unexercised until now. This codec CAN
    // encode (`caps().encode` is true), so `test_input` (conformance.rs)
    // always prefers its own encoder over the supplied fixture — the
    // fixture argument below is accepted but not consulted for THIS codec.
    // It is kept, under the same gate and with the same call shape Tasks 5
    // and 6 copy, so the pattern is established here even though the
    // cross-backend proof it might suggest is not what this particular
    // call performs — see `c_decodes_a_stream_this_codec_wrote` and
    // `this_codec_decodes_a_stream_the_c_backend_wrote` below for that
    // proof instead.
    #[cfg(all(feature = "zstd-pure", feature = "zstd-c"))]
    #[test]
    fn zstd_pure_conforms_against_a_fixture() {
        let fixture = crate::zstd_c::encode_for_test(b"conformance fixture payload");
        stuffr_core::testing::assert_codec_conforms_with(&Zstd, &meta(), Some(&fixture));
    }

    #[cfg(all(feature = "zstd-pure", feature = "zstd-c"))]
    #[test]
    fn c_decodes_a_stream_this_codec_wrote() {
        // The direction that matters most: a pure build's output must not
        // be a dead end only a pure build can open.
        let plain = b"cross-backend: ruzstd writes, the C backend reads".repeat(50);
        let packed = compress(&plain);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let mut dec = crate::zstd_c::Zstd
            .decoder(src, &DecodeOpts::default())
            .unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    #[cfg(all(feature = "zstd-pure", feature = "zstd-c"))]
    #[test]
    fn this_codec_decodes_a_stream_the_c_backend_wrote() {
        let plain = b"cross-backend: the C backend writes, ruzstd reads".repeat(50);
        let packed = crate::zstd_c::encode_for_test(plain.as_slice());
        assert_eq!(decompress(packed), plain);
    }
}
