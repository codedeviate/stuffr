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
//! ## No version pin any more — the root `Cargo.toml` has the history
//!
//! Earlier in this project's history the root `Cargo.toml` pinned
//! `ruzstd = "=0.8.1"` exactly, because the 1.85 MSRV floor of the time
//! refused 0.9.0 (`rust-version = "1.87"`) and 0.8.2 built on a modern
//! toolchain but failed under 1.85 (it calls the unsigned
//! `is_multiple_of` stdlib method, stabilised in 1.87, without declaring
//! that as its own `rust-version`). Raising the MSRV floor to 1.88 freed
//! both, and the root `Cargo.toml` now carries a caret range,
//! `ruzstd = "0.9"`, with the full story in its own comment there rather
//! than duplicated here.
//!
//! **Upgrading did not let any workaround in this module be deleted.**
//! Every API surface this module depends on —
//! `decoding::StreamingDecoder`, `encoding::{FrameCompressor,
//! CompressionLevel, compress_to_vec}` — was re-confirmed directly
//! against 0.9.0's own source, and all three defects this module works
//! around persist there unchanged: `Default`/`Better`/`Best` still panic,
//! the content checksum is still never verified on read, and multi-frame
//! `.zst` is still truncated to its first frame. Do not remove a guard
//! below on the assumption that a newer release fixed it; re-measure
//! first, the way this file's own history did. 0.9.0 did buy one real
//! improvement — see "The content checksum is on here BY DEFAULT" below
//! for the window-size-cap detail.
//!
//! ## Three of five compression levels panic — read this before touching `level`
//!
//! Measured directly against `ruzstd` 0.8.1's `encoding::frame_compressor`,
//! and reconfirmed directly against 0.9.0's after the unpin:
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
//! CorruptionDetection::WhenPresent` real rather than aspirational — see the
//! corruption-sweep tests for the measured figures, on both a stream this
//! codec wrote and one `zstd_c` wrote.
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
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FormatId, Result, Sink,
    Source, StreamOnly,
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
            detects_corruption: CorruptionDetection::WhenPresent,
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
    ///
    /// **This decoder only weakly detects corruption in a stream that was
    /// not written with the content checksum on.** `caps().detects_corruption`
    /// is `CorruptionDetection::WhenPresent` because THIS codec's own encoder
    /// cannot even produce a checksumless stream (the `hash` feature is
    /// unconditional here — see
    /// the module doc) — but that says nothing about a `.zst` some other
    /// tool wrote with its own checksum left off, still fully valid zstd
    /// under the format (see `format.rs`'s `detects_corruption` doc for why
    /// this distinction applies to zstd generally, and `zstd_c.rs`'s
    /// `decoder` doc for the same disclosure on the C backend, whose
    /// checksumless figure is measured separately and comes out very
    /// different). Measured directly here, sweeping every byte position of
    /// a real payload encoded via the raw `zstd` crate with no
    /// `include_checksum` call (built via `zstd::stream::write::Encoder`
    /// directly — `zstd_c::Zstd`'s own encoder always turns the checksum
    /// on, so it cannot produce this case itself): only 9 of 4105 flipped
    /// positions were detected, 4096 decoded to silently WRONG bytes, and
    /// one (the structural window-descriptor exception documented on the
    /// corruption-sweep tests below) was silently unchanged. That is a much
    /// higher miss rate than `zstd_c.rs`'s own measured checksumless figure
    /// (17-21 of 61) — the two backends' block layout for incompressible
    /// data differs enough that the comparison is only useful qualitatively
    /// ("both are weak without the checksum"), not by ratio. See
    /// `corruption_sweep_on_a_checksumless_foreign_stream` for the sweep
    /// this cites.
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
/// `read` call, rather than inside `Codec::decoder`, and — because a single
/// `StreamingDecoder` handles exactly one zstd frame, never more (its own
/// doc says so explicitly: "expects the underlying stream to only contain a
/// single frame") — re-constructs a fresh one for each further frame in a
/// concatenated stream, rather than stopping at the first frame's clean end.
///
/// ## Why construction is deferred at all
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
///
/// ## Concatenated frames: the defect this fixes and how
///
/// A `.zst` made of several concatenated frames (`cat a.zst b.zst >
/// both.zst`) is ordinary, valid zstd — the same shape gzip's
/// `MultiGzDecoder` and `lz4.rs`'s own `EnforceEndMark` (see its module doc)
/// already exist to handle for their own formats. Before this fix,
/// `LazyRuzstdDecoder` reported the first frame's clean `Ok(0)` straight to
/// its caller as end of stream: every byte after the first frame's end was
/// silently dropped, with `read_to_end` returning `Ok` and no error at all —
/// confirmed independently by two reviewers on different cut points (1900 of
/// 3900 bytes; 2000 of 4100 bytes), and the single worst failure mode this
/// project recognises, because the caller gets a plausible-looking partial
/// result with no signal anything was lost. It survived `make check`
/// specifically because that gate runs `--all-features`, where `zstd_c`
/// (immune to this — the C `zstd` crate's `Decoder` handles concatenated
/// frames internally, confirmed to return all 4100 of 4100 bytes on the
/// review's own repro) wins format selection in the registry, so the pure
/// decoder was never reached through that path at all; the regression tests
/// below call `Zstd` directly rather than through `stuffr::registry()`, so
/// they exercise `ruzstd` regardless of which other backend is also
/// compiled in.
///
/// The fix: on a clean `Ok(0)` (current frame ended, checksum verified —
/// see the note below on where that check runs), recover the underlying
/// source via `into_inner`, and peek exactly one byte from what remains
/// (`PeekSource::fill(remaining, 1)`, non-destructive — the peeked byte is
/// replayed, not consumed). Peeking is what tells apart the two ways this
/// can go, which look identical until you actually try to read past the
/// frame boundary:
///
/// - The peek's prefix is empty: the source is genuinely, entirely
///   exhausted. No more frames follow — this is the one legitimate `Ok(0)`,
///   reported once and (via the `Done` state) idempotently on every further
///   call.
/// - The peek's prefix holds a byte: something follows. Constructing a new
///   `StreamingDecoder` on the peeked-plus-remaining source either succeeds
///   (a genuine next frame; the loop continues and serves its bytes
///   transparently) or fails the same way any truncated/malformed header
///   would (`frame_decoder_error_to_io` applies unchanged) — so a complete
///   first frame followed by a TRUNCATED second one is still rejected, not
///   waved through as "just the first frame, nothing more". See
///   `a_truncated_second_frame_in_a_concatenated_stream_is_rejected`.
enum LazyRuzstdDecoder {
    Pending(Box<dyn Source>),
    Ready(Box<StreamingDecoder<Box<dyn Source>, ruzstd::decoding::FrameDecoder>>),
    /// Every frame has ended, and the underlying source confirmed
    /// genuinely empty (not merely a `Ok(0)` from one frame's own end).
    /// Every further `read` keeps returning `Ok(0)` without re-probing.
    Done,
    /// The one attempt at construction — of the first frame, or of a
    /// concatenated later one — already failed. Reading again must keep
    /// failing rather than panic on an already-taken `Pending` value.
    Failed,
}

impl LazyRuzstdDecoder {
    fn new(src: Box<dyn Source>) -> Self {
        Self::Pending(src)
    }
}

impl Read for LazyRuzstdDecoder {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // A zero-length buffer conventionally yields `Ok(0)` with no I/O
        // attempted at all — see `lz4.rs`'s `EnforceEndMark::read` for the
        // identical guard and why it exists: running an empty read through
        // the state machine below would misread it as a genuine frame end
        // and start probing for a concatenated next frame (or verifying a
        // checksum) that nothing actually reached yet.
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self {
                LazyRuzstdDecoder::Done => return Ok(0),
                LazyRuzstdDecoder::Ready(dec) => {
                    let n = dec.read(buf)?;
                    if n > 0 {
                        return Ok(n);
                    }
                    // n == 0: this frame ended cleanly. Verify its checksum
                    // — if it carried one — before considering whether a
                    // concatenated next frame follows.
                    //
                    // This check fires only here, at a clean `Ok(0)` — a
                    // caller that stops reading before reaching one (never
                    // asks for the last few bytes) skips it. That is
                    // inherent to any TRAILER checksum, not a gap specific
                    // to this codec: gzip's own trailer CRC32 behaves
                    // identically, and every caller in `ops.rs` reads to a
                    // clean `Ok(0)` via `read_to_end`/the copy loop, so this
                    // is documented rather than "fixed" — there is nothing
                    // to fix; a checksum that could fire before its own
                    // bytes arrive would not be verifying anything.
                    //
                    // `StreamingDecoder::read` stores both checksums
                    // (`get_checksum_from_data`: what the stream claims;
                    // `get_calculated_checksum`: what was actually decoded)
                    // but never compares them itself — measured directly
                    // against `streaming_decoder.rs`'s `read` impl, which
                    // has no such comparison anywhere. Doing it here is
                    // what turns the `hash` feature's checksum from a value
                    // merely carried in the frame into something this
                    // decoder actually enforces — see the module doc.
                    //
                    if let (Some(expected), Some(actual)) = (
                        dec.decoder.get_checksum_from_data(),
                        dec.decoder.get_calculated_checksum(),
                    ) && expected != actual
                    {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "ruzstd: content checksum mismatch: stream claims \
                                 {expected:#010x}, calculated {actual:#010x}"
                            ),
                        ));
                    }

                    // Recover the underlying source and check — by peeking,
                    // non-destructively, exactly one byte — whether a
                    // concatenated next frame follows. See the module doc's
                    // note on concatenation for why this is the mechanism.
                    let LazyRuzstdDecoder::Ready(dec) =
                        std::mem::replace(self, LazyRuzstdDecoder::Failed)
                    else {
                        unreachable!("just matched Ready above")
                    };
                    let remaining = dec.into_inner();
                    let peeked = match stuffr_core::PeekSource::fill(remaining, 1) {
                        Ok(p) => p,
                        Err(e) => return Err(std::io::Error::other(e)),
                    };
                    if peeked.prefix().is_empty() {
                        // Genuinely nothing left: the whole stream — one
                        // frame or several — is done.
                        *self = LazyRuzstdDecoder::Done;
                        return Ok(0);
                    }
                    match StreamingDecoder::new(Box::new(peeked) as Box<dyn Source>) {
                        Ok(next) => *self = LazyRuzstdDecoder::Ready(Box::new(next)),
                        Err(e) => return Err(frame_decoder_error_to_io(e)),
                    }
                    // Loop back around: the state is now Ready(next), and
                    // the top of the loop serves its bytes like any other
                    // frame's.
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

    /// Regression for the silent-data-loss defect found in review: a single
    /// `StreamingDecoder` handles exactly one zstd frame (its own doc says
    /// so), and `LazyRuzstdDecoder` used to report that frame's clean
    /// `Ok(0)` straight to the caller — a concatenated `.zst` (ordinary,
    /// valid zstd; `cat a.zst b.zst > both.zst` produces exactly this)
    /// decoded to only its first frame, with `read_to_end` returning `Ok`
    /// and no error at all. Confirmed independently by two reviewers on two
    /// different cut points before the fix (1900 of 3900 bytes; 2000 of
    /// 4100 bytes) — this test pins the general shape rather than either
    /// specific number, since the exact byte count depends on compression
    /// output, not on the defect.
    ///
    /// This calls `Zstd` directly, the same way every other test in this
    /// module does, rather than through `stuffr::registry()` — that is
    /// what makes it exercise `ruzstd` regardless of whether `zstd-c` is
    /// ALSO compiled in (which wins registry selection and would otherwise
    /// make a registry-level test of this exercise the C backend instead,
    /// proving nothing about this defect). See the module doc's note on
    /// concatenation for why `make check` alone never caught this: it runs
    /// `--all-features`, where the registry always resolves to `zstd_c`.
    #[test]
    fn decodes_concatenated_frames_not_just_the_first() {
        let mut two = compress(b"first-");
        two.extend_from_slice(&compress(b"second"));
        assert_eq!(decompress(two), b"first-second");
    }

    #[test]
    fn a_truncated_second_frame_in_a_concatenated_stream_is_rejected() {
        // The concatenation fix must not reopen its own hole: a complete
        // first frame followed by a TRUNCATED second one must still be
        // rejected, not silently accepted as "just the first frame,
        // nothing more" — see `lz4.rs`'s identical test for the same
        // property proven against a different backend's concatenation fix.
        let complete = compress(b"first-");
        let second_full = compress(b"second-frame-payload");
        let mut two = complete.clone();
        two.extend_from_slice(&second_full[..second_full.len() - 1]);

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(two)));
        let mut dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        assert!(
            dec.read_to_end(&mut out).is_err(),
            "a complete frame followed by a truncated second one must not decode cleanly"
        );
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
            silently_unchanged, 0,
            "ruzstd 0.9.0 detects every flipped position in a stream it wrote, byte 5 \
             (the window descriptor) included. Under the previously pinned 0.8.1 that \
             one byte decoded unchanged and this assertion read 1, so the upgrade \
             improved coverage rather than regressing it. Any non-zero count now is a \
             genuine change in detection coverage: measured {silently_unchanged}"
        );
        assert_eq!(
            invalid_data,
            packed.len(),
            "ruzstd 0.9.0 detects EVERY position, with no structural exception. The \
             previously pinned 0.8.1 left byte 5 (the window descriptor) undetected, \
             so this read `packed.len() - 1`; the upgrade closed that gap."
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
            silently_unchanged, 0,
            "as with the self-written sweep, ruzstd 0.9.0 detects byte 5 (the window \
             descriptor) where the previously pinned 0.8.1 did not: measured \
             {silently_unchanged}"
        );
    }

    /// The measurement `decoder`'s own doc requires: what THIS decoder does
    /// with a `.zst` that carries no content checksum at all — a foreign
    /// tool's choice, not this codec's own (see the module doc: this
    /// codec's encoder cannot even produce one, since `content_checksum:
    /// cfg!(feature = "hash")` is unconditional whenever the default `hash`
    /// feature is on). Built with the raw `zstd` crate directly, NOT
    /// through `zstd_c::Zstd` (which always calls `include_checksum(true)`
    /// and so can never produce this case) — deliberately skipping that
    /// call is what "a foreign tool that left the checksum off" looks like.
    #[cfg(all(feature = "zstd-pure", feature = "zstd-c"))]
    #[test]
    fn corruption_sweep_on_a_checksumless_foreign_stream() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        enc.write_all(&plain).unwrap();
        let packed = enc.finish().unwrap();

        let (invalid_data, other_kind, silently_wrong, silently_unchanged) = sweep(&plain, &packed);
        eprintln!(
            "zstd_pure corruption sweep (checksumless foreign stream, {} bytes): \
             detected(InvalidData)={} silently_wrong={} silently_unchanged={} other_kind={}",
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
        // Measured, not merely bounded: 9 of 4105 detected (structural
        // framing bytes only — no checksum exists to catch a corrupted
        // literal), 4096 silently wrong, and no silently-unchanged
        // window-descriptor position the other two sweeps hit. A
        // dramatically weaker showing than either checksummed sweep above,
        // which is the whole point of this test — see the `decoder` doc's
        // disclosure this backs.
        assert_eq!(
            invalid_data,
            9,
            "measured {invalid_data} of {} positions detected without a checksum to check \
             against — only structural framing bytes remain protected",
            packed.len()
        );
        assert_eq!(
            silently_wrong,
            4096,
            "measured {silently_wrong} of {} positions silently wrong — with no checksum, \
             a corrupted literal byte decodes to a different byte with no error at all",
            packed.len()
        );
        assert_eq!(
            silently_unchanged, 0,
            "0.9.0's window-size cap catches the flipped window descriptor here too, so \
             no position decodes unchanged — independent of the checksum question, which \
             is the point of this sweep: measured {silently_unchanged}"
        );
    }

    /// Makes the "corrupting the window descriptor cannot change decoded
    /// output" claim (see the sweep tests above) demonstrable, not merely
    /// argued: those sweeps used an INCOMPRESSIBLE payload, which contains
    /// no repeat at all — every byte is a literal, so of course no offset
    /// ever gets checked against the window there.
    ///
    /// Proving the SHRINK direction is actually caught turned out to need
    /// more than just "a payload with a real match", measured directly
    /// while building this test: a marker repeated with a real gap, as long
    /// as the WHOLE marker-gap-marker payload stays under the format's 128
    /// KiB max block size, still round-trips even with byte 5 zeroed.
    /// Traced to `ruzstd`'s own decode-side behavior, not anything
    /// encoder-specific: within one compressed block, `decode_blocks`
    /// resolves every sequence in that block in one atomic pass, and the
    /// external draining that actually enforces the declared window
    /// (`DecodeBuffer::drain_to_window_size`, invoked between separate
    /// `decode_blocks` calls as `StreamingDecoder::read` pulls bytes out)
    /// never runs in the middle of it. So a shrunk window is structurally
    /// unable to matter for a match resolved within a single block — this
    /// test's marker and filler must be large enough that the payload spans
    /// MULTIPLE compressed blocks, with the second marker copy in a later
    /// block referencing back into an earlier one, for the shrink to have
    /// anything to catch.
    ///
    /// `ruzstd`'s own `Fastest` encoder cannot be used to build that payload
    /// reliably: its `FrameCompressor` matcher holds only ONE 128 KiB slice
    /// in its matching window at a time (`MatchGeneratorDriver::new(1024 *
    /// 128, 1)` — the `1` is `max_slices_in_window`), so it cannot find a
    /// match crossing its own block boundary even in principle. This test
    /// instead builds its payload with the raw `zstd` crate at level 19 (a
    /// real, independent implementation with no such limit) — what's under
    /// test is THIS codec's DECODER reacting to a corrupted window field,
    /// not either encoder's own matching behavior, so using the more
    /// capable encoder to construct the fixture is not a shortcut around
    /// what matters here.
    ///
    /// Two corruptions of byte 5, in the two directions that matter:
    /// - XOR 0xFF (what the sweep tests actually flip to): the window
    ///   GROWS, which cannot invalidate a match that already fit in the
    ///   smaller original window. Still round-trips.
    /// - Overwritten to 0x00: the window SHRINKS to 1 KiB (windowLog 10,
    ///   the format's minimum — `ruzstd::common::MIN_WINDOW_SIZE`), well
    ///   below the real cross-block match's ~250 KiB offset — and, with the
    ///   payload now spanning multiple blocks, `drain_to_window_size` gets
    ///   the chance (described above) to actually discard the earlier
    ///   block's bytes before the later block's sequence needs them:
    ///   `DecodeBufferError::OffsetTooBig`, confirmed to surface through
    ///   this codec's decoder as a real, detected error. This is the
    ///   reviewer's independently-confirmed case.
    #[cfg(all(feature = "zstd-pure", feature = "zstd-c"))]
    #[test]
    fn window_descriptor_corruption_is_detected_in_both_directions() {
        // A 50 KiB marker (not a short one: a small marker's savings get
        // lost in per-block-header overhead once the payload spans multiple
        // wire blocks, measured directly while building this test) repeated
        // with 200 KiB of DIFFERENT incompressible filler in between — well
        // past the format's 128 KiB max block size, so the two marker
        // copies land in separate compressed blocks. That is required, not
        // incidental: within a single block, ruzstd resolves every sequence
        // in one atomic pass before any external drain can run (confirmed
        // directly while building this test — a marker-gap-marker payload
        // under 128 KiB round-tripped fine even with byte 5 zeroed, because
        // the corrupted window was never actually consulted). Only once a
        // backreference crosses a REAL block boundary does ruzstd's
        // decode-buffer draining between blocks (`DecodeBuffer::
        // drain_to_window_size`, driven by `StreamingDecoder::read`'s own
        // calls) get a chance to discard the earlier block's bytes before
        // the later block's sequence needs them.
        //
        // Built with the raw `zstd` crate directly (not `zstd_c::Zstd`,
        // whose own encoder never turns on a custom level) at level 19 —
        // level 3 also finds this particular match, 19 just gives more
        // margin. Neither encoder's own matching behavior is what's under
        // test here: this is about ruzstd's DECODER reacting to a corrupted
        // window field.
        fn seeded_incompressible(len: usize, seed: u32) -> Vec<u8> {
            let mut s = seed;
            (0..len)
                .map(|_| {
                    s = s.wrapping_mul(1103515245).wrapping_add(12345);
                    (s >> 16) as u8
                })
                .collect()
        }
        let marker = seeded_incompressible(50 * 1024, 1);
        let filler = seeded_incompressible(200 * 1024, 2);
        let mut plain = Vec::new();
        plain.extend_from_slice(&marker);
        plain.extend_from_slice(&filler);
        plain.extend_from_slice(&marker);

        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 19).unwrap();
        enc.write_all(&plain).unwrap();
        let packed = enc.finish().unwrap();
        // Both `marker` and `filler` are individually incompressible, so an
        // UNMATCHED encoding would be close to `plain.len()` (two full
        // marker copies plus the filler, virtually nothing shrinking). A
        // MATCHED encoding is close to `filler.len() + marker.len()` (one
        // marker copy paid for, the second nearly free) — the two differ by
        // roughly `marker.len()` (50 KiB), an unambiguous signal.
        assert!(
            packed.len() < filler.len() + marker.len() + 4096,
            "expected a real cross-block backreference to the repeated marker: measured {} \
             bytes packed, matched estimate ~{} bytes, unmatched estimate ~{} bytes",
            packed.len(),
            filler.len() + marker.len(),
            plain.len()
        );
        assert_eq!(&packed[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
        assert_eq!(
            decompress(packed.clone()),
            plain,
            "an uncorrupted stream must round-trip"
        );

        // Direction 1: grow the window. **This reversed with the upgrade from
        // ruzstd 0.8.1 to 0.9.0, and the reversal is why this test is worth
        // keeping.** Under 0.8.1, growing the declared window was harmless and
        // this asserted a clean round-trip. 0.9.0 added a window-size cap and
        // now REJECTS it — measured: `WindowSizeTooBig { requested:
        // 2199023255552, max: 104857600 }`, i.e. a flipped descriptor asking
        // for 2.2 TB against a 100 MiB ceiling.
        //
        // That is a resource guard rather than an integrity check, and it is
        // worth noticing as such: it is precisely the protection `lzma-rust2`'s
        // xz decoder lacks (see `xz_pure.rs`'s module doc, where a 60-byte file
        // can demand an allocation sized by its own declared dictionary).
        let mut grown = packed.clone();
        grown[5] ^= 0xFF;
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(grown)));
        let mut dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        assert!(
            dec.read_to_end(&mut out).is_err(),
            "ruzstd 0.9.0 caps the window at 100 MiB, so a grown descriptor must be \
             refused rather than honoured; if this starts passing, the cap was removed \
             or raised and the sweep tests' silently_unchanged counts will have moved too"
        );

        // Direction 2: shrink the window well below the real match's
        // distance (250 KiB+, comfortably past the 1 KiB the format's
        // minimum window descriptor allows).
        let mut shrunk = packed;
        shrunk[5] = 0x00;
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(shrunk)));
        let mut dec = Zstd.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        assert!(
            dec.read_to_end(&mut out).is_err(),
            "shrinking the window below the real match's offset must be detected, not decode \
             to wrong or truncated output silently"
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
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::WhenPresent,
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
