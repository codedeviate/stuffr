//! LZMA1 (the `.lzma` "alone" format), pure Rust, via `lzma-rust2` — the same
//! dependency `xz_pure.rs` uses (Task 5), and a full codec here too: encode
//! AND decode, no `weak_encoder`.
//!
//! `LZMA` and `meta()` live in `crate::lzma_shared`, not here — see that
//! module's doc for why: this codec registers the exact same
//! [`stuffr_core::FormatId`] as `lzma_c`, and `lib.rs`'s `register_all` makes
//! the two mutually exclusive (`lzma_c` wins whenever both are compiled).
//!
//! ## The push-to-pull bridge is cancelled
//!
//! The plan that preceded this task called a `pushpull.rs` bridge module "the
//! only genuinely new machinery in this cycle", built to wrap `lzma-rs`'s
//! `Write`-shaped decompressor behind the `Read`-shaped interface
//! [`stuffr_core::Codec::decoder`] needs. Two measurements removed it before
//! any code was written:
//!
//! 1. `lzma-rs`'s `LzCircularBuffer` drains to its writer only when the
//!    dictionary window wraps. At the default 8 MiB dictionary it emitted
//!    **nothing at all** for 1.1 MB and 4.4 MB payloads, and first emitted at
//!    3,448,832 bytes only once the payload passed 13.2 MB — conformance
//!    property 8 (below) uses a 4 MiB payload, so no bridge, however
//!    carefully written, could have made this an incremental codec: the
//!    buffering sits behind the interface a bridge would wrap.
//! 2. `lzma_rust2::LzmaReader` already implements `Read` directly and
//!    streams: measured serving its first KiB after consuming only 68 of
//!    2,126,405 bytes. There is nothing to bridge.
//!
//! `lzma-rs` is not a dependency of this project.
//!
//! ## The end-marker path, verified
//!
//! [`Codec::encoder`] is handed a `Write` and never learns the input length
//! in advance, so `LzmaWriter::new_use_header`'s third argument is always
//! `None` here — the end-marker path, not the "known length" one. Verified
//! directly this task: for a 1.1 MB payload, this codec's own output and
//! `lzma_c`'s (`liblzma`) output are an **identical 299 bytes**, both
//! starting `5d 00 00 80 00 ff ff ff ff ff ff ff ff` (properties byte,
//! preset 6's dictionary size, then the eight `ff` bytes that are LZMA1's
//! "uncompressed size unknown" sentinel) — see
//! `the_two_backends_agree_in_both_directions` for the pinned regression.
//!
//! ## Deferred construction — the same reason as `zstd_pure`'s `LazyRuzstdDecoder`
//!
//! `LzmaReader::new_mem_limit` parses the 13-byte header (and, one layer
//! down, the range coder's own 5-byte prologue) eagerly, at construction —
//! not lazily on first read. Conformance properties 9-11 all call
//! `codec.decoder(src, opts)` and `.unwrap()` it unconditionally, matching
//! errors only against what a later `.read()` call returns; property 10 cuts
//! as short as 1 byte. A codec whose `decoder()` itself fails on a 1-byte
//! input would panic there instead of exercising the property it exists to
//! check. [`LazyLzmaDecoder`] defers construction to the first `read`, the
//! same fix `zstd_pure.rs`'s `LazyRuzstdDecoder` needed for the same reason —
//! see that type's doc for the fuller statement of the contract.
//!
//! ## Truncation by exactly one byte — measured, and why a plain trailing-garbage check cannot catch it
//!
//! Naively mirroring `lzma_c.rs`'s `RejectTrailingGarbage` (peek the
//! underlying reader once decode reports done; error if anything remains) is
//! not sufficient here, and this was measured directly, not assumed: cutting
//! a real encoded stream short by exactly its last byte still decodes to the
//! exact original plaintext, `Ok`, no error, at every payload shape tried (a
//! 103-byte compressible-text stream, a 4,170-byte incompressible one, and a
//! 66,452-byte one matching the conformance harness's own 64 KiB fixture
//! size) — and property 10 tests exactly this cut (`len - 1`) as one of its
//! three. A **two**-byte cut behaves the same way on compressible input
//! (measured: `Ok` with the exact original plaintext), so this is not
//! uniquely a one-byte phenomenon; the guard below, not the crate, is what
//! catches both. Traced to the cause: `lzma_rust2`'s `impl<T: Read> RangeReader for
//! T`'s `read_u8` (`range_dec.rs`) deliberately swallows a real EOF from the
//! wrapped reader and substitutes the sentinel byte `1` instead of
//! propagating an error — a documented 10% decode speedup, on the reasoning
//! that a genuinely truncated stream will fail anyway once the substituted
//! byte corrupts the range coder's state. That reasoning holds for a cut two
//! or more bytes short, but not for a cut exactly one byte short: the
//! `normalize()` lookahead call consuming that final byte runs strictly
//! *after* the decoder has already found its end marker and finished
//! producing output, so the substituted value is provably irrelevant to
//! anything already decoded, and the crate reports success.
//!
//! Note the payload dependence, because it decides whether a test of this is
//! load-bearing: on an **incompressible** payload the crate detects every short
//! cut unaided, so a truncation test using one passes with `GuardedReader`
//! deleted. Only a compressible payload reaches the faked-byte path. The tests
//! below use compressible input for exactly that reason.
//!
//! Measured directly that a plain "anything left over" check cannot
//! distinguish this from a genuine, complete stream either: decoding the
//! full, untruncated 66,452-byte fixture above consumes exactly 66,452 of
//! 66,452 bytes from the underlying reader (zero left over) — the *same*
//! "nothing left" state a stream truncated by one byte reaches, since that
//! missing byte is never actually read (it is faked). Peeking the source
//! after decode cannot tell these two apart; the two cases are
//! indistinguishable from outside the crate's own read calls.
//!
//! The fix: [`GuardedReader`] wraps the underlying source and records
//! whether **any** `read()` call during decode ever genuinely returned `Ok(0)`
//! — real physical EOF, as opposed to the crate's own internal sentinel
//! substitution, which never touches the wrapped reader at all once it has
//! decided to fake a byte. A real `Ok(0)` reaching `GuardedReader` can only
//! mean the underlying source ran out while the decoder was still asking for
//! bytes, which the full-stream measurement above shows never happens for a
//! genuinely complete stream. This is exactly the situation a cut of two or
//! more bytes also produces (in addition to the crate's own internal
//! consistency check failing); the one-byte cut is the sole case where the
//! crate's own logic reports success anyway, so `hit_eof` is what catches
//! it. Separately, [`GuardedReader::has_more`] answers the *other* question —
//! whether bytes remain unconsumed after a clean, non-truncated finish — via
//! one non-destructive `BufRead::fill_buf` call, the same mechanism
//! `lzma_c.rs`'s `RejectTrailingGarbage` uses. The two checks are
//! complementary, not redundant: `hit_eof` catches a stream that ends too
//! early, `has_more` catches one with extra bytes appended after a complete
//! one — see `truncated_by_exactly_one_byte_is_still_detected` and
//! `concatenated_streams_are_reported_as_corrupt_not_silently_truncated`.
//!
//! ## No concatenation convention — matches `lzma_c.rs`
//!
//! Same as the C backend: the `.lzma` alone format has no notion of
//! concatenated streams, so `cat a.lzma b.lzma` is one valid stream followed
//! by garbage, not two streams to decode in sequence. A reviewer confirmed
//! against real `xz`/`lzma` 5.8.3 that the reference tools reject trailing
//! NUL padding too, not just a second genuine stream — measured here against
//! `lzma-rust2` directly: both cases decode the first stream's payload with
//! `Ok` and no error from the raw crate (it never reads far enough to notice
//! anything follows), so [`GuardedReader::has_more`] is exactly what makes
//! this codec agree with the C backend and the reference tools instead of
//! silently truncating.
//!
//! ## Corruption detection: measured against this backend specifically
//!
//! Swept four payload shapes with `lzma_c.rs`'s own methodology (flip every
//! byte position of a real encoded stream, not one flip; separately truncate
//! at every prefix length): compressible text, incompressible random data,
//! all zeros, and (per this task's ruling) a source-corpus-shaped payload.
//! Zero silently-wrong decodes in any of them — every flipped position
//! either errored or reproduced the exact original plaintext. The positions
//! that reproduce the original untouched are exactly the header's declared
//! dictionary-size field (4 bytes, the same honest exception `lzma_c.rs`
//! documents) plus, only for this backend, the final 4 bytes of the range
//! coder's flush (the same flush bytes behind the truncation finding above —
//! their *values* don't affect the decoded output, only their *presence*
//! sometimes does). See `corruption_sweep_is_detected_almost_everywhere` for
//! the exact counts this backs `detects_corruption: true` with, and
//! `crate::normalize`'s `LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF` doc
//! for the raw error-kind vocabulary measured underneath.
//!
//! This is the same kind of guarantee `format.rs`'s `detects_corruption` doc
//! now documents for `lzma_c.rs`: detection by structural invalidity, not a
//! designed checksum — a high empirical rate against *random* corruption,
//! not a promise against a deliberately crafted edit.
//!
//! ## Level validation: not delegated to the crate, same reasoning as `xz_pure.rs`
//!
//! Measured directly: `lzma_rust2::LzmaOptions::with_preset`/`set_preset`
//! **silently clamps** an out-of-range preset (`preset.min(9)`) rather than
//! erroring — preset 10 and preset 99 both come back as preset 9's options,
//! no error, no panic. `check_encode_opts` below enforces `0..=9` itself,
//! independently of the crate, with the same message wording and exit code
//! `lzma_c.rs` uses (`Error::Usage`, exit 2), so `stf pack --format lzma
//! --level 99` behaves identically whichever backend a given build compiled.
//!
//! ## `memory_per_worker`: preset 6's dictionary
//!
//! `8 * 1024 * 1024` (8 MiB) — `LzmaOptions::PRESET_TO_DICT_SIZE[6]`, this
//! codec's default level when no `--level` is given, the same figure
//! `lzma_c.rs` declares for the same reason (see that module's `caps()` doc).

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};

use lzma_rust2::{LzmaOptions, LzmaReader, LzmaWriter};

use stuffr_core::{
    Codec, CodecCaps, DecodeOpts, EncodeOpts, Error, FormatId, Result, Sink, Source, StreamOnly,
};

pub use crate::lzma_shared::{LZMA, lzma_meta as meta};
use crate::normalize::{LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF, NormalizeDecodeErrors};

#[derive(Debug)]
pub struct Lzma;

impl Codec for Lzma {
    fn id(&self) -> FormatId {
        LZMA
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // Measured against THIS backend specifically — see the module
            // doc's "Corruption detection" section for the sweep.
            detects_corruption: true,
            // preset 6's dictionary (8 MiB) — see the module doc.
            memory_per_worker: Some(8 * 1024 * 1024),
            // A full codec, not a weaker stand-in: see
            // `it_is_a_full_codec_and_not_a_weak_one`.
            weak_encoder: false,
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `StreamOnly`: this crate exposes no frame/block index, so
    /// decoded output must not claim random access — see `lzma_c.rs`'s
    /// identical note.
    ///
    /// Wrapped in `NormalizeDecodeErrors` — see
    /// `LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF`'s doc for the
    /// measured kinds folded here. [`LazyLzmaDecoder`] itself raises
    /// `InvalidData` directly for the two cases only it can detect (a
    /// stream truncated by exactly one byte, and trailing bytes appended
    /// after a complete one) — see the module doc's "Truncation by exactly
    /// one byte" and "No concatenation convention" sections.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let dec = LazyLzmaDecoder::new(src);
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            dec,
            LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF,
        ))))
    }

    /// LZMA1's preset range, enforced here rather than delegated to
    /// `lzma_rust2` — see the module doc's "Level validation" section.
    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        match o.level {
            Some(n) if !(0..=9).contains(&n) => Err(Error::Usage(format!(
                "lzma compression level must be 0-9, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        // Not redundant with `ops`'s own pre-flight call: `encoder` is a
        // public trait method any caller can reach directly without going
        // through `ops`, and this is what stops an out-of-range preset
        // reaching `LzmaOptions::with_preset`, which would otherwise
        // silently clamp it rather than reject it — see the module doc.
        // Conformance property 6 keeps this in step with
        // `check_encode_opts`.
        self.check_encode_opts(o)?;
        let level = o.level.unwrap_or(6) as u32;
        let opts = LzmaOptions::with_preset(level);
        // `None`: the end-marker path — see the module doc's "The
        // end-marker path, verified" section for why `Some(len)` is wrong
        // here and what verifying `None` found.
        let writer = LzmaWriter::new_use_header(dst, &opts, None)?;
        Ok(Box::new(LzmaPureSink(writer)))
    }
}

struct LzmaPureSink(LzmaWriter<Box<dyn Write + Send>>);

impl Write for LzmaPureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for LzmaPureSink {
    /// Writes the closing chunk and the end-of-payload marker.
    ///
    /// `lzma_rust2::LzmaWriter::finish` returns `io::Result<W>` (the inner
    /// destination), propagating a genuine write error encountered during
    /// finalisation rather than discarding it — no `CaptureWriteError`
    /// adapter is needed here, the same as `xz_pure.rs`.
    fn finish(self: Box<Self>) -> Result<()> {
        let LzmaPureSink(writer) = *self;
        let mut w = writer.finish()?;
        w.flush()?;
        Ok(())
    }
}

/// Wraps the raw byte source so [`LazyLzmaDecoder`] can answer two questions
/// the crate's own `LzmaReader` cannot be asked directly — see the module
/// doc's "Truncation by exactly one byte" section for why both are needed
/// and why neither alone is enough.
struct GuardedReader {
    inner: BufReader<Box<dyn Source>>,
    /// Set the moment any `read()` call on this wrapper genuinely returns
    /// `Ok(0)` — real exhaustion of the underlying source, never the
    /// crate's own internal sentinel substitution, which does not go
    /// through this wrapper at all.
    hit_eof: bool,
}

impl GuardedReader {
    fn new(src: Box<dyn Source>) -> Self {
        Self {
            inner: BufReader::new(src),
            hit_eof: false,
        }
    }

    /// Non-destructive: is there anything left unconsumed in the underlying
    /// source? One `fill_buf` call, same mechanism `lzma_c.rs`'s
    /// `RejectTrailingGarbage` uses.
    fn has_more(&mut self) -> std::io::Result<bool> {
        Ok(!self.inner.fill_buf()?.is_empty())
    }
}

impl Read for GuardedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            self.hit_eof = true;
        }
        Ok(n)
    }
}

/// Defers `LzmaReader::new_mem_limit`'s construction to the first `read`
/// (see the module doc's "Deferred construction" section), and, once the
/// crate's own decode loop reports it is done, checks for exactly the two
/// failure modes the raw crate cannot itself detect — see the module doc's
/// "Truncation by exactly one byte" and "No concatenation convention"
/// sections.
enum LazyLzmaDecoder {
    Pending(Box<dyn Source>),
    Ready {
        // Boxed because `LzmaReader` is ~3,969 bytes while every other variant
        // here is at most 16, and this enum is assigned through `*self = ...`
        // on each state transition. Unboxed, `clippy::large_enum_variant` fails
        // the build, and rightly: every transition would move ~4 KiB.
        inner: Box<LzmaReader<GuardedReader>>,
        finished: bool,
    },
    /// The crate's own decode loop reported success, and both post-decode
    /// checks (truncation-by-one-byte, trailing garbage) passed. Every
    /// further read keeps returning `Ok(0)` without re-checking.
    Done,
    /// A prior read already failed. Reading again must keep failing rather
    /// than panic on an already-taken `Pending`/`Ready` value.
    Failed,
}

impl LazyLzmaDecoder {
    fn new(src: Box<dyn Source>) -> Self {
        Self::Pending(src)
    }
}

impl Read for LazyLzmaDecoder {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Same guard `zstd_pure.rs`'s `LazyRuzstdDecoder` and `lz4.rs`'s
        // `EnforceEndMark` use: an empty read must not be misread as a
        // genuine end-of-stream by the state machine below.
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self {
                LazyLzmaDecoder::Done => return Ok(0),
                LazyLzmaDecoder::Failed => {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "lzma-rust2: stream failed to decode",
                    ));
                }
                LazyLzmaDecoder::Pending(_) => {
                    let LazyLzmaDecoder::Pending(src) =
                        std::mem::replace(self, LazyLzmaDecoder::Failed)
                    else {
                        unreachable!("just matched Pending above")
                    };
                    let guarded = GuardedReader::new(src);
                    let dec = LzmaReader::new_mem_limit(guarded, u32::MAX, None)?;
                    *self = LazyLzmaDecoder::Ready {
                        inner: Box::new(dec),
                        finished: false,
                    };
                }
                LazyLzmaDecoder::Ready { inner, finished } if !*finished => {
                    let n = inner.read(buf)?;
                    if n > 0 {
                        return Ok(n);
                    }
                    *finished = true;
                }
                LazyLzmaDecoder::Ready { inner, .. } => {
                    if inner.inner_mut().hit_eof {
                        *self = LazyLzmaDecoder::Failed;
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "truncated LZMA1 stream: the decoder reached its end marker only \
                             by substituting a byte the source did not actually have",
                        ));
                    }
                    if inner.inner_mut().has_more()? {
                        *self = LazyLzmaDecoder::Failed;
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "trailing byte(s) after the LZMA1 stream's end marker — the alone \
                             format has no concatenation convention, so this is not valid \
                             additional data",
                        ));
                    }
                    *self = LazyLzmaDecoder::Done;
                    return Ok(0);
                }
            }
        }
    }
}

/// Compresses `plain` with this codec's default options, for tests only.
///
/// Mirrors `xz_c.rs`'s and `lzma_c.rs`'s helpers of the same name.
#[cfg(test)]
pub(crate) fn encode_for_test(plain: &[u8]) -> Vec<u8> {
    let buf = stuffr_core::testing::SharedBuf::new();
    let mut sink = Lzma
        .encoder(Box::new(buf.clone()), &EncodeOpts::default())
        .unwrap();
    sink.write_all(plain).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use stuffr_core::source::{SeekRead, SourceCaps};
    use stuffr_core::testing::SharedBuf;
    use stuffr_core::{DecodeOpts, EncodeOpts, ReaderSource, Source};

    use super::*;

    fn compress(plain: &[u8]) -> Vec<u8> {
        encode_for_test(plain)
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    fn encode_with(codec: &Lzma, plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = codec
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    #[cfg(feature = "lzma-c")]
    fn decode_with<C: stuffr_core::Codec>(codec: &C, packed: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let mut dec = codec.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    /// A `Source` that counts every byte actually read off it, so a test can
    /// tell how much of a compressed stream a decoder consumed before
    /// producing its first output — mirrors `xz_pure.rs`'s helper of the
    /// same name.
    struct MeteredSource {
        inner: std::io::Cursor<Vec<u8>>,
        consumed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl MeteredSource {
        fn new(bytes: Vec<u8>, consumed: std::sync::Arc<std::sync::atomic::AtomicU64>) -> Self {
            Self {
                inner: std::io::Cursor::new(bytes),
                consumed,
            }
        }
    }

    impl Read for MeteredSource {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.consumed
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(n)
        }
    }

    impl Source for MeteredSource {
        fn caps(&self) -> SourceCaps {
            SourceCaps {
                seekable: false,
                len: None,
            }
        }

        fn as_seek(&mut self) -> Option<&mut dyn SeekRead> {
            None
        }
    }

    #[test]
    fn lzma_pure_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Lzma, &meta());
    }

    #[test]
    fn it_is_a_full_codec_and_not_a_weak_one() {
        let c = Lzma.caps();
        assert!(c.encode && c.decode);
        assert!(!c.weak_encoder);
    }

    #[test]
    fn it_serves_output_before_it_has_read_everything() {
        let plain = stuffr_core::testing::incompressible(4 * 1024 * 1024);
        let packed = encode_with(&Lzma, &plain);
        let consumed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let src: Box<dyn Source> = Box::new(MeteredSource::new(packed, consumed.clone()));
        let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        let mut first = [0u8; 1024];
        let n = dec.read(&mut first).unwrap();
        assert!(n > 0);
        let read = consumed.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            read < 1024 * 1024,
            "read {read} bytes before its first output"
        );
    }

    /// LZMA1 has no magic and a loose header, so a mismatch between the two
    /// backends here would be invisible to detection and would only show up
    /// as a corrupt file.
    #[cfg(feature = "lzma-c")]
    #[test]
    fn the_two_backends_agree_in_both_directions() {
        let plain = b"cross-backend payload ".repeat(2048);
        let ours = encode_with(&Lzma, &plain);
        let theirs = crate::lzma_c::encode_for_test(&plain);
        assert_eq!(
            decode_with(&crate::lzma_c::Lzma, ours),
            plain,
            "liblzma cannot read ours"
        );
        assert_eq!(
            decode_with(&Lzma, theirs),
            plain,
            "we cannot read liblzma's"
        );
    }

    /// Pins the exact byte-for-byte agreement measured in the module doc:
    /// both backends write `5d 00 00 80 00 ff ff ff ff ff ff ff ff` and an
    /// identical total length for the same input under the end-marker path.
    #[cfg(feature = "lzma-c")]
    #[test]
    fn both_backends_write_an_identical_stream_for_the_same_input() {
        let plain = b"the end-marker path, verified ".repeat(40_000);
        let ours = encode_with(&Lzma, &plain);
        let theirs = crate::lzma_c::encode_for_test(&plain);
        assert_eq!(
            ours, theirs,
            "the end-marker path (None passed to new_use_header) must match liblzma byte-for-byte"
        );
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = compress(&plain);
        assert!(
            packed.len() < plain.len(),
            "lzma must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_lzma_alone_header() {
        let packed = compress(b"payload");
        assert_eq!(
            &packed[..13],
            &[
                0x5d, 0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ]
        );
    }

    #[test]
    fn encode_for_test_helper_produces_a_decodable_stream() {
        let packed = encode_for_test(b"cross-backend payload");
        assert_eq!(decompress(packed), b"cross-backend payload");
    }

    /// The measurement that ruled out a plain trailing-garbage check — see
    /// the module doc's "Truncation by exactly one byte" section. Without
    /// `GuardedReader`'s `hit_eof` flag, this decodes to the exact original
    /// plaintext with no error at all.
    #[test]
    fn truncated_by_exactly_one_byte_is_still_detected() {
        // COMPRESSIBLE payloads, deliberately, and this choice is the whole
        // point of the test. On an *incompressible* payload `lzma-rust2`
        // detects every short cut by itself, so a test using one passes with
        // `GuardedReader` deleted and proves nothing about the guard it exists
        // to protect. Measured on compressible text through the raw crate:
        // cuts of one *and two* bytes both return `Ok` with the exact original
        // plaintext. Only a compressible payload reaches the code path where
        // `RangeReader::read_u8` fakes a byte past real EOF.
        //
        // Both cut depths are checked because the module doc originally said
        // two-byte cuts are "detected every time" — measurement says otherwise
        // for compressible input, so the guard, not the crate, is what catches
        // them.
        for cut in [1usize, 2] {
            let plain: Vec<u8> = b"the quick brown fox jumps over the lazy dog\n"
                .repeat(4096)
                .to_vec();
            let packed = encode_with(&Lzma, &plain);
            let truncated = packed[..packed.len() - cut].to_vec();
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
            let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) => panic!(
                    "compressible stream cut short by {cut} byte(s) decoded without error \
                     — got {} of {} bytes; GuardedReader::hit_eof is not firing",
                    out.len(),
                    plain.len()
                ),
                Err(e) => assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidData,
                    "cut -{cut}: expected InvalidData after normalisation"
                ),
            }
        }
    }

    /// The incompressible case too, which the crate detects unaided — kept as a
    /// separate test so that if `lzma-rust2` ever changes its EOF handling, the
    /// two failures are distinguishable.
    #[test]
    fn truncated_incompressible_stream_is_detected_by_the_backend_itself() {
        let plain = stuffr_core::testing::incompressible(64 * 1024);
        let packed = encode_with(&Lzma, &plain);
        let truncated = packed[..packed.len() - 1].to_vec();
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
        let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        match dec.read_to_end(&mut out) {
            Ok(_) => panic!(
                "cut to the last byte decoded without error — got {} of {} bytes",
                out.len(),
                plain.len()
            ),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
        }
    }

    #[test]
    fn concatenated_streams_are_reported_as_corrupt_not_silently_truncated() {
        let mut two = compress(b"first-stream-");
        two.extend_from_slice(&compress(b"second-stream"));

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(two)));
        let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        match dec.read_to_end(&mut out) {
            Ok(_) => panic!(
                "expected trailing data after the first stream's end marker to be reported as \
                 corrupt; got Ok with {} bytes",
                out.len()
            ),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
        }
    }

    /// Matches `lzma_c.rs`'s equivalent measurement: the reference `xz`/`lzma`
    /// tools reject trailing NUL padding too, not just a second genuine
    /// stream, so this codec must as well.
    #[test]
    fn trailing_nul_padding_is_also_rejected() {
        let mut padded = compress(b"payload-with-nul-padding");
        padded.extend_from_slice(&[0u8; 16]);

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(padded)));
        let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        match dec.read_to_end(&mut out) {
            Ok(_) => panic!("expected trailing NUL padding to be reported as corrupt"),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
        }
    }

    #[test]
    fn a_single_stream_with_nothing_appended_decodes_cleanly() {
        let packed = compress(b"just one stream, nothing after it");
        assert_eq!(decompress(packed), b"just one stream, nothing after it");
    }

    #[test]
    fn level_zero_through_nine_are_all_accepted() {
        for n in 0..=9 {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            assert!(
                Lzma.check_encode_opts(&opts).is_ok(),
                "level {n} must be accepted"
            );
            assert!(
                Lzma.encoder(Box::new(SharedBuf::new()), &opts).is_ok(),
                "level {n} must be accepted by encoder() too"
            );
        }
    }

    #[test]
    fn an_out_of_range_level_is_a_usage_error_not_silently_clamped() {
        for n in [-1, 10, i32::MIN, i32::MAX] {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            match Lzma.check_encode_opts(&opts) {
                Err(err) => {
                    assert!(matches!(err, stuffr_core::Error::Usage(_)));
                    assert_eq!(err.exit_code(), 2);
                    assert!(
                        err.to_string().contains("0-9"),
                        "the error must name the real range: {err}"
                    );
                }
                Ok(_) => panic!("level {n} is out of range and must be rejected"),
            }
            match Lzma.encoder(Box::new(SharedBuf::new()), &opts) {
                Err(err) => assert!(matches!(err, stuffr_core::Error::Usage(_))),
                Ok(_) => panic!("encoder() must agree with check_encode_opts() and reject {n}"),
            }
        }
    }

    /// Measured directly: `LzmaOptions::with_preset`/`set_preset` silently
    /// CLAMPS an out-of-range preset (`preset.min(9)`) rather than erroring —
    /// see the module doc's "Level validation" section. This is what proves
    /// `check_encode_opts` catches the same inputs `lzma_c.rs` rejects, even
    /// though the crate itself would not.
    #[test]
    fn with_preset_silently_clamps_out_of_range_values() {
        assert_eq!(
            LzmaOptions::with_preset(9).dict_size,
            LzmaOptions::with_preset(10).dict_size
        );
        assert_eq!(
            LzmaOptions::with_preset(9).dict_size,
            LzmaOptions::with_preset(99).dict_size
        );
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Lzma.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        assert!(!c.weak_encoder, "a full codec, not a weaker fallback");
        let m = meta();
        assert_eq!(m.id, LZMA);
        assert_eq!(m.extensions, &["lzma"]);
        assert!(m.magics.is_empty());
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn lzma_declares_corruption_detection_and_a_memory_figure() {
        let c = Lzma.caps();
        assert!(
            c.detects_corruption,
            "measured against lzma-rust2 specifically; see the module doc"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    /// Sweeps every byte position of a real encoded payload — mirrors
    /// `lzma_c.rs`'s own sweep of the same name, against THIS backend.
    /// Backs `detects_corruption: true` with direct measurement and
    /// documents the honest exceptions: the header's dictionary-size field
    /// (4 bytes, same as `lzma_c.rs`) plus, only for this backend, the
    /// range coder's final flush bytes (4 more) — see the module doc's
    /// "Corruption detection" section.
    #[test]
    fn corruption_sweep_is_detected_almost_everywhere() {
        use stuffr_core::testing::incompressible;

        let plain = incompressible(4 * 1024);
        let packed = compress(&plain);

        let mut invalid_data = 0usize;
        let mut other_kind = 0usize;
        let mut silently_wrong = 0usize;
        let mut silently_unchanged = 0usize;
        for i in 0..packed.len() {
            let mut corrupted = packed.clone();
            corrupted[i] ^= 0xFF;
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(corrupted)));
            let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) if out == plain => silently_unchanged += 1,
                Ok(_) => silently_wrong += 1,
                Err(e) => match e.kind() {
                    std::io::ErrorKind::InvalidData => invalid_data += 1,
                    _ => other_kind += 1,
                },
            }
        }

        assert_eq!(
            silently_wrong, 0,
            "every flipped position must decode either to an error or to the exact original; \
             measured {silently_wrong} silently wrong"
        );
        assert_eq!(
            other_kind, 0,
            "NormalizeDecodeErrors folds every kind this backend raises onto InvalidData; \
             {other_kind} positions reported neither"
        );
        // The header's 4-byte dictionary-size field (same as `lzma_c.rs`)
        // plus this backend's own 4-byte flush-tail exception — see the
        // module doc. A different count means this measurement needs
        // redoing, not that the assertion is wrong.
        assert_eq!(
            silently_unchanged, 8,
            "expected exactly 8 unchecked bytes (4 header + 4 flush-tail); measured \
             {silently_unchanged}"
        );
        assert!(invalid_data > 0);
    }

    /// The truncation counterpart, including the one-byte cut that a plain
    /// trailing-garbage check cannot catch — see
    /// `truncated_by_exactly_one_byte_is_still_detected` for that case in
    /// isolation, and the module doc for why it needs `GuardedReader` at all.
    #[test]
    fn truncation_is_detected_at_every_cut() {
        let plain = stuffr_core::testing::incompressible(4 * 1024);
        let packed = compress(&plain);

        for cut in [1, packed.len() / 4, packed.len() / 2, packed.len() - 1] {
            let truncated = packed[..cut].to_vec();
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
            let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            match dec.read_to_end(&mut out) {
                Ok(_) => panic!(
                    "cut to {cut} of {} bytes decoded without error",
                    packed.len()
                ),
                Err(e) => assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidData,
                    "cut to {cut}: expected InvalidData after normalisation, got {:?}",
                    e.kind()
                ),
            }
        }
    }
}
