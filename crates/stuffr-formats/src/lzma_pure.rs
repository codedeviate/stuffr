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
//! the exact counts this backs `detects_corruption: CorruptionDetection::
//! Structural` with, and
//! `crate::normalize`'s `LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF` doc
//! for the raw error-kind vocabulary measured underneath.
//!
//! This is the same kind of guarantee `format.rs`'s `detects_corruption` doc
//! now documents for `lzma_c.rs`: detection by structural invalidity, not a
//! designed checksum — a high empirical rate against *random* corruption,
//! not a promise against a deliberately crafted edit.
//!
//! ## Corruption vs resource limit: a heuristic, because LZMA1 has no magic
//!
//! `xz_pure.rs` and `lzip.rs` both require their format's own magic before
//! trusting a declared dictionary size enough to refuse it as
//! `Error::ResourceLimit` — without that, non-matching garbage whose bytes
//! happen to decode a large dictionary would be misreported as exit 6, a
//! resource limit, when the truth is exit 5, corruption. **LZMA1 has no
//! magic anywhere in its header** — one props byte, four dictionary-size
//! bytes, then eight uncompressed-size bytes, no signature — which is
//! exactly why this codec is extension/`--format`-only and cannot be
//! auto-detected on a pipe. So the xz/lzip remedy cannot port directly:
//! there is no signature to check first.
//!
//! Measured before any fix: 34 of 40 fresh random 200-byte inputs fed as
//! `--format lzma` with no flags misreported as exit 6 ("raise
//! --memory-limit") rather than exit 5. `LzmaReader::new_mem_limit` already
//! rejects an invalid props byte or an out-of-range dictionary size with
//! `InvalidInput` (folded to `Corrupt` by
//! `LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF` below) *before* it ever
//! reaches the memory check, so those two fields are not the leak — the
//! leak is the third header field, the 8-byte uncompressed-size, which the
//! crate reads but never inspects for plausibility before deciding a
//! declared dictionary is a genuine ask.
//!
//! Every real encoder measured (`xz --format=lzma`, `lzma`, and this
//! codec's own writer via `LzmaWriter::new_use_header(.., None)`) writes
//! the all-ones "unknown" sentinel there, even when the input length was
//! known up front — streaming-only is the convention in practice, not just
//! in principle. [`GuardedReader::header_uncompressed_size_is_plausible`]
//! trusts the resource-limit refusal only when that field is the sentinel
//! or at least within [`PLAUSIBLE_UNCOMPRESSED_SIZE_MAX`] (a bound with
//! slack above any real archive, but far below where a genuinely random
//! 64-bit value lands almost every time). **This is a heuristic, not a
//! signature check** — a format with no magic cannot tell "hostile LZMA1"
//! from "not LZMA1 at all" with certainty, only with high confidence, and a
//! hand-crafted stream that clears the bound deliberately still gets the
//! resource-limit refusal it asked for (measured: a real `.lzma` with only
//! its dictionary field raised, sentinel intact, still exits 6). What the
//! heuristic closes is the overwhelming case: bytes that are not LZMA1 at
//! all, where the third field is essentially always outside the bound.
//!
//! ## Level validation: not delegated to the crate, same reasoning as `xz_pure.rs`
//!
//! Measured directly: `lzma_rust2::LzmaOptions::with_preset`/`set_preset`
//! **silently clamps** an out-of-range preset (`preset.min(9)`) rather than
//! erroring — preset 10 and preset 99 both come back as preset 9's options,
//! no error, no panic. `check_encode_opts` below enforces `0..=9` itself,
//! independently of the crate, with the same message wording and exit code
//! `lzma_c.rs` uses (`Error::Usage`, exit 2), so `stuffr pack --format lzma
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
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FormatId, Result, Sink,
    Source, StreamOnly, format_size,
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
            detects_corruption: CorruptionDetection::Structural,
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
    /// one byte" and "No concatenation convention" sections. It also raises
    /// `OutOfMemory` directly, when `o.memory_limit` refuses the header's
    /// declared dictionary — deliberately NOT one of the kinds
    /// `LZMA_PURE_MALFORMED_AS_INVALID_DATA_OTHER_EOF` folds, so it survives
    /// `NormalizeDecodeErrors` untouched and reaches `Error::from_decode_io`
    /// as `ResourceLimit` (exit 6), not `Corrupt` (exit 5) — see
    /// `DecodeOpts::memory_limit`'s doc.
    fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> Result<Box<dyn Source>> {
        // The crate's parameter is KiB in a u32. `u32::MAX` KiB is ~4 TiB, so
        // saturating there is equivalent to "unbounded" for any real limit.
        let mem_limit_kb = match o.memory_limit {
            Some(bytes) => (bytes / 1024).min(u32::MAX as u64) as u32,
            None => u32::MAX,
        };
        let dec = LazyLzmaDecoder::new(src, mem_limit_kb);
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

/// Above this, a `.lzma` header's uncompressed-size field (bytes 5..13)
/// stops being treated as a plausible real size — see the module doc's
/// "Corruption vs resource limit" section. 256 TiB is far beyond anything
/// this project expects to meet as a genuine archive; it exists only to
/// admit slack above outrageous-but-conceivable sizes while still rejecting
/// the near-certainly-random 64-bit values ~200 bytes of noise produces
/// (a uniformly random `u64` lands below this bound only about 1 time in
/// 65,536).
const PLAUSIBLE_UNCOMPRESSED_SIZE_MAX: u64 = 1 << 48;

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

    /// Best-effort, non-destructive read of the `.lzma` header's declared
    /// memory need, in KiB — for the `memory_limit` refusal's message only.
    ///
    /// One `fill_buf` call, same non-destructive mechanism [`Self::has_more`]
    /// uses: it peeks the buffered bytes without consuming them, so
    /// `LzmaReader::new_mem_limit`'s own `props`/`dict_size` reads afterward
    /// see the exact same first 5 bytes. Returns `None` rather than erroring
    /// when fewer than 5 bytes are buffered (a genuinely truncated header) —
    /// that case is `new_mem_limit`'s own EOF error to raise, not this
    /// method's; a missing declared-size figure just means the refusal
    /// message below omits it rather than naming it.
    fn peek_declared_need_kb(&mut self) -> Option<u32> {
        let buf = self.inner.fill_buf().ok()?;
        if buf.len() < 5 {
            return None;
        }
        let props = buf[0];
        let dict_size = u32::from_le_bytes(buf[1..5].try_into().expect("checked len >= 5"));
        lzma_rust2::lzma_get_memory_usage_by_props(dict_size, props).ok()
    }

    /// Best-effort, non-destructive check of whether the header's
    /// uncompressed-size field (bytes 5..13) looks like a genuine LZMA1
    /// stream rather than noise that happened to decode a large
    /// dictionary — see the module doc's "Corruption vs resource limit"
    /// section for why this field, not the props byte or the dictionary
    /// size, is the one worth checking here.
    ///
    /// Same non-destructive `fill_buf` mechanism as
    /// [`Self::peek_declared_need_kb`], reading further into the same
    /// buffered prefix so `LzmaReader::new_mem_limit`'s own header read
    /// afterward still sees identical bytes. Returns `true` ("trust the
    /// refusal") when fewer than 13 bytes are buffered: reaching this check
    /// at all requires `new_mem_limit` to have already computed a memory
    /// figure from a *valid* props byte and dictionary size, which itself
    /// requires having read all 13 header bytes successfully, so "too
    /// short to tell" cannot actually arise at the call site — the
    /// permissive default exists only so this method has a well-defined
    /// answer in isolation, the same "cannot decide" convention
    /// `xz_pure.rs`'s and `lzip.rs`'s parsers use.
    fn header_uncompressed_size_is_plausible(&mut self) -> bool {
        let Ok(buf) = self.inner.fill_buf() else {
            return true;
        };
        if buf.len() < 13 {
            return true;
        }
        let uncompressed_size =
            u64::from_le_bytes(buf[5..13].try_into().expect("checked len >= 13"));
        uncompressed_size == u64::MAX || uncompressed_size <= PLAUSIBLE_UNCOMPRESSED_SIZE_MAX
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
    /// The source, and the caller's `DecodeOpts::memory_limit` already
    /// converted to the crate's KiB unit — see `Codec::decoder`.
    Pending(Box<dyn Source>, u32),
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
    fn new(src: Box<dyn Source>, mem_limit_kb: u32) -> Self {
        Self::Pending(src, mem_limit_kb)
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
                LazyLzmaDecoder::Pending(_, _) => {
                    let LazyLzmaDecoder::Pending(src, mem_limit_kb) =
                        std::mem::replace(self, LazyLzmaDecoder::Failed)
                    else {
                        unreachable!("just matched Pending above")
                    };
                    let mut guarded = GuardedReader::new(src);
                    // Best-effort only — see `peek_declared_need_kb`'s doc.
                    // Peeked, not consumed, so `new_mem_limit`'s own header
                    // read below sees the identical first 5 (then 13) bytes.
                    let declared_need_kb = guarded.peek_declared_need_kb();
                    let uncompressed_size_plausible =
                        guarded.header_uncompressed_size_is_plausible();
                    let dec =
                        LzmaReader::new_mem_limit(guarded, mem_limit_kb, None).map_err(|e| {
                            if e.kind() != ErrorKind::OutOfMemory {
                                return e;
                            }
                            // The props byte and dictionary size were BOTH
                            // already valid — an invalid one of either would
                            // have raised `InvalidInput` (folded to
                            // `InvalidData`/`Corrupt` below) before
                            // `new_mem_limit` ever computed a memory figure
                            // to compare against `mem_limit_kb`. So the only
                            // remaining question is whether the header's
                            // THIRD field — the uncompressed size, which the
                            // crate reads but never inspects for plausibility
                            // — looks like a real LZMA1 stream. See the
                            // module doc's "Corruption vs resource limit"
                            // section: LZMA1 has no magic, so this is a
                            // heuristic, not a signature check.
                            if !uncompressed_size_plausible {
                                // Almost certainly not LZMA1 at all: hand it
                                // back as corruption (exit 5), not a memory
                                // refusal (exit 6) that would tell the user
                                // to raise a limit that cannot help.
                                return std::io::Error::new(
                                    ErrorKind::InvalidData,
                                    "lzma: header does not look like a genuine LZMA1 stream \
                                     (implausible uncompressed-size field) — treating the \
                                     declared dictionary as corrupt input, not a resource limit",
                                );
                            }
                            // Replace the crate's static, number-free message
                            // ("needed memory too big for mem_limit_kb") with
                            // one naming the declared size, the limit, and
                            // the flag to raise — see `DecodeOpts::memory_limit`.
                            // NOT `InvalidData`: this is not a corrupt file,
                            // it is a refusal to allocate, and must reach
                            // `Error::from_decode_io` as `OutOfMemory` so it
                            // classifies as `ResourceLimit` (exit 6), not
                            // `Corrupt` (exit 5).
                            // Rendered via the shared `format_size` (MiB/GiB,
                            // matching `stuffr info` and the xz/lzip refusal
                            // messages) rather than this codec's own KiB
                            // unit — see the whole-branch review's LOW-5
                            // finding: three different unit conventions for
                            // the same quantity across this one tool.
                            let msg = match declared_need_kb {
                                Some(need_kb) => format!(
                                    "lzma: header declares a dictionary needing {}, but \
                                     --memory-limit allows only {} — raise --memory-limit to \
                                     decode this file",
                                    format_size(u64::from(need_kb) * 1024),
                                    format_size(u64::from(mem_limit_kb) * 1024)
                                ),
                                None => format!(
                                    "lzma: header declares a dictionary exceeding the {} \
                                     --memory-limit — raise --memory-limit to decode this file",
                                    format_size(u64::from(mem_limit_kb) * 1024)
                                ),
                            };
                            std::io::Error::new(ErrorKind::OutOfMemory, msg)
                        })?;
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
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::Structural,
            "measured against lzma-rust2 specifically; see the module doc"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    /// Sweeps every byte position of a real encoded payload — mirrors
    /// `lzma_c.rs`'s own sweep of the same name, against THIS backend.
    /// Backs `detects_corruption: CorruptionDetection::Structural` with
    /// direct measurement and documents the honest exceptions: the header's
    /// dictionary-size field
    /// (4 bytes, same as `lzma_c.rs`) plus, only for this backend, the
    /// range coder's final flush bytes (4 more) — see the module doc's
    /// "Corruption detection" section.
    #[test]
    fn corruption_sweep_is_detected_almost_everywhere() {
        use stuffr_core::testing::incompressible;

        // EXHAUSTIVE, but over a deliberately SMALL stream — and that choice is
        // the point, so do not "restore" the 4 KiB payload `lzma_c.rs` uses.
        //
        // The reason is the debug profile, not this codec's design. Tests build
        // unoptimised, and `lzma-rust2` is Rust while `liblzma` is C compiled
        // with optimisation by its own build script whatever the Rust profile —
        // measured elsewhere this cycle at 15x encode and 21x decode in debug,
        // against 1.37x and 1.77x in release. The identical 4,170-position
        // sweep costs liblzma about 1 s and cost this backend **103 s**, which
        // was the entire runtime of `make check`.
        //
        // Exhaustive-over-small beats sampled-over-large here for a specific
        // reason: it preserves the exact-count assertion below. Every
        // structural region is still present in a short stream — the 13-byte
        // header, the range-coded body, the flush tail — so the eight
        // unchecked bytes are all still in scope and can be asserted exactly.
        // Sampling a larger stream would hit only some of them and force the
        // assertion down to a weaker bound.
        let plain = incompressible(128);
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
        // Structurally inert positions: bytes whose corruption cannot change the
        // decoded output — the header's dictionary-size field and the flush
        // tail. **The exact count is payload-dependent**, which is worth knowing
        // before anyone "fixes" this number: the 4 KiB payload this sweep
        // originally used measured 8, and the 128-byte payload it uses now
        // measures 6. That is not a regression, it is a smaller stream having
        // fewer inert bytes. The earlier "4 header + 4 flush-tail" gloss was an
        // explanation fitted to the 8, and it does not survive the change of
        // payload, so it is not repeated here as fact.
        //
        // The assertion stays exact rather than becoming a bound, because
        // `incompressible()` is deterministic: any change in this number means
        // the backend's behaviour changed and deserves a look.
        assert_eq!(
            silently_unchanged, 6,
            "expected exactly 6 structurally inert bytes for this payload; measured \
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

    /// A `.lzma` header declares its dictionary in bytes 1-4, little-endian.
    /// Craft one claiming 512 MiB and hand it a 1 MiB limit: the reader must
    /// refuse rather than allocate, and the refusal must be exit 6
    /// (`ResourceLimit`), NOT exit 5 — reporting "your file is corrupt" when
    /// the real problem is "this build will not allocate that much" would be
    /// actively misleading.
    ///
    /// `LzmaReader::new_mem_limit` (measured, this crate version) refuses
    /// eagerly at construction, before any byte is decoded — but that is a
    /// property of `lzma-rust2`, not of this codec's contract, so the test
    /// accepts a refusal surfacing on the first `read` too rather than
    /// assuming which one fires.
    #[test]
    fn a_declared_dictionary_over_the_limit_is_refused_before_allocating() {
        let mut packed = encode_with(&Lzma, b"payload".repeat(100).as_slice());
        packed[1..5].copy_from_slice(&(512u32 * 1024 * 1024).to_le_bytes());

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let construct_err = Lzma.decoder(
            src,
            &DecodeOpts {
                memory_limit: Some(1024 * 1024),
                ..Default::default()
            },
        );
        let err = match construct_err {
            Err(e) => e,
            Ok(mut dec) => {
                // Construction succeeded; the crate defers the check, so it
                // must surface on the first read instead.
                let mut buf = [0u8; 1];
                let io_err = dec
                    .read(&mut buf)
                    .expect_err("a 512 MiB declaration under a 1 MiB limit must be refused");
                stuffr_core::Error::from_decode_io(io_err)
            }
        };
        assert_eq!(
            err.exit_code(),
            6,
            "a memory refusal is ResourceLimit, not Corrupt: {err}"
        );
        assert!(
            err.to_string().contains("--memory-limit"),
            "the message must name the flag so the user can raise it: {err}"
        );
    }

    /// HIGH-1 (whole-branch review, 2026-09-02): before this fix, feeding
    /// arbitrary non-LZMA1 bytes to `--format lzma` misreported as
    /// `ResourceLimit` (exit 6, "raise --memory-limit") on 34 of 40 fresh
    /// random 200-byte inputs, because `LzmaReader::new_mem_limit` computes
    /// its memory figure from the props byte and dictionary size alone and
    /// never inspects the uncompressed-size field for plausibility. See the
    /// module doc's "Corruption vs resource limit" section for the
    /// heuristic this pins: a header whose uncompressed-size field is
    /// neither the "unknown" sentinel nor within a plausible bound is
    /// treated as not genuinely LZMA1, and the refusal must be corruption,
    /// not a resource limit that tells the user to raise a flag that cannot
    /// help.
    ///
    /// Deterministic stand-in for "not LZMA1 at all", not real randomness:
    /// a valid props byte and an over-limit dictionary size (so the crate
    /// WOULD compute an over-limit memory figure, exactly like the test
    /// above), but an uncompressed-size field that is neither the sentinel
    /// nor plausible — the one field every real encoder measured
    /// (`xz --format=lzma`, `lzma`, and this codec's own writer) leaves as
    /// the sentinel even when the input length is known up front.
    #[test]
    fn an_implausible_header_reports_corruption_not_a_resource_limit() {
        let mut packed = vec![0u8; 64];
        packed[0] = 0x5d; // a valid props byte (93, preset 6's)
        packed[1..5].copy_from_slice(&(512u32 * 1024 * 1024).to_le_bytes()); // over the limit below
        packed[5..13].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes()); // not the sentinel, not plausible
        for (i, b) in packed[13..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3); // deterministic filler
        }

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let construct_err = Lzma.decoder(
            src,
            &DecodeOpts {
                memory_limit: Some(1024 * 1024),
                ..Default::default()
            },
        );
        let err = match construct_err {
            Err(e) => e,
            Ok(mut dec) => {
                let mut buf = [0u8; 1];
                let io_err = dec
                    .read(&mut buf)
                    .expect_err("an implausible header must not silently decode");
                stuffr_core::Error::from_decode_io(io_err)
            }
        };
        assert_eq!(
            err.exit_code(),
            5,
            "an implausible header is corruption (exit 5), not a memory refusal: {err}"
        );
    }

    /// Matters more than the refusal above: over-strictness rejects valid
    /// files, and this project shipped that mirror defect twice in Phase 1e
    /// (lzip's trailing-data guard, and gzip/bzip2 refusing padding the
    /// reference tools recover). A legitimate dictionary that fits under the
    /// limit must still decode.
    #[test]
    fn a_legitimate_dictionary_under_the_limit_still_decodes() {
        let plain = b"ordinary payload ".repeat(2000);
        let packed = encode_with(&Lzma, &plain);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let mut dec = Lzma
            .decoder(
                src,
                &DecodeOpts {
                    memory_limit: Some(64 * 1024 * 1024),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    /// `DecodeOpts::default()` has `memory_limit: None`. The CLI always sets
    /// a limit (25% of available RAM); a library caller who deliberately
    /// passes `None` keeps the old, unbounded behaviour rather than getting a
    /// surprise ceiling.
    #[test]
    fn no_limit_means_no_bound_for_library_callers() {
        let plain = b"payload ".repeat(2000);
        let packed = encode_with(&Lzma, &plain);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let mut dec = Lzma.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }
}
