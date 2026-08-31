//! LZIP (`.lz`), pure Rust, via `lzma-rust2` — the same dependency
//! `lzma_pure.rs` and `xz_pure.rs` use, and this crate's third format built
//! on it. A full codec: encode AND decode, no `weak_encoder`.
//!
//! ## No shared module, and that is a deliberate departure
//!
//! `xz_shared.rs`, `lzma_shared.rs` and `zstd_shared.rs` each exist because
//! their format has TWO backends (a C one and a pure one) that must agree on
//! the same [`stuffr_core::FormatId`], magic rule and [`stuffr_core::
//! FormatMeta`] — neither backend module can own that identity, because a
//! build with only one of the two features has no module for the other to
//! share with. LZIP has no such pair: `lzma-rust2` is the only backend this
//! project has (or plans), so there is nothing a second module would need to
//! agree with. `LZIP`, [`meta`] and the magic rule live directly in this
//! module for exactly that reason — introducing a `lzip_shared.rs` with one
//! consumer would be a shape copied from the pairs above without the
//! constraint that motivates it there.
//!
//! ## The backend has a silent-data-loss defect — measured directly
//!
//! `lzma_rust2::lzip::reader::LzipReader::start_next_member` (0.20.1) treats
//! ANY failure to parse the next member's 6-byte header — a magic mismatch,
//! an unsupported version byte, an invalid dictionary-size byte — as "no
//! more members, clean end of stream":
//!
//! ```text
//! let header = match LzipHeader::parse(&mut reader) {
//!     Ok(header) => header,
//!     Err(_) => {
//!         self.inner = Some(reader);
//!         return Ok(false);   // <- "EOF", not "corrupt"
//!     }
//! };
//! ```
//!
//! That is the right call for a genuine, empty tail after the last member.
//! It is the wrong call for a damaged header, and the two are indistinguishable
//! to this code: both look like "the next 4-6 bytes are not a valid LZIP
//! header". Measured directly against three shapes:
//!
//! | input | measured result |
//! |---|---|
//! | any of the first member's 6 header bytes flipped | `Ok`, 0 bytes output |
//! | any of the second member's 4 magic bytes flipped (2-member concatenation) | `Ok`, only the first member's bytes — the second silently dropped |
//! | entirely non-LZIP input (plain text) | `Ok`, 0 bytes output |
//! | payload bytes corrupted (member intact otherwise) | `Err` — `reader.rs`'s trailer CRC32 check does fire |
//! | intact 2-member concatenation | correct, both members' bytes |
//! | truncation | `Err` |
//!
//! Untreated, `stf cat --format lzip notes.txt` on a file with a damaged
//! later member prints only the earlier members' data and exits 0 — silent
//! data loss, indistinguishable from a short, honest file.
//!
//! ## The fix: two checks, closing two different gaps
//!
//! [`GuardedLzipReader`] adds exactly the two checks the raw crate cannot
//! do for itself, and they are not redundant with each other:
//!
//! 1. **The first member's magic is verified before `LzipReader` ever sees
//!    it.** One non-destructive `BufRead::fill_buf` call peeks the first
//!    four bytes; a mismatch (or too few bytes to have any) is `InvalidData`
//!    immediately. This alone catches non-LZIP input and a damaged first
//!    header — but NOT a damaged later member, because by the time that
//!    member's bytes are current, this check has already run and passed.
//! 2. **Once `LzipReader` itself reports `Ok(0)`, this wrapper checks
//!    whether the underlying reader still holds any unconsumed bytes** —
//!    the same peek-without-consuming `fill_buf` mechanism, at the opposite
//!    end of the stream. A genuinely finished stream has nothing left; a
//!    stream that stopped early because a later member's header failed to
//!    parse still has that member's undigested bytes sitting there. This is
//!    the same mechanism `lzma_c.rs`'s `RejectTrailingGarbage` uses, reused
//!    rather than reinvented — see that module's doc — though what it
//!    means here differs: there it is "extra data appended after one
//!    complete stream"; here it is "a later member's header that the crate
//!    swallowed as if it were the end". `lzma_pure.rs`'s `GuardedReader`
//!    is the other prior art surveyed and not the fit here: its `hit_eof`
//!    flag exists because the crate it wraps FAKES a sentinel byte past
//!    real EOF, so a plain "anything left over" peek cannot tell a one-byte
//!    truncation from a genuine finish. `LzipReader` has no equivalent —
//!    measured truncation already reports `Err` unaided (see the table
//!    above) — so only the `has_more`-shaped half of that prior art is
//!    needed, not the `hit_eof` half.
//!
//! Check 2 is not a special case of check 1: check 1 only ever looks at the
//! stream's first four bytes. A later member's header, corrupted or not,
//! is invisible to it — by the time those bytes are current, `LzipReader`
//! has already consumed and validated everything before them.
//!
//! Both checks raise `io::ErrorKind::InvalidData` directly (they are this
//! codec's own classification, not a raw error the backend produced), so
//! neither needs folding through [`crate::normalize::NormalizeDecodeErrors`]
//! — that wrapper exists for the raw error kinds the backend itself raises
//! on a genuinely malformed member it DOES detect (CRC/data-size/member-size
//! mismatch, a corrupted embedded LZMA1 body), which is a different set. See
//! [`crate::normalize::LZIP_MALFORMED_AS_INVALID_DATA`]'s doc for that
//! measurement.
//!
//! ## Corruption detection: `Always`, and why the header blind spot does not undermine it
//!
//! LZIP mandates a CRC32 in every member's trailer, and `LzipReader` verifies
//! it (`reader.rs`'s `finish_current_member`) — a format-wide guarantee, not
//! a per-writer option the way xz's check-type field or zstd's content
//! checksum are, and not close analysis needed the way LZMA1's checksumless
//! structural detection is. That is [`CorruptionDetection::Always`]'s exact
//! shape.
//!
//! The header-byte blind spot the sections above document might look like it
//! contradicts that claim — a damaged header WAS a silent, undetected failure
//! before this codec's own checks existed. It does not survive scrutiny: that
//! blind spot lived entirely in the raw `lzma_rust2::LzipReader`, not in the
//! format's own CRC32 guarantee, and it is exactly what [`GuardedLzipReader`]
//! closes. With the fix in place, a corrupted header is caught by check 1 or
//! check 2 above, and a corrupted payload is caught by the mandated CRC32 the
//! same as always. Measured directly with the same sweep methodology used
//! throughout this project (flip every byte position of a real one-member
//! encoded stream, not one flip): every position either errors or reproduces
//! the exact original, with exactly ONE honest exception — 2 of 173 swept
//! positions, both in the embedded LZMA1 body's range-coder flush tail,
//! where the flipped byte's VALUE provably never reaches the decoded output
//! at all, only its presence would. That is not a gap in the CRC32
//! guarantee: nothing in the content actually changed, so there is nothing
//! for any checksum to catch, LZIP's included — the same shape `snappy.rs`'s
//! own `Always` sweep documents for its one framing-byte exception, and the
//! same underlying phenomenon `lzma_pure.rs`'s sweep documents for the
//! identical `lzma_rust2` LZMA1 encoder/decoder pair. See
//! `corruption_sweep_is_detected_everywhere` for the exact counts.
//!
//! ## Level validation: enforced here, not delegated to the crate
//!
//! `LzipOptions::with_preset` forwards to `LzmaOptions::with_preset`, which
//! `lzma_pure.rs`'s module doc already measured silently CLAMPS an
//! out-of-range preset (`preset.min(9)`) rather than erroring — verified
//! again here directly against `LzipOptions::with_preset` specifically,
//! since a different entry point could in principle behave differently (it
//! does not: see `with_preset_silently_clamps_out_of_range_values`).
//! `check_encode_opts` enforces LZIP's real range, `0..=9` — the same range
//! LZMA1 and xz use, because LZIP's payload IS an LZMA1 stream with no
//! format-specific preset extension — independently of the crate, with the
//! same message wording and exit code (`Error::Usage`, exit 2) the other two
//! `lzma-rust2`-backed codecs in this project use.
//!
//! ## `memory_per_worker`: preset 6's dictionary
//!
//! `8 * 1024 * 1024` (8 MiB) — the same figure `lzma_pure.rs` and
//! `lzma_c.rs` declare for the same reason: LZIP's payload is an LZMA1
//! stream, and preset 6 (this codec's default level when no `--level` is
//! given) uses an 8 MiB dictionary.
//!
//! ## Cross-implementation validation: the reference `lzip` tool, plus liblzma at the payload level
//!
//! Two independent checks, at two different layers, and neither subsumes the
//! other.
//!
//! **The reference `lzip` 1.26 tool**, run directly (skipped cleanly, not
//! failed, on a machine without it — see `which_lzip`, the same shape
//! `xz_pure.rs`'s `which_xz` uses): [`the_system_lzip_tool_accepts_what_this_writes`]
//! writes with this codec and confirms `lzip -t` and `lzip -dc` both accept
//! it and decode it byte-for-byte; [`this_codec_decodes_what_the_system_lzip_tool_writes`]
//! is the reverse direction, decoding a member the reference tool produced;
//! [`the_system_lzip_tool_agrees_on_a_two_member_concatenation`] targets this
//! task's whole reason for existing directly — LZIP's own multi-member
//! concatenation, decoded independently by this codec and by `lzip -dc`,
//! must agree — this is the same defect CLASS (a concatenated stream
//! silently truncated to less than all of it) that has bitten gzip, bzip2,
//! xz and LZMA1 elsewhere in this project, so proving THIS codec gets the
//! genuine, undamaged case right, not only the damaged-header case the
//! regression tests above cover, matters on its own. This validates the
//! outer container this codec writes and reads — the layer the liblzma
//! check below cannot reach at all, since `liblzma` has no notion of an
//! LZIP member or its trailer.
//!
//! **`liblzma`, at the payload level, gated `#[cfg(feature = "lzma-c")]`:**
//! an LZIP member is exactly a 6-byte header (4-byte `"LZIP"` magic, 1-byte
//! version, 1-byte encoded dictionary size), then a raw LZMA1 stream with no
//! header of its own, then a 20-byte trailer (CRC32, 8-byte data size,
//! 8-byte member size, all little-endian) — and the `.lzma` "alone" format's
//! header is just a properties byte plus a 4-byte raw dictionary size plus
//! an 8-byte size field, wrapping the same kind of raw LZMA1 stream
//! `lzma_c.rs` and `lzma_pure.rs` already validate against `liblzma`. So a
//! member's payload can be re-wrapped in a synthesized `.lzma`-alone header
//! and handed to `liblzma` directly. [`the_alone_reconstruction_is_decoded_correctly_by_liblzma`]
//! does exactly that, and it passed: `liblzma` decoded the reconstruction
//! byte-for-byte. This is complementary to the `lzip`-binary checks above,
//! not redundant with them: it validates the compressed LZMA1 DATA member by
//! member, independently of this project's own two LZMA1 backends agreeing,
//! while the `lzip`-binary checks validate the outer LZIP container (the
//! header, trailer and multi-member framing) that `liblzma` never sees.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};

use lzma_rust2::{LzipOptions, LzipReader, LzipWriter};

use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FormatId, FormatMeta,
    MagicRule, Result, Sink, Source, StreamOnly,
};

use crate::normalize::{LZIP_MALFORMED_AS_INVALID_DATA, NormalizeDecodeErrors};

/// The four-byte magic every LZIP member's header begins with.
const MAGIC_BYTES: &[u8; 4] = b"LZIP";

/// This codec's identity. No sibling backend exists to share it with — see
/// the module doc's "No shared module" section.
pub const LZIP: FormatId = FormatId::new("lzip");

const LZIP_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: MAGIC_BYTES,
    format: LZIP,
}];

/// Registration metadata for LZIP.
pub fn meta() -> FormatMeta {
    FormatMeta::codec(LZIP, &["lz"], LZIP_MAGIC)
}

#[derive(Debug)]
pub struct Lzip;

impl Codec for Lzip {
    fn id(&self) -> FormatId {
        LZIP
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // The format mandates a CRC32 in every member's trailer, and
            // this backend verifies it — see the module doc's "Corruption
            // detection" section for why the header blind spot this codec
            // closes does not undermine the claim.
            detects_corruption: CorruptionDetection::Always,
            // preset 6's dictionary (8 MiB) — see the module doc.
            memory_per_worker: Some(8 * 1024 * 1024),
            weak_encoder: false,
            ..CodecCaps::round_trip()
        }
    }

    /// Wrapped in `StreamOnly`: this crate exposes no frame/block index
    /// this codec surfaces as random access, so decoded output must not
    /// claim seekability.
    ///
    /// Wrapped in [`GuardedLzipReader`] before `NormalizeDecodeErrors` — see
    /// the module doc's "The fix" section for why both of its checks are
    /// needed and raise `InvalidData` directly. Wrapped in
    /// `NormalizeDecodeErrors` for the raw kinds the backend itself raises
    /// on a member it DOES recognize as malformed — see
    /// `crate::normalize::LZIP_MALFORMED_AS_INVALID_DATA`'s doc.
    fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let guarded = GuardedLzipReader::new(src);
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            guarded,
            LZIP_MALFORMED_AS_INVALID_DATA,
        ))))
    }

    /// LZIP's payload is an LZMA1 stream, so its preset range is the same
    /// `0..=9` `lzma_c.rs` and `lzma_pure.rs` enforce — see the module
    /// doc's "Level validation" section for why this is not delegated to
    /// `LzipOptions::with_preset`.
    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        match o.level {
            Some(n) if !(0..=9).contains(&n) => Err(Error::Usage(format!(
                "lzip compression level must be 0-9, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        // Not redundant with `ops`'s own pre-flight call: `encoder` is a
        // public trait method any caller can reach directly without going
        // through `ops`, and this is what stops an out-of-range preset
        // reaching `LzipOptions::with_preset`, which would otherwise
        // silently clamp it rather than reject it — see the module doc.
        // Conformance property 6 keeps this in step with
        // `check_encode_opts`.
        self.check_encode_opts(o)?;
        let level = o.level.unwrap_or(6) as u32;
        let opts = LzipOptions::with_preset(level);
        let writer = LzipWriter::new(dst, opts);
        Ok(Box::new(LzipSink(writer)))
    }
}

struct LzipSink(LzipWriter<Box<dyn Write + Send>>);

impl Write for LzipSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for LzipSink {
    /// Writes the trailer of the last open member.
    ///
    /// `lzma_rust2::LzipWriter::finish` returns `io::Result<W>` (the inner
    /// destination), propagating a genuine write error encountered during
    /// finalisation rather than discarding it — no `CaptureWriteError`
    /// adapter needed, the same as `lzma_pure.rs` and `xz_pure.rs`.
    fn finish(self: Box<Self>) -> Result<()> {
        let LzipSink(writer) = *self;
        let mut w = writer.finish()?;
        w.flush()?;
        Ok(())
    }
}

/// See the module doc's "The backend has a silent-data-loss defect" and
/// "The fix" sections for what this closes and why it needs two checks
/// rather than one.
struct GuardedLzipReader {
    inner: LzipReader<BufReader<Box<dyn Source>>>,
    state: GuardState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardState {
    /// The first `read` call has not run yet, so the magic bytes have not
    /// been checked.
    Unchecked,
    /// Magic checked and matched; delegating reads to `inner`.
    Streaming,
    /// `inner` reported `Ok(0)` and the trailing-bytes check already ran
    /// clean. Every further read returns `Ok(0)` without repeating it.
    Done,
    /// A prior read already failed (bad magic, unconsumed trailing bytes,
    /// or a genuine error from `inner`). Reading again must keep failing.
    Failed,
}

impl GuardedLzipReader {
    fn new(src: Box<dyn Source>) -> Self {
        Self {
            inner: LzipReader::new(BufReader::new(src)),
            state: GuardState::Unchecked,
        }
    }

    /// Non-destructive: does the underlying source still hold any
    /// unconsumed bytes? One `BufRead::fill_buf` call — the same mechanism
    /// `lzma_c.rs`'s `RejectTrailingGarbage` and `lzma_pure.rs`'s
    /// `GuardedReader::has_more` use.
    fn has_more(&mut self) -> std::io::Result<bool> {
        Ok(!self.inner.inner_mut().fill_buf()?.is_empty())
    }

    /// Non-destructive: do the first bytes available match LZIP's magic?
    /// One `BufRead::fill_buf` call, run once before `inner` ever sees the
    /// stream.
    fn magic_matches(&mut self) -> std::io::Result<bool> {
        Ok(self.inner.inner_mut().fill_buf()?.starts_with(MAGIC_BYTES))
    }
}

impl Read for GuardedLzipReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Same guard every codec in this crate that wraps a stateful
        // decoder uses: an empty read must not be misread as genuine
        // end-of-stream by the state machine below.
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.state {
                GuardState::Unchecked => {
                    if !self.magic_matches()? {
                        self.state = GuardState::Failed;
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "not an LZIP stream: missing the \"LZIP\" magic bytes at the start",
                        ));
                    }
                    self.state = GuardState::Streaming;
                }
                GuardState::Streaming => match self.inner.read(buf) {
                    Ok(0) => {
                        if self.has_more()? {
                            self.state = GuardState::Failed;
                            return Err(std::io::Error::new(
                                ErrorKind::InvalidData,
                                "LZIP stream ended with unconsumed bytes remaining — a later \
                                 member's header failed to parse, which lzma-rust2's LzipReader \
                                 misreads as a clean end of stream rather than as corruption",
                            ));
                        }
                        self.state = GuardState::Done;
                        return Ok(0);
                    }
                    Ok(n) => return Ok(n),
                    Err(e) => {
                        self.state = GuardState::Failed;
                        return Err(e);
                    }
                },
                GuardState::Done => return Ok(0),
                GuardState::Failed => {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "lzip stream previously failed to decode",
                    ));
                }
            }
        }
    }
}

/// Compresses `plain` with this codec's default options, for tests only.
///
/// Mirrors `lzma_pure.rs`'s and `xz_pure.rs`'s helpers of the same name.
#[cfg(test)]
pub(crate) fn encode_for_test(plain: &[u8]) -> Vec<u8> {
    let buf = stuffr_core::testing::SharedBuf::new();
    let mut sink = Lzip
        .encoder(Box::new(buf.clone()), &EncodeOpts::default())
        .unwrap();
    sink.write_all(plain).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use stuffr_core::testing::SharedBuf;
    use stuffr_core::{DecodeOpts, EncodeOpts, ReaderSource, Source};

    use super::*;

    fn compress(plain: &[u8]) -> Vec<u8> {
        encode_for_test(plain)
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Lzip.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    fn try_decompress(bytes: Vec<u8>) -> std::io::Result<Vec<u8>> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Lzip.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn lzip_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Lzip, &meta());
    }

    #[test]
    fn it_is_a_full_codec_and_not_a_weak_one() {
        let c = Lzip.caps();
        assert!(c.encode && c.decode);
        assert!(!c.weak_encoder);
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = compress(&plain);
        assert!(
            packed.len() < plain.len(),
            "lzip must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_lzip_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..4], b"LZIP");
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Lzip.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        assert!(!c.weak_encoder, "a full codec, not a weaker fallback");
        let m = meta();
        assert_eq!(m.id, LZIP);
        assert_eq!(m.extensions, &["lz"]);
        assert_eq!(m.magics.len(), 1);
        assert_eq!(m.magics[0].bytes, b"LZIP");
        assert_eq!(m.magics[0].offset, 0);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn lzip_declares_corruption_detection_and_a_memory_figure() {
        let c = Lzip.caps();
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::Always,
            "LZIP mandates a CRC32 in every member trailer; see the module doc"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    #[test]
    fn level_zero_through_nine_are_all_accepted() {
        for n in 0..=9 {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            assert!(
                Lzip.check_encode_opts(&opts).is_ok(),
                "level {n} must be accepted"
            );
            assert!(
                Lzip.encoder(Box::new(SharedBuf::new()), &opts).is_ok(),
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
            match Lzip.check_encode_opts(&opts) {
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
            match Lzip.encoder(Box::new(SharedBuf::new()), &opts) {
                Err(err) => assert!(matches!(err, stuffr_core::Error::Usage(_))),
                Ok(_) => panic!("encoder() must agree with check_encode_opts() and reject {n}"),
            }
        }
    }

    /// Measured directly against `LzipOptions::with_preset` specifically —
    /// see the module doc's "Level validation" section for why a different
    /// entry point onto the same underlying `LzmaOptions::with_preset`
    /// could in principle have behaved differently, and did not.
    #[test]
    fn with_preset_silently_clamps_out_of_range_values() {
        assert_eq!(
            LzipOptions::with_preset(9).lzma_options.dict_size,
            LzipOptions::with_preset(10).lzma_options.dict_size
        );
        assert_eq!(
            LzipOptions::with_preset(9).lzma_options.dict_size,
            LzipOptions::with_preset(99).lzma_options.dict_size
        );
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Lzip.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    // --- Regression tests for the three silent-data-loss shapes measured
    // against the raw backend — see the module doc for the full table.

    /// Row 1 of the module doc's table: any of the first member's 6 header
    /// bytes flipped. Without `GuardedLzipReader`'s magic check (and, for a
    /// non-magic byte, its trailing-bytes check), the raw crate returns
    /// `Ok` with 0 bytes — this is exactly what a corrupted archive must
    /// NOT do silently.
    #[test]
    fn damaged_first_member_header_is_rejected_not_silently_empty() {
        let good = compress(b"the first member's header must survive intact");
        for i in 0..6 {
            let mut corrupted = good.clone();
            corrupted[i] ^= 0xFF;
            match try_decompress(corrupted) {
                Ok(out) => panic!(
                    "flipping header byte {i} decoded without error — got {} bytes; expected \
                     InvalidData",
                    out.len()
                ),
                Err(e) => assert_eq!(
                    e.kind(),
                    ErrorKind::InvalidData,
                    "byte {i}: expected InvalidData, got {:?}",
                    e.kind()
                ),
            }
        }
    }

    /// Row 2 of the module doc's table: the SECOND member's magic damaged
    /// in a two-member concatenation. Without `GuardedLzipReader`'s
    /// trailing-bytes check, the raw crate decodes the first member's bytes
    /// only and returns `Ok` — 6,300 of 12,900 bytes in the measurement that
    /// motivated this task, half the archive silently gone with no error.
    #[test]
    fn damaged_second_member_header_is_rejected_not_silently_truncated() {
        let first = compress(&b"first member payload, repeated so it is not tiny ".repeat(200));
        let second = compress(&b"second member payload, repeated so it is not tiny ".repeat(200));
        let mut two = first.clone();
        two.extend_from_slice(&second);

        // Flip one byte inside the second member's magic (the first 4 bytes
        // of `second`, now at offset `first.len()`).
        let mut corrupted = two.clone();
        corrupted[first.len()] ^= 0xFF;

        match try_decompress(corrupted) {
            Ok(out) => panic!(
                "expected the damaged second member to be reported as corrupt; got Ok with \
                 {} of {} bytes — the second member was silently dropped",
                out.len(),
                first.len() + second.len() - 40 // rough decoded-size sanity, not exact
            ),
            Err(e) => assert_eq!(e.kind(), ErrorKind::InvalidData),
        }

        // Sanity: the *intact* concatenation decodes both members' worth of
        // plaintext, so the corrupted case above is a genuine regression
        // catch, not an artefact of two-member archives never working.
        let intact_plain = decompress(two);
        assert!(intact_plain.len() > first.len() / 2);
    }

    /// Row 3 of the module doc's table: entirely non-LZIP input. Without
    /// the magic check, the raw crate returns `Ok` with 0 bytes for this
    /// too — indistinguishable from a genuinely empty archive.
    #[test]
    fn non_lzip_input_is_rejected_not_silently_empty() {
        let plain_text = b"this is not an LZIP stream at all, just plain text data".to_vec();
        match try_decompress(plain_text) {
            Ok(out) => panic!(
                "plain text decoded without error — got {} bytes; expected InvalidData",
                out.len()
            ),
            Err(e) => assert_eq!(e.kind(), ErrorKind::InvalidData),
        }
    }

    #[test]
    fn a_single_member_with_nothing_appended_decodes_cleanly() {
        let packed = compress(b"just one member, nothing after it");
        assert_eq!(decompress(packed), b"just one member, nothing after it");
    }

    #[test]
    fn truncation_is_detected_at_every_cut() {
        let plain = stuffr_core::testing::incompressible(4 * 1024);
        let packed = compress(&plain);

        for cut in [1, packed.len() / 4, packed.len() / 2, packed.len() - 1] {
            let truncated = packed[..cut].to_vec();
            match try_decompress(truncated) {
                Ok(_) => panic!(
                    "cut to {cut} of {} bytes decoded without error",
                    packed.len()
                ),
                Err(e) => assert_eq!(
                    e.kind(),
                    ErrorKind::InvalidData,
                    "cut to {cut}: expected InvalidData, got {:?}",
                    e.kind()
                ),
            }
        }
    }

    /// Sweeps every byte position of a real one-member encoded payload.
    /// Backs `detects_corruption: CorruptionDetection::Always` with direct
    /// measurement rather than an assumption from the format spec alone —
    /// see the module doc's "Corruption detection" section.
    ///
    /// Measured exactly TWO positions that flip a byte and still decode to
    /// the exact original plaintext (for a 173-byte encoded stream: bytes
    /// 150 and 152, the last three bytes of the embedded LZMA1 body minus
    /// one). This is not a gap in the CRC32 guarantee — it is the same
    /// range-coder flush-tail phenomenon `lzma_pure.rs`'s own sweep
    /// documents for the identical underlying `lzma_rust2::LzmaReader`/
    /// `LzmaWriter` pair: a handful of trailing bytes in the range coder's
    /// flush exist to satisfy its own internal state machine, and their
    /// exact VALUE (as opposed to their presence) does not reach the
    /// decoded output at all for a short stream. A byte that provably
    /// cannot change the decoded content cannot be "detected" as corrupt by
    /// any checksum, LZIP's included, because there is nothing wrong with
    /// the content to detect — the same reasoning `snappy.rs`'s own
    /// `Always` sweep documents for its one framing-byte exception. Kept as
    /// an exact assertion, not a bound, so a change in this count (a
    /// `lzma-rust2` upgrade changing the flush length, say) gets noticed
    /// rather than silently absorbed.
    #[test]
    fn corruption_sweep_is_detected_everywhere() {
        use stuffr_core::testing::incompressible;

        // EXHAUSTIVE, but over a deliberately SMALL stream: tests build
        // unoptimised, and `lzma-rust2` runs 15-20x slower in that profile
        // than a C backend — `lzma_pure.rs`'s equivalent sweep measured 103s
        // over 4 KiB, which was the entire runtime of `make check`. See
        // that module's `corruption_sweep_is_detected_almost_everywhere` for
        // the full accounting; the same reasoning applies here unchanged.
        let plain = incompressible(128);
        let packed = compress(&plain);

        let mut invalid_data = 0usize;
        let mut other_kind = 0usize;
        let mut silently_wrong = 0usize;
        let mut silently_unchanged = 0usize;
        for i in 0..packed.len() {
            let mut corrupted = packed.clone();
            corrupted[i] ^= 0xFF;
            match try_decompress(corrupted) {
                Ok(out) if out == plain => silently_unchanged += 1,
                Ok(_) => silently_wrong += 1,
                Err(e) => match e.kind() {
                    ErrorKind::InvalidData => invalid_data += 1,
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
            "NormalizeDecodeErrors (or this codec's own checks) must fold every kind this \
             backend raises onto InvalidData; {other_kind} positions reported neither"
        );
        assert_eq!(
            silently_unchanged, 2,
            "expected exactly 2 structurally inert bytes (the range coder's flush tail) for \
             this payload; measured {silently_unchanged} — see this test's doc comment before \
             changing this number"
        );
        assert_eq!(invalid_data, packed.len() - silently_unchanged);
    }

    /// Cross-implementation validation of the embedded LZMA1 payload against
    /// `liblzma` — see the module doc's "Cross-implementation validation"
    /// section for why this is complementary to (not a substitute for) the
    /// reference `lzip`-binary tests below, which validate the outer
    /// container this test never touches, and for the dictionary-size
    /// decode formula reproduced here (read from the member's own header
    /// byte, not assumed — `lzip` shrinks the dictionary to fit small
    /// inputs, so a fixed preset size would be wrong here).
    #[cfg(feature = "lzma-c")]
    #[test]
    fn the_alone_reconstruction_is_decoded_correctly_by_liblzma() {
        let plain = b"cross-implementation payload, repeated ".repeat(1000);
        let member = compress(&plain);

        // An LZIP member: 6-byte header, raw LZMA1 body, 20-byte trailer.
        assert_eq!(&member[..4], b"LZIP");
        let dict_size_byte = member[5];
        let body = &member[6..member.len() - 20];

        // Header byte 5's encoding, reproduced here rather than reused from
        // the crate (it is a private function there): bits 4-0 are the
        // base-2 log of a base size, bits 7-5 are a numerator subtracted as
        // a fraction (0-7 sixteenths) of that base.
        let base_log2 = dict_size_byte & 0x1f;
        let base = 1u32 << base_log2;
        let numerator = (dict_size_byte >> 5) & 0x07;
        let dict_size = base - (base / 16) * numerator as u32;

        // Reassemble a `.lzma` "alone" header around the same raw LZMA1
        // body: properties byte for lc=3/lp=0/pb=2 (LZIP's fixed
        // parameters, same as `lzma_c.rs`'s and `lzma_pure.rs`'s own
        // output), the dictionary size just decoded (little-endian), then
        // the 8-byte "size unknown" sentinel — the embedded stream carries
        // an end marker rather than a known length, the same as this
        // project's other two LZMA1 backends.
        let mut alone = Vec::with_capacity(13 + body.len());
        alone.push(0x5d);
        alone.extend_from_slice(&dict_size.to_le_bytes());
        alone.extend_from_slice(&[0xff; 8]);
        alone.extend_from_slice(body);

        let stream = liblzma::stream::Stream::new_lzma_decoder(u64::MAX).unwrap();
        let mut dec =
            liblzma::read::XzDecoder::new_stream(std::io::Cursor::new(alone.clone()), stream);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .expect("liblzma must decode the reconstructed .lzma-alone stream");
        assert_eq!(
            out, plain,
            "liblzma's decode must match the original byte-for-byte"
        );
    }

    // --- Reference `lzip` binary interop — see the module doc's
    // "Cross-implementation validation" section.

    /// Finds the `lzip` binary on `PATH` without shelling out to `which` —
    /// same shape `xz_pure.rs`'s `which_xz` uses, for the same reason:
    /// returns `None` rather than panicking, so the interop tests below skip
    /// cleanly on a machine with no `lzip` installed instead of failing the
    /// whole suite.
    fn which_lzip() -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join("lzip");
            candidate.is_file().then_some(candidate)
        })
    }

    /// The write direction: a member THIS codec writes must be accepted and
    /// correctly decoded by the reference tool, not just by itself.
    #[test]
    fn the_system_lzip_tool_accepts_what_this_writes() {
        let Some(lzip) = which_lzip() else {
            return;
        };
        let plain = b"interop payload, written by this codec ".repeat(4096);
        let packed = compress(&plain);
        let path = std::env::temp_dir().join("stf-lzip-interop-ours.lz");
        std::fs::write(&path, &packed).unwrap();

        let test = std::process::Command::new(&lzip)
            .arg("-t")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            test.status.success(),
            "system lzip -t rejected our output: {}",
            String::from_utf8_lossy(&test.stderr)
        );

        let cat = std::process::Command::new(&lzip)
            .arg("-dc")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            cat.status.success(),
            "system lzip -dc failed on our output: {}",
            String::from_utf8_lossy(&cat.stderr)
        );
        assert_eq!(
            cat.stdout, plain,
            "system lzip decoded our output to different bytes"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The read direction: a member the REFERENCE tool writes must be
    /// readable by this codec, not just the reverse.
    #[test]
    fn this_codec_decodes_what_the_system_lzip_tool_writes() {
        let Some(lzip) = which_lzip() else {
            return;
        };
        let plain = b"the system lzip tool wrote this, lzma-rust2 must read it back ".repeat(4096);
        let src_path = std::env::temp_dir().join("stf-lzip-interop-theirs-src.bin");
        std::fs::write(&src_path, &plain).unwrap();

        let out = std::process::Command::new(&lzip)
            .arg("-9")
            .arg("-k")
            .arg("-f")
            .arg("-c")
            .arg(&src_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "system lzip failed to compress: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        assert_eq!(decompress(out.stdout), plain);
        let _ = std::fs::remove_file(&src_path);
    }

    /// The multi-member case, checked against the reference tool directly —
    /// this task exists because of a defect class (a concatenated stream
    /// silently truncated to less than all of it) that has bitten gzip,
    /// bzip2, xz and LZMA1 elsewhere in this project, so proving this codec
    /// agrees with `lzip -dc` on the genuine, undamaged two-member case
    /// matters on its own, distinct from the damaged-header regression tests
    /// above.
    #[test]
    fn the_system_lzip_tool_agrees_on_a_two_member_concatenation() {
        let Some(lzip) = which_lzip() else {
            return;
        };
        let first = b"first member, written by the reference tool ".repeat(2048);
        let second = b"second member, written by the reference tool ".repeat(2048);

        let compress_with_reference = |plain: &[u8], tag: &str| -> Vec<u8> {
            let src_path = std::env::temp_dir().join(format!("stf-lzip-interop-multi-{tag}.bin"));
            std::fs::write(&src_path, plain).unwrap();
            let out = std::process::Command::new(&lzip)
                .arg("-9")
                .arg("-k")
                .arg("-f")
                .arg("-c")
                .arg(&src_path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "system lzip failed to compress: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let _ = std::fs::remove_file(&src_path);
            out.stdout
        };

        let mut both = compress_with_reference(&first, "a");
        both.extend_from_slice(&compress_with_reference(&second, "b"));

        let both_path = std::env::temp_dir().join("stf-lzip-interop-multi-both.lz");
        std::fs::write(&both_path, &both).unwrap();
        let reference_cat = std::process::Command::new(&lzip)
            .arg("-dc")
            .arg(&both_path)
            .output()
            .unwrap();
        assert!(
            reference_cat.status.success(),
            "system lzip -dc failed on the two-member concatenation: {}",
            String::from_utf8_lossy(&reference_cat.stderr)
        );

        let mut expected = first.clone();
        expected.extend_from_slice(&second);
        assert_eq!(
            reference_cat.stdout, expected,
            "sanity check: the reference tool itself must decode both members"
        );

        assert_eq!(
            decompress(both),
            expected,
            "this codec must agree with `lzip -dc` on the two-member concatenation — not just \
             the first member's bytes"
        );

        let _ = std::fs::remove_file(&both_path);
    }
}
