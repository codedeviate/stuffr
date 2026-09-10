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
//! Untreated, `stuffr cat --format lzip notes.txt` on a file with a damaged
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
//! 2. **Once `LzipReader` itself reports `Ok(0)`, this wrapper classifies
//!    whatever the underlying reader still holds** — NOT a blanket "any
//!    unconsumed byte is corrupt" (Review Round 1 caught that: it rejected
//!    files the reference `lzip` binary itself accepts, e.g. NUL-padded
//!    trailing garbage), but [`GuardedLzipReader::classify_trailing_data`],
//!    which reproduces reference lzip's own forgiveness rule bit-for-bit —
//!    see "Matching the reference tool's trailing-data rule" below for the
//!    derivation. A genuinely finished stream has nothing left, which this
//!    still accepts unconditionally; a stream that stopped early because a
//!    later member's header failed to parse usually — but, per the
//!    reference tool's own rule, not always — has that failure's bytes
//!    still sitting there as a detectable signal. `lzma_pure.rs`'s
//!    `GuardedReader` is prior art surveyed and not the fit here: its
//!    `hit_eof` flag exists because the crate it wraps FAKES a sentinel
//!    byte past real EOF, so a plain "anything left over" peek cannot tell
//!    a one-byte truncation from a genuine finish. `LzipReader` has no
//!    equivalent — measured truncation already reports `Err` unaided (see
//!    the table above) — so this check only ever has to answer "what DO
//!    these leftover bytes mean", never "did the crate fake past a missing
//!    one".
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
//! [`crate::normalize::LZIP_MALFORMED_AS_INVALID_DATA_OTHER_EOF`]'s doc for that
//! measurement.
//!
//! ## Matching the reference tool's trailing-data rule
//!
//! Review Round 1's critical finding: the first version of check 2 above
//! ("any unconsumed byte after `Ok(0)` is corrupt") is STRICTER than
//! reference `lzip` 1.26, and rejects real files the reference accepts —
//! NUL padding, arbitrary trailing bytes of many lengths, all decode
//! cleanly through the reference tool (`lzip -t`/`-dc` exit 0) but were
//! rejected here. That is a genuine defect in the opposite direction from
//! `brotli.rs`'s documented divergence (too permissive there; too strict
//! here) — matching the reference exactly is the fix, not picking a
//! direction and calling it good enough.
//!
//! Extracted directly from reference lzip 1.26's own source
//! (`lzip.h`'s `Lzip_header::check_prefix`/`check_corrupt`, driving
//! `main.cc`'s `decompress()` member loop), NOT reverse-engineered from
//! black-box probing alone — probing pinned the shape, reading the C++
//! confirmed the exact rule and one case probing alone would have gotten
//! wrong (below). Verified byte-for-byte against the installed `lzip`
//! 1.26 binary, both via a regular file and via a pipe: `decompress()`'s
//! member-loop logic itself (`check_prefix`/`check_corrupt`/`check_magic`,
//! everything this section documents) runs identically either way. That is
//! NOT true of every check in `main.cc`, though, and one is worth naming
//! precisely rather than glossed over: `decompress()` also rejects a
//! FILE (not stdin) whose LAST member decodes to zero bytes, in a
//! multi-member archive — `"Empty member not allowed"` — gated on
//! `!from_stdin`, not on seekability as such, but `from_stdin` is exactly
//! "was a file path given rather than `-`" in this tool, so the practical
//! effect is the same. Verified directly: a real member followed by a
//! genuinely empty second member exits 2 as a file, 0 through a pipe, same
//! bytes either way. `stuffr` never distinguishes file input from pipe input
//! at this codec's layer — a seekable source is still read forward, never
//! seeked, by `GuardedLzipReader` — so this codec's behavior always matches
//! reference lzip's PIPE path, never its file path, on this one check. That
//! is the defensible side to match: it is the one that still means
//! something once the input genuinely cannot be seeked, which the
//! file-only check does not generalize to.
//!
//! The bullets below (the member-loop rule this codec DOES reproduce) hold
//! identically whether reference lzip reads a file or a pipe:
//!
//! - **No member decoded yet.** Reference lzip's `first_member` branches
//!   never consult any forgiveness rule at all — even a complete,
//!   well-formed 6-byte header with nothing after it (no body, no
//!   trailer) is rejected ("File ends unexpectedly at member header"),
//!   verified directly against the binary. This project's own upfront
//!   magic check (check 1 above) already independently confirms the first
//!   four bytes of the whole stream before `LzipReader` ever runs, so the
//!   only way [`GuardedLzipReader::classify_trailing_data`] is reached
//!   with no member decoded yet is a bad version or dictionary-size byte
//!   in that very first member — which the reference also rejects
//!   unconditionally. [`TrailingVerdict::Reject`] unconditionally in this
//!   case, no further inspection.
//! - **At least one member decoded, and the stream then truly ends** (no
//!   more bytes exist anywhere, verified by pulling up to 7 bytes in a
//!   loop rather than trusting a single `fill_buf`, matching reference
//!   lzip's own `readblock` loop in spirit — see
//!   [`GuardedLzipReader::peek_tail`]'s doc): reference lzip's
//!   `check_prefix` applies — a CONTIGUOUS match against the magic,
//!   starting at position 0, over however many of the first 4 bytes are
//!   actually available. Looks like the truncated start of a real header →
//!   reject ("Truncated header in multimember file"); otherwise → accept.
//! - **At least one member decoded, and more data follows a 6-byte
//!   header-shaped read:** reference lzip's `check_magic`/`check_corrupt`
//!   apply instead — an EXACT 4-byte match means something else in that
//!   header was wrong (version/dictionary size), which is an unconditional
//!   reject, same reasoning as the no-member-decoded-yet case; otherwise,
//!   count how many of the 4 magic-byte POSITIONS match, independent of
//!   contiguity or order — 2 or 3 matches → reject ("Corrupt header in
//!   multimember file"); 0 or 1 → accept.
//!
//! The last two rules are NOT the same predicate, and conflating them was
//! the trap a naive re-implementation would fall into. Measured the
//! distinguishing case directly against the binary: trailing bytes
//! `"XZIP"` (position 0 wrong, positions 1-3 correct — 3 POSITIONAL
//! matches) with NOTHING after them are ACCEPTED (`check_prefix` fails
//! immediately at position 0, contiguity broken), but the identical 4
//! bytes followed by more data are REJECTED (`check_corrupt`'s count of 3
//! doesn't care about contiguity at all). Both directions are pinned by
//! [`the_two_trailing_data_rules_are_genuinely_different`] with fixtures
//! this project constructed and then asked the reference tool to judge —
//! not the tool's own vocabulary assumed and hard-coded, which is exactly
//! what let the original, too-strict version through review undetected.
//!
//! ## An undocumented dependency: this codec assumes a pre-filled prefix
//!
//! Check 1's magic peek is one non-destructive `BufRead::fill_buf` call —
//! it does not loop, and on a source that hands back data one byte at a
//! time it could in principle see fewer than 4 bytes on the first call and
//! wrongly conclude "no match" before the real magic has fully arrived.
//! This is not a latent bug so much as an undocumented DEPENDENCY on this
//! codec's only caller: `stuffr`'s `ops::decompress_with`
//! (`crates/stuffr/src/ops.rs:650`) calls `stuffr_core::probe` before ANY
//! codec's `decoder()` is invoked, and `probe` (`crates/stuffr-core/src/
//! probe.rs`) reads up to `PROBE_LEN` (4096) bytes via `PeekSource::fill`
//! for a non-seekable source, replaying them non-destructively to whatever
//! reads the source afterward. By the time this codec's `decoder()` ever
//! sees the stream, at least the first 4096 bytes (or the whole stream, if
//! shorter) are already resident and replayable — the single `fill_buf`
//! call in check 1 is guaranteed to see all of them at once. If `ops` ever
//! stopped pre-filling before handing a codec its source, THIS codec would
//! break on a slow/fragmented pipe and its own tests — which all construct
//! sources from an in-memory `Cursor`, not a genuinely slow pipe — would
//! not catch it. [`GuardedLzipReader::peek_tail`] (check 2, at the tail of
//! the stream rather than the head) does not share this dependency: it
//! loops its own reads rather than trusting one `fill_buf`, precisely
//! because nothing upstream pre-fills the TAIL of the stream the way
//! `probe` pre-fills the head.
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
//! ## `memory_per_worker`: preset 6's dictionary for `caps()`, level-aware for `acquire_many`
//!
//! `caps().memory_per_worker` declares `896 * 1024 * 1024` (896 MiB) — the
//! STATIC, conservative figure for preset 9, the highest this codec accepts.
//! `encoder` below instead calls `per_worker_bytes(level)`, defined near
//! `member_size_for`, which is level-aware and returns a much smaller figure
//! (128 MiB) at the default preset 6. See `per_worker_bytes`'s own doc for
//! the Task 7 measurement backing both numbers — it found the true
//! per-worker cost roughly five times the naive `3 × dict_size` member-size
//! guess, at both presets — and `xz_pure.rs`'s identical split, measured
//! independently against the same underlying crate.
//!
//! ## Parallel encode: member size, and why the single-worker guard needs
//! ## an above-threshold payload to be testable
//!
//! `lzma_rust2::LzipWriterMt::new` refuses to construct without a member
//! size set, the same way `xz_pure.rs`'s `XzWriterMt::new` refuses without a
//! block size — measured directly: `error_invalid_input("member size must
//! be set")` on `LzipOptions::default()`'s `member_size: None`. `encoder`
//! below sets it to **three times the preset's dictionary size**, mirroring
//! `xz_pure.rs`'s `block_size_for` and, through it, liblzma's own documented
//! convention for `lzma_stream_encoder_mt` — LZIP has no C multi-threaded
//! reference of its own to measure against, since `liblzma` has no notion of
//! an LZIP member. At the default preset (6, 8 MiB dictionary) that is 24
//! MiB. The crate floors the effective size at the dictionary itself
//! (`member_size.max(dict_size)`), so only the multiplier is this codec's
//! choice to make.
//!
//! **A payload at or below the member size yields ONE member, and this
//! backend's one-member MT output is BYTE-IDENTICAL to the single-threaded
//! writer's** — measured directly, mirroring `xz_pure.rs`'s identical
//! finding for its XZ blocks: at preset 0 (768 KiB member size, three times
//! its 256 KiB dictionary), `LzipWriterMt` with exactly one worker matches
//! `LzipWriter` byte-for-byte from 1 byte up to 512 KiB. **The guard-under-
//! test payload must exceed the member size at the level under test** — at
//! preset 0's 768 KiB threshold, a 1 MiB payload diverges (single-threaded
//! 1,063,714 bytes against one-worker MT's 1,063,762), which is what
//! `a_grant_of_one_worker_still_round_trips` below exercises. And, again
//! mirroring `xz_pure.rs`: **worker count, once above one, does not change
//! the output bytes at all** — a 2 MiB preset-0 payload (spanning multiple
//! 768 KiB members) produces byte-identical output at one worker and at
//! four, because member boundaries are fixed by `member_size` alone. No
//! payload size exists at which this codec's own output could prove
//! multiple workers actually ran; `parallel_output_decodes_to_the_same_plaintext_as_single_threaded`
//! below proves correctness under a genuinely multi-member encode instead,
//! and says so in its own comment.
//!
//! **No integrity-check call is needed on the MT path.** LZIP's trailer CRC32
//! is mandatory in every member regardless of how it was produced (see the
//! "Corruption detection" section above) — there is no per-writer check-type
//! choice the way xz's `CheckType` is, so nothing analogous to
//! `xz_pure.rs`'s CRC64 note applies here.
//!
//! ## Cross-implementation validation: the reference `lzip` tool, plus liblzma at the payload level
//!
//! Two independent checks, at two different layers, and neither subsumes the
//! other.
//!
//! **The reference `lzip` 1.26 tool**, run directly (via `require_lzip`,
//! which panics rather than skipping if it is absent — the same convention
//! `ar.rs`, `cpio.rs` and `zip.rs` use through their own `require_bin`; CI
//! installs `lzip` explicitly for exactly this reason):
//! [`the_system_lzip_tool_accepts_what_this_writes`]
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
//!
//! ## Decode memory bound: a dictionary pre-flight, not a bounded constructor
//!
//! Header byte 5 (the 6th byte: `"LZIP"` magic, 1-byte version, then this)
//! declares the member's dictionary size, and `lzma_rust2::LzipReader`
//! allocates a buffer of that size before producing any output — the same
//! shape `xz_pure.rs`'s module doc documents for `XzReader`, measured here
//! independently: a 114-byte member with byte 5 crafted to `0x1d` (declaring
//! `1 << 29` = 512 MiB) drove peak RSS to **538 MB** against a roughly 1.6 MB
//! baseline, and it decoded correctly — the cost is paid purely by the
//! declaration, not by anything actually wrong with the file. **lzip shrinks
//! the dictionary to fit small inputs** (measured: byte `0x0c` on a real
//! `lzip -9` encode of an 11-byte payload decodes to 4,096, not a fixed
//! preset size), so this pre-flight cannot assume a preset default the way a
//! level-only check could — it has to read the byte.
//!
//! Closed the same way as `xz_pure.rs`: [`declared_dictionary_bytes`] parses
//! header byte 5 directly out of the buffered prefix and `decoder` below
//! checks it against [`DecodeOpts::memory_limit`] *before* `LzipReader::new`
//! is ever called, rather than building a push-to-pull bridge onto
//! `lzma_rust2::LzipStream`'s own bounded constructor — see `lzma_pure.rs`'s
//! module doc, "The push-to-pull bridge is cancelled", for why that bridge is
//! not on the table.
//!
//! The formula, verified against reference `lzip` 1.26's own output:
//! `base = 1 << (b & 0x1f)`, then `base - (base / 16) * ((b >> 5) & 0x07)`.
//! Reference `lzip` itself still accepts and correctly decodes a file whose
//! declared size has been raised after the fact — evidently it grows its own
//! buffer rather than preallocating the full declared size up front, unlike
//! this project's `lzma-rust2` backend — which is exactly what makes the
//! crafted 512 MiB fixture above a *legitimate* file to refuse on resource
//! grounds, not a corrupt one: see
//! `the_reference_tool_still_accepts_what_we_now_refuse`.
//!
//! **`None` means ALLOW, not refuse.** Fewer than 6 bytes in the prefix means
//! a truncated header, which is corruption belonging to
//! [`GuardedLzipReader`]'s own checks (or the backend's), not to this
//! resource check.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::num::NonZeroU64;

use lzma_rust2::{LzipOptions, LzipReader, LzipWriter, LzipWriterMt};

use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FormatId, FormatMeta,
    MagicRule, Result, Sink, Source, StreamOnly, format_size,
};

use crate::normalize::{LZIP_MALFORMED_AS_INVALID_DATA_OTHER_EOF, NormalizeDecodeErrors};

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
            // Task 7 measurement: preset 9 (the highest this codec accepts)
            // derives a per-worker delta of ~833.7 MiB — see
            // `per_worker_bytes`'s doc for the full table. THIS FIELD is the
            // STATIC, conservative figure for the highest preset, rounded up
            // to 896 MiB — a static advertisement for callers that
            // introspect `caps()` without ever calling `encoder`. `encoder`
            // below calls `per_worker_bytes(level)` instead, which is
            // level-aware and uses a much smaller figure (128 MiB) at the
            // default preset 6. See the module doc's "memory_per_worker"
            // section.
            memory_per_worker: Some(896 * 1024 * 1024),
            weak_encoder: false,
            // `lzma_rust2::LzipWriterMt` is real: `encoder` below wires it
            // to a governor grant, using `member_size_for`'s three-times-
            // the-dictionary figure — see the module doc's "Parallel
            // encode" section for why that figure and for the refusal path
            // (a grant of one runs single-threaded, not an error).
            parallel_encode: true,
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
    /// `crate::normalize::LZIP_MALFORMED_AS_INVALID_DATA_OTHER_EOF`'s doc.
    ///
    /// **Memory pre-flight**: before `GuardedLzipReader` (and the
    /// `LzipReader` it wraps) ever exists, header byte 5's declared
    /// dictionary size is read out of the buffered prefix and checked
    /// against [`DecodeOpts::memory_limit`] — see the module doc's "Decode
    /// memory bound" section. `None` (cannot decide) means allow.
    fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> Result<Box<dyn Source>> {
        let mut buffered = BufReader::new(src);
        if let Some(limit) = o.memory_limit {
            let prefix = buffered.fill_buf().unwrap_or(&[]);
            if let Some(declared) = declared_dictionary_bytes(prefix)
                && declared > limit
            {
                return Err(Error::ResourceLimit(format!(
                    "lzip: header declares a dictionary needing {}, but --memory-limit \
                     allows only {} — raise --memory-limit to decode this file",
                    format_size(declared),
                    format_size(limit)
                )));
            }
        }
        let guarded = GuardedLzipReader::new(buffered);
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            guarded,
            LZIP_MALFORMED_AS_INVALID_DATA_OTHER_EOF,
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

    /// Single-threaded by default; opts into `lzma_rust2::LzipWriterMt` when
    /// the governor grants more than one worker. See the module doc's
    /// "Parallel encode" section for the member size chosen and the
    /// refusal path.
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

        // `filter(|n| *n > 0)`, not a bare unwrap_or_else: `--threads 0`
        // means AUTO, and passing 0 through as a request would ask for zero
        // workers. Mirrors `xz_pure.rs`'s and `xz_c.rs`'s `encoder`.
        let (writer, lease) = match &o.governor {
            Some(gov) => {
                let want = o
                    .threads
                    .filter(|n| *n > 0)
                    .unwrap_or_else(|| gov.workers());
                let granted = gov.acquire_many(want, per_worker_bytes(level));
                // A grant of one is single-threaded: `LzipWriterMt::new(_,
                // _, 1)` is a different code path from `LzipWriter::new`
                // with nothing to gain from it — `acquire_many` clamps
                // rather than failing, so a tight budget is a smaller grant
                // here, never an error. See the module doc's "Parallel
                // encode" section for the measurement backing this guard's
                // test.
                let writer = if granted.workers() > 1 {
                    let mut opts = LzipOptions::with_preset(level);
                    opts.set_member_size(Some(member_size_for(&opts)));
                    LzipPureWriter::Mt(Box::new(LzipWriterMt::new(
                        dst,
                        opts,
                        granted.workers() as u32,
                    )?))
                } else {
                    // Not a single member by any special case: `member_size`
                    // is left `None`, so `LzipWriter` never partitions.
                    LzipPureWriter::St(Box::new(LzipWriter::new(
                        dst,
                        LzipOptions::with_preset(level),
                    )))
                };
                (writer, Some(granted))
            }
            None => {
                let writer = LzipWriter::new(dst, LzipOptions::with_preset(level));
                (LzipPureWriter::St(Box::new(writer)), None)
            }
        };
        Ok(Box::new(LzipSink {
            writer,
            _lease: lease,
        }))
    }
}

/// This codec's member size for `LzipWriterMt`: three times the preset's
/// dictionary size, mirroring `xz_pure.rs`'s `block_size_for` — see the
/// module doc's "Parallel encode" section for the full justification.
/// `dict_size` is always positive (256 KiB at preset 0 through 64 MiB at
/// preset 9), so tripling it can never be zero.
fn member_size_for(opts: &LzipOptions) -> NonZeroU64 {
    NonZeroU64::new(u64::from(opts.lzma_options.dict_size) * 3)
        .expect("a preset's dict_size is always positive")
}

/// Reads the declared dictionary size out of an LZIP member header's byte 5
/// (the 6th byte: 4-byte `"LZIP"` magic, 1-byte version, then this) —
/// without constructing `LzipReader` or allocating anything sized by it. See
/// the module doc's "Decode memory bound" section for why this exists and
/// what it was measured against.
///
/// `None` means "the prefix does not contain enough to decide" and MUST be
/// treated as allow, not refuse, by every caller — see [`Codec::decoder`]'s
/// doc. Fewer than 6 bytes (a truncated header), or a magic mismatch, is
/// corruption belonging to [`GuardedLzipReader`]'s own checks, not this
/// one's to call: the magic is checked here too (not just presence of 6
/// bytes) so that non-LZIP input under a `--memory-limit` is left for
/// `GuardedLzipReader`'s own magic check to report as `Corrupt` (exit 5),
/// rather than this pre-flight racing ahead of it and misreporting arbitrary
/// bytes as a resource refusal (exit 6) whenever they happen to decode to a
/// large number.
///
/// Formula verified against reference `lzip` 1.26's own output (see the
/// module doc): `base = 1 << (b & 0x1f)`, then
/// `base - (base / 16) * ((b >> 5) & 0x07)`.
fn declared_dictionary_bytes(prefix: &[u8]) -> Option<u64> {
    if prefix.len() < 6 || !prefix.starts_with(MAGIC_BYTES) {
        return None;
    }
    let b = prefix[5];
    let base = 1u64 << (b & 0x1f);
    Some(base - (base / 16) * u64::from((b >> 5) & 0x07))
}

/// This codec's per-worker demand for `acquire_many` — level-aware, unlike
/// `caps().memory_per_worker`, which is a static, conservative figure for
/// callers that introspect `caps()` without ever calling `encoder`. `o.level`
/// is available right here, which `caps()` cannot see.
///
/// Measured directly (release build, `/usr/bin/time -l` on macOS, a
/// streamed, tiled-repetitive payload — content does not change dictionary
/// or match-finder memory, only encode speed, which is why a large payload
/// is affordable to measure at all), at 1, 2, 4 and 8 workers, deriving the
/// per-worker delta as `(rss_at_n - rss_at_1) / (n - 1)`:
///
/// | preset | payload | 1w | 2w | 4w | 8w | derived (n=8) |
/// |---|---|---|---|---|---|---|
/// | 6 (default) | 256 MiB | 86.9 MB | 473.8 MB | 666.7 MB | 1000.9 MB | 124.5 MiB |
/// | 9 (highest) | 1536 MiB | 645.0 MB | 3017.4 MB | 4371.9 MB | 6765.2 MB | 833.7 MiB |
///
/// **Both figures are far above `member_size_for`'s `3 × dict_size` guess**
/// (24 MiB at preset 6, 192 MiB at preset 9) — trust the measurement, per
/// the brief. The gap matches this crate's match-finder cost for the
/// default BT4 finder, roughly `10.5 × dict_size` per thread, on top of the
/// member buffer itself: `10.5 × 8 MiB + 24 MiB ≈ 108 MiB` at preset 6 and
/// `10.5 × 64 MiB + 192 MiB ≈ 864 MiB` at preset 9 — both within a few
/// percent of the measured deltas above, and within a fraction of a percent
/// of `xz_pure.rs`'s independent measurement of the same underlying crate at
/// the same two presets, which is why the figures below are the measured
/// ones, not the member-size guess.
///
/// Two tiers, thresholded at preset 7 (`lzma_encoder_presets.c`'s
/// `dict_pow2` table doubles the dictionary from there on — see
/// `xz_c.rs`'s and `xz_pure.rs`'s identical threshold): presets 0-6 get the
/// measured preset-6 figure (rounded up to 128 MiB), presets 7-9 get the
/// measured preset-9 figure (rounded up to 896 MiB). Coarser than a
/// per-preset table, and safe in the direction that matters — every preset
/// below 6 has a smaller dictionary than 6 itself, and 7-8's true cost is
/// well under 9's, so both tiers over-declare rather than under-declare.
fn per_worker_bytes(level: u32) -> u64 {
    if level >= 7 {
        896 * 1024 * 1024 // 896 MiB: headroom over the measured ~833.7 MiB.
    } else {
        128 * 1024 * 1024 // 128 MiB: headroom over the measured ~124.5 MiB.
    }
}

/// Either writer this codec's `encoder` can produce, unified so `LzipSink`
/// needs only one field regardless of which path was taken.
enum LzipPureWriter {
    St(Box<LzipWriter<Box<dyn Write + Send>>>),
    Mt(Box<LzipWriterMt<Box<dyn Write + Send>>>),
}

impl Write for LzipPureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            LzipPureWriter::St(w) => w.write(buf),
            LzipPureWriter::Mt(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            LzipPureWriter::St(w) => w.flush(),
            LzipPureWriter::Mt(w) => w.flush(),
        }
    }
}

struct LzipSink {
    writer: LzipPureWriter,
    /// Held, not read. Dropping it returns the workers and bytes to the
    /// governor, and `Drop` runs on error paths too — mirrors `xz_pure.rs`'s
    /// `XzPureSink` and `zstd_c.rs`'s `ZstdSink`.
    _lease: Option<stuffr_core::LeaseSet>,
}

impl Write for LzipSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl Sink for LzipSink {
    /// Writes the trailer of the last open member (or members, on the MT
    /// path). The governor lease (if any) is released when `self` drops at
    /// the end of this call.
    ///
    /// Both `LzipWriter::finish` and `LzipWriterMt::finish` return
    /// `io::Result<W>` (the inner destination), propagating a genuine write
    /// error encountered during finalisation rather than discarding it — no
    /// `CaptureWriteError` adapter needed, the same as `lzma_pure.rs` and
    /// `xz_pure.rs`.
    fn finish(self: Box<Self>) -> Result<()> {
        let LzipSink { writer, _lease } = *self;
        let mut w = match writer {
            LzipPureWriter::St(w) => w.finish()?,
            LzipPureWriter::Mt(w) => w.finish()?,
        };
        w.flush()?;
        Ok(())
    }
}

/// Wraps `BufReader<Box<dyn Source>>` for two things `lzma_rust2::LzipReader`
/// gives no way to ask from the outside, both needed by
/// `GuardedLzipReader::classify_trailing_data`:
///
/// 1. **How many bytes has `LzipReader` genuinely consumed so far** (via its
///    own `Read::read` calls — never via `fill_buf` alone, which is a
///    non-destructive peek this codec's own upfront magic check relies on
///    NOT counting as consumption). This is what makes "has at least one
///    member been successfully decoded yet" answerable at all: the crate
///    exposes no such accessor, and the two scenarios
///    `classify_trailing_data` must tell apart (a header-parse failure on
///    the very first attempt, versus a fully decoded — possibly
///    empty-content — first member followed by nothing else) are otherwise
///    indistinguishable purely from `Ok`/`Err` timing at the outer `read`
///    call boundary: both manifest as "the very first call returns `Ok(0)`".
/// 2. **The last up to 6 bytes actually consumed.** This is the harder
///    problem, and the one that broke the first version of this fix: when
///    `LzipReader::start_next_member` fails to parse the next member's
///    header, it does NOT fail atomically — `LzipHeader::parse` reads
///    magic, then version, then the dictionary-size byte, sequentially,
///    and returns as soon as any one of them is wrong. Those bytes are
///    genuinely consumed (the read calls that obtained them succeeded)
///    before the failure, and once `LzipReader` gives up and hands control
///    back to us as `Ok(0)`, they are GONE — not retrievable by peeking
///    forward, because peeking forward only sees what comes AFTER them.
///    Measured directly what this breaks: appending `"LZ"` + 40 unrelated
///    bytes after a valid member, `LzipReader`'s own failed header attempt
///    reads exactly 4 bytes (`"LZXX"`, the magic mismatching at the third
///    byte) before giving up — so a plain forward peek from that point
///    only ever sees the 38 REMAINING bytes, none of which resemble the
///    magic at all, and would wrongly ACCEPT what reference lzip rejects.
///    Recording the last 6 consumed bytes as they flow through — nothing
///    else ever intervenes between a failed header attempt and the `Ok(0)`
///    it produces (verified against `lzma_rust2` 0.20.1's own control
///    flow) — recovers the right byte VALUES, but `tail` alone cannot say
///    how MANY of them belong to the failed attempt once it has already
///    saturated at 6 from earlier, unrelated reads.
///
///    Review Round 2 caught that the fix's first version got this count via
///    arithmetic that assumed exactly one 20-byte trailer preceded the
///    failed attempt within the same outer read call (later widened,
///    still wrongly, to "one trailer plus N complete 26-byte empty-member
///    cycles"). Both were WRONG, and reachable with a single genuinely
///    empty-content member (legal LZIP — this codec's own `lzip_conforms`
///    test round-trips one) sitting between a real member and a corrupted
///    header: `LzipReader`'s loop processes the empty member's
///    already-succeeded header, its trailer, AND the next (failed) header
///    attempt all within ONE outer call, and the empty member's own LZMA
///    end-marker has no fixed, predictable byte cost (measured: 36 bytes
///    total for this codec's own empty-payload member, not the 26 either
///    fix assumed) — no per-member byte count is safe to assume, ever.
///
///    The fix that actually holds does not try to predict any member's
///    byte cost at all. `call_sizes` tracks the sizes of the last 3 `read`
///    calls, watching for the one pattern that can only mean "a trailer
///    was just fully, successfully read": `4, 8, 8` — `LzipTrailer::parse`
///    reads its three fields (CRC, data size, member size) via exactly
///    those three fixed-size calls, in that order, and a trailer that
///    fails partway is a genuine `Err` this codec never reaches
///    `classify_trailing_data` for at all (propagated directly, not
///    folded into `Ok(0)`). Every time that pattern is seen,
///    `consumed_after_last_trailer` snapshots `consumed` — so by
///    construction, whatever has been consumed SINCE that snapshot is
///    EXACTLY "everything after the most recently confirmed trailer",
///    updated fresh at every member boundary, however many intervened,
///    however large their content. The failed attempt is always the very
///    last thing consumed before `Ok(0)` (nothing else reads in between),
///    so `consumed - consumed_after_last_trailer` recovers its byte count
///    directly, with no assumption left to falsify — including the
///    partial-attempt case (a header failing partway because the source
///    itself ran out, contributing a genuine but harmless 0-byte read).
///
///    One residual worth naming rather than leaving implicit: `[4, 8, 8]`
///    is a READ-SIZE pattern, not a content check, so a real LZMA content
///    read that the CALLER happened to split into three consecutive calls
///    of exactly 4, then 8, then 8 bytes would reset the snapshot too
///    early, by coincidence. Not ruled out by construction — but not
///    reachable by anything this project's own callers do either: `ops`
///    drives decoding with a 64 KiB buffer, and the conformance harness's
///    incremental-decode property bounds every read at 1 byte, which can
///    never produce an 8-byte call at all. No test exercises this because
///    no caller in this codebase is shaped to trigger it.
struct TailWrapper<R> {
    inner: R,
    consumed: u64,
    /// Last up to 6 bytes consumed, oldest at index 0 of the filled prefix.
    tail: [u8; 6],
    tail_len: usize,
    /// Sizes of the last 3 `read` calls, oldest first (`[0]`) to most
    /// recent (`[2]`) — watched only for the `[4, 8, 8]` shape a
    /// completed trailer read always produces. See this type's doc, point
    /// 2, for why that shape is unambiguous.
    call_sizes: [usize; 3],
    /// `consumed`, snapshotted every time `call_sizes` becomes `[4, 8, 8]`
    /// (a trailer was just fully read). See this type's doc, point 2.
    consumed_after_last_trailer: u64,
}

impl<R> TailWrapper<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            consumed: 0,
            tail: [0u8; 6],
            tail_len: 0,
            call_sizes: [0; 3],
            consumed_after_last_trailer: 0,
        }
    }

    /// Reaches the wrapped reader directly — for `GuardedLzipReader`'s own
    /// peeks (`fill_buf`, and the destructive forward read past a failed
    /// header attempt), which must not themselves feed back into `tail`,
    /// `consumed`, or `call_sizes`: by the time either peek runs, the
    /// decision they exist to support has either not yet been made
    /// (`fill_buf`, non-destructive by construction) or already has been
    /// (the forward read, which runs AFTER everything else was consulted).
    fn raw_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Slides up to 6 bytes' worth of newly-consumed data into `tail`,
    /// dropping the oldest bytes first if it would overflow.
    fn push_tail(&mut self, new: &[u8]) {
        if new.is_empty() {
            return;
        }
        if new.len() >= self.tail.len() {
            let start = new.len() - self.tail.len();
            self.tail.copy_from_slice(&new[start..]);
            self.tail_len = self.tail.len();
            return;
        }
        let total = (self.tail_len + new.len()).min(self.tail.len());
        let drop_from_front = (self.tail_len + new.len()).saturating_sub(self.tail.len());
        let kept = self.tail_len - drop_from_front;
        self.tail.copy_within(drop_from_front..self.tail_len, 0);
        self.tail[kept..kept + new.len()].copy_from_slice(new);
        self.tail_len = total;
    }
}

impl<R: Read> Read for TailWrapper<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.consumed += n as u64;
        self.push_tail(&buf[..n]);
        self.call_sizes = [self.call_sizes[1], self.call_sizes[2], n];
        if self.call_sizes == [4, 8, 8] {
            self.consumed_after_last_trailer = self.consumed;
        }
        Ok(n)
    }
}

/// See the module doc's "The backend has a silent-data-loss defect" and
/// "The fix" sections for what this closes, and "Matching the reference
/// tool's trailing-data rule" for why the trailing-bytes check is not a
/// blanket "any leftover byte is corrupt" — that was Review Round 1's
/// finding: it rejected files the reference `lzip` accepts.
struct GuardedLzipReader {
    inner: LzipReader<TailWrapper<BufReader<Box<dyn Source>>>>,
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
    /// A prior read already failed (bad magic, rejected trailing bytes, or
    /// a genuine error from `inner`). Reading again must keep failing.
    Failed,
}

/// What to do once `inner` reports `Ok(0)` ("no more members") and some
/// number of bytes remain unconsumed in the underlying source.
enum TrailingVerdict {
    /// Nothing else to see here — a genuinely clean end of stream.
    Accept,
    /// Reject with this message (always folds to `InvalidData`).
    Reject(&'static str),
}

impl GuardedLzipReader {
    /// Takes an already-constructed `BufReader` rather than a bare
    /// `Box<dyn Source>` so `Codec::decoder` can peek the header's declared
    /// dictionary size (via one non-destructive `fill_buf` call — see the
    /// module doc's "Decode memory bound" section) *before* this type, and
    /// the `LzipReader` it wraps, ever exist — nothing already buffered by
    /// that peek is re-read from the underlying source, because it is the
    /// same `BufReader`, not a fresh one.
    fn new(buffered: BufReader<Box<dyn Source>>) -> Self {
        Self {
            inner: LzipReader::new(TailWrapper::new(buffered)),
            state: GuardState::Unchecked,
        }
    }

    /// Non-destructive: do the first bytes available match LZIP's magic?
    /// One `BufRead::fill_buf` call, run once before `inner` ever sees the
    /// stream. Reaches straight through `TailWrapper` via `raw_mut()`: this
    /// peek must NOT be recorded as consumption (see `TailWrapper`'s doc).
    fn magic_matches(&mut self) -> std::io::Result<bool> {
        Ok(self
            .inner
            .inner_mut()
            .raw_mut()
            .fill_buf()?
            .starts_with(MAGIC_BYTES))
    }

    /// Pulls up to `need` more bytes from whatever remains once `inner`
    /// reports `Ok(0)`, looping `Read::read` calls (not a single
    /// `fill_buf`) until either `need` bytes are in hand or a `read` call
    /// genuinely returns `Ok(0)` — the same "keep trying until enough or
    /// true EOF" shape reference `lzip`'s own `readblock` uses
    /// (`decoder.cc`), needed so a source that happens to deliver these
    /// final bytes across more than one physical read (a slow pipe, say)
    /// is not mistaken for having fewer bytes left than it really does.
    /// Reaches straight through `TailWrapper` via `raw_mut()`: by this
    /// point `classify_trailing_data` has already consulted `tail` and
    /// `consumed`, so nothing is lost by bypassing further tracking, and
    /// destructive is fine regardless — `inner` has already finished, so
    /// nothing downstream will ever see these bytes again either way.
    ///
    /// Returns `(bytes, how_many_are_real)`.
    fn read_more(&mut self, need: usize) -> std::io::Result<(Vec<u8>, usize)> {
        let mut probe = vec![0u8; need];
        let mut n = 0usize;
        while n < need {
            match self.inner.inner_mut().raw_mut().read(&mut probe[n..])? {
                0 => break,
                read => n += read,
            }
        }
        Ok((probe, n))
    }

    /// Decides what leftover bytes mean, once `inner` has reported `Ok(0)`.
    /// Reproduces reference `lzip` 1.26's OWN rule bit-for-bit
    /// (`Lzip_header::check_prefix`/`check_corrupt` in `lzip.h`, driving
    /// `decompress()`'s member loop in `main.cc`) rather than an invented
    /// approximation — see the module doc's "Matching the reference tool's
    /// trailing-data rule" section for the derivation and the byte-level
    /// probes that pinned it down, including the two cases that would look
    /// alike under a naive "count how many magic bytes match" reading but
    /// do not under the reference's actual (contiguous-prefix) one.
    ///
    /// The one case this function does NOT need to handle at all: leftover
    /// bytes whose first four match `"LZIP"` exactly AND at least one more
    /// byte follows them. That combination never reaches here — if the
    /// magic is fully intact and something follows, `lzma_rust2::LzipReader`
    /// itself successfully starts parsing it as a genuine next member and
    /// keeps decoding (or fails with a real decode error), so `inner.read`
    /// does not return `Ok(0)` in the first place.
    fn classify_trailing_data(&mut self) -> std::io::Result<TrailingVerdict> {
        // Reference `lzip`'s decompress() loop only ever forgives trailing
        // bytes in its `!first_member` branches. For the very first member,
        // ANY header-level failure is unconditional: "File ends unexpectedly
        // at member header" / bad-version / bad-dictionary-size, none of
        // which ever consult `check_prefix`/`check_corrupt`.
        //
        // The ONLY way this function is reached with no member successfully
        // decoded yet: `LzipHeader::parse` failed on version or dictionary
        // size (magic itself is already covered by this codec's own upfront
        // check, run before `inner` ever sees the stream). That failure
        // consumes at most 6 bytes (`lzma_rust2`'s own `HEADER_SIZE`) before
        // giving up — nowhere near enough for a genuine member, which needs
        // at least `HEADER_SIZE + TRAILER_SIZE` (26) bytes even for a
        // zero-byte payload, and measurably more in practice (a real
        // empty-payload member is 36 bytes). This is NOT reachable via "a
        // fully valid header with a missing body" — that combination
        // succeeds `start_next_member` and fails later, as a genuine `Err`
        // from constructing/reading the LZMA body, never as `Ok(0)` here;
        // verified directly (see
        // `a_lone_valid_looking_header_with_no_body_is_rejected_as_the_first_member`,
        // which passes via that `Err` path, not through this branch at all).
        //
        // [`TailWrapper`] is what makes "at least one member decoded"
        // externally observable at all, since `lzma_rust2::LzipReader`
        // exposes no such accessor and the two scenarios are otherwise
        // indistinguishable from outside (both look like "the very first
        // `read` call returns `Ok(0)`") — see that type's doc.
        const MIN_VALID_MEMBER_SIZE: u64 = 26; // HEADER_SIZE (6) + TRAILER_SIZE (20)
        let wrapper = self.inner.inner_mut();
        if wrapper.consumed < MIN_VALID_MEMBER_SIZE {
            return Ok(TrailingVerdict::Reject(
                "the LZIP stream's first member header parsed far enough to pass the magic \
                 check but failed later (version or dictionary size) — the reference lzip tool \
                 treats this as an unconditional error too, never as ignorable trailing data",
            ));
        }

        // Reconstruct the up-to-6-byte header attempt `LzipReader`'s own
        // failed `start_next_member` just made. `tail`'s LAST 6 bytes are
        // "the last 6 bytes consumed overall, oldest at index 0" — but that
        // window saturates at 6, so once it has been filled by an earlier,
        // UNRELATED read (a prior member's trailer, say), the sliding
        // window alone cannot tell "these are this attempt's own bytes"
        // apart from "these are stale bytes from whatever came before it".
        // Measured directly why this distinction matters: appending `"LZ"`
        // + 40 unrelated bytes after a valid member, the failed attempt
        // consumes exactly 4 bytes (`"LZXX"`) — using `tail`'s full 6 bytes
        // unconditionally would silently include 2 bytes from the PRIOR
        // member's trailer at the front, misaligning the window and (in
        // that specific case) hiding the magic mismatch entirely.
        //
        // Review Round 2 caught that this fix's first version tried to
        // recover the count via byte-count arithmetic that assumed a fixed
        // cost per intervening member (one 20-byte trailer, later widened
        // to "20 + 26*M" for M intervening empty members) — WRONG either
        // way, and reachable by a perfectly ordinary, CONFORMING encoder
        // with just ONE intervening empty member, not a contrived chain: a
        // genuinely empty-content member is legal LZIP (this codec's own
        // `lzip_conforms` test round-trips one), and its own LZMA
        // end-marker has no fixed, predictable byte cost — "26 bytes per
        // empty member" was itself an unverified assumption, and the real
        // figure (measured: 36 bytes for this codec's own empty-payload
        // member) broke the arithmetic the same way the original "one
        // trailer" assumption did. One real member, one genuinely EMPTY
        // member, then a corrupted third header is enough to reach this —
        // and it is exactly the kind of file `lzip` itself can produce and
        // reference lzip 1.26 still rejects ("Corrupt header in
        // multimember file", file and stdin agreeing). A second attempt,
        // tracking read-call SIZES instead of an aggregate count, fixed
        // that case but broke a DIFFERENT one it hadn't been checked
        // against: a header attempt failing because the source itself ran
        // out partway through (a genuine, harmless 0-byte read) doesn't
        // fit a fixed [4]/[4,1]/[4,1,1] size pattern either.
        //
        // No fixed per-member cost, and no fixed read-call-size pattern,
        // survived contact with a real case — so the fix that holds
        // predicts neither. [`TailWrapper::consumed_after_last_trailer`]
        // is a snapshot of `consumed` taken every time a trailer is
        // confirmed fully read (the unambiguous `[4, 8, 8]` read-size
        // shape `LzipTrailer::parse` always produces) — updated fresh at
        // EVERY member boundary, however many intervened, however large
        // their content, with no need to predict any of it. The failed
        // attempt is always the very last thing consumed before `Ok(0)`
        // (nothing else reads in between), so simply summing bytes
        // consumed since that snapshot recovers its count directly —
        // including the partial-attempt case, since a harmless 0-byte read
        // contributes 0 to a sum without needing special-casing the way it
        // broke the size-pattern match.
        let k = ((wrapper.consumed - wrapper.consumed_after_last_trailer) as usize).min(6);
        let tail = wrapper.tail;
        let mut window = [0u8; 6];
        window[..k].copy_from_slice(&tail[6 - k..]);

        // Peek `7 - k` bytes forward: enough to fill out the rest of the
        // conceptual 6-byte window plus one more, to answer reference
        // lzip's own "is there anything beyond it" question in the same
        // single step.
        let forward_needed = 6 - k + 1;
        let (forward, forward_got) = self.read_more(forward_needed)?;
        let extra = forward_got.min(6 - k);
        window[k..k + extra].copy_from_slice(&forward[..extra]);
        let window_len = k + extra;
        // Got fewer bytes forward than asked for only because a `read` call
        // genuinely returned `Ok(0)` — true end of the source, nothing
        // beyond the window. Reference lzip's own `rdec.finished()` check,
        // reconstructed the same way.
        let at_eof = forward_got < forward_needed;

        if at_eof {
            if window_len == 0 {
                return Ok(TrailingVerdict::Accept);
            }
            // `check_prefix`: a CONTIGUOUS match starting at position 0,
            // over however many of the first 4 magic bytes are actually
            // available — not a count of matching positions regardless of
            // order. Measured directly why this distinction matters: a
            // trailing `"XZIP"` with nothing following (position 0 wrong,
            // 1-3 right) is ACCEPTED by the reference (exit 0) because the
            // prefix check fails immediately at position 0, while the same
            // 4 bytes followed by more data are REJECTED (see below) —
            // `check_corrupt` counts positions independently of order.
            let looks_like_a_header_start =
                (0..window_len.min(4)).all(|i| window[i] == MAGIC_BYTES[i]);
            if looks_like_a_header_start {
                return Ok(TrailingVerdict::Reject(
                    "the LZIP stream ends with what looks like the start of a truncated member \
                     header — matching reference lzip's \"Truncated header in multimember \
                     file\"",
                ));
            }
            return Ok(TrailingVerdict::Accept);
        }

        // Not at EOF: a full 6-byte header-shaped read, with more data
        // still following it. Exact magic match here means SOMETHING ELSE
        // in that header is what's wrong (version or dictionary size) — see
        // this function's doc for why that combination never reaches this
        // point when the magic ISN'T exact but the header otherwise would
        // have been fine; when magic IS exact, the reference always treats
        // it as a hard error too (`check_version`/dictionary-size checks
        // never consult `ignore_trailing`), so there is no forgiveness to
        // apply either way.
        if window[..4] == *MAGIC_BYTES {
            return Ok(TrailingVerdict::Reject(
                "a later member's header has an intact magic but fails validation further in \
                 (version or dictionary size) — the reference lzip tool treats this as an \
                 unconditional error too, never as ignorable trailing data",
            ));
        }
        // `check_corrupt`: count how many of the 4 magic-byte POSITIONS
        // match, independent of contiguity or order — 2 or 3 matches reads
        // as "this was probably an attempt at a header, now corrupted",
        // matching reference lzip's "Corrupt header in multimember file".
        // 0 or 1 matches is ordinary trailing data.
        let matches = (0..4).filter(|&i| window[i] == MAGIC_BYTES[i]).count();
        if matches > 1 {
            return Ok(TrailingVerdict::Reject(
                "trailing bytes look like a corrupted member header (2 or more of the 4 magic \
                 bytes present) — matching reference lzip's own detection rule",
            ));
        }
        Ok(TrailingVerdict::Accept)
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
                    // The magic peek is non-destructive and never blocks
                    // waiting for more than one buffer's worth of data, but
                    // it relies on the caller having already primed that
                    // buffer with at least a few bytes — see the module
                    // doc's "An undocumented dependency" section for why
                    // that is always true in practice for this codec's only
                    // caller, `stuffr`'s `ops::decompress_with`.
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
                    Ok(0) => match self.classify_trailing_data()? {
                        TrailingVerdict::Accept => {
                            self.state = GuardState::Done;
                            return Ok(0);
                        }
                        TrailingVerdict::Reject(msg) => {
                            self.state = GuardState::Failed;
                            return Err(std::io::Error::new(ErrorKind::InvalidData, msg));
                        }
                    },
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

    /// Encodes at preset 0 rather than the default 6, for the parallel
    /// encode tests below — mirrors `xz_pure.rs`'s helper of the same name:
    /// preset 0's member size (768 KiB, three times its 256 KiB dictionary)
    /// is small enough that a payload well above it still encodes fast.
    fn compress_fastest(plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = Lzip
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    level: Some(0),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
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
        assert!(c.parallel_encode, "1f: lzma_rust2::LzipWriterMt");
        assert!(!c.frame_index, "not until 1f");
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
    fn a_tight_memory_limit_clamps_the_worker_count() {
        // The declared figure is what the governor divides by, so a limit of
        // three workers' worth must yield at most three however many CPUs
        // the budget allows. Reads memory_per_worker rather than repeating
        // it: a test with its own copy of the constant stops tracking it.
        let per = Lzip
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
        // constant: preset 9 must demand more memory per worker than the
        // default preset 6, matching Task 7's measurement (~833.7 MiB
        // derived at preset 9 against ~124.5 MiB at preset 6).
        assert!(
            per_worker_bytes(9) > per_worker_bytes(6),
            "the highest preset must demand more memory per worker than the default"
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

    // --- Parallel encode (Phase 1f Task 6) — see the module doc's
    // "Parallel encode" section for the measurements these tests rest on.

    #[test]
    fn parallel_encode_is_declared() {
        assert!(
            Lzip.caps().parallel_encode,
            "lzip's lzma_rust2 backend has LzipWriterMt"
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
        let mut sink = Lzip
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
        // `acquire_many` clamps rather than failing: a memory limit below
        // one worker's demand yields exactly one worker, and the codec must
        // run single-threaded rather than erroring or oversubscribing.
        //
        // The payload here MUST exceed the member size at the level under
        // test — see the module doc's "Parallel encode" section: below the
        // member size, `LzipWriterMt` at one worker is byte-identical to
        // `LzipWriter` regardless of whether the `granted.workers() > 1`
        // guard is even present. Level 0's member size is 768 KiB (three
        // times its 256 KiB dictionary); 1 MiB clears it with headroom, and
        // encoding at level 0 keeps this fast.
        use std::sync::Arc;
        use stuffr_core::testing::incompressible;
        let plain = incompressible(1024 * 1024);
        // 1 byte of budget against a multi-MiB per-worker demand.
        let gov = stuffr_core::Governor::new(8, 1);
        let buf = SharedBuf::new();
        let mut sink = Lzip
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    level: Some(0),
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

        // AND the bytes must match a no-governor, single-threaded encode at
        // the same level exactly.
        //
        // Measured (single-threaded len / one-worker-MT len at level 0 on
        // this 1 MiB payload, above the 768 KiB member size): 1,063,714 /
        // 1,063,762 — always unequal above the threshold, which is what
        // makes this assertion able to catch a deleted guard.
        assert_eq!(
            buf.contents(),
            compress_fastest(&plain),
            "a one-worker grant must produce byte-identical output to a \
             single-threaded encode. If this differs, the `granted.workers() \
             > 1` guard has been removed and the MT writer is being used for \
             a grant with nothing to parallelise."
        );
    }

    #[test]
    fn parallel_output_decodes_to_the_same_plaintext_as_single_threaded() {
        // Bytes may differ from a single-threaded encode — multi-threaded
        // LZIP splits input into members. DATA may not. Asserting the
        // plaintext rather than the bytes is the whole reason parallelism
        // is safe to offer.
        //
        // The 2 MiB payload, at level 0 (768 KiB member size), spans
        // multiple members — well above the threshold, so this is a
        // genuinely multi-member encode, not the single-member case the
        // module doc warns produces identical bytes regardless of worker
        // count. What this test CANNOT do, and does not attempt: prove
        // multiple workers actually ran — measured directly (see the module
        // doc), this backend's output bytes do not change with worker count
        // at all, only `member_size` decides the member boundaries.
        // Correctness under a real multi-member encode is the property this
        // test proves instead.
        use stuffr_core::testing::incompressible;
        let plain = incompressible(2 * 1024 * 1024);
        let st = compress_fastest(&plain);
        let gov = stuffr_core::Governor::new(4, 256 * 1024 * 1024);
        let buf = SharedBuf::new();
        let mut sink = Lzip
            .encoder(
                Box::new(buf.clone()),
                &EncodeOpts {
                    level: Some(0),
                    governor: Some(gov),
                    ..Default::default()
                },
            )
            .unwrap();
        sink.write_all(&plain).unwrap();
        sink.finish().unwrap();
        assert_eq!(decompress(buf.contents()), decompress(st));
    }

    // --- Reference `lzip` binary interop — see the module doc's
    // "Cross-implementation validation" section.

    /// Finds the `lzip` binary on `PATH` without shelling out to `which`.
    fn which_lzip() -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join("lzip");
            candidate.is_file().then_some(candidate)
        })
    }

    /// Locates `lzip` on `PATH`, panicking rather than silently skipping if
    /// it is absent — the same convention `ar.rs`, `cpio.rs` and `zip.rs`
    /// use via their own `require_bin`. CI installs `lzip` explicitly (it is
    /// not on the base image the way `xz` is), so an absence here means only
    /// a contributor's own machine lacks it, and a silent `return` in that
    /// case would report every interop test in this file as PASSING having
    /// verified nothing at all — the shape Finding 8 (Phase 1e) warns
    /// against. Failing loudly beats passing quietly.
    fn require_lzip() -> std::path::PathBuf {
        which_lzip().unwrap_or_else(|| {
            panic!(
                "no reference `lzip` tool found on PATH — this test proved nothing, which is \
                 worth knowing rather than passing silently"
            )
        })
    }

    /// Cross-implementation arbiter for the parallel path specifically: a
    /// stream `LzipWriterMt` produced must be accepted and correctly
    /// decoded by the reference `lzip` tool, not just by this codec's own
    /// decoder — mirrors `the_system_lzip_tool_accepts_what_this_writes`
    /// below, but through the governed encoder path. Uses
    /// `EncodeOpts::default()` (level 6, 24 MiB member size) on a 2 MiB
    /// payload — below the member size, so this is a single-member MT
    /// stream; it proves format compatibility, not multi-member splitting
    /// (`parallel_output_decodes_to_the_same_plaintext_as_single_threaded`
    /// above already covers that).
    #[test]
    fn the_system_lzip_tool_accepts_our_parallel_output() {
        let lzip = require_lzip();
        use std::sync::Arc;
        use stuffr_core::testing::incompressible;
        let plain = incompressible(2 * 1024 * 1024);
        let gov = stuffr_core::Governor::new(4, 256 * 1024 * 1024);
        let buf = SharedBuf::new();
        let mut sink = Lzip
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
        let packed = buf.contents();

        let path = std::env::temp_dir().join("stuffr-lzip-interop-parallel.lz");
        std::fs::write(&path, &packed).unwrap();

        let test = std::process::Command::new(&lzip)
            .arg("-t")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            test.status.success(),
            "system lzip -t rejected our parallel output: {}",
            String::from_utf8_lossy(&test.stderr)
        );

        let cat = std::process::Command::new(&lzip)
            .arg("-dc")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            cat.status.success(),
            "system lzip -dc failed on our parallel output: {}",
            String::from_utf8_lossy(&cat.stderr)
        );
        assert_eq!(
            cat.stdout, plain,
            "system lzip decoded our parallel output to different bytes"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The write direction: a member THIS codec writes must be accepted and
    /// correctly decoded by the reference tool, not just by itself.
    #[test]
    fn the_system_lzip_tool_accepts_what_this_writes() {
        let lzip = require_lzip();
        let plain = b"interop payload, written by this codec ".repeat(4096);
        let packed = compress(&plain);
        let path = std::env::temp_dir().join("stuffr-lzip-interop-ours.lz");
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
        let lzip = require_lzip();
        let plain = b"the system lzip tool wrote this, lzma-rust2 must read it back ".repeat(4096);
        let src_path = std::env::temp_dir().join("stuffr-lzip-interop-theirs-src.bin");
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
        let lzip = require_lzip();
        let first = b"first member, written by the reference tool ".repeat(2048);
        let second = b"second member, written by the reference tool ".repeat(2048);

        let compress_with_reference = |plain: &[u8], tag: &str| -> Vec<u8> {
            let src_path =
                std::env::temp_dir().join(format!("stuffr-lzip-interop-multi-{tag}.bin"));
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

        let both_path = std::env::temp_dir().join("stuffr-lzip-interop-multi-both.lz");
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

    // --- Review Round 1, Finding 2: the reference tool decides the expected
    // outcome for every trailing-data case, rather than this codec's own
    // reading of `lzip.h` being trusted and asserted directly. See the
    // module doc's "Matching the reference tool's trailing-data rule"
    // section.

    /// Feeds `lzip -t` the exact bytes under test and reports whether it
    /// accepted them (exit 0) — the verdict every case below is graded
    /// against, not this codec's own expectation of what `lzip.h` says.
    fn reference_accepts(lzip: &std::path::Path, bytes: &[u8]) -> bool {
        let path = std::env::temp_dir().join(format!(
            "stuffr-lzip-trailing-probe-{}-{}.lz",
            std::process::id(),
            bytes.len()
        ));
        std::fs::write(&path, bytes).unwrap();
        let out = std::process::Command::new(lzip)
            .arg("-t")
            .arg(&path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        out.status.success()
    }

    /// Review Round 1's own table, reproduced as fixtures and judged live by
    /// the installed reference binary — this is what was missing before: a
    /// test that ASKS rather than asserts. Skips cleanly with no `lzip`
    /// installed, same as every other reference-tool test in this module.
    #[test]
    fn trailing_data_after_a_valid_member_matches_the_reference_tool() {
        let lzip = require_lzip();

        let plain = b"trailing-data classification payload, repeated a bit ".repeat(64);
        let base = compress(&plain);

        let mut cases: Vec<(&'static str, Vec<u8>)> = vec![
            ("32 NUL bytes", vec![0u8; 32]),
            ("1 X byte", vec![b'X'; 1]),
            ("4 X bytes", vec![b'X'; 4]),
            ("5 X bytes", vec![b'X'; 5]),
            ("6 X bytes", vec![b'X'; 6]),
            ("17 X bytes", vec![b'X'; 17]),
            ("35 X bytes", vec![b'X'; 35]),
            ("36 X bytes", vec![b'X'; 36]),
            ("37 X bytes", vec![b'X'; 37]),
            ("50 X bytes", vec![b'X'; 50]),
            ("113 X bytes", vec![b'X'; 113]),
            ("114 X bytes", vec![b'X'; 114]),
            ("1-byte magic prefix L, then junk", {
                let mut v = b"L".to_vec();
                v.extend(std::iter::repeat_n(b'X', 40));
                v
            }),
            ("2-byte magic prefix LZ, then junk", {
                let mut v = b"LZ".to_vec();
                v.extend(std::iter::repeat_n(b'X', 40));
                v
            }),
            ("3-byte magic prefix LZI, then junk", {
                let mut v = b"LZI".to_vec();
                v.extend(std::iter::repeat_n(b'X', 40));
                v
            }),
            ("full magic + garbage body", {
                let mut v = b"LZIP".to_vec();
                v.push(1); // version
                v.push(0x0c); // a validly-encoded dictionary size
                v.extend_from_slice(b"garbagegarbagegarbagegarbage");
                v
            }),
        ];
        // Exactly the magic, nothing else at all (true EOF right at the
        // 4-byte boundary) — reference lzip: "Truncated header".
        cases.push(("exactly the 4-byte magic, nothing after", b"LZIP".to_vec()));
        // Exactly a 2-byte magic prefix, nothing else.
        cases.push((
            "exactly a 2-byte magic prefix, nothing after",
            b"LZ".to_vec(),
        ));

        for (desc, extra) in cases {
            let mut candidate = base.clone();
            candidate.extend_from_slice(&extra);

            let expected = reference_accepts(&lzip, &candidate);
            let ours = try_decompress(candidate).is_ok();
            assert_eq!(
                ours,
                expected,
                "case {desc:?}: reference lzip {}, this codec {}",
                if expected { "accepted" } else { "rejected" },
                if ours { "accepted" } else { "rejected" }
            );
        }
    }

    /// The specific divergence Review Round 1 flagged as the trap a naive
    /// re-implementation would fall into: `check_prefix` (contiguous, from
    /// position 0) and `check_corrupt` (a position-independent count) are
    /// NOT the same predicate, and they disagree on exactly this input.
    /// Judged by the reference tool directly, not asserted from this
    /// codec's own reading of `lzip.h` — see the module doc.
    #[test]
    fn the_two_trailing_data_rules_are_genuinely_different() {
        let lzip = require_lzip();

        let plain = b"xzip divergence payload, repeated a bit ".repeat(64);
        let base = compress(&plain);

        // "XZIP": position 0 wrong ('X' vs 'L'), positions 1-3 correct — 3
        // POSITIONAL matches, but NOT a valid prefix (fails at position 0).
        let mut nothing_after = base.clone();
        nothing_after.extend_from_slice(b"XZIP");
        let mut something_after = base.clone();
        something_after.extend_from_slice(b"XZIP");
        something_after.extend(std::iter::repeat_n(b'Y', 40));

        let nothing_after_expected = reference_accepts(&lzip, &nothing_after);
        let something_after_expected = reference_accepts(&lzip, &something_after);
        assert!(
            nothing_after_expected,
            "sanity check on the reference tool itself: \"XZIP\" with nothing after must be \
             accepted (check_prefix fails at position 0) — reference disagreed, so this test's \
             own premise is wrong"
        );
        assert!(
            !something_after_expected,
            "sanity check on the reference tool itself: \"XZIP\" followed by more data must be \
             rejected (check_corrupt counts 3 positional matches) — reference disagreed, so \
             this test's own premise is wrong"
        );

        assert_eq!(
            try_decompress(nothing_after).is_ok(),
            nothing_after_expected,
            "\"XZIP\" with nothing after: must match the reference tool's accept"
        );
        assert_eq!(
            try_decompress(something_after).is_ok(),
            something_after_expected,
            "\"XZIP\" followed by more data: must match the reference tool's reject"
        );
    }

    /// The narrow edge case the module doc's "Matching the reference tool's
    /// trailing-data rule" section calls out by name: even a COMPLETE,
    /// well-formed 6-byte header (valid magic, version, dictionary size)
    /// with nothing after it at all is still rejected when no member has
    /// been decoded yet — reference lzip never consults `check_prefix`'s
    /// forgiveness for the very first member. Judged by the reference tool.
    #[test]
    fn a_lone_valid_looking_header_with_no_body_is_rejected_as_the_first_member() {
        let lzip = require_lzip();
        let lone_header: Vec<u8> = vec![b'L', b'Z', b'I', b'P', 1, 0x0c];
        assert!(
            !reference_accepts(&lzip, &lone_header),
            "sanity check on the reference tool itself: a bare 6-byte header with no body must \
             be rejected — reference disagreed, so this test's own premise is wrong"
        );
        assert!(
            try_decompress(lone_header).is_err(),
            "a lone, complete-looking header with no body must be rejected, matching the \
             reference tool, not accepted as an empty stream"
        );
    }

    /// Review Round 2's minimal reproduction: a genuinely empty-content
    /// member (legal LZIP, produced by an ordinary conforming encoder — no
    /// crafted file needed) sitting between a real member and a corrupted
    /// header is enough, on its own, to shift the byte-counting arithmetic
    /// this codec's fix used to assume "exactly one trailer" for. Judged by
    /// the reference tool, per that review's own standard.
    #[test]
    fn a_corrupted_header_after_one_empty_member_is_rejected_not_silently_dropped() {
        let lzip = require_lzip();

        let real = compress(&b"a real, non-empty member, repeated a bit ".repeat(64));
        let empty = compress(b""); // legal LZIP: a genuinely empty-content member

        let mut candidate = real;
        candidate.extend_from_slice(&empty);
        // 3 of 4 magic bytes match ("L","Z",_,"P") — reference lzip's own
        // `check_corrupt` rule, not a blanket "any leftover byte" one.
        candidate.extend_from_slice(b"LZXP");
        candidate.extend_from_slice(b"junk trailing the corrupted third header");

        assert!(
            !reference_accepts(&lzip, &candidate),
            "sanity check on the reference tool itself: real member + empty member + corrupted \
             third header must be rejected — reference disagreed, so this test's own premise is \
             wrong"
        );
        assert!(
            try_decompress(candidate).is_err(),
            "a corrupted third member's header, following one real member and one genuinely \
             EMPTY member, must be rejected — not silently accepted with the third member \
             dropped, which is exactly the defect class this codec exists to close"
        );
    }

    /// The generality the fix's arithmetic claims: not "one empty member",
    /// any number of them. Two intervening empty members, not one, so a
    /// fix narrowly patched to the minimal reproduction above (rather than
    /// the general per-boundary reset it actually uses) would still fail
    /// here.
    #[test]
    fn a_corrupted_header_after_two_empty_members_is_rejected_not_silently_dropped() {
        let lzip = require_lzip();

        let real = compress(&b"a real, non-empty member, repeated a bit ".repeat(64));
        let empty = compress(b"");

        let mut candidate = real;
        candidate.extend_from_slice(&empty);
        candidate.extend_from_slice(&empty);
        candidate.extend_from_slice(b"LZXP");
        candidate.extend_from_slice(b"junk trailing the corrupted fourth header");

        assert!(
            !reference_accepts(&lzip, &candidate),
            "sanity check on the reference tool itself: real member + two empty members + \
             corrupted header must be rejected — reference disagreed, so this test's own \
             premise is wrong"
        );
        assert!(
            try_decompress(candidate).is_err(),
            "a corrupted fourth member's header, following one real member and TWO genuinely \
             empty members, must be rejected — not silently accepted with the fourth member \
             dropped"
        );
    }

    // --- Dictionary pre-flight (Phase 1f Task 9) — see the module doc's
    // "Decode memory bound" section and `declared_dictionary_bytes`'s own
    // doc for the formula and why `None` means allow.

    /// The formula pinned against three concrete bytes: `0x6e` and `0x1d`
    /// are the module doc's own measurements (13,312 against reference
    /// `lzip` 1.26's real output; `1 << 29` = 512 MiB, the crafted DoS
    /// byte), `0x0c` is this codec's own preset-6-on-a-tiny-payload output
    /// (4,096 — see `a_real_small_file_shrinks_its_declared_dictionary`
    /// below for where that number comes from).
    #[test]
    fn declared_dictionary_bytes_matches_the_measured_formula() {
        let header_with = |b: u8| -> Vec<u8> { vec![b'L', b'Z', b'I', b'P', 1, b] };
        assert_eq!(
            declared_dictionary_bytes(&header_with(0x6e)),
            Some(13_312),
            "measured against reference lzip 1.26 — see the module doc"
        );
        assert_eq!(
            declared_dictionary_bytes(&header_with(0x1d)),
            Some(512 * 1024 * 1024),
            "1 << 29 — the crafted DoS byte"
        );
        assert_eq!(declared_dictionary_bytes(&header_with(0x0c)), Some(4_096));
    }

    /// `lzip` shrinks the dictionary to fit a small input rather than always
    /// using the preset's full size — measured here directly against the
    /// installed reference `lzip` 1.26 binary, so
    /// `declared_dictionary_bytes_matches_the_measured_formula`'s `0x0c`
    /// fixture is not an unexplained magic number. Deliberately NOT tested
    /// through this codec's own `compress()`: `lzma_rust2::LzipWriter` does
    /// not perform this shrink at all (measured directly — it declares
    /// preset 6's full 8 MiB, `0x16`, even for an 11-byte payload), so only
    /// the reference tool's own output demonstrates the behavior
    /// `declared_dictionary_bytes` must decode correctly. Skips cleanly when
    /// `lzip` is not on `PATH`.
    #[test]
    fn a_real_small_file_shrinks_its_declared_dictionary() {
        let lzip = require_lzip();
        let src_path = std::env::temp_dir().join("stuffr-lzip-preflight-shrink-src.bin");
        std::fs::write(&src_path, b"hello world").unwrap();
        let out = std::process::Command::new(&lzip)
            .arg("-9")
            .arg("-k")
            .arg("-f")
            .arg("-c")
            .arg(&src_path)
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(
            declared_dictionary_bytes(&out.stdout),
            Some(4_096),
            "byte 5 of a real small-input member must reflect the shrunk dictionary, not \
             preset 6's full 8 MiB"
        );
        let _ = std::fs::remove_file(&src_path);
    }

    /// `None` on a prefix too short to contain even the magic, and on a
    /// prefix that does not start with LZIP's magic at all — both are
    /// corruption's territory ([`GuardedLzipReader`]'s own checks), not this
    /// one's to call. The magic check matters specifically so non-LZIP input
    /// under a `--memory-limit` is left to be reported as `Corrupt` (exit
    /// 5), not misreported as a resource refusal (exit 6) by this pre-flight
    /// racing ahead of the real detection.
    #[test]
    fn declared_dictionary_bytes_is_none_without_a_matching_magic() {
        assert_eq!(declared_dictionary_bytes(&[]), None);
        assert_eq!(declared_dictionary_bytes(b"LZI"), None);
        assert_eq!(
            declared_dictionary_bytes(b"not an lzip stream at all!!"),
            None
        );
    }

    /// The refusal path: a member declaring `0x1d`'s 512 MiB dictionary
    /// (exactly the module doc's crafted DoS byte), under a 1 MiB limit,
    /// must be refused by `decoder()` itself — before `LzipReader::new` (and
    /// its allocation) ever runs — and the refusal must be exit 6
    /// (`ResourceLimit`), NEVER exit 5: the file is not damaged, this build
    /// simply will not allocate that much.
    #[test]
    fn a_declared_dictionary_over_the_limit_is_refused_before_allocating() {
        let mut packed = compress(b"payload".repeat(100).as_slice());
        packed[5] = 0x1d;

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let err = match Lzip.decoder(
            src,
            &DecodeOpts {
                memory_limit: Some(1024 * 1024),
                ..Default::default()
            },
        ) {
            Err(e) => e,
            Ok(_) => panic!("a declared 512 MiB dictionary must be refused under a 1 MiB limit"),
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

    /// Matters more than the refusal above: over-strictness rejects valid
    /// files, and this project shipped that mirror defect twice in Phase 1e
    /// (this very module's trailing-data guard, and gzip/bzip2 refusing
    /// padding the reference tools recover). A legitimate dictionary that
    /// fits under the limit must still decode.
    #[test]
    fn a_legitimate_dictionary_under_the_limit_still_decodes() {
        let plain = b"ordinary payload ".repeat(2000);
        let packed = compress(&plain);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let mut dec = Lzip
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
    /// a limit; a library caller who deliberately passes `None` keeps the
    /// old, unbounded behaviour.
    #[test]
    fn no_limit_means_no_bound_for_library_callers() {
        let plain = b"payload ".repeat(2000);
        let packed = compress(&plain);
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let mut dec = Lzip.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }

    /// The test that matters more than the refusal: we are refusing on a
    /// resource policy, not on validity. Reproduces the exact 114-byte
    /// crafted fixture that produced the 538 MB measurement in the module
    /// doc (byte 5 raised to `0x1d` after an otherwise-genuine encode) and
    /// confirms the installed reference `lzip` binary still accepts and
    /// decodes it — so refusing it here must be exit 6 (`ResourceLimit`),
    /// never exit 5 (`Corrupt`). Getting that backwards would tell users
    /// their archive is damaged when it is fine. Skips cleanly when `lzip`
    /// is not on `PATH`.
    #[test]
    fn the_reference_tool_still_accepts_what_we_now_refuse() {
        let lzip = require_lzip();

        let mut packed = compress(b"hello world");
        packed[5] = 0x1d; // declares 1 << 29 = 512 MiB

        let path = std::env::temp_dir().join("stuffr-lzip-preflight-crafted.lz");
        std::fs::write(&path, &packed).unwrap();

        let test = std::process::Command::new(&lzip)
            .arg("-t")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            test.status.success(),
            "sanity check on the reference tool itself: it must accept a file whose only fault \
             is an inflated declared dictionary — reference disagreed, so this test's own \
             premise is wrong: {}",
            String::from_utf8_lossy(&test.stderr)
        );
        let cat = std::process::Command::new(&lzip)
            .arg("-dc")
            .arg(&path)
            .output()
            .unwrap();
        assert!(cat.status.success());
        assert_eq!(cat.stdout, b"hello world");

        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
        let err = match Lzip.decoder(
            src,
            &DecodeOpts {
                memory_limit: Some(1024 * 1024),
                ..Default::default()
            },
        ) {
            Err(e) => e,
            Ok(_) => panic!("a declared 512 MiB dictionary must be refused under a 1 MiB limit"),
        };
        assert_eq!(
            err.exit_code(),
            6,
            "a legitimate, reference-tool-accepted file refused on a resource policy must be \
             ResourceLimit, never Corrupt: {err}"
        );

        let _ = std::fs::remove_file(&path);
    }
}
