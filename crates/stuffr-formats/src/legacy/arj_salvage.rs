//! ARJ salvage scan: recovers entries by looking directly for the two-byte
//! header id every ARJ header carries, rather than walking forward from the
//! archive's main header the way `unarj_rs::ArjArchieve` does.
//!
//! `arj.rs` is a correct, honest reader for an INTACT archive, and the way it
//! reaches entry N is by having successfully parsed the main header and
//! entries 1..N-1 — ARJ has no index and no entry table, so one damaged
//! header is the end of the archive as far as any ordinary reader is
//! concerned. That is the damage this module is for. It is the fifth and last
//! salvage scanner of Stage 2, after `arc_salvage.rs` (Task 3),
//! `zoo_salvage.rs` (Task 4) and `lha_salvage.rs` (Task 5), built on the same
//! shared [`stuffr_core::salvage`] machinery.
//!
//! # ARJ is the weakest-evidence format in this project, and this module does
//! not pretend otherwise
//!
//! **Read this before trusting a single green test below.** `legacy::arc` and
//! `legacy::zoo` are checked against CRC-16s that DOS-era archivers computed
//! over the original bytes decades ago; `legacy::compress_z` against
//! `ncompress`; `legacy::lha` against `lhasa`, a decoder sharing no code with
//! the `delharc` this project reads LHA through. **ARJ has none of that.** No
//! `arj`/`unarj` binary is obtainable on any platform in reach, and
//! `fixtures/legacy/sample.arj` is hand-built from this project's own reading
//! of the ARJ specification and of `unarj-rs`'s parser —
//! `fixtures/legacy/MANIFEST.md` calls it the weakest provenance in the
//! phase, in those words.
//!
//! So this scanner can only be checked against `unarj-rs` and against the
//! published specification, **and if both share a misreading, every test in
//! this repository stays green.** That is not hypothetical: a Phase 3b review
//! caught exactly that (the main header's `file_type`, which the spec
//! requires equal 2 and `unarj-rs` never validates), and Stage 2 paid for the
//! same shape once already (`unarc-rs` models ZOO's fixed record as 59 bytes
//! where it is 56, and a reader built on 59 reports healthy what is damaged).
//!
//! Which is precisely why the validation gate below leans on the three
//! constraints that are checkable **independently of any parser** — the
//! specification states them and `unarj-rs` enforces at most one:
//!
//! 1. the **2600-byte** maximum basic header size,
//! 2. the **basic-header-size identity**, `first_hdr_size + strlen(filename)
//!    + 1 + strlen(comment) + 1`,
//! 3. **`file type` must equal 2 in the MAIN header**, which is what lets a
//!    scanner tell an archive's own main header from a file entry at all.
//!
//! Where a test below proves only that this parser agrees with `unarj-rs`, or
//! with this project's own encoder, it is said so in that test's own doc.
//! **Nothing here has the evidentiary weight `lha_salvage.rs`'s `lhasa`
//! cross-check or ARC/ZOO's borrowed CRC-16 corpus carries.**
//!
//! # Where this module's byte offsets come from
//!
//! Every constant below is cited to **"ARJ TECHNICAL INFORMATION" (April
//! 1993, ARJ Software Inc.)**, the copy read being
//! <https://www.opennet.ru/docs/formats/arj.txt>, exactly as `arj.rs`'s own
//! write side is (Ruling F) — and NOT to `unarj-rs`, which validates almost
//! none of them, so a value derived from that parser would only be this
//! project agreeing with itself.
//!
//! The header ENVELOPE, shared by the main header and every local file
//! header, beginning at byte `H`:
//!
//! | offset | size | field | source |
//! |---|---|---|---|
//! | `H+0` | 2 | header id, `0x60 0xEA` | spec; `arj_archive.rs:126-128` |
//! | `H+2` | 2 | basic header size, LE (`= 0` if end of archive) | spec; `arj_archive.rs:141-150` |
//! | `H+4` | `N` | basic header CONTENT | spec |
//! | `H+4+N` | 4 | basic header CRC-32 over the content, LE | spec; `arj_archive.rs:153-162` |
//! | `H+8+N` | 2 | 1st extended header size, LE (0 if none) | spec; `read_extended_headers` |
//!
//! and the local file header's own CONTENT, at offsets from the content's
//! first byte:
//!
//! | offset | size | field |
//! |---|---|---|
//! | `+0` | 1 | `first_hdr_size` — "size up to and including 'extra data'" |
//! | `+1` | 1 | archiver version number |
//! | `+2` | 1 | minimum archiver version to extract |
//! | `+3` | 1 | host OS (`2` = UNIX) |
//! | `+4` | 1 | arj flags |
//! | `+5` | 1 | method (0 stored .. 4 compressed fastest) |
//! | `+6` | 1 | file type (0 binary, 1 7-bit text, 2 comment header, 3 directory, 4 volume label) |
//! | `+7` | 1 | reserved |
//! | `+8` | 4 | date time modified, DOS-packed, LE |
//! | `+12` | 4 | compressed size, LE |
//! | `+16` | 4 | original size, LE |
//! | `+20` | 4 | original file's CRC-32, LE |
//! | `+24` | 2 | filespec position in filename |
//! | `+26` | 2 | file access mode (host-defined) |
//! | `+28` | 2 | host data |
//! | `+first_hdr_size` | .. | filename, NUL-terminated |
//! | .. | .. | comment, NUL-terminated |
//!
//! The name starts at `first_hdr_size`, **not at a fixed 30**, and that
//! distinction is the whole of criterion 6: the identity
//! `first_hdr_size + strlen(filename) + 1 + strlen(comment) + 1 ==
//! basic_header_size` is the spec's own statement of how those two
//! variable-length strings sit inside a header whose fixed prefix may be
//! longer than 30 bytes.
//!
//! **This module does not call `unarj_rs::local_file_header::LocalFileHeader
//! ::load_from`, and that is deliberate.** That function reads its fixed
//! prefix as 30, 34 or 46 bytes depending on thresholds of its own
//! (`STD_HDR_SIZE`, `R9_HDR_SIZE`) rather than on `first_hdr_size` itself, so
//! for any other value it reads the strings from the wrong offset; and its
//! `convert_string!` macro indexes `$x[0]` in a `while` loop with no bound at
//! all, so a content buffer with no NUL in it **panics**. A scanner is
//! pointed at hostile bytes by construction, and a panic is the one failure
//! shape `stuffr_core::testing::check_error_is_classified` can never see.
//!
//! # What this scanner does NOT report, and why
//!
//! **A header whose `file type` is 2 is never a candidate.** The spec's main
//! header table says "file type (must equal 2)"; the local file header table
//! gives 2 the meaning "comment header". The two headers are otherwise
//! structurally identical — same envelope, same `first_hdr_size`, same
//! trailing name and comment — and `unarj-rs` tells them apart by POSITION
//! alone (the first header it meets is the main header). A scanner has no
//! position to trust: in the archive this verb exists for, the main header
//! may be the damaged one.
//!
//! Reporting a main header as an entry would be actively wrong rather than
//! merely noisy. At the offsets a local header spends on `compressed size`
//! and `original size` the main header carries `date time modified` and
//! `archive size`, so such a candidate would claim a payload of whatever the
//! archive's timestamp happens to encode — a multi-gigabyte "entry" of
//! nothing, at exit 0. Skipping `file type == 2` is what the spec's strongest
//! "must" actually buys a scanner.
//!
//! The collateral is a genuine, documented narrowing: an entry whose file
//! type really is 2 — a COMMENT HEADER, which `arj.rs` lists as
//! [`EntryKind::Other`] — is not salvaged. No ARJ writer in this project
//! emits one, and nothing distinguishes it from the archive's own main
//! header; the alternative is a false entry on every healthy archive there
//! is. There is deliberately no Ruling S-V sighting for this shape, unlike
//! `lha_salvage.rs`'s level-2/level-3 sightings: **every** healthy ARJ
//! carries exactly one `file type == 2` header, so a sighting would turn an
//! honestly-empty archive into `Error::Unsupported` at exit 3 for a scan
//! working exactly as designed.
//!
//! # The validation gate
//!
//! A candidate is reported only once ALL of the following hold, checked in an
//! order that never allocates or trusts anything before it is cheap to check:
//!
//! 1. The two-byte header id `0x60 0xEA` sits at the candidate offset.
//! 2. The basic header size at `H+2` is **non-zero** — zero is the spec's
//!    end-of-archive marker, a real structural element and not an entry —
//!    and **at most [`MAX_ARJ_HEADER_SIZE`] (2600)**, the spec's stated
//!    maximum for both header tables.
//! 3. The whole envelope is present in the source: `4 + N + 4 + 2` bytes from
//!    `H`.
//! 4. **The basic header CRC-32 over the content reproduces** the value the
//!    envelope records — `unarj_rs::arj_archive::read_header`'s own check,
//!    computed here with `arj.rs`'s [`crc32_ieee`] rather than by calling
//!    into the dependency, so the gate stays falsifiable from inside this
//!    crate. Thirty-two bits, and by far the strongest single signal here.
//! 5. `first_hdr_size` is at least [`ARJ_FIRST_HDR_SIZE`] (30, the spec's own
//!    standard header) and no larger than the content itself.
//! 6. **The basic-header-size identity holds**: `first_hdr_size +
//!    strlen(filename) + 1 + strlen(comment) + 1` equals the declared basic
//!    header size, with both NUL terminators inside the content, and the
//!    filename is not empty.
//! 7. The `file type` byte is not 2 — see the section above.
//! 8. The `method` byte is one the format assigned ([`Method::from_byte`]).
//!    Recognised, not necessarily DECODABLE — see [`Method::decodable`].
//! 9. The extended-header chain behind the basic header walks to its
//!    terminator inside the source and inside [`MAX_EXT_CHAIN`], which is
//!    what makes the payload's position computable at all.
//!
//! Any failure at 2-9 is not an error — it means these two bytes were a
//! coincidence, not a header, and the scan resumes **one byte past the id**,
//! never past a whole assumed header, so a genuine header overlapping a false
//! match is never skipped.
//!
//! **Reported, never rejected:** a declared payload length whose bytes do not
//! all fit inside the source. That is `zip_salvage.rs`'s "criterion 6
//! reports, it does not reject" ruling, and the reason is the same: a
//! truncated archive's last entry must be a STATEMENT
//! ([`Candidate::available_len`], `Partial`), never silence.
//!
//! # Two bytes of magic is weak; the ceiling and the identity are what carry
//!
//! `0x60 0xEA` is **two bytes**, so uniform random data holds one about every
//! **64 KiB** — a 1 MiB noise corpus contains roughly sixteen of them by
//! chance alone. That is four orders of magnitude weaker than
//! `lha_salvage.rs`'s five-byte ASCII method identifier (one per ~93 GiB) and
//! weaker even than `zoo_salvage.rs`'s four-byte tag (one per 4 GiB). **The
//! id is not a gate at all; it is only where to look.**
//!
//! What actually rejects noise, in order of strength:
//!
//! - **the basic header CRC-32** (criterion 4) — 32 bits, one chance in
//!   4,294,967,296 that random bytes agree with their own recorded checksum;
//! - **the basic-header-size identity** (criterion 6) — two NUL terminators
//!   that must fall exactly where `first_hdr_size` and the declared basic
//!   header size say they do, which for a random 2600-byte window is
//!   vanishingly unlikely and, crucially, is checkable WITHOUT any parser;
//! - **the 2600-byte ceiling** (criterion 2) — rejects about 96% of random
//!   `u16`s outright, before a single further byte is read, and is the reason
//!   a false id near the end of a file cannot make this module read an
//!   arbitrary span.
//!
//! **Each of those three is separately falsifiable**, and that is why the
//! noise corpus below carries a crafted splice per signal rather than one
//! splice overall — the discipline `lha_salvage.rs` arrived at when it
//! measured that its six bare seeded identifiers produced ZERO phantoms with
//! the checksum gate deleted, so a single-splice corpus would have gone
//! quietly vacuous with every test green. See
//! [`tests::CRC_ONLY_DEFECT_OFFSET`], [`tests::IDENTITY_ONLY_DEFECT_OFFSET`]
//! and [`tests::OVERSIZED_HEADER_OFFSET`]; the task report records the run
//! with each check deleted in turn.
//!
//! # Verification reuses the decoders `unarj-rs` itself dispatches to
//!
//! [`ArjSalvage::verify`] seeks to the candidate's own
//! [`Candidate::payload_start`], bounds the read to the declared compressed
//! length, and decodes:
//!
//! - **method 0 (`Stored`)** — the payload IS the content, streamed straight
//!   through with no decoder and no allocation at all;
//! - **methods 1-3** — `delharc`'s [`DecoderAny`] over
//!   `CompressionMethod::Lh6`, which is exactly what
//!   `unarj_rs::ArjArchieve::read` hands those three methods, reached
//!   directly so it can be driven in [`DECODE_CHUNK`] steps instead of one
//!   whole-entry `fill_buffer`;
//! - **method 4 (`CompressedFastest`)** — `unarj_rs::decode_fastest`, the
//!   only arm with no streaming form: it takes the whole compressed slice and
//!   returns the whole decoded `Vec`.
//!
//! The decoded bytes stream through Task 1's
//! [`crate::salvage_verify::stream_verify`], which is what decides
//! [`SalvageStatus`] (length agreement, then the CRC-32 comparison) rather
//! than a second hand-rolled comparison.
//!
//! **[`SalvageStatus::Complete`] is unreachable for ARJ, and that is a
//! contract, not an accident.** `Complete` means the format offers NO
//! checksum at all to prove a payload with (tar, cpio, ar). Every ARJ local
//! file header carries a CRC-32 over the original file, so a candidate this
//! build did not or could not check is [`SalvageStatus::Unverified`] — a tier
//! carries a decision, a message carries a cause.
//!
//! # The whole-entry ceiling, and why ARJ has one where LHA does not
//!
//! See [`ArjSalvage::max_whole_entry`]. Three of the four decodable arms
//! above stream and would need no ceiling; **method 4 does not**, and one arm
//! that materialises a header-declared length is enough to make this the
//! ARC/ZOO case rather than the LHA/zip one. The figure is
//! [`MAX_ARJ_ENTRY_LEN`], read from `arj.rs` rather than restated, so `list`,
//! `unpack` and `salvage` cannot come to disagree about one archive: the
//! ordinary reader already refuses an entry past it at exit 6, on both size
//! fields, before `ArjArchieve::read` allocates.
//!
//! `original_size` gets a SECOND, per-entry check that the engine cannot make
//! for us, **gated to method 4 alone** — the only arm that allocates from it.
//! That is Task 4's established exception, and its scope is the part Task 4
//! got wrong and paid a fix round for: applied to every arm it refuses
//! entries whose own method never reads the field, and `entries.rs` never
//! writes an `Unverified` entry, so the refusal costs a payload that was
//! entirely recoverable.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

use delharc::decode::{Decoder, DecoderAny};
use unarj_rs::date_time::DosDateTime;
use unarj_rs::decode_fastest::decode_fastest;

use stuffr_core::salvage::{
    Candidate, SalvageOutcome, SalvagePolicy, SalvageScan, SalvageStatus, SalvagedEntry,
    UnverifiedCause, Verifier, salvage_all, stream_bounded_copy,
};
use stuffr_core::{EntryKind, EntryMeta, Error, FormatId, Result, SeekRead};

use super::arj::{
    ARJ_FIRST_HDR_SIZE, FILE_TYPE_DIRECTORY, HOST_OS_UNIX, MAIN_HEADER_FILE_TYPE,
    MAX_ARJ_ENTRY_LEN, MAX_ARJ_HEADER_SIZE, crc32_ieee, dos_mtime,
};

/// The two bytes every ARJ header opens with — spec, both header tables:
/// "header id (main and local file header) = 0x60 0xEA".
const HEADER_ID: [u8; 2] = [0x60, 0xEA];

/// Bytes read per [`find_next_id`] chunk. O(1) memory regardless of how far
/// the next id is, or whether there is one at all — same figure, same
/// reasoning, as `zip_salvage.rs`'s, `arc_salvage.rs`'s, `zoo_salvage.rs`'s
/// and `lha_salvage.rs`'s own `SCAN_CHUNK`.
const SCAN_CHUNK: usize = 64 * 1024;

/// The header id plus the `u16` basic header size that follows it — the
/// bytes in front of a header's CONTENT.
const ENVELOPE_PREFIX: u64 = 4;

/// The basic header CRC-32 plus the `u16` "1st extended header size" — the
/// bytes behind a header's content, before either the extended-header chain
/// or (with no chain) the payload.
const ENVELOPE_SUFFIX: u64 = 6;

/// Content offsets, from the content's own first byte. Every one is a row of
/// this module's doc table; named here so no literal offset appears below.
const FIRST_HDR_SIZE_I: usize = 0;
const HOST_OS_I: usize = 3;
const METHOD_I: usize = 5;
const FILE_TYPE_I: usize = 6;
const DATE_TIME_I: usize = 8;
const COMPRESSED_SIZE_I: usize = 12;
const ORIGINAL_SIZE_I: usize = 16;
const ORIGINAL_CRC_I: usize = 20;
const FILE_ACCESS_MODE_I: usize = 26;

/// The most bytes this scanner will walk through an extended-header chain
/// before deciding the chain is not one.
///
/// The ARJ specification assigns extended headers no defined content at all
/// ("extended header ... currently not used"), and neither `arj.rs`'s writer
/// nor any fixture here emits one, so a real chain is a single zero `u16`.
/// The cap is four maximal headers' worth — a `u16` length plus its own
/// CRC-32, four times over — which is two orders of magnitude past anything
/// plausible while still bounding the walk of a file that is all zeros.
///
/// The cap is about the WALK, not about an allocation: the walk reads two
/// bytes per hop and SEEKS past the rest, so it never allocates from a length
/// any header declares.
/// [`tests::a_chain_of_maximal_extended_headers_never_becomes_an_allocation`]
/// proves that with the recording allocator rather than asserting a status.
const MAX_EXT_CHAIN: u64 = 4 * (2 + 65_535 + 4);

/// Bytes decoded per `fill_buffer` call on the `delharc` arm (methods 1-3).
///
/// `delharc`'s [`Decoder::fill_buffer`] is all-or-nothing: it fills the whole
/// slice it is given or fails, and a failure says nothing about how much of
/// the slice it had already written. On a TRUNCATED entry — the single most
/// common damaged archive there is — that discards the final, partly-decoded
/// chunk, so the chunk size is the upper bound on how much of a genuine
/// surviving prefix `NAME.partial` loses. 4 KiB rather than
/// [`crate::salvage_verify`]'s own 64 KiB window for exactly that reason, and
/// [`recover_the_last_chunk`] is what recovers the rest — the identical
/// mechanism, and the identical reasoning, as `lha_salvage.rs`'s.
const DECODE_CHUNK: usize = 4096;

/// The compression methods an ARJ local file header can name.
///
/// # What is in the set
///
/// Exactly `unarj_rs::local_file_header::CompressionMethod`'s own named
/// values — the table the reader beside this scanner already dispatches on —
/// which are the spec's "method (0 = stored, 1 = compressed most ... 4
/// compressed fastest)" plus the two `NO DATA` values 8 and 9 that crate
/// names. Seven of 256 byte values, so criterion 8 is worth about five bits
/// against noise: real, and nothing compared with criterion 4's thirty-two.
///
/// # Recognised is not decodable
///
/// [`Self::decodable`] is a separate, exhaustive `match`. A
/// recognised-but-undecodable method is a real, reportable entry — the
/// archive is fine, this build cannot decode that one method — and is
/// answered [`UnverifiedCause::UndecodableMethod`], never dropped from the
/// scan and never `Complete`. That mirrors `arj.rs`'s own reader, which
/// raises [`Error::Unsupported`] (exit 3) rather than `Corrupt` for these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Method {
    /// Method 0: the payload IS the entry's bytes.
    Stored,
    /// Method 1. `unarj-rs` decodes 1, 2 and 3 identically, through
    /// `delharc`'s `-lh6-` decoder.
    CompressedMost,
    /// Method 2.
    Compressed,
    /// Method 3.
    CompressedFaster,
    /// Method 4: `unarj-rs`'s own `decode_fastest`, the one arm with no
    /// streaming form.
    CompressedFastest,
    /// Method 8. Named by `unarj-rs`, decoded by nothing: its own
    /// `ArjArchieve::read` raises `InvalidData` for this value.
    NoDataNoCrc,
    /// Method 9. As above.
    NoData,
}

impl Method {
    /// The byte this method is stored as.
    pub(super) const fn byte(self) -> u8 {
        match self {
            Method::Stored => 0,
            Method::CompressedMost => 1,
            Method::Compressed => 2,
            Method::CompressedFaster => 3,
            Method::CompressedFastest => 4,
            Method::NoDataNoCrc => 8,
            Method::NoData => 9,
        }
    }

    /// The method a header's `method` byte names, or `None` for a value the
    /// format never assigned — the scan's criterion 8.
    pub(super) fn from_byte(byte: u8) -> Option<Self> {
        Self::all().find(|method| method.byte() == byte)
    }

    /// The [`FormatId`] [`EntryMeta::codec`] carries for this method.
    ///
    /// **Populating [`EntryMeta::codec`] at all is load-bearing**, and it is
    /// the gap ARC shipped with in Task 3: `entries.rs`'s salvage write
    /// dispatch reads this field to decide how to decode, and a candidate
    /// that leaves it `None` makes every entry a silent
    /// `SalvageDisposition::SkippedNotBuiltIn` — a real scanner that quietly
    /// writes nothing. It is set for every RECOGNISED method here, decodable
    /// or not, so an entry this build cannot decode reaches the write path
    /// and is refused there by name rather than vanishing into the same "not
    /// built in" disposition a missing dispatch arm would produce.
    ///
    /// Derived from ONE table — this `match`, which [`Self::all`] also drives
    /// — so the compiler, not a reviewer, is what notices a new variant with
    /// no answer here.
    pub(super) const fn codec(self) -> FormatId {
        match self {
            Method::Stored => FormatId::new("arj-stored"),
            Method::CompressedMost => FormatId::new("arj-most"),
            Method::Compressed => FormatId::new("arj-compressed"),
            Method::CompressedFaster => FormatId::new("arj-faster"),
            Method::CompressedFastest => FormatId::new("arj-fastest"),
            Method::NoDataNoCrc => FormatId::new("arj-nodata-nocrc"),
            Method::NoData => FormatId::new("arj-nodata"),
        }
    }

    /// Whether THIS BUILD can decode a payload stored under this method.
    ///
    /// An exhaustive `match` so a variant added without an answer here does
    /// not compile, and pinned against `arj.rs`'s own reader — which refuses
    /// exactly `NoData`, `NoDataNoCrc` and any unknown byte with
    /// [`Error::Unsupported`] — by
    /// [`tests::decodability_matches_what_the_ordinary_reader_refuses`].
    pub(super) const fn decodable(self) -> bool {
        match self {
            Method::Stored
            | Method::CompressedMost
            | Method::Compressed
            | Method::CompressedFaster
            | Method::CompressedFastest => true,
            Method::NoDataNoCrc | Method::NoData => false,
        }
    }

    /// Whether this arm sizes a buffer from the header's `original size`
    /// field — the one figure [`stuffr_core::salvage::annotate_candidates`]
    /// never sees, because it is a DECODED length that no byte range in the
    /// file bounds.
    ///
    /// True for [`Method::CompressedFastest`] alone: `unarj_rs::
    /// decode_fastest` is `Vec::with_capacity(original_size)` over a whole
    /// compressed slice. [`Method::Stored`] copies, and methods 1-3 stream
    /// through [`DecodedReader`]'s fixed [`DECODE_CHUNK`] window — neither
    /// reads the field for an allocation at all, and bounding them by it is
    /// exactly what ZOO's fix round 1 measured the cost of: a completely
    /// recoverable payload reported "over the ceiling" and written nowhere.
    pub(super) const fn allocates_from_original_size(self) -> bool {
        matches!(self, Method::CompressedFastest)
    }

    /// `delharc`'s own enum value for this method. `None` for every arm
    /// `unarj-rs` does not route through that crate.
    const fn lzh_compression(self) -> Option<delharc::header::CompressionMethod> {
        match self {
            // `unarj_rs::ArjArchieve::read` hands all three of these to
            // `DecoderAny::new_from_compression(CompressionMethod::Lh6, ..)`
            // — one decoder for three method bytes, which is the crate's own
            // shape and not a simplification made here.
            Method::CompressedMost | Method::Compressed | Method::CompressedFaster => {
                Some(delharc::header::CompressionMethod::Lh6)
            }
            Method::Stored | Method::CompressedFastest | Method::NoDataNoCrc | Method::NoData => {
                None
            }
        }
    }

    /// The variant after `self` in declaration order, `None` past the last.
    ///
    /// Exists only to drive [`Self::all`], and is an exhaustive `match` for
    /// exactly one reason: **an eighth variant added to [`Method`] without an
    /// arm here does not compile.** Same shape, same reason, as `arc.rs`'s,
    /// `zoo.rs`'s and `lha_salvage.rs`'s own `Method::next`.
    const fn next(self) -> Option<Self> {
        match self {
            Method::Stored => Some(Method::CompressedMost),
            Method::CompressedMost => Some(Method::Compressed),
            Method::Compressed => Some(Method::CompressedFaster),
            Method::CompressedFaster => Some(Method::CompressedFastest),
            Method::CompressedFastest => Some(Method::NoDataNoCrc),
            Method::NoDataNoCrc => Some(Method::NoData),
            Method::NoData => None,
        }
    }

    /// Every recognised method, in declaration order — seeded from the first
    /// variant and driven by [`Self::next`]'s exhaustive `match`.
    ///
    /// **The chain is compiler-checked; the SEED is not**, the identical
    /// asymmetry `arc.rs`'s, `zoo.rs`'s and `lha_salvage.rs`'s own `all`
    /// document: a variant added at the END cannot be forgotten, one added at
    /// the FRONT compiles cleanly and is silently absent. The front door is
    /// closed by [`tests::the_recognised_set_is_exactly_unarjs_own_table`],
    /// which sweeps the whole byte space rather than iterating this function.
    pub(super) fn all() -> impl Iterator<Item = Self> {
        std::iter::successors(Some(Method::Stored), |method| method.next())
    }
}

/// Maps [`EntryMeta::codec`] (as [`Method::codec`] filled it) back to the
/// [`Method`] the decoders dispatch on.
///
/// Searches [`Method::all`] for the variant whose [`Method::codec`] matches,
/// rather than hand-copying the same seven strings in the opposite direction
/// — the shape Ruling S-K deleted from ARC.
fn method_for_codec(codec: Option<FormatId>) -> Option<Method> {
    let codec = codec?;
    Method::all().find(|method| method.codec() == codec)
}

/// One gated ARJ local file header.
#[derive(Debug)]
struct EntryHeader {
    method: Method,
    /// The entry's COMPRESSED length — the byte span of its payload in the
    /// file, whatever the method.
    declared_len: u64,
    /// The entry's DECODED length.
    original_size: u64,
    /// The CRC-32 the original writer computed over the decoded bytes.
    file_crc: u32,
    mtime: Option<SystemTime>,
    mode: Option<u32>,
    kind: EntryKind,
    name: String,
    /// Absolute position of the first payload byte — the whole envelope plus
    /// the extended-header chain.
    payload_start: u64,
}

/// Scans an ARJ archive for local file headers directly, without walking
/// forward from the archive's main header the way `unarj_rs::ArjArchieve`
/// does — one damaged header ends that walk, and every entry behind it with
/// it.
///
/// Carries no state between calls beyond what [`SalvageScan::next_candidate`]
/// itself receives — the same shape `ZipSalvage`, `ArcSalvage` and
/// `ZooSalvage` have. Unlike `LhaSalvage` there is no Ruling S-V sighting to
/// carry: see this module's doc for why `file type == 2` deliberately gets no
/// such channel.
#[derive(Debug, Default)]
pub struct ArjSalvage;

impl ArjSalvage {
    pub fn new() -> Self {
        Self
    }
}

impl SalvageScan for ArjSalvage {
    fn next_candidate(&mut self, src: &mut dyn SeekRead, from: u64) -> Result<Option<Candidate>> {
        let file_len = src.seek(SeekFrom::End(0))?;
        let mut search_from = from;
        loop {
            let Some(offset) = find_next_id(src, search_from, file_len)? else {
                return Ok(None);
            };
            match read_candidate_at(src, offset, file_len) {
                Some(candidate) => return Ok(Some(candidate)),
                // The id matched and the gate rejected everything behind it:
                // a coincidence, not a header. Resume one byte past the id
                // itself, not past a whole assumed header, so a genuine
                // header overlapping this false match is never skipped.
                None => search_from = offset + 1,
            }
        }
    }

    /// **ARJ declares a real whole-entry ceiling, and the measurement rather
    /// than the format's reputation is what decides that.**
    ///
    /// `lha_salvage.rs` and `zip_salvage.rs` answer `u64::MAX` because every
    /// payload they touch streams, so a ceiling would stand in front of no
    /// allocation and would only cost recoverable entries — ZOO's fix round 1
    /// measured that cost directly (an 11,357-byte payload, entirely present,
    /// reported "over the ceiling" and written nowhere). `arc_salvage.rs` and
    /// `zoo_salvage.rs` answer a real figure because their decoders size a
    /// buffer from a header field.
    ///
    /// ARJ is the second kind, and only just: three of its four decodable
    /// arms stream here (method 0 copies; methods 1-3 run through
    /// [`DecodedReader`]'s fixed window), but **method 4 has no streaming
    /// form at all** — `unarj_rs::decode_fastest` takes the whole compressed
    /// slice and returns the whole decoded `Vec`. One arm that materialises a
    /// header-declared length is enough: `max_whole_entry` is scanner-wide,
    /// there is no per-method version of it, and the alternative
    /// (`u64::MAX`, with a second ceiling on `declared_len` inside
    /// [`Self::verify`]) would put two owners on the one quantity the engine
    /// already owns — exactly the shape three of Task 3c's fix rounds
    /// deleted.
    ///
    /// [`MAX_ARJ_ENTRY_LEN`] is read from `arj.rs` rather than restated, and
    /// that is what keeps this build self-consistent: the ORDINARY reader
    /// already refuses an entry past this figure at exit 6, on both size
    /// fields, before `ArjArchieve::read` allocates — so salvage refusing the
    /// same entry costs nothing `list` or `unpack` could have done, and a
    /// user cannot get two different answers about one archive.
    ///
    /// [`tests::a_stored_entry_just_under_the_ceiling_never_becomes_an_allocation`]
    /// proves the three streaming arms really do stream, with the recording
    /// allocator rather than by assertion.
    fn max_whole_entry(&self) -> u64 {
        MAX_ARJ_ENTRY_LEN
    }

    fn verify(&self, src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
        verify_candidate(src, candidate)
    }
}

/// Searches forward from `from` for the next [`HEADER_ID`] match, in bounded
/// chunks so memory use does not depend on how far through the source the
/// next one is.
///
/// Carries one byte across a chunk boundary — the longest a two-byte match
/// can straddle — so a match split across two reads is never missed.
/// `Ok(None)` when no id remains before `file_len`.
fn find_next_id(src: &mut dyn SeekRead, from: u64, file_len: u64) -> io::Result<Option<u64>> {
    if from >= file_len {
        return Ok(None);
    }
    src.seek(SeekFrom::Start(from))?;

    let mut window: Vec<u8> = Vec::with_capacity(SCAN_CHUNK + 1);
    let mut window_start = from;
    let mut buf = vec![0u8; SCAN_CHUNK];

    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        window.extend_from_slice(&buf[..n]);

        if let Some(at) = window.windows(2).position(|w| w == HEADER_ID) {
            return Ok(Some(window_start + at as u64));
        }

        // Keep only the last byte: the longest prefix of the id that could
        // still be waiting for its second byte in the next chunk.
        let keep = window.len().saturating_sub(1);
        window_start += keep as u64;
        window.drain(..keep);
    }
}

/// Walks the extended-header chain that begins at `at` (the `u16` "1st
/// extended header size" word behind a basic header) and answers the absolute
/// position of the first PAYLOAD byte.
///
/// `None` when the chain runs past the source or past [`MAX_EXT_CHAIN`] — to
/// a scanner that means the payload's position is unknowable, which is the
/// same answer as "these bytes were not a header".
///
/// # The chain's own CRC-32s are deliberately NOT checked
///
/// `unarj_rs::arj_archive::read_extended_headers` validates one per extended
/// header, and mirroring that here would make the gate stronger still — and
/// would cost a recoverable entry whose only damage is in a field the
/// payload's position does not depend on. The basic header's own CRC-32
/// (criterion 4) is already thirty-two bits of gate; this walk is about
/// ARITHMETIC, not about trust, so it reads two bytes per hop and SEEKS past
/// everything else.
fn walk_extended_headers(src: &mut dyn SeekRead, at: u64, file_len: u64) -> Option<u64> {
    let mut pos = at;
    let mut walked = 0u64;
    let mut size_buf = [0u8; 2];
    loop {
        if pos.checked_add(2)? > file_len {
            return None;
        }
        src.seek(SeekFrom::Start(pos)).ok()?;
        src.read_exact(&mut size_buf).ok()?;
        pos = pos.checked_add(2)?;
        walked = walked.checked_add(2)?;

        let declared = u64::from(u16::from_le_bytes(size_buf));
        if declared == 0 {
            // The spec's terminator: "1st extended header size (0 if none)",
            // and `read_extended_headers` loops on the same rule. The payload
            // begins here.
            return Some(pos);
        }
        // The header's own bytes plus the CRC-32 that follows every non-empty
        // one.
        let step = declared.checked_add(4)?;
        if pos.checked_add(step)? > file_len {
            return None;
        }
        pos = pos.checked_add(step)?;
        walked = walked.checked_add(step)?;
        if walked > MAX_EXT_CHAIN {
            return None;
        }
    }
}

/// Reads and gates the header believed to start at `offset`, per the criteria
/// in this module's doc.
///
/// `None` for ANY gate failure, including a genuine read error: to a SCANNER
/// they all mean the same thing — these bytes are not a header — so they fold
/// here rather than propagating and ending a run over one coincidence.
fn parse_header_at(src: &mut dyn SeekRead, offset: u64, file_len: u64) -> Option<EntryHeader> {
    // Criterion 3, first half: the envelope's own fixed bytes must be there
    // before anything they describe is read.
    if file_len.checked_sub(offset)? < ENVELOPE_PREFIX + ENVELOPE_SUFFIX {
        return None;
    }
    src.seek(SeekFrom::Start(offset)).ok()?;
    let mut prefix = [0u8; 4];
    src.read_exact(&mut prefix).ok()?;

    // Criterion 1. The caller found this id, but a candidate must never stand
    // on its caller's word for a field it can read itself.
    if prefix[..2] != HEADER_ID {
        return None;
    }

    // Criterion 2. A declared size of zero is the end-of-archive marker, and
    // the 2600-byte ceiling is the spec's own — bounding the read below to a
    // fixed, small figure that nothing in the file can raise.
    let declared_header = usize::from(u16::from_le_bytes([prefix[2], prefix[3]]));
    if declared_header == 0 || declared_header > MAX_ARJ_HEADER_SIZE {
        return None;
    }

    // Criterion 3, second half.
    let content_at = offset.checked_add(ENVELOPE_PREFIX)?;
    let content_end = content_at.checked_add(declared_header as u64)?;
    if content_end.checked_add(ENVELOPE_SUFFIX)? > file_len {
        return None;
    }
    let mut content = vec![0u8; declared_header];
    src.read_exact(&mut content).ok()?;
    let mut crc_bytes = [0u8; 4];
    src.read_exact(&mut crc_bytes).ok()?;

    // Criterion 4 — the strongest signal here by three orders of magnitude,
    // and one of the three Step 5 falsifies.
    if crc32_ieee(&content) != u32::from_le_bytes(crc_bytes) {
        return None;
    }

    // Criterion 5.
    let first_hdr_size = usize::from(*content.get(FIRST_HDR_SIZE_I)?);
    if first_hdr_size < ARJ_FIRST_HDR_SIZE as usize || first_hdr_size > content.len() {
        return None;
    }

    // Criterion 6 — the basic-header-size identity, and the second signal
    // Step 5 falsifies. Both strings are NUL-terminated and both terminators
    // must fall inside the content the header itself declared.
    let name_bytes = content.get(first_hdr_size..)?;
    let name_len = name_bytes.iter().position(|&b| b == 0)?;
    let comment_at = first_hdr_size.checked_add(name_len)?.checked_add(1)?;
    let comment_len = content.get(comment_at..)?.iter().position(|&b| b == 0)?;
    if first_hdr_size
        .checked_add(name_len)?
        .checked_add(1)?
        .checked_add(comment_len)?
        .checked_add(1)?
        != declared_header
    {
        return None;
    }
    // A nameless entry is not a shape any ARJ writer produces, and it is what
    // a run of zeroed bytes behind a coincidental id looks like.
    if name_len == 0 {
        return None;
    }

    // Criterion 7 — see this module's doc. The archive's own MAIN header, and
    // a comment header, are indistinguishable from each other and neither is
    // a file entry with a payload.
    let file_type = *content.get(FILE_TYPE_I)?;
    if file_type == MAIN_HEADER_FILE_TYPE {
        return None;
    }

    // Criterion 8.
    let method = Method::from_byte(*content.get(METHOD_I)?)?;

    // Criterion 9.
    let payload_start = walk_extended_headers(src, content_end.checked_add(4)?, file_len)?;

    let compressed_size = read_u32(&content, COMPRESSED_SIZE_I)?;
    let original_size = read_u32(&content, ORIGINAL_SIZE_I)?;
    let file_crc = read_u32(&content, ORIGINAL_CRC_I)?;
    let packed_time = read_u32(&content, DATE_TIME_I)?;
    let access_mode = u16::from_le_bytes(
        content
            .get(FILE_ACCESS_MODE_I..FILE_ACCESS_MODE_I + 2)?
            .try_into()
            .ok()?,
    );
    let host_os = *content.get(HOST_OS_I)?;

    Some(EntryHeader {
        method,
        declared_len: u64::from(compressed_size),
        original_size: u64::from(original_size),
        file_crc,
        mtime: dos_mtime(DosDateTime::new(packed_time)),
        // `arj.rs`'s own `unix_mode` rule, reproduced rather than reached
        // into (it takes an `unarj_rs::LocalFileHeader` this module never
        // builds): the `file access mode` field is HOST-DEFINED, so only a
        // header declaring host OS 2 (UNIX) puts a unix mode there, and a
        // zero is an absence rather than mode `0o000`.
        mode: (host_os == HOST_OS_UNIX && access_mode != 0).then(|| u32::from(access_mode)),
        // `arj.rs`'s own "Entry kinds" mapping, minus the `CommentHeader`
        // arm criterion 7 already removed: only `Binary` (0) and `Text7Bit`
        // (1) are plain files, `Directory` (3) is a directory, and every
        // other value is the kind that cannot say what it is.
        kind: match file_type {
            0 | 1 => EntryKind::File,
            FILE_TYPE_DIRECTORY => EntryKind::Dir,
            _ => EntryKind::Other,
        },
        // `unarj_rs`'s `convert_string!` pushes each byte as a `char`, i.e. a
        // LATIN-1 decode, and `arj.rs` reports exactly that string. Name
        // matching in this project is EXACT (`--pattern`, `cat NAME`), so a
        // scanner with its own decoding would report entries under names
        // `stuffr list` never shows.
        name: content
            .get(first_hdr_size..first_hdr_size + name_len)?
            .iter()
            .map(|&b| b as char)
            .collect(),
        payload_start,
    })
}

/// A little-endian `u32` at `at`, or `None` if the content is shorter than
/// the field the layout puts there.
fn read_u32(content: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        content.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Turns a gated [`EntryHeader`] into the [`Candidate`] the engine annotates.
fn read_candidate_at(src: &mut dyn SeekRead, offset: u64, file_len: u64) -> Option<Candidate> {
    let header = parse_header_at(src, offset, file_len)?;

    let declared = header.declared_len;
    let available_len = match header.payload_start.checked_add(declared) {
        Some(end) if end <= file_len => None,
        // Either the declared end overflows `u64`, or it runs past the
        // source. Both mean the same thing to a reader: fewer bytes are
        // present than the header promises.
        _ => {
            let present = file_len.saturating_sub(header.payload_start);
            // `Some(n)` ALWAYS means `n < declared_len`, per the field's own
            // contract.
            (present < declared).then_some(present)
        }
    };

    let mut meta = EntryMeta::file(header.name.clone());
    meta.size = Some(header.original_size);
    meta.compressed_size = Some(declared);
    meta.kind = header.kind;
    meta.mtime = header.mtime;
    meta.mode = header.mode;
    meta.codec = Some(header.method.codec());

    Some(Candidate {
        offset,
        // Computed ONCE, here, with `checked_add` throughout — see
        // `Candidate::payload_start`'s own doc for why no consumer may
        // re-derive it from `offset`.
        payload_start: header.payload_start,
        meta,
        declared_len: Some(declared),
        verifier: Some(Verifier::Crc32(header.file_crc)),
        available_len,
        // ARJ has no deleted flag — `arj flags`' assigned bits are GARBLED,
        // VOLUME, EXTFILE, PATHSYM and BACKUP, none of which marks a record
        // removed. See `Candidate::marked_deleted`'s own doc for why that is
        // a plain `false` rather than an `Option`.
        marked_deleted: false,
    })
}

/// A `Read` over `delharc`'s all-or-nothing [`Decoder::fill_buffer`], bounded
/// by the entry's own declared uncompressed length.
///
/// Transcribed from `lha_salvage.rs`'s reader of the same name, because it is
/// the same decoder with the same all-or-nothing contract: the bound is what
/// makes `fill_buffer` usable at all, since it fills the whole slice it is
/// handed or fails, and a caller that asked for more than the entry contains
/// would turn a complete decode into an error.
///
/// Each call decodes at most [`DECODE_CHUNK`] bytes — and, past
/// [`Self::fine_from`], exactly one — see [`recover_the_last_chunk`] for why
/// a recovery verb needs both.
struct DecodedReader<R> {
    decoder: DecoderAny<R>,
    /// Decoded bytes still owed before this entry's own declared
    /// uncompressed length is reached.
    remaining: u64,
    /// Decoded bytes produced so far, which is what [`Self::fine_from`] is
    /// compared against.
    produced: u64,
    /// The decoded position past which this reader decodes **one byte at a
    /// time** instead of [`DECODE_CHUNK`] at a time. `u64::MAX` — the
    /// ordinary case — means "never": chunked throughout.
    fine_from: u64,
}

impl<R: io::Read> io::Read for DecodedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let chunk = if self.produced >= self.fine_from {
            1
        } else {
            // Never step ACROSS the boundary: a chunk that straddled it would
            // take the fine-grained region's first bytes with it if it
            // failed, which is the whole thing the boundary exists to stop.
            DECODE_CHUNK.min(usize::try_from(self.fine_from - self.produced).unwrap_or(usize::MAX))
        };
        let len = buf
            .len()
            .min(chunk)
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        self.decoder
            .fill_buffer(&mut buf[..len])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
        self.remaining -= len as u64;
        self.produced += len as u64;
        Ok(len)
    }
}

/// Counts what reaches `inner`, so [`write_payload`] knows how much of a
/// truncated entry its first pass actually recovered without `inner` having
/// to be seekable.
struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    written: u64,
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A reader over one entry's RECOVERED (decoded) bytes.
///
/// A DIRECTORY entry gets [`io::empty`]: ARJ records the kind in a field of
/// its own, so a directory has no payload to decode however its `method` byte
/// reads — which is exactly what `arj.rs`'s reader does (it `skip`s the
/// declared bytes rather than decoding them).
///
/// The three arms below are `unarj_rs::ArjArchieve::read`'s own dispatch,
/// reached directly — see this module's doc.
fn decoded_reader<'a, R: io::Read + 'a>(
    method: Method,
    is_dir: bool,
    compressed: R,
    expected_len: u64,
    fine_from: u64,
) -> io::Result<Box<dyn io::Read + 'a>> {
    if is_dir {
        return Ok(Box::new(io::empty()));
    }
    match method {
        // The payload IS the entry. No decoder, no allocation, and a
        // truncated entry gives up its genuine prefix for free.
        Method::Stored => Ok(Box::new(compressed)),
        Method::CompressedFastest => {
            // **The one arm with no streaming form.** Both allocations here
            // are already bounded: the compressed side by the engine's own
            // ceiling (`max_whole_entry`, applied before `verify` is called
            // at all), the decoded side by
            // `Method::allocates_from_original_size`'s check in the two
            // callers below.
            let mut raw = Vec::new();
            let mut compressed = compressed;
            compressed.read_to_end(&mut raw)?;
            if starts_with_a_backreference(&raw, expected_len) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ARJ method 4 stream opens with a back-reference and has no history to \
                     copy from",
                ));
            }
            let decoded =
                decode_fastest(&raw, usize::try_from(expected_len).unwrap_or(usize::MAX))?;
            Ok(Box::new(io::Cursor::new(decoded)))
        }
        other => {
            let Some(lzh) = other.lzh_compression() else {
                // `NoData`/`NoDataNoCrc`: both callers refuse an undecodable
                // method before reaching here, so this is an unreachable
                // backstop rather than a second refusal path.
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("ARJ method {} has no decoder in this build", other.byte()),
                ));
            };
            Ok(Box::new(DecodedReader {
                decoder: DecoderAny::new_from_compression(lzh, compressed),
                remaining: expected_len,
                produced: 0,
                fine_from,
            }))
        }
    }
}

/// Whether a method-4 stream opens with a back-reference, which
/// `unarj_rs::decode_fastest` **panics** on.
///
/// # This is a real panic in a dependency, on two bits of input
///
/// `decode_fastest` (crate 0.2.1, `decode_fastest.rs:38`) evaluates
/// `back_ptr > res.len() - 1` for every token that is not a literal, and
/// `res` is EMPTY on the first iteration — so a stream whose first token is a
/// match underflows a `usize` and aborts the process (`attempt to subtract
/// with overflow` in a debug build; a wrapped comparison and then an
/// out-of-range index in a release one). It was found by this module's own
/// `garbage_under_a_compressed_method_is_partial` test on the first run,
/// which is a fair summary of how reachable it is.
///
/// The predicate is exactly one BIT, which is what makes this a guard rather
/// than a second decoder. `decode_val(r, 0, 7)` reads one bit and breaks
/// immediately on a zero, answering `len == 0` — a literal; any other first
/// bit means a match. The stream is MSB-first (`BitReader::endian(data,
/// BigEndian)`), so "the first token is a match" is precisely
/// `data[0] & 0x80 != 0`. An empty `data`, or a zero `original_size`, never
/// reaches the subtraction at all: the loop is `while res.len() <
/// original_size` and the read fails first.
///
/// **`arj.rs`'s ORDINARY reader is exposed to the same panic and this does
/// not close it**: `ArjArchieve::read` performs the whole decode behind one
/// call, with no way for a caller to inspect the payload's first byte first,
/// so `stuffr list`/`cat`/`unpack` on a crafted method-4 archive still abort
/// at exit 101. Recorded in this task's report as a finding for a follow-up
/// rather than fixed here, because closing it means restructuring that
/// reader off `ArjArchieve::read`, which is a change to the READ path and
/// not to this scanner.
fn starts_with_a_backreference(data: &[u8], original_size: u64) -> bool {
    original_size > 0 && data.first().is_some_and(|b| b & 0x80 != 0)
}

/// Decides [`SalvageStatus`] for one candidate by decoding its payload
/// through the decoders `unarj-rs` itself dispatches to and comparing the
/// result against the candidate's [`Verifier::Crc32`] via Task 1's shared
/// [`crate::salvage_verify::stream_verify`].
///
/// **Never returns `Err`, for any input.** Malformed, truncated and genuinely
/// I/O-failing input all fold into [`SalvageStatus::Partial`] or an
/// [`UnverifiedCause`], the discipline `zip_salvage.rs`'s, `arc_salvage.rs`'s,
/// `zoo_salvage.rs`'s and `lha_salvage.rs`'s own `verify_candidate` document
/// at length: an `Err` out of `verify` aborts the WHOLE run and discards
/// every entry already recovered, which is the one thing this verb exists not
/// to do. The `Result` in the signature is the trait's, kept so a scanner CAN
/// report a genuine whole-run fault; this implementation has none to report.
///
/// # The second declared length, and why it needs its own answer here
///
/// `annotate_candidates` bounds `declared_len` — the COMPRESSED length —
/// against [`ArjSalvage::max_whole_entry`] before this runs, so nothing here
/// needs to re-check that figure. `original_size` is a SECOND, independent
/// `u32` the engine never sees (it reaches [`EntryMeta::size`] and nothing the
/// engine compares), and `unarj_rs::decode_fastest` sizes its output from it:
/// left unbounded that is a 4 GiB allocation from a header field.
///
/// It is answered as a per-entry [`UnverifiedCause::OverEntryCeiling`],
/// **never** as an `Err`, and **gated to the one arm that allocates from it**
/// — ZOO's fix round 1 measured what applying it to every arm costs: a
/// completely recoverable payload reported "over the ceiling" and written
/// nowhere, because `entries.rs`'s `place_salvaged_file` never writes an
/// `Unverified` entry.
fn verify_candidate(src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
    // The payload is PROVABLY incomplete — nothing needs decoding to know the
    // answer. Sits above the method dispatch for the reason
    // `zip_salvage.rs`'s own `verify_candidate` gives: a truncated payload
    // under an undecodable method is still truncated, and `Partial` (proven
    // missing) is a stronger claim than `Unverified` (nothing attempted).
    if candidate.available_len.is_some() {
        return Ok(SalvageStatus::Partial);
    }
    let Some(declared_len) = candidate.declared_len else {
        // Unreachable in practice: `read_candidate_at` always reports one.
        // Kept as the honest fallback rather than a `Complete` this scanner
        // never means — every ARJ local file header carries a CRC-32.
        return Ok(SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength));
    };
    let Some(Verifier::Crc32(expected_crc)) = candidate.verifier else {
        // Likewise unreachable: `read_candidate_at` gives every ARJ candidate
        // a `Verifier::Crc32`, because the format mandates one.
        // `NoDeclaredLength` is the NEAREST cause this enum offers and not an
        // accurate one — a length was declared; a checksum was not — and
        // saying so is better than answering `Complete`, which would claim
        // the format has no checksum to offer when ARJ's whole point here is
        // that it does. All three `Unverified` causes lead to the same
        // decision (listed, not written, exit 3); see `UnverifiedCause`'s own
        // doc, "a tier carries a decision, a message carries a cause".
        return Ok(SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength));
    };
    let Some(method) = method_for_codec(candidate.meta.codec) else {
        return Ok(SalvageStatus::Unverified(
            UnverifiedCause::UndecodableMethod,
        ));
    };
    if !method.decodable() && !matches!(candidate.meta.kind, EntryKind::Dir) {
        // The archive is fine; this build has no decoder for methods 8 and 9
        // — the same answer `arj.rs`'s reader gives them (exit 3).
        // `Unverified`, never `Complete` and never `Partial`: nothing was
        // attempted, so nothing failed.
        return Ok(SalvageStatus::Unverified(
            UnverifiedCause::UndecodableMethod,
        ));
    }

    let expected_len = candidate.meta.size.unwrap_or(0);
    // See this function's doc. Gated to the arm that allocates from the
    // field, and answered as a status rather than an `Err`.
    if method.allocates_from_original_size()
        && !matches!(candidate.meta.kind, EntryKind::Dir)
        && expected_len > MAX_ARJ_ENTRY_LEN
    {
        return Ok(SalvageStatus::Unverified(
            UnverifiedCause::OverEntryCeiling {
                needed: expected_len,
                ceiling: MAX_ARJ_ENTRY_LEN,
            },
        ));
    }

    if src.seek(SeekFrom::Start(candidate.payload_start)).is_err() {
        return Ok(SalvageStatus::Partial);
    }
    let compressed = src.take(declared_len);
    let decoded = match decoded_reader(
        method,
        matches!(candidate.meta.kind, EntryKind::Dir),
        compressed,
        expected_len,
        u64::MAX,
    ) {
        Ok(decoded) => decoded,
        // A decode that could not even START (method 4's whole-slice read, or
        // its bitstream refusing the input) is exactly as unproven as one
        // that fails midway — `Partial`, not a second `Err` path.
        Err(_) => return Ok(SalvageStatus::Partial),
    };

    Ok(crate::salvage_verify::stream_verify(
        decoded,
        expected_len,
        &Verifier::Crc32(expected_crc),
    ))
}

/// Reads one entry's stored payload and writes its RECOVERED (decoded) bytes
/// to `out`. Returns whether the decode reached the entry's own declared
/// length ([`EntryMeta::size`]) — `entries.rs`'s own signal for
/// `PartialCause`, matching `zip_salvage.rs`'s, `arc_salvage.rs`'s,
/// `zoo_salvage.rs`'s and `lha_salvage.rs`'s `write_payload` exactly.
///
/// Uses [`SalvagedEntry::payload_start`] directly, computed once by
/// [`read_candidate_at`] at discovery — see that field's own doc for why a
/// consumer must never re-derive a payload's location from `offset`.
///
/// # What is bounded, and what needs no bound
///
/// The compressed read is bounded by what the SOURCE actually holds
/// (`available` below, from a fresh `seek(End(0))`), never by `compressed_len`
/// alone, so a truncated entry's genuine surviving prefix still reaches the
/// decoder and is written rather than the whole read failing and nothing being
/// written — `arc_salvage.rs`'s fix rounds 1 and 2, inherited rather than
/// rediscovered.
///
/// Both ceiling branches are gated to [`Method::allocates_from_original_size`]
/// — method 4 — and through `stuffr::entries::salvage` neither is reachable at
/// all (the engine's own `max_whole_entry` refuses such an entry before any
/// writer is called). They are kept because this function is `pub`: a direct
/// caller supplying its own [`SalvagedEntry`] gets the bound too.
///
/// A decode that fails here is re-running bytes [`verify_candidate`] already
/// examined (or a genuine prefix of them), and is folded into `Ok(false)` for
/// the same reason that function folds the same failures into `Partial`: one
/// entry's damage must never abort the recovery of every other entry in the
/// archive.
pub fn write_payload(
    archive_path: &Path,
    entry: &SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
) -> Result<bool> {
    // Refused BEFORE `archive_path` is opened, which `entries.rs`'s own
    // `salvage_seam_tests::every_salvage_slot_reaches_a_real_payload_writer`
    // relies on: it probes every slot with a codec-less entry and a path that
    // does not exist.
    let Some(method) = method_for_codec(entry.meta.codec) else {
        return Err(Error::Unsupported(format!(
            "entry `{}` carries codec {:?}, which this build's ARJ salvage writer does not \
             decode (every method byte outside ARJ's own table is already refused at \
             discovery, so this is a backstop rather than a reachable answer)",
            entry.meta.name, entry.meta.codec
        )));
    };
    if !method.decodable() && !matches!(entry.meta.kind, EntryKind::Dir) {
        // Reachable only through this function's own `pub` door: through
        // `entries::salvage` such an entry is `Unverified` and
        // `place_salvaged_file` never writes one. `Error::Unsupported` is
        // what `place_salvaged_file` maps to `SkippedNotBuiltIn`, which is
        // the honest disposition — this build has no decoder, so there is
        // nothing recovered to write.
        return Err(Error::Unsupported(format!(
            "entry `{}` uses ARJ compression method {}, which this build cannot decode \
             (`unarj-rs` has no decoder for the two NO DATA methods)",
            entry.meta.name,
            method.byte(),
        )));
    }

    let mut f = File::open(archive_path)?;
    let Ok(file_len) = f.seek(SeekFrom::End(0)) else {
        return Ok(false);
    };
    if f.seek(SeekFrom::Start(entry.payload_start)).is_err() {
        return Ok(false);
    }

    // Bound by what the SOURCE actually holds, never by `compressed_len`
    // alone — see this function's own doc.
    let available = file_len.saturating_sub(entry.payload_start);
    let readable_len = compressed_len.min(available);
    // Decided from the two lengths alone, BEFORE the read: if fewer
    // compressed bytes are present than the header declared, this entry's
    // payload is truncated, full stop, regardless of what
    // `stream_bounded_copy` goes on to report against a declared uncompressed
    // size small enough that a partial decode still satisfies it
    // (`arc_salvage.rs`'s fix round 2, NEW-1 — a message must not contradict
    // the reason the entry is `Partial` in the first place).
    let truncated = readable_len < compressed_len;

    let expected = entry.meta.size.unwrap_or(0);
    if method.allocates_from_original_size()
        && !matches!(entry.meta.kind, EntryKind::Dir)
        && (expected > MAX_ARJ_ENTRY_LEN || readable_len > MAX_ARJ_ENTRY_LEN)
    {
        return Ok(false);
    }

    let mut counting = CountingWriter {
        inner: out,
        written: 0,
    };
    let completed = {
        let decoded = match decoded_reader(
            method,
            matches!(entry.meta.kind, EntryKind::Dir),
            (&mut f).take(readable_len),
            expected,
            u64::MAX,
        ) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(false),
        };
        stream_bounded_copy(decoded, expected, &mut counting)?
    };

    if !completed && counting.written < expected && method.lzh_compression().is_some() {
        recover_the_last_chunk(&mut f, entry, method, readable_len, expected, &mut counting)?;
    }

    Ok(completed && !truncated)
}

/// The second pass over a `delharc`-decoded payload the first one could not
/// finish: re-decodes what already worked, then creeps through the region
/// where the stream dies, one byte at a time, appending whatever more it can
/// reach.
///
/// # Why a second pass exists at all
///
/// `delharc`'s [`Decoder::fill_buffer`] is all-or-nothing — it fills the whole
/// slice it is handed or fails, and a failure says nothing about how much of
/// that slice it had already written, so those bytes cannot be used. On a
/// healthy archive that costs nothing. On a TRUNCATED entry it is the
/// difference between recovering a prefix and recovering nothing: the last
/// [`DECODE_CHUNK`] bytes requested are simply lost, **and for any entry
/// smaller than one chunk that is the entire payload**. `lha_salvage.rs`
/// measured exactly that before its own copy of this function existed (a
/// 144-byte entry cut 30 bytes short recovered 0 of the 114 bytes present),
/// and this module's `delharc` arm is the same decoder with the same
/// contract.
///
/// Only the `delharc` arm needs it: [`Method::Stored`] streams the file's own
/// bytes and recovers its prefix for free, and
/// [`Method::CompressedFastest`]'s whole-slice decode has no partial result
/// to recover.
///
/// The cost is bounded and falls only on the failure path: one extra decode of
/// the bytes already recovered (in ordinary [`DECODE_CHUNK`] steps, which is
/// what [`DecodedReader::fine_from`] is for), plus at most one chunk's worth
/// of single-byte steps. A healthy entry never reaches this function.
fn recover_the_last_chunk(
    f: &mut File,
    entry: &SalvagedEntry,
    method: Method,
    readable_len: u64,
    expected: u64,
    out: &mut CountingWriter<'_>,
) -> Result<()> {
    let already = out.written;
    if f.seek(SeekFrom::Start(entry.payload_start)).is_err() {
        return Ok(());
    }
    let Ok(mut decoded) = decoded_reader(
        method,
        matches!(entry.meta.kind, EntryKind::Dir),
        (&mut *f).take(readable_len),
        expected,
        already,
    ) else {
        return Ok(());
    };
    // Re-decode and DISCARD what the first pass already wrote. `already` is
    // exactly what reached `out`, so this cannot skip a byte the caller has
    // not seen — and it runs at full chunk size, since `fine_from` is that
    // same figure.
    if io::copy(&mut (&mut decoded).take(already), &mut io::sink()).is_err() {
        // The identical bytes decoded a moment ago; a failure here means the
        // source changed underneath us. One entry's problem, never the run's.
        return Ok(());
    }
    stream_bounded_copy(decoded, expected - already, out)?;
    Ok(())
}

/// Runs [`ArjSalvage`] over `src` and annotates the result — the whole
/// scanner, matching `zip_salvage.rs`'s `salvage_zip`, `arc_salvage.rs`'s
/// `salvage_arc`, `zoo_salvage.rs`'s `salvage_zoo` and `lha_salvage.rs`'s
/// `salvage_lha` entry points exactly (`entries.rs`'s `salvage_scan`
/// dispatches to all five the same way).
///
/// Like ARC, ZOO and LHA, and unlike zip, there is no second index to
/// reconcile against: ARJ has no central directory and no entry count at all,
/// so the raw scan is the only source there is. And unlike LHA there is no
/// Ruling S-V refusal to raise — see this module's doc for why `file type ==
/// 2` deliberately gets no sighting channel.
pub fn salvage_arj(src: &mut dyn SeekRead, policy: &SalvagePolicy) -> Result<SalvageOutcome> {
    let mut scanner = ArjSalvage::new();
    salvage_all(&mut scanner, src, policy)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use stuffr_core::salvage::MAX_SALVAGE_ENTRY;

    use super::*;

    /// The checked-in fixture: two `Stored` entries, hand-built in Phase 3b
    /// from the published header tables. **Its provenance is the weakest in
    /// this tree** — see `fixtures/legacy/MANIFEST.md` and this module's own
    /// doc — so a test standing on it proves this scanner agrees with the
    /// bytes Phase 3b transcribed, and nothing beyond that.
    const SAMPLE_ARJ: &[u8] = include_bytes!("../../fixtures/legacy/sample.arj");

    fn scan(bytes: &[u8]) -> SalvageOutcome {
        salvage_arj(&mut Cursor::new(bytes.to_vec()), &SalvagePolicy::default())
            .expect("a salvage scan must not error over any input")
    }

    // -------------------------------------------------------------------
    // Fixture builders.
    //
    // These wrap the header CONTENT the way the spec's envelope does, and
    // they are this module's own transcription — the SAME weakness `arj.rs`'s
    // `build_arj` carries and says so about. Where a check below could
    // instead stand on the PRODUCTION writer it does
    // (`write_arj_through_the_real_writer`), which is a different kind of
    // weak: the encoder and this parser are both this project's.
    // -------------------------------------------------------------------

    /// The spec's envelope: id, `u16` content length, content, CRC-32 over
    /// the content, and the `u16` zero that terminates the extended-header
    /// chain.
    fn wrap(content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&HEADER_ID);
        out.extend_from_slice(&(content.len() as u16).to_le_bytes());
        out.extend_from_slice(content);
        out.extend_from_slice(&crc32_ieee(content).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// A local file header's content, with every field at its spec offset.
    fn local_content(
        name: &[u8],
        method: u8,
        file_type: u8,
        compressed_size: u32,
        original_size: u32,
        crc: u32,
    ) -> Vec<u8> {
        let mut c = vec![
            ARJ_FIRST_HDR_SIZE,
            0, // archiver version
            0, // minimum version to extract
            HOST_OS_UNIX,
            0, // arj flags
            method,
            file_type,
            0, // reserved
        ];
        c.extend_from_slice(&0u32.to_le_bytes()); // date time modified
        c.extend_from_slice(&compressed_size.to_le_bytes());
        c.extend_from_slice(&original_size.to_le_bytes());
        c.extend_from_slice(&crc.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes()); // filespec position
        c.extend_from_slice(&0u16.to_le_bytes()); // file access mode
        c.extend_from_slice(&0u16.to_le_bytes()); // host data
        assert_eq!(c.len(), ARJ_FIRST_HDR_SIZE as usize);
        c.extend_from_slice(name);
        c.push(0); // name terminator
        c.push(0); // comment terminator
        c
    }

    /// One `Stored` entry: header plus its verbatim payload.
    fn stored_entry(name: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = wrap(&local_content(
            name,
            Method::Stored.byte(),
            0,
            payload.len() as u32,
            payload.len() as u32,
            crc32_ieee(payload),
        ));
        out.extend_from_slice(payload);
        out
    }

    /// The archive main header, `file type = 2`.
    ///
    /// It carries a non-empty ARCHIVE NAME on purpose, unlike `arj.rs`'s own
    /// writer (which emits an empty one): with an empty name, criterion 6's
    /// "a nameless entry is not a header" clause would reject a main header
    /// before criterion 7 ever looked at its `file type`, and
    /// `the_main_header_is_never_reported_as_an_entry` would then be pinning
    /// the wrong criterion. Real ARJ stores the archive's own filename here,
    /// so the named form is also the commoner one in the wild.
    fn main_header() -> Vec<u8> {
        let mut c = vec![ARJ_FIRST_HDR_SIZE, 0, 0, HOST_OS_UNIX, 0, 0];
        c.push(MAIN_HEADER_FILE_TYPE);
        c.push(0); // reserved
        c.extend_from_slice(&[0u8; 16]); // two timestamps, archive size, envelope position
        c.extend_from_slice(&[0u8; 6]); // filespec position, envelope length, unused
        assert_eq!(c.len(), ARJ_FIRST_HDR_SIZE as usize);
        c.extend_from_slice(b"archive.arj");
        c.push(0); // archive name terminator
        c.push(0); // archive comment (empty)
        wrap(&c)
    }

    /// A whole archive: main header, the entries, end-of-archive marker.
    fn build_archive(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = main_header();
        for (name, payload) in entries {
            out.extend_from_slice(&stored_entry(name, payload));
        }
        out.extend_from_slice(&HEADER_ID);
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn temp_archive(bytes: &[u8], tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "stuffr-arj-salvage-{tag}-{}-{:?}.arj",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, bytes).expect("write temp archive");
        path
    }

    fn entry_for(outcome: &SalvageOutcome, name: &str) -> usize {
        outcome
            .entries
            .iter()
            .position(|e| e.meta.name == name)
            .unwrap_or_else(|| panic!("no entry named {name}"))
    }

    // -------------------------------------------------------------------
    // The anti-vacuity pair (Step 1)
    // -------------------------------------------------------------------

    /// A small linear congruential generator, not the `rand` crate — the
    /// corpus must be byte-identical on every machine and in CI. Same
    /// constants (Knuth & Lewis, via Numerical Recipes) `zip_salvage.rs`,
    /// `arc_salvage.rs`, `zoo_salvage.rs` and `lha_salvage.rs` use.
    fn deterministic_noise(len: usize) -> Vec<u8> {
        let mut state: u32 = 0xC0FF_EE42;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Fixed offsets where only the two id bytes are forced — everything
    /// behind them stays whatever the LCG produced.
    ///
    /// # Why seeding these is almost beside the point
    ///
    /// **Two bytes of magic is the weakest anchor of the five scanners.**
    /// `0x60 0xEA` occurs in uniform random bytes about once per 64 KiB, so
    /// a 1 MiB corpus already holds roughly sixteen by chance — against
    /// `lha`'s one per 93 GiB and `zoo`'s one per 4 GiB. The seeds below only
    /// make the count deterministic; they are not what makes this test a test
    /// of the gate. The three CRAFTED splices below are.
    const SEEDED_ID_OFFSETS: [usize; 6] = [65_536, 196_608, 344_064, 491_520, 638_976, 786_432];

    /// A complete, otherwise gate-clearing archive whose ONLY defect is the
    /// basic header CRC-32 (criterion 4) — the strongest single signal here,
    /// and therefore the one whose deletion would be least visible.
    const CRC_ONLY_DEFECT_OFFSET: usize = 300_000;

    /// A complete, otherwise gate-clearing archive whose ONLY defect is the
    /// basic-header-size identity (criterion 6): one stray byte behind the
    /// comment terminator, the `u16` length raised to match, and the CRC-32
    /// RECOMPUTED so criterion 4 still clears. Step 5 falsifies exactly this.
    const IDENTITY_ONLY_DEFECT_OFFSET: usize = 500_000;

    /// A complete, internally consistent header whose ONLY defect is that its
    /// basic header size is past the spec's 2600-byte maximum (criterion 2) —
    /// correct CRC-32, correct identity, wholly present in the file.
    const OVERSIZED_HEADER_OFFSET: usize = 700_000;

    fn crc_only_defect() -> Vec<u8> {
        let content = local_content(
            b"CRCONLY.TXT",
            Method::Stored.byte(),
            0,
            7,
            7,
            crc32_ieee(b"payload"),
        );
        let mut bytes = wrap(&content);
        bytes.extend_from_slice(b"payload");
        // The four CRC bytes sit behind the content, which is untouched — so
        // the identity, the method, the file type and both sizes all still
        // clear, and only the recorded checksum disagrees.
        let at = ENVELOPE_PREFIX as usize + content.len();
        bytes[at] ^= 0x01;
        bytes
    }

    fn identity_only_defect() -> Vec<u8> {
        let mut content = local_content(b"IDONLY.TXT", Method::Stored.byte(), 0, 7, 7, 0);
        // One byte past the comment terminator: the declared basic header
        // size now counts a byte the identity does not.
        content.push(0x41);
        let mut out = wrap(&content);
        out.extend_from_slice(b"payload");
        out
    }

    fn oversized_header() -> Vec<u8> {
        // A name long enough to push the basic header size past 2600 —
        // everything else about the header is correct, including its CRC-32.
        let name = vec![b'X'; MAX_ARJ_HEADER_SIZE];
        stored_entry(&name, b"payload")
    }

    fn noise_with_seeded_ids(len: usize) -> Vec<u8> {
        let mut noise = deterministic_noise(len);
        for &at in &SEEDED_ID_OFFSETS {
            noise[at..at + 2].copy_from_slice(&HEADER_ID);
        }
        for (at, defect) in [
            (CRC_ONLY_DEFECT_OFFSET, crc_only_defect()),
            (IDENTITY_ONLY_DEFECT_OFFSET, identity_only_defect()),
            (OVERSIZED_HEADER_OFFSET, oversized_header()),
        ] {
            noise[at..at + defect.len()].copy_from_slice(&defect);
        }
        noise
    }

    /// The negative double for the whole feature: a scanner that reported
    /// every header-id sighting as an entry would be worse than no scanner at
    /// all — and with a two-byte id that is a real risk rather than a
    /// theoretical one.
    #[test]
    fn arj_salvage_over_random_bytes_finds_nothing() {
        let noise = noise_with_seeded_ids(1 << 20); // 1 MiB, fixed seed
        let out = scan(&noise);
        assert!(
            out.entries.is_empty(),
            "found {} phantom entries in noise: {:?}",
            out.entries.len(),
            out.entries
                .iter()
                .map(|e| (&e.meta.name, e.offset))
                .collect::<Vec<_>>()
        );
    }

    /// Without this, the test above could pass because the noise happens to
    /// contain no header id at all — proving nothing about the validation
    /// gate. This asserts the gate is what rejects the hits, not their
    /// absence.
    #[test]
    fn the_arj_noise_corpus_really_does_contain_the_header_id() {
        let noise = noise_with_seeded_ids(1 << 20);
        let hits = noise.windows(2).filter(|w| *w == HEADER_ID).count();
        // The six deliberately seeded ids, plus one for each of the three
        // spliced archives. `>=` rather than `==`: this does not also assert
        // the LCG produces no INCIDENTAL id of its own — with a two-byte
        // anchor it certainly does, which is the point.
        let seeded = SEEDED_ID_OFFSETS.len() + 3;
        assert!(
            hits >= seeded,
            "expected at least the {seeded} deliberately placed ids, found {hits}"
        );
    }

    /// Isolates `CRC_ONLY_DEFECT_OFFSET`'s own archive to prove it clears
    /// every OTHER criterion — so deleting criterion 4 is really what the
    /// falsification in the task report exercises.
    #[test]
    fn the_crc_only_defect_is_rejected_by_the_header_crc_alone() {
        assert!(
            scan(&crc_only_defect()).entries.is_empty(),
            "a header whose own CRC-32 does not reproduce must be rejected"
        );
        let healthy = stored_entry(b"CRCONLY.TXT", b"payload");
        let out = scan(&healthy);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].meta.name, "CRCONLY.TXT");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    /// The same isolation for criterion 6 — the gate Step 5 falsifies, and
    /// the one this format's evidence rests on hardest, since it is
    /// checkable from the SPECIFICATION with no parser at all.
    #[test]
    fn the_identity_only_defect_is_rejected_by_the_size_identity_alone() {
        assert!(
            scan(&identity_only_defect()).entries.is_empty(),
            "a header whose declared size does not equal first_hdr_size + strlen(name) + 1 + \
             strlen(comment) + 1 must be rejected"
        );
        // The identical archive with the stray byte removed IS found, which
        // is what makes the assertion above about the identity.
        let healthy = stored_entry(b"IDONLY.TXT", b"payload");
        let out = scan(&healthy);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].meta.name, "IDONLY.TXT");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    /// And for criterion 2 — the spec's 2600-byte maximum, which is the gate
    /// that stops a coincidental id from making this module read an arbitrary
    /// span of the file.
    #[test]
    fn the_oversized_header_is_rejected_by_the_2600_byte_ceiling_alone() {
        let oversized = oversized_header();
        assert!(
            scan(&oversized).entries.is_empty(),
            "a basic header past the spec's {MAX_ARJ_HEADER_SIZE}-byte maximum must be rejected"
        );
        // Everything else about that header is correct: shortening the name
        // to the largest the ceiling admits makes the identical construction
        // a recoverable entry.
        let longest = vec![b'X'; MAX_ARJ_HEADER_SIZE - ARJ_FIRST_HDR_SIZE as usize - 2];
        let out = scan(&stored_entry(&longest, b"payload"));
        assert_eq!(
            out.entries.len(),
            1,
            "only the ceiling may separate these two archives"
        );
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    // -------------------------------------------------------------------
    // The positive complement: a scanner that always returned `Ok(None)`
    // would also pass the anti-vacuity pair trivially.
    // -------------------------------------------------------------------

    /// **Weak evidence, stated as such.** `sample.arj` is hand-built from
    /// this project's own reading of the ARJ specification, with no tool
    /// anywhere able to check it — `MANIFEST.md` calls it the weakest
    /// provenance in the phase. This proves the scanner reads what Phase 3b
    /// wrote; it is not a cross-implementation check and must not be cited as
    /// one.
    #[test]
    fn salvage_recovers_both_entries_of_the_hand_built_fixture() {
        let out = scan(SAMPLE_ARJ);
        let names: Vec<&str> = out.entries.iter().map(|e| e.meta.name.as_str()).collect();
        assert_eq!(names, ["sample/hello.txt", "sample/sub/b.bin"]);
        for entry in &out.entries {
            assert_eq!(
                entry.status,
                SalvageStatus::Intact,
                "{} must verify against its own CRC-32",
                entry.meta.name
            );
        }
        assert_eq!(out.entries[0].meta.size, Some(6));
        assert_eq!(out.entries[1].meta.size, Some(5));
    }

    /// The motivating shape for the whole scanner: ARJ has no index, so
    /// `unarj_rs::ArjArchieve` reaches entry 2 only by having parsed entry 1.
    /// Wiping one header's declared size costs the ordinary reader everything
    /// behind it; the scan finds each header on its own.
    #[test]
    fn an_entry_behind_a_destroyed_header_is_still_recovered() {
        let mut bytes = build_archive(&[(b"first.txt", b"AAAA"), (b"second.txt", b"BBBB")]);
        // The first LOCAL header's `u16` basic header size, two bytes past
        // its id.
        let first = main_header().len();
        bytes[first + 2] = 0xFF;
        bytes[first + 3] = 0xFF;

        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1, "{:?}", out.entries);
        assert_eq!(out.entries[0].meta.name, "second.txt");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    /// Criterion 7, and the one narrowing this module makes deliberately: an
    /// archive's own main header is structurally identical to a local file
    /// header, and reporting one would claim a payload of whatever its `date
    /// time modified` field encodes.
    #[test]
    fn the_main_header_is_never_reported_as_an_entry() {
        let out = scan(&build_archive(&[(b"only.txt", b"content")]));
        assert_eq!(out.entries.len(), 1, "{:?}", out.entries);
        assert_eq!(out.entries[0].meta.name, "only.txt");

        // And the main header really does clear every other criterion — it is
        // criterion 7 alone that removes it. Flipping its `file type` to 0
        // turns the identical bytes into a reported candidate.
        let mut bytes = build_archive(&[(b"only.txt", b"content")]);
        let content_at = ENVELOPE_PREFIX as usize;
        let crc_at = main_header().len() - 6;
        bytes[content_at + FILE_TYPE_I] = 0;
        let fixed = crc32_ieee(&bytes[content_at..crc_at]);
        bytes[crc_at..crc_at + 4].copy_from_slice(&fixed.to_le_bytes());
        assert_eq!(
            scan(&bytes).entries.len(),
            2,
            "only `file type == 2` may separate these two archives"
        );
    }

    /// An empty archive — main header, end-of-archive marker, nothing else —
    /// must report NOTHING recoverable rather than a refusal.
    ///
    /// This is why `file type == 2` deliberately gets no Ruling S-V sighting
    /// channel: every healthy ARJ carries exactly one such header, so a
    /// sighting would turn this archive into `Error::Unsupported` at exit 3
    /// for a scan working exactly as designed.
    #[test]
    fn an_empty_archive_reports_nothing_rather_than_refusing() {
        let out = scan(&build_archive(&[]));
        assert!(out.entries.is_empty());
    }

    /// The end-of-archive marker is `60 EA 00 00` — a header id followed by a
    /// zero length. Criterion 2 must read that as the structural element it
    /// is, never as a candidate.
    #[test]
    fn the_end_of_archive_marker_is_not_a_candidate() {
        let bytes = build_archive(&[(b"a.txt", b"A")]);
        assert_eq!(&bytes[bytes.len() - 4..], &[0x60, 0xEA, 0x00, 0x00]);
        assert_eq!(scan(&bytes).entries.len(), 1);
    }

    // -------------------------------------------------------------------
    // The method table.
    // -------------------------------------------------------------------

    /// Sweeps the whole byte space in both directions, so neither a method
    /// `unarj-rs` names nor one it does not can drift out of step with
    /// [`Method`] silently — the front door [`Method::all`]'s own doc says
    /// its `next` chain cannot close.
    #[test]
    fn the_recognised_set_is_exactly_unarjs_own_table() {
        use unarj_rs::local_file_header::CompressionMethod;
        for byte in 0u8..=255 {
            let ours = Method::from_byte(byte);
            let theirs = CompressionMethod::from(byte);
            let they_name_it = !matches!(theirs, CompressionMethod::Unknown(_));
            assert_eq!(
                ours.is_some(),
                they_name_it,
                "method byte {byte}: this module says {ours:?}, unarj-rs says {theirs:?}"
            );
        }
        assert_eq!(Method::all().count(), 7);
    }

    /// Pinned against the only authority that matters for the DECISION — the
    /// ordinary reader beside this scanner, which refuses exactly `NoData`,
    /// `NoDataNoCrc` and any unknown byte with `Error::Unsupported`.
    #[test]
    fn decodability_matches_what_the_ordinary_reader_refuses() {
        use unarj_rs::local_file_header::CompressionMethod;
        for method in Method::all() {
            let theirs = CompressionMethod::from(method.byte());
            let reader_refuses = matches!(
                theirs,
                CompressionMethod::NoData
                    | CompressionMethod::NoDataNoCrc
                    | CompressionMethod::Unknown(_)
            );
            assert_eq!(
                method.decodable(),
                !reader_refuses,
                "{method:?} disagrees with `arj.rs`'s own next_entry refusal"
            );
        }
    }

    /// Every recognised method must map to a distinct codec id, or two
    /// methods would decode as one on the write side.
    #[test]
    fn every_recognised_method_round_trips_through_its_codec_id() {
        let mut seen: Vec<FormatId> = Vec::new();
        for method in Method::all() {
            let codec = method.codec();
            assert!(!seen.contains(&codec), "{codec:?} is used twice");
            seen.push(codec);
            assert_eq!(method_for_codec(Some(codec)), Some(method));
        }
        assert_eq!(method_for_codec(None), None);
        assert_eq!(method_for_codec(Some(FormatId::new("arj-nope"))), None);
    }

    /// A method this build cannot decode is a REPORTED entry, never dropped
    /// and never `Complete` — the archive is fine, the build is not.
    #[test]
    fn an_undecodable_method_is_unverified_not_dropped_and_not_complete() {
        let mut out = wrap(&local_content(
            b"nodata.bin",
            Method::NoData.byte(),
            0,
            4,
            4,
            0,
        ));
        out.extend_from_slice(b"ABCD");
        let scanned = scan(&out);
        assert_eq!(scanned.entries.len(), 1);
        assert_eq!(
            scanned.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::UndecodableMethod)
        );
    }

    /// A method byte the format never assigned is not a header at all —
    /// criterion 8.
    #[test]
    fn an_unassigned_method_byte_is_not_a_candidate() {
        let mut out = wrap(&local_content(b"weird.bin", 200, 0, 4, 4, 0));
        out.extend_from_slice(b"ABCD");
        assert!(scan(&out).entries.is_empty());
    }

    // -------------------------------------------------------------------
    // Entry shapes.
    // -------------------------------------------------------------------

    #[test]
    fn a_directory_entry_is_reported_as_a_directory_and_is_intact() {
        let out = wrap(&local_content(
            b"tree",
            Method::Stored.byte(),
            FILE_TYPE_DIRECTORY,
            0,
            0,
            crc32_ieee(&[]),
        ));
        let scanned = scan(&out);
        assert_eq!(scanned.entries.len(), 1);
        assert_eq!(scanned.entries[0].meta.kind, EntryKind::Dir);
        assert_eq!(scanned.entries[0].status, SalvageStatus::Intact);
    }

    /// `file type` 4 (volume label) and 5 (chapter label) are neither files
    /// nor directories, and `arj.rs` reports them `EntryKind::Other`. Only
    /// `file type == 2` is excluded.
    #[test]
    fn an_unusual_file_type_is_reported_as_other() {
        let mut out = wrap(&local_content(
            b"LABEL",
            Method::Stored.byte(),
            4,
            2,
            2,
            crc32_ieee(b"hi"),
        ));
        out.extend_from_slice(b"hi");
        let scanned = scan(&out);
        assert_eq!(scanned.entries.len(), 1);
        assert_eq!(scanned.entries[0].meta.kind, EntryKind::Other);
    }

    /// Names are `unarj-rs`'s own Latin-1 decode, byte for byte, because
    /// matching in this project is EXACT and `stuffr list` shows that
    /// spelling.
    #[test]
    fn a_high_byte_name_is_decoded_exactly_as_the_ordinary_reader_decodes_it() {
        let raw: &[u8] = b"caf\xe9.txt";
        let mut out = wrap(&local_content(
            raw,
            Method::Stored.byte(),
            0,
            1,
            1,
            crc32_ieee(b"x"),
        ));
        out.extend_from_slice(b"x");
        let scanned = scan(&out);
        assert_eq!(scanned.entries.len(), 1);
        // `unarj_rs`'s `convert_string!` is `push(byte as char)`: byte 0xE9
        // becomes U+00E9, not a UTF-8 replacement character and not two
        // bytes read as one code point.
        assert_eq!(scanned.entries[0].meta.name, "caf\u{e9}.txt");
    }

    /// A nameless entry is what a run of zeroed bytes behind a coincidental
    /// id looks like — criterion 6's second half.
    #[test]
    fn a_zero_length_name_is_rejected() {
        let mut out = wrap(&local_content(b"", Method::Stored.byte(), 0, 1, 1, 0));
        out.extend_from_slice(b"x");
        assert!(scan(&out).entries.is_empty());
    }

    /// A `first_hdr_size` below the spec's own standard header cannot
    /// describe the fixed fields behind it — criterion 5.
    #[test]
    fn a_short_first_hdr_size_is_rejected() {
        let mut content = local_content(b"short.txt", Method::Stored.byte(), 0, 1, 1, 0);
        content[FIRST_HDR_SIZE_I] = ARJ_FIRST_HDR_SIZE - 1;
        let mut out = wrap(&content);
        out.extend_from_slice(b"x");
        assert!(scan(&out).entries.is_empty());
    }

    /// The id can straddle a [`SCAN_CHUNK`] boundary, and a scanner that
    /// dropped the carry byte would silently miss every header at such a
    /// position.
    #[test]
    fn an_id_straddling_a_chunk_boundary_is_found() {
        let entry = stored_entry(b"edge.txt", b"payload");
        let mut bytes = vec![0u8; SCAN_CHUNK - 1];
        bytes.extend_from_slice(&entry);
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].offset, SCAN_CHUNK as u64 - 1);
    }

    // -------------------------------------------------------------------
    // Truncation, corruption and the ceilings.
    // -------------------------------------------------------------------

    /// A declared payload running past the end of the file is REPORTED, never
    /// dropped — `zip_salvage.rs`'s criterion-6 ruling, which is what turns
    /// the single most common damaged archive there is from silence into a
    /// statement.
    #[test]
    fn a_declared_length_running_past_the_file_is_reported_not_dropped() {
        let mut bytes = build_archive(&[(b"cut.txt", b"0123456789")]);
        bytes.truncate(bytes.len() - 4 - 5); // drop the marker and half the payload
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].meta.name, "cut.txt");
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "a truncated payload is Partial, never Intact and never Complete"
        );
        assert_eq!(
            out.entries[0].meta.size,
            Some(10),
            "the declared figure is reported exactly as the header stated it"
        );
    }

    #[test]
    fn a_corrupted_payload_salvages_as_partial() {
        let mut bytes = build_archive(&[(b"flip.txt", b"payload!")]);
        let at = bytes.len() - 4 - 1;
        bytes[at] ^= 0xFF;
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "every declared byte decoded, and disagreed with the CRC-32"
        );
    }

    /// A lying declared length must not swallow the entries behind it —
    /// `collect_candidates`'s own advance rule, exercised through this
    /// scanner.
    #[test]
    fn a_lying_declared_length_does_not_swallow_the_real_entries_after_it() {
        let mut bytes = build_archive(&[
            (b"liar.txt", b"AAAA"),
            (b"real-one.txt", b"BBBB"),
            (b"real-two.txt", b"CCCC"),
        ]);
        // Raise the FIRST entry's compressed size to a figure far past the
        // file, and refresh its header CRC so the gate still clears.
        let at = main_header().len() + ENVELOPE_PREFIX as usize;
        bytes[at + COMPRESSED_SIZE_I..at + COMPRESSED_SIZE_I + 4]
            .copy_from_slice(&0x4000_0000u32.to_le_bytes());
        let content_len = ARJ_FIRST_HDR_SIZE as usize + "liar.txt".len() + 2;
        let fixed = crc32_ieee(&bytes[at..at + content_len]);
        bytes[at + content_len..at + content_len + 4].copy_from_slice(&fixed.to_le_bytes());

        let out = scan(&bytes);
        let names: Vec<&str> = out.entries.iter().map(|e| e.meta.name.as_str()).collect();
        assert!(
            names.contains(&"real-one.txt") && names.contains(&"real-two.txt"),
            "a phantom length must not cost the entries behind it: {names:?}"
        );
    }

    /// **The whole-entry ceiling is this scanner's own, and it is the same
    /// figure the ORDINARY reader enforces.**
    #[test]
    fn the_scanner_declares_the_containers_own_whole_entry_ceiling() {
        assert_eq!(ArjSalvage::new().max_whole_entry(), MAX_ARJ_ENTRY_LEN);
        const {
            assert!(
                MAX_ARJ_ENTRY_LEN < MAX_SALVAGE_ENTRY,
                "the scanner's ceiling must narrow the policy's, not widen it"
            )
        };
    }

    /// The three streaming arms really do stream: a `Stored` entry declaring
    /// a length just under the scanner's own ceiling must never become a
    /// buffer of that size.
    ///
    /// Proven with the recording allocator rather than with the resulting
    /// STATUS, which is identical either way — `alloc_probe`'s own doc
    /// records the 2.86 GiB allocation that passed a status-only test.
    #[test]
    fn a_stored_entry_just_under_the_ceiling_never_becomes_an_allocation() {
        let declared = (MAX_ARJ_ENTRY_LEN - 1) as u32;
        // The COMPRESSED payload is entirely present — which is what makes
        // this a test of the streaming decode rather than of the truncation
        // shortcut, since `verify_candidate` answers `Partial` at its first
        // line for anything `available_len` marks short. The DECODED length
        // is the lie, and it is the figure a whole-decoding scanner would
        // allocate.
        let payload = b"only thirty-two bytes are here!!";
        let mut bytes = wrap(&local_content(
            b"huge.bin",
            Method::Stored.byte(),
            0,
            payload.len() as u32,
            declared,
            0,
        ));
        bytes.extend_from_slice(payload);

        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| scan(&bytes));
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes — a {declared}-byte header field \
             became a buffer, which is what the Stored arm's streaming decode says cannot \
             happen"
        );
        // **The LOWER bound, and it is not decoration.** An assertion that is
        // only an upper bound cannot notice the PROBE's own absence — detach
        // `alloc_probe`'s `#[global_allocator]` and
        // `largest_single_allocation` reports `0`, which satisfies
        // `<= 1 << 20` perfectly while measuring nothing. `find_next_id`
        // allocates a `SCAN_CHUNK`-sized read buffer on every scan, so that
        // figure is a floor the probe cannot report unless it is attached.
        assert!(
            largest >= SCAN_CHUNK,
            "largest single allocation was only {largest} bytes, below the {SCAN_CHUNK}-byte \
             buffer every scan allocates — the recording allocator is not attached, so the \
             ceiling above is measuring nothing"
        );
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "thirty-two bytes are not {declared}, and that is a verdict reached by STREAMING"
        );
    }

    /// An entry over the run's ceiling is answered
    /// `Unverified(OverEntryCeiling)` — a per-entry STATUS, never an `Err`
    /// that would discard every entry already recovered — and `verify` is not
    /// called for it at all, so nothing is read and nothing is allocated.
    ///
    /// Driven through `--max-entry` rather than through
    /// [`MAX_ARJ_ENTRY_LEN`], and that is a deliberate limitation rather than
    /// a shortcut: the engine compares the BOUNDED length
    /// (`available_len.or(declared_len)`), so an entry whose declared payload
    /// is not really present can never exceed the ceiling however large its
    /// declaration — reaching the 256 MiB figure with a present payload would
    /// mean a 256 MiB fixture in a gate that already runs twice.
    /// [`the_scanner_declares_the_containers_own_whole_entry_ceiling`] owns
    /// the figure; this owns the behaviour.
    #[test]
    fn an_entry_over_the_ceiling_is_a_status_and_costs_no_other_entry() {
        let bytes = build_archive(&[
            (b"over.bin", b"twenty bytes exactly"),
            (b"after.txt", b"tiny"),
        ]);
        let policy = SalvagePolicy {
            max_entry: 4,
            ..SalvagePolicy::default()
        };
        let out = salvage_arj(&mut Cursor::new(bytes), &policy).expect("scan");

        let i = entry_for(&out, "over.bin");
        assert_eq!(
            out.entries[i].status,
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: 20,
                ceiling: 4,
            })
        );
        let j = entry_for(&out, "after.txt");
        assert_eq!(
            out.entries[j].status,
            SalvageStatus::Intact,
            "one oversized entry must never cost the entries around it"
        );
    }

    /// The SECOND declared length — `original size`, which the engine never
    /// sees — bounded on the one arm that allocates from it, and NOT on the
    /// arms that do not.
    #[test]
    fn the_original_size_ceiling_binds_method_four_alone() {
        let build = |method: u8| {
            let mut out = wrap(&local_content(
                b"big-org.bin",
                method,
                0,
                4,
                u32::MAX,
                crc32_ieee(b"ABCD"),
            ));
            out.extend_from_slice(b"ABCD");
            out
        };

        // Method 4 allocates `Vec::with_capacity(original_size)`, so the
        // figure is refused before `decode_fastest` is ever called.
        let out = scan(&build(Method::CompressedFastest.byte()));
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: u64::from(u32::MAX),
                ceiling: MAX_ARJ_ENTRY_LEN,
            })
        );

        // `Stored` never reads the field for an allocation, so the identical
        // declaration must NOT be refused for it — ZOO's fix round 1 (HIGH)
        // measured what the unconditional version costs.
        let out = scan(&build(Method::Stored.byte()));
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "a Stored entry must be answered by STREAMING, not refused for a field its own \
             method ignores"
        );
    }

    /// Method 4's whole-slice decode must never allocate `original_size`
    /// before the check above refuses it.
    ///
    /// The upper bound alone cannot notice the probe's absence, so the
    /// `SCAN_CHUNK` floor rides beside it — `alloc_probe`'s own rule.
    #[test]
    fn a_four_gigabyte_original_size_never_becomes_an_allocation() {
        let mut bytes = wrap(&local_content(
            b"bomb.bin",
            Method::CompressedFastest.byte(),
            0,
            4,
            u32::MAX,
            crc32_ieee(b"ABCD"),
        ));
        bytes.extend_from_slice(b"ABCD");

        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| scan(&bytes));
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes — a 4 GiB `original size` reached \
             `decode_fastest`'s own `Vec::with_capacity`"
        );
        assert!(
            largest >= SCAN_CHUNK,
            "largest single allocation was only {largest} bytes, below the {SCAN_CHUNK}-byte \
             buffer every scan allocates — the recording allocator is not attached"
        );
        assert!(matches!(
            out.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling { .. })
        ));
    }

    /// The extended-header walk reads two bytes per hop and SEEKS past the
    /// rest, so a chain of maximal headers costs nothing but the seek —
    /// proven with the allocator, not with the resulting status.
    #[test]
    fn a_chain_of_maximal_extended_headers_never_becomes_an_allocation() {
        const EXT_LEN: usize = u16::MAX as usize;
        let payload = b"payload";
        let content = local_content(
            b"chained.txt",
            Method::Stored.byte(),
            0,
            payload.len() as u32,
            payload.len() as u32,
            crc32_ieee(payload),
        );
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&HEADER_ID);
        bytes.extend_from_slice(&(content.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&content);
        bytes.extend_from_slice(&crc32_ieee(&content).to_le_bytes());
        // One maximal extended header, genuinely present, then the zero that
        // ends the chain.
        bytes.extend_from_slice(&(EXT_LEN as u16).to_le_bytes());
        bytes.extend_from_slice(&vec![0x5Au8; EXT_LEN]);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // the chain header's own CRC
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let payload_at = bytes.len() as u64;
        bytes.extend_from_slice(payload);

        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| scan(&bytes));
        assert_eq!(out.entries.len(), 1, "{:?}", out.entries);
        assert_eq!(
            out.entries[0].payload_start, payload_at,
            "the payload sits behind the whole chain, and `payload_start` must say so"
        );
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes — the {EXT_LEN}-byte extended \
             header became a buffer, which the walk's seek-past says cannot happen"
        );
        assert!(
            largest >= SCAN_CHUNK,
            "largest single allocation was only {largest} bytes — the recording allocator is \
             not attached"
        );
    }

    /// A chain that never terminates inside the file makes the payload's
    /// position unknowable, which to a scanner is the same answer as "not a
    /// header".
    #[test]
    fn a_chain_running_past_the_end_of_the_file_is_rejected() {
        let content = local_content(b"nochain.txt", Method::Stored.byte(), 0, 1, 1, 0);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&HEADER_ID);
        bytes.extend_from_slice(&(content.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&content);
        bytes.extend_from_slice(&crc32_ieee(&content).to_le_bytes());
        bytes.extend_from_slice(&u16::MAX.to_le_bytes()); // declares 65,535 bytes that are absent
        bytes.extend_from_slice(b"x");
        assert!(scan(&bytes).entries.is_empty());
    }

    // -------------------------------------------------------------------
    // The compressed arms.
    //
    // ARJ's methods 1-4 have no encoder anywhere in reach — `arj.rs`'s own
    // writer emits method 0 and nothing else, and no `arj` binary is
    // obtainable on any platform this project can use. The `-lh6-` test
    // below is the ONE positive check available, and it is cross-
    // implementation in a narrow sense: `oxiarc-lzhuf` encodes the stream and
    // `delharc` decodes it, two crates sharing no code — but ARJ's own
    // framing around it is still this project's reading of the spec.
    // Method 4's decoder (`unarj_rs::decode_fastest`) has no encoder
    // ANYWHERE, so only its refusals and its failures are exercised.
    // -------------------------------------------------------------------

    /// A genuine method-1 entry: `oxiarc-lzhuf` writes the `-lh6-` stream,
    /// and the scanner decodes it through the same `delharc` decoder
    /// `unarj_rs::ArjArchieve::read` hands methods 1-3 to.
    ///
    /// Gated on `lha` because that is the feature carrying the encoder; both
    /// legs of `make check` build it (it is in `default` via `legacy`, and in
    /// `--all-features`).
    #[cfg(feature = "lha")]
    #[test]
    fn a_compressed_entry_decodes_through_the_same_delharc_decoder_the_reader_uses() {
        let plain: Vec<u8> = b"ARJ methods 1-3 are -lh6- streams. "
            .iter()
            .cycle()
            .take(4096)
            .copied()
            .collect();
        let packed = oxiarc_lzhuf::encode_lzh(&plain, oxiarc_lzhuf::LzhMethod::Lh6)
            .expect("oxiarc-lzhuf must encode an -lh6- stream");
        let mut bytes = wrap(&local_content(
            b"packed.txt",
            Method::CompressedMost.byte(),
            0,
            packed.len() as u32,
            plain.len() as u32,
            crc32_ieee(&plain),
        ));
        bytes.extend_from_slice(&packed);

        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1, "{:?}", out.entries);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Intact,
            "the decoded bytes must agree with the CRC-32 the header records"
        );

        // And the write side recovers the identical bytes.
        let path = temp_archive(&bytes, "lh6");
        let mut got = Vec::new();
        let completed = write_payload(
            &path,
            &out.entries[0],
            out.entries[0].meta.compressed_size.unwrap(),
            &mut got,
        )
        .expect("write_payload");
        let _ = std::fs::remove_file(&path);
        assert!(completed);
        assert_eq!(got, plain);
    }

    /// A truncated `-lh6-` entry must give up its genuine surviving prefix
    /// rather than nothing — the whole reason [`recover_the_last_chunk`]
    /// exists, and the one place it is reachable in this module.
    #[cfg(feature = "lha")]
    #[test]
    fn a_truncated_compressed_entry_still_recovers_a_prefix() {
        let plain: Vec<u8> = b"prefix recovery matters most on a truncated archive. "
            .iter()
            .cycle()
            .take(8192)
            .copied()
            .collect();
        let packed = oxiarc_lzhuf::encode_lzh(&plain, oxiarc_lzhuf::LzhMethod::Lh6)
            .expect("oxiarc-lzhuf must encode an -lh6- stream");
        let mut bytes = wrap(&local_content(
            b"cut.txt",
            Method::CompressedMost.byte(),
            0,
            packed.len() as u32,
            plain.len() as u32,
            crc32_ieee(&plain),
        ));
        bytes.extend_from_slice(&packed[..packed.len() / 2]);

        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);

        let path = temp_archive(&bytes, "lh6cut");
        let mut got = Vec::new();
        let completed = write_payload(
            &path,
            &out.entries[0],
            out.entries[0].meta.compressed_size.unwrap(),
            &mut got,
        )
        .expect("write_payload");
        let _ = std::fs::remove_file(&path);
        assert!(!completed, "a truncated entry never reports completion");
        assert!(
            !got.is_empty() && plain.starts_with(&got),
            "recovered {} bytes, and they must be a genuine PREFIX of the original {} — \
             nothing is ever padded or invented",
            got.len(),
            plain.len()
        );
    }

    /// Garbage under a compressed method is `Partial`, never an `Err` that
    /// would end the run, and never `Intact`.
    ///
    /// **The method-4 half of this test found a PANIC in `unarj-rs` on its
    /// first run** — `decode_fastest`'s `res.len() - 1` underflows on a
    /// stream whose first token is a back-reference. See
    /// [`starts_with_a_backreference`], and this task's report for why the
    /// ordinary reader's exposure to the same two bits is recorded rather
    /// than closed here.
    #[test]
    fn garbage_under_a_compressed_method_is_partial() {
        for method in [Method::CompressedMost, Method::CompressedFastest] {
            let mut bytes = wrap(&local_content(
                b"junk.bin",
                method.byte(),
                0,
                8,
                64,
                0xDEAD_BEEF,
            ));
            bytes.extend_from_slice(b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8");
            let out = scan(&bytes);
            assert_eq!(out.entries.len(), 1, "{method:?}");
            assert_eq!(out.entries[0].status, SalvageStatus::Partial, "{method:?}");
        }
    }

    /// The guard's own double: the predicate is ONE BIT, and both sides of it
    /// are pinned so a guard widened to "refuse every method-4 stream" — or
    /// narrowed to nothing — would fail here rather than pass quietly.
    ///
    /// The `0x80` case is the panicking one and must never reach
    /// `decode_fastest`; the `0x00` case opens with a LITERAL and must reach
    /// it, failing on its own terms (the stream runs out) rather than on the
    /// guard's.
    #[test]
    fn the_method_four_backreference_guard_is_exactly_one_bit() {
        assert!(starts_with_a_backreference(&[0x80], 1));
        assert!(starts_with_a_backreference(&[0xFF], 64));
        assert!(!starts_with_a_backreference(&[0x7F], 64));
        assert!(!starts_with_a_backreference(&[0x00], 64));
        // Nothing to decode, so the subtraction is never reached.
        assert!(!starts_with_a_backreference(&[0xFF], 0));
        assert!(!starts_with_a_backreference(&[], 64));

        // End to end, through the scanner: a first bit of 0 reaches the real
        // decoder and is answered `Partial` by IT, not by the guard.
        let mut bytes = wrap(&local_content(
            b"literal.bin",
            Method::CompressedFastest.byte(),
            0,
            2,
            64,
            0xDEAD_BEEF,
        ));
        bytes.extend_from_slice(&[0x00, 0x00]);
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
    }

    // -------------------------------------------------------------------
    // The write side.
    // -------------------------------------------------------------------

    #[test]
    fn write_payload_recovers_a_stored_entry() {
        let bytes = build_archive(&[(b"a.txt", b"AAAA"), (b"b.txt", b"BBBBBB")]);
        let out = scan(&bytes);
        let path = temp_archive(&bytes, "stored");
        for (entry, expected) in out.entries.iter().zip([&b"AAAA"[..], &b"BBBBBB"[..]]) {
            let mut got = Vec::new();
            let completed =
                write_payload(&path, entry, entry.meta.compressed_size.unwrap(), &mut got)
                    .expect("write_payload");
            assert!(completed);
            assert_eq!(got, expected);
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The genuine surviving prefix of a truncated `Stored` entry is written,
    /// and nothing is padded.
    #[test]
    fn write_payload_recovers_the_prefix_of_a_truncated_entry() {
        let mut bytes = build_archive(&[(b"cut.txt", b"0123456789")]);
        bytes.truncate(bytes.len() - 4 - 4);
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        let path = temp_archive(&bytes, "cut");
        let mut got = Vec::new();
        let completed = write_payload(
            &path,
            &out.entries[0],
            out.entries[0].meta.compressed_size.unwrap(),
            &mut got,
        )
        .expect("write_payload");
        let _ = std::fs::remove_file(&path);
        assert!(!completed);
        assert_eq!(got, b"012345", "a genuine prefix, never padded to 10 bytes");
    }

    /// The backstop `entries.rs`'s own seam test relies on: refused by name,
    /// and without ever opening the archive.
    #[test]
    fn write_payload_refuses_a_codec_less_entry_without_opening_the_archive() {
        let entry = SalvagedEntry {
            scan_position: 0,
            offset: 0,
            payload_start: 0,
            meta: EntryMeta::file("probe"),
            status: SalvageStatus::Complete,
            shadows: None,
            collides_with: None,
            marked_deleted: false,
        };
        let err = write_payload(
            Path::new("/nonexistent-arj-salvage-probe"),
            &entry,
            0,
            &mut io::sink(),
        )
        .expect_err("a codec-less entry must be refused");
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        assert!(err.to_string().contains("ARJ salvage writer"));
    }

    #[test]
    fn write_payload_refuses_an_undecodable_method_by_name() {
        let mut entry = SalvagedEntry {
            scan_position: 0,
            offset: 0,
            payload_start: 0,
            meta: EntryMeta::file("nodata.bin"),
            status: SalvageStatus::Complete,
            shadows: None,
            collides_with: None,
            marked_deleted: false,
        };
        entry.meta.codec = Some(Method::NoData.codec());
        let err = write_payload(
            Path::new("/nonexistent-arj-salvage-probe"),
            &entry,
            0,
            &mut io::sink(),
        )
        .expect_err("an undecodable method must be refused");
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        assert!(err.to_string().contains("cannot decode"));
    }

    /// Two records under one name are both reported — the engine's
    /// `collides_with` annotation, reached through this scanner.
    #[test]
    fn two_records_under_one_name_both_survive_the_scan() {
        let bytes = build_archive(&[
            (b"dup.txt", b"the first record"),
            (b"other.txt", b"between them"),
            (b"dup.txt", b"a SECOND record!"),
        ]);
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 3, "{:?}", out.entries);
        assert_eq!(out.entries[2].collides_with, Some(0));
        assert_eq!(out.entries[2].shadows, None);
        for entry in &out.entries {
            assert_eq!(entry.status, SalvageStatus::Intact);
        }
    }

    /// Byte-identical duplicates are MEASURED copies, which is the stronger
    /// annotation.
    #[test]
    fn a_byte_identical_duplicate_shadows() {
        let bytes = build_archive(&[(b"dup.txt", b"identical"), (b"dup.txt", b"identical")]);
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 2);
        assert_eq!(out.entries[1].shadows, Some(0));
        assert_eq!(out.entries[1].collides_with, None);
    }

    /// The production writer's own output must scan cleanly. **This proves
    /// only that this module agrees with `arj.rs`'s encoder — both are this
    /// project's** — and is included for the regression value, not as
    /// evidence about the format.
    #[test]
    fn the_production_writers_output_scans_cleanly() {
        use stuffr_core::{Container, CreateOpts, PlainSink};

        let buf = stuffr_core::testing::SharedBuf::new();
        let mut w = super::super::arj::Arj
            .create(
                PlainSink::new(Box::new(buf.clone())),
                &CreateOpts::default(),
            )
            .expect("create");
        for (name, content) in [
            ("one.txt", &b"first payload"[..]),
            ("two.bin", &b"second"[..]),
        ] {
            let mut meta = EntryMeta::file(name);
            meta.size = Some(content.len() as u64);
            w.add(&meta, &mut Cursor::new(content.to_vec()))
                .expect("add");
        }
        w.finish().expect("finish").finish().expect("sink finish");
        let bytes = buf.contents();

        let out = scan(&bytes);
        let names: Vec<&str> = out.entries.iter().map(|e| e.meta.name.as_str()).collect();
        assert_eq!(names, ["one.txt", "two.bin"]);
        for entry in &out.entries {
            assert_eq!(entry.status, SalvageStatus::Intact);
        }
    }
}
