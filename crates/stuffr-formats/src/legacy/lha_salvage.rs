//! LHA/LZH salvage scan: recovers entries by looking directly for the
//! five-byte ASCII compression-method identifier every entry header carries
//! at its own offset 2, rather than walking the chain of `skip size` hops
//! `lha.rs`'s reader follows from the front of the file.
//!
//! `lha.rs` is a correct, honest reader for an INTACT archive, and the way
//! it reaches entry N is by having successfully parsed entries 1..N — LHA
//! has no index, no entry count and no trailer, so one damaged header is the
//! end of the archive as far as any ordinary reader is concerned. That is
//! the damage this module is for. It is the fourth legacy scanner after
//! `arc_salvage.rs` (Task 3) and `zoo_salvage.rs` (Task 4), built on the
//! same shared [`stuffr_core::salvage`] machinery.
//!
//! # Where this module's byte offsets come from
//!
//! **Nothing here is asserted without a source.** LHA is the one format in
//! this crate with no in-tree record parser to reuse — `lha.rs` delegates
//! every read to `delharc` — so the layout below is stated with its
//! provenance rather than left for a reader to trust, the way `arj.rs`
//! cites the ARJ specification. Three independent sources agree on it, and
//! two of them are checkable from inside this repository:
//!
//! 1. **The LHA header specification** — `header.txt`, distributed with the
//!    `lha` utility itself and mirrored widely as Tomohiro Kubota's English
//!    *LHA/LZH file-format description*. This is the document that names the
//!    fields; it is the only one of the three that is not in this repo.
//! 2. **`delharc 0.6.2`'s `src/header/parser.rs`, `LhaHeader::read`** (line
//!    182 onward) — the parser `lha.rs` already reads every LHA archive in
//!    this project through. Every offset in the table below was read off
//!    that function's own sequence of reads: `header_len` (line 189),
//!    `csum` (193), the packed `LhaRawBaseHeader` (line 70: method, two
//!    sizes, timestamp, attrs, level), the filename length and filename
//!    (206-216, levels 0 and 1 only), the file CRC-16 (218), OS-TYPE (221,
//!    level 1 and above), the extended area (227-245) and the first
//!    extra-header length (254).
//! 3. **This project's own `lha.rs::write_level1_header`** — a level-1
//!    header writer whose output `lhasa 0.6.0`, an implementation sharing no
//!    code with `delharc`, reads byte-for-byte
//!    (`lha.rs`'s `lhasa_reads_what_we_write`). [`LEVEL1_HEADER_OVERHEAD`]
//!    is imported from it rather than re-spelled here.
//!
//! The layout, for a **level 0 or 1** header beginning at byte `H` (level
//! 2's is a separate, fixed 26 bytes — see [`LEVEL2_BASE_LEN`] and its
//! neighbours, cited the same way):
//!
//! | offset | size | field | source |
//! |---|---|---|---|
//! | `H+0` | 1 | header length, counted from `H+2` | spec; `parser.rs:189` |
//! | `H+1` | 1 | header checksum: `sum(H+2 .. H+2+len) mod 256` | spec; `parser.rs:270-273`; `write_level1_header` |
//! | `H+2` | 5 | compression method, ASCII (`-lh5-`) | spec; `parser.rs:70` |
//! | `H+7` | 4 | compressed size (level 1: **skip size**), LE | spec; `parser.rs:70` |
//! | `H+11` | 4 | original size, LE | spec; `parser.rs:70` |
//! | `H+15` | 4 | MS-DOS timestamp, LE | spec; `parser.rs:70` |
//! | `H+19` | 1 | MS-DOS attribute byte | spec; `parser.rs:70` |
//! | `H+20` | 1 | header level (0 or 1 here) | spec; `parser.rs:70` |
//! | `H+21` | 1 | filename length `F` | spec; `parser.rs:208` |
//! | `H+22` | `F` | filename | spec; `parser.rs:212` |
//! | `H+22+F` | 2 | CRC-16/ARC of the UNCOMPRESSED file, LE | spec; `parser.rs:219` |
//! | `H+24+F` | 1 | OS-TYPE (level 1 only) | spec; `parser.rs:223` |
//! | `H+25+F`† | 2 | first extra-header length, LE (level 1 only) | spec; `parser.rs:254` |
//!
//! † **the one row this module deliberately does NOT read at its stated
//! offset**, and Ruling F is about the table rather than the code, so it is
//! said here too. `delharc` accepts an optional *extended area* of
//! `header_len - min_len` bytes between the OS-TYPE byte and this field
//! (`parser.rs:227-245`), so `H+25+F` is where it sits only when that area is
//! empty — which is every archive this project writes and every one it has a
//! fixture for, and not a guarantee. [`parse_level_0_or_1`] reads it as the
//! LAST two bytes of the base header (`base_len - 2`) instead, which is
//! correct either way.
//!
//! and the one derived fact everything downstream stands on:
//!
//! > **the whole base header occupies `2 + header_len` bytes**, for level 0
//! > and level 1 alike.
//!
//! That is the spec's own reading (the length field counts from `H+2`), and
//! it is confirmed twice in-tree: `write_level1_header` emits exactly
//! `LEVEL1_HEADER_OVERHEAD + name.len()` counted bytes behind a length byte
//! holding that same figure, and
//! [`tests::the_header_geometry_agrees_with_delharcs_own_parser`] re-derives
//! it at runtime from `delharc`'s own stream position after
//! `LhaHeader::read` returns, over every fixture and every shape these
//! tests build.
//!
//! # Levels 0, 1 and 2 are scanned; level 3 is not (Ruling S-U)
//!
//! **This module shipped scanning levels 0 and 1 alone, on a premise that
//! was false, and the correction is worth keeping rather than quietly
//! folding in.** The original reasoning was that "levels 2 and 3 carry no
//! header checksum", so admitting them would weaken the gate. That is true
//! of a level-2 BASE header and false of a level-2 header: the base header's
//! 8-bit sum is replaced by an `EXT_HEADER_COMMON` (`0x00`) extension header
//! carrying a **CRC-16 over the whole header**, which `delharc` already
//! parses and validates (`parser.rs:306-317`, `356-360`). Sixteen bits
//! against levels 0 and 1's eight. Scanning level 2 makes this scanner's
//! weakest gate STRONGER.
//!
//! What settled it is what a user saw. On a HEALTHY, undamaged level-2
//! archive the `0.5.0` binary answered:
//!
//! ```text
//! $ stuffr list level2.lzh            # exit 0:  0  30  level2.txt
//! $ stuffr salvage level2.lzh --list
//! salvage -> the scan found nothing recoverable in this archive
//! exit=5
//! ```
//!
//! One tool contradicting itself across two lines on a file with nothing
//! wrong with it — and pointed the wrong way besides, since exit 5 is a
//! claim about the ARCHIVE where the truth was a claim about the BUILD (this
//! project spends exit 3 on that, and `entries.rs`'s `salvage_scan` says so
//! in those words for a format it has no scanner for at all).
//!
//! **Level 2's gate is MANDATORY where `delharc`'s is advisory**, and that
//! is the one deliberate narrowing: `LhaHeader::read` accepts a level-2
//! header with no common extension header (there is simply nothing to
//! compare), and [`parse_level_2`] refuses one, because a scanner with no
//! checksum has nothing to tell a real header from five coincidental bytes.
//! `a_level_2_header_with_no_common_extension_header_is_not_scanned` pins
//! both halves, `delharc`'s acceptance included, so the narrowing is visible
//! rather than implied.
//!
//! **Level 3 is still not scanned**, and for the reason level 2's premise
//! turned out not to be: it is materially a different parser rather than a
//! wider `if`. Its header length lives in a `u32` at `H+24`, its extension
//! chain uses 4-byte length counters instead of 2, and its first two bytes
//! must read `4, 0` (`parser.rs:259-264`, `333-338`). It does carry the same
//! common-header CRC-16, so the gate exists for it too — the work is the
//! second layout, not the gate.
//!
//! # What a scan SAYS about a shape it cannot gate (Ruling S-V)
//!
//! **Ruling S-U closed a population and left its own class open**, and this
//! is the correction. Two shapes still met the reader and not the scanner —
//! a level-2 header with no common extension header, and a level-3 header —
//! and on a HEALTHY archive of either, `stuffr list` printed the entry at
//! exit 0 while `stuffr salvage --list` answered `the scan found nothing
//! recoverable in this archive` at **exit 5**. Same defect, narrower
//! population: a claim about the ARCHIVE where the truth is a claim about
//! the BUILD. `examples.txt` documenting it was not enough — nothing at
//! runtime told a user which of the two situations they were in.
//!
//! [`UngateableSightings`] records such a sighting and [`salvage_lha`] turns
//! a run that recovered NOTHING while seeing one into
//! [`Error::Unsupported`] — **exit 3**, the code `entries.rs`'s own
//! `salvage_scan` already spends on precisely this distinction — naming the
//! level, naming what is missing, and saying that the ordinary verbs still
//! read the archive.
//!
//! Two things about that which are not obvious:
//!
//! - **A sighting needs structure, never plausibility.** A false one would
//!   replace an honest "nothing recoverable" with a confident, wrong claim
//!   about header levels, so level 3 needs `delharc`'s own mandated `4, 0`
//!   prefix behind the five-byte identifier (about one chance in 2^56 in
//!   random bytes) and level 2 needs a full parse that succeeded at
//!   everything except the checksum. `noise_never_produces_an_ungateable_sighting`
//!   is the standing double.
//! - **Only when the run recovered nothing.** An `Err` discards every entry
//!   already recovered, which is the one thing this verb exists not to do.
//!   A MIXED archive therefore still reports what it got, at its ordinary
//!   exit code — an incompleteness rather than a contradiction, since
//!   nothing false is claimed. Closing that too would need a note channel
//!   [`SalvageOutcome`] does not have, and no LHA writer mixes header levels
//!   within one archive.
//!
//! # The validation gate
//!
//! A candidate is reported only once ALL of the following hold, checked in
//! an order that never allocates or trusts anything before it is cheap to
//! check:
//!
//! 1. The five-byte method identifier at `H+2` is one the format assigned
//!    ([`Method::from_identifier`]). Recognised, not necessarily DECODABLE —
//!    see [`Method::decodable`].
//! 2. The header level at `H+20` is 0, 1 or 2 (see above).
//! 3. The declared header length reaches at least as far as the fields the
//!    level in question requires, and the whole header is present in the
//!    source — `2 + header_len` bytes for levels 0 and 1, the `u16` total at
//!    `H+0` for level 2.
//! 4. **A checksum over the header reproduces.** For levels 0 and 1 that is
//!    the 8-bit sum: `sum(H+2 .. H+2+header_len) mod 256` equals the byte at
//!    `H+1` ([`checksum_of`]). For level 2 it is the `EXT_HEADER_COMMON`
//!    extension header's **CRC-16 over the whole header** with its own two
//!    checksum bytes zeroed ([`walk_extra_headers`], [`parse_level_2`]) —
//!    sixteen bits rather than eight, and mandatory.
//! 5. There is a name. Levels 0 and 1 require a non-zero filename length in
//!    the base header; level 2 requires the chain to have yielded a `0x01`
//!    or `0x02` extension header. A nameless entry is not a shape any LHA
//!    writer produces, and it is what a run of zeroed bytes behind a
//!    coincidental method string looks like.
//! 6. For levels 1 and 2, the extra-header chain walks to its terminator
//!    inside the source, inside [`MAX_EXTRA_CHAIN`], and inside the budget
//!    the header itself declared — the skip size for level 1 (which is what
//!    makes the compressed payload length, `skip size` minus the chain,
//!    computable at all) and the total header size for level 2.
//!
//! Any failure at 2-6 is not an error — it means these five bytes were a
//! coincidence, not a header, and the scan resumes one byte past the method
//! identifier itself, never past a whole assumed header.
//!
//! **A level-2 chain can also RESTATE both sizes (Ruling S-W).** An
//! `EXT_HEADER_MSDOS_SIZE` (`0x42`) header carries a 64-bit compressed and
//! decoded length that override the base header's `u32`s at level >= 2 —
//! that is how the format expresses an entry past 4 GiB — and `delharc`
//! honours it (`parser.rs:325-330`). This scanner ignored it until fix round
//! 2, so `stuffr list` and `stuffr salvage` reported two different sizes for
//! one healthy entry (measured: 5,000 against 100), which the CRC gate kept
//! from ever becoming a false `Intact` but which is the self-contradiction
//! this project refuses on principle. [`ExtraChain::msdos_size`] carries it
//! now, and the delharc cross-check has a fixture for it.
//!
//! **Reported, never rejected:** a declared payload length whose bytes do
//! not all fit inside the source. That is `zip_salvage.rs`'s "criterion 6
//! reports, it does not reject" ruling, and the reason is the same: a
//! truncated archive's last entry must be a STATEMENT
//! ([`Candidate::available_len`], `Partial`), never silence.
//!
//! # The header checksum is doing most of the work, and it is falsifiable
//!
//! Criterion 1 alone is already a far stronger anchor than either sibling
//! scanner has: eleven accepted five-byte spellings occur in uniform random
//! bytes about once per **93 GiB**, against ZOO's four-byte tag at once per
//! 4 GiB and ARC's marker+method pair at roughly once per 8 KiB. Criterion 4
//! multiplies that by another 256.
//!
//! That strength is exactly why the checksum has to be shown to be load-
//! bearing rather than assumed to be: with criteria 1-3 as strong as they
//! are, a gate that had quietly stopped checking the checksum would still
//! find nothing in noise, and nothing would say so. **Measured during the
//! fix round, not reasoned about:** with criterion 4 removed entirely, the
//! six bare seeded identifiers in the corpus produced ZERO phantoms — the
//! remaining criteria rejected every one — so an unspliced corpus would have
//! gone quietly vacuous with every test green.
//!
//! The noise corpus therefore carries **two spliced archives, one per
//! checksum**: [`tests::CHECKSUM_ONLY_DEFECT_OFFSET`] is a level-1 archive
//! whose only defect is its 8-bit header checksum, and
//! [`tests::LEVEL2_CRC_ONLY_DEFECT_OFFSET`] a level-2 one whose only defect
//! is its common-header CRC-16. Deleting either check turns that splice into
//! a phantom entry and the anti-vacuity test goes red. Two splices rather
//! than one because criterion 4 is two different comparisons — a single
//! splice would have left the other silently disableable, which is the same
//! vacuity one level down. The task report records both runs.
//!
//! # Verification reuses `delharc`'s own decoders, never a second stack
//!
//! [`LhaSalvage::verify`] seeks to the candidate's own
//! [`Candidate::payload_start`], bounds the read to the declared compressed
//! length, and hands it to `delharc`'s [`DecoderAny`] — the identical
//! decoder `lha.rs`'s reader dispatches to, selected by the identical
//! method identifier. The decoded bytes stream through Task 1's
//! [`crate::salvage_verify::stream_verify`], which is what decides
//! [`SalvageStatus`] (length agreement, then the CRC-16/ARC comparison)
//! rather than a second hand-rolled comparison.
//!
//! **LHA STREAMS, and that is why this scanner declares no whole-entry
//! ceiling** — see [`LhaSalvage::max_whole_entry`]. It is the zip shape, not
//! the ARC/ZOO one, and declaring a ceiling it does not need would refuse
//! recoverable entries for a cost this format never pays.
//!
//! **[`SalvageStatus::Complete`] is unreachable for LHA, and that is a
//! contract, not an accident.** `Complete` means the format offers NO
//! checksum at all to prove a payload with (tar, cpio, ar). Every LHA entry
//! header carries a CRC-16/ARC over the uncompressed file, so a candidate
//! this build did not or could not check is [`SalvageStatus::Unverified`] —
//! a tier carries a decision, a message carries a cause.
//!
//! # Names are `lha.rs`'s, exactly
//!
//! [`super::lha::lha_name_from_parts`] is shared rather than reimplemented.
//! This project's reported LHA names are deliberately NOT `delharc`'s (three
//! documented differences — see `lha.rs`'s `raw_pathname`), and name
//! matching in this project is EXACT, so a scanner with its own copy of the
//! escaping would report an entry under a name `stuffr list` never shows and
//! `salvage --pattern` would match neither spelling.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use delharc::decode::{Decoder, DecoderAny};
use delharc::header::CompressionMethod;

use stuffr_core::salvage::{
    Candidate, SalvageOutcome, SalvagePolicy, SalvageScan, SalvageStatus, SalvagedEntry,
    UnverifiedCause, Verifier, salvage_all, stream_bounded_copy,
};
use stuffr_core::{EntryKind, EntryMeta, Error, FormatId, Result, SeekRead};

use super::crc::{crc16_arc, crc16_arc_continued};
use super::lha::{LEVEL1_HEADER_OVERHEAD, lha_mtime, lha_name_from_parts};

/// Bytes read per [`find_next_method`] chunk. O(1) memory regardless of how
/// far the next identifier is, or whether there is one at all — same figure,
/// same reasoning, as `zip_salvage.rs`'s, `arc_salvage.rs`'s and
/// `zoo_salvage.rs`'s own `SCAN_CHUNK`.
const SCAN_CHUNK: usize = 64 * 1024;

/// The most bytes a level-0/1 base header can occupy: the length byte, the
/// checksum byte, and the `u8`-declared `header_len` bytes behind them.
const MAX_BASE_HEADER: usize = 2 + u8::MAX as usize;

/// Offsets within a level-0/1 base header, from the header's own first byte.
/// Every one of them is a row of this module's doc table; named here so no
/// literal offset appears in the code below.
const HEADER_LEN_I: usize = 0;
const HEADER_CSUM_I: usize = 1;
const METHOD_I: usize = 2;
const COMPRESSED_SIZE_I: usize = 7;
const ORIGINAL_SIZE_I: usize = 11;
const LAST_MODIFIED_I: usize = 15;
const HEADER_LEVEL_I: usize = 20;
const NAME_LEN_I: usize = 21;
const NAME_I: usize = 22;

/// Every byte a level-**0** header carries except the filename, counted the
/// way the header-length field itself counts — from `METHOD_I`, so the two
/// bytes in front of it are excluded: the 5-byte method, three `u32` fields,
/// the attribute byte, the level byte, the filename-length byte and the
/// trailing `u16` CRC-16. A level-0 header therefore declares
/// `LEVEL0_HEADER_OVERHEAD + name.len()` at minimum.
///
/// Level 1's equivalent is [`LEVEL1_HEADER_OVERHEAD`] (25 — three more: the
/// OS-TYPE byte and the `u16` first-extra-header length), imported from
/// `lha.rs` rather than restated, because that constant is the one the
/// production writer counts with.
const LEVEL0_HEADER_OVERHEAD: usize = 22;

/// The whole of a level-**2** base header, which is a fixed 26 bytes: the
/// `u16` total header size at `H+0` (level 2 spends the length and checksum
/// bytes on one figure), the 5-byte method, three `u32` fields, a reserved
/// byte, the level byte, the `u16` file CRC-16, the OS-TYPE byte and the
/// `u16` first-extra-header length. **No filename and no filename length** —
/// a level-2 name lives in a `0x01` extension header, which is why this is a
/// fixed figure where levels 0 and 1 declare theirs.
///
/// Read off `delharc 0.6.2`'s `parser.rs` exactly as the level-0/1 table in
/// this module's doc was: the packed `LhaRawBaseHeader` (line 70), the
/// filename read SKIPPED for `lha_level >= 2` (line 207), the file CRC-16
/// (218), OS-TYPE (221-224, level > 0), and `first_header_len` (258).
const LEVEL2_BASE_LEN: usize = 26;

/// `H+21`: the level-2 file CRC-16. Levels 0 and 1 put it behind the
/// filename, at a position only the name length can locate; level 2 has no
/// name in the base header, so it is fixed.
const LEVEL2_CRC_I: usize = 21;

/// `H+24`: the level-2 `u16` first-extra-header length.
const LEVEL2_FIRST_EXTRA_I: usize = 24;

/// The smallest a level-1 or level-2 extra header can be: one identifier
/// byte plus the two-byte length of the next one. `delharc`'s own parser
/// rejects anything smaller (`parser.rs`'s `min_header_len` for level < 3).
const MIN_EXTRA_HEADER: u64 = 3;

/// The most bytes this scanner will walk through a level-1 extra-header
/// chain before deciding the chain is not one.
///
/// A real chain is a few hundred bytes — a filename header, a path header, a
/// "common" CRC header, a Unix timestamp — and the ceiling is two orders of
/// magnitude above that. It is deliberately **one byte above** the largest a
/// single extra header can declare (a `u16`, 65,535), so a well-formed chain
/// of one maximal header is never refused by the cap itself; only a chain
/// that keeps going past the point of plausibility is.
///
/// The cap is about the WALK, not about an allocation: each header is read
/// into a buffer sized by its own `u16` length, so the largest buffer this
/// module ever asks for is 65,535 bytes no matter what any header declares.
/// [`tests::a_level_1_chain_never_allocates_from_the_skip_size_it_declares`]
/// proves that with the recording allocator rather than asserting a status.
const MAX_EXTRA_CHAIN: u64 = 64 * 1024;

/// Bytes decoded per `fill_buffer` call.
///
/// `delharc`'s [`Decoder::fill_buffer`] is all-or-nothing: it fills the whole
/// slice it is given or fails, and a failure says nothing about how much of
/// the slice it had already written. On a TRUNCATED entry — the single most
/// common damaged archive there is — that discards the final, partly-decoded
/// chunk, so the chunk size is the upper bound on how much of a genuine
/// surviving prefix `NAME.partial` loses. 4 KiB rather than
/// [`crate::salvage_verify`]'s own 64 KiB window for exactly that reason;
/// `stuffr`'s ordinary `unpack` path pays the larger figure because it is not
/// a recovery verb and stops at the first error anyway.
const DECODE_CHUNK: usize = 4096;

/// The compression-method identifiers an LHA/LZH entry header can carry, in
/// the `-lh*-`/`-lz*-` families `lha.rs`'s own registered magic claims.
///
/// # What is in the set, and what deliberately is not
///
/// Exactly the `-lh*-`/`-lz*-` rows of `delharc 0.6.2`'s own identifier
/// table (`src/header/compression.rs:30-50`) — the table the reader beside
/// this scanner already dispatches on. **PMarc's `-pm0-`/`-pm1-`/`-pm2-` are
/// excluded on purpose**, even though `delharc` names them: `lha.rs`'s
/// `LHA_MAGIC` registers two rules, `-lh` and `-lz` at offset 2, so a PMarc
/// file is not something `stuffr list` will open as `lha` at all, and a
/// salvage scan claiming to have found entries in one would be claiming a
/// format this build does not otherwise read.
///
/// [`tests::the_recognised_set_is_exactly_delharcs_own_lh_and_lz_table`]
/// brute-forces both families over the whole byte space in both directions,
/// so neither a method this crate's own reader knows nor one it does not can
/// drift out of step with this enum silently.
///
/// # Recognised is not decodable
///
/// [`Self::decodable`] is a separate, exhaustive `match`, pinned against
/// `delharc`'s own `DecoderAny::is_supported` by
/// [`tests::decodability_matches_what_this_build_actually_compiled`]. A
/// recognised-but-undecodable method is a real, reportable entry — the
/// archive is fine, this build cannot decode that one method — and is
/// answered [`UnverifiedCause::UndecodableMethod`], never dropped from the
/// scan and never `Complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Method {
    /// `-lhd-`: not a compression method at all, but the format's marker for
    /// a DIRECTORY entry — no payload, and `delharc`'s own
    /// `CompressionMethod::is_directory` is what reads it.
    Lhd,
    Lh0,
    Lh1,
    Lh4,
    Lh5,
    Lh6,
    Lh7,
    /// `-lhx-`: recognised by the format, not compiled into this build
    /// (`lha.rs`'s module doc: `delharc` with `std`, `lh1`, `lz` — no
    /// `lhx`).
    Lhx,
    Lzs,
    Lz4,
    Lz5,
}

impl Method {
    /// The five-byte ASCII identifier this method is stored as.
    pub(super) const fn identifier(self) -> &'static [u8; 5] {
        match self {
            Method::Lhd => b"-lhd-",
            Method::Lh0 => b"-lh0-",
            Method::Lh1 => b"-lh1-",
            Method::Lh4 => b"-lh4-",
            Method::Lh5 => b"-lh5-",
            Method::Lh6 => b"-lh6-",
            Method::Lh7 => b"-lh7-",
            Method::Lhx => b"-lhx-",
            Method::Lzs => b"-lzs-",
            Method::Lz4 => b"-lz4-",
            Method::Lz5 => b"-lz5-",
        }
    }

    /// The method a header's five identifier bytes name, or `None` for bytes
    /// the format never assigned — the scan's criterion 1.
    pub(super) fn from_identifier(id: &[u8; 5]) -> Option<Self> {
        Self::all().find(|method| method.identifier() == id)
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
    /// and is refused there by name rather than vanishing into the same
    /// "not built in" disposition a missing dispatch arm would produce.
    pub(super) const fn codec(self) -> FormatId {
        match self {
            Method::Lhd => FormatId::new("lha-lhd"),
            Method::Lh0 => FormatId::new("lha-lh0"),
            Method::Lh1 => FormatId::new("lha-lh1"),
            Method::Lh4 => FormatId::new("lha-lh4"),
            Method::Lh5 => FormatId::new("lha-lh5"),
            Method::Lh6 => FormatId::new("lha-lh6"),
            Method::Lh7 => FormatId::new("lha-lh7"),
            Method::Lhx => FormatId::new("lha-lhx"),
            Method::Lzs => FormatId::new("lha-lzs"),
            Method::Lz4 => FormatId::new("lha-lz4"),
            Method::Lz5 => FormatId::new("lha-lz5"),
        }
    }

    /// `delharc`'s own enum value for this method, which is what selects a
    /// decoder. `None` for [`Method::Lhx`] is deliberate and is NOT the same
    /// fact as "delharc does not name it" — it does; this build simply has
    /// no decoder compiled for it, and [`Self::decodable`] is where that is
    /// said.
    const fn compression(self) -> CompressionMethod {
        match self {
            Method::Lhd => CompressionMethod::Lhd,
            Method::Lh0 => CompressionMethod::Lh0,
            Method::Lh1 => CompressionMethod::Lh1,
            Method::Lh4 => CompressionMethod::Lh4,
            Method::Lh5 => CompressionMethod::Lh5,
            Method::Lh6 => CompressionMethod::Lh6,
            Method::Lh7 => CompressionMethod::Lh7,
            Method::Lhx => CompressionMethod::Lhx,
            Method::Lzs => CompressionMethod::Lzs,
            Method::Lz4 => CompressionMethod::Lz4,
            Method::Lz5 => CompressionMethod::Lz5,
        }
    }

    /// Whether THIS BUILD can decode a payload stored under this method.
    ///
    /// An exhaustive `match` so a variant added without an answer here does
    /// not compile, and pinned against the only authority that actually
    /// knows — `delharc`'s own `DecoderAny::is_supported`, over the feature
    /// set this build compiled — by
    /// [`tests::decodability_matches_what_this_build_actually_compiled`].
    /// `Lhd` answers `false` because there is no payload to decode, which is
    /// a different fact from `Lhx`'s and is handled separately everywhere it
    /// matters ([`Self::is_directory`]).
    pub(super) const fn decodable(self) -> bool {
        match self {
            Method::Lh0 | Method::Lh1 | Method::Lh4 | Method::Lh5 | Method::Lh6 | Method::Lh7 => {
                true
            }
            Method::Lzs | Method::Lz4 | Method::Lz5 => true,
            Method::Lhd | Method::Lhx => false,
        }
    }

    /// Whether this identifier marks a DIRECTORY entry rather than naming a
    /// compression method. Such an entry has no payload at all, so there is
    /// nothing to decode and nothing missing when nothing is decoded.
    pub(super) const fn is_directory(self) -> bool {
        matches!(self, Method::Lhd)
    }

    /// The variant after `self` in declaration order, `None` past the last.
    ///
    /// Exists only to drive [`Self::all`], and is an exhaustive `match` for
    /// exactly one reason: **a twelfth variant added to [`Method`] without
    /// an arm here does not compile.** Same shape, same reason, as
    /// `arc.rs`'s and `zoo.rs`'s own `Method::next`.
    const fn next(self) -> Option<Self> {
        match self {
            Method::Lhd => Some(Method::Lh0),
            Method::Lh0 => Some(Method::Lh1),
            Method::Lh1 => Some(Method::Lh4),
            Method::Lh4 => Some(Method::Lh5),
            Method::Lh5 => Some(Method::Lh6),
            Method::Lh6 => Some(Method::Lh7),
            Method::Lh7 => Some(Method::Lhx),
            Method::Lhx => Some(Method::Lzs),
            Method::Lzs => Some(Method::Lz4),
            Method::Lz4 => Some(Method::Lz5),
            Method::Lz5 => None,
        }
    }

    /// Every recognised method, in declaration order — seeded from the first
    /// variant and driven by [`Self::next`]'s exhaustive `match`.
    ///
    /// **The chain is compiler-checked; the SEED is not**, the identical
    /// asymmetry `arc.rs`'s and `zoo.rs`'s own `all` document: a variant
    /// added at the END cannot be forgotten, one added at the FRONT compiles
    /// cleanly and is silently absent. The front door is closed by
    /// [`tests::the_recognised_set_is_exactly_delharcs_own_lh_and_lz_table`],
    /// which sweeps the identifier space rather than iterating this
    /// function.
    pub(super) fn all() -> impl Iterator<Item = Self> {
        std::iter::successors(Some(Method::Lhd), |method| method.next())
    }
}

/// Maps [`EntryMeta::codec`] (as [`Method::codec`] filled it) back to the
/// [`Method`] the decoders dispatch on.
///
/// Searches [`Method::all`] for the variant whose [`Method::codec`] matches,
/// rather than hand-copying the same eleven strings in the opposite
/// direction — the shape Ruling S-K deleted from ARC.
fn method_for_codec(codec: Option<FormatId>) -> Option<Method> {
    let codec = codec?;
    Method::all().find(|method| method.codec() == codec)
}

/// One level-0/1 entry header, parsed out of its base header and (for level
/// 1) the extra-header chain behind it.
#[derive(Debug)]
struct EntryHeader {
    method: Method,
    /// The compressed payload's own length: the header's `compressed size`
    /// field for levels 0 and 2, and for level 1 that field (the SKIP size)
    /// minus every byte of the extra-header chain — the one level where the
    /// field means something else (`parser.rs:365-368`).
    declared_len: u64,
    /// The entry's DECODED length. A `u64` rather than the base header's own
    /// `u32` because a level-2 `EXT_HEADER_MSDOS_SIZE` header overrides it
    /// with a 64-bit figure — Ruling S-W, and the whole reason that header
    /// exists.
    original_size: u64,
    file_crc: u16,
    /// Decoded here rather than carried raw, because the field does not mean
    /// the same thing at every level: levels 0 and 1 pack an MS-DOS date/time
    /// word, level 2 a Unix timestamp in seconds (`delharc`'s own
    /// `parse_last_modified` makes the identical split).
    mtime: Option<SystemTime>,
    name: String,
    /// Absolute position of the first compressed payload byte — the base
    /// header plus, for levels 1 and 2, the whole extra-header chain.
    payload_start: u64,
}

/// Scans an LHA/LZH archive for entry headers directly, without walking the
/// chain of `skip size` hops from the front of the file that a damaged
/// header breaks for every entry behind it.
///
/// Carries no state between calls beyond what [`SalvageScan::next_candidate`]
/// itself receives — the same shape `ZipSalvage`, `ArcSalvage` and
/// `ZooSalvage` have.
#[derive(Debug, Default)]
pub struct LhaSalvage {
    /// Header shapes this scan recognised and cannot gate — Ruling S-V. The
    /// one piece of state this scanner carries between calls, and it exists
    /// so [`salvage_lha`] can tell "this archive holds nothing recoverable"
    /// apart from "this build cannot gate what this archive holds". See
    /// [`UngateableSightings`].
    seen: UngateableSightings,
}

impl LhaSalvage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SalvageScan for LhaSalvage {
    fn next_candidate(&mut self, src: &mut dyn SeekRead, from: u64) -> Result<Option<Candidate>> {
        let file_len = src.seek(SeekFrom::End(0))?;
        // The identifier sits at the header's own offset 2, so a header at
        // or after `from` has its identifier at or after `from + 2`.
        let mut search_from = from.saturating_add(METHOD_I as u64);
        loop {
            let Some(at) = find_next_method(src, search_from, file_len)? else {
                return Ok(None);
            };
            let offset = at - METHOD_I as u64;
            match read_candidate_at(src, offset, file_len, &mut self.seen) {
                Some(candidate) => return Ok(Some(candidate)),
                // The identifier matched and the gate rejected everything
                // around it: a coincidence, not a header. Resume one byte
                // past the identifier itself, not past a whole assumed
                // header, so a genuine header overlapping this false match
                // is never skipped.
                None => search_from = at + 1,
            }
        }
    }

    /// **LHA imposes no whole-entry ceiling of its own, and that is a
    /// measured claim rather than an omission.**
    ///
    /// `arc.rs` and `zoo.rs` override this with a 256 MiB figure because
    /// those two containers decode an entry WHOLE: a declared length really
    /// does become one allocation there. LHA does not. `delharc`'s decoders
    /// are `fill_buffer`-shaped over a fixed dictionary window, so
    /// [`verify_candidate`] streams a candidate through
    /// [`crate::salvage_verify::stream_verify`]'s 64 KiB window and
    /// [`write_payload`] through [`stream_bounded_copy`]'s, and **nothing in
    /// this module is ever sized from a header field** — the one buffer that
    /// is (a level-1 extra header) is bounded by its own `u16` type, 64 KiB,
    /// and again by [`MAX_EXTRA_CHAIN`].
    ///
    /// That is the same answer `zip_salvage.rs` gives, for the same reason,
    /// and it is deliberately not the conservative one: a ceiling declared
    /// here is applied by `annotate_candidates` BEFORE [`Self::verify`] runs
    /// and makes the entry [`UnverifiedCause::OverEntryCeiling`], which
    /// `entries.rs` never writes. ZOO's fix round 1 measured what that costs
    /// when the ceiling does not match the allocation it is standing in for:
    /// a completely recoverable 11,357-byte payload reported "over the
    /// ceiling" and written nowhere. A format that allocates nothing has
    /// nothing to protect, and `policy.max_entry` (4 GiB, `--max-entry`) is
    /// still in force above it — which for LHA is the whole of the range its
    /// own `u32` size fields can express.
    ///
    /// [`tests::a_four_gigabyte_declaration_never_becomes_an_allocation`]
    /// proves the premise with the recording allocator rather than asserting
    /// it.
    fn max_whole_entry(&self) -> u64 {
        u64::MAX
    }

    fn verify(&self, src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
        verify_candidate(src, candidate)
    }

    /// The write half of this scanner's seam, declared beside the scan half
    /// (final whole-branch review, F2). Delegates to this module's own free
    /// [`write_payload`], which is still `pub` and is what `entries.rs`'s
    /// dispatch and this module's tests both reach — the method exists so
    /// the trait DECLARES a scanner's write path rather than leaving it to
    /// a private `match` on a format name.
    fn write_payload(
        &self,
        archive_path: &std::path::Path,
        entry: &SalvagedEntry,
        compressed_len: u64,
        out: &mut dyn std::io::Write,
    ) -> Result<bool> {
        write_payload(archive_path, entry, compressed_len, out)
    }
}

/// Searches forward from `from` for the next position holding a five-byte
/// identifier [`Method::from_identifier`] accepts, in bounded chunks so
/// memory use does not depend on how far through the source the next one is.
///
/// Carries at most four bytes across a chunk boundary — the longest a
/// five-byte match can straddle — so a match split across two reads is never
/// missed. `Ok(None)` when no identifier remains before `file_len`.
fn find_next_method(src: &mut dyn SeekRead, from: u64, file_len: u64) -> io::Result<Option<u64>> {
    if from >= file_len {
        return Ok(None);
    }
    src.seek(SeekFrom::Start(from))?;

    let mut window: Vec<u8> = Vec::with_capacity(SCAN_CHUNK + 4);
    let mut window_start = from;
    let mut buf = vec![0u8; SCAN_CHUNK];

    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        window.extend_from_slice(&buf[..n]);

        if let Some(at) = window.windows(5).position(|w| {
            // Every identifier the format assigned is `-` `x` `y` `z` `-`,
            // so two byte comparisons reject essentially every position
            // before the table is consulted at all.
            w[0] == b'-'
                && w[4] == b'-'
                && Method::from_identifier(&[w[0], w[1], w[2], w[3], w[4]]).is_some()
        }) {
            return Ok(Some(window_start + at as u64));
        }

        // Keep only the last 4 bytes: the longest prefix of an identifier
        // that could still be waiting for its remaining bytes in the next
        // chunk.
        let keep = window.len().saturating_sub(4);
        window_start += keep as u64;
        window.drain(..keep);
    }
}

/// The header checksum an LHA level-0/1 header carries at its own offset 1:
/// the bytes from offset 2 through the end of the header, summed mod 256.
///
/// `base[2..]` rather than a length argument because the caller has already
/// bounded the slice to the whole header — see this module's doc table for
/// the field, and `lha.rs`'s `write_level1_header`, which computes the
/// identical sum over the identical run when it WRITES one.
fn checksum_of(counted: &[u8]) -> u8 {
    counted.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// Reads and gates the header believed to start at `offset`, per the
/// criteria in this module's doc.
///
/// `None` for ANY gate failure, including a genuine read error: to a SCANNER
/// they all mean the same thing — these bytes are not a header — so they
/// fold here rather than propagating and ending a run over one coincidence.
///
/// Dispatches on the header LEVEL, because the three shapes agree on almost
/// nothing behind their shared method identifier: level 0 and level 1 share a
/// base header and an 8-bit checksum, level 2 replaces the length and
/// checksum bytes with one `u16` total size, moves every field behind the
/// (absent) filename, and is gated on a 16-bit CRC in an extension header
/// instead. Level 3 is not scanned — see this module's doc.
fn parse_header_at(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
    seen: &mut UngateableSightings,
) -> Option<EntryHeader> {
    // Criterion 3, first half: read at most one base header's worth, and
    // never past the end of the source. A fixed 257-byte read — the whole
    // range a `u8` length field can describe, and comfortably more than
    // level 2's fixed 26 — so nothing here is sized from anything the file
    // declares.
    let want = MAX_BASE_HEADER.min(usize::try_from(file_len.checked_sub(offset)?).ok()?);
    if want < NAME_I {
        return None;
    }
    src.seek(SeekFrom::Start(offset)).ok()?;
    let mut base = vec![0u8; want];
    src.read_exact(&mut base).ok()?;

    // Criterion 1. The caller found this identifier, but a candidate must
    // never stand on its caller's word for a field it can read itself.
    let method = Method::from_identifier(&base[METHOD_I..METHOD_I + 5].try_into().ok()?)?;

    // Criterion 2.
    match base[HEADER_LEVEL_I] {
        level @ (0 | 1) => parse_level_0_or_1(src, offset, file_len, &base, method, level),
        2 => match parse_level_2(src, offset, file_len, &base, method) {
            Level2::Header(header) => Some(header),
            Level2::NoCommonHeader => {
                seen.level_2_without_common_header = true;
                None
            }
            Level2::NotAHeader => None,
        },
        3 => {
            // **Ruling S-V.** Level 3 is not parsed — see this module's doc
            // — but it IS recognised, on evidence strong enough that saying
            // so cannot be a coincidence. `delharc` requires a level-3
            // header to open with the bytes `4, 0` (`parser.rs:259-264`
            // raises "invalid header" otherwise: the word-size field is
            // always 4 and the byte after it always 0), so a sighting needs
            // the five-byte method identifier AND sixteen more structural
            // bits — about one chance in 2^56 in random bytes.
            //
            // Recognised, never reported as a candidate: there is no level-3
            // parser here, so there is no payload position to hand back.
            // What it buys is a RUN that can name the limitation instead of
            // answering "nothing recoverable in this archive".
            if base[HEADER_LEN_I] == 4 && base[HEADER_CSUM_I] == 0 {
                seen.level_3 = true;
            }
            None
        }
        _ => None,
    }
}

/// Header shapes the scan RECOGNISED and has no gate for — Ruling S-V.
///
/// # Why this exists rather than a silent `None`
///
/// Ruling S-U closed a population and left its own class open. On a HEALTHY
/// archive whose headers this scanner cannot gate, `stuffr list` printed the
/// entry at exit 0 while `stuffr salvage --list` answered `the scan found
/// nothing recoverable in this archive` at **exit 5** — a claim about the
/// ARCHIVE where the truth is a claim about the BUILD, which inverts this
/// project's own convention (`entries.rs`'s `salvage_scan` spends exit 3 on
/// exactly that distinction, "a statement about this build rather than about
/// the archive"). Documenting it in `examples.txt` was not enough: nothing
/// at runtime told a user which of the two situations they were in.
///
/// [`salvage_lha`] now turns a scan that recovered NOTHING while seeing one
/// of these into [`Error::Unsupported`] — exit 3 — naming the level and what
/// is missing.
///
/// # Both flags are set on strong structural evidence, never on a guess
///
/// That matters more here than anywhere else in this module: a false
/// sighting would turn an honest "this archive holds nothing recoverable"
/// into a confident, wrong claim about header levels. So
/// [`Self::level_3`] needs `delharc`'s own mandated `4, 0` prefix behind the
/// method identifier, and [`Self::level_2_without_common_header`] needs a
/// full level-2 parse to have succeeded at everything EXCEPT the checksum —
/// the declared total consistent, the extension chain terminating exactly
/// where the header said, and a name recovered from it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct UngateableSightings {
    /// A level-2 header whose extension chain carried no `EXT_HEADER_COMMON`
    /// (`0x00`) header, and therefore no checksum at any strength.
    level_2_without_common_header: bool,
    /// A level-3 header, which this build has no parser for at all.
    level_3: bool,
}

impl UngateableSightings {
    fn any(self) -> bool {
        self.level_2_without_common_header || self.level_3
    }

    /// The sentence a run reports when it recovered nothing and saw one of
    /// these. Names the level and what is missing, and says plainly that
    /// the ordinary verbs still read the archive — which is the whole
    /// difference between this and "nothing recoverable".
    fn refusal(self) -> String {
        let mut shapes: Vec<&str> = Vec::new();
        if self.level_2_without_common_header {
            shapes.push(
                "level-2 headers carrying no `common` (0x00) extension header, which is where \
                 the CRC-16 this scan gates on lives",
            );
        }
        if self.level_3 {
            shapes.push(
                "level-3 headers, whose 32-bit length fields and 4-byte extension counters need \
                 a parser this build does not have",
            );
        }
        format!(
            "this build's LHA salvage scanner recognised {} but has no gate for {}; the \
             archive itself may be perfectly readable — `stuffr list` and `stuffr unpack` \
             handle these headers normally, and it is the SCAN that stops here",
            if shapes.len() == 1 {
                "a header shape"
            } else {
                "header shapes"
            },
            shapes.join("; and "),
        )
    }
}

/// The level-0/1 half of [`parse_header_at`] — everything from criterion 3's
/// second half onward, for the two levels that share a base header and an
/// 8-bit header checksum.
fn parse_level_0_or_1(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
    base: &[u8],
    method: Method,
    level: u8,
) -> Option<EntryHeader> {
    // Criterion 3, second half.
    let header_len = usize::from(base[HEADER_LEN_I]);
    let base_len = METHOD_I.checked_add(header_len)?;
    if base_len > base.len() {
        return None;
    }
    let name_len = usize::from(base[NAME_LEN_I]);
    // Criterion 5.
    if name_len == 0 {
        return None;
    }
    let overhead = if level == 0 {
        LEVEL0_HEADER_OVERHEAD
    } else {
        LEVEL1_HEADER_OVERHEAD
    };
    // The name plus everything the level's own fields require behind it. For
    // level 0 that is the trailing CRC-16; for level 1 the CRC-16, the
    // OS-TYPE byte and the first extra-header length, which is what
    // `LEVEL1_HEADER_OVERHEAD` already counts.
    // Compared against `header_len`, NOT against `base_len`: both overhead
    // figures count from `METHOD_I`, exactly as the length field itself
    // does. Comparing the two-bytes-larger total instead would admit a
    // header declaring two bytes fewer than its own fields need.
    let minimum = overhead.checked_add(name_len)?;
    if header_len < minimum {
        return None;
    }

    // Criterion 4 — the second signal, and the one Step 5 falsifies.
    if checksum_of(&base[METHOD_I..base_len]) != base[HEADER_CSUM_I] {
        return None;
    }

    let name_bytes = base.get(NAME_I..NAME_I.checked_add(name_len)?)?;
    let crc_at = NAME_I + name_len;
    let file_crc = u16::from_le_bytes(base.get(crc_at..crc_at + 2)?.try_into().ok()?);
    let skip_size = u32::from_le_bytes(
        base.get(COMPRESSED_SIZE_I..COMPRESSED_SIZE_I + 4)?
            .try_into()
            .ok()?,
    );
    let original_size = u32::from_le_bytes(
        base.get(ORIGINAL_SIZE_I..ORIGINAL_SIZE_I + 4)?
            .try_into()
            .ok()?,
    );
    let last_modified = u32::from_le_bytes(
        base.get(LAST_MODIFIED_I..LAST_MODIFIED_I + 4)?
            .try_into()
            .ok()?,
    );

    let base_end = offset.checked_add(base_len as u64)?;
    let (payload_start, extra_total, ext_name, ext_path) = if level == 0 {
        // Level 0 has no extra headers at all (`parser.rs`'s `first_header_len`
        // is only ever read for levels 1-3), so the payload begins where the
        // base header ends.
        (base_end, 0u64, Vec::new(), Vec::new())
    } else {
        // The first extra-header length is the LAST two bytes of the base
        // header, whatever optional extended area sits in front of it — see
        // this module's doc for why `2 + header_len` bounds the whole base
        // header for both levels.
        let first = u16::from_le_bytes(base.get(base_len - 2..base_len)?.try_into().ok()?);
        let walk = walk_extra_headers(
            src,
            base_end,
            file_len,
            u64::from(first),
            u64::from(skip_size),
            0,
        )?;
        (
            base_end.checked_add(walk.total)?,
            walk.total,
            walk.name,
            walk.path,
        )
    };

    // Criterion 6's arithmetic half: level 1's size field is the SKIP size —
    // the payload PLUS every extra header — so the payload's own length is
    // what is left after the chain. `checked_sub`, because a header
    // declaring a chain longer than its own skip size is contradicting
    // itself, which is `delharc`'s own verdict too (`parser.rs:365-368`
    // raises "wrong length of skip size").
    let declared_len = u64::from(skip_size).checked_sub(extra_total)?;

    // Extra headers 0x01 (filename) and 0x02 (path) take precedence exactly
    // as `lha.rs`'s `raw_pathname` applies them, and the escaping is that
    // function's own — see this module's doc.
    let base_name: &[u8] = if ext_name.is_empty() {
        name_bytes
    } else {
        &ext_name
    };
    let name = lha_name_from_parts(&ext_path, base_name);

    Some(EntryHeader {
        method,
        declared_len,
        // Levels 0 and 1 have no 64-bit override; the base header's `u32` is
        // the whole of what they can say.
        original_size: u64::from(original_size),
        file_crc,
        mtime: lha_mtime(last_modified),
        name,
        payload_start,
    })
}

/// The level-**2** half of [`parse_header_at`].
///
/// # Why level 2 is scanned at all, and what gates it (Ruling S-U)
///
/// The first version of this module scanned levels 0 and 1 only, on the
/// stated reasoning that levels 2 and 3 "carry no header checksum" and that
/// admitting them would weaken the gate. **The premise was false of level 2
/// and the cost was measured.** On a HEALTHY, undamaged level-2 archive the
/// `0.5.0` binary answered:
///
/// ```text
/// $ stuffr list level2.lzh          # exit 0:  0  30  level2.txt
/// $ stuffr salvage level2.lzh --list
/// salvage -> the scan found nothing recoverable in this archive
/// exit=5
/// ```
///
/// Two lines of one tool contradicting each other on an undamaged file, and
/// the message pointed the wrong way besides: exit 5 is a claim about the
/// ARCHIVE, where the truth was a claim about the BUILD (this project spends
/// exit 3 on that, and `salvage_scan`'s own refusal says so in those words).
///
/// **And a stronger gate than level 0/1's was available the whole time.** A
/// level-2 header conventionally carries an `EXT_HEADER_COMMON` (`0x00`)
/// extension header holding a **CRC-16 over the whole header** — base bytes,
/// every extension header, and the padding byte, with its own two checksum
/// bytes zeroed while the sum is taken (`delharc 0.6.2`'s
/// `parser.rs:306-317` extracts and zeroes it, `356-360` validates it).
/// Sixteen bits against levels 0 and 1's 8-bit sum-mod-256: a coincidence
/// roughly every 65,536 candidate positions rather than every 256. Scanning
/// level 2 makes this scanner's weakest gate *stronger*, not weaker.
///
/// **This gate is MANDATORY where `delharc`'s is advisory**, and that is the
/// one deliberate narrowing. `LhaHeader::read` accepts a level-2 header with
/// no common extension header at all (`header_crc` stays `None` and the
/// comparison is skipped); this function refuses one, because a scanner with
/// no checksum to check has nothing to tell a real header from five
/// coincidental bytes. Every level-2 writer in practice emits the common
/// header; one that does not is not scanned, and that is a narrower gap than
/// the one this ruling closed.
///
/// # The CRC-16 is `legacy::crc`'s own, and that is checked rather than assumed
///
/// `delharc`'s `Crc16` (`src/crc.rs`) is a table-driven CRC-16/ARC — its
/// table's second entry is `0xc0c1`, the reflected-`0xA001` signature, with
/// init 0 and no final xor — i.e. bit-for-bit
/// [`super::crc::crc16_arc`], which this crate already pins against the
/// published RevEng check value. So this computes the identical sum with
/// this crate's own function rather than reaching into `delharc`'s, which is
/// what keeps the gate falsifiable: a check that lives inside the dependency
/// cannot be disabled to prove it is load-bearing, and that is the whole
/// reason this module owns a parser at all.
fn parse_level_2(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
    base: &[u8],
    method: Method,
) -> Level2 {
    // Every `?` in the body below means "that field is not there", which is
    // the same answer as every other structural failure: not a header.
    // Folded once, here, rather than spelled out at each site.
    parse_level_2_inner(src, offset, file_len, base, method).unwrap_or(Level2::NotAHeader)
}

fn parse_level_2_inner(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
    base: &[u8],
    method: Method,
) -> Option<Level2> {
    if base.len() < LEVEL2_BASE_LEN {
        return Some(Level2::NotAHeader);
    }
    // Level 2 spends the two bytes levels 0 and 1 give to a length and a
    // checksum on ONE `u16` total header size (`parser.rs:257`:
    // `long_header_len = u16::from_le_bytes([header_len, csum])`).
    let total = u64::from(u16::from_le_bytes(
        base.get(HEADER_LEN_I..HEADER_LEN_I + 2)?.try_into().ok()?,
    ));
    // Criterion 3: the declared header has to be at least a base header, and
    // all of it has to be present.
    if total < LEVEL2_BASE_LEN as u64 || offset.checked_add(total)? > file_len {
        return Some(Level2::NotAHeader);
    }

    let compressed_size = u32::from_le_bytes(
        base.get(COMPRESSED_SIZE_I..COMPRESSED_SIZE_I + 4)?
            .try_into()
            .ok()?,
    );
    let original_size = u32::from_le_bytes(
        base.get(ORIGINAL_SIZE_I..ORIGINAL_SIZE_I + 4)?
            .try_into()
            .ok()?,
    );
    let unix_time = u32::from_le_bytes(
        base.get(LAST_MODIFIED_I..LAST_MODIFIED_I + 4)?
            .try_into()
            .ok()?,
    );
    let file_crc = u16::from_le_bytes(base.get(LEVEL2_CRC_I..LEVEL2_CRC_I + 2)?.try_into().ok()?);
    let first = u16::from_le_bytes(
        base.get(LEVEL2_FIRST_EXTRA_I..LEVEL2_FIRST_EXTRA_I + 2)?
            .try_into()
            .ok()?,
    );

    // The running CRC-16 covers the header from its very first byte, in the
    // order `delharc`'s parser reads it — so it is seeded over the whole
    // fixed base header and carried through the chain walk.
    let seed = crc16_arc(&base[..LEVEL2_BASE_LEN]);
    let base_end = offset.checked_add(LEVEL2_BASE_LEN as u64)?;
    let walk = walk_extra_headers(src, base_end, file_len, u64::from(first), total, seed)?;

    let mut consumed = LEVEL2_BASE_LEN as u64 + walk.total;
    let mut running = walk.crc;
    if consumed.checked_add(1)? == total {
        // `parser.rs:344-348`: level 2 alone may carry ONE padding byte
        // between the last extension header and the payload, and it is
        // inside the CRC's range.
        src.seek(SeekFrom::Start(offset.checked_add(consumed)?))
            .ok()?;
        let mut pad = [0u8; 1];
        src.read_exact(&mut pad).ok()?;
        running = crc16_arc_continued(running, &pad);
        consumed += 1;
    } else if consumed != total && consumed != total.checked_add(2)? {
        // `parser.rs:349-354`: the only other shape `delharc` tolerates is
        // the Osk packers' — a total that does not count its own two bytes.
        // Anything else is a header contradicting its own declared size.
        return Some(Level2::NotAHeader);
    }

    // Criterion 5's analogue, checked BEFORE the checksum so a nameless run
    // of bytes is never reported as a gateable header shape this build
    // lacks — see [`Level2`] for why that ordering matters. Level 2 carries
    // no name in the base header at all, so an empty one means the chain
    // held no `0x01` and no `0x02` header, which no real writer produces.
    let name = lha_name_from_parts(&walk.path, &walk.name);
    if name.is_empty() {
        return Some(Level2::NotAHeader);
    }

    // **Criterion 4 for level 2, and the one Step 5's level-2 twin
    // falsifies.** Mandatory: no common header means no checksum, and no
    // checksum means nothing separates this from five coincidental bytes.
    let Some(declared_crc) = walk.common_crc else {
        // Everything structural held and there is simply no checksum to
        // check — a shape this BUILD cannot gate rather than one this
        // archive got wrong. Ruling S-V: reported upward so the run can say
        // so by name instead of answering "nothing recoverable".
        return Some(Level2::NoCommonHeader);
    };
    if declared_crc != running {
        return Some(Level2::NotAHeader);
    }

    // **Ruling S-W.** A `0x42` extension header overrides BOTH base fields
    // at level >= 2 — that is how the format expresses an entry past the
    // 4 GiB its `u32`s can hold — and `delharc` honours it, so `list` and
    // `salvage` reported two different sizes for one healthy entry until
    // this did too (measured: 5,000 against 100).
    let (compressed_size, original_size) = match walk.msdos_size {
        Some((compressed, original)) => (compressed, original),
        None => (u64::from(compressed_size), u64::from(original_size)),
    };

    Some(Level2::Header(EntryHeader {
        method,
        // NOT reduced by the chain: level 1's size field is the skip size and
        // level 2's is the compressed length itself, which is exactly why
        // `delharc` subtracts the extras for level 1 ALONE
        // (`parser.rs:365-368`).
        declared_len: compressed_size,
        original_size,
        file_crc,
        // A Unix timestamp in seconds, not an MS-DOS word — `delharc`'s
        // `parse_last_modified` makes the same split at the same level.
        mtime: Some(UNIX_EPOCH + Duration::from_secs(u64::from(unix_time))),
        name,
        payload_start: offset.checked_add(consumed)?,
    }))
}

/// What [`parse_level_2`] made of the bytes at an offset.
///
/// Three answers rather than two, because Ruling S-V turns on the middle
/// one: "these bytes are not a header" and "these bytes ARE a header this
/// build has no gate for" lead to opposite things being said to a user, and
/// an `Option` cannot tell them apart.
enum Level2 {
    Header(EntryHeader),
    /// Everything structural held — the declared total is consistent, the
    /// extension chain walked to its terminator exactly where the header
    /// said it would, and a name came out of it — and the chain carried no
    /// `EXT_HEADER_COMMON` header, so there is no checksum at any strength
    /// to gate on. See [`UngateableSightings`].
    NoCommonHeader,
    NotAHeader,
}

/// What an extra-header chain walk recovered.
struct ExtraChain {
    /// Total bytes the chain occupies, which is what separates the base
    /// header from the payload — and, for level 1 alone, what must be
    /// subtracted from the skip size to get the payload's own length.
    total: u64,
    /// The `0x01` (filename) extra header's data, if the chain carried one.
    name: Vec<u8>,
    /// The `0x02` (path) extra header's data, if the chain carried one.
    path: Vec<u8>,
    /// The `0x00` ("common") extra header's declared CRC-16 over the WHOLE
    /// header, if the chain carried one. `None` for every level-1 archive in
    /// practice and for a level-2 one whose writer omitted it — which
    /// [`parse_level_2`] refuses, since that is its entire gate.
    common_crc: Option<u16>,
    /// The `0x42` ("MS-DOS size") extra header's `(compressed, original)`
    /// pair, if the chain carried one — Ruling S-W. **64-bit**, where the
    /// base header's own fields are `u32`, which is the entire reason the
    /// header exists: it is how a level-2 archive expresses an entry past
    /// 4 GiB. `delharc` lets it override BOTH base fields at level >= 2
    /// (`parser.rs:325-330`), and [`parse_level_2`] now does the same.
    ///
    /// Read from `buf[1..]` — the header INCLUDING its trailing next-length
    /// field — rather than from the name/path arms' `buf[..len - 2]`,
    /// because that is the slice `delharc` matches on for this arm. The two
    /// splits are different on purpose: `raw_pathname` reads names through
    /// `iter_extra`, which strips the counter, and `LhaHeader::read` reads
    /// this one through the full buffer, which does not.
    msdos_size: Option<(u64, u64)>,
    /// The running CRC-16/ARC over every byte walked, continued from the
    /// caller's seed, **with the common header's own two checksum bytes
    /// replaced by zeros** — the order and the substitution `delharc`'s
    /// `parser.rs:306-331` performs.
    crc: u16,
}

/// Walks an extra-header chain from `start`, per this module's gate
/// criterion 6. `None` — a rejected candidate, never an error — if the chain
/// runs off the end of the source, past [`MAX_EXTRA_CHAIN`], past `budget`
/// (the skip size for level 1, the declared total header size for level 2),
/// or through a header too small to carry its own terminator.
///
/// Each header is read into a buffer sized by that header's own `u16` length
/// field, so the largest allocation this function can be made to request is
/// 65,535 bytes regardless of what any other field says.
///
/// `crc_seed` is the running CRC-16/ARC over whatever the caller has already
/// walked (level 2's fixed base header); level 1 passes `0` and ignores the
/// result, because no level-1 gate uses it.
fn walk_extra_headers(
    src: &mut dyn SeekRead,
    start: u64,
    file_len: u64,
    first_len: u64,
    budget: u64,
    crc_seed: u16,
) -> Option<ExtraChain> {
    let mut chain = ExtraChain {
        total: 0,
        name: Vec::new(),
        path: Vec::new(),
        common_crc: None,
        msdos_size: None,
        crc: crc_seed,
    };
    let mut pos = start;
    let mut next = first_len;
    let mut buf: Vec<u8> = Vec::new();

    while next != 0 {
        if next < MIN_EXTRA_HEADER {
            return None;
        }
        chain.total = chain.total.checked_add(next)?;
        if chain.total > MAX_EXTRA_CHAIN || chain.total > budget {
            return None;
        }
        let end = pos.checked_add(next)?;
        if end > file_len {
            return None;
        }
        src.seek(SeekFrom::Start(pos)).ok()?;
        let len = usize::try_from(next).ok()?;
        buf.clear();
        buf.resize(len, 0);
        src.read_exact(&mut buf).ok()?;

        // `delharc`'s `ExtraHeaderIter` yields each header WITHOUT its
        // trailing two-byte "next length" field, identifier byte first —
        // `[EXT_HEADER_FILENAME, data @ ..]` in `lha.rs`'s `raw_pathname`.
        // This mirrors that split rather than inventing a second one.
        match &buf[..len - 2] {
            [delharc::header::ext::EXT_HEADER_FILENAME, data @ ..] => chain.name = data.to_vec(),
            [delharc::header::ext::EXT_HEADER_PATH, data @ ..] => chain.path = data.to_vec(),
            [delharc::header::ext::EXT_HEADER_COMMON, ..] => {
                // `delharc` raises "double common CRC-16 header" for a second
                // one rather than letting either win; a scanner refuses the
                // candidate for the same reason.
                if chain.common_crc.is_some() {
                    return None;
                }
                // The checksum covers the header with its OWN two bytes
                // zeroed, so they are lifted out and zeroed before this
                // header joins the running sum — `parser.rs:306-317`.
                //
                // The `get` cannot fail: `MIN_EXTRA_HEADER` is 3, so `buf`
                // always holds these two bytes. On a MINIMAL 3-byte common
                // header they are the trailing next-length field rather than
                // a checksum — **and `delharc` reads exactly the same two
                // bytes** (`data.get_mut(0..2)` over a `data` that includes
                // that field, `parser.rs:311-316`), then terminates the
                // chain on the zeroed value. Mirrored rather than corrected:
                // a divergence here is a divergence from the reader beside
                // us, which is worse than sharing its quirk.
                let crc_bytes = buf.get(1..3)?;
                chain.common_crc = Some(u16::from_le_bytes(crc_bytes.try_into().ok()?));
                buf[1] = 0;
                buf[2] = 0;
            }
            _ => {}
        }
        // **Ruling S-W**, and matched on the FULL buffer rather than the
        // name/path arms' `buf[..len - 2]`, because that is the slice
        // `delharc`'s own `LhaHeader::read` matches for this header
        // (`parser.rs:325-330`, `data.len() >= 16` over a `data` that
        // includes the trailing next-length field). Mirrored exactly,
        // overlap and all: diverging here is how `list` and `salvage` came
        // to report two different sizes for one healthy entry.
        if buf[0] == delharc::header::ext::EXT_HEADER_MSDOS_SIZE
            && let Some(data) = buf.get(1..len)
            && data.len() >= 16
        {
            chain.msdos_size = Some((
                u64::from_le_bytes(data[0..8].try_into().ok()?),
                u64::from_le_bytes(data[8..16].try_into().ok()?),
            ));
        }
        chain.crc = crc16_arc_continued(chain.crc, &buf[..len]);

        next = u64::from(u16::from_le_bytes(buf[len - 2..].try_into().ok()?));
        pos = end;
    }

    Some(chain)
}

/// Turns a gated [`EntryHeader`] into the [`Candidate`] the engine annotates.
fn read_candidate_at(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
    seen: &mut UngateableSightings,
) -> Option<Candidate> {
    let header = parse_header_at(src, offset, file_len, seen)?;

    let declared = header.declared_len;
    let available_len = match header.payload_start.checked_add(declared) {
        Some(end) if end <= file_len => None,
        // Either the declared end overflows `u64`, or it runs past the
        // source. Both mean the same thing to a reader: fewer bytes are
        // present than the header promises.
        _ => {
            let present = file_len.saturating_sub(header.payload_start);
            // `Some(n)` ALWAYS means `n < declared_len`, per the field's own
            // contract. A zero-length payload whose position is itself past
            // the end of the file would otherwise report `Some(0)` against a
            // declared `0` and claim a truncation that is not one.
            (present < declared).then_some(present)
        }
    };

    let mut meta = EntryMeta::file(header.name.clone());
    meta.size = Some(header.original_size);
    meta.compressed_size = Some(declared);
    meta.kind = if header.method.is_directory() {
        EntryKind::Dir
    } else {
        EntryKind::File
    };
    meta.mtime = header.mtime;
    meta.codec = Some(header.method.codec());

    // `payload_start` is computed ONCE, at discovery, with `checked_add`
    // throughout — see `Candidate::payload_start`'s own doc for why no
    // consumer may re-derive it from `offset`.
    //
    // `marked_deleted` is left at `Candidate::new`'s `false`: LHA has no
    // deleted flag at all — see `Candidate::marked_deleted`'s own doc for
    // why that is a plain `false` rather than an `Option`.
    Some(
        Candidate::new(offset, header.payload_start, meta)
            .with_declared_len(Some(declared))
            .with_verifier(Some(Verifier::Crc16(header.file_crc)))
            .with_available_len(available_len),
    )
}

/// A `Read` over `delharc`'s all-or-nothing [`Decoder::fill_buffer`],
/// bounded by the entry's own declared uncompressed length.
///
/// The bound is what makes `fill_buffer` usable at all: it fills the whole
/// slice it is handed or fails, so a caller that asked for more than the
/// entry contains would turn a complete decode into an error. `delharc`'s
/// own `LhaDecodeReader::read_all` does the identical `min` against
/// `original_size - output_length`; this is that bookkeeping without the
/// header re-parse `LhaDecodeReader::new` would also perform.
///
/// Each call decodes at most [`DECODE_CHUNK`] bytes — and, past
/// [`Self::fine_from`], exactly one — see [`DECODE_CHUNK`] and
/// [`write_payload`]'s second pass for why a recovery verb needs both.
struct DecodedReader<R> {
    decoder: DecoderAny<R>,
    /// Decoded bytes still owed before this entry's own declared
    /// uncompressed length is reached.
    remaining: u64,
    /// Decoded bytes produced so far, which is what [`Self::fine_from`] is
    /// compared against.
    produced: u64,
    /// The decoded position past which this reader decodes **one byte at a
    /// time** instead of [`DECODE_CHUNK`] at a time.
    ///
    /// `u64::MAX` — the ordinary case — means "never": chunked throughout.
    /// [`write_payload`]'s second pass sets it to however many bytes its
    /// FIRST pass managed, so the re-decode races through the part already
    /// known to work and then creeps through the part where the stream dies,
    /// which is the only way `fill_buffer`'s all-or-nothing contract lets a
    /// truncated entry give up its last few bytes.
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
            // Never step ACROSS the boundary: a chunk that straddled it
            // would take the fine-grained region's first bytes with it if it
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
/// to be seekable (it is a `&mut dyn Write` to a file, a pipe or
/// `io::sink()`).
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
/// A directory entry gets [`io::empty`] rather than a decoder: `-lhd-` is a
/// kind marker, not a compression method, so `delharc` has no decoder for it
/// and there is no payload to want one for. Every other recognised method
/// goes to the same [`DecoderAny`] `lha.rs`'s reader dispatches to.
fn decoded_reader<'a, R: io::Read + 'a>(
    method: Method,
    compressed: R,
    expected_len: u64,
) -> Box<dyn io::Read + 'a> {
    if method.is_directory() {
        return Box::new(io::empty());
    }
    decoded_reader_fine_from(method, compressed, expected_len, u64::MAX)
}

/// [`decoded_reader`] with an explicit [`DecodedReader::fine_from`] — only
/// [`write_payload`]'s second pass passes anything but `u64::MAX`.
fn decoded_reader_fine_from<'a, R: io::Read + 'a>(
    method: Method,
    compressed: R,
    expected_len: u64,
    fine_from: u64,
) -> Box<dyn io::Read + 'a> {
    if method.is_directory() {
        return Box::new(io::empty());
    }
    Box::new(DecodedReader {
        decoder: DecoderAny::new_from_compression(method.compression(), compressed),
        remaining: expected_len,
        produced: 0,
        fine_from,
    })
}

/// Decides [`SalvageStatus`] for one candidate by decoding its payload
/// through `delharc`'s own decoder and comparing the result against the
/// candidate's [`Verifier::Crc16`] via Task 1's shared
/// [`crate::salvage_verify::stream_verify`].
///
/// **Never returns `Err`, for any input.** Malformed, truncated and
/// genuinely I/O-failing input all fold into [`SalvageStatus::Partial`] or an
/// [`UnverifiedCause`], the discipline `zip_salvage.rs`'s, `arc_salvage.rs`'s
/// and `zoo_salvage.rs`'s own `verify_candidate` document at length: an `Err`
/// out of `verify` aborts the WHOLE run and discards every entry already
/// recovered, which is the one thing this verb exists not to do. The
/// `Result` in the signature is the trait's, kept so a scanner CAN report a
/// genuine whole-run fault; this implementation has none to report.
///
/// **There is no entry-size ceiling here, and that is deliberate** — see
/// [`LhaSalvage::max_whole_entry`]. Nothing in this function is sized from a
/// header field: the compressed side is a `take` and the decoded side a
/// fixed window, so there is no allocation for a ceiling to stand in front
/// of. Adding one "for symmetry" with ARC and ZOO would reintroduce exactly
/// what ZOO's fix round 1 removed — an entry refused, and therefore written
/// nowhere, for a cost its own method never pays.
fn verify_candidate(src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
    // The payload is PROVABLY incomplete — nothing needs decoding to know
    // the answer. Sits above the method dispatch for the reason
    // `zip_salvage.rs`'s own `verify_candidate` gives: a truncated payload
    // under an undecodable method is still truncated, and `Partial` (proven
    // missing) is a stronger claim than `Unverified` (nothing attempted).
    if candidate.available_len.is_some() {
        return Ok(SalvageStatus::Partial);
    }
    let Some(declared_len) = candidate.declared_len else {
        // Unreachable in practice: `read_candidate_at` always reports one.
        // Kept as the honest fallback rather than a `Complete` this scanner
        // never means — every LHA header carries a CRC-16.
        return Ok(SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength));
    };
    let Some(Verifier::Crc16(expected_crc)) = candidate.verifier else {
        // Likewise unreachable: `read_candidate_at` gives every LHA
        // candidate a `Verifier::Crc16`, because the format mandates one.
        // `NoDeclaredLength` is the NEAREST cause this enum offers and not
        // an accurate one — a length was declared; a checksum was not — and
        // saying so is better than answering `Complete`, which would claim
        // the format has no checksum to offer when LHA's whole point here is
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
    if !method.decodable() && !method.is_directory() {
        // The archive is fine; this build has no decoder for that method
        // (`-lhx-`). `Unverified`, never `Complete` and never `Partial` —
        // nothing was attempted, so nothing failed.
        return Ok(SalvageStatus::Unverified(
            UnverifiedCause::UndecodableMethod,
        ));
    }

    let expected_len = candidate.meta.size.unwrap_or(0);
    if src.seek(SeekFrom::Start(candidate.payload_start)).is_err() {
        return Ok(SalvageStatus::Partial);
    }
    let compressed = src.take(declared_len);
    let decoded = decoded_reader(method, compressed, expected_len);

    Ok(crate::salvage_verify::stream_verify(
        decoded,
        expected_len,
        &Verifier::Crc16(expected_crc),
    ))
}

/// Reads one entry's stored payload and writes its RECOVERED (decoded) bytes
/// to `out`. Returns whether the decode reached the entry's own declared
/// length ([`EntryMeta::size`]) — `entries.rs`'s own signal for
/// `PartialCause`, matching `zip_salvage.rs`'s, `arc_salvage.rs`'s and
/// `zoo_salvage.rs`'s `write_payload` exactly.
///
/// Uses [`SalvagedEntry::payload_start`] directly, computed once by
/// [`read_candidate_at`] at discovery — see that field's own doc for why a
/// consumer must never re-derive a payload's location from `offset`.
///
/// # What is bounded, and what needs no bound
///
/// The compressed read is bounded by what the SOURCE actually holds
/// (`available` below, from a fresh `seek(End(0))`), never by
/// `compressed_len` alone, so a truncated entry's genuine surviving prefix
/// still reaches the decoder and is written rather than the whole read
/// failing and nothing being written — `arc_salvage.rs`'s fix rounds 1 and 2,
/// inherited rather than rediscovered. Nothing else needs a bound: the
/// decoded side streams through [`stream_bounded_copy`]'s fixed window, so
/// unlike ARC's and ZOO's own writers there is no `org_size`-shaped
/// allocation for a ceiling to sit in front of.
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
    // relies on: it probes every slot with a codec-less entry and a path
    // that does not exist.
    let Some(method) = method_for_codec(entry.meta.codec) else {
        return Err(Error::Unsupported(format!(
            "entry `{}` carries codec {:?}, which this build's LHA salvage writer does not \
             decode (every identifier outside the `-lh*-`/`-lz*-` table is already refused at \
             discovery, so this is a backstop rather than a reachable answer)",
            entry.meta.name, entry.meta.codec
        )));
    };
    if !method.decodable() && !method.is_directory() {
        // Reachable only through this function's own `pub` door: through
        // `entries::salvage` such an entry is `Unverified` and
        // `place_salvaged_file` never writes one. `Error::Unsupported` is
        // what `place_salvaged_file` maps to `SkippedNotBuiltIn`, which is
        // the honest disposition — this build has no decoder, so there is
        // nothing recovered to write.
        return Err(Error::Unsupported(format!(
            "entry `{}` uses LHA compression method `{}`, which this build cannot decode \
             (delharc compiled with `std`, `lh1`, `lz` — no `lhx`)",
            entry.meta.name,
            String::from_utf8_lossy(method.identifier()),
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
    // `stream_bounded_copy` goes on to report against a declared
    // uncompressed size small enough that a partial decode still satisfies
    // it (`arc_salvage.rs`'s fix round 2, NEW-1 — a message must not
    // contradict the reason the entry is `Partial` in the first place).
    let truncated = readable_len < compressed_len;

    let expected = entry.meta.size.unwrap_or(0);
    let mut counting = CountingWriter {
        inner: out,
        written: 0,
    };
    let completed = {
        let decoded = decoded_reader(method, (&mut f).take(readable_len), expected);
        stream_bounded_copy(decoded, expected, &mut counting)?
    };

    if !completed && counting.written < expected {
        recover_the_last_chunk(&mut f, entry, method, readable_len, expected, &mut counting)?;
    }

    Ok(completed && !truncated)
}

/// The second pass over a payload the first one could not finish: re-decodes
/// what already worked, then creeps through the region where the stream
/// dies, one byte at a time, appending whatever more it can reach.
///
/// # Why a second pass exists at all
///
/// `delharc`'s [`Decoder::fill_buffer`] is all-or-nothing — it fills the
/// whole slice it is handed or fails, and a failure says nothing about how
/// much of that slice it had already written, so those bytes cannot be used.
/// On a healthy archive that costs nothing. On a TRUNCATED entry it is the
/// difference between recovering a prefix and recovering nothing: the last
/// [`DECODE_CHUNK`] bytes requested are simply lost, **and for any entry
/// smaller than one chunk that is the entire payload**. Measured before this
/// existed, on a 144-byte stored entry cut 30 payload bytes short:
/// `NAME.partial` held 0 bytes, at exit 4, for an entry whose first **114**
/// bytes were sitting in the file (`got 0 of the 114 that are in the file`,
/// which is what the test prints when the second pass is disabled). That is
/// `arc_salvage.rs`'s fix rounds 1 and 2 recurring through a different
/// decoder API, and it is the one thing this verb exists not to do.
///
/// # Why it is a second pass rather than a smaller chunk
///
/// A smaller chunk bounds the loss but never removes it, because the final
/// request is always `min(chunk, remaining)` — an entry shorter than one
/// chunk is one request either way. Restarting is the only way to get finer
/// granularity out of an API with no partial-result channel, and restarting
/// from the beginning is the only way to reach a given decoded position: LHA
/// is a sliding-window format with no entry-internal seek point.
///
/// The cost is bounded and falls only on the failure path: one extra decode
/// of the bytes already recovered (in ordinary [`DECODE_CHUNK`] steps, which
/// is what [`DecodedReader::fine_from`] is for), plus at most one chunk's
/// worth of single-byte steps. A healthy entry never reaches this function.
///
/// Errors from `out` still propagate — a destination that cannot be written
/// is not this entry's problem, it is the run's — while a decode that fails
/// again is the expected outcome and simply ends the recovery.
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
    let mut decoded =
        decoded_reader_fine_from(method, (&mut *f).take(readable_len), expected, already);
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

/// Runs [`LhaSalvage`] over `src` and annotates the result — the whole
/// scanner, matching `zip_salvage.rs`'s `salvage_zip`, `arc_salvage.rs`'s
/// `salvage_arc` and `zoo_salvage.rs`'s `salvage_zoo` entry points exactly
/// (`entries.rs`'s `salvage_scan` dispatches to all four the same way). Like
/// ARC and ZOO and unlike zip there is no second index to reconcile against:
/// LHA has no central directory, no entry count and no trailer at all, so the
/// raw scan is the only source there is.
pub fn salvage_lha(src: &mut dyn SeekRead, policy: &SalvagePolicy) -> Result<SalvageOutcome> {
    let mut scanner = LhaSalvage::new();
    let outcome = salvage_all(&mut scanner, src, policy)?;

    // **Ruling S-V.** A run that recovered NOTHING while recognising a
    // header shape it cannot gate must not fall through to the engine's
    // empty-outcome path, which the CLI reports as `the scan found nothing
    // recoverable in this archive` at exit 5 — a claim about the ARCHIVE
    // where the truth is a claim about the BUILD. `Error::Unsupported` is
    // exit 3, the code `entries.rs`'s own `salvage_scan` already spends on
    // exactly this distinction.
    //
    // **Only when nothing came back**, and that condition is load-bearing
    // rather than defensive: an `Err` out of here discards every entry the
    // run recovered, which is the one thing this verb exists not to do. A
    // MIXED archive — some headers gateable, some not — therefore still
    // reports what it recovered, at its ordinary exit code. That is an
    // incompleteness rather than a contradiction: nothing false is claimed,
    // where exit 5 on a healthy file was. Saying more would need a note
    // channel [`SalvageOutcome`] does not have, and no LHA writer mixes
    // header levels within one archive.
    if outcome.entries.is_empty() && scanner.seen.any() {
        return Err(Error::Unsupported(scanner.seen.refusal()));
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::super::crc::crc16_arc;
    use super::super::lha::write_level1_header;
    use super::*;

    const SAMPLE_LZH: &[u8] = include_bytes!("../../fixtures/legacy/sample.lzh");

    fn scan(bytes: &[u8]) -> SalvageOutcome {
        salvage_lha(&mut Cursor::new(bytes.to_vec()), &SalvagePolicy::default())
            .expect("a salvage scan must not error over any input")
    }

    /// One stored (`-lh0-`) level-1 entry plus the optional end-of-archive
    /// marker, built through the PRODUCTION header writer — the same
    /// discipline `lha.rs`'s own `build_named_entry_lha` follows, and for the
    /// same reason: a second hand-rolled copy of the level-1 layout in a
    /// test module is how a fixture and its expectation drift apart.
    fn build_level1(name: &[u8], method: &[u8; 5], content: &[u8]) -> Vec<u8> {
        let size = content.len() as u32;
        let mut out = Vec::new();
        write_level1_header(&mut out, method, name, size, size, crc16_arc(content), 0);
        out.extend_from_slice(content);
        out.push(0);
        out
    }

    /// A LEVEL-0 header, the one shape this project has no production writer
    /// for.
    ///
    /// The layout is this module's own doc table, and it is checked rather
    /// than trusted:
    /// [`the_header_geometry_agrees_with_delharcs_own_parser`] parses every
    /// archive this helper builds with `delharc`'s `LhaHeader::read` and
    /// requires the two to agree field for field and byte for byte on where
    /// the payload starts. A builder and a parser written by one author
    /// agreeing with each other proves nothing; `delharc` is the third party
    /// that makes it evidence.
    fn build_level0(name: &[u8], method: &[u8; 5], content: &[u8]) -> Vec<u8> {
        let size = content.len() as u32;
        let mut counted = Vec::new();
        counted.extend_from_slice(method);
        counted.extend_from_slice(&size.to_le_bytes());
        counted.extend_from_slice(&size.to_le_bytes());
        counted.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        counted.push(0x20); // MS-DOS ARCHIVE attribute
        counted.push(0); // header level
        counted.push(name.len() as u8);
        counted.extend_from_slice(name);
        counted.extend_from_slice(&crc16_arc(content).to_le_bytes());
        assert_eq!(counted.len(), LEVEL0_HEADER_OVERHEAD + name.len());

        let mut out = Vec::new();
        out.push(counted.len() as u8);
        out.push(checksum_of(&counted));
        out.extend_from_slice(&counted);
        out.extend_from_slice(content);
        out.push(0);
        out
    }

    /// A LEVEL-2 header (Ruling S-U), the shape with no length byte, no
    /// checksum byte, no filename in the base header and a mandatory
    /// `EXT_HEADER_COMMON` CRC-16 over the whole thing.
    ///
    /// Layout from this module's own level-2 table, and — like the level-0
    /// builder — checked rather than trusted:
    /// [`the_header_geometry_agrees_with_delharcs_own_parser`] parses
    /// everything this builds with `delharc`'s `LhaHeader::read` too and
    /// requires byte-exact agreement on where the payload starts. A builder
    /// and a parser written by one author agreeing with each other proves
    /// nothing; `delharc` is the third party that makes it evidence.
    ///
    /// `refresh_common_crc` decides whether the common header's checksum is
    /// left correct — `false` builds the crafted defect whose ONLY fault is
    /// that checksum, which is what makes Step 5's level-2 falsification
    /// about the CRC rather than about some other malformation.
    fn build_level2_with(
        name: &[u8],
        method: &[u8; 5],
        content: &[u8],
        refresh_common_crc: bool,
    ) -> Vec<u8> {
        // `0x00` + the CRC-16 + the next header's length.
        let common_len = 1 + 2 + 2;
        // `0x01` + the name + the next header's length (zero: chain ends).
        let name_len = 1 + name.len() + 2;
        let total = LEVEL2_BASE_LEN + common_len + name_len;

        let mut header = Vec::new();
        header.extend_from_slice(&(total as u16).to_le_bytes()); // H+0
        header.extend_from_slice(method); // H+2
        header.extend_from_slice(&(content.len() as u32).to_le_bytes()); // H+7
        header.extend_from_slice(&(content.len() as u32).to_le_bytes()); // H+11
        header.extend_from_slice(&1_000_000_000u32.to_le_bytes()); // H+15, Unix
        header.push(0x20); // H+19, reserved
        header.push(2); // H+20, level
        header.extend_from_slice(&crc16_arc(content).to_le_bytes()); // H+21
        header.push(b'U'); // H+23, OS-TYPE
        header.extend_from_slice(&(common_len as u16).to_le_bytes()); // H+24
        assert_eq!(header.len(), LEVEL2_BASE_LEN);

        header.push(delharc::header::ext::EXT_HEADER_COMMON);
        header.extend_from_slice(&0u16.to_le_bytes()); // the CRC, zeroed
        header.extend_from_slice(&(name_len as u16).to_le_bytes());
        header.push(delharc::header::ext::EXT_HEADER_FILENAME);
        header.extend_from_slice(name);
        header.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(header.len(), total);

        // Over the WHOLE header with the common header's own two bytes still
        // zero, which is exactly the state they are in right now.
        let crc = if refresh_common_crc {
            crc16_arc(&header)
        } else {
            crc16_arc(&header).wrapping_add(1)
        };
        header[LEVEL2_BASE_LEN + 1..LEVEL2_BASE_LEN + 3].copy_from_slice(&crc.to_le_bytes());

        let mut out = header;
        out.extend_from_slice(content);
        out.push(0); // end-of-archive marker
        out
    }

    fn build_level2(name: &[u8], method: &[u8; 5], content: &[u8]) -> Vec<u8> {
        build_level2_with(name, method, content, true)
    }

    /// A level-2 archive whose chain carries an `EXT_HEADER_MSDOS_SIZE`
    /// (`0x42`) header declaring the REAL lengths, while the base header's
    /// own `u32` fields declare `base_lie` — Ruling S-W's fixture, and the
    /// review's own numbers.
    ///
    /// The `0x42` payload is two little-endian `u64`s, compressed first, and
    /// the whole header goes inside the common CRC exactly like every other.
    fn build_level2_with_msdos_size(name: &[u8], content: &[u8], base_lie: u32) -> Vec<u8> {
        let common_len = 1 + 2 + 2;
        let size_len = 1 + 16 + 2;
        let name_len = 1 + name.len() + 2;
        let total = LEVEL2_BASE_LEN + common_len + size_len + name_len;

        let mut header = Vec::new();
        header.extend_from_slice(&(total as u16).to_le_bytes());
        header.extend_from_slice(b"-lh0-");
        header.extend_from_slice(&base_lie.to_le_bytes());
        header.extend_from_slice(&base_lie.to_le_bytes());
        header.extend_from_slice(&1_000_000_000u32.to_le_bytes());
        header.push(0x20);
        header.push(2);
        header.extend_from_slice(&crc16_arc(content).to_le_bytes());
        header.push(b'U');
        header.extend_from_slice(&(common_len as u16).to_le_bytes());
        assert_eq!(header.len(), LEVEL2_BASE_LEN);

        header.push(delharc::header::ext::EXT_HEADER_COMMON);
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&(size_len as u16).to_le_bytes());

        header.push(delharc::header::ext::EXT_HEADER_MSDOS_SIZE);
        header.extend_from_slice(&(content.len() as u64).to_le_bytes());
        header.extend_from_slice(&(content.len() as u64).to_le_bytes());
        header.extend_from_slice(&(name_len as u16).to_le_bytes());

        header.push(delharc::header::ext::EXT_HEADER_FILENAME);
        header.extend_from_slice(name);
        header.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(header.len(), total);

        let crc = crc16_arc(&header);
        header[LEVEL2_BASE_LEN + 1..LEVEL2_BASE_LEN + 3].copy_from_slice(&crc.to_le_bytes());

        let mut out = header;
        out.extend_from_slice(content);
        out.push(0);
        out
    }

    /// A LEVEL-3 header — the shape this scanner deliberately does not parse
    /// (Ruling S-V), built only so the refusal can be tested against an
    /// archive `delharc` genuinely reads.
    ///
    /// Layout from `delharc`'s own parser, which is all this builder needs
    /// to be right about: the first two bytes are the mandated `4, 0`
    /// (`parser.rs:259-264`), the base header is the level-0/1 one through
    /// OS-TYPE, and then TWO `u32`s — the whole header's length and the
    /// first extension header's — where level 2 has one `u16`
    /// (`parser.rs:260-262`). Extension headers use 4-byte counters at this
    /// level, so the chain's terminator is a `u32` zero.
    /// A level-2 archive whose extension-header chain starts at the
    /// FILENAME header, so the COMMON header — the one carrying the header
    /// CRC this scanner gates on — is absent. `delharc` reads it; this
    /// scanner refuses it by name at `Error::Unsupported`.
    ///
    /// Lifted out of `a_level_2_header_with_no_common_extension_header_is_
    /// refused_by_name` in Task 7's fix round (F2) so the whole-container
    /// control in `damage_catalogue::the_header_levels_this_scanner_refuses_
    /// are_ones_the_reader_lists` can run over the identical bytes rather
    /// than a second hand-built approximation of them.
    pub(super) fn build_level2_without_common_header() -> Vec<u8> {
        let bytes = build_level2(b"nocrc.txt", b"-lh0-", b"payload");
        // Point the base header's first-extra-header field straight at the
        // FILENAME header, skipping the common one, and shorten the declared
        // total to match the chain that remains.
        let common_len = 5usize;
        let mut trimmed = bytes[..LEVEL2_BASE_LEN].to_vec();
        trimmed.extend_from_slice(&bytes[LEVEL2_BASE_LEN + common_len..]);
        let name_len = 1 + b"nocrc.txt".len() + 2;
        let total = LEVEL2_BASE_LEN + name_len;
        trimmed[HEADER_LEN_I..HEADER_LEN_I + 2].copy_from_slice(&(total as u16).to_le_bytes());
        trimmed[LEVEL2_FIRST_EXTRA_I..LEVEL2_FIRST_EXTRA_I + 2]
            .copy_from_slice(&(name_len as u16).to_le_bytes());
        trimmed
    }

    pub(super) fn build_level3(name: &[u8], content: &[u8]) -> Vec<u8> {
        let name_len = 1 + name.len() + 4;
        let total = 32 + name_len;

        let mut out = Vec::new();
        out.push(4); // word size, mandated
        out.push(0); // and the byte after it, likewise
        out.extend_from_slice(b"-lh0-");
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&1_000_000_000u32.to_le_bytes());
        out.push(0x20); // reserved
        out.push(3); // header level
        out.extend_from_slice(&crc16_arc(content).to_le_bytes());
        out.push(b'U'); // OS-TYPE
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&(name_len as u32).to_le_bytes());
        assert_eq!(out.len(), 32);

        out.push(delharc::header::ext::EXT_HEADER_FILENAME);
        out.extend_from_slice(name);
        out.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(out.len(), total);

        out.extend_from_slice(content);
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// A level-1 entry carrying a real extra-header chain: a `0x02` path
    /// header and a `0x01` filename header, the two `lha.rs`'s `raw_pathname`
    /// consults. The base header's own filename field holds `fallback`, which
    /// the `0x01` header must override — so a scanner that ignored the chain
    /// would report the wrong name AND the wrong payload position, and this
    /// one fixture catches both.
    fn build_level1_with_extras(
        fallback: &[u8],
        path: &[u8],
        ext_name: &[u8],
        content: &[u8],
    ) -> Vec<u8> {
        // Each extra header is `1 + data + 2` bytes; the trailing `u16` is
        // the NEXT header's length, and the chain ends with a zero.
        let path_header_len = 1 + path.len() + 2;
        let name_header_len = 1 + ext_name.len() + 2;
        let extra_total = path_header_len + name_header_len;

        let mut extras = Vec::new();
        extras.push(delharc::header::ext::EXT_HEADER_PATH);
        extras.extend_from_slice(path);
        extras.extend_from_slice(&(name_header_len as u16).to_le_bytes());
        extras.push(delharc::header::ext::EXT_HEADER_FILENAME);
        extras.extend_from_slice(ext_name);
        extras.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(extras.len(), extra_total);

        let size = content.len() as u32;
        let mut out = Vec::new();
        // Level 1's size field is the SKIP size: the payload plus the whole
        // extra-header chain.
        write_level1_header(
            &mut out,
            b"-lh0-",
            fallback,
            size + extra_total as u32,
            size,
            crc16_arc(content),
            0,
        );
        // `write_level1_header` emits a zero `first_header_len`; the chain
        // this fixture carries has to be declared in its place.
        let at = out.len() - 2;
        out[at..].copy_from_slice(&(path_header_len as u16).to_le_bytes());
        // And the header checksum covers that field, so it is recomputed.
        let counted_len = usize::from(out[HEADER_LEN_I]);
        out[HEADER_CSUM_I] = checksum_of(&out[METHOD_I..METHOD_I + counted_len]);

        out.extend_from_slice(&extras);
        out.extend_from_slice(content);
        out.push(0);
        out
    }

    // -------------------------------------------------------------------
    // The anti-vacuity pair (Step 1)
    // -------------------------------------------------------------------

    /// A small linear congruential generator, not the `rand` crate — the
    /// corpus must be byte-identical on every machine and in CI. Same
    /// constants (Knuth & Lewis, via Numerical Recipes) `zip_salvage.rs`,
    /// `arc_salvage.rs` and `zoo_salvage.rs` use, for the same reason:
    /// nothing cryptographic is needed, only enough uniformity to make a
    /// coincidence rare.
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

    /// Fixed offsets, each with lots of room after it, where only the five
    /// METHOD bytes are forced — the header length, the checksum, the level,
    /// the name length and everything else stays whatever the LCG produced.
    ///
    /// # How much this gate is carrying, and why the seeding is mandatory
    ///
    /// **A five-byte ASCII method identifier is a far stronger anchor than
    /// either sibling scanner's.** Eleven accepted spellings over a five-byte
    /// window is `11 / 2^40` per position: about **one hit per 93 GiB** of
    /// uniform random bytes. ZOO's four-byte tag is one per 4 GiB — 23 times
    /// more often — and ARC's one-byte marker plus a method in `1..=11` is
    /// roughly one per 8 KiB, twelve million times more often.
    ///
    /// So a 1 MiB noise corpus contains an incidental LHA method identifier
    /// with probability about one in a hundred thousand, and an unseeded
    /// "salvage over random bytes finds nothing" test would be proving that
    /// the anchor is rare, not that the criteria BEHIND it work. Seeding the
    /// identifiers directly is what makes this corpus a test of the gate.
    const SEEDED_METHOD_OFFSETS: [usize; 6] = [65_536, 196_608, 344_064, 491_520, 638_976, 786_432];

    /// A seventh splice, distinct from the bare-identifier ones above: a
    /// complete, otherwise gate-clearing level-1 LHA archive whose ONLY
    /// defect is its header checksum byte.
    ///
    /// This is what ties Step 5's falsification of the checksum gate to a
    /// SPECIFIC position. With criteria 1-3 as strong as they are, deleting
    /// the checksum check would otherwise still find nothing in noise — the
    /// gate would go quietly vacuous with every test green, which is the
    /// exact failure mode this project keeps rediscovering.
    const CHECKSUM_ONLY_DEFECT_OFFSET: usize = 500_000;

    /// The level-2 twin of [`CHECKSUM_ONLY_DEFECT_OFFSET`], added with Ruling
    /// S-U: level 2 has its own criterion 4 (the `EXT_HEADER_COMMON` CRC-16),
    /// so it needs its own crafted splice, or disabling THAT check would go
    /// unnoticed exactly the way disabling the level-0/1 one would have
    /// without the splice above.
    const LEVEL2_CRC_ONLY_DEFECT_OFFSET: usize = 700_000;

    fn checksum_only_defect() -> Vec<u8> {
        let mut bytes = build_level1(b"OK.TXT", b"-lh0-", b"payload");
        // Every other criterion still holds; only the checksum is wrong.
        bytes[HEADER_CSUM_I] = bytes[HEADER_CSUM_I].wrapping_add(1);
        bytes
    }

    fn level2_crc_only_defect() -> Vec<u8> {
        build_level2_with(b"OK2.TXT", b"-lh0-", b"payload", false)
    }

    fn noise_with_seeded_methods(len: usize) -> Vec<u8> {
        let mut noise = deterministic_noise(len);
        for &at in &SEEDED_METHOD_OFFSETS {
            noise[at..at + 5].copy_from_slice(Method::Lh5.identifier());
        }
        for (at, defect) in [
            (CHECKSUM_ONLY_DEFECT_OFFSET, checksum_only_defect()),
            (LEVEL2_CRC_ONLY_DEFECT_OFFSET, level2_crc_only_defect()),
        ] {
            noise[at..at + defect.len()].copy_from_slice(&defect);
        }
        noise
    }

    /// The negative double for the whole feature: a scanner that reported
    /// every method-identifier sighting as an entry would be worse than no
    /// scanner at all.
    #[test]
    fn lha_salvage_over_random_bytes_finds_nothing() {
        let noise = noise_with_seeded_methods(1 << 20); // 1 MiB, fixed seed
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
    /// contain no method identifier at all — proving nothing about the
    /// validation gate. This asserts the gate is what rejects the hits, not
    /// their absence.
    #[test]
    fn the_lha_noise_corpus_really_does_contain_the_method_identifier() {
        let noise = noise_with_seeded_methods(1 << 20);
        let hits = noise
            .windows(5)
            .filter(|w| Method::from_identifier(&[w[0], w[1], w[2], w[3], w[4]]).is_some())
            .count();
        // The six deliberately seeded identifiers, plus one for each of the
        // two spliced archives. `>=` rather than `==`: this does not also
        // assert the LCG produces no INCIDENTAL identifier of its own, which
        // would only be one more coincidence for the gate to reject.
        let seeded = SEEDED_METHOD_OFFSETS.len() + 2;
        assert!(
            hits >= seeded,
            "expected at least the {seeded} deliberately placed identifiers, found {hits}"
        );
    }

    /// Isolates `CHECKSUM_ONLY_DEFECT_OFFSET`'s own archive to prove it
    /// clears every OTHER criterion — so deleting the checksum check is
    /// really what the falsification in the task report exercises, not some
    /// other defect in the crafted bytes.
    #[test]
    fn the_checksum_only_defect_is_rejected_by_the_checksum_alone() {
        assert!(
            scan(&checksum_only_defect()).entries.is_empty(),
            "a header whose own checksum does not reproduce must be rejected"
        );
        // The identical archive with the checksum left correct IS found,
        // which is what makes the assertion above about the checksum byte.
        let healthy = build_level1(b"OK.TXT", b"-lh0-", b"payload");
        let out = scan(&healthy);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].meta.name, "OK.TXT");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    // -------------------------------------------------------------------
    // The positive complement: a scanner that always returned `Ok(None)`
    // would also pass the anti-vacuity pair trivially.
    // -------------------------------------------------------------------

    /// The externally-underwritten fixture: `sample.lzh` is hand-built from
    /// the level-1 layout and then independently verified by `lhasa 0.6.0`
    /// (`lha v`/`t`/`x`), an implementation sharing no code with `delharc`.
    /// See `fixtures/legacy/MANIFEST.md`.
    #[test]
    fn salvage_recovers_both_entries_of_the_externally_verified_fixture() {
        let out = scan(SAMPLE_LZH);
        assert_eq!(out.entries.len(), 2);
        assert_eq!(out.entries[0].meta.name, "sample/hello.txt");
        assert_eq!(out.entries[1].meta.name, "sample/sub/b.bin");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
        assert_eq!(out.entries[1].status, SalvageStatus::Intact);
        assert_eq!(out.entries[0].meta.size, Some(6));
        assert_eq!(out.entries[1].meta.size, Some(5));
    }

    /// The motivating damage: LHA has no index, so `lha.rs`'s reader reaches
    /// entry 2 only by having parsed entry 1. Corrupt entry 1's header and
    /// the ordinary reader stops there; the scanner finds entry 2 anyway.
    ///
    /// Asserted against the ordinary reader in the same test rather than
    /// claimed in prose — otherwise this is only a test that the scanner
    /// finds an entry.
    #[test]
    fn an_entry_behind_a_destroyed_header_is_still_recovered() {
        let mut bytes = SAMPLE_LZH.to_vec();
        // Wipe the first header's length byte and its checksum: the first
        // entry is now unreachable and so, for any forward reader, is
        // everything behind it.
        bytes[HEADER_LEN_I] = 0xFF;
        bytes[HEADER_CSUM_I] = 0xFF;

        let entries = super::super::lha::test_archives::read_entry_names(&bytes);
        assert!(
            entries.is_err() || entries.as_ref().unwrap().is_empty(),
            "the ordinary reader must NOT be able to walk this archive; got {entries:?}"
        );

        let out = scan(&bytes);
        let names: Vec<&str> = out.entries.iter().map(|e| e.meta.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["sample/sub/b.bin"],
            "the surviving entry is exactly what salvage exists to hand back"
        );
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    /// A LEVEL-0 header — the one shape with no production writer in this
    /// tree — is recognised, and its geometry (no OS-TYPE byte, no extra
    /// headers, so a payload two bytes earlier than a level-1 header of the
    /// same name would put it) is right.
    #[test]
    fn a_level_0_header_is_recognised() {
        let bytes = build_level0(b"OLD.TXT", b"-lh0-", b"level zero payload");
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].meta.name, "OLD.TXT");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    /// **Ruling S-U, the positive half.** A healthy level-2 archive is
    /// recovered. Before the ruling this scanner refused every level-2
    /// header, so `stuffr list` printed the entry and `stuffr salvage
    /// --list` answered "the scan found nothing recoverable" at exit 5 — one
    /// tool contradicting itself across two lines, on an UNDAMAGED file.
    #[test]
    fn a_healthy_level_2_archive_is_recovered() {
        let bytes = build_level2(b"level2.txt", b"-lh0-", b"level two payload");
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1, "{:?}", out.entries);
        assert_eq!(out.entries[0].meta.name, "level2.txt");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
        assert_eq!(out.entries[0].meta.codec, Some(FormatId::new("lha-lh0")));
        assert_eq!(
            out.entries[0].meta.mtime,
            Some(UNIX_EPOCH + Duration::from_secs(1_000_000_000)),
            "a level-2 timestamp is Unix seconds, not an MS-DOS word — reading one as the \
             other is a silent decades-wide error, never a parse failure"
        );
    }

    /// **Ruling S-U, the recovery half.** The same damage the level-1
    /// reproducer uses, applied to level 2: destroy the first header's own
    /// declared size and the entry behind it is unreachable to any forward
    /// reader, while the scanner finds the second header on its own.
    #[test]
    fn a_level_2_archive_with_a_destroyed_first_header_still_salvages_the_rest() {
        let first = build_level2(b"gone.txt", b"-lh0-", b"first payload");
        let second = build_level2(b"survivor.txt", b"-lh0-", b"second payload");
        let mut bytes = first[..first.len() - 1].to_vec();
        bytes.extend_from_slice(&second);
        // Wipe the first header's `u16` total size. Its method identifier is
        // untouched, so the scan still SEES it and the gate still rejects it.
        bytes[HEADER_LEN_I] = 0xFF;
        bytes[HEADER_LEN_I + 1] = 0xFF;

        let out = scan(&bytes);
        let names: Vec<&str> = out.entries.iter().map(|e| e.meta.name.as_str()).collect();
        assert_eq!(names, vec!["survivor.txt"], "{names:?}");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    /// **The level-2 arm of Step 5's falsification**, and the reason
    /// `LEVEL2_CRC_ONLY_DEFECT_OFFSET` exists: this archive clears every
    /// other level-2 criterion and fails only on the `EXT_HEADER_COMMON`
    /// CRC-16, so deleting that comparison turns it into a phantom in the
    /// noise corpus.
    #[test]
    fn the_level_2_crc_only_defect_is_rejected_by_the_common_crc_alone() {
        assert!(
            scan(&level2_crc_only_defect()).entries.is_empty(),
            "a level-2 header whose common CRC-16 does not reproduce must be rejected"
        );
        // The identical archive with the CRC left correct IS found, which is
        // what makes the assertion above about the checksum.
        let healthy = build_level2_with(b"OK2.TXT", b"-lh0-", b"payload", true);
        assert_eq!(scan(&healthy).entries.len(), 1);
    }

    /// The one place this scanner is deliberately STRICTER than `delharc`:
    /// a level-2 header carrying no common extension header at all parses
    /// fine for the reader and is refused here, because there is then no
    /// checksum to tell a real header from five coincidental bytes.
    ///
    /// **Ruling S-V changed what the refusal SAYS, not whether it happens.**
    /// The strictness is upheld; what was wrong was answering it with the
    /// engine's empty outcome, which the CLI reports as `the scan found
    /// nothing recoverable in this archive` at exit 5 — a claim about the
    /// archive, on a file `stuffr list` reads at exit 0. It is now
    /// `Error::Unsupported` (exit 3), naming the level and what is missing.
    #[test]
    fn a_level_2_header_with_no_common_extension_header_is_refused_by_name() {
        let trimmed = build_level2_without_common_header();

        // The CONTROL: `delharc` — the parser `stuffr list` reads through —
        // accepts this archive, which is what makes the refusal below a
        // deliberate narrowing rather than a shared limitation.
        assert!(
            delharc::header::LhaHeader::read(&mut Cursor::new(trimmed.clone()))
                .expect("delharc accepts a level-2 header with no common CRC")
                .is_some()
        );
        let err = salvage_lha(&mut Cursor::new(trimmed.clone()), &SalvagePolicy::default())
            .expect_err(
                "a recognised header shape with no gate must be NAMED, never answered with the \
             empty outcome the CLI reports as `nothing recoverable` at exit 5",
            );
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        let message = err.to_string();
        assert!(message.contains("level-2"), "{message}");
        assert!(message.contains("common"), "{message}");
        assert!(
            message.contains("stuffr list"),
            "the message must say the archive itself may be fine: {message}"
        );
    }

    /// **Ruling S-V's other half.** A healthy LEVEL-3 archive: `delharc`
    /// reads it, so `stuffr list` prints the entry at exit 0, and this
    /// scanner has no parser for it. Before the ruling that combination
    /// produced `the scan found nothing recoverable in this archive` at exit
    /// 5 — the tool contradicting itself on a file with nothing wrong with
    /// it, which is precisely the defect Ruling S-U named and closed for one
    /// population only.
    #[test]
    fn a_level_3_header_is_refused_by_name_rather_than_reported_as_an_empty_archive() {
        let bytes = build_level3(b"level3.txt", b"level three payload");

        // The CONTROL, and the whole point: `delharc` — the parser
        // `stuffr list` reads through — accepts this archive.
        assert!(
            delharc::header::LhaHeader::read(&mut Cursor::new(bytes.clone()))
                .expect("delharc reads level 3")
                .is_some()
        );

        let err = salvage_lha(&mut Cursor::new(bytes), &SalvagePolicy::default()).expect_err(
            "a level-3 archive the reader handles must not be reported as holding nothing",
        );
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        let message = err.to_string();
        assert!(message.contains("level-3"), "{message}");
        assert!(message.contains("stuffr list"), "{message}");
    }

    /// The negative double for both refusals above, and the one that keeps
    /// them from being a new way to lie: a sighting must rest on structure,
    /// never on a plausible-looking byte. Random noise carrying method
    /// identifiers must still answer the ordinary empty outcome — if it did
    /// not, `salvage` would start confidently naming header levels in files
    /// that hold none.
    #[test]
    fn noise_never_produces_an_ungateable_sighting() {
        let noise = noise_with_seeded_methods(1 << 20);
        let out = salvage_lha(&mut Cursor::new(noise), &SalvagePolicy::default()).expect(
            "noise must reach the ordinary empty outcome, never a confident claim about \
             header levels this build cannot gate",
        );
        assert!(out.entries.is_empty());
    }

    /// **Ruling S-W.** A `0x42` (`EXT_HEADER_MSDOS_SIZE`) extension header
    /// overrides BOTH size fields at level >= 2, and `delharc` honours it —
    /// so until this did too, `stuffr list` and `stuffr salvage` reported
    /// two different sizes for one healthy entry (measured: 5,000 against
    /// 100).
    ///
    /// The base header here declares 100 and the `0x42` header 5,000, which
    /// is the review's own fixture. Both figures are asserted, because
    /// getting only the compressed one right would still leave `-C` writing
    /// the wrong number of bytes.
    #[test]
    fn a_level_2_msdos_size_header_overrides_both_base_fields() {
        let content = vec![0xEEu8; 5_000];
        let bytes = build_level2_with_msdos_size(b"big.txt", &content, 100);
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1, "{:?}", out.entries);
        assert_eq!(
            out.entries[0].meta.compressed_size,
            Some(5_000),
            "the 0x42 header's 64-bit compressed length must win over the base header's u32"
        );
        assert_eq!(
            out.entries[0].meta.size,
            Some(5_000),
            "and so must its decoded length — `-C` sizes the written file from this"
        );
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Intact,
            "with the right length the payload verifies; with the base header's 100 it could \
             not have"
        );
    }

    /// The other side of the branch: with no `0x42` header the base fields
    /// stand, so the test above cannot be passing because the override runs
    /// unconditionally.
    #[test]
    fn without_an_msdos_size_header_the_base_fields_stand() {
        let bytes = build_level2(b"small.txt", b"-lh0-", b"0123456789");
        let out = scan(&bytes);
        assert_eq!(out.entries[0].meta.compressed_size, Some(10));
        assert_eq!(out.entries[0].meta.size, Some(10));
    }

    /// Level 3 is deliberately out of scope — see this module's doc. Pinned
    /// rather than left implicit, so the day a level-3 parser lands this test
    /// says out loud that the coverage just changed.
    #[test]
    fn a_level_3_header_is_not_recognised_by_this_scanner() {
        let mut bytes = build_level2(b"lvl3.txt", b"-lh0-", b"payload");
        bytes[HEADER_LEVEL_I] = 3;
        assert!(
            scan(&bytes).entries.is_empty(),
            "level 3 re-sizes every length field to 32 bits and is a different parser"
        );
    }

    /// A level-1 extra-header chain moves the payload and can rename the
    /// entry. Both are checked here because a scanner that ignored the chain
    /// would get both wrong at once — the name from the base header's
    /// fallback field, and the payload two extra headers too early.
    #[test]
    fn a_level_1_extra_header_chain_moves_the_payload_and_names_the_entry() {
        let bytes = build_level1_with_extras(b"IGNORED", b"dir\xff", b"real.txt", b"chained");
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].meta.name, "dir/real.txt",
            "the 0x01 and 0x02 extra headers take precedence, exactly as `raw_pathname` applies \
             them"
        );
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Intact,
            "and the payload position is right, which is the half a name check cannot see"
        );
        assert_eq!(out.entries[0].meta.compressed_size, Some(7));
    }

    /// **The single strongest structural check in this module.**
    ///
    /// This scanner's parser is its own, because the header checksum has to
    /// be a gate criterion it can falsify (see this module's doc) — and a
    /// second copy of a layout is exactly what `zoo_salvage.rs`'s module doc
    /// warns about: `unarc-rs` models ZOO's fixed record as 59 bytes where it
    /// is 56, and a reader built on 59 reports healthy what is actually
    /// damaged.
    ///
    /// So every archive shape these tests build, and the externally-verified
    /// fixture, is parsed BOTH ways — by [`parse_header_at`] and by
    /// `delharc`'s own `LhaHeader::read`, the parser `lha.rs` reads every
    /// real archive through — and the two must agree on the method, both
    /// sizes, the CRC-16, the name and, above all, on **where the payload
    /// starts**, which `delharc` reports simply by where it left the stream.
    /// A divergence between the copy and the library's own is itself the
    /// finding this cross-check exists to surface.
    #[test]
    fn the_header_geometry_agrees_with_delharcs_own_parser() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (SAMPLE_LZH.to_vec(), "sample.lzh (level 1, lhasa-verified)"),
            (build_level1(b"L1.TXT", b"-lh0-", b"one"), "built level 1"),
            (build_level0(b"L0.TXT", b"-lh0-", b"zero"), "built level 0"),
            (
                build_level0(b"L0EMPTY.TXT", b"-lh0-", b""),
                "built level 0, empty payload",
            ),
            (
                build_level1_with_extras(b"IGNORED", b"dir\xff", b"real.txt", b"chained"),
                "built level 1 with an extra-header chain",
            ),
            (
                build_level2(b"level2.txt", b"-lh0-", b"level two"),
                "built level 2 (Ruling S-U)",
            ),
            (
                build_level2(b"dir\xffdeep.txt", b"-lh0-", b""),
                "built level 2, empty payload and a path-shaped name",
            ),
            (
                build_level2_with_msdos_size(b"big.txt", &vec![0xEEu8; 5_000], 100),
                "built level 2 with an EXT_HEADER_MSDOS_SIZE override (Ruling S-W)",
            ),
        ];

        for (bytes, label) in cases {
            let mut ours = Cursor::new(bytes.clone());
            let mut seen = UngateableSightings::default();
            let mine = parse_header_at(&mut ours, 0, bytes.len() as u64, &mut seen)
                .unwrap_or_else(|| panic!("{label}: this module's parser must accept it"));

            let mut theirs = Cursor::new(bytes.clone());
            let header = delharc::header::LhaHeader::read(&mut theirs)
                .unwrap_or_else(|_| panic!("{label}: delharc must accept it"))
                .unwrap_or_else(|| panic!("{label}: delharc must find a header"));
            // `LhaHeader::read` consumes exactly the header — the base plus,
            // for level 1, the whole extra-header chain — so where it left
            // the stream IS the payload's start, derived with no arithmetic
            // of ours at all.
            let their_payload_start = theirs.position();

            assert_eq!(
                mine.method.identifier(),
                &header.compression,
                "{label}: method identifier"
            );
            assert_eq!(
                mine.payload_start, their_payload_start,
                "{label}: payload start — the one figure everything downstream reads"
            );
            assert_eq!(
                mine.declared_len, header.compressed_size,
                "{label}: compressed payload length (level 1's skip size minus its chain)"
            );
            assert_eq!(
                mine.original_size, header.original_size,
                "{label}: original size"
            );
            assert_eq!(mine.file_crc, header.file_crc, "{label}: file CRC-16");
            // The timestamp is asserted for LEVEL 2 alone, and deliberately.
            // At levels 0 and 1 the only figure to compare against is
            // `lha_mtime`'s own output — this module's function — which
            // would be a tautology; `lha.rs`'s
            // `a_packed_dos_timestamp_round_trips_through_its_own_inverse`
            // pins that one against the production WRITER instead. Level 2
            // is different: the field is raw Unix seconds, so `delharc`'s
            // own `last_modified` is an independent figure to check against,
            // and reading a level-2 stamp as an MS-DOS word (or the reverse)
            // is a silent decades-wide error rather than a parse failure.
            if header.level >= 2 {
                assert_eq!(
                    mine.mtime,
                    Some(UNIX_EPOCH + Duration::from_secs(u64::from(header.last_modified))),
                    "{label}: a level-2 timestamp is Unix seconds"
                );
            }
            assert_eq!(
                mine.name,
                super::super::lha::test_archives::pathname(&header),
                "{label}: reported name — this project's mapping, not delharc's"
            );
        }
    }

    // -------------------------------------------------------------------
    // The method table
    // -------------------------------------------------------------------

    /// Closes [`Method::all`]'s front door and pins the recognised set to
    /// `delharc`'s own identifier table, in BOTH directions, by sweeping the
    /// whole `-lh?-`/`-lz?-` byte space rather than iterating either list.
    #[test]
    fn the_recognised_set_is_exactly_delharcs_own_lh_and_lz_table() {
        let mut recognised = 0;
        for family in [b"-lh", b"-lz"] {
            for byte in 0..=u8::MAX {
                let id = [family[0], family[1], family[2], byte, b'-'];
                let theirs = CompressionMethod::try_from(&id).is_ok();
                let mine = Method::from_identifier(&id).is_some();
                assert_eq!(
                    mine,
                    theirs,
                    "identifier {:?}: delharc {} it, this module {} it",
                    String::from_utf8_lossy(&id),
                    if theirs { "names" } else { "does not name" },
                    if mine { "does" } else { "does not" },
                );
                if mine {
                    recognised += 1;
                }
            }
        }
        assert_eq!(
            recognised,
            Method::all().count(),
            "every variant must be reachable from its own identifier — a variant added at the \
             FRONT of `Method::all`'s seed chain would otherwise be silently absent"
        );
        assert_eq!(
            recognised, 11,
            "the `-lh*-`/`-lz*-` table has eleven rows; a change to that set is a deliberate \
             act, not something this test should absorb"
        );
    }

    /// [`Method::decodable`] is a hand-written `match`; this is the only
    /// authority that actually knows, over the feature set this build
    /// compiled. Without it, a `delharc` feature change (or a version bump
    /// adding `lhx`) would leave every `-lhx-` entry reported
    /// `Unverified (undecodable method)` while the decoder for it sat
    /// compiled in and unused.
    #[test]
    fn decodability_matches_what_this_build_actually_compiled() {
        for method in Method::all() {
            let empty: &[u8] = &[];
            let supported =
                DecoderAny::new_from_compression(method.compression(), empty).is_supported();
            assert_eq!(
                method.decodable(),
                supported,
                "{:?}: `decodable()` says {}, delharc's own `is_supported` says {supported}",
                method,
                method.decodable()
            );
        }
    }

    /// Every method a real LHA header can carry must survive the round trip
    /// salvage's write path depends on — [`Method::codec`] →
    /// [`method_for_codec`]. Driven from the identifier sweep rather than
    /// from `Method::all()`, for the same reason its ZOO twin is.
    #[test]
    fn every_recognised_method_can_be_written_back() {
        let mut seen = 0;
        for family in [b"-lh", b"-lz"] {
            for byte in 0..=u8::MAX {
                let id = [family[0], family[1], family[2], byte, b'-'];
                let Some(method) = Method::from_identifier(&id) else {
                    continue;
                };
                seen += 1;
                assert_eq!(
                    method_for_codec(Some(method.codec())),
                    Some(method),
                    "{:?}'s codec {:?} must map back to it — otherwise salvage reports \
                     SkippedNotBuiltIn and silently writes nothing for every entry using it",
                    method,
                    method.codec()
                );
            }
        }
        assert_eq!(seen, 11);
        // And two different methods never share a codec, which is what makes
        // the reverse map single-valued at all.
        let mut codecs: Vec<FormatId> = Method::all().map(Method::codec).collect();
        codecs.sort_by_key(|c| c.as_str());
        let before = codecs.len();
        codecs.dedup();
        assert_eq!(before, codecs.len(), "every method needs its own codec id");
    }

    /// A recognised method this build has no decoder for is a REPORTED entry
    /// — the archive is fine, this build cannot read that one method — and
    /// it is `Unverified`, never `Complete` (the format does carry a
    /// checksum) and never `Partial` (nothing was attempted, so nothing
    /// failed).
    #[test]
    fn an_undecodable_method_is_unverified_not_dropped_and_not_complete() {
        let bytes = build_level1(b"OLD.LZH", b"-lhx-", b"whatever bytes");
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].meta.name, "OLD.LZH");
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::UndecodableMethod)
        );
        assert_eq!(out.entries[0].meta.codec, Some(FormatId::new("lha-lhx")));
    }

    /// A `-lhd-` entry is a DIRECTORY marker, not a compression method: no
    /// payload, and nothing missing when nothing is decoded.
    #[test]
    fn a_directory_entry_is_reported_as_a_directory_and_is_intact() {
        let bytes = build_level1(b"subdir\xff", b"-lhd-", b"");
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].meta.name, "subdir/");
        assert_eq!(out.entries[0].meta.kind, EntryKind::Dir);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Intact,
            "an empty payload against a CRC-16 of nothing is a real, passing comparison"
        );
    }

    // -------------------------------------------------------------------
    // Truncation, damage and the absence of a ceiling
    // -------------------------------------------------------------------

    /// Criterion "reports rather than rejects", mirroring `zip_salvage.rs`'s
    /// own ruling: a header promising payload the file cannot deliver is
    /// still a header, and dropping it would make a truncated archive's last
    /// entry vanish with no row and exit 0 — the single most common damaged
    /// archive there is.
    #[test]
    fn a_declared_length_running_past_the_file_is_reported_not_dropped() {
        let bytes = build_level1(b"CUT.TXT", b"-lh0-", b"twenty bytes of text");
        let truncated = &bytes[..bytes.len() - 9];
        let out = scan(truncated);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].meta.compressed_size,
            Some(20),
            "the declared figure is reported exactly as the header stated it"
        );
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "and the shortfall is a statement, not silence"
        );
    }

    /// A payload that is entirely present but was corrupted in place:
    /// something WAS checked and it did not hold. `Partial`, never `Intact`
    /// and never `Complete`.
    #[test]
    fn a_corrupted_payload_salvages_as_partial() {
        let mut bytes = build_level1(b"BAD.TXT", b"-lh0-", b"the quick brown fox");
        let at = bytes.len() - 5;
        bytes[at] ^= 0xFF;
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
    }

    /// A header whose declared length overruns everything left in the file
    /// must not swallow the real entries after it — the engine fix
    /// `collect_candidates` documents, reproduced here for LHA rather than
    /// left to a coincidence in noise.
    #[test]
    fn a_lying_declared_length_does_not_swallow_the_real_entries_after_it() {
        let first = build_level1(b"FIRST.TXT", b"-lh0-", b"hello");
        let mut phantom = build_level1(b"PHANTOM.BIN", b"-lh0-", b"");
        let second = build_level1(b"SECOND.TXT", b"-lh0-", b"world");

        // Raise the middle header's skip size to a bald lie, and repair its
        // checksum so the gate still admits it — the point is the LENGTH,
        // not the checksum.
        phantom[COMPRESSED_SIZE_I..COMPRESSED_SIZE_I + 4]
            .copy_from_slice(&50_000_000u32.to_le_bytes());
        let counted_len = usize::from(phantom[HEADER_LEN_I]);
        phantom[HEADER_CSUM_I] = checksum_of(&phantom[METHOD_I..METHOD_I + counted_len]);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first[..first.len() - 1]);
        bytes.extend_from_slice(&phantom[..phantom.len() - 1]);
        bytes.extend_from_slice(&second);

        let out = scan(&bytes);
        let names: Vec<&str> = out.entries.iter().map(|e| e.meta.name.as_str()).collect();
        assert!(
            names.contains(&"FIRST.TXT"),
            "the entry BEFORE the phantom must survive: {names:?}"
        );
        assert!(
            names.contains(&"SECOND.TXT"),
            "the entry AFTER the phantom must survive — this is the whole fix: {names:?}"
        );
    }

    /// **The premise behind [`LhaSalvage::max_whole_entry`]'s `u64::MAX`,
    /// proven rather than asserted.**
    ///
    /// A ceiling exists to stop a header field becoming an allocation. LHA
    /// streams, so no header field ever does — and the only instrument that
    /// can tell "nothing was allocated" from "the status came out right
    /// anyway" is the recording allocator. A header declaring the largest
    /// figure its own `u32` fields can express must not move this needle.
    ///
    /// Note the shape: the assertion is on the ALLOCATION, and it is made
    /// first, so a future change that started buffering a payload would fail
    /// HERE rather than being hidden behind a status that happens to stay
    /// the same.
    /// # The fixture has to REACH the decode, which the first draft did not
    ///
    /// Written first with the COMPRESSED size raised too, so the candidate
    /// was truncated and `verify_candidate` answered `Partial` at its first
    /// line — before any decoder existed to allocate anything. That version
    /// passed with the guard sabotaged, which is the "a status assertion
    /// that fires first" shape the recording allocator exists to expose, one
    /// layer up. Here the compressed side is entirely PRESENT and only the
    /// DECODED length is absurd, so the entry really does reach
    /// `stream_verify` and the 4 GiB figure really is the one a buffer would
    /// be sized from.
    #[test]
    fn a_four_gigabyte_declaration_never_becomes_an_allocation() {
        let mut bytes = build_level1(b"HUGE.BIN", b"-lh0-", b"present!");
        // The compressed payload is all there; the DECODED length is the
        // lie, and it is the figure a whole-decoding scanner would allocate.
        bytes[ORIGINAL_SIZE_I..ORIGINAL_SIZE_I + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let counted_len = usize::from(bytes[HEADER_LEN_I]);
        bytes[HEADER_CSUM_I] = checksum_of(&bytes[METHOD_I..METHOD_I + counted_len]);

        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| scan(&bytes));
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes — a 4 GiB header field became a \
             buffer, which is what `max_whole_entry`'s `u64::MAX` says cannot happen"
        );
        // **The LOWER bound, and it is not decoration.** Fix round 1's
        // MEDIUM: an assertion that is only an upper bound cannot notice the
        // PROBE's own absence — detach `alloc_probe`'s `#[global_allocator]`
        // and `largest_single_allocation` reports `0`, which satisfies
        // `<= 1 << 20` perfectly while measuring nothing. Measured: with the
        // attribute patched to `#[cfg(any())]`, this test passed and its
        // sibling below failed. `find_next_method` allocates a
        // `SCAN_CHUNK`-sized read buffer on every scan, so that figure is a
        // floor the probe cannot report unless it is actually attached.
        assert!(
            largest >= SCAN_CHUNK,
            "largest single allocation was only {largest} bytes, below the {SCAN_CHUNK}-byte \
             buffer every scan allocates — the recording allocator is not attached, so the \
             ceiling above is measuring nothing"
        );
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].meta.size,
            Some(u64::from(u32::MAX)),
            "the declared figure is reported exactly as the header stated it"
        );
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "eight bytes do not decode to four gigabytes — but that is a verdict reached by \
             STREAMING, not by refusing the entry for its size"
        );
    }

    /// The other half of the claim above: a level-1 extra-header chain is the
    /// one place this module reads a length-declared buffer at all, and it is
    /// bounded by the header's OWN `u16`, never by the skip size behind it.
    ///
    /// A header declaring a 4 GiB skip size and a MAXIMAL first extra header
    /// whose bytes are genuinely present must allocate that header's own
    /// `u16` worth and not one byte more — proven with the allocator, not
    /// with the resulting status, which is identical either way.
    ///
    /// # The chain must be REACHED, which the first draft's was not
    ///
    /// Written first with the maximal header DECLARED and absent, so the
    /// walk refused it for running past the file before `buf.resize` ran at
    /// all. Sabotaged (`buf.resize(skip_size)`) that version still passed —
    /// an allocation bound asserted over a path that never allocates. The
    /// fixture now carries the whole 65,535 bytes, so the resize really
    /// happens and the sabotage really is a 4 GiB request.
    #[test]
    fn a_level_1_chain_never_allocates_from_the_skip_size_it_declares() {
        const EXTRA_LEN: usize = u16::MAX as usize;
        let payload = b"present";
        let mut bytes = build_level1(b"CHAIN.BIN", b"-lh0-", payload);
        // Level 1's size field is the SKIP size — the chain plus the payload
        // — and the absurd figure here is what a careless walk would size a
        // buffer from.
        bytes[COMPRESSED_SIZE_I..COMPRESSED_SIZE_I + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let counted_len = usize::from(bytes[HEADER_LEN_I]);
        let first_at = METHOD_I + counted_len - 2;
        bytes[first_at..first_at + 2].copy_from_slice(&(EXTRA_LEN as u16).to_le_bytes());
        bytes[HEADER_CSUM_I] = checksum_of(&bytes[METHOD_I..METHOD_I + counted_len]);

        // A real, maximal extra header: an identifier this walk ignores, a
        // body, and a trailing `u16` zero that terminates the chain.
        let base_end = METHOD_I + counted_len;
        let mut extra = vec![0xAAu8; EXTRA_LEN];
        extra[0] = 0x40; // EXT_HEADER_MSDOS_ATTRS — neither a name nor a path
        extra[EXTRA_LEN - 2] = 0;
        extra[EXTRA_LEN - 1] = 0;
        bytes.splice(base_end..base_end, extra);

        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| scan(&bytes));
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes — the extra-header walk sized a \
             buffer from something other than one header's own u16 length"
        );
        assert!(
            largest >= EXTRA_LEN,
            "largest single allocation was only {largest} bytes, so the {EXTRA_LEN}-byte extra \
             header was never read at all — an allocation bound asserted over a path that \
             does not allocate is exactly the vacuity this test was rewritten to escape"
        );
        assert_eq!(
            out.entries.len(),
            1,
            "the chain terminates inside the file, so this IS a header: {:?}",
            out.entries
        );
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "its skip size still claims 4 GiB the file does not hold"
        );
    }

    /// The companion refusal, with no allocator involved: a chain declaring
    /// bytes the file does not hold is not a chain, and the candidate is
    /// rejected rather than walked.
    #[test]
    fn a_chain_running_past_the_end_of_the_file_is_rejected() {
        let mut bytes = build_level1(b"CHAIN.BIN", b"-lh0-", b"");
        bytes[COMPRESSED_SIZE_I..COMPRESSED_SIZE_I + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let counted_len = usize::from(bytes[HEADER_LEN_I]);
        let first_at = METHOD_I + counted_len - 2;
        bytes[first_at..first_at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[HEADER_CSUM_I] = checksum_of(&bytes[METHOD_I..METHOD_I + counted_len]);
        assert!(scan(&bytes).entries.is_empty());
    }

    /// A chain declaring more bytes than the header's own skip size is the
    /// header contradicting itself — `delharc` raises "wrong length of skip
    /// size" for it, and a scanner must reject rather than compute a
    /// negative payload length.
    #[test]
    fn a_chain_longer_than_its_own_skip_size_is_rejected() {
        let mut bytes = build_level1_with_extras(b"IGNORED", b"dir\xff", b"real.txt", b"chained");
        // Drop the skip size to the payload alone, which no longer leaves
        // room for the chain in front of it.
        bytes[COMPRESSED_SIZE_I..COMPRESSED_SIZE_I + 4].copy_from_slice(&7u32.to_le_bytes());
        let counted_len = usize::from(bytes[HEADER_LEN_I]);
        bytes[HEADER_CSUM_I] = checksum_of(&bytes[METHOD_I..METHOD_I + counted_len]);
        assert!(scan(&bytes).entries.is_empty());
    }

    /// A zero-length filename is criterion 5, and it is what a run of zeroed
    /// bytes behind a coincidental identifier looks like.
    #[test]
    fn a_zero_length_name_is_rejected() {
        let mut bytes = build_level1(b"N.TXT", b"-lh0-", b"x");
        bytes[NAME_LEN_I] = 0;
        let counted_len = usize::from(bytes[HEADER_LEN_I]);
        bytes[HEADER_CSUM_I] = checksum_of(&bytes[METHOD_I..METHOD_I + counted_len]);
        assert!(scan(&bytes).entries.is_empty());
    }

    /// A match split across a [`SCAN_CHUNK`] boundary must still be found —
    /// the four-byte carry `find_next_method` keeps exists for exactly this.
    #[test]
    fn an_identifier_straddling_a_chunk_boundary_is_found() {
        let mut bytes = vec![0u8; SCAN_CHUNK * 2];
        let at = SCAN_CHUNK - 2;
        bytes[at..at + 5].copy_from_slice(Method::Lh5.identifier());
        let found = find_next_method(&mut Cursor::new(bytes), 0, (SCAN_CHUNK * 2) as u64).unwrap();
        assert_eq!(found, Some(at as u64));
    }

    /// The wiring `a_four_gigabyte_declaration_never_becomes_an_allocation`
    /// depends on, stated directly: this scanner declares no ceiling of its
    /// own, so `policy.max_entry` is the only figure in force.
    #[test]
    fn the_scanner_declares_no_whole_entry_ceiling_of_its_own() {
        assert_eq!(LhaSalvage::new().max_whole_entry(), u64::MAX);
    }

    // -------------------------------------------------------------------
    // The write side
    // -------------------------------------------------------------------

    /// A uniquely-named temporary archive. The counter is what keeps two
    /// tests running in parallel from colliding on one path — the process id
    /// alone does not, since every test in this binary shares it.
    fn temp_archive(bytes: &[u8], tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "stuffr-lha-salvage-{tag}-{}-{}.lzh",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// The companion half of the scanner: a scan arm with no writer arm is a
    /// silent `SkippedNotBuiltIn`, which is the gap ARC shipped with. This
    /// drives [`write_payload`] over a real archive and a real recovered
    /// entry, through the stored (`-lh0-`) arm.
    #[test]
    fn write_payload_recovers_a_stored_entry() {
        let content = b"the quick brown fox jumps over the lazy dog, repeatedly. ".repeat(4);
        let bytes = build_level1(b"DOC.TXT", b"-lh0-", &content);
        let path = temp_archive(&bytes, "stored");
        let out = scan(&bytes);
        let entry = &out.entries[0];
        let mut sink: Vec<u8> = Vec::new();
        let completed = write_payload(&path, entry, entry.meta.compressed_size.unwrap(), &mut sink)
            .expect("a healthy entry writes without error");
        let _ = std::fs::remove_file(&path);
        assert!(completed, "a healthy entry completes");
        assert_eq!(sink, content, "the recovered bytes are the content");
    }

    /// The COMPRESSED arm, over an archive this project's own `-lh5-`
    /// encoder produced — the only method it can produce — so the decoder
    /// this module dispatches to is exercised rather than only the
    /// passthrough one.
    #[test]
    fn write_payload_recovers_an_lh5_entry() {
        let content = b"compressible compressible compressible compressible\n".repeat(20);
        let bytes = super::super::lha::test_archives::build_lha(&[("BIG.TXT", &content)]);
        let path = temp_archive(&bytes, "lh5");
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1, "{:?}", out.entries);
        let entry = &out.entries[0];
        assert_eq!(entry.meta.codec, Some(FormatId::new("lha-lh5")));
        assert_eq!(entry.status, SalvageStatus::Intact);
        let mut sink: Vec<u8> = Vec::new();
        let completed = write_payload(&path, entry, entry.meta.compressed_size.unwrap(), &mut sink)
            .expect("a healthy entry writes without error");
        let _ = std::fs::remove_file(&path);
        assert!(completed);
        assert_eq!(sink, content);
    }

    /// The externally-verified fixture's own payloads, through the write
    /// path — bytes no encoder in this project produced.
    #[test]
    fn write_payload_recovers_the_externally_verified_fixture() {
        let path = temp_archive(SAMPLE_LZH, "sample");
        let out = scan(SAMPLE_LZH);
        let expected: [&[u8]; 2] = [b"alpha\n", b"beta\n"];
        for (entry, want) in out.entries.iter().zip(expected) {
            let mut sink: Vec<u8> = Vec::new();
            let completed =
                write_payload(&path, entry, entry.meta.compressed_size.unwrap(), &mut sink)
                    .expect("a healthy fixture writes without error");
            assert!(completed, "{}", entry.meta.name);
            assert_eq!(sink, want, "{}", entry.meta.name);
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A truncated entry's genuine surviving prefix is written, rather than
    /// the whole read failing and nothing being written —
    /// `arc_salvage.rs`'s fix rounds 1 and 2, inherited.
    #[test]
    fn write_payload_recovers_the_prefix_of_a_truncated_entry() {
        let content = b"abcdefghijklmnopqrstuvwxyz0123456789".repeat(4);
        let bytes = build_level1(b"CUT.TXT", b"-lh0-", &content);
        // Drop the last 30 payload bytes and the end-of-archive marker.
        let cut = &bytes[..bytes.len() - 31];
        let path = temp_archive(cut, "truncated");
        let out = scan(cut);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);

        let mut sink: Vec<u8> = Vec::new();
        let completed = write_payload(
            &path,
            &out.entries[0],
            out.entries[0].meta.compressed_size.unwrap(),
            &mut sink,
        )
        .expect("a truncated entry must not error the write path");
        let _ = std::fs::remove_file(&path);
        assert!(
            !completed,
            "it cannot be `completed`: its own header declares a length the content does not \
             reach"
        );
        // EXACTLY the bytes that are present, not merely "some of them":
        // this entry is 144 bytes and one `DECODE_CHUNK` is 4096, so before
        // `recover_the_last_chunk` existed the whole payload was one
        // all-or-nothing `fill_buffer` call and `NAME.partial` held ZERO
        // bytes at exit 4. A `!sink.is_empty()` assertion would pass on a
        // single recovered byte and hide a regression to that shape.
        assert_eq!(
            sink,
            content[..content.len() - 30],
            "every present byte must be recovered, as a genuine prefix: got {} of the {} that \
             are in the file",
            sink.len(),
            content.len() - 30
        );
    }

    /// The other half of [`recover_the_last_chunk`]: on an entry much LARGER
    /// than one [`DECODE_CHUNK`], the first pass recovers whole chunks and
    /// the second adds only the tail — so this pins the fast path
    /// ([`DecodedReader::fine_from`] racing through what already worked)
    /// rather than the degenerate one above, where the fine region is the
    /// whole entry.
    ///
    /// Measured with the second pass disabled: `got 16384 of the 19990 bytes
    /// that are in the file` — it recovers `4 * DECODE_CHUNK` and stops
    /// **3,606** short. Without `fine_from` it would recover the same bytes
    /// at 19,990 single-byte `fill_buffer` calls instead of four chunked ones
    /// plus a few thousand.
    #[test]
    fn write_payload_recovers_a_truncated_entry_past_the_first_whole_chunk() {
        let content: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let bytes = build_level1(b"BIG.BIN", b"-lh0-", &content);
        let missing = 10;
        let cut = &bytes[..bytes.len() - (missing + 1)];
        let path = temp_archive(cut, "truncated-large");
        let out = scan(cut);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);

        let mut sink: Vec<u8> = Vec::new();
        let completed = write_payload(
            &path,
            &out.entries[0],
            out.entries[0].meta.compressed_size.unwrap(),
            &mut sink,
        )
        .expect("a truncated entry must not error the write path");
        let _ = std::fs::remove_file(&path);
        assert!(!completed);
        assert_eq!(
            sink,
            content[..content.len() - missing],
            "got {} of the {} bytes that are in the file",
            sink.len(),
            content.len() - missing
        );
    }

    /// An undecodable method reaching the `pub` write path is refused by
    /// NAME, as `Error::Unsupported` — which `place_salvaged_file` maps to
    /// `SkippedNotBuiltIn`, the honest disposition — rather than writing an
    /// empty file under the entry's real name.
    #[test]
    fn write_payload_refuses_an_undecodable_method_by_name() {
        let bytes = build_level1(b"OLD.LZH", b"-lhx-", b"whatever");
        let path = temp_archive(&bytes, "undecodable");
        let out = scan(&bytes);
        let mut sink: Vec<u8> = Vec::new();
        let err = write_payload(&path, &out.entries[0], 8, &mut sink)
            .expect_err("an undecodable method must be refused, never silently written");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        assert!(err.to_string().contains("-lhx-"), "{err}");
        assert!(sink.is_empty());
    }

    /// A codec-less entry is refused BEFORE `archive_path` is opened —
    /// `entries.rs`'s `every_salvage_slot_reaches_a_real_payload_writer`
    /// probes every slot with exactly that shape and a path that does not
    /// exist.
    #[test]
    fn write_payload_refuses_a_codec_less_entry_without_opening_the_archive() {
        let entry = SalvagedEntry::new(0, 0, 0, EntryMeta::file("probe"), SalvageStatus::Complete);
        let err = write_payload(
            Path::new("/nonexistent-lha-salvage-probe"),
            &entry,
            0,
            &mut io::sink(),
        )
        .expect_err("a codec-less probe entry must always be refused");
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
    }

    /// `shadows` is a MEASUREMENT the engine makes from `(name,
    /// declared_len, verifier)`, never an inference from a repeated name —
    /// so two byte-identical records are linked and two same-named records
    /// with different content are not.
    #[test]
    fn a_byte_identical_duplicate_shadows_and_a_differing_one_only_collides() {
        let one = build_level1(b"DUP.TXT", b"-lh0-", b"identical content");
        let copy = build_level1(b"DUP.TXT", b"-lh0-", b"identical content");
        let differing = build_level1(b"DUP.TXT", b"-lh0-", b"different content");

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&one[..one.len() - 1]);
        bytes.extend_from_slice(&copy[..copy.len() - 1]);
        bytes.extend_from_slice(&differing);

        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 3, "{:?}", out.entries);
        assert_eq!(out.entries[0].shadows, None);
        assert_eq!(
            out.entries[1].shadows,
            Some(0),
            "a byte-identical record is a MEASURED copy of the first"
        );
        assert_eq!(
            out.entries[2].shadows, None,
            "different content, so no copy"
        );
        assert_eq!(
            out.entries[2].collides_with,
            Some(0),
            "but the name repeats, which is the weaker fact"
        );
    }
}

// -------------------------------------------------------------------------
// Salvage Stage 2 Task 7: the damage catalogue.
//
// **Every expectation here is the PRE-DAMAGE state, and none of it comes
// from this scanner.** The base archive is `fixtures/legacy/sample.lzh`,
// the one legacy fixture an implementation OUTSIDE this project has agreed
// with: hand-assembled (nothing on any reachable machine can CREATE an
// `.lzh` — `lhasa` is decode-only and `delharc` has no writer), then
// independently confirmed by `lhasa`, a decoder sharing no code with
// `delharc`. `fixtures/legacy/MANIFEST.md` records both facts.
//
// **The live external witness runs at the CLI**, not here: `cli.rs`'s
// `lhasa_agrees_with_the_lha_damage_catalogue` builds an archive, has
// `lha t` pronounce it good BEFORE any damage, damages one entry, and has
// `lha t` name that same entry bad — so the damage is real by an outside
// account, not only by ours. This module is the fast half of the same
// catalogue.
//
// Note what a mid-payload flip produces: the TIER is `Partial` always, and
// the rows below assert that, because the CAUSE one crate up
// (`stuffr::entries::PartialCause`) depends on the CODEC rather than on the
// damage — `-lh0-` decodes whole and disagrees (`ChecksumMismatch`), while
// `-lh5-` usually aborts mid-stream. That difference is real and worth
// reporting; what was WRONG, and what Ruling S-AA fixed in this fix round,
// is that the aborting case printed `Partial (truncated)` over an archive
// from which nothing had been cut. There are three causes now, and the CLI
// asserts the exact one (`cli.rs`'s
// `damage_catalogue_the_three_partial_causes_are_distinguishable`); this
// layer cannot see `PartialCause` at all, so the tier is still what it
// pins.
// -------------------------------------------------------------------------
#[cfg(test)]
mod damage_catalogue {
    use std::io::Cursor;

    use stuffr_core::salvage::{SalvagePolicy, SalvageStatus};
    use stuffr_core::{Container, Error, OpenOpts, ReaderSource, Source, StreamPolicy};

    use super::super::lha::test_archives::{build_lha, read_entry_names};
    use super::super::lha::{LHA, Lha};
    use super::salvage_lha;
    use super::tests::{build_level2_without_common_header, build_level3};

    /// Two `-lh0-` (Stored) level-1 entries — `sample/hello.txt` (6 bytes)
    /// and `sample/sub/b.bin` (5 bytes) — whose CRC-16s `lhasa` has
    /// independently verified. See `fixtures/legacy/MANIFEST.md`.
    const SAMPLE_LZH: &[u8] = include_bytes!("../../fixtures/legacy/sample.lzh");

    /// One level-1 header's geometry, parsed out of the raw bytes by this
    /// test: `header_len(1) + checksum(1) + method(5) + skip_size(u32) +
    /// original_size(u32) + …`, with the payload beginning
    /// `header_len + 2` bytes past the header's own start.
    ///
    /// Hand-rolled rather than reusing this module's own parser, for the
    /// reason `cli.rs`'s `parse_real_zip_local_entries` is hand-rolled: an
    /// expectation read through the code under test is not an expectation.
    struct Header {
        offset: usize,
        /// Byte offset of the five-byte method identifier.
        method_at: usize,
        /// Byte offset of the one-byte header checksum.
        checksum_at: usize,
        payload: std::ops::Range<usize>,
        /// The CRC-16/ARC the header declares over this entry's ORIGINAL
        /// content — a level-0/1 header carries it immediately after the
        /// filename. Fix round 1, F5: without it this module had no way to
        /// check the reader's decoded bytes against anything the archive
        /// itself states, which made LHA the one agreement property of four
        /// with no content leg.
        declared_crc: u16,
    }

    fn headers(bytes: &[u8]) -> Vec<Header> {
        let mut out = Vec::new();
        let mut at = 0usize;
        // A zero `header_len` byte is LHA's optional end-of-archive marker.
        while at + 22 < bytes.len() && bytes[at] != 0 {
            let header_len = bytes[at] as usize;
            let skip = u32::from_le_bytes(bytes[at + 7..at + 11].try_into().unwrap()) as usize;
            let name_len = bytes[at + 21] as usize;
            let crc_at = at + 22 + name_len;
            let declared_crc = u16::from_le_bytes(bytes[crc_at..crc_at + 2].try_into().unwrap());
            let start = at + header_len + 2;
            out.push(Header {
                offset: at,
                method_at: at + 2,
                checksum_at: at + 1,
                payload: start..start + skip,
                declared_crc,
            });
            at = start + skip;
        }
        out
    }

    /// CRC-16/ARC written out longhand, independent of
    /// `super::super::crc::crc16_arc` — the same witness `arc_salvage.rs`
    /// and `zoo_salvage.rs` carry, and pinned to the published RevEng check
    /// value below for the same reason.
    fn crc16_witness(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for &b in data {
            crc ^= u16::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xA001
                } else {
                    crc >> 1
                };
            }
        }
        crc
    }

    #[test]
    fn the_witness_checksum_matches_the_published_check_value() {
        assert_eq!(crc16_witness(b"123456789"), 0xBB3D);
    }

    /// What the ORDINARY reader enumerates AND decodes — `read_entry_names`
    /// reports names alone, which is why the agreement property below needed
    /// this instead (fix round 1, F5).
    fn reader_entries(bytes: &[u8]) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(Cursor::new(bytes.to_vec())));
        let resolved = stuffr_core::resolve(src, LHA, Lha.caps(), &StreamPolicy::default())
            .map_err(|e| format!("resolve: {e}"))?;
        let mut ar = Lha
            .open(resolved, &OpenOpts::default())
            .map_err(|e| format!("open: {e}"))?;
        let mut out = Vec::new();
        loop {
            match ar.next_entry() {
                Ok(Some(mut entry)) => {
                    let name = entry.meta().name.clone();
                    let mut data = Vec::new();
                    entry
                        .reader()
                        .read_to_end(&mut data)
                        .map_err(|e| format!("read {name}: {e}"))?;
                    out.push((name, data));
                }
                Ok(None) => return Ok(out),
                Err(e) => return Err(format!("next_entry: {e}")),
            }
        }
    }

    fn salvaged(bytes: &[u8]) -> Vec<(String, SalvageStatus)> {
        salvage_lha(&mut Cursor::new(bytes.to_vec()), &SalvagePolicy::default())
            .expect("a damaged archive must never abort the run")
            .entries
            .iter()
            .map(|e| (e.meta.name.clone(), e.status))
            .collect()
    }

    fn names(rows: &[(String, SalvageStatus)]) -> Vec<&str> {
        rows.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// A three-entry archive from the PRODUCTION writer, with payloads big
    /// enough that a mid-payload flip has somewhere to land. Its external
    /// witness is `cli.rs`'s `lha t` pass over the same shape; here it is
    /// the multi-entry base the `sample.lzh` fixture (11 payload bytes in
    /// total) is too small to be.
    fn three_entries() -> Vec<u8> {
        build_lha(&[
            (
                "one.txt",
                b"first entry payload, repeated. ".repeat(20).as_slice(),
            ),
            (
                "two.txt",
                b"second entry payload, repeated. ".repeat(20).as_slice(),
            ),
            (
                "three.txt",
                b"third entry payload, repeated. ".repeat(20).as_slice(),
            ),
        ])
    }

    // ---------------------------------------------------------------------
    // Step 1: the agreement property.
    // ---------------------------------------------------------------------

    /// **Salvage of an UNDAMAGED archive must agree exactly with what the
    /// ordinary reader enumerates** — same names, same order, every entry
    /// `Intact`, nothing shadowing anything.
    ///
    /// `read_entry_names` walks through `delharc`, which is the parser
    /// `stuffr list`/`cat`/`unpack`/`test` all read the archive with, while
    /// this scanner owns a SECOND, independent header parser (see this
    /// module's own doc for why). So the property compares two parsers
    /// written from the same spec and not from each other — the closest
    /// thing to an in-process second opinion LHA has.
    #[test]
    fn salvage_of_a_healthy_archive_agrees_with_the_ordinary_reader() {
        let built = three_entries();
        for (label, bytes) in [
            ("sample.lzh (lhasa-verified)", SAMPLE_LZH),
            ("three entries, production writer", &built[..]),
        ] {
            let read = reader_entries(bytes)
                .unwrap_or_else(|e| panic!("{label}: the ordinary reader must walk it: {e}"));
            let rows = salvaged(bytes);
            let geometry = headers(bytes);
            assert_eq!(
                rows.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                read.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                "{label}: salvage and the ordinary reader must enumerate the same names in \
                 the same order"
            );
            // `read_entry_names` is the reader route the module's other
            // tests use; asserted equal here so the two never drift apart
            // and the content leg below is known to be over the same walk.
            assert_eq!(
                read_entry_names(bytes).expect("the name-only reader route must agree"),
                read.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                "{label}: the two reader routes must enumerate the same entries"
            );
            assert_eq!(
                geometry.len(),
                read.len(),
                "{label}: and both must agree with the header geometry this test parsed \
                 longhand out of the archive's own bytes"
            );
            for (name, status) in &rows {
                assert_eq!(
                    *status,
                    SalvageStatus::Intact,
                    "{label}: an undamaged entry (`{name}`) must verify Intact"
                );
            }
            // **The content leg (fix round 1, F5).** Without this, "every
            // entry Intact" above is salvage's own verdict with nothing
            // corroborating it: `read_entry_names` reads no payload, so the
            // two sides agreed about names and about nothing else. The
            // reader's DECODED bytes are checked against the CRC-16 the
            // header itself declares, through an implementation independent
            // of `legacy::crc`'s — the same third leg ARC, ZOO and ARJ each
            // already had.
            for ((name, content), header) in read.iter().zip(geometry.iter()) {
                assert_eq!(
                    crc16_witness(content),
                    header.declared_crc,
                    "{label}: the reader's output for `{name}` must match the CRC-16 the \
                     header declares — otherwise `Intact` above is agreement between two \
                     wrongs"
                );
            }
        }
    }

    /// **Ruling S-V, pinned on the side this module could not see.** A
    /// level-2 header with no common extension header, and a level-3
    /// header, are both refused by the SCAN at `Error::Unsupported` (exit 3,
    /// naming the limitation) — `a_level_2_header_with_no_common_extension_
    /// header_is_refused_by_name` and its level-3 sibling above assert that,
    /// with `delharc` itself as the control.
    ///
    /// What they do NOT assert is the other half of the asymmetry: that the
    /// ORDINARY reader — the whole `Lha` container, not just `delharc`'s
    /// header parser — really does list these archives normally. Without
    /// that, "refused at exit 3, naming the limitation" could be describing
    /// an archive nothing in this project can read, where exit 5 would have
    /// been right after all. Exit 3 is a claim about the BUILD, and this is
    /// what makes it one.
    #[test]
    fn the_header_levels_this_scanner_refuses_are_ones_the_reader_lists() {
        for (label, bytes, expected) in [
            (
                "level 3",
                build_level3(b"level3.txt", b"level three payload"),
                "level3.txt",
            ),
            // F2: the shape the module's own worked example shows a user
            // hitting. It had only `delharc`'s header parser as its
            // control; this is the whole-container half, over the IDENTICAL
            // bytes the refusal test uses.
            (
                "level 2 with no common header",
                build_level2_without_common_header(),
                "nocrc.txt",
            ),
        ] {
            assert_eq!(
                read_entry_names(&bytes)
                    .unwrap_or_else(|e| panic!("{label}: the ordinary reader must list it: {e}")),
                [expected],
                "{label}: exit 3 says `this build cannot scan it`, which is only honest \
                 while the reader CAN read it"
            );
            assert!(
                matches!(
                    salvage_lha(&mut Cursor::new(bytes), &SalvagePolicy::default()),
                    Err(Error::Unsupported(_))
                ),
                "{label}: and the scan must refuse it by name, never report an empty archive"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Step 2: the mutation catalogue.
    // ---------------------------------------------------------------------

    /// Row 1/3 — **a truncated tail**, over the externally-witnessed fixture
    /// and over the three-entry archive, swept across the last payload
    /// rather than sampled at one point.
    #[test]
    fn damage_catalogue_a_truncated_tail() {
        let built = three_entries();
        for (label, bytes, expected) in [
            (
                "sample.lzh",
                SAMPLE_LZH,
                vec!["sample/hello.txt", "sample/sub/b.bin"],
            ),
            (
                "three entries",
                &built[..],
                vec!["one.txt", "two.txt", "three.txt"],
            ),
        ] {
            let g = headers(bytes);
            assert_eq!(
                g.len(),
                expected.len(),
                "{label}: sanity, the pre-damage record count"
            );
            let last = g.last().unwrap().payload.clone();
            let declared = last.len();
            for keep in [0, 1, declared / 2, declared - 1] {
                let rows = salvaged(&bytes[..last.start + keep]);
                assert_eq!(
                    names(&rows),
                    expected,
                    "{label}/keep={keep}: the cut entry's header is still there and its \
                     being uncompletable is a fact worth a row, never silence"
                );
                for (i, (name, status)) in rows.iter().enumerate() {
                    let want = if i + 1 == rows.len() {
                        SalvageStatus::Partial
                    } else {
                        SalvageStatus::Intact
                    };
                    assert_eq!(*status, want, "{label}/keep={keep}: `{name}`");
                }
            }
            assert!(
                salvaged(bytes)
                    .iter()
                    .all(|(_, s)| *s == SalvageStatus::Intact),
                "{label}: the UNCUT archive must still come back entirely Intact"
            );
        }
    }

    /// Row 2/3 — **a byte flipped mid-payload.** That entry `Partial`, every
    /// neighbour `Intact`, with every entry taking its turn as the damaged
    /// one so a scanner that stopped at the first damaged record could not
    /// pass.
    #[test]
    fn damage_catalogue_a_byte_flipped_mid_payload() {
        let built = three_entries();
        for (label, healthy, expected) in [
            (
                "sample.lzh",
                SAMPLE_LZH.to_vec(),
                vec!["sample/hello.txt", "sample/sub/b.bin"],
            ),
            (
                "three entries",
                built,
                vec!["one.txt", "two.txt", "three.txt"],
            ),
        ] {
            let g = headers(&healthy);
            for (damaged, header) in g.iter().enumerate() {
                let mut bytes = healthy.clone();
                let range = header.payload.clone();
                bytes[range.start + range.len() / 2] ^= 0xFF;

                let rows = salvaged(&bytes);
                assert_eq!(
                    names(&rows),
                    expected,
                    "{label}: a flipped payload byte moves no header"
                );
                for (i, (name, status)) in rows.iter().enumerate() {
                    let want = if i == damaged {
                        SalvageStatus::Partial
                    } else {
                        SalvageStatus::Intact
                    };
                    assert_eq!(
                        *status, want,
                        "{label}: `{name}` with entry {damaged} damaged"
                    );
                }
            }
        }
    }

    /// Row 3/3 — **a header field corrupted.** That entry absent, its
    /// neighbours surviving, in every position. Corrupting the FIRST
    /// header is the interesting direction: LHA has no index at all, so an
    /// ordinary forward reader reaches entry 2 only by having parsed entry
    /// 1 — losing one header loses the whole archive for it, and the
    /// scanner recovering the rest is this module's entire reason to exist.
    #[test]
    fn damage_catalogue_a_corrupted_header_field() {
        let healthy = three_entries();
        let g = headers(&healthy);
        let all = ["one.txt", "two.txt", "three.txt"];
        assert_eq!(g.len(), all.len(), "sanity: the pre-damage record count");

        for damaged in 0..g.len() {
            let survivors: Vec<&str> = all
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != damaged)
                .map(|(_, n)| *n)
                .collect();

            // (a) the five-byte method identifier — a spelling LHA never
            // assigned.
            let mut bytes = healthy.clone();
            bytes[g[damaged].method_at + 2] = b'X';
            assert_eq!(
                names(&salvaged(&bytes)),
                survivors,
                "an unassigned method identifier must drop `{}` and nothing else",
                all[damaged]
            );

            // (b) the header checksum — the gate that separates a real
            // header from a coincidental method identifier inside a
            // payload.
            let mut bytes = healthy.clone();
            bytes[g[damaged].checksum_at] ^= 0xFF;
            assert_eq!(
                names(&salvaged(&bytes)),
                survivors,
                "a header whose own checksum no longer vouches for it must drop `{}` and \
                 nothing else",
                all[damaged]
            );

            // (c) the declared header length, which moves where the name,
            // the checksum's coverage and the payload all begin.
            let mut bytes = healthy.clone();
            bytes[g[damaged].offset] = 0xFE;
            assert_eq!(
                names(&salvaged(&bytes)),
                survivors,
                "a corrupted header length must drop `{}` and nothing else",
                all[damaged]
            );
        }
    }
}
