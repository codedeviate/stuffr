//! ZOO directory-record salvage scan: recovers entries by looking directly
//! for the four-byte `ZOO_TAG` every directory entry opens with, rather than
//! following the linked list of absolute file offsets `zoo.rs`'s own reader
//! walks.
//!
//! `zoo.rs` is a correct, honest reader for an INTACT archive. This module
//! is for when the chain itself is the damage — a zeroed `next` link (the
//! four-byte reproducer `ZooRead::refuse_a_chain_that_reaches_nothing`'s
//! doc describes, which makes an 11 KiB archive read as empty), a record
//! overwritten in the middle of the file, a truncated download. It is the
//! third legacy scanner after `arc_salvage.rs` (Task 3), built on the same
//! shared [`stuffr_core::salvage`] machinery.
//!
//! # A ZOO directory entry is effectively a local header, and that is the
//! whole reason this format is scannable
//!
//! Salvage needs a record it can recognise ANYWHERE in a file without
//! having reached it from somewhere else. ZOO supplies one twice over:
//!
//! - every directory entry opens with `zoo.h`'s `ZOO_TAG` (`0xFDC4A7DC`, the
//!   bytes `DC A7 C4 FD`), a FOUR-byte anchor — as strong as zip's
//!   `PK\x03\x04` and far stronger than ARC's two-byte marker+method pair,
//!   which recurs by chance roughly every 8 KiB;
//! - and its payload sits [`SIZ_FLDR`] = **5** bytes past the record's own
//!   end, `zoo.h`'s `FILE_LEADER "@)#("` plus its NUL, because `zooadd.c`
//!   computes `direntry.offset = this_dir_offset + SIZ_DIRL + var_dir_len +
//!   SIZ_FLDR`.
//!
//! So a record found in isolation names its own payload's position without
//! consulting anything else — see [`Candidate::payload_start`], computed
//! once here and never re-derived downstream.
//!
//! **What that proof does and does not cover.** It covers the **type-2**
//! record, which is what all four borrowed fixtures carry and what every
//! zoo 2.10 writes. It says nothing about the **type-0/1** record —
//! `zoo.h`'s `SIZ_DIR`, 51 bytes with no `var_dir_len`, `tz` or `dir_crc`
//! behind it — which this scanner also accepts and for which it computes
//! the same `record_len + SIZ_FLDR`. That extends `zooadd.c`'s
//! `SIZ_DIRL + var_dir_len + SIZ_FLDR` formula to a record shape the
//! formula does not name, and **no borrowed byte witnesses it**: `zoo.rs`'s
//! own module doc already lists the 51-byte record among the three readings
//! nothing in this project's possession can check, and `raw_entries` asserts
//! every fixture is type 2. `zoo.rs`'s READER does not depend on the
//! arithmetic at all — it follows the record's own absolute `offset` — so
//! this is a gap the scanner introduces and the reader does not have.
//! Nothing is known to be wrong; there is simply no evidence either way, and
//! the first type-0/1 ZOO archive anyone finds is what would settle it.
//!
//! **This scanner computes that position STRUCTURALLY, where `zoo.rs`'s
//! reader uses the record's own `offset` field, and the difference is
//! deliberate.** `offset` is an absolute file position: for a zoo-written
//! archive the two always agree (proven over all four borrowed fixtures by
//! [`tests::the_structural_payload_position_agrees_with_the_records_own_offset_field`]),
//! but in a DAMAGED archive `offset` is one more attacker-controlled link,
//! exactly like `next`, and a corrupt one would make salvage read some other
//! entry's bytes and report them under this record's name. The structural
//! position can only ever be immediately behind the record it came from.
//!
//! # The fixed record is 56 bytes, and a scanner built on 59 is worse than
//! a reader built on 59
//!
//! `zoo.rs`'s module doc carries the five measurements that settle
//! `SIZ_DIRL = 56` against `unarc-rs`'s `DIRENT_HEADER_SIZE = 59` (three
//! modelling errors — `var_dir_len` as a `u8`, `dir_crc` as a `u32`, and
//! `namlen`/`dirlen` pulled into the fixed part — cancelling to `56 + 3`).
//! That question lands harder here than anywhere else in this crate,
//! because the structural arithmetic above is built on it: under the
//! 59-byte model every payload position is computed **three bytes late**, so
//! the last three declared bytes of every entry run past the end of the
//! file and every archive — healthy ones included — reports its final entry
//! `Partial (truncated)`. A verb whose entire job is telling a user which
//! of their archives is damaged would answer "damaged" for all of them.
//! Task 4's report records that falsification run and its output.
//!
//! **Nothing here carries its own copy of that layout.** [`read_dir_entry`],
//! [`DirEntry`], [`Method`], [`decode`] and the constants are `zoo.rs`'s
//! own, reused across the module boundary for exactly this reason: a second
//! copy would be one edit away from disagreeing with the reader beside it
//! and nothing would fail to say so. The test-only `raw_entries` in
//! `zoo.rs` stays independent of both on purpose — it is the borrowed
//! fixtures' ground truth, and a witness derived from the parser under test
//! witnesses nothing.
//!
//! # The validation gate
//!
//! A candidate is reported only once ALL of the following hold, checked in
//! an order that never allocates or trusts anything before it is cheap to
//! check:
//!
//! 1. The four-byte tag matches ([`find_next_tag`]).
//! 2. The record PARSES: [`read_dir_entry`] accepts its `type` (0, 1 or 2 —
//!    `portable.c` asserts `type <= 2`) and the `var_dir_len`-many bytes of
//!    its variable part are actually present. That allocation is bounded by
//!    the field's own `u16` type, 64 KiB, and needs no ceiling of its own.
//! 3. The packing method is one the format ever assigned — `<= `
//!    [`Method::MAX_PACK`], `zoo.h`'s `#define MAX_PACK 2`, read from
//!    `zoo.rs` rather than re-derived here. Recognised, not necessarily
//!    DECODABLE: all three are decodable in this build, so unlike ARC there
//!    is no gap between the two, but the distinction is kept in the same
//!    place so a future method cannot silently close it.
//! 4. The name is non-empty, AND either prints as ASCII or the record's own
//!    `dir_crc` reproduces. See [`name_looks_real`] and the section below.
//!
//! Any failure at 2-4 is not an error — it means these four bytes were a
//! coincidence, not a record, and the scan resumes one byte past the tag.
//!
//! **Reported, never rejected:** a declared `size_now` whose bytes do not
//! all fit inside the source. That is `zip_salvage.rs`'s "criterion 6
//! reports, it does not reject" ruling, and the reason is the same: a
//! truncated archive's last entry must be a STATEMENT ([`Candidate::
//! available_len`], `Partial`), never silence.
//!
//! **Deliberately NOT a gate criterion: `size_now` or `org_size` against any
//! ceiling.** [`ZooSalvage::max_whole_entry`] is where that lives, applied
//! by `annotate_candidates` before [`ZooSalvage::verify`] is ever called —
//! see that method for why a scanner that checks a size itself and
//! `?`-propagates the failure reintroduces the defect three fix rounds of
//! Task 3c chased.
//!
//! # `dir_crc` as the second signal
//!
//! Every type-2 record carries a CRC-16/ARC over itself with its own
//! checksum field zeroed (`portable.c`'s `dir_to_b`). `zoo.rs`'s reader
//! surfaces a mismatch as [`stuffr_core::Fidelity::DirectoryRecordChecksum`]
//! and never enforces it, because zoo itself treats a bad one as advisory.
//! A SCANNER can use it for something a reader cannot: as evidence that a
//! sighting is a real record at all.
//!
//! It is used to WIDEN acceptance, never to narrow it, and only over the
//! name: a record whose own checksum reproduces is real whatever its 13-byte
//! DOS name field decodes to — a CP437 name with high-bit characters is
//! exactly the shape a floppy-era archive carries and exactly the shape
//! [`name_looks_real`] refuses. Narrowing on it instead (demanding the CRC
//! verify) would refuse a record damaged in its own header, which is the
//! archive a caller reached for salvage to rescue.
//!
//! The name being NON-EMPTY stays mandatory under both arms, and that is
//! what keeps the terminator out: `zooadd.c` writes the trailing record as a
//! zeroed struct with a correct `dir_crc`, so the checksum arm alone would
//! report it as an entry with no name and no content.
//! `the_terminator_is_not_reported_as_an_entry` pins it. The terminator is
//! deliberately NOT excluded by `next == 0`, which is how `zoo.rs`'s reader
//! recognises it: a real record whose `next` was zeroed by damage is the
//! motivating reproducer for this whole verb, and dropping it would lose the
//! one entry salvage exists to recover.
//!
//! # Verification reuses `zoo.rs`'s own decoders, never a second stack
//!
//! [`ZooSalvage::verify`] re-reads the record at the candidate's own offset,
//! dispatches through [`Method::from_byte`] — the SAME capability gate
//! `zoo.rs`'s container applies — and hands the payload to [`decode`], the
//! identical whole-buffer decoder [`super::zoo`]'s reader calls. ZOO decodes
//! an entry whole (its CRC-16 covers the entire decoded entry and neither
//! the LZW nor the LH5 layer has a streaming form here), so the decoded
//! buffer is handed to Task 1's [`crate::salvage_verify::stream_verify`]
//! wrapped in a [`std::io::Cursor`] — which is what decides
//! [`SalvageStatus`] (length agreement, then the CRC-16/ARC comparison)
//! rather than a second hand-rolled comparison.
//!
//! **[`SalvageStatus::Complete`] is unreachable for ZOO, and that is a
//! contract, not an accident.** `Complete` means the format offers NO
//! checksum at all to prove a payload with (tar, cpio, ar). Every ZOO entry
//! carries a CRC-16 the format mandates, so a candidate this build did not
//! or could not check is [`SalvageStatus::Unverified`] — a tier carries a
//! decision, a message carries a cause.
//!
//! # A deleted record IS reported, and it carries a marker (Ruling S-R)
//!
//! `zoo d` marks an entry `deleted = 1` and leaves it, payload and all, in
//! the file; `zoolist.c` does not list it and `zoo x` does not extract it,
//! and `zoo.rs`'s reader follows that exactly. This scanner does not, and
//! the asymmetry is deliberate: the bytes are present and recoverable, the
//! flag is ONE BYTE — so in a damaged archive a flipped bit turns a live
//! entry into one no ordinary verb will ever hand back — and this project's
//! own second-commonest defect is an entry lost silently. Salvage is the one
//! recovery-biased verb; a deleted record is precisely the content the
//! ordinary reader will not give back.
//!
//! **Reporting it was right and reporting it BARE was not**, which is fix
//! round 1's reframing of the question. Everywhere else salvage accepts less
//! than an ordinary entry it says so on the artifact or in the row: a
//! `Partial` lands as `NAME.partial` and never under its real name, a second
//! record under a taken name lands as `NAME.salvaged-N`, a proven copy
//! prints `[shadowed]`. A deleted record reported `Intact` under its real
//! name at exit 0 was the single place that leniency was invisible — four
//! verbs call the archive empty and the fifth writes the file, with nothing
//! telling a user which it was. The candidate now carries
//! [`Candidate::marked_deleted`], the CLI row prints
//! `[deleted: the archive marks this entry removed]`, and **the exit code
//! does not move**: recovering a deleted record is this verb working as
//! designed, not degraded fidelity.
//! `a_deleted_record_is_reported_and_annotated` pins both halves.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use stuffr_core::salvage::{
    Candidate, SalvageOutcome, SalvagePolicy, SalvageScan, SalvageStatus, SalvagedEntry,
    UnverifiedCause, Verifier, salvage_all, stream_bounded_copy,
};
use stuffr_core::{EntryKind, EntryMeta, Error, FormatId, Result, SeekRead};

use super::zoo::{
    DirEntry, MAX_ZOO_ENTRY_LEN, Method, SIZ_FLDR, ZOO_TAG, decode, read_dir_entry, zoo_mtime,
};

/// The four bytes a directory entry opens with, little-endian [`ZOO_TAG`].
/// Derived from `zoo.rs`'s own constant rather than written out again, so
/// the two cannot drift.
const TAG_BYTES: [u8; 4] = ZOO_TAG.to_le_bytes();

/// Bytes read per [`find_next_tag`] chunk. O(1) memory regardless of how far
/// the next tag is, or whether there is one at all — same figure, same
/// reasoning, as `zip_salvage.rs`'s and `arc_salvage.rs`'s own `SCAN_CHUNK`.
const SCAN_CHUNK: usize = 64 * 1024;

/// Scans a ZOO archive for directory records directly, without following the
/// chain of absolute offsets that a damaged archive's own damage may be in.
///
/// Carries no state between calls beyond what [`SalvageScan::next_candidate`]
/// itself receives — the same shape `ZipSalvage` and `ArcSalvage` have.
#[derive(Debug, Default)]
pub struct ZooSalvage;

impl ZooSalvage {
    pub fn new() -> Self {
        Self
    }
}

impl SalvageScan for ZooSalvage {
    fn next_candidate(&mut self, src: &mut dyn SeekRead, from: u64) -> Result<Option<Candidate>> {
        let file_len = src.seek(SeekFrom::End(0))?;
        let mut search_from = from;
        loop {
            let Some(offset) = find_next_tag(src, search_from, file_len)? else {
                return Ok(None);
            };
            match read_candidate_at(src, offset, file_len) {
                Some(candidate) => return Ok(Some(candidate)),
                // The tag matched and the gate rejected everything behind
                // it: a coincidence, not a record. Resume one byte past the
                // tag itself, not past a whole fixed record, so a genuine
                // record overlapping this false match is never skipped.
                None => search_from = offset + 1,
            }
        }
    }

    /// ZOO decodes an entry WHOLE — `zoo.rs`'s own module doc records that
    /// its CRC-16 covers the entire decoded entry and neither the LZW nor
    /// the LH5 layer has a streaming form here — so a candidate's declared
    /// length really does become one allocation, unlike zip, which streams
    /// every payload it verifies through a `take` and declares no ceiling of
    /// its own.
    ///
    /// [`MAX_ZOO_ENTRY_LEN`] is the identical 256 MiB figure `zoo.rs`'s own
    /// `read_payload` enforces, read from that module rather than restated.
    ///
    /// **Declaring it HERE is what makes it a per-entry refusal.**
    /// `annotate_candidates` reads this figure, answers
    /// [`UnverifiedCause::OverEntryCeiling`] above it, and never calls
    /// [`Self::verify`] for such a candidate — so nothing is read and
    /// nothing is allocated, and one oversized entry can never abort a run
    /// and discard every entry already recovered. `arc_salvage.rs`'s own
    /// `max_whole_entry` carries what the `Err`-raising shape this replaced
    /// measured at the CLI.
    fn max_whole_entry(&self) -> u64 {
        MAX_ZOO_ENTRY_LEN
    }

    fn verify(&self, src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
        verify_candidate(src, candidate)
    }
}

/// Searches forward from `from` for the next four-byte [`TAG_BYTES`] match,
/// in bounded chunks so memory use does not depend on how far through the
/// source the next one is.
///
/// Carries at most three bytes across a chunk boundary — the longest a
/// four-byte match can straddle — so a match split across two reads is never
/// missed. `Ok(None)` when no tag remains before `file_len`.
fn find_next_tag(src: &mut dyn SeekRead, from: u64, file_len: u64) -> io::Result<Option<u64>> {
    if from >= file_len {
        return Ok(None);
    }
    src.seek(SeekFrom::Start(from))?;

    let mut window: Vec<u8> = Vec::with_capacity(SCAN_CHUNK + 3);
    let mut window_start = from;
    let mut buf = vec![0u8; SCAN_CHUNK];

    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        window.extend_from_slice(&buf[..n]);

        if let Some(at) = window
            .windows(TAG_BYTES.len())
            .position(|w| w == TAG_BYTES.as_slice())
        {
            return Ok(Some(window_start + at as u64));
        }

        // Keep only the last 3 bytes: the longest prefix of the tag that
        // could still be waiting for its remaining bytes in the next chunk.
        let keep = window.len().saturating_sub(3);
        window_start += keep as u64;
        window.drain(..keep);
    }
}

/// Whether a record's decoded name looks like real header data rather than
/// whatever bytes happened to follow a coincidental tag match.
///
/// [`read_dir_entry`]'s own name decode is LOSSY by design, and stores the
/// name verbatim: a container reading trusted-enough bytes must not reject a
/// name for its own sake, since refusing a hostile name is the ops layer's
/// job and a container that rewrote one would destroy the evidence that
/// refusal depends on (container-conformance property 12). Salvage is
/// scanning UNTRUSTED bytes, so this applies a stricter, PURELY LOCAL check
/// — it changes nothing about what `read_dir_entry` returns, only what THIS
/// module treats as further evidence: every byte a printable ASCII character
/// (`0x20..=0x7E`).
///
/// **Emptiness is checked by the caller, not here**, because the two facts
/// are used differently: a non-empty name is mandatory under both arms of
/// the gate's criterion 4 (it is what keeps the zeroed terminator out),
/// while printability is the half a verifying `dir_crc` is allowed to
/// substitute for. Folding them together here would have made a valid
/// `dir_crc` able to admit a nameless record.
fn name_looks_real(name: &str) -> bool {
    name.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// Whether this record carries enough evidence to be treated as real rather
/// than as a coincidental four-byte match — the gate's criterion 4.
///
/// See this module's doc for why `dir_crc` widens acceptance over the NAME
/// alone and never narrows it, and why non-emptiness survives both arms.
fn record_looks_real(header: &DirEntry) -> bool {
    if header.name.is_empty() {
        return false;
    }
    if name_looks_real(&header.name) {
        return true;
    }
    // `dir_crc_mismatch` is `None` both for a record whose checksum
    // reproduces AND for a type-0/1 record, which carries no such field at
    // all — so the record length is checked too, or "has no checksum" would
    // read as "its checksum verified".
    header.fixed_len == super::zoo::SIZ_DIRL && header.dir_crc_mismatch.is_none()
}

/// Maps a ZOO packing-method byte to the [`FormatId`] [`EntryMeta::codec`]
/// carries for it.
///
/// Derives from [`Method::from_byte`] and [`Method::codec`] rather than
/// hand-copying the mapping a second time — see [`Method::codec`]'s own doc.
/// `None` for a byte past `MAX_PACK`, which the discovery gate has already
/// rejected, so this is a backstop rather than a reachable answer.
///
/// **Populating [`EntryMeta::codec`] at all is load-bearing**, and it is the
/// gap ARC shipped with in Task 3: `entries.rs`'s salvage write dispatch
/// reads this field to decide how to decode, and a candidate that leaves it
/// `None` makes every entry a silent `SalvageDisposition::SkippedNotBuiltIn`
/// — a real scanner that quietly writes nothing.
fn codec_for_zoo_method(method_byte: u8) -> Option<FormatId> {
    Method::from_byte(method_byte, "").ok().map(Method::codec)
}

/// Maps [`EntryMeta::codec`] (as [`codec_for_zoo_method`] filled it) back to
/// the [`Method`] [`decode`] dispatches on.
///
/// Searches [`Method::all`] for the variant whose [`Method::codec`] matches,
/// rather than hand-copying the same three strings in the opposite
/// direction. `Method::all` is generated from an exhaustive `match`, so a
/// fourth decodable method cannot be added without `zoo.rs` failing to
/// compile — the difference between a documented convention and an enforced
/// one.
fn method_for_codec(codec: Option<FormatId>) -> Option<Method> {
    let codec = codec?;
    Method::all().find(|method| method.codec() == codec)
}

/// Reads the record believed to start at `offset` and runs it through the
/// gate described in this module's doc.
///
/// `None` for ANY gate failure — including the record itself running past
/// `file_len`, which means there was never a full record to read in the
/// first place. A rejection here is never an error: see the module doc.
/// [`read_dir_entry`]'s own `Err`s (a tag that does not match, a `type`
/// above 2, a variable part that runs off the end of the file, a genuine
/// read failure) all mean the same thing to a SCANNER — these bytes are not
/// a record — so they fold here rather than propagating and ending a run
/// over one coincidence.
fn read_candidate_at(src: &mut dyn SeekRead, offset: u64, file_len: u64) -> Option<Candidate> {
    let header = read_dir_entry(src, offset).ok()?;
    if header.method_byte > Method::MAX_PACK {
        return None;
    }
    if !record_looks_real(&header) {
        return None;
    }

    // Built with `checked_add`, like every other offset computation in this
    // crate's scanners. `offset` is a scanner-discovered tag position and
    // the record is at most 56 + 65_535 + 5 bytes, so overflow is not
    // reachable on any real archive — but a candidate whose arithmetic
    // overflows is refused the same way every other malformed one is:
    // `None`, never a panic or a wrapped value.
    let payload_start = offset
        .checked_add(header.record_len)
        .and_then(|v| v.checked_add(SIZ_FLDR))?;

    let declared = u64::from(header.size_now);
    let available_len = match payload_start.checked_add(declared) {
        Some(end) if end <= file_len => None,
        // Either the declared end overflows `u64`, or it runs past the
        // source. Both mean the same thing to a reader: fewer bytes are
        // present than the header promises.
        _ => {
            let present = file_len.saturating_sub(payload_start);
            // `Some(n)` ALWAYS means `n < declared_len`, per the field's own
            // contract. A zero-length payload whose position is itself past
            // the end of the file would otherwise report `Some(0)` against a
            // declared `0` and claim a truncation that is not one.
            (present < declared).then_some(present)
        }
    };

    let mut meta = EntryMeta::file(header.name.clone());
    meta.size = Some(u64::from(header.org_size));
    meta.compressed_size = Some(declared);
    meta.kind = EntryKind::File;
    meta.mtime = zoo_mtime(header.packed_datetime);
    meta.codec = codec_for_zoo_method(header.method_byte);

    Some(Candidate {
        offset,
        payload_start,
        meta,
        declared_len: Some(declared),
        verifier: Some(Verifier::Crc16(header.crc16)),
        available_len,
        // Ruling S-R. Reported, not dropped — and ANNOTATED, which is the
        // half a review had to add: see this module's own section below and
        // `Candidate::marked_deleted`'s doc.
        marked_deleted: header.deleted,
    })
}

/// Decides [`SalvageStatus`] for one candidate by re-reading its record,
/// decoding its payload through `zoo.rs`'s own [`decode`], and comparing the
/// result against the candidate's [`Verifier::Crc16`] via Task 1's shared
/// [`crate::salvage_verify::stream_verify`].
///
/// **Never returns `Err`, for any input.** Malformed, truncated and
/// genuinely I/O-failing input all fold into [`SalvageStatus::Partial`] or
/// an [`UnverifiedCause`], the discipline `zip_salvage.rs`'s and
/// `arc_salvage.rs`'s own `verify_candidate` document at length: an `Err`
/// out of `verify` aborts the WHOLE run and discards every entry already
/// recovered, which is the one thing this verb exists not to do. The
/// `Result` in the signature is the trait's, kept so a scanner CAN report a
/// genuine whole-run fault; this implementation has none to report.
///
/// # The second declared length, and why it needs its own answer here
///
/// `annotate_candidates` bounds `declared_len` — ZOO's `size_now`, the
/// COMPRESSED length — against [`ZooSalvage::max_whole_entry`] before this
/// runs, so the payload buffer below needs no check of its own. `org_size`
/// is a SECOND, independent `u32` the engine never sees (it reaches
/// [`EntryMeta::size`] and nothing the engine compares), and [`decode`]'s
/// LH5 arm sizes its output buffer from it: left unbounded that is a 4 GiB
/// allocation from a header field.
///
/// It is answered as a per-entry [`UnverifiedCause::OverEntryCeiling`],
/// **never** as an `Err` and never as a check on the figure the engine
/// already owns. That distinction is the whole lesson of Task 3c's three fix
/// rounds: what they deleted was three checks on ONE quantity under two
/// owners, each able to abort a run. This is a different quantity, with one
/// owner, and its refusal is a status — so it cannot cost the entries
/// around it.
///
/// # The bound belongs to the ARM that allocates, not to the entry
///
/// Fix round 1's HIGH finding, and the reason this section exists rather
/// than the paragraph above standing alone. The check first shipped
/// unconditional, for all three methods — and only [`Method::Lh5`]
/// allocates from `org_size`. [`Method::Stored`] copies the payload;
/// [`Method::Lzw`] grows its own output under `zoo.rs`'s `guard_output`.
/// Measured at the CLI on `store.zoo` with `org_size` alone corrupted to
/// `0xAAAA_AAAA` and its `dir_crc` refreshed, so all 11,357 stored bytes
/// are present and byte-identical to the healthy fixture:
///
/// ```text
/// $ stuffr salvage bigorg.zoo --list
/// 0    Unverified (over the ceiling)    license [needs 2863311530 bytes; …]
/// exit=3
/// $ stuffr salvage bigorg.zoo -C out      # out/ is EMPTY
/// salvage -> 1 scanned: 0 written, …, 1 unverified, …
/// exit=3
/// ```
///
/// `entries.rs`'s `place_salvaged_file` never writes an `Unverified` entry,
/// so one corrupted four-byte field cost a completely recoverable payload —
/// in the verb that exists for exactly that archive. Gated on the LH5 arm
/// the same record is `Partial`, and `license.partial` holds all 11,357
/// bytes at exit 4.
///
/// **`org_size` has no "bounded" counterpart the way `size_now` does**, and
/// that is worth stating rather than leaving as an apparent exception to
/// `annotate_candidates`'s "the bounded length, never the declared one"
/// rule. `size_now` describes a byte range in the FILE, so
/// [`Candidate::available_len`] can say how much of it is really there;
/// `org_size` describes the DECODED length, which no byte range bounds. The
/// figure compared is therefore necessarily the declared one — and that is
/// sound here precisely because it is not a proxy for anything: it is
/// literally the length `lh5_decode` is about to pass to `vec![0u8; _]`. A
/// truncated candidate never reaches this comparison at all; it returned
/// `Partial` at this function's first line.
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
        // never means — ZOO always carries a checksum.
        return Ok(SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength));
    };
    let Some(Verifier::Crc16(expected_crc)) = candidate.verifier else {
        // Likewise unreachable: `read_candidate_at` gives every ZOO
        // candidate a `Verifier::Crc16`, because the format mandates one.
        //
        // `NoDeclaredLength` is the NEAREST cause this enum offers and not
        // an accurate one — a length was declared; a checksum was not — and
        // saying so is better than either inventing a variant for a branch
        // nothing reaches or answering `Complete`, which would claim the
        // format has no checksum to offer when ZOO's whole point here is
        // that it does. All three `Unverified` causes lead to the same
        // decision (listed, not written, exit 3), so the tier is right even
        // where the message would be imprecise; see `UnverifiedCause`'s own
        // doc, "a tier carries a decision, a message carries a cause".
        return Ok(SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength));
    };

    let Ok(header) = read_dir_entry(src, candidate.offset) else {
        // The record parsed at discovery, so this is a genuine source
        // failure rather than a shape change — one entry's problem.
        return Ok(SalvageStatus::Partial);
    };

    let method = match Method::from_byte(header.method_byte, &header.name) {
        Ok(method) => method,
        // Unreachable through the gate (criterion 3 already refused a byte
        // past `MAX_PACK`), but the honest answer if a future method byte is
        // recognised without being decodable: the format DOES carry a
        // checksum here, this build simply never attempted to check it.
        // `Unverified`, never `Complete`.
        Err(_) => {
            return Ok(SalvageStatus::Unverified(
                UnverifiedCause::UndecodableMethod,
            ));
        }
    };

    let org_size = u64::from(header.org_size);
    // **Only the arm that allocates from this field is bounded by it.** See
    // this function's doc for the whole rule, and fix round 1 (HIGH) for
    // what applying it to all three methods cost: a `Stored` entry whose
    // 11,357 bytes were all present, and whose method never reads
    // `org_size` for an allocation at all, was reported `Unverified (over
    // the ceiling)` and written nowhere.
    if method == Method::Lh5 && org_size > MAX_ZOO_ENTRY_LEN {
        return Ok(SalvageStatus::Unverified(
            UnverifiedCause::OverEntryCeiling {
                needed: org_size,
                ceiling: MAX_ZOO_ENTRY_LEN,
            },
        ));
    }

    // `declared_len` is already at or below `MAX_ZOO_ENTRY_LEN`:
    // `annotate_candidates` answers `Unverified(OverEntryCeiling)` itself,
    // without calling this function at all, for anything above it. That is
    // `SalvageScan::verify`'s own documented contract, and it is why there
    // is no ceiling check on this figure here.
    if src.seek(SeekFrom::Start(candidate.payload_start)).is_err() {
        return Ok(SalvageStatus::Partial);
    }
    let mut payload = vec![0u8; declared_len as usize];
    if src.read_exact(&mut payload).is_err() {
        return Ok(SalvageStatus::Partial);
    }

    let decoded = match decode(method, &payload, &header.name, header.org_size) {
        Ok(decoded) => decoded,
        // A decode failure (malformed compressed data, or `zoo.rs`'s own
        // LZW output ceiling) is exactly as unproven as a checksum that
        // disagrees — `Partial`, not a second `Err` path.
        Err(_) => return Ok(SalvageStatus::Partial),
    };

    Ok(crate::salvage_verify::stream_verify(
        io::Cursor::new(decoded),
        org_size,
        &Verifier::Crc16(expected_crc),
    ))
}

/// Reads one entry's stored payload and writes its RECOVERED (decoded) bytes
/// to `out`. Returns whether the decode reached the entry's own declared
/// length ([`EntryMeta::size`]) — `entries.rs`'s own signal for
/// `PartialCause`, matching `zip_salvage.rs`'s and `arc_salvage.rs`'s
/// `write_payload` exactly.
///
/// Uses [`SalvagedEntry::payload_start`] directly, computed once by
/// [`read_candidate_at`] at discovery — see that field's own doc for why a
/// consumer must never re-derive a payload's location from `offset`.
///
/// An entry reaching this function was already reported `Intact` or
/// `Partial` by [`verify_candidate`] — never `Unverified`, which
/// `entries.rs`'s `place_salvaged_file` refuses before calling any payload
/// writer. So a decode that fails here is re-running bytes
/// `verify_candidate` already examined (or a genuine prefix of them), and is
/// folded into `Ok(false)` for the same reason that function folds the same
/// failures into `Partial`: one entry's damage must never abort the recovery
/// of every other entry in the archive.
///
/// # Both declared lengths are bounded by what is PRESENT, before anything
/// is sized from either
///
/// `arc_salvage.rs`'s fix rounds 1 and 2 are inherited rather than
/// rediscovered. A `Partial` entry reaches this function having been
/// reported `Partial` at [`verify_candidate`]'s very first line, so its
/// header's declarations have been bounded by nothing at that point:
///
/// - the compressed read is bounded by the SOURCE's own remaining length
///   (`available` below, from a fresh `seek(End(0))`), so a truncated
///   entry's genuine surviving prefix reaches [`decode`] and is written
///   rather than the whole `read_exact` failing and nothing being written;
/// - what is genuinely PRESENT can itself still exceed the ceiling, and that
///   is folded into `Ok(false)`, never propagated;
/// - `org_size` is bounded too — **on the LH5 arm alone**, because that is
///   the only arm of [`decode`] that sizes a buffer from it. See
///   [`verify_candidate`]'s own doc for the field, and fix round 1 (HIGH)
///   for what bounding all three arms by it cost.
///
/// Through `stuffr::entries::salvage` the ceiling branches are unreachable
/// (the engine's own `max_whole_entry` refuses such an entry before any
/// writer is called). They are kept because this function is `pub`: a direct
/// caller supplying its own [`SalvagedEntry`] gets the bound too.
pub fn write_payload(
    archive_path: &Path,
    entry: &SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
) -> Result<bool> {
    write_payload_bounded(archive_path, entry, compressed_len, out, MAX_ZOO_ENTRY_LEN)
}

/// [`write_payload`]'s whole body, parameterised over the ceiling it refuses
/// an oversized read against.
///
/// Split out purely so a unit test can exercise the fold-into-`Ok(false)`
/// behaviour with a SMALL ceiling and a small fixture, rather than needing a
/// 256 MiB file to reach the real [`MAX_ZOO_ENTRY_LEN`] — which would make
/// it the single most expensive thing in a gate that already runs 35-60s,
/// twice, for a branch whose own logic is one comparison.
fn write_payload_bounded(
    archive_path: &Path,
    entry: &SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
    ceiling: u64,
) -> Result<bool> {
    // Refused BEFORE `archive_path` is opened, which `entries.rs`'s own
    // `salvage_seam_tests::every_salvage_slot_reaches_a_real_payload_writer`
    // relies on: it probes every slot with a codec-less entry and a path
    // that does not exist.
    let Some(method) = method_for_codec(entry.meta.codec) else {
        return Err(Error::Unsupported(format!(
            "entry `{}` carries codec {:?}, which this build's salvage writer does not \
             decode (every ZOO method past `zoo.h`'s MAX_PACK is already refused at \
             discovery, so this is a backstop rather than a reachable answer)",
            entry.meta.name, entry.meta.codec
        )));
    };

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
    if readable_len > ceiling {
        return Ok(false);
    }

    let expected = entry.meta.size.unwrap_or(readable_len);
    // Bounded on the LH5 arm ALONE, the twin of `verify_candidate`'s own
    // check and for the same reason: `decode`'s LH5 arm sizes
    // `vec![0u8; org_size]` from this figure and the other two arms never
    // read it. Fix round 1 (HIGH): applying it to all three refused a
    // `Stored` entry whose bytes were entirely present, writing nothing.
    if method == Method::Lh5 && expected > ceiling {
        return Ok(false);
    }
    // Saturating rather than refusing, because for `Stored` and `Lzw` this
    // value is passed to `decode` and never read — only the LH5 arm reads
    // it, and the comparison above has already bounded that arm well inside
    // a `u32`. Refusing here instead would reintroduce the same defect one
    // line down: a `Stored` entry declaring an absurd `org_size` would go
    // unwritten for a figure its own method ignores.
    let org_size = u32::try_from(expected).unwrap_or(u32::MAX);

    // Decided from the two lengths alone, BEFORE the read: if fewer
    // compressed bytes are present than the header declared, this entry's
    // payload is truncated, full stop, regardless of what
    // `stream_bounded_copy` goes on to report against a declared `org_size`
    // small enough that a partial decode still satisfies it
    // (`arc_salvage.rs`'s fix round 2, NEW-1 — a message must not contradict
    // the reason the entry is `Partial` in the first place).
    let truncated = readable_len < compressed_len;

    let mut payload = vec![0u8; readable_len as usize];
    if f.read_exact(&mut payload).is_err() {
        // A genuine race (the archive changed on disk between the scan and
        // this write) rather than a length mismatch, which `readable_len`
        // has already ruled out.
        return Ok(false);
    }

    let decoded = match decode(method, &payload, &entry.meta.name, org_size) {
        Ok(decoded) => decoded,
        // Malformed or genuinely truncated compressed data. ZOO's two
        // compressed methods decode whole, so a mid-stream cut has no
        // defined partial result; `Stored` recovers its prefix.
        Err(_) => return Ok(false),
    };

    let completed = stream_bounded_copy(io::Cursor::new(decoded), expected, out)?;
    Ok(completed && !truncated)
}

/// Runs [`ZooSalvage`] over `src` and annotates the result — the whole
/// scanner, matching `zip_salvage.rs`'s `salvage_zip` and
/// `arc_salvage.rs`'s `salvage_arc` entry points exactly (`entries.rs`'s
/// `salvage_scan` dispatches to all three the same way). Like ARC and unlike
/// zip there is no second index to reconcile against: ZOO's directory is a
/// chain, not a table, and the raw scan is the only source there is.
pub fn salvage_zoo(src: &mut dyn SeekRead, policy: &SalvagePolicy) -> Result<SalvageOutcome> {
    let mut scanner = ZooSalvage::new();
    salvage_all(&mut scanner, src, policy)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::super::zoo::test_archives::{Spec, build_zoo};
    use super::*;

    const STORE_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/store.zoo");
    const DEFAULT_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/default.zoo");
    const HIGH_PER_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/high_per.zoo");
    const WRONGCRC16_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/wrongcrc16.zoo");

    /// Where `build_zoo` puts its first directory record: straight after the
    /// 42-byte `SIZ_ZOOH` archive header it writes. Named once rather than
    /// spelled `42` at each site — the builder's own `assert_eq!(out.len(),
    /// 42, "SIZ_ZOOH")` is what keeps the two in step.
    const FIRST_RECORD: usize = 42;

    /// `zoo.h`'s `SIZNOW_I 24` within a directory record — the compressed
    /// length, which several tests below raise to a lie.
    const SIZE_NOW_I: usize = 24;

    fn scan(bytes: &[u8]) -> SalvageOutcome {
        salvage_zoo(&mut Cursor::new(bytes.to_vec()), &SalvagePolicy::default())
            .expect("a salvage scan must not error over any input")
    }

    // -------------------------------------------------------------------
    // The anti-vacuity pair (Step 2)
    // -------------------------------------------------------------------

    /// A small linear congruential generator, not the `rand` crate — the
    /// corpus must be byte-identical on every machine and in CI. Same
    /// constants (Knuth & Lewis, via Numerical Recipes) `zip_salvage.rs` and
    /// `arc_salvage.rs` use, for the same reason: nothing cryptographic is
    /// needed, only enough uniformity to make a coincidence rare.
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

    /// Fixed offsets, each with lots of room after it, where only the four
    /// TAG bytes are forced — the type, method, name and everything else
    /// stays whatever the LCG produced. A four-byte tag's own chance of
    /// landing anywhere in a 1 MiB buffer is about one in four thousand, so
    /// seeding them directly is what makes this corpus a real test of the
    /// criteria BEHIND the tag rather than of luck.
    const SEEDED_TAG_OFFSETS: [usize; 6] = [65_536, 196_608, 344_064, 491_520, 638_976, 786_432];

    /// A seventh splice, distinct from the bare-tag ones above: a complete,
    /// otherwise gate-clearing ZOO archive (a real tag, a type-2 record, a
    /// printable name, a correct `dir_crc`, a payload that fits) whose ONLY
    /// defect is `method = 200` — a value past `zoo.h`'s `MAX_PACK`. This is
    /// what ties Step 6's falsification of the method check to a SPECIFIC
    /// position rather than to a hand-rolled unit test elsewhere that could
    /// pass or fail for unrelated reasons.
    const METHOD_ONLY_DEFECT_OFFSET: usize = 500_000;

    fn method_only_defect() -> Vec<u8> {
        let mut spec = Spec::stored("OK.TXT", b"");
        spec.method = 200;
        build_zoo(&[spec])
    }

    fn noise_with_seeded_tags(len: usize) -> Vec<u8> {
        let mut noise = deterministic_noise(len);
        for &at in &SEEDED_TAG_OFFSETS {
            noise[at..at + 4].copy_from_slice(&TAG_BYTES);
        }
        let defect = method_only_defect();
        noise[METHOD_ONLY_DEFECT_OFFSET..METHOD_ONLY_DEFECT_OFFSET + defect.len()]
            .copy_from_slice(&defect);
        noise
    }

    /// The negative double for the whole feature: a scanner that reported
    /// every tag sighting as an entry would be worse than no scanner at all.
    #[test]
    fn zoo_salvage_over_random_bytes_finds_nothing() {
        let noise = noise_with_seeded_tags(1 << 20); // 1 MiB, fixed seed
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
    /// contain no tag at all — proving nothing about the validation gate.
    /// This asserts the gate is what rejects the hits, not their absence.
    #[test]
    fn the_zoo_noise_corpus_really_does_contain_the_tag() {
        let noise = noise_with_seeded_tags(1 << 20);
        let hits = noise
            .windows(4)
            .filter(|w| *w == TAG_BYTES.as_slice())
            .count();
        // The six deliberately seeded tags, plus the spliced archive's own
        // header tag, its record's and its terminator's — nine. `>=` rather
        // than `==`: this does not also assert the LCG produces no
        // INCIDENTAL tag of its own, which would only be one more
        // coincidence for the gate to reject.
        let seeded = SEEDED_TAG_OFFSETS.len() + 3;
        assert!(
            hits >= seeded,
            "expected at least the {seeded} deliberately placed tags, found {hits}"
        );
    }

    /// Isolates `METHOD_ONLY_DEFECT_OFFSET`'s own archive to prove it clears
    /// every OTHER criterion — so deleting the method check is really what
    /// the falsification in the task report exercises, not some other defect
    /// in the crafted bytes.
    #[test]
    fn the_method_only_defect_is_rejected_by_the_method_check_alone() {
        assert!(
            scan(&method_only_defect()).entries.is_empty(),
            "a method past `zoo.h`'s MAX_PACK must be rejected"
        );
        // The identical archive with a method the format assigned IS found,
        // which is what makes the assertion above about the method byte.
        let mut spec = Spec::stored("OK.TXT", b"");
        spec.method = 0;
        assert_eq!(scan(&build_zoo(&[spec])).entries.len(), 1);
    }

    // -------------------------------------------------------------------
    // The positive complement: a scanner that always returned `Ok(None)`
    // would also pass the anti-vacuity pair trivially.
    // -------------------------------------------------------------------

    #[test]
    fn salvage_finds_every_entry_in_a_built_archive() {
        let bytes = build_zoo(&[
            Spec::stored("ONE.TXT", b"hello, zoo"),
            Spec::stored("TWO.TXT", b"aaaaaaaaaaaaaaaaaaaa"),
        ]);
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 2);
        assert_eq!(out.entries[0].meta.name, "ONE.TXT");
        assert_eq!(out.entries[1].meta.name, "TWO.TXT");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
        assert_eq!(out.entries[1].status, SalvageStatus::Intact);
    }

    /// Every borrowed fixture — one stored, one `lzd` LZW, one LH5 — reaches
    /// `Intact` through this scanner, which means the record layout, the
    /// structural payload arithmetic, the method dispatch and the CRC-16
    /// comparison all have to be right at once over bytes no code in this
    /// project produced.
    #[test]
    fn every_borrowed_fixture_salvages_intact() {
        for (bytes, label) in [
            (STORE_ZOO, "store.zoo"),
            (DEFAULT_ZOO, "default.zoo"),
            (HIGH_PER_ZOO, "high_per.zoo"),
        ] {
            let out = scan(bytes);
            assert_eq!(out.entries.len(), 1, "{label}");
            assert_eq!(out.entries[0].meta.name, "license", "{label}");
            assert_eq!(out.entries[0].status, SalvageStatus::Intact, "{label}");
            assert_eq!(out.entries[0].meta.size, Some(11_357), "{label}");
        }
    }

    /// The negative twin from the same borrowed corpus: correct bytes, one
    /// wrong recorded CRC-16. `Partial`, never `Intact` and never
    /// `Complete` — something WAS checked and it did not hold.
    #[test]
    fn the_wrong_crc_fixture_salvages_as_partial() {
        let out = scan(WRONGCRC16_ZOO);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
    }

    /// **The 56-versus-59 discriminator, and the permanent form of Step 6's
    /// falsification.**
    ///
    /// This scanner computes a payload's position STRUCTURALLY — record
    /// start plus `record_len` plus [`SIZ_FLDR`] — while the record itself
    /// declares an absolute `offset`, written decades ago by zoo 2.10 with
    /// no knowledge of this project. The two must agree byte-exactly on
    /// every borrowed fixture.
    ///
    /// Under `unarc-rs`'s 59-byte model they cannot: the fixed record is
    /// modelled three bytes too long, so every structural position lands
    /// three bytes past the payload's real start, and (since every fixture
    /// holds exactly one entry whose payload runs to the end of the file)
    /// the last three declared bytes fall off the end — a healthy archive
    /// reported truncated. The task report records that run.
    #[test]
    fn the_structural_payload_position_agrees_with_the_records_own_offset_field() {
        for (bytes, label) in [
            (STORE_ZOO, "store.zoo"),
            (DEFAULT_ZOO, "default.zoo"),
            (HIGH_PER_ZOO, "high_per.zoo"),
            (WRONGCRC16_ZOO, "wrongcrc16.zoo"),
        ] {
            let mut cursor = Cursor::new(bytes.to_vec());
            let candidate = ZooSalvage::new()
                .next_candidate(&mut cursor, 0)
                .unwrap()
                .unwrap_or_else(|| panic!("{label}: the first record must clear the gate"));
            let declared = read_dir_entry(&mut Cursor::new(bytes.to_vec()), candidate.offset)
                .unwrap_or_else(|_| panic!("{label}: the record parses"))
                .offset;
            assert_eq!(
                candidate.payload_start,
                u64::from(declared),
                "{label}: the structural payload position (record + record_len + SIZ_FLDR) \
                 must equal the absolute `offset` the archive's own record declares — a \
                 59-byte fixed record puts it exactly three bytes late"
            );
            // Every borrowed fixture is type 2, which is why this proves
            // nothing about the 51-byte type-0/1 record the scanner also
            // accepts — see this module's own doc. Asserted rather than
            // left implicit, so the day a type-0/1 fixture arrives this
            // test says out loud that its coverage just changed.
            assert_eq!(
                read_dir_entry(&mut Cursor::new(bytes.to_vec()), candidate.offset)
                    .unwrap()
                    .fixed_len,
                super::super::zoo::SIZ_DIRL,
                "{label}: the claim above covers the type-2 record and nothing else"
            );
            assert_eq!(
                candidate.available_len, None,
                "{label}: a healthy fixture's payload is entirely present"
            );
        }
    }

    #[test]
    fn an_ordinary_record_is_accepted() {
        let bytes = build_zoo(&[Spec::stored("HELLO.TXT", b"hi")]);
        let candidate = ZooSalvage::new()
            .next_candidate(&mut Cursor::new(bytes), 0)
            .unwrap()
            .expect("a well-formed record must be accepted");
        assert_eq!(candidate.meta.name, "HELLO.TXT");
        assert_eq!(candidate.declared_len, Some(2));
        assert_eq!(candidate.meta.codec, Some(FormatId::new("zoo-stored")));
        assert!(matches!(candidate.verifier, Some(Verifier::Crc16(_))));
    }

    /// The zeroed trailing record `zooadd.c` writes carries a CORRECT
    /// `dir_crc`, so the checksum arm of criterion 4 alone would admit it as
    /// an entry with no name and no content. The non-empty-name requirement
    /// is what keeps it out — and it is required under BOTH arms for exactly
    /// this reason.
    #[test]
    fn the_terminator_is_not_reported_as_an_entry() {
        let bytes = build_zoo(&[Spec::stored("ONLY.TXT", b"payload")]);
        let out = scan(&bytes);
        assert_eq!(
            out.entries.len(),
            1,
            "the terminator must not be reported alongside the one real entry: {:?}",
            out.entries
                .iter()
                .map(|e| (&e.meta.name, e.offset))
                .collect::<Vec<_>>()
        );
        assert_eq!(out.entries[0].meta.name, "ONLY.TXT");
    }

    /// The terminator is refused for its EMPTY NAME, not for `next == 0` —
    /// which is how `zoo.rs`'s reader recognises it, and which a scanner
    /// must not copy: a real record whose `next` was zeroed by damage is the
    /// motivating reproducer for this whole verb (`zoo.rs`'s
    /// `refuse_a_chain_that_reaches_nothing` doc: four bytes turn an 11 KiB
    /// archive into one that lists nothing at exit 0).
    #[test]
    fn a_real_record_whose_next_link_was_zeroed_is_still_recovered() {
        let mut spec = Spec::stored("SURVIVOR.TXT", b"the reason salvage exists");
        spec.next_override = Some(0);
        let out = scan(&build_zoo(&[spec]));
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].meta.name, "SURVIVOR.TXT");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    // -------------------------------------------------------------------
    // `dir_crc` as the second signal (Step 4)
    // -------------------------------------------------------------------

    /// A CP437-era name with high-bit bytes fails [`name_looks_real`], and a
    /// record whose own checksum reproduces is real anyway. This is the
    /// widening half of criterion 4.
    #[test]
    fn a_non_printable_name_is_accepted_when_the_records_own_crc_reproduces() {
        let mut bytes = build_zoo(&[Spec::stored("NAME.TXT", b"payload")]);
        overwrite_name_and_refresh_dir_crc(&mut bytes, &[0xC4, 0xD9, 0xB3]);
        let out = scan(&bytes);
        assert_eq!(
            out.entries.len(),
            1,
            "a verifying `dir_crc` must admit a record whose name this scanner cannot read"
        );
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
    }

    /// The other half, and what makes the test above about the CHECKSUM
    /// rather than about names in general: the identical record with its
    /// `dir_crc` left stale has neither signal, and is rejected.
    #[test]
    fn a_non_printable_name_with_a_broken_dir_crc_is_rejected() {
        let mut bytes = build_zoo(&[Spec::stored("NAME.TXT", b"payload")]);
        let at = FIRST_RECORD;
        bytes[at + super::super::zoo::FNAME_I..at + super::super::zoo::FNAME_I + 3]
            .copy_from_slice(&[0xC4, 0xD9, 0xB3]);
        // `dir_crc` deliberately NOT refreshed.
        assert!(
            scan(&bytes).entries.is_empty(),
            "neither signal holds, so this is a coincidence as far as the gate can tell"
        );
    }

    /// Overwrites the first record's name field with `raw` and recomputes
    /// that record's own `dir_crc` the way `portable.c`'s `dir_to_b` does —
    /// the field itself zeroed, CRC-16/ARC over `SIZ_DIRL + var_dir_len`
    /// bytes.
    /// Every offset below is `zoo.rs`'s own constant, never a literal — fix
    /// round 1's LOW finding, and the one file where it matters most: the
    /// whole subject here is that `unarc-rs` hand-copied `56` and got it
    /// wrong.
    fn overwrite_name_and_refresh_dir_crc(bytes: &mut [u8], raw: &[u8]) {
        use super::super::crc::crc16_arc;
        use super::super::zoo::{DCRC_I, FNAME_I, FNM_SIZ, SIZ_DIRL, VARDIRLEN_I};
        let at = FIRST_RECORD;
        for b in &mut bytes[at + FNAME_I..at + FNAME_I + FNM_SIZ] {
            *b = 0;
        }
        bytes[at + FNAME_I..at + FNAME_I + raw.len()].copy_from_slice(raw);
        let var_len = usize::from(u16::from_le_bytes([
            bytes[at + VARDIRLEN_I],
            bytes[at + VARDIRLEN_I + 1],
        ]));
        let len = SIZ_DIRL + var_len;
        bytes[at + DCRC_I] = 0;
        bytes[at + DCRC_I + 1] = 0;
        let crc = crc16_arc(&bytes[at..at + len]);
        bytes[at + DCRC_I..at + DCRC_I + 2].copy_from_slice(&crc.to_le_bytes());
    }

    // -------------------------------------------------------------------
    // Truncation, deletion and the ceiling
    // -------------------------------------------------------------------

    /// Criterion "reports rather than rejects", mirroring `zip_salvage.rs`'s
    /// own ruling: a record promising payload the file cannot deliver is
    /// still a record, and dropping it would make a truncated archive's last
    /// entry vanish with no row and exit 0.
    #[test]
    fn a_declared_length_running_past_the_file_is_reported_not_dropped() {
        let bytes = build_zoo(&[Spec::stored("HELLO.TXT", b"hi")]);
        // Cut the file short of the two payload bytes and the terminator.
        let truncated = &bytes[..bytes.len() - 57];
        let out = scan(truncated);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].meta.compressed_size,
            Some(2),
            "the declared figure is reported exactly as the record stated it"
        );
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "and the shortfall is a statement, not silence"
        );
    }

    /// Ruling S-R, both halves. `zoo.rs`'s reader skips a deleted record;
    /// this scanner reports it AND annotates it, because this was the one
    /// place salvage's leniency carried no marker — see this module's doc.
    #[test]
    fn a_deleted_record_is_reported_and_annotated() {
        let mut spec = Spec::stored("GONE.TXT", b"deleted but still here");
        spec.deleted = true;
        let out = scan(&build_zoo(&[spec]));
        assert_eq!(
            out.entries.len(),
            1,
            "a deleted record's payload is still in the file, and salvage is what recovers \
             what the ordinary reader will not"
        );
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
        assert!(
            out.entries[0].marked_deleted,
            "reporting it bare, as an ordinary `Intact` row, is what fix round 1 rejected"
        );
    }

    /// The negative double for the annotation: an ordinary record must never
    /// be marked. Without this, a `marked_deleted` hardcoded to `true` would
    /// satisfy the test above.
    #[test]
    fn an_ordinary_record_is_not_marked_deleted() {
        let out = scan(&build_zoo(&[Spec::stored("LIVE.TXT", b"still here")]));
        assert_eq!(out.entries.len(), 1);
        assert!(!out.entries[0].marked_deleted);
    }

    /// A `Read + Seek` mock that:
    ///  - answers `seek(SeekFrom::End(0))` with a LIE — a huge reported
    ///    length, so the "does the payload fit inside the file" check at
    ///    discovery does not short-circuit this candidate as merely
    ///    truncated (which would return `Partial` without ever reaching the
    ///    ceiling this test exists to exercise);
    ///  - panics if ever asked to `read` more than `max_single_read` bytes
    ///    in one call — the same instrument `zoo.rs`'s own
    ///    `refuses_an_absurd_size_now_before_the_allocation_it_would_size`
    ///    and `arc_salvage.rs`'s `LyingLenPanicsOnBigRead` use, and for the
    ///    same reason: a test asserting only the status passes even when
    ///    `vec![0u8; declared]` was already allocated, which is the entire
    ///    defect this class of test exists to catch.
    struct LyingLenPanicsOnBigRead {
        inner: Cursor<Vec<u8>>,
        reported_len: u64,
        max_single_read: usize,
    }

    impl Read for LyingLenPanicsOnBigRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(
                buf.len() <= self.max_single_read,
                "a single read of {} bytes was requested — past the {}-byte guard. That is \
                 proof a buffer was already allocated from a header field before any refusal \
                 ran",
                buf.len(),
                self.max_single_read
            );
            self.inner.read(buf)
        }
    }

    impl Seek for LyingLenPanicsOnBigRead {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            if let SeekFrom::End(0) = pos {
                return Ok(self.reported_len);
            }
            self.inner.seek(pos)
        }
    }

    /// The same declared size the Phase 3a `container` fuzz target's cpio
    /// reproducer named, and `arc.rs`'s own `ABSURD_SIZE` — reused so the
    /// figure is a real one rather than a stand-in.
    const ABSURD_SIZE: u32 = 0xAAAA_AAAA;

    /// Pins ZOO's OWN ceiling, at its real 256 MiB value, through the real
    /// scan — and pins both halves of what "refused" has to mean.
    ///
    /// `ABSURD_SIZE` (~2.86 GiB) is comfortably UNDER the default policy's
    /// own 4 GiB `max_entry`, so the policy's figure cannot be what refuses
    /// this candidate: only [`ZooSalvage::max_whole_entry`] can, which makes
    /// this the wiring assertion for that method rather than a restatement
    /// of the engine rule. The lying source panics on any large read, so
    /// "nothing was allocated or read for it" is proven rather than assumed,
    /// and the run still COMPLETES with the entry reported — the half whose
    /// absence cost ARC three fix rounds.
    #[test]
    fn refuses_an_absurd_size_now_before_the_allocation_it_would_size() {
        let mut bytes = build_zoo(&[Spec::stored("BIG.BIN", b"")]);
        let at = FIRST_RECORD;
        bytes[at + SIZE_NOW_I..at + SIZE_NOW_I + 4].copy_from_slice(&ABSURD_SIZE.to_le_bytes());
        let mut src = LyingLenPanicsOnBigRead {
            inner: Cursor::new(bytes),
            reported_len: u64::from(ABSURD_SIZE) * 4,
            // Comfortably above `SCAN_CHUNK` (discovery reads in 64 KiB
            // chunks regardless of this test) and comfortably below
            // `ABSURD_SIZE` (~2.86 GiB).
            max_single_read: 128 * 1024,
        };
        assert!(
            u64::from(ABSURD_SIZE) < SalvagePolicy::default().max_entry,
            "the point of this fixture is that only ZOO's own ceiling can refuse it"
        );
        let out = salvage_zoo(&mut src, &SalvagePolicy::default())
            .expect("an absurd size_now is one entry's problem, not the run's");
        assert_eq!(out.entries.len(), 1, "the entry is still reported");
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: u64::from(ABSURD_SIZE),
                ceiling: MAX_ZOO_ENTRY_LEN,
            }),
            "an implausible declared length is this build refusing to allocate, not a verdict \
             that the archive is damaged — and not `Partial`, which would claim somebody read it"
        );
    }

    /// The SECOND declared length — `org_size`, which the engine never sees
    /// and which [`decode`]'s **LH5 arm alone** sizes its output buffer
    /// from.
    ///
    /// # Why this one needs a different instrument from its sibling
    ///
    /// Fix round 1's MEDIUM finding.
    /// `refuses_an_absurd_size_now_before_the_allocation_it_would_size`
    /// above is genuinely proven by [`LyingLenPanicsOnBigRead`]: there the
    /// oversized figure becomes a `read_exact` **against the source**, which
    /// is exactly what that mock watches. Here it does not. The allocation
    /// is `vec![0u8; org_size as usize]` inside `zoo.rs`'s `lh5_decode`,
    /// over an **in-memory slice** the source never sees — so neutering the
    /// check to `if false && …` left this test failing on its STATUS
    /// assertion (`left: Partial`) and never on the reader's guard, with the
    /// 2,863,311,530-byte buffer allocated and the run carrying on. The two
    /// tests looked identical and were not.
    ///
    /// [`crate::alloc_probe`] is what can see it: a `#[cfg(test)]` recording
    /// allocator with a thread-local maximum. The lying `seek(End(0))` is
    /// still needed (without it the candidate short-circuits to `Partial`
    /// before the ceiling is ever consulted), so the mock stays — but its
    /// panic guard is inert for this test and the allocation ceiling below
    /// is what carries it.
    #[test]
    fn an_absurd_org_size_on_lh5_is_refused_before_the_allocation_it_would_size() {
        // Method 2 (LH5) is the ONLY arm that allocates from `org_size` —
        // see `verify_candidate`'s own doc, and the Stored test below for
        // what bounding the other two by it cost.
        let mut spec = Spec::stored("BIG.LH5", b"");
        spec.method = 2;
        spec.declared_org = Some(ABSURD_SIZE);
        let mut src = LyingLenPanicsOnBigRead {
            inner: Cursor::new(build_zoo(&[spec])),
            reported_len: u64::from(ABSURD_SIZE) * 4,
            max_single_read: 128 * 1024,
        };
        let (out, largest) = crate::alloc_probe::largest_single_allocation(|| {
            salvage_zoo(&mut src, &SalvagePolicy::default())
                .expect("an absurd org_size is one entry's problem, not the run's")
        });
        // **Asserted BEFORE the status**, deliberately: with the ceiling
        // neutered, the status assertion fires first and hides the finding
        // this test exists for — which is exactly how the old version of
        // this test came to pass while the buffer was allocated. The scan
        // itself allocates a `SCAN_CHUNK` buffer and a window of the same
        // order, so this ceiling sits well above those and three orders of
        // magnitude below `ABSURD_SIZE` (~2.86 GiB).
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes — `org_size` was allocated from \
             before anything refused it, which no source-side mock in this crate can see"
        );
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: u64::from(ABSURD_SIZE),
                ceiling: MAX_ZOO_ENTRY_LEN,
            })
        );
    }

    /// **Fix round 1, HIGH.** The `org_size` ceiling used to run for all
    /// three methods, and only [`Method::Lh5`] allocates from the field:
    /// `Stored` copies its payload and `Lzw` grows its own output under
    /// `zoo.rs`'s `guard_output`. So a Stored entry whose bytes were
    /// entirely present was reported `Unverified (over the ceiling)` and —
    /// because `entries.rs` never writes an `Unverified` entry — recovered
    /// nowhere, for a figure its own method never reads.
    ///
    /// Measured at the CLI on `store.zoo` with `org_size` alone corrupted:
    /// `1 scanned: 0 written`, an empty destination, exit 3. Gated on the
    /// LH5 arm the same record is `Partial` and `license.partial` holds all
    /// 11,357 bytes at exit 4.
    #[test]
    fn an_absurd_org_size_on_a_stored_entry_does_not_cost_its_recoverable_payload() {
        let content = b"every one of these bytes is present and recoverable".repeat(3);
        let mut spec = Spec::stored("BIG.TXT", &content);
        spec.declared_org = Some(ABSURD_SIZE);
        let bytes = build_zoo(&[spec]);

        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "a Stored entry never allocates from `org_size`, so an absurd one is a header \
             disagreeing with its contents — not this build refusing to allocate"
        );

        // And the payload really is recovered, which is what the old
        // behaviour cost: `Unverified` is never written at all.
        let path = temp_archive(&bytes, "stored-bigorg");
        let entry = &out.entries[0];
        let mut sink: Vec<u8> = Vec::new();
        let completed = write_payload(&path, entry, entry.meta.compressed_size.unwrap(), &mut sink)
            .expect("an absurd org_size must not error the write path");
        let _ = std::fs::remove_file(&path);
        assert!(
            !completed,
            "the entry cannot be `completed`: its own header declares a length the content \
             does not reach"
        );
        assert_eq!(
            sink, content,
            "but every present byte is recovered — this is the entry the unconditional \
             ceiling threw away"
        );
    }

    /// The wiring `refuses_an_absurd_size_now...` depends on, stated
    /// directly: the scanner `salvage_zoo` builds declares ZOO's own
    /// container ceiling, not some other number.
    #[test]
    fn the_scanner_declares_zoos_own_whole_entry_ceiling() {
        assert_eq!(ZooSalvage::new().max_whole_entry(), MAX_ZOO_ENTRY_LEN);
    }

    /// The regression guard for the two tests above: with the LYING seek
    /// removed (so the source's real, short length is visible), a modest
    /// declared size with no data behind it is caught by the ORDINARY
    /// truncation path instead — `Partial`, never over-ceiling.
    #[test]
    fn a_modest_declared_size_with_no_data_behind_it_is_partial_not_over_ceiling() {
        let mut bytes = build_zoo(&[Spec::stored("SHORT.BIN", b"")]);
        let at = FIRST_RECORD;
        bytes[at + SIZE_NOW_I..at + SIZE_NOW_I + 4].copy_from_slice(&64u32.to_le_bytes());
        let out = scan(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
    }

    /// A record whose declared length overruns everything left in the file
    /// must not swallow the real records after it — the engine fix
    /// `collect_candidates` documents, reproduced here for ZOO rather than
    /// left to a coincidence in noise.
    #[test]
    fn a_lying_declared_length_does_not_swallow_the_real_entries_after_it() {
        let mut bytes = build_zoo(&[
            Spec::stored("FIRST.TXT", b"hello"),
            Spec::stored("PHANTOM.BIN", b""),
            Spec::stored("SECOND.TXT", b"world"),
        ]);
        // Raise the SECOND record's declared `size_now` to a bald lie. Its
        // own record starts right after the first entry's record, leader and
        // payload; locate it by its name rather than by arithmetic.
        let at = find_record_by_name(&bytes, "PHANTOM.BIN");
        bytes[at + SIZE_NOW_I..at + SIZE_NOW_I + 4].copy_from_slice(&50_000_000u32.to_le_bytes());

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

    /// Finds the offset of the record whose 13-byte DOS name field holds
    /// `name`, by walking tag sightings rather than by re-deriving record
    /// arithmetic a test has no business knowing.
    fn find_record_by_name(bytes: &[u8], name: &str) -> usize {
        use super::super::zoo::{FNAME_I, FNM_SIZ, SIZ_DIRL};
        for at in 0..bytes.len().saturating_sub(SIZ_DIRL) {
            if bytes[at..at + 4] != TAG_BYTES {
                continue;
            }
            let field = &bytes[at + FNAME_I..at + FNAME_I + FNM_SIZ];
            let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
            if &field[..end] == name.as_bytes() {
                return at;
            }
        }
        panic!("no record named `{name}` in this archive");
    }

    // -------------------------------------------------------------------
    // The write side
    // -------------------------------------------------------------------

    /// A uniquely-named temporary archive. The counter is what keeps two
    /// tests running in parallel from colliding on one path — the process
    /// id alone does not, since every test in this binary shares it.
    fn temp_archive(bytes: &[u8], tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "stuffr-zoo-salvage-{tag}-{}-{}.zoo",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// The companion half of the scanner: a scan arm with no writer arm is
    /// a silent `SkippedNotBuiltIn`, which is the gap ARC shipped with. This
    /// drives `write_payload` over a real archive and a real recovered
    /// entry, through the `Stored` arm — the only method `zoo.rs` can BUILD
    /// an archive for, since it has no encoder by construction. The other
    /// two arms are exercised over the borrowed corpus by
    /// [`write_payload_recovers_the_compressed_borrowed_fixtures`] below,
    /// which is stronger evidence anyway: those bytes are decades old and
    /// nothing in this project produced them.
    #[test]
    fn write_payload_recovers_a_stored_entry() {
        let content = b"the quick brown fox jumps over the lazy dog, repeatedly. ".repeat(4);
        let bytes = build_zoo(&[Spec::stored("DOC.TXT", &content)]);
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

    /// The compressed methods, over the borrowed corpus — `default.zoo` is
    /// zoo's own `lzd` LZW and `high_per.zoo` is LH5, and both must come
    /// back byte-identical to the stored fixture's payload.
    #[test]
    fn write_payload_recovers_the_compressed_borrowed_fixtures() {
        let stored_path = temp_archive(STORE_ZOO, "license-source");
        let stored_out = scan(STORE_ZOO);
        let mut license: Vec<u8> = Vec::new();
        write_payload(
            &stored_path,
            &stored_out.entries[0],
            stored_out.entries[0].meta.compressed_size.unwrap(),
            &mut license,
        )
        .unwrap();
        let _ = std::fs::remove_file(&stored_path);
        assert_eq!(license.len(), 11_357);

        for (bytes, label) in [(DEFAULT_ZOO, "default.zoo"), (HIGH_PER_ZOO, "high_per.zoo")] {
            let path = temp_archive(bytes, label);
            let out = scan(bytes);
            let entry = &out.entries[0];
            let mut sink: Vec<u8> = Vec::new();
            let completed =
                write_payload(&path, entry, entry.meta.compressed_size.unwrap(), &mut sink)
                    .expect("a healthy fixture writes without error");
            let _ = std::fs::remove_file(&path);
            assert!(completed, "{label}");
            assert_eq!(sink, license, "{label}: decodes to the same licence text");
        }
    }

    /// Fix-round parity with ARC: what is genuinely PRESENT can itself
    /// exceed a ceiling, and that must be a per-entry `Ok(false)` rather
    /// than an `Err` that would abort the whole run. Exercised with a SMALL
    /// ceiling rather than the real 256 MiB figure.
    #[test]
    fn an_entry_whose_present_bytes_alone_exceed_the_ceiling_is_folded_into_ok_false() {
        let present = vec![0xABu8; 100];
        let bytes = build_zoo(&[Spec::stored("BIG.BIN", &present)]);
        let path = temp_archive(&bytes, "ceiling");
        let out = scan(&bytes);
        let entry = &out.entries[0];

        let mut sink: Vec<u8> = Vec::new();
        let result = write_payload_bounded(&path, entry, 100, &mut sink, 50);
        let _ = std::fs::remove_file(&path);

        let completed = result.expect(
            "an over-ceiling-but-present read must be folded into Ok(false), never propagated \
             as an Err that would abort the whole salvage run",
        );
        assert!(!completed, "must report as not completed, never an Err");
        assert!(
            sink.is_empty(),
            "nothing should be written once the bounded read is refused before allocating"
        );
    }

    /// **Fix round 2, NEW-1.** The write side's own `org_size` ceiling had
    /// no test at all: neutering it entirely left 619 passed / 2 ignored in
    /// this crate and 3 passed in `stuffr`'s `salvage_zoo.rs`, all green.
    ///
    /// The Stored regression test above proves the LH5 GATE's placement on
    /// that line (drop `method == Method::Lh5 &&` and it fails), and
    /// `an_entry_whose_present_bytes_alone_exceed_the_ceiling_…` exercises
    /// `readable_len > ceiling`, one branch earlier — so the
    /// `expected > ceiling` arm had never executed, and the
    /// `vec![0u8; org_size]` inside `zoo.rs`'s `lh5_decode` was reachable
    /// from this `pub` function with a figure up to 4 GiB.
    ///
    /// # Why this drives `write_payload`, not `write_payload_bounded`
    ///
    /// `write_payload_bounded` exists so a SMALL ceiling can be passed; that
    /// is the right instrument for the `readable_len` branch, whose fixture
    /// would otherwise have to be 256 MiB of real bytes. This branch needs
    /// no such trick — `expected` comes from the entry's own
    /// [`EntryMeta::size`], which a caller sets freely — so the test uses
    /// the REAL ceiling through the REAL public entry point, which is
    /// exactly the population `write_payload`'s own doc says the check is
    /// kept for: a direct caller supplying its own [`SalvagedEntry`].
    /// Through `stuffr::entries::salvage` the branch is unreachable (an
    /// over-ceiling entry is `Unverified` at verify time and
    /// `place_salvaged_file` never writes one).
    ///
    /// [`crate::alloc_probe`] is what makes this a guard rather than a
    /// restatement of the return value: neutered, the assertion that fires
    /// is the ALLOCATION one, because `Ok(false)` alone is also what a
    /// failed decode answers.
    #[test]
    fn an_absurd_org_size_is_refused_before_the_allocation_it_would_size_on_the_write_side() {
        // Any bytes at all: the ceiling refuses before a single one is read,
        // which is the point. A real LH5 payload is not needed and could not
        // be built here — `zoo.rs` has no encoder.
        let path = temp_archive(&[0u8; 64], "write-ceiling");

        let entry = SalvagedEntry {
            scan_position: 0,
            offset: 0,
            payload_start: 0,
            meta: {
                let mut m = EntryMeta::file("BIG.LH5");
                m.codec = codec_for_zoo_method(2); // the arm that allocates
                m.size = Some(u64::from(ABSURD_SIZE));
                m.compressed_size = Some(8);
                m
            },
            status: SalvageStatus::Partial,
            shadows: None,
            collides_with: None,
            marked_deleted: false,
        };

        let mut sink: Vec<u8> = Vec::new();
        let (result, largest) = crate::alloc_probe::largest_single_allocation(|| {
            write_payload(&path, &entry, 8, &mut sink)
        });
        let _ = std::fs::remove_file(&path);

        // Asserted FIRST, for the reason its verify-side twin is: with the
        // ceiling neutered the `Ok(false)`/empty-sink assertions still hold
        // (the decode fails on garbage and answers `Ok(false)` too), so they
        // would hide the finding this test exists for.
        assert!(
            largest <= 1 << 20,
            "largest single allocation was {largest} bytes — `org_size` reached \
             `lh5_decode`'s `vec![0u8; _]` from a `pub` entry point with nothing bounding it"
        );
        let completed = result.expect(
            "an over-ceiling `org_size` must fold into Ok(false), never an Err that would \
             abort the whole salvage run",
        );
        assert!(!completed);
        assert!(sink.is_empty());
    }

    /// The other side of the branch, so the test above cannot be satisfied
    /// by a ceiling that refuses everything: an LH5 entry whose declared
    /// `org_size` is UNDER the ceiling passes the comparison and reaches
    /// `decode`, which then fails on bytes that are not an LH5 stream. Both
    /// answer `Ok(false)`; only the allocation tells them apart, which is
    /// why the probe is the discriminator here too.
    #[test]
    fn an_org_size_under_the_ceiling_reaches_the_decoder_rather_than_being_refused() {
        let path = temp_archive(&[0u8; 64], "write-under-ceiling");
        let modest = 64 * 1024u32;

        let entry = SalvagedEntry {
            scan_position: 0,
            offset: 0,
            payload_start: 0,
            meta: {
                let mut m = EntryMeta::file("SMALL.LH5");
                m.codec = codec_for_zoo_method(2);
                m.size = Some(u64::from(modest));
                m.compressed_size = Some(8);
                m
            },
            status: SalvageStatus::Partial,
            shadows: None,
            collides_with: None,
            marked_deleted: false,
        };

        let mut sink: Vec<u8> = Vec::new();
        let (result, largest) = crate::alloc_probe::largest_single_allocation(|| {
            write_payload(&path, &entry, 8, &mut sink)
        });
        let _ = std::fs::remove_file(&path);
        result.expect("a modest org_size must not error either");
        assert!(
            largest >= usize::try_from(modest).unwrap(),
            "an org_size UNDER the ceiling must reach `lh5_decode` and be allocated — \
             {largest} bytes says the ceiling is refusing entries it should pass, which \
             would make the test above pass for the wrong reason"
        );
    }

    /// Every method a real ZOO record can produce must survive the round
    /// trip salvage's write path depends on — `from_byte` → `Method::codec`
    /// → `method_for_codec`. Driven from `from_byte` over the WHOLE byte
    /// space rather than from `Method::all()`, which is what closes
    /// `all()`'s one uncovered hole (its seed is a literal, so a variant
    /// added at the FRONT compiles and is silently absent).
    #[test]
    fn every_method_the_reader_decodes_can_be_written_back() {
        let mut decodable = 0;
        for byte in 0..=u8::MAX {
            let Ok(method) = Method::from_byte(byte, "x") else {
                continue;
            };
            decodable += 1;
            assert_eq!(
                method_for_codec(Some(method.codec())),
                Some(method),
                "method byte {byte} decodes as {method:?}, whose codec {:?} must map back to \
                 it — otherwise salvage reports SkippedNotBuiltIn and silently writes nothing \
                 for every entry using it",
                method.codec()
            );
        }
        assert_eq!(
            decodable, 3,
            "ZOO's method space is 0, 1 and 2 (`zoo.h`'s MAX_PACK); a change to that set is a \
             deliberate act, not something this test should absorb"
        );
    }

    /// A tag match split across a [`SCAN_CHUNK`] boundary must still be
    /// found — the carry `find_next_tag` keeps exists for exactly this.
    #[test]
    fn a_tag_straddling_a_chunk_boundary_is_found() {
        let mut bytes = vec![0u8; SCAN_CHUNK * 2];
        let at = SCAN_CHUNK - 1;
        bytes[at..at + 4].copy_from_slice(&TAG_BYTES);
        let found = find_next_tag(&mut Cursor::new(bytes), 0, (SCAN_CHUNK * 2) as u64).unwrap();
        assert_eq!(found, Some(at as u64));
    }
}

// -------------------------------------------------------------------------
// Salvage Stage 2 Task 7: the damage catalogue.
//
// **Every expectation here is the PRE-DAMAGE state, and none of it comes
// from this scanner.** The content, the compression methods and the
// CRC-16/ARC values all come from the borrowed `unarc-rs` 0.6.3 corpus
// (`fixtures/legacy/zoo/`, see `fixtures/legacy/MANIFEST.md`) — bytes zoo
// 2.10 wrote decades before this project existed, each record carrying the
// checksum its ORIGINAL writer computed over the original content.
//
// **The one compromise, stated rather than hidden.** Every borrowed ZOO
// fixture holds exactly ONE entry, and "neighbours unaffected" is a claim
// that needs at least two. ZOO's directory is a CHAIN of records carrying
// ABSOLUTE `next` and payload offsets, so two archives cannot simply be
// concatenated. [`two_borrowed_entries`] therefore re-FRAMES two borrowed
// records into one archive through `zoo.rs`'s own `build_zoo`: the framing
// (the 42-byte header, the chain links, the `dir_crc`s) is this project's,
// while each entry's PAYLOAD BYTES, METHOD, ORIGINAL SIZE and CRC-16 are
// the borrowed corpus's, carried across unchanged. So the evidence that
// matters — "does this scanner's verdict agree with a checksum another
// program computed?" — is still borrowed; only the envelope is ours. The
// single-entry rows below run against the untouched fixtures for the same
// reason, so nothing rests on the re-framing alone.
//
// **What makes `build_zoo`'s envelope credible rather than merely
// self-consistent**, and the mitigation this header used to omit (fix round
// 1, F6): `the_structural_payload_position_agrees_with_the_records_own_offset
// _field`, in this module's own `tests`, already checks the 56-byte type-2
// record model against ALL FOUR borrowed fixtures — the structural payload
// position against the absolute offset zoo 2.10 itself wrote. The framing
// the rows below corrupt is therefore a framing an outside archiver has
// agreed with, even though this particular archive's bytes are ours. Worth
// knowing the shape precisely rather than reading the paragraph above
// generously: of the nine rows here, two run over an untouched fixture
// (the agreement property and the Stored-payload flip) and one over
// `wrongcrc16.zoo`; every mutation row runs on `build_zoo`'s envelope.
//
// **One discipline this module does NOT follow, named rather than left to
// be noticed:** [`borrowed_record`] and [`geometry`] below parse through
// `zoo::read_dir_entry` — the same function `salvage_zoo` itself calls.
// ARC, LHA and ARJ each parse their geometry LONGHAND in the test, on the
// rule that an expectation read through the parser being tested is not an
// expectation. ZOO's records are a linked chain with absolute offsets and a
// per-record `dir_crc`, so a second longhand walk here would be a third copy
// of a layout `zoo.rs` and this scanner already share. The mitigation is
// that `read_dir_entry` is the READER's parser, not the scanner's verdict —
// and that the test named above pins it against the borrowed bytes
// independently.
//
// No external tool witnesses this: no `zoo` binary is obtainable on any
// platform in reach (measured: `which zoo` finds nothing). The stored
// CRC-16 IS the witness, and it is a good one.
// -------------------------------------------------------------------------
#[cfg(test)]
mod damage_catalogue {
    use std::io::Cursor;

    use stuffr_core::salvage::{SalvagePolicy, SalvageStatus};
    use stuffr_core::{Container, OpenOpts, ReaderSource, Source, StreamPolicy};

    use super::super::zoo::test_archives::{Spec, build_zoo};
    use super::super::zoo::{ZOO, Zoo, read_dir_entry};
    use super::salvage_zoo;

    const STORE_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/store.zoo");
    const DEFAULT_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/default.zoo");
    const HIGH_PER_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/high_per.zoo");
    /// The borrowed corpus's negative twin: one record whose recorded
    /// CRC-16 does not describe the payload behind it. See
    /// `a_deliberately_wrong_checksum_is_the_documented_asymmetry`.
    const WRONGCRC16_ZOO: &[u8] = include_bytes!("../../fixtures/legacy/zoo/wrongcrc16.zoo");

    /// CRC-16/ARC written out longhand, independent of
    /// `super::super::crc::crc16_arc` — the same double-entry discipline
    /// `stuffr_core::container_conformance`'s own `crc16_arc_witness` uses.
    /// Pinned to the published RevEng check value below.
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

    /// One borrowed record's own declarations, read out of the archive's
    /// first directory entry: `(method, crc16, original size, payload
    /// bytes)`. This is the only place the borrowed corpus is consulted,
    /// and it reads DECLARATIONS — never a decoder's output.
    fn borrowed_record(bytes: &[u8]) -> (u8, u16, u32, Vec<u8>) {
        let d = read_dir_entry(&mut Cursor::new(bytes.to_vec()), 42)
            .expect("every borrowed fixture's first record parses");
        let start = d.offset as usize;
        (
            d.method_byte,
            d.crc16,
            d.org_size,
            bytes[start..start + d.size_now as usize].to_vec(),
        )
    }

    /// Two borrowed records, re-framed into one archive — see this module's
    /// header comment for exactly which parts are borrowed and which are
    /// ours. Entry 1 is `store.zoo`'s method-0 (Stored) record, entry 2 is
    /// `high_per.zoo`'s method-2 (`-lh5-`) one; both carry the CRC-16
    /// `0xB065` zoo 2.10 computed over the same 11,357-byte content.
    fn two_borrowed_entries() -> Vec<u8> {
        let (m1, c1, o1, p1) = borrowed_record(STORE_ZOO);
        let (m2, c2, o2, p2) = borrowed_record(HIGH_PER_ZOO);
        let mut first = Spec::stored("store.lic", &p1);
        first.method = m1;
        first.crc16 = Some(c1);
        first.declared_org = Some(o1);
        let mut second = Spec::stored("high.lic", &p2);
        second.method = m2;
        second.crc16 = Some(c2);
        second.declared_org = Some(o2);
        build_zoo(&[first, second])
    }

    /// `(record offset, payload range)` per entry, walked along the
    /// archive's own `next` chain — the geometry every mutation below is
    /// aimed with, read from the archive rather than from a salvage result.
    fn geometry(bytes: &[u8]) -> Vec<(u64, std::ops::Range<usize>)> {
        let mut out = Vec::new();
        let mut at = 42u64;
        loop {
            let d = match read_dir_entry(&mut Cursor::new(bytes.to_vec()), at) {
                Ok(d) => d,
                Err(_) => return out,
            };
            if d.name.is_empty() {
                return out; // the terminator record
            }
            let start = d.offset as usize;
            out.push((at, start..start + d.size_now as usize));
            if d.next == 0 {
                return out;
            }
            at = u64::from(d.next);
        }
    }

    fn reader_entries(bytes: &[u8]) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(Cursor::new(bytes.to_vec())));
        let resolved = stuffr_core::resolve(src, ZOO, Zoo.caps(), &StreamPolicy::default())
            .map_err(|e| format!("resolve: {e}"))?;
        let mut ar = Zoo
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
        salvage_zoo(&mut Cursor::new(bytes.to_vec()), &SalvagePolicy::default())
            .expect("a damaged archive must never abort the run")
            .entries
            .iter()
            .map(|e| (e.meta.name.clone(), e.status))
            .collect()
    }

    fn names(rows: &[(String, SalvageStatus)]) -> Vec<&str> {
        rows.iter().map(|(n, _)| n.as_str()).collect()
    }

    // ---------------------------------------------------------------------
    // Step 1: the agreement property.
    // ---------------------------------------------------------------------

    /// **Salvage of an UNDAMAGED archive must agree exactly with what the
    /// ordinary reader enumerates** — same names, same order, every entry
    /// `Intact` — over all three decodable borrowed fixtures and over the
    /// re-framed two-entry archive.
    ///
    /// The third leg is what stops this being two implementations agreeing
    /// with each other: the bytes the READER produced are checked against
    /// the CRC-16 each record DECLARES, through [`crc16_witness`], an
    /// implementation independent of `legacy::crc`'s.
    #[test]
    fn salvage_of_a_healthy_archive_agrees_with_the_ordinary_reader() {
        let spliced = two_borrowed_entries();
        for (label, bytes) in [
            ("store.zoo", STORE_ZOO),
            ("default.zoo", DEFAULT_ZOO),
            ("high_per.zoo", HIGH_PER_ZOO),
            ("two borrowed records, re-framed", &spliced[..]),
        ] {
            let read = reader_entries(bytes)
                .unwrap_or_else(|e| panic!("{label}: the ordinary reader must walk it: {e}"));
            let rows = salvaged(bytes);
            assert_eq!(
                rows.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                read.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                "{label}: salvage and the ordinary reader must enumerate the same names in \
                 the same order"
            );
            for (name, status) in &rows {
                assert_eq!(
                    *status,
                    SalvageStatus::Intact,
                    "{label}: an undamaged entry (`{name}`) must verify Intact"
                );
            }
            // Each record's own declared CRC-16, against the reader's own
            // output, through an independent implementation.
            let mut at = 42u64;
            for (name, content) in &read {
                let d = read_dir_entry(&mut Cursor::new(bytes.to_vec()), at).unwrap();
                assert_eq!(
                    crc16_witness(content),
                    d.crc16,
                    "{label}: the reader's output for `{name}` must match the CRC-16 the \
                     record itself declares — otherwise `Intact` above is agreement between \
                     two wrongs"
                );
                at = u64::from(d.next);
            }
        }
    }

    /// **Ruling S-R, pinned on BOTH sides in one test.** A record the
    /// archive marks deleted is SKIPPED by `zoo.rs`'s reader (following
    /// `zoolist.c`) and REPORTED by salvage, annotated `marked_deleted` —
    /// because the flag is one byte, and in a damaged archive a bit flip
    /// turns a live entry into one no ordinary verb will ever hand back.
    ///
    /// Asserting only the salvage half would leave the interesting claim —
    /// that the two verbs deliberately disagree — untested.
    #[test]
    fn a_deleted_record_is_the_documented_asymmetry() {
        let (m1, c1, o1, p1) = borrowed_record(STORE_ZOO);
        let (m2, c2, o2, p2) = borrowed_record(HIGH_PER_ZOO);
        let mut first = Spec::stored("store.lic", &p1);
        first.method = m1;
        first.crc16 = Some(c1);
        first.declared_org = Some(o1);
        first.deleted = true;
        let mut second = Spec::stored("high.lic", &p2);
        second.method = m2;
        second.crc16 = Some(c2);
        second.declared_org = Some(o2);
        let bytes = build_zoo(&[first, second]);

        let read = reader_entries(&bytes).expect("the reader walks past a deleted record");
        assert_eq!(
            read.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["high.lic"],
            "the ordinary reader must not list a deleted record"
        );

        let outcome = salvage_zoo(&mut Cursor::new(bytes), &SalvagePolicy::default()).unwrap();
        assert_eq!(
            outcome
                .entries
                .iter()
                .map(|e| (e.meta.name.as_str(), e.status, e.marked_deleted))
                .collect::<Vec<_>>(),
            [
                ("store.lic", SalvageStatus::Intact, true),
                ("high.lic", SalvageStatus::Intact, false),
            ],
            "salvage must recover the deleted record, verify it, and SAY it was deleted"
        );
    }

    /// **The fourth asymmetry, and the only row in this phase whose
    /// `Partial` is proven against a checksum ANOTHER PROGRAM deliberately
    /// got wrong** (fix round 1, F3).
    ///
    /// ZOO decodes an entry WHOLE — `zoo.rs`'s own module doc says so in as
    /// many words — so unlike six of the eight containers here, `stuffr
    /// list` on a ZOO archive really does read every payload and can itself
    /// fail. `wrongcrc16.zoo` is the borrowed corpus's negative twin
    /// (`fixtures/legacy/MANIFEST.md`): a record whose recorded CRC-16 does
    /// not describe the bytes behind it. The ordinary reader refuses the
    /// archive outright (`Error::Corrupt`, exit 5 at the CLI, naming both
    /// figures); salvage reports the entry `Partial` and recovers what is
    /// there.
    ///
    /// ARC's sibling row (`arc_salvage.rs`'s
    /// `a_method_this_build_cannot_decode_is_the_documented_asymmetry`)
    /// pins the same "decodes whole, so `list` itself can fail" fact through
    /// an undecodable METHOD; this pins it through a wrong CHECKSUM, which
    /// is the half no construction of ours could supply honestly.
    ///
    /// The independent leg: the record is method 0 (Stored), so its payload
    /// IS its content and [`crc16_witness`] can settle, with no decoder in
    /// the loop, that the recorded value really is wrong for these bytes —
    /// so `Partial` is right for a reason established before the scan ran.
    #[test]
    fn a_deliberately_wrong_checksum_is_the_documented_asymmetry() {
        let record = read_dir_entry(&mut Cursor::new(WRONGCRC16_ZOO.to_vec()), 42).unwrap();
        assert_eq!(
            record.method_byte, 0,
            "Stored — the payload IS the content, which is what lets the witness below \
             settle this with no decoder in the loop"
        );
        let payload = &WRONGCRC16_ZOO
            [record.offset as usize..record.offset as usize + record.size_now as usize];
        assert_ne!(
            crc16_witness(payload),
            record.crc16,
            "the fixture's whole point is a recorded CRC-16 that does not describe its \
             payload; if these agreed the row below would prove nothing"
        );

        let err = reader_entries(WRONGCRC16_ZOO)
            .expect_err("ZOO decodes an entry whole, so the ordinary reader must refuse this");
        assert!(
            err.contains("CRC-16"),
            "the reader's refusal must name the cause: {err}"
        );

        assert_eq!(
            salvaged(WRONGCRC16_ZOO),
            vec![("license".to_string(), SalvageStatus::Partial)],
            "salvage recovers what is there and says it could not prove it — never \
             `Intact`, and never `Complete`, which would claim ZOO offers no checksum"
        );
    }

    // ---------------------------------------------------------------------
    // Step 2: the mutation catalogue.
    // ---------------------------------------------------------------------

    /// Row 1/3 — **a truncated tail.** The earlier entry `Intact`, the cut
    /// one `Partial`, swept across the whole payload rather than sampled at
    /// one point.
    #[test]
    fn damage_catalogue_a_truncated_tail() {
        let bytes = two_borrowed_entries();
        let g = geometry(&bytes);
        assert_eq!(g.len(), 2, "sanity: two records before anything is cut");
        let last = g[1].1.clone();

        let declared = last.len();
        for keep in [0, 1, declared / 2, declared - 1] {
            let rows = salvaged(&bytes[..last.start + keep]);
            assert_eq!(
                names(&rows),
                ["store.lic", "high.lic"],
                "keep={keep}: the cut record's header is still there and must be counted"
            );
            assert_eq!(rows[0].1, SalvageStatus::Intact, "keep={keep}");
            assert_eq!(rows[1].1, SalvageStatus::Partial, "keep={keep}");
        }

        let whole = salvaged(&bytes);
        assert!(
            whole.iter().all(|(_, s)| *s == SalvageStatus::Intact),
            "the UNCUT archive must still come back entirely Intact"
        );
    }

    /// Row 2/3 — **a byte flipped mid-payload.** That entry `Partial`, its
    /// neighbour untouched, run in both directions.
    #[test]
    fn damage_catalogue_a_byte_flipped_mid_payload() {
        let healthy = two_borrowed_entries();
        let g = geometry(&healthy);
        for (damaged, intact) in [(0usize, 1usize), (1, 0)] {
            let mut bytes = healthy.clone();
            let range = g[damaged].1.clone();
            bytes[range.start + range.len() / 2] ^= 0xFF;

            let rows = salvaged(&bytes);
            assert_eq!(names(&rows), ["store.lic", "high.lic"]);
            assert_eq!(
                rows[damaged].1,
                SalvageStatus::Partial,
                "the damaged record's content no longer matches its own CRC-16"
            );
            assert_eq!(
                rows[intact].1,
                SalvageStatus::Intact,
                "the untouched record must not be implicated"
            );
        }
    }

    /// Row 2/3, the no-decoder variant: `store.zoo`'s single entry is method
    /// 0 (Stored), so a flipped byte reaches the CRC-16 comparison with
    /// nothing in between — the arrangement where `Partial` can only mean
    /// "the checksum disagreed". The flip is proven to change the checksum
    /// first, through the independent witness, so the row cannot pass for
    /// the wrong reason.
    #[test]
    fn damage_catalogue_a_flipped_byte_in_a_stored_payload() {
        let range = geometry(STORE_ZOO)[0].1.clone();
        let declared = read_dir_entry(&mut Cursor::new(STORE_ZOO.to_vec()), 42)
            .unwrap()
            .crc16;
        assert_eq!(
            crc16_witness(&STORE_ZOO[range.clone()]),
            declared,
            "a Stored payload IS its content, so the borrowed CRC-16 must match it directly"
        );

        let mut bytes = STORE_ZOO.to_vec();
        bytes[range.start + range.len() / 2] ^= 0xFF;
        assert_ne!(
            crc16_witness(&bytes[range.clone()]),
            declared,
            "the flip must actually change the checksum, or this row proves nothing"
        );
        assert_eq!(
            salvaged(&bytes),
            vec![("license".to_string(), SalvageStatus::Partial)]
        );
        assert_eq!(
            salvaged(STORE_ZOO),
            vec![("license".to_string(), SalvageStatus::Intact)]
        );
    }

    /// Row 3/3 — **a header field corrupted.** That record absent, its
    /// neighbour surviving, in both directions. Corrupting the FIRST
    /// record is the interesting one: ZOO's directory is a chain, so
    /// destroying a link is exactly what makes every record behind it
    /// unreachable to the ordinary reader.
    #[test]
    fn damage_catalogue_a_corrupted_header_field() {
        let healthy = two_borrowed_entries();
        let g = geometry(&healthy);
        let all = ["store.lic", "high.lic"];

        for (damaged, survivor) in [(0usize, 1usize), (1, 0)] {
            let at = g[damaged].0 as usize;

            // (a) the four-byte record tag — the signature the scan looks
            // for at all.
            let mut bytes = healthy.clone();
            bytes[at] ^= 0xFF;
            assert_eq!(
                names(&salvaged(&bytes)),
                [all[survivor]],
                "a destroyed record tag must drop `{}` and nothing else",
                all[damaged]
            );

            // (b) the method byte — a value past `zoo.h`'s `MAX_PACK`.
            let mut bytes = healthy.clone();
            bytes[at + 5] = 200;
            assert_eq!(
                names(&salvaged(&bytes)),
                [all[survivor]],
                "an unassigned method byte must drop `{}` and nothing else",
                all[damaged]
            );

            // (c) the record's own `dir_crc`, which is the gate that lets a
            // non-printable name through and the one a coincidental tag
            // cannot forge.
            let mut bytes = healthy.clone();
            bytes[at + 54] ^= 0xFF;
            bytes[at + 38] = 0x01; // a control byte in the name field
            assert_eq!(
                names(&salvaged(&bytes)),
                [all[survivor]],
                "a name no reader would report, behind a `dir_crc` that no longer vouches \
                 for it, must drop `{}` and nothing else",
                all[damaged]
            );
        }
    }

    /// The header field that is NOT absent-or-refused, for the same reason
    /// ARC's is not: a lying compressed length still sits behind a record
    /// whose tag, method, name and `dir_crc` all check out, so the candidate
    /// is REPORTED with its payload bounded by what the file holds — and,
    /// critically, the record behind it is not swallowed by the lie.
    #[test]
    fn damage_catalogue_a_corrupted_declared_length_is_reported_not_believed() {
        let healthy = two_borrowed_entries();
        let g = geometry(&healthy);
        let mut bytes = healthy.clone();
        let at = g[0].0 as usize;
        bytes[at + 24..at + 28].copy_from_slice(&9_999_999u32.to_le_bytes());
        // `dir_crc` covers the record, so it has to be refreshed or the
        // record is refused by criterion (c) above instead — which would
        // make this row a duplicate of that one rather than its complement.
        bytes[at + 54] = 0;
        bytes[at + 55] = 0;
        let len = read_dir_entry(&mut Cursor::new(bytes.clone()), at as u64)
            .unwrap()
            .record_len as usize;
        let fresh = crc16_witness(&bytes[at..at + len]);
        bytes[at + 54..at + 56].copy_from_slice(&fresh.to_le_bytes());

        let rows = salvaged(&bytes);
        assert_eq!(
            names(&rows),
            ["store.lic", "high.lic"],
            "a lying length must not swallow the record behind it"
        );
        assert_eq!(rows[0].1, SalvageStatus::Partial);
        assert_eq!(rows[1].1, SalvageStatus::Intact);
    }
}
