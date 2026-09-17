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
//! # A deleted record IS reported
//!
//! `zoo d` marks an entry `deleted = 1` and leaves it, payload and all, in
//! the file; `zoolist.c` does not list it and `zoo x` does not extract it,
//! and `zoo.rs`'s reader follows that exactly. This scanner does not, and
//! the asymmetry is deliberate: the bytes are present and recoverable, the
//! flag is bookkeeping about the CHAIN rather than about whether the content
//! exists, and this project's own second-commonest defect is an entry lost
//! silently. Salvage is the one recovery-biased verb; a deleted record is
//! precisely the content the ordinary reader will not give back.
//! `a_deleted_record_is_still_reported_by_the_scan` pins it.

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
/// is a SECOND, independent `u32` the engine never sees, and `decode`'s LH5
/// arm sizes its output buffer from it: left unbounded that is a 4 GiB
/// allocation from a header field.
///
/// It is answered as a per-entry [`UnverifiedCause::OverEntryCeiling`],
/// **never** as an `Err` and never as a check on the figure the engine
/// already owns. That distinction is the whole lesson of Task 3c's three fix
/// rounds: what they deleted was three checks on ONE quantity under two
/// owners, each able to abort a run. This is a different quantity, with one
/// owner, and its refusal is a status — so it cannot cost the entries
/// around it.
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
        // Likewise unreachable: every ZOO candidate carries a CRC-16.
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
    if org_size > MAX_ZOO_ENTRY_LEN {
        // See this function's doc: the engine bounds `declared_len`, never
        // this second field, and `decode`'s LH5 arm allocates from it.
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
/// - `org_size` is bounded too, because [`decode`]'s LH5 arm sizes its
///   output buffer from it — the same second field [`verify_candidate`]'s
///   own doc explains.
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
    if expected > ceiling {
        // `decode`'s LH5 arm sizes `vec![0u8; org_size]` from this figure.
        return Ok(false);
    }
    let Ok(org_size) = u32::try_from(expected) else {
        // Unreachable: `ceiling` is at most `MAX_ZOO_ENTRY_LEN` (256 MiB),
        // well inside a `u32`. Refused rather than truncated by a cast.
        return Ok(false);
    };

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
        let at = 42; // the first record, straight after the 42-byte header
        bytes[at + 38..at + 41].copy_from_slice(&[0xC4, 0xD9, 0xB3]);
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
    fn overwrite_name_and_refresh_dir_crc(bytes: &mut [u8], raw: &[u8]) {
        use super::super::crc::crc16_arc;
        let at = 42; // the first record, straight after the 42-byte header
        for b in &mut bytes[at + 38..at + 51] {
            *b = 0;
        }
        bytes[at + 38..at + 38 + raw.len()].copy_from_slice(raw);
        let var_len = usize::from(u16::from_le_bytes([bytes[at + 51], bytes[at + 52]]));
        let len = 56 + var_len;
        bytes[at + 54] = 0;
        bytes[at + 55] = 0;
        let crc = crc16_arc(&bytes[at..at + len]);
        bytes[at + 54..at + 56].copy_from_slice(&crc.to_le_bytes());
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

    /// `zoo.rs`'s reader skips a deleted record; this scanner reports it.
    /// See this module's doc for the ruling — the bytes are present and
    /// recoverable, and salvage is the one recovery-biased verb.
    #[test]
    fn a_deleted_record_is_still_reported_by_the_scan() {
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
        let at = 42;
        bytes[at + 24..at + 28].copy_from_slice(&ABSURD_SIZE.to_le_bytes());
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
    /// and which `decode`'s LH5 arm sizes its output buffer from. Refused
    /// as a per-entry status by `verify_candidate`, with the same panicking
    /// reader proving nothing was allocated for it.
    #[test]
    fn an_absurd_org_size_is_refused_before_the_allocation_it_would_size() {
        // Method 2 (LH5) is the arm that allocates from `org_size`.
        let mut spec = Spec::stored("BIG.LH5", b"");
        spec.method = 2;
        spec.declared_org = Some(ABSURD_SIZE);
        let mut src = LyingLenPanicsOnBigRead {
            inner: Cursor::new(build_zoo(&[spec])),
            reported_len: u64::from(ABSURD_SIZE) * 4,
            max_single_read: 128 * 1024,
        };
        let out = salvage_zoo(&mut src, &SalvagePolicy::default())
            .expect("an absurd org_size is one entry's problem, not the run's");
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: u64::from(ABSURD_SIZE),
                ceiling: MAX_ZOO_ENTRY_LEN,
            })
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
        let at = 42;
        bytes[at + 24..at + 28].copy_from_slice(&64u32.to_le_bytes());
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
        bytes[at + 24..at + 28].copy_from_slice(&50_000_000u32.to_le_bytes());

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
        for at in 0..bytes.len().saturating_sub(56) {
            if bytes[at..at + 4] != TAG_BYTES {
                continue;
            }
            let field = &bytes[at + 38..at + 51];
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
