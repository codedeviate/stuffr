//! ARC/PAK header salvage scan: recovers entries by looking directly for
//! `0x1A <method>` entry markers, rather than trusting a single linear pass
//! that gives up at the first damaged record. `arc.rs`'s own container
//! reader (Phase 3c) is a correct, honest reader for an INTACT archive; this
//! module is for when a header is corrupt, truncated, or the archive was
//! damaged somewhere in its middle and everything after the damage should
//! still be recoverable — the same motivation `../zip_salvage.rs` documents
//! for zip, and the first of Salvage Stage 2's legacy scanners (Task 3),
//! proving the shared [`stuffr_core::salvage`] machinery works for a format
//! other than zip.
//!
//! # The gate carries more weight here than it does for zip
//!
//! zip's four-byte `PK\x03\x04` occurs by chance roughly once every 4 GiB of
//! random data. ARC's own signature is the marker byte `0x1A` (DOS's own
//! end-of-file character — see `arc.rs`'s own doc for why the format chose
//! it) followed by a method byte drawn from an eleven-value set (`1..=11`,
//! the same range `arc.rs`'s own `ARC_MAGIC` table lists) — two bytes, one
//! in 256 and one in roughly 23, a coincidence roughly every **8 KiB**. That
//! is a MUCH weaker anchor than zip's, so this scanner leans harder on its
//! OTHER criteria (the name, the declared size, the declared payload fitting
//! inside the file) to tell a real header from noise, and the anti-vacuity
//! pair below is what proves the combination actually holds.
//!
//! A candidate is reported only once ALL of the following hold, checked in
//! an order that never allocates or trusts anything before it is cheap to
//! check:
//!
//! 1. The marker byte matches ([`find_next_marker`]).
//! 2. The method byte that follows is one ARC ever assigned (`1..=11` —
//!    [`read_candidate_at`] mirrors `arc.rs`'s own `ARC_MAGIC` table rather
//!    than re-deriving a second list; `0` is the end-of-archive marker, not
//!    an entry, and is deliberately excluded here for the identical reason
//!    `ARC_MAGIC` excludes it — see that table's own doc). Recognised, not
//!    necessarily DECODABLE by this build: methods 5-7 and 10-11 are real
//!    ARC metadata this build cannot decode, and rejecting them at discovery
//!    would be confusing a capability limit (verification's job) with a
//!    coincidence (discovery's job).
//! 3. The name (`ArcHeader::parse`'s own NUL-truncated field) decodes as
//!    non-empty, printable ASCII with no substitution character — see
//!    [`name_looks_real`] for why this is a REAL filter here where a lossy
//!    decode is not (the same asymmetry `zip_salvage.rs`'s own module doc
//!    argues for strict UTF-8 over CP437).
//! 4. `marker_offset + 1 + HEADER_LEN + compressed_size` fits inside the
//!    source — and, per Ruling from `../zip_salvage.rs` ("Criterion 6
//!    reports, it does not reject"), a candidate that does NOT fit is not
//!    dropped: it is reported with [`Candidate::available_len`] naming what
//!    actually survived, so a truncated archive's last entry is a STATEMENT
//!    (`Partial`), never silence.
//!
//! Any failure at 2-3 is not an error — it means this marker byte was a
//! coincidence, not a header, and the scan resumes one byte past it.
//!
//! **Deliberately NOT a gate criterion: the declared `compressed_size`
//! against any ceiling.** An oversized `compressed_size` is neither
//! obviously noise (unlike zip's 16-bit `name_len`, nothing about ARC's
//! format makes a large `u32` implausible) nor safe to allocate from
//! blindly. [`verify_candidate`] is where it is actually bounded — against
//! [`super::arc::MAX_ARC_ENTRY_LEN`], the identical ceiling `arc.rs`'s own
//! `read_payload` enforces — immediately before the payload buffer it would
//! size is allocated, and via `Err`, not a silent skip: see that function's
//! own doc and `refuses_an_absurd_compressed_size_before_the_allocation_it_
//! would_size` below. Folding this into the discovery gate as a silent
//! rejection would have made the anti-vacuity test's outcome depend on
//! whatever compressed-size bytes the noise generator happened to produce
//! at each coincidental marker+method hit — fragile, and beside the point:
//! the size ceiling is a resource decision, not evidence about whether a
//! byte sequence is a real header.
//!
//! # Verification reuses `arc.rs`'s own decoder, never a second one
//!
//! [`ArcSalvage::verify`] re-reads the header at a candidate's own offset,
//! decodes its method via [`super::arc::Method::from_byte`] (the SAME
//! capability gate `arc.rs`'s own container applies — methods 5-7 and 10-11
//! answer [`SalvageStatus::Unverified`], never [`SalvageStatus::Complete`]:
//! ARC entries always carry a CRC-16, so `Complete` — "no checksum to
//! offer" — would be a lie here, unlike tar/cpio/ar), bounds the declared
//! length against the ceiling, then hands the payload to [`super::arc::decode`]
//! — the identical whole-buffer decoder `arc.rs`'s own [`ArcRead`] calls,
//! not a second decompression stack built for salvage. `arc.rs`'s own module
//! doc records that this container "decodes whole and cannot stream"
//! (`MAX_ARC_ENTRY_LEN`'s doc), so unlike zip's Deflate branch this cannot
//! stream either — the decoded buffer is handed to Task 1's
//! [`crate::salvage_verify::stream_verify`] wrapped in a [`std::io::Cursor`],
//! which is what actually decides [`SalvageStatus`] (length agreement, then
//! the CRC-16/ARC comparison) rather than a second hand-rolled comparison —
//! the first real exercise of `stream_verify`'s `Verifier::Crc16` arm
//! outside its own unit tests.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use stuffr_core::salvage::{
    Candidate, SalvageOutcome, SalvagePolicy, SalvageScan, SalvageStatus, SalvagedEntry,
    UnverifiedCause, Verifier, salvage_all, stream_bounded_copy,
};
use stuffr_core::{EntryKind, EntryMeta, Error, FormatId, Result, SeekRead};

use super::arc::{
    ArcHeader, HEADER_LEN, MARKER, Method, arc_mtime, decode, refuse_if_over_ceiling,
};

/// The lowest and highest method byte ARC ever assigned — `arc.rs`'s own
/// `ARC_MAGIC` table lists one [`stuffr_core::MagicRule`] per value in this
/// range, and this scanner's gate mirrors it rather than re-deriving a
/// second list. `0` (the end-of-archive marker) sits just below it and is
/// excluded on purpose, the same way `ARC_MAGIC` excludes it: two bytes
/// carrying no further evidence at all.
const KNOWN_METHOD_RANGE: std::ops::RangeInclusive<u8> = 1..=11;

/// Bytes read per [`find_next_marker`] chunk. O(1) memory regardless of how
/// far the next marker byte is, or whether there is one at all — same
/// figure, same reasoning, as `zip_salvage.rs`'s own `SCAN_CHUNK`.
const SCAN_CHUNK: usize = 64 * 1024;

/// Scans an ARC/PAK archive for entry markers directly, without trusting a
/// single linear pass to survive the whole file.
///
/// Carries no state between calls beyond what
/// [`SalvageScan::next_candidate`] itself receives, so there is nothing to
/// initialise beyond the unit value — the same shape `ZipSalvage` has.
#[derive(Debug, Default)]
pub struct ArcSalvage;

impl ArcSalvage {
    pub fn new() -> Self {
        Self
    }
}

impl SalvageScan for ArcSalvage {
    fn next_candidate(&mut self, src: &mut dyn SeekRead, from: u64) -> Result<Option<Candidate>> {
        let file_len = src.seek(SeekFrom::End(0))?;
        let mut search_from = from;
        loop {
            let Some(offset) = find_next_marker(src, search_from, file_len)? else {
                return Ok(None);
            };
            match read_candidate_at(src, offset, file_len)? {
                Some(candidate) => return Ok(Some(candidate)),
                // The marker byte matched, but the gate rejected everything
                // behind it: a coincidence, not a header. Resume one byte
                // past the marker itself, not past a whole fixed block, so a
                // genuine header overlapping this false match is never
                // skipped.
                None => search_from = offset + 1,
            }
        }
    }

    fn verify(&self, src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
        verify_candidate(src, candidate)
    }
}

/// Searches forward from `from` for the next [`MARKER`] byte, in bounded
/// chunks so memory use does not depend on how far through the source the
/// next one is. Unlike `zip_salvage.rs`'s equivalent, this signature is a
/// single byte, so no match can straddle a chunk boundary and there is
/// nothing to carry across reads.
///
/// `Ok(None)` when no marker byte remains before `file_len`.
fn find_next_marker(src: &mut dyn SeekRead, from: u64, file_len: u64) -> io::Result<Option<u64>> {
    if from >= file_len {
        return Ok(None);
    }
    src.seek(SeekFrom::Start(from))?;
    let mut buf = vec![0u8; SCAN_CHUNK];
    let mut pos = from;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        if let Some(at) = buf[..n].iter().position(|&b| b == MARKER) {
            return Ok(Some(pos + at as u64));
        }
        pos += n as u64;
    }
}

/// Whether an ARC header's decoded name looks like real header data rather
/// than whatever bytes happened to follow a coincidental marker+method
/// match.
///
/// [`ArcHeader::parse`]'s own name decode is LOSSY (`String::from_utf8_lossy`)
/// by design — a container reading trusted-enough bytes must not reject a
/// name for its own sake, and `arc.rs`'s own doc records that the name is
/// stored verbatim, never sanitised, so a hostile name stays evidence for
/// the ops layer to refuse rather than being quietly rewritten. Salvage is
/// scanning UNTRUSTED bytes for a two-byte signature that recurs roughly
/// every 8 KiB, so this criterion applies a stricter, PURELY LOCAL check —
/// it does not change what `ArcHeader::parse` returns, only what THIS
/// module treats as further evidence of a real header: non-empty, and every
/// byte a printable ASCII character (`0x20..=0x7E`). A genuine DOS-era
/// archive name is exactly this; the substitution character `ArcHeader::
/// parse`'s lossy decode inserts for a genuinely invalid byte sequence
/// already fails this (it is outside `0x20..=0x7E`), and so does an
/// embedded control byte a real name would never carry.
fn name_looks_real(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// Reads the marker+header believed to start at `offset` and runs it
/// through the gate described in this module's doc. `Ok(None)` for ANY gate
/// failure — including the header itself running past `file_len`, which
/// means there was never a full 28-byte record to read in the first place —
/// see the module doc for why a rejection here is never an error.
fn read_candidate_at(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
) -> Result<Option<Candidate>> {
    src.seek(SeekFrom::Start(offset))?;
    let mut marker = [0u8; 1];
    if src.read_exact(&mut marker).is_err() {
        return Ok(None);
    }
    debug_assert_eq!(marker[0], MARKER, "caller already matched the marker");

    let mut record = [0u8; HEADER_LEN];
    if src.read_exact(&mut record).is_err() {
        return Ok(None);
    }
    // `record[0]` is the method byte — see `ArcHeader::parse`'s own layout.
    // `0` is the end-of-archive marker, not an entry, and carries no
    // further evidence at all; anything outside `KNOWN_METHOD_RANGE` is a
    // value ARC never assigned. Both are treated identically here: not a
    // real header.
    if !KNOWN_METHOD_RANGE.contains(&record[0]) {
        return Ok(None);
    }

    let header = ArcHeader::parse(&record);
    if !name_looks_real(&header.name) {
        return Ok(None);
    }

    let compressed_size = u64::from(header.compressed_size);
    // Fix round 2, NEW-3: built with `checked_add` like every other offset
    // computation in this module (and like `zip_salvage.rs`'s own
    // equivalent) — a raw `+` here was the actual finding; a comment
    // claiming it already used `checked_add` was not enough to make it
    // true. `offset` is a scanner-discovered marker position and `1 +
    // HEADER_LEN` is a small constant, so overflow is not reachable on any
    // real archive, but a candidate whose arithmetic overflows is refused
    // the same way every other malformed candidate in this function is:
    // `Ok(None)`, never a panic or a wrapped value.
    let Some(payload_start) = offset
        .checked_add(1)
        .and_then(|v| v.checked_add(HEADER_LEN as u64))
    else {
        return Ok(None);
    };
    let available_len = match payload_start.checked_add(compressed_size) {
        Some(end) if end <= file_len => None,
        // Either the declared end overflows `u64`, or it runs past the
        // source. Both mean the same thing to a reader: fewer bytes are
        // present than the header promises. `payload_start` itself is
        // already `<= file_len` (the marker+record `read_exact` above
        // proved that many bytes exist), so this saturating subtraction
        // never underflows.
        _ => Some(file_len.saturating_sub(payload_start)),
    };

    let mut meta = EntryMeta::file(header.name.clone());
    meta.size = Some(u64::from(header.original_size));
    meta.compressed_size = Some(compressed_size);
    meta.kind = EntryKind::File;
    meta.mtime = arc_mtime(header.packed_datetime);
    // Fix round (Task 3c): previously left `None` unconditionally, which
    // made a real write of an `Intact`/`Complete`/`Partial` ARC entry
    // silently no-op as `SkippedNotBuiltIn` — `entries.rs`'s write dispatch
    // reads this field to decide how to decode, the same way it already did
    // for zip's `codec_for_method`, and an ARC candidate never populated it.
    meta.codec = codec_for_arc_method(record[0]);

    Ok(Some(Candidate {
        offset,
        payload_start,
        meta,
        declared_len: Some(compressed_size),
        verifier: Some(Verifier::Crc16(header.crc16)),
        available_len,
    }))
}

/// Maps an ARC method byte to the [`FormatId`] [`EntryMeta::codec`] carries
/// for it — the same role `zip_salvage.rs`'s own `codec_for_method` plays,
/// naming ARC's five DECODABLE methods (`arc.rs`'s own [`Method`] enum;
/// see its module doc's method table) rather than a zip compression method.
/// `None` for the six methods this build recognises but cannot decode —
/// those candidates already report
/// [`SalvageStatus::Unverified`]`(`[`UnverifiedCause::UndecodableMethod`]`)`
/// from [`verify_candidate`], which `entries.rs`'s write path refuses
/// before ever reading this field, so `None` here is never reached by a
/// write attempt in practice.
///
/// Fix round 2, Ruling S-K: derives from [`Method::from_byte`] and
/// [`Method::codec`] rather than hand-copying the byte ranges a second
/// time — see [`Method::codec`]'s own doc for why.
fn codec_for_arc_method(method_byte: u8) -> Option<FormatId> {
    Method::from_byte(method_byte, "").ok().map(Method::codec)
}

/// Decides [`SalvageStatus`] for one candidate by re-reading the header at
/// its own `offset`, bounding its declared length, decoding its payload
/// through `arc.rs`'s own [`decode`], and comparing the result against the
/// candidate's [`Verifier::Crc16`] via Task 1's shared
/// [`crate::salvage_verify::stream_verify`] — see this module's doc comment
/// for why nothing here is a second decompression stack.
///
/// Never returns `Err` for malformed, truncated or genuinely I/O-failing
/// input — every one of those folds into [`SalvageStatus::Partial`], the
/// same discipline `zip_salvage.rs`'s own `verify_candidate` documents at
/// length: salvage exists to recover as much of a damaged archive as it
/// can, and aborting the WHOLE run over one bad entry would be worse than
/// marking that entry `Partial` and continuing.
///
/// The ONE exception is [`super::arc::refuse_if_over_ceiling`]: an
/// implausible declared `compressed_size` is refused with
/// [`stuffr_core::Error::ResourceLimit`] (exit 6), propagated rather than
/// folded — the identical ceiling, the identical error, `arc.rs`'s own
/// `read_payload` raises for the same field, checked here BEFORE the
/// payload buffer it would size is ever allocated. See this module's doc
/// for why this could not live in the discovery gate instead.
fn verify_candidate(src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
    // The payload is PROVABLY incomplete — nothing needs decoding to know
    // the answer. Sits above the method dispatch on purpose, for the
    // identical reason `zip_salvage.rs`'s own `verify_candidate` gives: a
    // truncated payload under an undecodable method is still truncated, and
    // `Partial` (proven missing) is a stronger claim than `Unverified`
    // (nothing attempted).
    if candidate.available_len.is_some() {
        return Ok(SalvageStatus::Partial);
    }
    let Some(declared_len) = candidate.declared_len else {
        // Unreachable in practice: `read_candidate_at` always reports a
        // declared length for an ARC candidate (the format has no
        // equivalent of zip's data-descriptor case). Kept as the honest
        // fallback rather than a `Complete` this scanner never means.
        return Ok(SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength));
    };
    let Some(Verifier::Crc16(expected_crc)) = candidate.verifier else {
        // Every ARC candidate this scanner reports carries a CRC-16 (see
        // `read_candidate_at`) — unreachable in practice.
        return Ok(SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength));
    };

    if src.seek(SeekFrom::Start(candidate.offset)).is_err() {
        return Ok(SalvageStatus::Partial);
    }
    let mut marker = [0u8; 1];
    let mut record = [0u8; HEADER_LEN];
    if src.read_exact(&mut marker).is_err() || src.read_exact(&mut record).is_err() {
        return Ok(SalvageStatus::Partial);
    }
    let header = ArcHeader::parse(&record);

    let method = match Method::from_byte(header.method_byte, &header.name) {
        Ok(method) => method,
        // A method this build recognises as real ARC metadata but cannot
        // decode (5-7, 10-11) — the format DOES carry a checksum here, this
        // build simply never attempted to check it. `Unverified`, never
        // `Complete`.
        Err(_) => {
            return Ok(SalvageStatus::Unverified(
                UnverifiedCause::UndecodableMethod,
            ));
        }
    };

    // Bound BEFORE allocating the payload buffer below — the identical
    // ceiling and error `arc.rs`'s own `read_payload` raises for this same
    // field, checked independently here because `verify` is the one place
    // in this module that actually allocates one.
    refuse_if_over_ceiling(&header.name, declared_len, "compressed data")?;

    // Fix round 1, LOW-1: use the field the candidate already carries
    // rather than re-deriving it — `Candidate::payload_start`'s own doc
    // exists precisely so nothing else in this crate has to recompute a
    // payload's location from `offset` at all, let alone risk a second
    // derivation drifting from `read_candidate_at`'s own (fix round 2,
    // NEW-3: also `checked_add`-built, not the raw `+` an earlier version
    // of this comment claimed).
    if src.seek(SeekFrom::Start(candidate.payload_start)).is_err() {
        return Ok(SalvageStatus::Partial);
    }
    let mut payload = vec![0u8; declared_len as usize];
    if src.read_exact(&mut payload).is_err() {
        return Ok(SalvageStatus::Partial);
    }

    let decoded = match decode(method, &payload, &header.name) {
        Ok(decoded) => decoded,
        // A decode failure here (malformed compressed data, or the
        // decoder's own output-side ceiling) is exactly as unproven as a
        // checksum that disagrees — `Partial`, not a second `Err` path.
        Err(_) => return Ok(SalvageStatus::Partial),
    };

    Ok(crate::salvage_verify::stream_verify(
        io::Cursor::new(decoded),
        u64::from(header.original_size),
        &Verifier::Crc16(expected_crc),
    ))
}

/// Maps [`EntryMeta::codec`] (as [`codec_for_arc_method`] filled it) back
/// to the [`Method`] [`super::arc::decode`] dispatches on.
///
/// `None` covers the same "never reached in practice" cases
/// `codec_for_arc_method`'s own doc names: a `None` codec, or one this
/// module never produces. [`write_payload`] treats it exactly like an
/// unrecognised zip method — [`Error::Unsupported`], defensive rather than
/// reachable.
///
/// Fix round 2, Ruling S-K: searches the five decodable variants for the
/// one whose [`Method::codec`] matches, rather than hand-copying the same
/// five strings a second time in the opposite direction — see that
/// method's own doc.
fn method_for_codec(codec: Option<FormatId>) -> Option<Method> {
    const DECODABLE: [Method; 5] = [
        Method::Stored,
        Method::Rle90,
        Method::Squeezed,
        Method::Crunched,
        Method::Squashed,
    ];
    let codec = codec?;
    DECODABLE
        .into_iter()
        .find(|&method| method.codec() == codec)
}

/// Reads one entry's compressed payload and writes its RECOVERED (decoded)
/// bytes to `out`. Returns whether the decode reached the entry's own
/// declared length ([`EntryMeta::size`]) — `entries.rs`'s own signal for
/// `PartialCause`, matching `zip_salvage.rs`'s own `write_payload` exactly.
///
/// Uses [`SalvagedEntry::payload_start`] directly, computed once by
/// [`read_candidate_at`] at discovery time — see that field's own doc for
/// why a consumer must never re-derive a payload's location from `offset`
/// itself. Before Task 3c, `entries.rs`'s salvage write path did exactly
/// that, unconditionally as if every candidate were zip-shaped: it read 30
/// bytes from `entry.offset` as a zip local header, which for an ARC entry
/// near end-of-file ran past EOF and raised `Error::Io` (exit 1) — the
/// wildcard this project treats as a defect — rather than anything
/// classified. Locating the payload is this scanner's own job now, decided
/// once by [`read_candidate_at`] and never repeated here.
///
/// An entry reaching this function was already reported `Intact`,
/// `Complete` or `Partial` by [`verify_candidate`] — never `Unverified`,
/// which `entries.rs`'s `place_salvaged_file` already refuses before
/// calling this. So a decode that fails here is re-running bytes
/// `verify_candidate` already examined (or a genuine prefix of them — see
/// below), and is folded into `Ok(false)` ("did not complete") for the same
/// reason that function folds the same failures into
/// `SalvageStatus::Partial` rather than an `Err`: one entry's damage must
/// never abort the recovery of every other entry in the archive.
///
/// # Fix round 1, HIGH-1 and MEDIUM-1: bound the read by what is PRESENT,
/// never by what `compressed_len` DECLARES
///
/// The first version of this function called
/// [`super::arc::refuse_if_over_ceiling`] on `compressed_len` directly —
/// the header's own declaration — and then `read_exact`'d exactly that many
/// bytes. For a `Partial` entry whose payload is TRUNCATED,
/// [`verify_candidate`] returns `Partial` at its very first line, before
/// its OWN ceiling check ever runs — so a truncated header could declare an
/// arbitrary multi-hundred-megabyte figure and reach this function with
/// nothing having bounded it yet. That reproduced, in a second code path,
/// the exact failure mode [`stuffr_core::salvage::collect_candidates`]'s
/// own doc already argues against at length: checking a DECLARED length
/// against a ceiling "would abort the WHOLE run (exit 6) over a garbage
/// length in a tail the scan has already established is not there, which
/// is exactly the archive a caller reached for salvage to rescue". A
/// second, smaller consequence of the same bug: even where the ceiling was
/// not hit, `read_exact` on the full declared length simply failed outright
/// for a truncated Stored entry, writing NOTHING — discarding a genuinely
/// recoverable prefix that zip's own `write_payload` (a `Read`-bounded
/// `.take(compressed_len)`) already recovers.
///
/// Both are closed the same way: `readable_len` below is bounded by the
/// SOURCE's own remaining length, computed from a fresh `seek(End(0))`,
/// never by the header's declaration alone. The subsequent `read_exact`
/// can no longer fail on a truncated entry's own short length, so a
/// truncated Stored (or Rle90) entry's genuine surviving bytes now reach
/// [`super::arc::decode`] and are written, same as zip's truncated-tail
/// case. The non-streamable methods (`Squeezed`, `Crunched`, `Squashed`)
/// still legitimately produce nothing on a truncated input — they decode
/// whole, like `arc.rs`'s own reader, and a mid-stream cut Huffman tree or
/// LZW chain has no defined partial decode — so `Ok(false)` with nothing
/// written stays the honest answer for those.
///
/// # Fix round 2, HIGH-1 residual: what is PRESENT can itself exceed the
/// ceiling, and that must be a per-entry skip, not a whole-run abort
///
/// Round 1's bound closed the common case (a truncated header lying about
/// a payload that never follows) but left the ceiling CHECK propagating a
/// real `Err` when the bytes that genuinely exist are themselves still
/// over [`super::arc::MAX_ARC_ENTRY_LEN`] — measured, on a 283 MB archive
/// whose only fault was one entry's truncated tail also being larger than
/// the ceiling, `salvage --list` still aborted at exit 6 with NO rows
/// printed at all, the exact symptom HIGH-1 was raised about, on the same
/// input class. [`write_payload_bounded`] below now folds that refusal
/// into `Ok(false)` instead — reported as this one entry not completing,
/// never propagated as an `Err` that takes every other entry in the
/// archive down with it, matching every other unrecoverable condition this
/// function already reports this way.
pub fn write_payload(
    archive_path: &Path,
    entry: &SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
) -> Result<bool> {
    write_payload_bounded(
        archive_path,
        entry,
        compressed_len,
        out,
        super::arc::MAX_ARC_ENTRY_LEN,
    )
}

/// [`write_payload`]'s whole body, parameterised over the ceiling it
/// refuses an oversized read against.
///
/// Split out purely so a unit test can exercise the fold-into-`Ok(false)`
/// behaviour above with a SMALL ceiling and a small fixture —
/// `an_entry_whose_present_bytes_alone_exceed_the_ceiling_is_folded_into_ok_false`
/// below — rather than needing a multi-hundred-megabyte file to reach
/// ARC's real 256 MiB [`super::arc::MAX_ARC_ENTRY_LEN`], which would make
/// this the single most expensive thing in a gate that already runs
/// 35-60s, twice, for a branch whose own logic is one comparison.
fn write_payload_bounded(
    archive_path: &Path,
    entry: &SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
    ceiling: u64,
) -> Result<bool> {
    let Some(method) = method_for_codec(entry.meta.codec) else {
        return Err(Error::Unsupported(format!(
            "entry `{}` carries codec {:?}, which this build's salvage writer does not \
             decode (every ARC method it cannot decode already reports as Unverified \
             before reaching here)",
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
    // alone — see this function's own doc above (fix round 1, HIGH-1).
    let available = file_len.saturating_sub(entry.payload_start);
    let readable_len = compressed_len.min(available);

    // Fix round 2, HIGH-1 residual: folded into `Ok(false)`, never
    // propagated — see this function's own doc above for why. Checked
    // against the BOUNDED figure, so a genuinely huge but PRESENT entry is
    // still refused here, before the buffer it would size is allocated;
    // a truncated entry's lie about its own declared size no longer
    // decides this on its own.
    if readable_len > ceiling {
        return Ok(false);
    }

    // Fix round 2, NEW-1: decided from the two lengths alone, BEFORE the
    // read — if fewer compressed bytes are present than the header
    // declared, this entry's compressed payload is truncated, full stop,
    // regardless of what `stream_bounded_copy` below goes on to report.
    // Needed because `expected` (the declared UNCOMPRESSED size, read
    // below) can be small enough that a truncated entry's own partial
    // decode still satisfies it: measured, a header declaring 36
    // compressed bytes and an `original_size` of 10 with only 20
    // compressed bytes actually present decoded its available prefix to
    // exactly 10 bytes and reported "completed" — relabelling a
    // truncation as `PartialCause::ChecksumMismatch` even though no
    // checksum comparison ever ran. A tier carries a decision (already
    // correct: `verify_candidate` reported this entry `Partial` before
    // `write_payload` is ever called); a message carries a cause, and the
    // cause must not contradict the reason the entry is `Partial` in the
    // first place.
    let truncated = readable_len < compressed_len;

    // Fix round 1, MEDIUM-1: reading exactly `readable_len` bytes — never
    // more than the file actually holds — means this `read_exact` no
    // longer fails on a truncated entry, so its genuine surviving prefix
    // reaches `decode` below rather than the whole read failing and
    // nothing being written at all.
    let mut payload = vec![0u8; readable_len as usize];
    if f.read_exact(&mut payload).is_err() {
        // A genuine race (the archive changed on disk between the scan and
        // this write) rather than a length mismatch, which `readable_len`
        // has already ruled out above.
        return Ok(false);
    }

    let decoded = match super::arc::decode(method, &payload, &entry.meta.name) {
        Ok(decoded) => decoded,
        // Malformed or genuinely truncated compressed data — a
        // non-streamable method decoding whole has no defined partial
        // result for a mid-stream cut, and a malformed stream is
        // deterministically the same failure `verify_candidate` already
        // saw and reported as `Partial`. Not propagated, for the reason
        // this function's own doc gives.
        Err(_) => return Ok(false),
    };

    let expected = entry.meta.size.unwrap_or(compressed_len);
    let completed = stream_bounded_copy(io::Cursor::new(decoded), expected, out)?;
    // Fix round 2, NEW-1: a truncated compressed payload is never
    // "completed", whatever `stream_bounded_copy` reports against a
    // possibly-too-small declared `original_size` — see this function's
    // own doc above.
    Ok(completed && !truncated)
}

/// Runs [`ArcSalvage`] over `src` and annotates the result — the whole
/// scanner, matching `zip_salvage.rs`'s own `salvage_zip` entry point
/// exactly (`entries.rs`'s `salvage_scan` dispatches to both the same way).
/// Unlike zip, there is no second index to reconcile against: ARC carries
/// no central directory, so the raw scan is the only source there is.
pub fn salvage_arc(src: &mut dyn SeekRead, policy: &SalvagePolicy) -> Result<SalvageOutcome> {
    let mut scanner = ArcSalvage::new();
    salvage_all(&mut scanner, src, policy)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek};

    use stuffr_core::Error;
    use stuffr_core::salvage::SalvagePolicy;

    use super::super::crc::crc16_arc;
    use super::*;

    // -------------------------------------------------------------------
    // Test-only header builders — mirrors `arc.rs`'s own `build_arc_entry`
    // helper, not reused directly: that one lives inside `arc.rs`'s private
    // `#[cfg(test)] mod tests`, unreachable from a sibling module.
    // -------------------------------------------------------------------

    const NAME_LEN: usize = 13;

    fn build_arc_entry_declaring(
        method: u8,
        name: &str,
        payload: &[u8],
        declared_size: u32,
        declared_original: u32,
    ) -> Vec<u8> {
        let mut out = vec![MARKER, method];
        let mut field = [0u8; NAME_LEN];
        field[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&field);
        out.extend_from_slice(&declared_size.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // date/time
        out.extend_from_slice(&crc16_arc(payload).to_le_bytes());
        out.extend_from_slice(&declared_original.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn build_arc_entry(method: u8, name: &str, payload: &[u8]) -> Vec<u8> {
        build_arc_entry_declaring(
            method,
            name,
            payload,
            payload.len() as u32,
            payload.len() as u32,
        )
    }

    fn build_arc(entries: &[(u8, &str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(method, name, payload) in entries {
            out.extend_from_slice(&build_arc_entry(method, name, payload));
        }
        out.extend_from_slice(&[MARKER, 0]); // end-of-archive marker
        out
    }

    // -------------------------------------------------------------------
    // The anti-vacuity pair (Step 1)
    // -------------------------------------------------------------------

    /// A small linear congruential generator, not the `rand` crate — the
    /// corpus must be byte-identical on every machine and in CI. Same
    /// constants (Knuth & Lewis, via Numerical Recipes) `zip_salvage.rs`
    /// uses, for the same reason: nothing cryptographic is needed, only
    /// enough uniformity to make a two-byte coincidence rare.
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

    /// Fixed offsets, each with lots of room after it, where only the
    /// MARKER byte is forced — the method byte and everything past it stays
    /// whatever the LCG produced. A marker's own chance of landing on any
    /// given byte is 1-in-256, so seeding it directly (rather than leaving
    /// it to chance across a 1 MiB buffer) is what makes this corpus a real
    /// test of the criteria BEHIND the marker rather than of luck.
    const SEEDED_MARKER_OFFSETS: [usize; 6] = [65_536, 196_608, 344_064, 491_520, 638_976, 786_432];

    /// A fifth (well, seventh) splice, distinct from the bare-marker ones
    /// above: a complete, otherwise gate-clearing ARC header (a recognised
    /// marker, a printable name, an in-bounds and fully-present payload)
    /// whose ONLY defect is `method = 200` — a value `KNOWN_METHOD_RANGE`
    /// does not recognise. This is what ties Step 7's falsification (delete
    /// the method-range check, confirm this position starts clearing the
    /// whole gate) to a SPECIFIC position, rather than to a hand-rolled unit
    /// test elsewhere that could pass or fail for unrelated reasons.
    const METHOD_ONLY_DEFECT_OFFSET: usize = 500_000;

    fn noise_with_seeded_marker(len: usize) -> Vec<u8> {
        let mut noise = deterministic_noise(len);
        for &at in &SEEDED_MARKER_OFFSETS {
            noise[at] = MARKER;
        }
        let defect = build_arc_entry_declaring(200, "OK.TXT", b"", 0, 0);
        noise[METHOD_ONLY_DEFECT_OFFSET..METHOD_ONLY_DEFECT_OFFSET + defect.len()]
            .copy_from_slice(&defect);
        noise
    }

    /// A two-byte marker+method match occurs by chance roughly every 8 KiB
    /// (see this module's doc) — far weaker than zip's four-byte signature.
    /// A scanner that reports every such coincidence as an entry is WORSE
    /// than no scanner at all: this is the negative double for the whole
    /// feature.
    #[test]
    fn arc_salvage_over_random_bytes_finds_nothing() {
        let noise = noise_with_seeded_marker(1 << 20); // 1 MiB, fixed seed
        let mut scan = ArcSalvage::new();
        let out = salvage_all(
            &mut scan,
            &mut Cursor::new(noise),
            &SalvagePolicy::default(),
        )
        .expect("a noise corpus must not error the scan, only find nothing in it");
        assert!(
            out.entries.is_empty(),
            "found {} phantom entries in noise",
            out.entries.len()
        );
    }

    /// Without this, the test above could pass because the noise happens to
    /// contain no marker byte at all — proving nothing about the validation
    /// gate. This asserts the gate is what rejects the hits, not their
    /// absence.
    #[test]
    fn the_arc_noise_corpus_really_does_contain_the_marker() {
        let noise = noise_with_seeded_marker(1 << 20);
        let hits = noise.iter().filter(|&&b| b == MARKER).count();
        assert!(
            hits > 0,
            "the anti-vacuity corpus must contain the marker byte it is testing rejection of"
        );
        // `>=` rather than `==`: the deliberately seeded hits are
        // guaranteed, but this does not also assert the LCG produces no
        // INCIDENTAL extra marker byte of its own — an incidental hit is
        // just one more coincidence for the gate to reject, and must not
        // make this assertion flaky.
        let seeded = SEEDED_MARKER_OFFSETS.len() + 1;
        assert!(
            hits >= seeded,
            "expected at least the {seeded} deliberately seeded hits, found {hits}"
        );
    }

    // -------------------------------------------------------------------
    // Fix round 1, REQUIRED 2: the anti-vacuity pair above only proves the
    // gate REJECTS a coincidence — it never proves the SCAN survives one and
    // keeps going. It did not: the fix round's own falsification of the
    // pair above found a genuine marker+name coincidence in the noise at
    // offset 251426 (name `"lf@"`, declared length 1,619,268,811), not the
    // deliberately seeded defect header this test file's report originally
    // (and wrongly) blamed. `stuffr_core::salvage::collect_candidates` used
    // to advance past a truncated candidate by `available_len` — "every
    // byte left in the file" by construction — so that one lying header
    // jumped the scan straight to EOF and silently dropped every real entry
    // after it, with no error, no `Partial`, no note. This test reproduces
    // that shape directly rather than relying on a coincidence to appear
    // in noise, and must never regress.
    // -------------------------------------------------------------------

    /// A real entry, then a region shaped exactly like the false positive
    /// that exposed the engine bug — a plausible marker, a recognised
    /// method, a printable name, but a declared `compressed_size` that
    /// overruns everything left in the buffer (so `available_len` reports
    /// "the rest of the file", the same figure a genuinely truncated real
    /// last entry would report) — then MORE real entries after it. Before
    /// the engine fix, `collect_candidates` trusted that lying length to
    /// skip straight to the end of the source, and `SECOND.TXT` was never
    /// found at all: this is that regression, made deterministic instead of
    /// waiting for a coincidence in noise.
    #[test]
    fn a_lying_declared_length_does_not_swallow_the_real_entries_after_it() {
        let mut bytes = build_arc_entry(2, "FIRST.TXT", b"hello");
        // The phantom-shaped region: nothing genuine follows it before
        // `SECOND.TXT`'s own header, so its declared 50,000,000-byte
        // payload is a bald lie the moment the file runs out.
        bytes.extend_from_slice(&build_arc_entry_declaring(
            3,
            "PHANTOM.BIN",
            b"",
            50_000_000,
            0,
        ));
        bytes.extend_from_slice(&build_arc_entry(4, "SECOND.TXT", b"world"));
        bytes.extend_from_slice(&[MARKER, 0]); // end-of-archive marker

        let out = salvage_all(
            &mut ArcSalvage::new(),
            &mut Cursor::new(bytes),
            &SalvagePolicy::default(),
        )
        .expect("a lying declared length must not abort the whole scan");

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

    // -------------------------------------------------------------------
    // The positive complement: a scanner that always returned `Ok(None)`
    // would also pass the anti-vacuity pair trivially. These prove the gate
    // ACCEPTS real headers too, not only rejects fake ones.
    // -------------------------------------------------------------------

    #[test]
    fn salvage_finds_every_entry_in_a_real_archive() {
        let bytes = build_arc(&[
            (2, "ONE.TXT", b"hello, arc"),
            (3, "TWO.TXT", b"aaaaaaaaaaaaaaaaaaaa"),
        ]);
        let out = salvage_all(
            &mut ArcSalvage::new(),
            &mut Cursor::new(bytes),
            &SalvagePolicy::default(),
        )
        .expect("a real archive's headers must all clear the gate");
        assert_eq!(out.entries.len(), 2);
        assert_eq!(out.entries[0].meta.name, "ONE.TXT");
        assert_eq!(out.entries[1].meta.name, "TWO.TXT");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
        assert_eq!(out.entries[1].status, SalvageStatus::Intact);
    }

    #[test]
    fn an_ordinary_header_is_accepted() {
        let bytes = build_arc_entry(2, "HELLO.TXT", b"hi");
        let mut scan = ArcSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes), 0)
            .unwrap()
            .expect("a well-formed header must be accepted");
        assert_eq!(candidate.meta.name, "HELLO.TXT");
        assert_eq!(candidate.declared_len, Some(2));
        assert!(matches!(candidate.verifier, Some(Verifier::Crc16(_))));
    }

    #[test]
    fn a_method_arc_never_assigned_is_rejected() {
        let bytes = build_arc_entry(200, "HELLO.TXT", b"hi");
        let mut scan = ArcSalvage::new();
        assert!(
            scan.next_candidate(&mut Cursor::new(bytes), 0)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn the_end_of_archive_marker_is_not_a_candidate() {
        let bytes = vec![MARKER, 0];
        let mut scan = ArcSalvage::new();
        assert!(
            scan.next_candidate(&mut Cursor::new(bytes), 0)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_name_with_no_printable_bytes_is_rejected() {
        let mut bytes = build_arc_entry(2, "AA", b"hi");
        // Overwrite the two name bytes (right after marker+method) with
        // control bytes that never appear in a real DOS-era name.
        bytes[2] = 0x01;
        bytes[3] = 0x02;
        let mut scan = ArcSalvage::new();
        assert!(
            scan.next_candidate(&mut Cursor::new(bytes), 0)
                .unwrap()
                .is_none()
        );
    }

    /// Criterion 4 REPORTS rather than rejects, mirroring `zip_salvage.rs`'s
    /// own ruling: a header promising payload the file cannot deliver is
    /// still a header, and dropping it would make a truncated archive's
    /// last entry vanish with no row and exit 0.
    #[test]
    fn a_declared_length_running_past_the_file_is_reported_not_dropped() {
        let mut bytes = build_arc_entry(2, "HELLO.TXT", b"hi");
        // Declare a compressed size far larger than what actually follows,
        // without changing the bytes present.
        bytes[15..19].copy_from_slice(&1_000_000u32.to_le_bytes());
        let mut scan = ArcSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes), 0)
            .unwrap()
            .expect("a header found but not completable is still a header");
        assert_eq!(
            candidate.declared_len,
            Some(1_000_000),
            "the declared figure is reported as the header stated it"
        );
        assert_eq!(
            candidate.available_len,
            Some(2),
            "and the two bytes that ARE there are named separately"
        );
    }

    #[test]
    fn a_truncated_candidate_verifies_as_partial() {
        let mut bytes = build_arc_entry(2, "HELLO.TXT", b"hi");
        bytes[15..19].copy_from_slice(&1_000_000u32.to_le_bytes());
        let out = salvage_all(
            &mut ArcSalvage::new(),
            &mut Cursor::new(bytes),
            &SalvagePolicy::default(),
        )
        .unwrap();
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
    }

    /// A method this build recognises as real ARC metadata but cannot
    /// decode (5-7, 10-11) is found and bounded, but never verified —
    /// `Unverified`, never `Complete` (ARC always carries a CRC-16).
    #[test]
    fn an_undecodable_but_recognised_method_verifies_as_unverified() {
        let bytes = build_arc_entry(10, "DISTILLED.BIN", b"whatever");
        let out = salvage_all(
            &mut ArcSalvage::new(),
            &mut Cursor::new(bytes),
            &SalvagePolicy::default(),
        )
        .unwrap();
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::UndecodableMethod)
        );
    }

    /// A decodable entry whose bytes were tampered with after the header
    /// was written disagrees with its own CRC-16 — `Partial`, not a fourth
    /// status: something WAS checked, and it did not hold.
    #[test]
    fn a_decodable_entry_with_a_wrong_crc_verifies_as_partial() {
        let mut bytes = build_arc_entry(2, "HELLO.TXT", b"hi");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF; // flip a payload byte after the CRC was computed
        let out = salvage_all(
            &mut ArcSalvage::new(),
            &mut Cursor::new(bytes),
            &SalvagePolicy::default(),
        )
        .unwrap();
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
    }

    // -------------------------------------------------------------------
    // The ceiling: bounded before allocating, tested with a reader that
    // panics if it ever is (Global Constraints; mirrors `arc.rs`'s own
    // `refuses_an_absurd_compressed_size_before_the_allocation_it_would_size`).
    // -------------------------------------------------------------------

    /// A `Read + Seek` mock that:
    ///  - answers `seek(SeekFrom::End(0))` with a LIE — a huge reported
    ///    length, so the "does the payload fit inside the file" check at
    ///    discovery does not short-circuit this candidate as merely
    ///    truncated (which would return `Partial` without ever reaching the
    ///    ceiling check this test exists to exercise);
    ///  - panics if ever asked to `read` more than `max_single_read` bytes
    ///    in one call — the same instrument `arc.rs`'s own `PanicsOnBigRead`
    ///    and `cpio.rs`'s `refuses_an_absurd_namesize_before_the_allocation_
    ///    it_would_size` use, and for the same reason: a test asserting only
    ///    the error code passes even when `vec![0u8; declared_size]` was
    ///    already allocated, which is the entire defect this class of test
    ///    exists to catch.
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
                 proof `vec![0u8; declared_size]` was already allocated from the header's own \
                 field before any refusal ran",
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
    /// reproducer named, and `arc.rs`'s own `ABSURD_SIZE` — reused here so
    /// the figure is a real one rather than a stand-in, and traceable back
    /// to the container-level test this one mirrors.
    const ABSURD_SIZE: u32 = 0xAAAA_AAAA;

    #[test]
    fn refuses_an_absurd_compressed_size_before_the_allocation_it_would_size() {
        let bytes = build_arc_entry_declaring(2, "BIG.BIN", b"", ABSURD_SIZE, 0);
        let mut src = LyingLenPanicsOnBigRead {
            inner: Cursor::new(bytes),
            reported_len: u64::from(ABSURD_SIZE) * 4,
            // Comfortably above `SCAN_CHUNK` (the discovery-time scan reads
            // in 64 KiB chunks regardless of this test) and comfortably
            // below `ABSURD_SIZE` (~2.86 GiB) — wide enough that ordinary
            // header/scan reads never trip it, narrow enough that the
            // payload allocation this test forbids still would.
            max_single_read: 128 * 1024,
        };
        let err = salvage_all(&mut ArcSalvage::new(), &mut src, &SalvagePolicy::default())
            .expect_err("an absurd compressed_size must be refused");
        assert!(
            matches!(err, Error::ResourceLimit(_)),
            "an implausible declared length is this build refusing to allocate, not a verdict \
             that the archive is damaged — see MAX_ARC_ENTRY_LEN's doc; got {err:?}"
        );
        assert_eq!(err.exit_code(), 6, "ResourceLimit is exit 6: {err:?}");
        assert!(
            err.to_string().contains(&ABSURD_SIZE.to_string()),
            "the message must name the declared size, got: {err}"
        );
    }

    /// The regression guard for the test above: with the LYING seek removed
    /// (so the source's real, short length is visible), the identical
    /// absurd size is caught by the ORDINARY truncation path instead —
    /// `Partial`, never `ResourceLimit` — pinning that the ceiling check is
    /// bounded by `MAX_ARC_ENTRY_LEN` and does not fire merely because a
    /// declared length has no data behind it.
    #[test]
    fn a_modest_declared_size_with_no_data_behind_it_is_partial_not_resource_limited() {
        let bytes = build_arc_entry_declaring(2, "SHORT.BIN", b"", 64, 0);
        let out = salvage_all(
            &mut ArcSalvage::new(),
            &mut Cursor::new(bytes),
            &SalvagePolicy::default(),
        )
        .expect("a modest, merely truncated size must not be resource-limited");
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
    }

    // -------------------------------------------------------------------
    // Fix round 2, HIGH-1 residual: what is genuinely PRESENT can itself
    // exceed a ceiling, and `write_payload_bounded` must fold that into
    // `Ok(false)` rather than propagate an `Err` that would abort the
    // whole salvage run. Exercised with a SMALL ceiling and a small
    // fixture rather than the real 256 MiB `MAX_ARC_ENTRY_LEN` — see
    // `write_payload_bounded`'s own doc for why building a
    // multi-hundred-megabyte fixture here would be the wrong fix.
    // -------------------------------------------------------------------

    #[test]
    fn an_entry_whose_present_bytes_alone_exceed_the_ceiling_is_folded_into_ok_false() {
        // The header declares far more (10,000) than either the tiny test
        // ceiling below or the 100 bytes actually written to disk; what
        // matters is `available` — computed by `write_payload_bounded`
        // from the real file length — which is exactly the 100 bytes
        // present, comfortably over the 50-byte ceiling this test passes.
        let present = vec![0xABu8; 100];
        let bytes = build_arc_entry_declaring(1, "BIG.BIN", &present, 10_000, 100);

        let path = std::env::temp_dir().join(format!(
            "stuffr-arc-salvage-ceiling-{}-{:p}.arc",
            std::process::id(),
            &bytes
        ));
        std::fs::write(&path, &bytes).unwrap();

        let entry = SalvagedEntry {
            scan_position: 0,
            offset: 0,
            payload_start: 1 + HEADER_LEN as u64,
            meta: {
                let mut m = EntryMeta::file("BIG.BIN");
                m.codec = codec_for_arc_method(1);
                m.size = Some(100);
                m.compressed_size = Some(10_000);
                m
            },
            status: SalvageStatus::Partial,
            shadows: None,
            collides_with: None,
        };

        let mut sink: Vec<u8> = Vec::new();
        let result = write_payload_bounded(&path, &entry, 10_000, &mut sink, 50);
        let _ = std::fs::remove_file(&path);

        let completed = result.expect(
            "an over-ceiling-but-present read must be folded into Ok(false), never \
             propagated as an Err that would abort the whole salvage run (fix round 2, \
             HIGH-1 residual)",
        );
        assert!(!completed, "must report as not completed, never an Err");
        assert!(
            sink.is_empty(),
            "nothing should be written once the bounded read is refused before allocating"
        );
    }

    // -------------------------------------------------------------------
    // Step 7's falsification target: proven present in the noise corpus
    // above via `the_arc_noise_corpus_really_does_contain_the_marker`. The
    // task report records what happens to
    // `arc_salvage_over_random_bytes_finds_nothing` when the method-range
    // check in `read_candidate_at` is deleted.
    // -------------------------------------------------------------------

    #[test]
    fn the_method_only_defect_is_rejected_by_the_method_check_alone() {
        // Isolates `METHOD_ONLY_DEFECT_OFFSET`'s own header (not the whole
        // noise buffer) to prove it clears every OTHER criterion — so
        // deleting the method-range check is really what the falsification
        // in the task report exercises, not some other defect in the
        // crafted bytes.
        let defect = build_arc_entry_declaring(200, "OK.TXT", b"", 0, 0);
        let mut scan = ArcSalvage::new();
        assert!(
            scan.next_candidate(&mut Cursor::new(defect), 0)
                .unwrap()
                .is_none(),
            "method 200 must be rejected"
        );
    }
}
