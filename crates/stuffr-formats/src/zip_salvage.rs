//! zip local-header salvage scan: recovers entries by looking directly for
//! `PK\x03\x04` records, rather than trusting any index — the central
//! directory, the end-of-central-directory record — that may be truncated,
//! zeroed, or absent altogether. `zip.rs`'s [`crate::zip::walk_central_directory`]
//! recovers records an INTACT index shadows; this module is for when the
//! index cannot be trusted at all.
//!
//! # The validation gate is the whole point
//!
//! A four-byte magic occurs by chance roughly once every 4 GiB of random
//! data. A scanner that reports every `PK\x03\x04` sighting as an entry
//! would manufacture plausible-looking phantom entries out of pure noise —
//! worse than no scanner, because a caller has no way to tell a real
//! recovered entry from one the scanner invented. [`ZipSalvage`] therefore
//! reports a candidate only once ALL of the following hold, checked in an
//! order that never allocates or trusts anything before it is cheap to
//! check:
//!
//! 1. The four-byte signature matches ([`find_next_local_header`]).
//! 2. `version needed to extract` is a value this format could plausibly
//!    have written (see [`is_known_version`]).
//! 3. `compression method` is one this project recognises at all (see
//!    [`is_known_method`]) — recognised, not necessarily decodable by this
//!    build. A method this build cannot decode is still real zip metadata;
//!    refusing to decode it is a later concern (verification), not this
//!    one's (discovery).
//! 4. `name_len` is within [`MAX_LOCAL_NAME_LEN`], checked before a name
//!    buffer is ever allocated from it — same discipline, same numeral, as
//!    `zip.rs`'s `MAX_CD_NAME_LEN`. As that constant's own note records, a
//!    real header can never exceed it (the field is 16 bits), so this can
//!    only ever fire on a coincidence — kept anyway, for the reason that
//!    note gives: the day a length is read some other way, the ceiling is
//!    already in place.
//! 5. The name decodes as UTF-8 — strictly, not the lossy fallback
//!    `zip.rs`'s central-directory walk uses for the same field. That walk
//!    starts from an EOCD-anchored offset, where a signature match is
//!    already high-confidence and an unreadable name is still a name worth
//!    reporting. A raw byte-level match here carries none of that
//!    confidence yet, so an undecodable name is treated as the coincidence
//!    it almost certainly is, rather than forced through lossily.
//! 6. `local_header_offset + declared_len` fits inside the source. Nothing
//!    is ever sized or allocated from `declared_len` to reach this check —
//!    it is pure arithmetic against the source's own length.
//!
//! Any failure at 2-6 is not an error: it means this four-byte match was a
//! coincidence, not a header, so the scan simply resumes searching one byte
//! past it. That is a deliberate departure from `zip.rs`'s central-directory
//! walk, where a signature match past the EOCD is already trusted enough
//! that a LATER field failing to parse there is reported as
//! `Error::Corrupt` — this scan has no such anchor at all, so nothing found
//! here can be corruption; it can only be noise or a real header, and the
//! gate's whole job is telling the two apart.
//!
//! # General-purpose bit 3 — the data-descriptor case
//!
//! When flag bit 3 is set, `crc32`/`compressed_size`/`uncompressed_size` in
//! the local header are placeholders (zero) by construction — the real
//! values follow the payload in a data descriptor this module does not
//! locate. Reporting a "verified" checksum of `Crc32(0)` there would be a
//! lie, so a candidate found this way carries `declared_len: None` and
//! `verifier: None` instead: an honest "found a header, cannot bound or
//! verify its payload from here" — the same asymmetry [`Candidate::verifier`]
//! documents for a format with no checksum at all.
//!
//! # Verification, and the two methods it actually checks (Task 4)
//!
//! [`ZipSalvage::verify`] decides [`SalvageStatus`] by re-reading the local
//! header at a candidate's own offset — structurally, so this works
//! identically whether the candidate came from the scan above or from the
//! central-directory fallback below; a header's `name_len`/`extra_len` are
//! byte COUNTS, readable regardless of whether the name itself decodes as
//! UTF-8 — then decoding its declared payload and comparing the result
//! against [`Candidate::verifier`]:
//!
//! - **Stored** (method 0): the payload IS the uncompressed bytes; nothing
//!   to decode, only to read and hash.
//! - **Deflate** (method 8): inflated with `flate2::read::DeflateDecoder` —
//!   the identical backend `deflate.rs` and this crate's `zip = [...,
//!   "dep:flate2"]` feature line already depend on for this exact format.
//!   Not a new decompression stack; the lowest-level call the existing one
//!   already makes, used directly here because the entries this module
//!   exists to recover (a shadowed record, a CP437-named one) are precisely
//!   the ones the `zip` crate's own indexed reader cannot reach at all.
//! - **Anything else**: `Complete`. This build's zip codec registers more
//!   methods than this verifier decodes; a candidate using one is still
//!   correctly discovered and bounded, it is simply not checked against its
//!   CRC-32 today — a narrower scope than "every zip method", recorded here
//!   rather than silently assumed away.
//!
//! Fewer than the declared number of bytes actually present (a short read at
//! any point) is `Partial` immediately, before any decode is attempted — the
//! "payload ran out" half of [`SalvageStatus::Partial`]'s definition. A full
//! decode that disagrees with the declared CRC-32 is ALSO `Partial`, not a
//! fourth status: [`stuffr_core::salvage`]'s three tiers are deliberately
//! exhaustive, and a checksum that was checked and failed is exactly as
//! unproven as a decode that failed outright — neither `Intact` (the
//! checksum did not agree) nor `Complete` (something WAS checked, and it did
//! not hold).
//!
//! # Central-directory reconciliation (ruling R-H)
//!
//! The raw scan's strict UTF-8 name gate (this module's own
//! [`read_candidate_at`]) rejects a legitimate CP437-named entry from a
//! pre-EFS writer — deliberately, per the earlier section above arguing why
//! the gate stays strict. That gate has nowhere to fall back to on its own,
//! so [`salvage_zip`] is the actual safety net ruling R-H requires: it runs
//! the raw scan, then walks the central directory
//! ([`crate::zip::walk_central_directory`]) when one is intact, and for
//! every central-directory record whose `local_header_offset` the scan did
//! NOT already find — a name the scan's UTF-8 gate rejected, or a length the
//! scan's own "fits inside the file" check refused — recovers it
//! independently via [`candidate_from_cd_record`], which trusts the
//! CENTRAL-DIRECTORY's declared name/size/CRC (already lossily decoded and
//! already past `zip.rs`'s own record-level checks) rather than re-deriving
//! them from the raw header.
//!
//! This is the argument the earlier section's doc does not make: the reason
//! a CP437 name is not lost is NOT "the scan carries less confidence than
//! the index" — it is that **the central-directory path has no UTF-8
//! restriction at all**, and reconciling the two sources means a name only
//! the scan can see (behind a destroyed central directory) and a name only
//! the central directory can see (behind the scan's UTF-8 gate) both
//! survive. Only an archive with BOTH a destroyed central directory AND a
//! non-UTF-8 name loses that entry — proven by
//! `a_non_utf8_name_the_scan_rejects_is_still_recovered_through_the_central_directory`
//! below, whose falsification (skip the central-directory fallback) is
//! recorded in the task report.

use std::io::{self, Read, SeekFrom};

use stuffr_core::salvage::{
    Candidate, SalvageOutcome, SalvagePolicy, SalvageScan, SalvageStatus, Verifier,
    annotate_candidates, collect_candidates,
};
use stuffr_core::{EntryKind, EntryMeta, Error, Result, SeekRead};

/// Local file header. What every zip entry starts with (`zip.rs`'s private
/// `SIG_LOCAL_HEADER`, duplicated here rather than exported: it is a magic
/// number, not an API either module should have to expose to the other).
const SIG_LOCAL_HEADER: [u8; 4] = *b"PK\x03\x04";

/// Bytes of a whole local file header, signature included, up to (not
/// including) the name/extra/payload that follow it.
const LOCAL_HEADER_TOTAL: u64 = 30;

/// Ceiling on a local header's declared `name_len`, checked before
/// allocating a name buffer sized from it. Same numeral, same reasoning, as
/// `zip.rs`'s `MAX_CD_NAME_LEN`: the field is 16 bits, so no genuine header
/// can ever exceed this — it exists for the day that stops being true, and
/// to keep the discipline explicit at every site that reads an
/// attacker-controlled length off a scanned header.
const MAX_LOCAL_NAME_LEN: u64 = 65_536;

/// General-purpose bit flag bit 3 (APPNOTE 4.4.4): sizes and CRC-32 live in
/// a data descriptor that follows the payload, not in this header.
const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;

/// Bytes read per [`find_next_local_header`] chunk. Kept O(1) memory rather
/// than reading the remainder of a possibly enormous archive into one
/// buffer: unlike every other bounded read in this module, this scanner has
/// no idea how far the next match is when it starts looking.
const SCAN_CHUNK: usize = 64 * 1024;

/// Scans a zip for local file headers directly, without trusting any index.
///
/// Carries no state between calls beyond what
/// [`SalvageScan::next_candidate`] itself receives (a fresh archive offset
/// each time, per that method's contract), so there is nothing to
/// initialise beyond the unit value.
#[derive(Debug, Default)]
pub struct ZipSalvage;

impl ZipSalvage {
    pub fn new() -> Self {
        Self
    }
}

impl SalvageScan for ZipSalvage {
    fn next_candidate(&mut self, src: &mut dyn SeekRead, from: u64) -> Result<Option<Candidate>> {
        let file_len = src.seek(SeekFrom::End(0))?;
        let mut search_from = from;
        loop {
            let Some(offset) = find_next_local_header(src, search_from, file_len)? else {
                return Ok(None);
            };
            match read_candidate_at(src, offset, file_len)? {
                Some(candidate) => return Ok(Some(candidate)),
                // The signature matched, but the gate rejected it: a
                // coincidence, not a header. Resume one byte past the
                // signature's OWN first byte — not past the whole fixed
                // block — so a genuine header overlapping this false match
                // is never skipped over.
                None => search_from = offset + 1,
            }
        }
    }

    fn verify(&self, src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
        verify_candidate(src, candidate)
    }
}

/// Searches forward from `from` for the next four-byte local-header
/// signature, in bounded chunks so memory use does not depend on how far
/// through the source the next match is (or whether there is one at all).
///
/// `Ok(None)` when the signature is not found before `file_len`. Carries at
/// most three bytes across a chunk boundary — the longest a signature match
/// can straddle one — so a match split across two reads is never missed.
fn find_next_local_header(
    src: &mut dyn SeekRead,
    from: u64,
    file_len: u64,
) -> io::Result<Option<u64>> {
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
            .windows(SIG_LOCAL_HEADER.len())
            .position(|w| w == SIG_LOCAL_HEADER.as_slice())
        {
            return Ok(Some(window_start + at as u64));
        }

        // Keep only the last 3 bytes: the longest prefix of the magic that
        // could still be waiting for its remaining bytes in the next chunk.
        let keep = window.len().saturating_sub(3);
        window_start += keep as u64;
        window.drain(..keep);
    }
}

/// Reads the local header believed to start at `offset` and runs it through
/// the validation gate described in the module doc. `Ok(None)` for ANY gate
/// failure, including the header itself running past `file_len` — see the
/// module doc for why a rejection here is never an error.
fn read_candidate_at(
    src: &mut dyn SeekRead,
    offset: u64,
    file_len: u64,
) -> Result<Option<Candidate>> {
    src.seek(SeekFrom::Start(offset))?;
    let mut fixed = [0u8; LOCAL_HEADER_TOTAL as usize];
    if src.read_exact(&mut fixed).is_err() {
        return Ok(None);
    }
    debug_assert_eq!(
        fixed[0..4],
        SIG_LOCAL_HEADER,
        "caller already matched the signature"
    );

    let version = u16::from_le_bytes([fixed[4], fixed[5]]);
    let flags = u16::from_le_bytes([fixed[6], fixed[7]]);
    let method = u16::from_le_bytes([fixed[8], fixed[9]]);
    let crc32 = u32::from_le_bytes([fixed[14], fixed[15], fixed[16], fixed[17]]);
    let compressed_size = u32::from_le_bytes([fixed[18], fixed[19], fixed[20], fixed[21]]);
    let uncompressed_size = u32::from_le_bytes([fixed[22], fixed[23], fixed[24], fixed[25]]);
    let name_len = u16::from_le_bytes([fixed[26], fixed[27]]);
    let extra_len = u16::from_le_bytes([fixed[28], fixed[29]]);

    if !is_known_version(version) || !is_known_method(method) {
        return Ok(None);
    }
    if u64::from(name_len) > MAX_LOCAL_NAME_LEN {
        return Ok(None);
    }

    let mut name_bytes = vec![0u8; name_len as usize];
    if src.read_exact(&mut name_bytes).is_err() {
        return Ok(None);
    }
    let Ok(name) = String::from_utf8(name_bytes) else {
        return Ok(None);
    };

    if skip_forward(src, u64::from(extra_len)).is_err() {
        return Ok(None);
    }

    let has_data_descriptor = flags & FLAG_DATA_DESCRIPTOR != 0;
    let (declared_len, verifier, size) = if has_data_descriptor {
        (None, None, None)
    } else {
        (
            Some(u64::from(compressed_size)),
            Some(Verifier::Crc32(crc32)),
            Some(u64::from(uncompressed_size)),
        )
    };

    if let Some(len) = declared_len {
        let fits = offset
            .checked_add(LOCAL_HEADER_TOTAL)
            .and_then(|v| v.checked_add(u64::from(name_len)))
            .and_then(|v| v.checked_add(u64::from(extra_len)))
            .and_then(|start| start.checked_add(len))
            .is_some_and(|end| end <= file_len);
        if !fits {
            return Ok(None);
        }
    }

    // A zip directory entry is a zero-length entry whose name ends in `/`
    // (`zip.rs`'s `entry_meta` documents the same convention) — the one kind
    // of entry a bare local header can still tell apart from a plain file.
    let kind = if name.ends_with('/') {
        EntryKind::Dir
    } else {
        EntryKind::File
    };

    let mut meta = EntryMeta::file(name);
    meta.size = size;
    meta.compressed_size = declared_len;
    meta.kind = kind;

    Ok(Some(Candidate {
        offset,
        meta,
        declared_len,
        verifier,
    }))
}

/// Whether a local header's "version needed to extract" field is one the
/// zip format could plausibly have produced.
///
/// APPNOTE.TXT (section 4.4.3.2) states the field is `major*10 + minor` and
/// that "the current maximum value is 63" (i.e. 6.3, the newest revision
/// this constant tracks). No real writer emits a value above that, so this
/// alone already narrows a coincidental match to roughly one in 1,024 —
/// most of this gate's power against noise, for the cost of one comparison.
fn is_known_version(version: u16) -> bool {
    version <= 63
}

/// Whether a local header's compression method is one this project
/// recognises — mirrored from `zip.rs`'s own `method_name` table rather
/// than reusing it directly: that function exists for an ERROR MESSAGE
/// (naming what a real, indexed entry uses), this one is a GATE (deciding
/// whether a four-byte coincidence gets to masquerade as a header at all),
/// and the two call sites should not have to agree on visibility for what
/// happens to be the same table today.
fn is_known_method(method: u16) -> bool {
    matches!(
        method,
        0 | 1 | 2..=5 | 6 | 8 | 9 | 12 | 14 | 93 | 95 | 98 | 99
    )
}

/// Reads and discards exactly `n` bytes, failing on a short read rather than
/// silently leaving the cursor wherever a bare seek would land — the same
/// reasoning `zip.rs`'s own (private) `skip_forward` documents.
fn skip_forward(src: &mut dyn SeekRead, n: u64) -> io::Result<()> {
    let copied = io::copy(&mut src.take(n), &mut io::sink())?;
    if copied != n {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("expected to skip {n} bytes, only {copied} were available"),
        ));
    }
    Ok(())
}

/// Decides [`SalvageStatus`] for one candidate by re-reading the local
/// header at its own `offset` — see this module's doc comment for why that
/// works identically for a scan-found or a central-directory-recovered
/// candidate — then decoding its declared payload and comparing it against
/// [`Candidate::verifier`].
///
/// Never returns `Err` for malformed or truncated input: a read or decode
/// failure here is exactly what [`SalvageStatus::Partial`] means, not a hard
/// error. An `Err` only propagates from a genuine device-level I/O failure
/// on `src` itself, never from data this function merely dislikes.
fn verify_candidate(src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
    let Some(declared_len) = candidate.declared_len else {
        // A data-descriptor entry: no declared length, no verifier (see the
        // module doc's "general-purpose bit 3" section) — nothing here to
        // check, so `Complete` is the honest claim: the header parsed and
        // nothing is known to be missing, but there is no way to prove it.
        return Ok(SalvageStatus::Complete);
    };
    let Some(Verifier::Crc32(expected)) = candidate.verifier else {
        // Zip only ever reports `Crc32` (see `read_candidate_at`); anything
        // else reaching here is unreachable in practice, and `Complete` is
        // the safe answer if it ever did.
        return Ok(SalvageStatus::Complete);
    };

    if src.seek(SeekFrom::Start(candidate.offset)).is_err() {
        return Ok(SalvageStatus::Partial);
    }
    let mut fixed = [0u8; LOCAL_HEADER_TOTAL as usize];
    if src.read_exact(&mut fixed).is_err() {
        return Ok(SalvageStatus::Partial);
    }
    let method = u16::from_le_bytes([fixed[8], fixed[9]]);
    let name_len = u16::from_le_bytes([fixed[26], fixed[27]]);
    let extra_len = u16::from_le_bytes([fixed[28], fixed[29]]);
    let payload_start = candidate
        .offset
        .saturating_add(LOCAL_HEADER_TOTAL)
        .saturating_add(u64::from(name_len))
        .saturating_add(u64::from(extra_len));
    if src.seek(SeekFrom::Start(payload_start)).is_err() {
        return Ok(SalvageStatus::Partial);
    }

    let mut compressed = Vec::new();
    if src.take(declared_len).read_to_end(&mut compressed).is_err() {
        return Ok(SalvageStatus::Partial);
    }
    if compressed.len() as u64 != declared_len {
        // Fewer bytes than this candidate's own header declared were
        // actually present — the payload ran out before the header said it
        // would, the first half of `SalvageStatus::Partial`'s definition.
        return Ok(SalvageStatus::Partial);
    }

    let decoded = match method {
        // Stored: the payload IS the uncompressed bytes.
        0 => compressed,
        // Deflate: `flate2::read::DeflateDecoder`, the same backend
        // `deflate.rs` already depends on for this exact format — see the
        // module doc's "verification" section for why this is not a new
        // decompression stack.
        8 => {
            let mut out = Vec::new();
            if flate2::read::DeflateDecoder::new(compressed.as_slice())
                .read_to_end(&mut out)
                .is_err()
            {
                // The deflate stream itself ran out or was malformed before
                // producing all its bytes — "the decoder failed mid-stream",
                // the second half of `SalvageStatus::Partial`'s definition.
                return Ok(SalvageStatus::Partial);
            }
            out
        }
        // A method this verifier does not decode — see the module doc.
        // The declared bytes are confirmed present (above); their content is
        // simply not checked by this build.
        _ => return Ok(SalvageStatus::Complete),
    };

    if crc32_ieee(&decoded) == expected {
        Ok(SalvageStatus::Intact)
    } else {
        // Every declared byte decoded, but the result does not match the
        // checksum the original writer computed — not proven whole, so
        // `Partial`, never `Complete` (which would claim nothing had been
        // checked at all) and never `Intact`.
        Ok(SalvageStatus::Partial)
    }
}

/// CRC-32/ISO-HDLC (reflected polynomial 0xEDB88320, init and xorout
/// 0xFFFFFFFF) — the checksum a zip local/central header's `crc32` field
/// carries, over the entry's UNCOMPRESSED bytes.
///
/// Written here rather than taken from `crc32fast` (already in this
/// workspace's dependency tree via `zip`/`flate2`, but not a direct
/// dependency of this crate): `legacy/arj.rs`'s `crc32_ieee` makes the
/// identical argument for the identical algorithm — pulling in a crate for
/// one 12-line routine adds a dependency for no capability. Pinned to the
/// algorithm's published check value below, so a transcription error in the
/// polynomial cannot hide behind this project's own expectations. Not reused
/// from `legacy/arj.rs` directly: that module is feature-gated behind
/// `arj`/`arc`/`zoo`/`lha`, none of which `zip` implies, so a `zip`-only
/// build must not depend on it.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A `Sized` `Read + Seek` wrapper around a `&mut dyn SeekRead`, needed
/// purely so `walk_central_directory<R: Read + Seek>` — generic over a
/// SIZED reader, since it is `pub` API `zip.rs` also calls with concrete
/// types — can be called with a trait object at all. `dyn SeekRead` itself
/// is unsized and cannot instantiate that generic directly.
struct SeekReadRef<'a>(&'a mut dyn SeekRead);

impl Read for SeekReadRef<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Seek for SeekReadRef<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

/// Runs the raw local-header scan and reconciles it with the central
/// directory, when one is intact — see this module's doc comment ("Central-
/// directory reconciliation") for what this closes and why. Falls back to
/// the scan alone when the central directory cannot even be walked (a
/// destroyed or absent index), which is exactly the case the scan exists
/// for.
pub fn salvage_zip(src: &mut dyn SeekRead, policy: &SalvagePolicy) -> Result<SalvageOutcome> {
    let mut scanner = ZipSalvage::new();
    let mut candidates = collect_candidates(&mut scanner, src, policy)?;

    if let Some(cd_records) = crate::zip::walk_central_directory(&mut SeekReadRef(&mut *src)) {
        let found_offsets: std::collections::HashSet<u64> =
            candidates.iter().map(|c| c.offset).collect();

        for record in &cd_records {
            if found_offsets.contains(&record.local_header_offset) {
                // Already recovered by the scan — the scan's own candidate
                // is authoritative (it read the name straight off the local
                // header, rather than through the central directory's lossy
                // decode).
                continue;
            }
            if let Some(candidate) = candidate_from_cd_record(src, record, policy)? {
                candidates.push(candidate);
            }
        }

        // Reconciliation can add entries out of physical order (the central
        // directory itself is walked in ITS OWN order, not file order), so
        // `scan_position` must be renumbered from a single, consistent file
        // order across BOTH sources — not merely the scan's.
        candidates.sort_by_key(|c| c.offset);
    }

    annotate_candidates(&scanner, src, candidates)
}

/// Builds a [`Candidate`] from a central-directory record the raw scan did
/// NOT already find — a CP437 name the scan's strict UTF-8 gate rejected, or
/// a declared length the scan's own "fits inside the file" check refused
/// (a genuinely truncated archive whose central directory nonetheless
/// survived). Trusts the CENTRAL DIRECTORY's own fields (already validated
/// by `zip.rs`'s `read_one_cd_record`) rather than re-deriving them from the
/// raw header — the whole reason this recovers what the scan could not.
///
/// `Ok(None)` when the local header this record claims does not actually
/// begin there — the central directory itself can be trusted to have
/// parsed, but a record's OWN `local_header_offset` field is still
/// attacker- or corruption-controlled data, so this is checked before
/// anything is built from it, exactly as the raw scan checks its own
/// signature match.
fn candidate_from_cd_record(
    src: &mut dyn SeekRead,
    record: &crate::zip::CdRecord,
    policy: &SalvagePolicy,
) -> Result<Option<Candidate>> {
    if record.compressed_size > policy.max_entry {
        return Err(Error::ResourceLimit(format!(
            "central-directory record `{}` declares a compressed size of {} bytes, past the \
             {}-byte salvage ceiling (see stuffr_core::salvage::MAX_SALVAGE_ENTRY)",
            record.name, record.compressed_size, policy.max_entry
        )));
    }

    if src
        .seek(SeekFrom::Start(record.local_header_offset))
        .is_err()
    {
        return Ok(None);
    }
    let mut fixed = [0u8; LOCAL_HEADER_TOTAL as usize];
    if src.read_exact(&mut fixed).is_err() {
        return Ok(None);
    }
    if fixed[0..4] != SIG_LOCAL_HEADER {
        return Ok(None);
    }

    let kind = if record.name.ends_with('/') {
        EntryKind::Dir
    } else {
        EntryKind::File
    };
    let mut meta = EntryMeta::file(record.name.clone());
    meta.size = Some(record.uncompressed_size);
    meta.compressed_size = Some(record.compressed_size);
    meta.kind = kind;

    Ok(Some(Candidate {
        offset: record.local_header_offset,
        meta,
        declared_len: Some(record.compressed_size),
        verifier: Some(Verifier::Crc32(record.crc32)),
    }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use stuffr_core::salvage::{SalvagePolicy, salvage_all};

    use super::*;

    // -------------------------------------------------------------------
    // The anti-vacuity pair
    // -------------------------------------------------------------------

    /// A small linear congruential generator, not the `rand` crate: the
    /// corpus must be byte-identical on every machine and in CI, which a
    /// fixed-seed LCG guarantees and an external PRNG's implementation does
    /// not promise to preserve across versions. Numerical Recipes' constants
    /// (Knuth & Lewis) — nothing cryptographic is needed here, only enough
    /// uniformity to make a four-byte coincidence rare.
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

    /// Fixed offsets, at least [`SIG_LOCAL_HEADER`]'s width apart and each
    /// with LOTS of room after it. A uniform LCG stream is not expected to
    /// contain the magic on its own in only 1 MiB: roughly 2^20 candidate
    /// start positions against a 2^32-wide magic puts the expected natural
    /// count at about 1-in-4096, far from guaranteed. So four occurrences
    /// are spliced in here deliberately, rather than left to chance. Only
    /// the four magic bytes themselves are overwritten at each offset — the
    /// 26 bytes that follow (version, flags, method, sizes, name_len,
    /// extra_len) are left as untouched noise, so what comes after every
    /// seeded hit is exactly as arbitrary as everywhere else in the corpus.
    /// That is what makes `salvage_over_random_bytes_finds_nothing` a real
    /// test of the GATE and not of the corpus's luck:
    /// `the_noise_corpus_really_does_contain_the_local_header_magic` below
    /// proves the hits are really there, and the gate is what has to reject
    /// every one of them.
    const SEEDED_MAGIC_OFFSETS: [usize; 4] = [131_072, 327_680, 622_592, 913_408];

    /// A fifth, more elaborate splice, distinct from the four bare-magic
    /// ones above: not just the four signature bytes, but an otherwise
    /// complete, gate-clearing local header (known version, a decodable
    /// name, an in-bounds empty payload) whose ONLY defect is
    /// `method = 7`, a value [`is_known_method`] does not recognise.
    ///
    /// This is what ties Step 6's falsification (delete the method check,
    /// confirm this test regresses) to THIS test rather than only to a
    /// hand-rolled unit test elsewhere: with the method check removed,
    /// exactly this position starts clearing the whole gate. The four bare
    /// splices are not built to do that — none of them also happens to
    /// carry a known version, a decodable name and an in-bounds size, which
    /// is the whole point of proving (below) that they are rejected on
    /// several independent grounds, not because every one of them was
    /// secretly built to fail one single check.
    const METHOD_ONLY_DEFECT_OFFSET: usize = 500_000;

    fn noise_with_seeded_magic(len: usize) -> Vec<u8> {
        let mut noise = deterministic_noise(len);
        for &at in &SEEDED_MAGIC_OFFSETS {
            noise[at..at + SIG_LOCAL_HEADER.len()].copy_from_slice(&SIG_LOCAL_HEADER);
        }
        let defect = minimal_local_header(20, 7, "ok", b"");
        noise[METHOD_ONLY_DEFECT_OFFSET..METHOD_ONLY_DEFECT_OFFSET + defect.len()]
            .copy_from_slice(&defect);
        noise
    }

    /// A four-byte magic occurs by chance roughly every 4 GiB. A scanner
    /// that reports coincidences as entries is WORSE than no scanner. This
    /// is the negative double for the whole feature — five seeded
    /// coincidences in total (four bare, one a complete header whose only
    /// defect is its method), each rejected by a different gate criterion.
    #[test]
    fn salvage_over_random_bytes_finds_nothing() {
        let noise = noise_with_seeded_magic(1 << 20); // 1 MiB, fixed seed
        let mut scan = ZipSalvage::new();
        let out = salvage_all(
            &mut scan,
            &mut Cursor::new(noise),
            &SalvagePolicy::default(),
        )
        .unwrap();
        assert!(
            out.entries.is_empty(),
            "found {} phantom entries in noise",
            out.entries.len()
        );
    }

    /// Without this, the test above could pass because the noise happens to
    /// contain no `PK\x03\x04` at all — proving nothing about the
    /// validation gate. This asserts the gate is what rejects them, not
    /// their absence.
    #[test]
    fn the_noise_corpus_really_does_contain_the_local_header_magic() {
        let noise = noise_with_seeded_magic(1 << 20);
        let hits = noise.windows(4).filter(|w| *w == b"PK\x03\x04").count();
        assert!(
            hits > 0,
            "the anti-vacuity corpus must contain the magic it is testing rejection of"
        );
        // `>=` rather than `==`: the deliberately seeded hits (the four bare
        // ones, plus the crafted header's own signature) are guaranteed,
        // but this does not also assert the LCG produces no INCIDENTAL
        // extra one of its own — an incidental hit would not invalidate
        // this test (it would just be one more coincidence for the gate
        // above to reject), so it must not make this assertion flaky.
        let seeded = SEEDED_MAGIC_OFFSETS.len() + 1;
        assert!(
            hits >= seeded,
            "expected at least the {seeded} deliberately seeded hits, found {hits}"
        );
    }

    // -------------------------------------------------------------------
    // The positive complement: a scanner that always returned `Ok(None)`
    // would also pass the anti-vacuity pair above trivially. These prove
    // the gate ACCEPTS real headers too, not only rejects fake ones.
    // -------------------------------------------------------------------

    /// Cross-checked against `zip.rs`'s own `walk_central_directory` over
    /// the IDENTICAL bytes, rather than against hand-copied expected values
    /// that could silently drift from the fixture — the same reasoning
    /// `build_shadowing_zip`'s own doc comment gives for building its bytes
    /// at test time instead of committing them.
    #[test]
    fn salvage_finds_every_local_header_in_a_real_archive() {
        let bytes = crate::zip::build_shadowing_zip();
        let cd_records = crate::zip::walk_central_directory(&mut Cursor::new(&bytes))
            .expect("the fixture's own central directory walks cleanly");
        assert_eq!(cd_records.len(), 8, "sanity: the fixture's own shape");

        let mut scan = ZipSalvage::new();
        let out = salvage_all(
            &mut scan,
            &mut Cursor::new(bytes),
            &SalvagePolicy::default(),
        )
        .expect("a real archive's local headers must all clear the gate");
        assert_eq!(
            out.entries.len(),
            8,
            "every physical local header must be found, shadowed or not"
        );

        // The fixture lays its two duplicated local blocks out physically
        // in the same relative order it appends their central-directory
        // records in, so a scan in file order and a walk in central-
        // directory order line up index for index.
        for (entry, record) in out.entries.iter().zip(cd_records.iter()) {
            assert_eq!(entry.offset, record.local_header_offset);
            assert_eq!(entry.meta.name, record.name);
            assert_eq!(
                entry.meta.compressed_size,
                Some(record.compressed_size),
                "entry {} declared_len must match its central-directory record",
                entry.meta.name
            );
        }
    }

    /// The brief's own example: offsets, names, declared lengths, and that
    /// `verifier` is `Some(Crc32(..))` — checked directly against
    /// [`SalvageScan::next_candidate`], since [`stuffr_core::salvage::
    /// SalvagedEntry`] (what `salvage_all` returns) does not carry
    /// `verifier` at all yet — nothing downstream of this task consumes it
    /// today.
    #[test]
    fn a_candidate_carries_its_offset_name_and_crc32_verifier() {
        let bytes = crate::zip::build_shadowing_zip();
        let mut scan = ZipSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes), 0)
            .unwrap()
            .expect("the fixture's first entry is a real local header at offset 0");

        assert_eq!(candidate.offset, 0);
        assert_eq!(candidate.meta.name, "one.txt");
        assert_eq!(
            candidate.declared_len,
            Some(b"payload for entry one".len() as u64)
        );
        assert!(
            matches!(candidate.verifier, Some(Verifier::Crc32(_))),
            "a stored (non-data-descriptor) entry must carry its real CRC-32 as the verifier"
        );
    }

    // -------------------------------------------------------------------
    // The gate's individual criteria
    // -------------------------------------------------------------------

    /// Builds a minimal, otherwise-valid local header + payload, so each
    /// test below can break exactly one field of it.
    fn minimal_local_header(version: u16, method: u16, name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SIG_LOCAL_HEADER);
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags: no data descriptor
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mtime
        out.extend_from_slice(&0u16.to_le_bytes()); // mdate
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed_size
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // uncompressed_size
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra_len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn an_ordinary_header_is_accepted() {
        let bytes = minimal_local_header(20, 0, "hello.txt", b"hi");
        let mut scan = ZipSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes), 0)
            .unwrap()
            .expect("a well-formed header must be accepted");
        assert_eq!(candidate.meta.name, "hello.txt");
        assert_eq!(candidate.declared_len, Some(2));
    }

    #[test]
    fn an_implausible_version_is_rejected() {
        // 6.3 (63) is APPNOTE's own stated current maximum; 64 cannot have
        // come from a real writer.
        let bytes = minimal_local_header(64, 0, "hello.txt", b"hi");
        let mut scan = ZipSalvage::new();
        assert!(
            scan.next_candidate(&mut Cursor::new(bytes), 0)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn an_unrecognised_method_is_rejected() {
        let bytes = minimal_local_header(20, 7, "hello.txt", b"hi");
        let mut scan = ZipSalvage::new();
        assert!(
            scan.next_candidate(&mut Cursor::new(bytes), 0)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_name_that_is_not_valid_utf8_is_rejected() {
        let mut bytes = minimal_local_header(20, 0, "aa", b"hi");
        // Overwrite the two name bytes (right after the 30-byte fixed
        // block) with an invalid UTF-8 sequence: a lone continuation byte.
        bytes[30] = 0x80;
        bytes[31] = 0x80;
        let mut scan = ZipSalvage::new();
        assert!(
            scan.next_candidate(&mut Cursor::new(bytes), 0)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_declared_length_running_past_the_file_is_rejected() {
        let mut bytes = minimal_local_header(20, 0, "hello.txt", b"hi");
        // Declare a compressed size far larger than what actually follows,
        // without changing the bytes present — the header now promises
        // payload the file cannot deliver.
        let absurd = 1_000_000u32.to_le_bytes();
        bytes[18..22].copy_from_slice(&absurd);
        let mut scan = ZipSalvage::new();
        assert!(
            scan.next_candidate(&mut Cursor::new(bytes), 0)
                .unwrap()
                .is_none()
        );
    }

    /// General-purpose bit 3 set: the header's own crc32/sizes are
    /// placeholders, so a candidate is still found (the header itself is
    /// real and well-formed) but carries neither a declared length nor a
    /// verifier — reporting either would be inventing certainty the header
    /// does not have.
    #[test]
    fn a_data_descriptor_entry_is_found_but_unbounded_and_unverified() {
        let mut bytes = minimal_local_header(20, 8, "streamed.bin", b"");
        bytes[6..8].copy_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
        let mut scan = ZipSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes), 0)
            .unwrap()
            .expect("the header itself is well-formed and must still be found");
        assert_eq!(candidate.meta.name, "streamed.bin");
        assert_eq!(candidate.declared_len, None);
        assert_eq!(candidate.verifier, None);
    }

    /// A directory entry's name ends in `/` and is the one kind a bare
    /// local header can still tell apart from a plain file.
    #[test]
    fn a_trailing_slash_name_is_reported_as_a_directory() {
        let bytes = minimal_local_header(20, 0, "a/dir/", b"");
        let mut scan = ZipSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes), 0)
            .unwrap()
            .expect("a well-formed header must be accepted");
        assert_eq!(candidate.meta.kind, EntryKind::Dir);
    }

    /// A real header immediately followed by a phantom `PK\x03\x04` sitting
    /// INSIDE its own payload must not stop the scan from resuming just
    /// past the phantom's own start — proven by placing a second, genuine
    /// header right after such a payload and confirming both are found, in
    /// order.
    #[test]
    fn a_magic_byte_sequence_inside_a_payload_does_not_stop_the_scan() {
        let mut first = minimal_local_header(20, 0, "first.bin", b"xxPK\x03\x04xx");
        let second = minimal_local_header(20, 0, "second.bin", b"ok");
        let first_len = first.len();
        first.extend_from_slice(&second);

        let mut scan = ZipSalvage::new();
        let mut src = Cursor::new(first);
        let c1 = scan
            .next_candidate(&mut src, 0)
            .unwrap()
            .expect("first entry");
        assert_eq!(c1.offset, 0);
        assert_eq!(c1.meta.name, "first.bin");

        let c2 = scan
            .next_candidate(&mut src, c1.offset + c1.declared_len.unwrap())
            .unwrap()
            .expect("second entry, past the phantom magic inside the first payload");
        assert_eq!(c2.offset, first_len as u64);
        assert_eq!(c2.meta.name, "second.bin");
    }

    /// [`find_next_local_header`] carries at most three bytes across a
    /// chunk boundary. This pins that a signature straddling two reads —
    /// not merely landing inside one — is still found, by placing it one
    /// byte before a chunk boundary in a buffer bigger than [`SCAN_CHUNK`].
    #[test]
    fn a_signature_split_across_a_scan_chunk_boundary_is_still_found() {
        let mut bytes = vec![0u8; SCAN_CHUNK * 2];
        let at = SCAN_CHUNK - 1;
        bytes[at..at + 4].copy_from_slice(&SIG_LOCAL_HEADER);
        let found =
            find_next_local_header(&mut Cursor::new(bytes), 0, (SCAN_CHUNK * 2) as u64).unwrap();
        assert_eq!(found, Some(at as u64));
    }

    // -------------------------------------------------------------------
    // Task 4: verification, shadow detection, and central-directory
    // reconciliation.
    // -------------------------------------------------------------------

    use std::io::Write;

    /// Test-local convenience wrapper matching the task brief's own call
    /// shape (`salvage(&build_shadowing_zip())`). The real, permanent public
    /// entry point is [`salvage_zip`]; this only hides constructing a
    /// `Cursor` and a default policy — ruling R-C's "a test-local wrapper is
    /// fine, but it must not shadow the public name" is satisfied by
    /// spelling it differently from both `salvage_zip` and `salvage_all`.
    fn salvage(bytes: &[u8]) -> SalvageOutcome {
        salvage_zip(&mut Cursor::new(bytes.to_vec()), &SalvagePolicy::default())
            .expect("a healthy or merely-damaged zip must salvage without a hard error")
    }

    /// Task 4's first required test, verbatim from the brief. This is the
    /// one that FAILS against the placeholder engine Task 1 shipped (every
    /// candidate reported `Complete`, never `Intact`, regardless of whether
    /// a real CRC-32 agreed) — see the task report for the failing run.
    #[test]
    fn an_entry_whose_crc_agrees_is_intact() {
        let out = salvage(&crate::zip::build_shadowing_zip());
        assert_eq!(out.entries[0].meta.name, "one.txt");
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Intact,
            "an unmodified entry's real CRC-32 must agree"
        );
    }

    /// Builds a healthy single-entry zip whose one entry is DEFLATE-
    /// compressed (unlike `build_shadowing_zip`'s Stored fixtures, chosen
    /// there so a declared size needs no compression framing reasoned
    /// about) — here the opposite is wanted: a payload a decoder can
    /// genuinely fail to finish decoding. Returns the archive bytes
    /// alongside the entry's own compressed-payload span (as byte offsets
    /// into those bytes), so a caller can corrupt part of it in place
    /// without touching any declared size or offset.
    ///
    /// No extra field and no data descriptor are assumed in locating the
    /// span — true here because the sink is a `Cursor` (`Seek`), the same
    /// assumption `build_shadowing_zip`'s own doc comment states and checks.
    fn build_deflated_single_entry_zip(
        name: &str,
        payload: &[u8],
    ) -> (Vec<u8>, std::ops::Range<usize>) {
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            w.start_file(name, opts).expect("start_file");
            w.write_all(payload).expect("write payload");
            w.finish().expect("finish archive");
        }
        let bytes = cursor.into_inner();

        let records = crate::zip::walk_central_directory(&mut Cursor::new(&bytes))
            .expect("a freshly built archive's own central directory must walk cleanly");
        assert_eq!(records.len(), 1, "sanity: exactly one entry");
        let record = &records[0];

        let payload_start =
            record.local_header_offset as usize + LOCAL_HEADER_TOTAL as usize + name.len();
        let payload_end = payload_start + record.compressed_size as usize;
        (bytes, payload_start..payload_end)
    }

    /// Task 4's second required test, per the brief: "cut its last entry's
    /// payload in half". Done here by corrupting the SECOND half of its
    /// compressed bytes in place, rather than shortening the file: the
    /// candidate is still discovered (its declared length still fits
    /// exactly, so the raw scan's own gate has nothing to reject), and the
    /// corruption is caught at DECODE time instead — "the decoder failed
    /// mid-stream", `SalvageStatus::Partial`'s own second clause, and
    /// exactly what the brief's comment describes.
    #[test]
    fn an_entry_whose_payload_is_truncated_is_partial() {
        let payload = b"the quick brown fox jumps over the lazy dog. ".repeat(20);
        let (mut bytes, span) = build_deflated_single_entry_zip("big.txt", &payload);
        assert!(
            span.len() > 8,
            "the fixture's payload must compress to more than a few bytes, or corrupting \
             half of it corrupts nothing"
        );

        let half = span.start + (span.len() / 2);
        for b in &mut bytes[half..span.end] {
            *b = 0xFF;
        }

        let out = salvage(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "a compressed payload corrupted partway through must not be reported Intact or \
             Complete"
        );
    }

    /// Task 4's third required test, verbatim from the brief. Note it
    /// asserts `Intact`, not a damage status: the two extra physical records
    /// in `build_shadowing_zip` are byte-identical copies of real data —
    /// nothing in the archive is damaged, so a salvage tool that reported
    /// them as suspect would be wrong about the very shape that motivated
    /// this feature.
    #[test]
    fn a_duplicate_record_is_marked_as_shadowing_its_original() {
        let out = salvage(&crate::zip::build_shadowing_zip());
        assert_eq!(out.entries[6].shadows, Some(2));
        assert_eq!(out.entries[6].status, SalvageStatus::Intact);
    }

    /// Falsification guard for the mistake ruling out `shadows`-from-name:
    /// two DIFFERENT files (different content, different CRC-32) that
    /// happen to share a NAME must never be linked as shadow/original. Only
    /// a checksum match may set `shadows` — see this module's and
    /// `salvage.rs`'s own doc comments.
    ///
    /// The `zip` crate's own writer refuses two `start_file` calls under the
    /// identical name (`InvalidArchive("Duplicate filename: ...")`), so this
    /// writes two EQUAL-LENGTH but distinct names and patches the second
    /// entry's name bytes (its local header's AND its central-directory
    /// record's — the same two-copy shape `build_shadowing_zip` documents)
    /// down to the first entry's name afterward. Equal length keeps every
    /// offset in the archive unchanged.
    #[test]
    fn two_different_files_sharing_a_name_are_never_marked_as_shadowing_each_other() {
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            w.start_file("dupA.txt", opts).expect("start_file 1");
            w.write_all(b"first version").expect("write 1");
            w.start_file("dupB.txt", opts).expect("start_file 2");
            w.write_all(b"second, DIFFERENT version").expect("write 2");
            w.finish().expect("finish");
        }
        let mut bytes = cursor.into_inner();

        let mut patched = 0usize;
        let mut at = 0usize;
        while at + 8 <= bytes.len() {
            if bytes[at..at + 8] == *b"dupB.txt" {
                bytes[at..at + 8].copy_from_slice(b"dupA.txt");
                patched += 1;
                at += 8;
            } else {
                at += 1;
            }
        }
        assert_eq!(
            patched, 2,
            "expected to patch exactly two occurrences: the second entry's local header name \
             and its central-directory record name"
        );

        let out = salvage(&bytes);
        assert_eq!(
            out.entries.len(),
            2,
            "sanity: both physical records must be found"
        );
        assert_eq!(
            out.entries[1].shadows, None,
            "two different files sharing a name must not be linked as shadow/original"
        );
    }

    /// Ruling R-H's reconciliation requirement: a legitimate CP437-named
    /// entry the raw scan's strict UTF-8 gate rejects is still recovered
    /// through the central directory, which carries no such restriction —
    /// see this module's "Central-directory reconciliation" doc section.
    /// Both the local header's AND the central-directory record's copies of
    /// the two-byte name are patched to the SAME invalid-UTF-8 sequence, so
    /// nothing about the archive's structure (offsets, sizes) moves.
    #[test]
    fn a_non_utf8_name_the_scan_rejects_is_still_recovered_through_the_central_directory() {
        let (mut archive, _) = build_deflated_single_entry_zip("aa", b"hi");

        // Patch every occurrence of the ASCII name `aa` (there are exactly
        // two: the local header's own copy, and the central-directory
        // record's copy) to a lone-continuation-byte pair — invalid UTF-8,
        // same length, so no offset in the archive shifts.
        let invalid = [0x80u8, 0x80u8];
        let mut patched = 0usize;
        let mut at = 0usize;
        while at + 2 <= archive.len() {
            if archive[at..at + 2] == *b"aa" {
                archive[at..at + 2].copy_from_slice(&invalid);
                patched += 1;
                at += 2;
            } else {
                at += 1;
            }
        }
        assert_eq!(
            patched, 2,
            "expected to patch exactly two occurrences: the local header's name and the \
             central-directory record's name"
        );

        // Sanity: without the central-directory fallback, this entry is
        // lost entirely — the raw scan's own gate rejects the header
        // outright (`a_name_that_is_not_valid_utf8_is_rejected` above pins
        // the same gate on a smaller fixture).
        let mut scanner = ZipSalvage::new();
        let scan_only = salvage_all(
            &mut scanner,
            &mut Cursor::new(archive.clone()),
            &SalvagePolicy::default(),
        )
        .expect("the scan alone must not hard-error, only find nothing");
        assert!(
            scan_only.entries.is_empty(),
            "sanity: the raw scan alone must indeed lose this entry"
        );

        // Reconciliation recovers it.
        let out = salvage(&archive);
        assert_eq!(
            out.entries.len(),
            1,
            "the central-directory fallback must recover the entry the scan's UTF-8 gate lost"
        );
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Intact,
            "the recovered entry's own payload is undamaged"
        );
    }

    /// [`ZipSalvage::verify`] on a data-descriptor candidate (no declared
    /// length, no verifier — see the module's own "general-purpose bit 3"
    /// section) must answer `Complete`, never `Intact` (nothing was
    /// checked) and never `Partial` (nothing is known to be missing
    /// either).
    #[test]
    fn a_data_descriptor_candidate_verifies_as_complete() {
        let mut bytes = minimal_local_header(20, 8, "streamed.bin", b"");
        bytes[6..8].copy_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
        let mut scan = ZipSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes.clone()), 0)
            .unwrap()
            .expect("the header itself is well-formed and must still be found");
        let status = scan.verify(&mut Cursor::new(bytes), &candidate).unwrap();
        assert_eq!(status, SalvageStatus::Complete);
    }

    /// Pinned to the algorithm's published check value (CRC RevEng
    /// catalogue: `CRC-32/ISO-HDLC`, ASCII `"123456789"` -> `0xCBF43926`) —
    /// an external constant, so a transcription error in the polynomial
    /// cannot hide behind this module's own expectations. The identical
    /// value `legacy/arj.rs`'s own `crc32_ieee_matches_the_standard_check_value`
    /// pins, for the identical algorithm under a separate implementation
    /// (see this module's doc comment for why it is not shared code).
    #[test]
    fn crc32_ieee_matches_the_standard_check_value() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }
}
