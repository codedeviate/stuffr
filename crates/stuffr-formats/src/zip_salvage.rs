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
//!    `zip.rs`'s central-directory walk uses for the same field. This is
//!    NOT about how much confidence a signature match carries here versus
//!    there — it is that CP437 (the pre-EFS encoding a lossy decode would
//!    accept) maps every one of the 256 byte values to *something*, so a
//!    lossy decode excludes NOTHING and would gut this one check, the whole
//!    line of defence between a real header and four coincidental magic
//!    bytes. Strict UTF-8 is a real filter — most random byte sequences are
//!    not valid UTF-8; lossy CP437 is not a filter at all. The cost is a
//!    genuine CP437-named entry from a pre-EFS writer being rejected HERE —
//!    closed by reconciling against the central directory instead, which
//!    carries no such restriction (see "Central-directory reconciliation"
//!    below), never by weakening this gate.
//! 6. `local_header_offset + declared_len` fits inside the source. Nothing
//!    is ever sized or allocated from `declared_len` to reach this check —
//!    it is pure arithmetic against the source's own length.
//!
//! Any failure at 2-5 is not an error: it means this four-byte match was a
//! coincidence, not a header, so the scan simply resumes searching one byte
//! past it. That is a deliberate departure from `zip.rs`'s central-directory
//! walk, where a signature match past the EOCD is already trusted enough
//! that a LATER field failing to parse there is reported as
//! `Error::Corrupt` — this scan has no such anchor at all, so nothing found
//! here can be corruption; it can only be noise or a real header, and the
//! gate's whole job is telling the two apart.
//!
//! # Criterion 6 reports, it does not reject
//!
//! **Criterion 6 is the one that is not a rejection**, and it used to be.
//! A candidate whose declared payload runs past the end of the source is
//! reported with [`Candidate::available_len`] naming how many of its bytes
//! are actually present, and [`verify_candidate`] answers `Partial` for it
//! without decoding anything.
//!
//! It was a rejection until the final whole-branch review measured what
//! that cost. A truncated archive — an interrupted download, the single
//! most common damaged zip there is — was the one shape salvage reported
//! NOTHING about: swept across six truncation points inside a three-header
//! archive's last entry, every one printed "2 scanned: 2 written" at exit
//! 0. The third header was intact, about half its payload survived, and the
//! tool said nothing was wrong. Refusing to INVENT the missing bytes is
//! correct and is what the "Cross-checked against Info-Zip's `zip -FF`"
//! section below defends at length; implementing that refusal as SILENCE is
//! a different thing, and is what changed.
//!
//! Nothing about the anti-noise argument above is weakened by this. The
//! gate's power against a coincidental four-byte match comes from criteria
//! 2, 3 and 5 (a plausible version, a recognised method, a strictly
//! UTF-8-decodable name — jointly on the order of one in millions per
//! magic hit, against one magic hit per 4 GiB of random data); criterion 6
//! was a structural sanity check, not a filter. `salvage_over_random_bytes_
//! finds_nothing` still finds nothing, with the same five seeded
//! coincidences, and still would if criterion 6 were deleted outright.
//!
//! What criterion 6 still does is bound. A truncated candidate's
//! `available_len` — never its declared length — is what
//! [`stuffr_core::salvage::collect_candidates`] checks against
//! `policy.max_entry`, so a garbage length in a tail that is not there
//! cannot abort a run at exit 6 and take every recovered entry with it.
//! **It is no longer what the scan advances by.** Task 3's fix round found
//! that advancing by `available_len` let one coincidental phantom header —
//! a marker+name match sitting on top of noise, with a garbage declared
//! length far past the file — jump the scan straight to EOF in a single
//! step and silently drop every real entry between it and the end of the
//! file: no error, no `Partial`, no note, in the one verb whose entire job
//! is not losing entries silently. `collect_candidates` now advances a
//! truncated candidate past only its own marker byte, so the very next byte
//! is still examined for another header; an untruncated candidate (whose
//! declared length was just checked against the file, so it is not a lie)
//! still advances by that declared length, unchanged. See
//! `collect_candidates`'s own doc comment for the full reasoning.
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
//! documents for a format with no checksum at all. [`verify_candidate`]
//! reports such a candidate `Unverified(NoDeclaredLength)` — NOT `Complete`,
//! which this module reported here until Ruling R-M: `Complete` asserts
//! every DECLARED byte was present, and a data-descriptor candidate declares
//! none, so there was nothing whose presence had been confirmed. A
//! CD-reconciled data-descriptor entry is a different case entirely — see
//! [`candidate_from_cd_record`], which trusts the central directory's own
//! length and CRC and can honestly reach `Intact` or `Partial`.
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
//! - **Anything else**: `Unverified(UndecodableMethod)`. This build's zip
//!   codec registers more methods than this verifier decodes (method 99,
//!   AES, is the sharpest instance — an entry salvage cannot decrypt); a
//!   candidate using one is still correctly discovered and bounded, but its
//!   CRC-32 is simply not checked. `Unverified`, never `Complete`: the
//!   format DOES carry a checksum here, this build only failed to check it,
//!   and `Complete` is reserved for a format with no checksum to offer at
//!   all (see `SalvageStatus`'s own doc comment for why the two must not
//!   share a word). The SAME status, with the OTHER cause
//!   (`NoDeclaredLength`), covers an unreconciled data-descriptor candidate
//!   — see the "General-purpose bit 3" section above.
//!
//! Both decode branches are STREAMED, never buffered: `verify_candidate`
//! reads through a fixed-size window, updating a running CRC-32 and a
//! decoded-byte count, and materialises neither a compressed nor a
//! decompressed copy of the payload. This closes a real allocation defect a
//! fix-round review measured: buffering `DeflateDecoder::read_to_end`
//! reached a 64 MiB decode from a 65 KB archive with `--max-entry` set to
//! 1 MiB — `max_entry` bounds the DECLARED COMPRESSED length only
//! ([`stuffr_core::salvage::collect_candidates`]'s job), and deflate's
//! ~1032:1 worst-case ratio means the 4 GiB default admits a multi-terabyte
//! decode buffer, in the one verb this project builds specifically to run
//! on hostile input. The Deflate branch additionally stops the moment
//! decoded bytes exceed the local header's OWN declared `uncompressed_size`
//! — a second, independent bound (on output, not input) that a buffered
//! `read_to_end` had no way to apply, since nothing consulted that field at
//! all before this fix.
//!
//! Fewer than the declared number of bytes actually present (a short read at
//! any point) is `Partial` immediately, before verification concludes — the
//! "payload ran out" half of [`SalvageStatus::Partial`]'s definition. A full
//! decode that disagrees with the declared CRC-32 is ALSO `Partial`, not a
//! fourth status: [`stuffr_core::salvage`]'s tiers are deliberately
//! exhaustive, and a checksum that was checked and failed is exactly as
//! unproven as a decode that failed outright — neither `Intact` (the
//! checksum did not agree) nor `Complete` (something WAS checked, and it did
//! not hold) nor `Unverified` (something WAS attempted, unlike an
//! undecodable method).
//!
//! # Central-directory reconciliation (ruling R-H)
//!
//! The raw scan's strict UTF-8 name gate (criterion 5 above) rejects a
//! legitimate CP437-named entry from a pre-EFS writer — deliberately: see
//! that criterion for why the gate stays strict rather than accepting a
//! lossy decode. That gate has nowhere to fall back to on its own, so
//! [`salvage_zip`] is the actual safety net ruling R-H requires: it runs the
//! raw scan, then walks the central directory
//! ([`crate::zip::walk_central_directory`]) when one is intact, and for
//! every central-directory record whose `local_header_offset` the scan did
//! NOT already find — a name the scan's UTF-8 gate rejected, or a length the
//! scan's own "fits inside the file" check refused — recovers it
//! independently via [`candidate_from_cd_record`], which trusts the
//! CENTRAL-DIRECTORY's declared name/size/CRC (already lossily decoded and
//! already past `zip.rs`'s own record-level checks) rather than re-deriving
//! them from the raw header.
//!
//! Reconciling the two sources means a name only the scan can see (behind a
//! destroyed central directory) and a name only the central directory can
//! see (behind the scan's UTF-8 gate) both survive. Only an archive with
//! BOTH a destroyed central directory AND a non-UTF-8 name loses that entry
//! — proven by
//! `a_non_utf8_name_the_scan_rejects_is_still_recovered_through_the_central_directory`
//! below, whose falsification (skip the central-directory fallback) is
//! recorded in the task report.
//!
//! # Cross-checked against Info-Zip's `zip -FF` (Task 7)
//!
//! `crates/stuffr-cli/tests/cli.rs`'s damage catalogue (Task 7, Step 2) builds
//! one real, undamaged three-entry archive with the SYSTEM `zip` binary (never
//! this project's own writer), damages it in the shapes this module's
//! [`SalvageStatus`] tiers exist to describe, and — for the external-witness
//! test (Step 3) — compares against Info-ZIP's own `zip -FF` ("salvage what
//! can") run against the identical bytes.
//!
//! **Agreement, verified.** With the archive's central directory zeroed out
//! entirely (this module falls back to the raw scan alone, exactly as
//! "Central-directory reconciliation" above describes when there is no index
//! to reconcile against), `zip -FF` also recovers all three entries by
//! scanning local headers directly, and a follow-up `unzip -t` on its output
//! confirms every one decodes and checks out — the same `Intact` verdict this
//! module reaches, in the same pass, with no second tool needed to confirm it.
//!
//! **Disagreement found, and recorded here rather than tuned away.**
//! Truncating the archive partway through its LAST entry's payload (so the
//! central directory is lost along with the missing tail) is where the two
//! tools diverge, and manual reproduction — not automated in the test suite,
//! because it depends on `zip -FF`'s own internal buffer handling rather than
//! on anything this project controls — points at Info-Zip's tool, not this
//! one, being the one that is wrong:
//!
//! - This module (via [`salvage_zip`]'s raw scan) never invents the missing
//!   bytes. It reports the truncated entry as `Partial`, recovers the
//!   genuine prefix that survived as `NAME.partial`, and exits 4. **When
//!   this section was written it reported the entry as ABSENT instead**,
//!   and said nothing at all at exit 0 — see "Criterion 6 reports, it does
//!   not reject" above for the measurement that changed that. The
//!   comparison against `zip -FF` below is unaffected: what is being
//!   contrasted is fabricating content versus not fabricating it, and
//!   neither version of this module ever fabricated any.
//! - `zip -FF`, run against the IDENTICAL bytes (a Stored, `-X` archive whose
//!   third entry's 48-byte payload was cut to 24 bytes, dropping the central
//!   directory with it), printed `copying: gamma.bin (48 bytes)` — the
//!   entry's full DECLARED size, not the 24 genuine bytes available — with no
//!   warning at all. The archive it produced decodes that entry's first 24
//!   bytes correctly, followed by 24 bytes that are neither zero nor
//!   repeated: byte-for-byte, they are `50 4b 01 02 ...` — the
//!   central-directory-record signature and fields from elsewhere in the
//!   SAME original archive, bytes that do not exist anywhere in the
//!   truncated input `zip -FF` was actually given. Only a SEPARATE `unzip -t`
//!   pass on its output caught the result: a bad-CRC line naming the
//!   fabricated content.
//!
//! **The fabricated bytes are deterministic in KIND, not in VALUE — this was
//! independently re-verified and is worth a reader knowing before rerunning
//! the repro above.** Every run agrees the injected 24 bytes begin
//! `50 4b 01 02` and are a real central-directory record copied verbatim
//! from elsewhere in the SAME archive (one independent rerun confirmed the
//! injected bytes are `alpha.txt`'s own central-directory record, CRC
//! `20 c1 53 56` matching exactly) — but the exact bad-CRC VALUE `unzip -t`
//! reports for `gamma.bin` was measured differently across runs (`0f6603ba`
//! in one run, `506fb50e` in another, both against the identical repro
//! recipe). That is consistent with this section's own caveat that the
//! fabrication comes from `zip -FF`'s own internal buffer state (a stale or
//! reused read-ahead buffer, not a fixed offset into the file), so it is
//! expected to vary run to run and is not itself the load-bearing part of
//! this finding. What is load-bearing, and reproduced identically every
//! time: `zip -FF` reports success and a warning-free "fixed" archive for an
//! entry whose payload it could not actually deliver.
//!
//! So on a truncated tail, `zip -FF` is not merely less informative than this
//! module (it reports "fixed" or not, with no per-entry status tier at all)
//! — it fabricates plausible-looking bytes for content that no longer
//! exists and reports success while doing it. This module's own refusal to
//! invent a declared-but-absent payload was not changed to chase agreement
//! with that result.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use stuffr_core::salvage::{
    Candidate, SalvageOutcome, SalvagePolicy, SalvageScan, SalvageStatus, SalvagedEntry,
    UnverifiedCause, Verifier, annotate_candidates, collect_candidates, stream_bounded_copy,
};
use stuffr_core::{EntryKind, EntryMeta, Error, FormatId, Result, SeekRead};

use crate::salvage_verify::stream_verify;

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

    // The payload's START is computed unconditionally — even for a
    // data-descriptor entry with no `declared_len` at all — because a
    // consumer (`entries.rs`'s salvage write path) needs to know where a
    // recovered entry's bytes begin regardless of whether this scan could
    // also bound how many of them there are. It is already unfalsifiable at
    // this point: the name `read_exact` and the `extra_len` skip above both
    // fail on a short read, so reaching this line means the cursor sits at
    // `payload_start` with `payload_start <= file_len`.
    let Some(payload_start) = offset
        .checked_add(LOCAL_HEADER_TOTAL)
        .and_then(|v| v.checked_add(u64::from(name_len)))
        .and_then(|v| v.checked_add(u64::from(extra_len)))
    else {
        // The header's own arithmetic overflowed u64 — nothing about this
        // is a real record, so it stays a rejection.
        return Ok(None);
    };

    // Criterion 6: does the declared payload fit inside the source? A
    // candidate that does NOT fit is no longer rejected — it is reported
    // with `available_len` naming how many of its bytes are actually there.
    // See the module doc's "Criterion 6" section for the measurement that
    // changed this, and `Candidate::available_len`'s own doc for why the
    // declared figure is left untouched rather than reduced to what fits.
    let available_len = match declared_len {
        None => None,
        Some(len) => match payload_start.checked_add(len) {
            Some(end) if end <= file_len => None,
            // Either the declared end overflows, or it runs past the
            // source. Both mean the same thing to a reader: fewer bytes are
            // present than the header promises.
            _ => Some(file_len.saturating_sub(payload_start)),
        },
    };

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
    meta.codec = codec_for_method(method);

    Ok(Some(Candidate {
        offset,
        payload_start,
        meta,
        declared_len,
        verifier,
        available_len,
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

/// Maps a zip local-header compression method to the [`FormatId`] this
/// project's codec registry uses for it — mirroring `zip.rs`'s own private
/// `codec_for`/`STORE` (both genuinely unreachable from here: neither is
/// `pub` or `pub(crate)`), not inventing a second convention for the same
/// two strings. Filled at both discovery sites ([`read_candidate_at`] and
/// [`candidate_from_cd_record`]) so `entries.rs`'s ops layer can consume
/// [`EntryMeta::codec`] directly instead of re-parsing this same local-header
/// layout a third time (fix round 1, REQUIRED 4).
///
/// Deliberately narrow: this module only ever DECODES method 0 (Stored) and
/// method 8 (Deflate) — see [`verify_candidate`]'s own dispatch — so those
/// are the only two methods mapped to a real `FormatId`. Every other
/// recognised-but-undecodable method maps to `None` rather than a guessed
/// identifier: nothing here ever decodes them, and a speculative `FormatId`
/// no caller consumes is exactly the risk this fix round's own review named.
fn codec_for_method(method: u16) -> Option<FormatId> {
    match method {
        0 => Some(FormatId::new("store")),
        8 => Some(FormatId::new("deflate")),
        _ => None,
    }
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
/// candidate — then STREAMING its declared payload through the matching
/// decoder and comparing a running CRC-32 against [`Candidate::verifier`].
///
/// Never returns `Err` for malformed, truncated OR genuinely I/O-failing
/// input: every failure here — a bad checksum, a short read, a real device
/// error partway through a payload — is folded into [`SalvageStatus::Partial`]
/// alike. That is a deliberate choice, not an oversight: salvage exists to
/// recover as much of a large, possibly damaged archive as it can, and a
/// verb that aborted the ENTIRE run over one bad sector on one entry would
/// be worse than marking that one entry `Partial` and continuing. A
/// bubbled-up `Err` here would do exactly that, upstream in
/// `stuffr_core::salvage::annotate_candidates`'s `?`.
fn verify_candidate(src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
    let Some(declared_len) = candidate.declared_len else {
        // A data-descriptor entry: no declared length, no verifier (see the
        // module doc's "general-purpose bit 3" section). `Complete` used to
        // be reported here — wrong, per Ruling R-M: `Complete` asserts every
        // DECLARED byte was present, and nothing was declared, so there is
        // nothing whose presence could have been confirmed. "Nothing to
        // disprove" was being read as "proven". `Unverified` is honest
        // instead: nothing about this entry's content was verified, for the
        // same reason (no length to bound a read against) an undecodable
        // method is unverified, just a different cause of it.
        return Ok(SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength));
    };

    // The payload is PROVABLY incomplete — the source ends before the
    // header's declared length does — so nothing needs decoding to know the
    // answer. `Partial` is exactly "the payload ran out", its own first
    // clause, and it is decided here rather than left to fall out of a
    // short read below so the verdict does not depend on a decoder's
    // behaviour at end-of-input.
    //
    // This arm sits ABOVE the method dispatch on purpose: a truncated
    // payload under a method this build cannot decode is still truncated,
    // and `Partial` (proven missing) is a stronger and more useful claim
    // than `Unverified` (nothing was attempted). The bytes that ARE present
    // are still a genuine prefix, and `entries.rs`'s write path recovers
    // them as `NAME.partial` — never inventing the rest, which is what
    // `zip -FF` does and what this module's own doc refuses at length.
    if candidate.available_len.is_some() {
        return Ok(SalvageStatus::Partial);
    }

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
    let uncompressed_size = u64::from(u32::from_le_bytes([
        fixed[22], fixed[23], fixed[24], fixed[25],
    ]));
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

    // Bounds the COMPRESSED side: neither decode branch below can read past
    // `declared_len` bytes of input, however the OUTPUT side is bounded
    // (Stored has none to speak of; Deflate is bounded separately, below,
    // by the header's own `uncompressed_size`).
    let bounded = src.take(declared_len);

    Ok(match method {
        // Stored: the payload IS the uncompressed bytes — stream it
        // straight through the hash, no decoder involved.
        0 => stream_verify(bounded, declared_len, &Verifier::Crc32(expected)),
        // Deflate: `flate2::read::DeflateDecoder`, the same backend
        // `deflate.rs` already depends on for this exact format — see the
        // module doc's "Verification" section for why streaming this way is
        // not a new decompression stack, and for the allocation defect a
        // buffered version of this had.
        8 => stream_verify(
            flate2::read::DeflateDecoder::new(bounded),
            uncompressed_size,
            &Verifier::Crc32(expected),
        ),
        // A method this verifier does not decode — see the module doc. The
        // declared bytes are confirmed present above; the format DOES carry
        // a checksum here, this build simply did not check it, which is
        // exactly what `Unverified` (as opposed to `Complete`) says.
        _ => SalvageStatus::Unverified(UnverifiedCause::UndecodableMethod),
    })
}

/// A fresh handle onto `archive_path`, seeked to `start` and bounded to at
/// most `len` bytes — a new [`File`] per call rather than sharing one
/// across entries, the same trade `entries.rs`'s salvage write path always
/// made: a little overhead for never threading a mutable handle (and its
/// current seek position) through the call graph.
fn open_bounded_payload(archive_path: &Path, start: u64, len: u64) -> Result<impl Read> {
    let mut f = File::open(archive_path)?;
    f.seek(SeekFrom::Start(start))?;
    Ok(f.take(len))
}

/// Reads one entry's payload and writes its RECOVERED (decoded) bytes to
/// `out`. Returns whether the decode reached the entry's own declared
/// length ([`EntryMeta::size`]) — `entries.rs`'s own signal for
/// `PartialCause`.
///
/// Uses [`SalvagedEntry::payload_start`] directly — computed once by
/// [`read_candidate_at`]/[`candidate_from_cd_record`] at discovery time —
/// rather than re-parsing a local header here. Before Task 3c this
/// function (then living in `entries.rs`) re-read a 30-byte zip local
/// header from `entry.offset` on every call, which was silently WRONG for
/// any other format's candidate: an ARC entry near end-of-file made that
/// read run past EOF and raise `Error::Io` (exit 1) rather than anything
/// classified. Locating the payload is now this scanner's own job, decided
/// once, and never repeated (or mis-repeated) by a generic caller.
///
/// Dispatches on `entry.meta.codec` — filled by both discovery sites above.
/// `store` and `deflate` are the only two `Some` values it is ever filled
/// with: every other method already reports
/// [`stuffr_core::salvage::SalvageStatus::Unverified`] from this module's
/// own `verify_candidate`, which callers already refuse before reaching
/// here. The `_` arm below (`None`, or any other value) is therefore
/// defensive rather than reachable in practice.
///
/// # A real behaviour change (fix round 1, MEDIUM-3): Deflate decodes via
/// `flate2` directly, not the codec registry
///
/// Before Task 3c, this function's Deflate arm lived in `entries.rs` and
/// went through `crate::registry().require_decoder("deflate")` — the
/// facade crate's own registry, which requires the standalone `deflate`
/// feature to have registered a decoder at all. Moving `write_payload`
/// into this module (which already depends on `flate2` directly for the
/// identical decode `verify_candidate` above performs, to check a
/// candidate's CRC-32) means this arm now calls
/// `flate2::read::DeflateDecoder::new` directly instead. `stuffr`'s `zip`
/// feature does not imply `deflate` (`crates/stuffr/Cargo.toml`), so a
/// `--no-default-features --features zip` build used to report a Deflate
/// zip entry `SkippedNotBuiltIn` (`Error::FormatNotEnabled`) and now
/// decodes and writes it — an improvement, since `verify_candidate`
/// already decoded such an entry via `flate2` and already called it
/// `Intact`, so the scan and the write used to disagree about whether this
/// build could really decode the entry. Recorded here, and in
/// `entries.rs`'s own `salvage` doc, because a silent behaviour change on
/// a published crate's feature matrix is exactly the kind of thing
/// `CLAUDE.md`'s Publishing section warns costs more than it looks like.
pub fn write_payload(
    archive_path: &Path,
    entry: &SalvagedEntry,
    compressed_len: u64,
    out: &mut dyn Write,
) -> Result<bool> {
    let expected = entry.meta.size.unwrap_or(compressed_len);

    match entry.meta.codec {
        Some(id) if id == FormatId::new("store") => {
            let reader = open_bounded_payload(archive_path, entry.payload_start, compressed_len)?;
            stream_bounded_copy(reader, expected, out)
        }
        Some(id) if id == FormatId::new("deflate") => {
            let reader = open_bounded_payload(archive_path, entry.payload_start, compressed_len)?;
            // The same `flate2::read::DeflateDecoder` backend
            // `verify_candidate` above already uses to check this exact
            // entry's CRC-32 — not a second decompression stack.
            let decoded = flate2::read::DeflateDecoder::new(reader);
            stream_bounded_copy(decoded, expected, out)
        }
        other => Err(Error::Unsupported(format!(
            "entry `{}` carries codec {other:?}, which this build's salvage writer does \
             not decode (only Stored and Deflate; every other method already reports as \
             Unverified before reaching here)",
            entry.meta.name
        ))),
    }
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
    let mut candidates = collect_candidates(&mut scanner, src)?;

    if let Some(cd_records) = crate::zip::walk_central_directory(&mut SeekReadRef(&mut *src)) {
        let mut found_offsets: std::collections::HashSet<u64> =
            candidates.iter().map(|c| c.offset).collect();

        for record in &cd_records {
            if found_offsets.contains(&record.local_header_offset) {
                // Already recovered — either by the scan (whose own
                // candidate is authoritative: it read the name straight off
                // the local header, rather than through the central
                // directory's lossy decode) or by an EARLIER central-
                // directory record in this same loop that already claimed
                // this offset. Without tracking the latter, two CD records
                // sharing a `local_header_offset` would each independently
                // pass this check and manufacture a second, phantom
                // candidate at a real header's offset — measured during
                // this task's fix round.
                continue;
            }
            if let Some(candidate) = candidate_from_cd_record(src, record)? {
                found_offsets.insert(candidate.offset);
                candidates.push(candidate);
            }
        }

        // Reconciliation can add entries out of physical order (the central
        // directory itself is walked in ITS OWN order, not file order), so
        // `scan_position` must be renumbered from a single, consistent file
        // order across BOTH sources — not merely the scan's.
        candidates.sort_by_key(|c| c.offset);
    }

    annotate_candidates(&scanner, src, candidates, policy)
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
///
/// # This used to carry a second copy of the entry ceiling
///
/// It compared `record.compressed_size` against `policy.max_entry` and
/// raised [`stuffr_core::Error::ResourceLimit`] — which ENDED THE RUN, so
/// whether one absurd central-directory record cost a caller the whole
/// archive depended on which of the two sources found that record first
/// (the raw scan's own copy of the same check, in
/// `stuffr_core::salvage::collect_candidates`, had the identical effect).
/// Salvage Stage 2 Task 3c's fix round 3 made the ceiling one rule applied
/// once, in `annotate_candidates`, to the merged candidate list — which is
/// strictly after this function and covers what it produces, so the check
/// here was not merely redundant, it was the half that disagreed. Nothing
/// here sizes a buffer from the declared length (the record's own payload
/// is never read by this function), so removing it moves no allocation.
fn candidate_from_cd_record(
    src: &mut dyn SeekRead,
    record: &crate::zip::CdRecord,
) -> Result<Option<Candidate>> {
    let Ok(file_len) = src.seek(SeekFrom::End(0)) else {
        return Ok(None);
    };
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
    // The central directory's declared length can run past the end of the
    // file too — a truncated archive whose index nonetheless survived
    // (a zip written with its central directory first, or one truncated
    // between the payload and an appended index). Same treatment as the raw
    // scan's own criterion 6: report the shortfall, never fold it into the
    // declared figure. `name_len`/`extra_len` come from the LOCAL header,
    // which is where the payload actually begins — a central-directory
    // record's own extra field is a different field of a different length.
    let name_len = u64::from(u16::from_le_bytes([fixed[26], fixed[27]]));
    let extra_len = u64::from(u16::from_le_bytes([fixed[28], fixed[29]]));
    let payload_start = match record
        .local_header_offset
        .checked_add(LOCAL_HEADER_TOTAL)
        .and_then(|v| v.checked_add(name_len))
        .and_then(|v| v.checked_add(extra_len))
    {
        None => return Ok(None),
        Some(start) if start > file_len => return Ok(None),
        Some(start) => start,
    };
    let available_len = match payload_start.checked_add(record.compressed_size) {
        Some(end) if end <= file_len => None,
        _ => Some(file_len.saturating_sub(payload_start)),
    };

    let kind = if record.name.ends_with('/') {
        EntryKind::Dir
    } else {
        EntryKind::File
    };
    let mut meta = EntryMeta::file(record.name.clone());
    meta.size = Some(record.uncompressed_size);
    meta.compressed_size = Some(record.compressed_size);
    meta.kind = kind;
    // The CENTRAL DIRECTORY'S own method field, already parsed by
    // `zip.rs`'s record walk — no need to re-read the local header's copy
    // of it, which this function only touches at all to confirm the magic.
    meta.codec = codec_for_method(record.method);

    Ok(Some(Candidate {
        offset: record.local_header_offset,
        payload_start,
        meta,
        declared_len: Some(record.compressed_size),
        verifier: Some(Verifier::Crc32(record.crc32)),
        available_len,
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

    /// Criterion 6 REPORTS rather than rejects — see this module's
    /// "Criterion 6 reports, it does not reject" section. This test
    /// asserted `is_none()` until the final whole-branch review: a header
    /// promising payload the file cannot deliver was dropped, so a
    /// truncated archive's last entry vanished with no row and exit 0.
    /// The declared figure is left exactly as the header stated it and the
    /// shortfall is reported separately, so both numbers stay visible.
    #[test]
    fn a_declared_length_running_past_the_file_is_reported_not_dropped() {
        let mut bytes = minimal_local_header(20, 0, "hello.txt", b"hi");
        // Declare a compressed size far larger than what actually follows,
        // without changing the bytes present — the header now promises
        // payload the file cannot deliver.
        let absurd = 1_000_000u32.to_le_bytes();
        bytes[18..22].copy_from_slice(&absurd);
        let mut scan = ZipSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes), 0)
            .unwrap()
            .expect("a header found but not completable is still a header");
        assert_eq!(
            candidate.declared_len,
            Some(1_000_000),
            "the declared figure is reported as the header stated it, never reduced to \
             what fits — a truncated entry must not become indistinguishable from a whole \
             one of the smaller size"
        );
        assert_eq!(
            candidate.available_len,
            Some(2),
            "and the two bytes that ARE there are named separately"
        );
    }

    /// The complement: an untruncated header reports no shortfall at all.
    /// Without this, an `available_len` that was always `Some` would pass
    /// the test above and mark every healthy entry as truncated.
    #[test]
    fn a_declared_length_that_fits_reports_no_shortfall() {
        let bytes = minimal_local_header(20, 0, "hello.txt", b"hi");
        let mut scan = ZipSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes), 0)
            .unwrap()
            .expect("an ordinary header");
        assert_eq!(candidate.declared_len, Some(2));
        assert_eq!(candidate.available_len, None);
    }

    /// A truncated candidate is `Partial`, decided without decoding —
    /// "the payload ran out", `SalvageStatus::Partial`'s own first clause.
    #[test]
    fn a_truncated_candidate_verifies_as_partial() {
        let mut bytes = minimal_local_header(20, 0, "hello.txt", b"hi");
        bytes[18..22].copy_from_slice(&1_000_000u32.to_le_bytes());
        let out = salvage(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].status, SalvageStatus::Partial);
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

    // -------------------------------------------------------------------
    // Task 7, Step 1: salvage of an UNDAMAGED archive must agree exactly
    // with `list` — checked here against `crate::zip::walk_central_directory`,
    // the same central-directory walk `list` itself is built from (this
    // crate has no dependency on the `stuffr` facade crate `list` actually
    // lives in, so the comparison is made against the shared read path
    // rather than the CLI verb by name — the identical reasoning
    // `salvage_finds_every_local_header_in_a_real_archive` above already
    // gives for cross-checking against this same function rather than
    // hand-copied expected values). Any divergence on a healthy file is a
    // scanner bug, caught with no damage constructed at all.
    // -------------------------------------------------------------------

    /// Builds several distinct healthy archives via the `zip` crate — a
    /// single Stored entry, a single Deflated one, and a mixed multi-entry
    /// archive carrying an empty file and a directory — and asserts, for
    /// each, that [`salvage_zip`] finds exactly what the central-directory
    /// walk finds: the same names in the same order, every one `Intact`,
    /// none shadowing another.
    #[test]
    fn salvage_of_a_healthy_archive_agrees_with_list() {
        fn check(bytes: Vec<u8>, fixture: &str) {
            let cd_records = crate::zip::walk_central_directory(&mut Cursor::new(&bytes))
                .unwrap_or_else(|| {
                    panic!("{fixture}: this fixture's own central directory must walk cleanly")
                });
            let out = salvage(&bytes);
            assert_eq!(
                out.entries.len(),
                cd_records.len(),
                "{fixture}: salvage must find exactly what the central-directory walk (what \
                 `list` is built from) finds"
            );
            for (entry, record) in out.entries.iter().zip(cd_records.iter()) {
                assert_eq!(
                    entry.meta.name, record.name,
                    "{fixture}: salvage and the central-directory walk disagree on a name"
                );
                assert_eq!(
                    entry.status,
                    SalvageStatus::Intact,
                    "{fixture}: an undamaged entry (`{}`) must verify Intact, found {:?}",
                    entry.meta.name,
                    entry.status
                );
                assert_eq!(
                    entry.shadows, None,
                    "{fixture}: nothing here is a duplicate of anything else"
                );
            }
        }

        // A single Stored entry.
        {
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut w = zip::ZipWriter::new(&mut cursor);
                w.start_file("solo.txt", opts).unwrap();
                w.write_all(b"a single stored entry, nothing damaged")
                    .unwrap();
                w.finish().unwrap();
            }
            check(cursor.into_inner(), "single Stored entry");
        }

        // A single Deflated entry — the same builder Task 4's own
        // truncation test uses, undamaged this time.
        {
            let payload = b"deflate me please, more than once. ".repeat(30);
            let (bytes, _span) = build_deflated_single_entry_zip("solo.bin", &payload);
            check(bytes, "single Deflated entry");
        }

        // Several entries: mixed methods, an empty file, and a directory.
        {
            let stored = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            let deflated = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            let mut cursor = Cursor::new(Vec::new());
            {
                let mut w = zip::ZipWriter::new(&mut cursor);
                w.start_file("one.txt", stored).unwrap();
                w.write_all(b"first entry, stored").unwrap();
                w.start_file("two.bin", deflated).unwrap();
                w.write_all(b"second entry, deflated, deflated, deflated, deflated")
                    .unwrap();
                w.add_directory("adir/", stored).unwrap();
                w.start_file("empty.txt", stored).unwrap();
                w.finish().unwrap();
            }
            check(cursor.into_inner(), "mixed multi-entry archive");
        }
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

    /// REQUIRED 1/2 (fix round 1): a local header whose OWN
    /// `uncompressed_size` field understates what its compressed payload
    /// would actually decode to (a corrupt or hostile header — untouched
    /// here is `compressed_size`/CRC/payload bytes, only the declared
    /// output size is dropped) must be `Partial`, never `Intact`. This pins
    /// the OUTCOME of `stream_verify`'s output-side bound; the bound's
    /// actual EARLY-STOP behaviour (never decoding past the declared size at
    /// all, rather than decoding everything and comparing counts after) is
    /// a memory-safety property this fast unit test cannot distinguish from
    /// "decoded fully, then noticed the mismatch" — proven instead by direct
    /// reproduction against the fix-round review's own measurement (a 65 KB
    /// archive, highly compressible, driving a 64 MiB / `67_108_864`-byte
    /// decode with the PRE-fix buffered code and `--max-entry` set to
    /// 1 MiB — `max_entry` only ever bounded the DECLARED COMPRESSED
    /// length, never the decoder's output), recorded in the task report
    /// with the exact matching byte count.
    #[test]
    fn a_declared_uncompressed_size_understating_the_real_output_is_partial() {
        // Large and highly compressible, so decoding it in full (which the
        // pre-fix code did) is measurably different from stopping early.
        let payload = vec![b'x'; 200_000];
        let (mut bytes, _span) = build_deflated_single_entry_zip("big.bin", &payload);
        // The local header's `uncompressed_size` field sits at offset 22..26
        // (see `read_candidate_at`'s own field layout) — understate it far
        // below what decoding the payload would really produce.
        bytes[22..26].copy_from_slice(&10u32.to_le_bytes());

        let out = salvage(&bytes);
        assert_eq!(out.entries.len(), 1);
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "decoded output exceeding the header's own declared uncompressed_size must stop \
             and report Partial, never Intact or Complete"
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
        assert_eq!(
            out.entries[6].collides_with, None,
            "a PROVEN copy reports the stronger fact and only that one"
        );
    }

    /// The same eight records with the duplicates' content changed: nothing
    /// is a shadow any more (no checksum agrees), and the two repeated names
    /// are reported as collisions instead — the annotation `stuffr list`'s
    /// own fidelity warning corresponds to.
    ///
    /// The whole-branch review measured the gap this closes on exactly this
    /// archive: `list` warned that two records repeat a name and are
    /// shadowed, while `salvage --list` marked none of the eight rows at
    /// all. `build_distinct_duplicate_zip` is length-preserving against
    /// `build_shadowing_zip`, so the only difference between this test and
    /// the one above is the duplicates' bytes.
    #[test]
    fn a_duplicate_name_over_different_content_is_marked_as_a_collision() {
        let out = salvage(&crate::zip::build_distinct_duplicate_zip());
        assert_eq!(out.entries.len(), 8);
        assert!(
            out.entries.iter().all(|e| e.shadows.is_none()),
            "no checksum agrees, so nothing here is a proven copy"
        );
        assert_eq!(out.entries[6].collides_with, Some(2));
        assert_eq!(out.entries[7].collides_with, Some(3));
        assert!(
            out.entries[..6].iter().all(|e| e.collides_with.is_none()),
            "the six originals each use their name first"
        );
        assert!(
            out.entries
                .iter()
                .all(|e| e.status == SalvageStatus::Intact),
            "every record still verifies against its own CRC-32: both copies under each \
             repeated name are genuinely recoverable, which is what makes losing one a loss"
        );
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

    /// F7 (fix round 1): two central-directory records sharing a single
    /// `local_header_offset` must not manufacture a second, phantom
    /// candidate at a real header's offset. Both entries here are given
    /// non-UTF-8 names (the same CP437 patching technique as the test
    /// above) so BOTH are only reachable through the central-directory
    /// fallback, forcing them through the exact loop the bug lived in
    /// (`found_offsets` computed once before the loop, never updated as CD-
    /// derived candidates were pushed). After building, the SECOND record's
    /// `local_header_offset` field is overwritten to equal the first's —
    /// simulating a central directory that lies about entry count, or is
    /// simply corrupt in that one field.
    #[test]
    fn two_central_directory_records_sharing_a_local_header_offset_do_not_invent_a_phantom_entry() {
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            w.start_file("aa", opts).expect("start_file aa");
            w.write_all(b"first").expect("write aa");
            w.start_file("bb", opts).expect("start_file bb");
            w.write_all(b"second").expect("write bb");
            w.finish().expect("finish");
        }
        let mut bytes = cursor.into_inner();

        // Patch every occurrence of `aa`/`bb` (local header + CD record,
        // two each) to invalid UTF-8, same length — both entries now miss
        // the raw scan entirely and can only be recovered through the
        // central directory.
        let mut at = 0usize;
        while at + 2 <= bytes.len() {
            if bytes[at..at + 2] == *b"aa" {
                bytes[at..at + 2].copy_from_slice(&[0x80, 0x80]);
                at += 2;
            } else if bytes[at..at + 2] == *b"bb" {
                bytes[at..at + 2].copy_from_slice(&[0x81, 0x81]);
                at += 2;
            } else {
                at += 1;
            }
        }

        let records = crate::zip::walk_central_directory(&mut Cursor::new(&bytes))
            .expect("central directory must still walk (lossy name decode has no restriction)");
        assert_eq!(records.len(), 2, "sanity: both records present");
        let first_local_header_offset = records[0].local_header_offset;
        let second_record_cd_offset = records[1].offset as usize;
        // `local_header_offset` sits 42 bytes into a central-directory
        // record's content (4-byte signature + `zip.rs`'s own
        // `CENTRAL_HEADER_FIXED` layout, `le32(&fixed[38..])`) — same
        // constant `crate::zip`'s own `cd_record_span` test helper uses.
        bytes[second_record_cd_offset + 42..second_record_cd_offset + 46]
            .copy_from_slice(&(first_local_header_offset as u32).to_le_bytes());

        let out = salvage(&bytes);
        assert_eq!(
            out.entries.len(),
            1,
            "two CD records sharing one local_header_offset must recover ONE entry, not \
             manufacture a phantom second one at the same offset"
        );
    }

    /// [`ZipSalvage::verify`] on an UNRECONCILED data-descriptor candidate
    /// (no declared length, no verifier — see the module's own
    /// "general-purpose bit 3" section) must answer
    /// `Unverified(NoDeclaredLength)` (Ruling R-M, fix round 1) — never
    /// `Complete`, which asserts every DECLARED byte was present, and
    /// nothing was declared here for anything to have confirmed; never
    /// `Intact` (nothing was checked); never `Partial` (nothing is known to
    /// be missing either, since nothing was ever bounded in the first
    /// place).
    ///
    /// This test used to assert `Complete` — the exact false claim R-M's
    /// fix-round finding named: "nothing to disprove" was being read as
    /// "proven", the third instance of that shape in this enum. See the
    /// task report for this fixed round's falsification (reverting this one
    /// line and confirming this test names the regression).
    #[test]
    fn an_unreconciled_data_descriptor_candidate_verifies_as_unverified() {
        let mut bytes = minimal_local_header(20, 8, "streamed.bin", b"");
        bytes[6..8].copy_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
        let mut scan = ZipSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes.clone()), 0)
            .unwrap()
            .expect("the header itself is well-formed and must still be found");
        let status = scan.verify(&mut Cursor::new(bytes), &candidate).unwrap();
        assert_eq!(
            status,
            SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength)
        );
    }

    /// REQUIRED 3 (fix round 1): the CRC check that decides `Intact` was
    /// unpinned — `an_entry_whose_crc_agrees_is_intact` stayed green with
    /// the comparison replaced by `true`, and separately with the deflate
    /// decode-error branch neutered, because both of those defects are
    /// masked by a Deflate entry's OWN decode succeeding or failing for
    /// unrelated reasons. A **Stored** entry has no decoder to fail at all —
    /// only the CRC-32 comparison can catch a corrupted payload — so one
    /// flipped payload byte here, with the declared CRC and every size left
    /// untouched, pins the comparison itself. This is also exactly the
    /// spec's own named evidence-catalogue mutation, "a corrupted CRC".
    #[test]
    fn an_entry_whose_payload_byte_is_flipped_is_partial() {
        let bytes = crate::zip::build_shadowing_zip();
        let mut corrupted = bytes.clone();
        // `one.txt`'s local header starts at offset 0 (see
        // `a_candidate_carries_its_offset_name_and_crc32_verifier` above);
        // its payload begins right after the 30-byte fixed header and its
        // 7-byte name (`b"one.txt"`), with no extra field (Stored, built via
        // a `Cursor`, per `build_shadowing_zip`'s own doc comment).
        let payload_start = LOCAL_HEADER_TOTAL as usize + "one.txt".len();
        corrupted[payload_start] ^= 0xFF;

        let out = salvage(&corrupted);
        assert_eq!(out.entries[0].meta.name, "one.txt");
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Partial,
            "a Stored entry's only proof is its CRC-32; a flipped payload byte must not pass"
        );
    }

    // Falsification of REQUIRED 3, exactly as directed: replace the CRC
    // comparison with `true` and confirm the new test above (which the
    // unmodified suite passes) now fails, where the pre-fix suite stayed
    // green at 20 passed under the identical edit. Not run automatically —
    // recorded in the task report with the quoted failing output; this
    // comment is the pointer to where in the file that edit lands, now
    // `salvage_verify.rs`'s `stream_verify` (`Verifier::Crc32(expected) =>
    // !crc32_state == expected`), moved there by Salvage Stage 2 Task 1.

    /// A recognised-but-undecodable method (14 here — LZMA, which
    /// `is_known_method` accepts but this build's zip decoder path does not)
    /// must verify `Unverified`, never `Complete`: the format DOES carry a
    /// checksum for this entry, this build simply did not check it. Method
    /// 99 (AES) is the sharpest real instance the fix-round review named —
    /// this pins the general mechanism on a method that needs no encrypted
    /// fixture to construct.
    #[test]
    fn an_undecodable_but_recognised_method_verifies_as_unverified() {
        let bytes = minimal_local_header(20, 14, "encrypted.bin", b"whatever this is");
        let mut scan = ZipSalvage::new();
        let candidate = scan
            .next_candidate(&mut Cursor::new(bytes.clone()), 0)
            .unwrap()
            .expect("a well-formed header with a recognised method must be found");
        let status = scan
            .verify(&mut Cursor::new(bytes), &candidate)
            .expect("verify never hard-errors");
        assert_eq!(
            status,
            SalvageStatus::Unverified(UnverifiedCause::UndecodableMethod)
        );
    }

    /// REQUIRED 6 (fix round 1), end-to-end: an archive shaped like an
    /// ordinary Python package — two DIFFERENT empty files under different
    /// names, plus a directory entry — must report no shadow links at all.
    /// Every one of the three carries `Crc32(0)` (the fixed checksum of zero
    /// bytes), which a checksum-only match previously collapsed onto a
    /// single shadow chain — measured by the fix-round review against a
    /// real archive shaped exactly like this one.
    #[test]
    fn empty_files_and_directories_are_never_marked_as_shadowing_each_other() {
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            w.start_file("pkg/__init__.py", opts).expect("start_file 1");
            w.start_file("sub/__init__.py", opts).expect("start_file 2");
            w.add_directory("adir/", opts).expect("add_directory");
            w.finish().expect("finish");
        }
        let bytes = cursor.into_inner();

        let out = salvage(&bytes);
        assert_eq!(out.entries.len(), 3, "sanity: all three entries recovered");
        for entry in &out.entries {
            assert_eq!(
                entry.shadows, None,
                "entry `{}` must not be marked as shadowing anything: every empty/directory \
                 entry shares the same zero-byte CRC-32 by construction, not by collision",
                entry.meta.name
            );
        }
    }

    /// The sharper form of the same requirement: two empty files sharing
    /// the SAME name, same declared_len (0) and same verifier (`Crc32(0)`)
    /// — where the `(name, declared_len, verifier)` conjunction alone
    /// WOULD match, unlike the different-named entries above. Only the
    /// explicit zero-length rejection stops these from shadowing each
    /// other; this is what actually falsifies if that rejection is removed
    /// (see the task report). The `zip` crate's writer refuses two
    /// `start_file` calls under an identical name, so this writes two
    /// equal-length distinct names and patches the second down to the
    /// first afterward, exactly as
    /// `two_different_files_sharing_a_name_are_never_marked_as_shadowing_each_other`
    /// does above.
    #[test]
    fn two_empty_files_sharing_a_name_are_never_marked_as_shadowing_each_other() {
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            w.start_file("same1.txt", opts).expect("start_file 1");
            w.start_file("same2.txt", opts).expect("start_file 2");
            w.finish().expect("finish");
        }
        let mut bytes = cursor.into_inner();

        let mut patched = 0usize;
        let mut at = 0usize;
        while at + 9 <= bytes.len() {
            if bytes[at..at + 9] == *b"same2.txt" {
                bytes[at..at + 9].copy_from_slice(b"same1.txt");
                patched += 1;
                at += 9;
            } else {
                at += 1;
            }
        }
        assert_eq!(
            patched, 2,
            "expected the second entry's local header and CD record names"
        );

        let out = salvage(&bytes);
        assert_eq!(out.entries.len(), 2, "sanity: both empty entries recovered");
        assert_eq!(
            out.entries[1].shadows, None,
            "two zero-byte entries sharing a name must not shadow each other — a checksum of \
             zero bytes proves nothing, even under a matching name and length"
        );
    }
}
