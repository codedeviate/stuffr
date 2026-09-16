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

use std::io::{self, Read, SeekFrom};

use stuffr_core::salvage::{Candidate, SalvageScan, Verifier};
use stuffr_core::{EntryKind, EntryMeta, Result, SeekRead};

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
}
