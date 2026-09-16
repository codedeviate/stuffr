//! The salvage engine: format-agnostic scanning, bounding and collection.
//!
//! Salvage recovers entries from a damaged archive by scanning for records
//! directly, rather than trusting a single index (a central directory, an
//! EOCD) that may be truncated, zeroed, or — the motivating case — may
//! shadow real records behind a repeated name. The per-format part of that
//! (recognising a local header, computing a checksum) is a
//! [`SalvageScan`] implementation; this module is everything that does not
//! need to know which format it is scanning.
//!
//! **This module implements no per-format scanning at all.** It is proven
//! entirely against mocks — [`SalvageScan`] is the seam Task 2 onward builds
//! real scanners against (starting with zip).
//!
//! ## Verification and shadowing (Task 4)
//!
//! Two things this module now does, both format-agnostic:
//!
//! - **Deciding [`SalvageStatus`]** is delegated to [`SalvageScan::verify`],
//!   called once per candidate in [`annotate_candidates`]. The default
//!   answers [`SalvageStatus::Complete`] — "every declared byte fit inside
//!   the source and the header self-verified, but nothing checked its
//!   content" — which is honest for a mock with no [`Candidate::verifier`]
//!   to check, and for a real format with no checksum at all (tar, cpio,
//!   ar). A format that DOES carry one (zip's CRC-32) overrides `verify` to
//!   decode the payload and compare it, answering `Intact` on agreement and
//!   `Partial` otherwise — never `Complete`, which is reserved for "no way
//!   to prove", not "tried and it disagreed". Earlier revisions of this
//!   module recorded every candidate as `Complete` unconditionally; that was
//!   a placeholder, not a claim about zip, and it was wrong for every zip
//!   entry the moment a real scanner carried a CRC-32.
//! - **Detecting a shadowed record** (setting [`SalvagedEntry::shadows`]) is
//!   generic too: [`annotate_candidates`] remembers the first candidate to
//!   report each distinct [`Verifier`] value and marks any LATER candidate
//!   reporting the identical value as shadowing it. This is a MEASUREMENT —
//!   an equality check on [`Candidate::verifier`] — never an inference from
//!   [`EntryMeta::name`] repeating: two different files that happen to share
//!   a name must not be linked this way, only two records whose original
//!   writer computed the same checksum for both.
//!
//! [`collect_candidates`] (the resync loop: find a candidate, bound its
//! declared length, advance) and [`annotate_candidates`] (verify + shadow,
//! above) are both exposed separately from [`salvage_all`] — which is just
//! the two of them run in sequence — so a format that reconciles more than
//! one candidate source (zip's central-directory fallback, `zip_salvage.rs`)
//! can collect from each source under the identical bound, merge, and
//! annotate the merged list exactly once, rather than annotating twice and
//! reconciling two already-decided outcomes.

use crate::archive::EntryMeta;
use crate::error::{Error, Result};
use crate::source::SeekRead;

/// 4 GiB. A scanned length is untrustworthy TWICE over — attacker-controlled
/// AND possibly corrupt — so this is a structural ceiling, not a budget.
pub const MAX_SALVAGE_ENTRY: u64 = 4 * 1024 * 1024 * 1024;

/// What a format can prove about a candidate it found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verifier {
    /// CRC-32, as zip, arj and gzip compute it.
    Crc32(u32),
    /// CRC-16/ARC, as lha, arc and zoo compute it.
    Crc16(u16),
}

/// A record a scanner believes it found, before anything is decoded.
#[derive(Debug)]
pub struct Candidate {
    /// Byte offset of the record's header in the archive.
    pub offset: u64,
    pub meta: EntryMeta,
    /// Declared payload length. `None` when the header does not carry one.
    pub declared_len: Option<u64>,
    /// The checksum the ORIGINAL writer computed, when the format has one.
    /// `None` is what produces the intact/complete split honestly, rather
    /// than by a per-format convention someone has to remember.
    pub verifier: Option<Verifier>,
}

/// What was proven about an entry AFTER decoding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SalvageStatus {
    /// A checksum the original writer computed agrees.
    Intact,
    /// Every declared byte was present and the header self-verified, but the
    /// format offers no way to prove the content.
    Complete,
    /// The payload ran out, or the decoder failed mid-stream.
    Partial,
}

/// One entry the scan recovered.
#[derive(Debug)]
pub struct SalvagedEntry {
    /// This entry's position in SCAN order — not an index any container's
    /// own format assigns, and never renumbered by what `list` would show.
    /// A later task's CLI surfaces this distinction explicitly (`--index`
    /// on `salvage` names a scan position, not a list index).
    pub scan_position: usize,
    pub offset: u64,
    pub meta: EntryMeta,
    pub status: SalvageStatus,
    /// Set when this record's checksum matches an EARLIER record's — a
    /// measurement, never inferred from a repeated name. `None` in this
    /// task: nothing here compares checksums across entries yet.
    pub shadows: Option<usize>,
}

/// The result of a scan: every entry the scanner recovered, in scan order.
///
/// Later tasks may extend this struct; the `entries` field stays public.
#[derive(Debug)]
pub struct SalvageOutcome {
    pub entries: Vec<SalvagedEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialPolicy {
    Keep,
    Skip,
    Ask,
}

pub struct SalvagePolicy {
    /// Recovery-biased by default: salvage is the one permissive verb, and
    /// the strict path is the entire rest of the tool.
    pub partial: PartialPolicy,
    /// Structural ceiling on any declared length, refused BEFORE allocation.
    pub max_entry: u64,
    /// Demand proof: partial skipped, ceiling fixed, nothing unverifiable.
    pub strict: bool,
}

impl Default for SalvagePolicy {
    fn default() -> Self {
        Self {
            partial: PartialPolicy::Keep,
            max_entry: MAX_SALVAGE_ENTRY,
            strict: false,
        }
    }
}

/// The per-format seam. A scanner recognises its own format's record shape
/// (a local header's magic, a member's checksum field) and reports what it
/// finds as a stream of [`Candidate`]s; [`salvage_all`] supplies everything
/// that does not depend on which format that is.
pub trait SalvageScan {
    /// Find the next candidate at or after `from`. `Ok(None)` ends the scan.
    fn next_candidate(&mut self, src: &mut dyn SeekRead, from: u64) -> Result<Option<Candidate>>;

    /// Decide what was actually proven about a candidate's payload, after
    /// discovery — called once per candidate, in file order, by
    /// [`annotate_candidates`].
    ///
    /// The default answers [`SalvageStatus::Complete`] unconditionally: a
    /// scanner with no real checksum (or, in this module's own tests, a mock
    /// that never populates [`Candidate::verifier`]) has nothing to check,
    /// and `Complete` is the honest claim for that case. A format that DOES
    /// carry a checksum overrides this to decode the payload — reusing its
    /// own existing codec machinery, never inventing a new one here — and
    /// compare it against [`Candidate::verifier`].
    fn verify(&self, _src: &mut dyn SeekRead, _candidate: &Candidate) -> Result<SalvageStatus> {
        Ok(SalvageStatus::Complete)
    }
}

/// Walk `scan` over `src`, collecting every candidate it reports into a
/// [`SalvageOutcome`].
///
/// **Requires a seekable source.** Scanning searches back and forth over the
/// archive rather than reading it once in order, so this takes
/// `&mut dyn SeekRead` rather than the ladder's `Box<dyn Source>` (whose
/// `as_seek()` may be `None` for a pipe). A caller sitting on a
/// non-seekable source must spool it first — exactly as the `arj` and `zoo`
/// containers already do, reporting `Rung::Spilled` — which is a later
/// task's ops-layer concern, not this function's.
///
/// Every candidate's `declared_len` is bounded against `policy.max_entry`
/// **before** anything is sized from it: an oversized declaration is refused
/// with [`Error::ResourceLimit`] the moment it is seen, never after an
/// allocation or a read has already acted on it.
pub fn salvage_all(
    scan: &mut dyn SalvageScan,
    src: &mut dyn SeekRead,
    policy: &SalvagePolicy,
) -> Result<SalvageOutcome> {
    let candidates = collect_candidates(scan, src, policy)?;
    annotate_candidates(&*scan, src, candidates)
}

/// The resync loop alone: find a candidate, bound its declared length
/// against `policy.max_entry` **before** anything is sized from it, advance
/// strictly past it, repeat. Never reads a payload and never calls
/// [`SalvageScan::verify`] — see [`annotate_candidates`] for that.
///
/// Exposed separately from [`salvage_all`] so a format that reconciles more
/// than one candidate source (zip's central-directory fallback) can collect
/// from each source under the identical bound before merging.
pub fn collect_candidates(
    scan: &mut dyn SalvageScan,
    src: &mut dyn SeekRead,
    policy: &SalvagePolicy,
) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    let mut from = 0u64;

    while let Some(candidate) = scan.next_candidate(src, from)? {
        if let Some(len) = candidate.declared_len
            && len > policy.max_entry
        {
            return Err(Error::ResourceLimit(format!(
                "declared entry length {len} bytes exceeds the {}-byte salvage ceiling \
                 (see MAX_SALVAGE_ENTRY)",
                policy.max_entry
            )));
        }

        // Advance strictly past this candidate so the scan always makes
        // progress, regardless of what the scanner reported `from` as or
        // whether it declared a length at all.
        let advance = candidate.declared_len.unwrap_or(1).max(1);
        from = candidate.offset.saturating_add(advance);

        candidates.push(candidate);
    }

    Ok(candidates)
}

/// Turns already-discovered, already-bounded candidates — in file order —
/// into the verified, shadow-annotated entries a caller receives. See this
/// module's doc comment for what the two passes (verify, shadow) mean and
/// why they live here rather than per-format.
pub fn annotate_candidates(
    scan: &dyn SalvageScan,
    src: &mut dyn SeekRead,
    candidates: Vec<Candidate>,
) -> Result<SalvageOutcome> {
    let mut entries = Vec::with_capacity(candidates.len());
    // Earliest scan_position to report each distinct checksum seen so far —
    // a candidate reporting one already in here is shadowing that position.
    let mut seen: Vec<(Verifier, usize)> = Vec::new();

    for (scan_position, candidate) in candidates.into_iter().enumerate() {
        let status = scan.verify(src, &candidate)?;

        let shadows = candidate.verifier.and_then(|verifier| {
            seen.iter()
                .find(|&&(seen_verifier, _)| seen_verifier == verifier)
                .map(|&(_, earlier_position)| earlier_position)
        });
        if let Some(verifier) = candidate.verifier
            && shadows.is_none()
        {
            seen.push((verifier, scan_position));
        }

        entries.push(SalvagedEntry {
            scan_position,
            offset: candidate.offset,
            meta: candidate.meta,
            status,
            shadows,
        });
    }

    Ok(SalvageOutcome { entries })
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    use super::*;

    fn bytes(data: &[u8]) -> Cursor<Vec<u8>> {
        Cursor::new(data.to_vec())
    }

    /// A reader that panics if asked to read more bytes in one call than its
    /// backing buffer holds. `salvage_all`'s own loop never reads a
    /// candidate's payload at all (see the module doc), so a correct
    /// implementation never trips this — it exists to catch a regression
    /// that reads before bounding, the exact shape this project has shipped
    /// six times across `cpio`, `ar` and `zip`.
    struct PanickingReader(Cursor<Vec<u8>>);

    impl Read for PanickingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let backing_len = self.0.get_ref().len();
            assert!(
                buf.len() <= backing_len,
                "oversized read requested: {} bytes against a {backing_len}-byte source \
                 — an allocation or read was sized from a declared length before it was bounded",
                buf.len()
            );
            self.0.read(buf)
        }
    }

    impl Seek for PanickingReader {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }

    fn panicking_reader(len: usize) -> PanickingReader {
        PanickingReader(Cursor::new(vec![0u8; len]))
    }

    /// A scanner that never finds anything, however many times it is asked.
    struct NeverFinds;

    impl SalvageScan for NeverFinds {
        fn next_candidate(
            &mut self,
            _src: &mut dyn SeekRead,
            _from: u64,
        ) -> Result<Option<Candidate>> {
            Ok(None)
        }
    }

    /// A scanner that reports exactly one candidate, declaring the given
    /// length, then ends the scan. It never touches `src` itself — it
    /// exists purely to hand `salvage_all` a declared length to bound.
    struct DeclaresLength(u64);

    impl SalvageScan for DeclaresLength {
        fn next_candidate(
            &mut self,
            _src: &mut dyn SeekRead,
            from: u64,
        ) -> Result<Option<Candidate>> {
            if from > 0 {
                return Ok(None);
            }
            Ok(Some(Candidate {
                offset: 0,
                meta: EntryMeta::file("absurd"),
                declared_len: Some(self.0),
                verifier: None,
            }))
        }
    }

    #[test]
    fn a_scanner_that_finds_nothing_yields_no_entries() {
        let out = salvage_all(
            &mut NeverFinds,
            &mut bytes(&[0u8; 4096]),
            &SalvagePolicy::default(),
        );
        assert!(
            out.unwrap().entries.is_empty(),
            "a scanner finding nothing must yield nothing"
        );
    }

    /// The ceiling test that matters most: a reader that PANICS on an
    /// oversized read, so this test fails if the allocation happens at all
    /// — not merely if the wrong error code comes back. See this module's
    /// falsification note in the task report for what happens when the
    /// bound is moved below a read.
    #[test]
    fn an_absurd_declared_length_is_refused_before_the_allocation_it_would_size() {
        let mut scan = DeclaresLength(u64::MAX);
        let err = salvage_all(
            &mut scan,
            &mut panicking_reader(4096),
            &SalvagePolicy::default(),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 6);
    }

    #[test]
    fn a_declared_length_within_the_ceiling_is_collected_as_complete() {
        let mut scan = DeclaresLength(4096);
        let out = salvage_all(
            &mut scan,
            &mut panicking_reader(4096),
            &SalvagePolicy::default(),
        )
        .unwrap();
        assert_eq!(out.entries.len(), 1);
        let entry = &out.entries[0];
        assert_eq!(entry.scan_position, 0);
        assert_eq!(entry.offset, 0);
        assert_eq!(entry.status, SalvageStatus::Complete);
        assert_eq!(entry.shadows, None);
    }

    #[test]
    fn the_default_policy_is_recovery_biased() {
        let policy = SalvagePolicy::default();
        assert_eq!(policy.partial, PartialPolicy::Keep);
        assert_eq!(policy.max_entry, MAX_SALVAGE_ENTRY);
        assert!(!policy.strict);
    }

    // -----------------------------------------------------------------
    // Task 4: `verify` dispatch and shadow detection, proven against a
    // mock — same discipline as the rest of this module, since neither
    // mechanism needs to know which format it is annotating.
    // -----------------------------------------------------------------

    /// Reports a fixed, caller-scripted sequence of candidates and answers
    /// `verify` from the SAME script rather than decoding anything — this
    /// module's engine is proven against mocks, and verification/shadow
    /// detection are no exception.
    struct ScriptedCandidates {
        plan: Vec<(Option<Verifier>, SalvageStatus)>,
        next: usize,
    }

    impl SalvageScan for ScriptedCandidates {
        fn next_candidate(
            &mut self,
            _src: &mut dyn SeekRead,
            _from: u64,
        ) -> Result<Option<Candidate>> {
            if self.next >= self.plan.len() {
                return Ok(None);
            }
            let offset = self.next as u64;
            let (verifier, _) = self.plan[self.next];
            self.next += 1;
            Ok(Some(Candidate {
                offset,
                meta: EntryMeta::file(format!("entry-{offset}")),
                declared_len: Some(1),
                verifier,
            }))
        }

        fn verify(&self, _src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
            Ok(self.plan[candidate.offset as usize].1)
        }
    }

    /// `verify` decides each entry's status — the whole point of Task 4:
    /// this used to be a hardcoded `Complete` for every candidate, which was
    /// wrong for any format carrying a real checksum.
    #[test]
    fn verify_decides_each_entrys_status_not_a_hardcoded_default() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (Some(Verifier::Crc32(1)), SalvageStatus::Intact),
                (None, SalvageStatus::Complete),
                (Some(Verifier::Crc32(2)), SalvageStatus::Partial),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
        assert_eq!(out.entries[1].status, SalvageStatus::Complete);
        assert_eq!(out.entries[2].status, SalvageStatus::Partial);
    }

    /// A later candidate reporting the SAME verifier as an earlier one is
    /// its shadow — pointing at the earliest position, not merely "some"
    /// earlier one — and this is a checksum equality, never anything to do
    /// with `meta.name`, which `ScriptedCandidates` does not even vary here.
    #[test]
    fn a_later_candidate_sharing_an_earlier_verifier_is_marked_as_its_shadow() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (Some(Verifier::Crc32(7)), SalvageStatus::Intact),
                (Some(Verifier::Crc32(9)), SalvageStatus::Intact),
                (Some(Verifier::Crc32(7)), SalvageStatus::Intact),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(out.entries[0].shadows, None);
        assert_eq!(out.entries[1].shadows, None);
        assert_eq!(
            out.entries[2].shadows,
            Some(0),
            "must point at the earliest matching position"
        );
    }

    /// A candidate with no verifier at all (a format with no checksum, or a
    /// zip data-descriptor entry) must never be reported as shadowing or
    /// shadowed — there is nothing to measure, so nothing is claimed.
    #[test]
    fn candidates_with_no_verifier_never_shadow_each_other() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (None, SalvageStatus::Complete),
                (None, SalvageStatus::Complete),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(out.entries[0].shadows, None);
        assert_eq!(out.entries[1].shadows, None);
    }
}
