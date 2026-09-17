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
//!   report each distinct `(name, declared_len, verifier)` triple and marks
//!   any LATER candidate reporting the identical triple as shadowing it.
//!   This is a MEASUREMENT, never an inference from [`EntryMeta::name`]
//!   alone repeating: two different files that happen to share a name must
//!   not be linked this way, only two records whose original writer
//!   computed the same checksum, over the same declared length, under the
//!   same name. The checksum alone is not enough either — fixed after this
//!   module's own fix-round review measured it against real archives: every
//!   empty file and every directory entry in a zip has `Crc32(0)` — a
//!   structural certainty for a zero-byte payload, not a collision — so a
//!   checksum-only match reported an ordinary Python package's dozen
//!   `__init__.py` files, and its directories, as duplicates of one another.
//!   The degenerate case is refused outright rather than papered over by the
//!   wider conjunction: a candidate with `declared_len == Some(0)` never
//!   shadows and is never shadowed, because a checksum over zero bytes is
//!   the same value for every empty entry that ever existed and proves
//!   nothing about any of them being copies of each other.
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

/// Why an entry is [`SalvageStatus::Unverified`].
///
/// Two causes, and the STATUS does not distinguish them because the decision
/// they lead to is identical (listed, not written, exit 3) — the same split
/// [`crate::salvage`]'s consumers apply to [`SalvageStatus::Partial`] via
/// their own cause type (`entries.rs`'s `PartialCause`, one crate up): **a
/// tier carries a decision, a message carries a cause.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiedCause {
    /// This build recognises the entry's compression method but cannot
    /// decode it (zip method 99 is AES, 14 is LZMA — recognised, not
    /// decoded).
    UndecodableMethod,
    /// No length was available to bound the payload, so it was never read —
    /// a data-descriptor entry the raw scan found with no central-directory
    /// record to reconcile against. A CD-reconciled data-descriptor entry
    /// gets a real declared length and CRC from the central directory and
    /// does NOT reach this cause; see `zip_salvage.rs`'s
    /// `candidate_from_cd_record`.
    NoDeclaredLength,
}

/// What was proven about an entry AFTER decoding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SalvageStatus {
    /// A checksum the original writer computed agrees.
    Intact,
    /// Every declared byte was present and the header self-verified, but the
    /// format offers NO CHECKSUM AT ALL to prove the content — tar, cpio and
    /// ar, in this project's own formats. Never the right answer for a
    /// format that DOES carry one; see [`SalvageStatus::Unverified`] for
    /// that case, which this status is not permitted to stand in for.
    Complete,
    /// Nothing about this entry's content was verified.
    ///
    /// Two causes ([`UnverifiedCause`]), and the tier does not distinguish
    /// them because the decision is identical — the entry is listed, not
    /// written, and the run exits 3:
    ///   * this build could not decode the method (zip 99 is AES, 14 is
    ///     LZMA);
    ///   * no length was available to bound the payload, so it was never
    ///     read (a data-descriptor entry the raw scan found with no
    ///     central-directory record to reconcile against).
    ///
    /// Distinct from [`Self::Complete`], which asserts every DECLARED byte
    /// was present — a claim that requires something to have been declared
    /// in the first place. Reporting `Complete` for either cause above was
    /// this enum's third instance of "nothing to disprove" being read as
    /// "proven" (after the Task 1 hardcoded placeholder and the Task 4
    /// undecodable-method case this variant was originally added for) — the
    /// exit-code table this status exists to keep honest reserves exit 3 for
    /// both causes, never exit 0, which is what `Complete` would have routed
    /// either one to.
    Unverified(UnverifiedCause),
    /// The payload ran out, the decoder failed mid-stream, or the content
    /// decoded whole and disagreed with the checksum the original writer
    /// computed. All three are the same fact from a caller's perspective —
    /// this build could not confirm the content is what was written — and
    /// none of them is `Complete` (something WAS checked) or `Intact` (it
    /// did not agree, or never finished).
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
    /// Set when this record's `(name, declared_len, verifier)` all agree
    /// with an EARLIER record's — a measurement, never inferred from a
    /// repeated name alone, and never set for a degenerate zero-length
    /// checksum (every empty file and every directory entry shares one).
    /// See [`annotate_candidates`] for where this is computed.
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
    // Earliest scan_position to report each distinct (name, declared_len,
    // verifier) triple seen so far — a candidate reporting one already in
    // here is shadowing that position. A degenerate zero-length checksum
    // (every empty file, every directory entry) is never pushed here and
    // never looked up here — see `is_degenerate` below.
    let mut seen: Vec<(String, Option<u64>, Verifier, usize)> = Vec::new();

    for (scan_position, candidate) in candidates.into_iter().enumerate() {
        let status = scan.verify(src, &candidate)?;

        let declared_len = candidate.declared_len;
        let verifier = candidate.verifier;
        // A checksum over zero declared bytes is the same value for every
        // empty entry that ever existed (CRC-32 and CRC-16/ARC of an empty
        // input are both fixed constants) and proves nothing about any two
        // of them being copies of each other — measured against a real
        // archive during this task's fix round: every `__init__.py` and
        // every directory entry collapsed onto one shadow chain under a
        // checksum-only match.
        let is_degenerate = declared_len == Some(0);

        let shadows = if is_degenerate {
            None
        } else {
            verifier.and_then(|v| {
                seen.iter()
                    .find(|&&(ref seen_name, seen_len, seen_verifier, _)| {
                        seen_verifier == v
                            && seen_len == declared_len
                            && *seen_name == candidate.meta.name
                    })
                    .map(|&(_, _, _, earlier_position)| earlier_position)
            })
        };

        if !is_degenerate
            && shadows.is_none()
            && let Some(v) = verifier
        {
            seen.push((candidate.meta.name.clone(), declared_len, v, scan_position));
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
    /// detection are no exception. Each entry names its own `name` and
    /// `declared_len` (rather than a fixed, offset-derived name) so a test
    /// can freely vary any one of the three fields shadow detection now
    /// requires to agree.
    struct ScriptedCandidates {
        plan: Vec<(&'static str, Option<u64>, Option<Verifier>, SalvageStatus)>,
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
            let (name, declared_len, verifier, _) = self.plan[self.next];
            self.next += 1;
            Ok(Some(Candidate {
                offset,
                meta: EntryMeta::file(name),
                declared_len,
                verifier,
            }))
        }

        fn verify(&self, _src: &mut dyn SeekRead, candidate: &Candidate) -> Result<SalvageStatus> {
            Ok(self.plan[candidate.offset as usize].3)
        }
    }

    /// `verify` decides each entry's status — the whole point of Task 4:
    /// this used to be a hardcoded `Complete` for every candidate, which was
    /// wrong for any format carrying a real checksum.
    #[test]
    fn verify_decides_each_entrys_status_not_a_hardcoded_default() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (
                    "a",
                    Some(1),
                    Some(Verifier::Crc32(1)),
                    SalvageStatus::Intact,
                ),
                ("b", Some(1), None, SalvageStatus::Complete),
                (
                    "c",
                    Some(1),
                    Some(Verifier::Crc32(2)),
                    SalvageStatus::Partial,
                ),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(out.entries[0].status, SalvageStatus::Intact);
        assert_eq!(out.entries[1].status, SalvageStatus::Complete);
        assert_eq!(out.entries[2].status, SalvageStatus::Partial);
    }

    /// A later candidate reporting the SAME name, declared_len AND verifier
    /// as an earlier one is its shadow — pointing at the earliest position,
    /// not merely "some" earlier one.
    #[test]
    fn a_later_candidate_sharing_an_earlier_verifier_is_marked_as_its_shadow() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (
                    "dup",
                    Some(1),
                    Some(Verifier::Crc32(7)),
                    SalvageStatus::Intact,
                ),
                (
                    "other",
                    Some(1),
                    Some(Verifier::Crc32(9)),
                    SalvageStatus::Intact,
                ),
                (
                    "dup",
                    Some(1),
                    Some(Verifier::Crc32(7)),
                    SalvageStatus::Intact,
                ),
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
                ("a", Some(1), None, SalvageStatus::Complete),
                ("a", Some(1), None, SalvageStatus::Complete),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(out.entries[0].shadows, None);
        assert_eq!(out.entries[1].shadows, None);
    }

    /// Two candidates whose checksum AND declared_len agree but whose NAME
    /// differs must never be linked — the fix-round requirement that a
    /// checksum match alone is not enough, only the full
    /// `(name, declared_len, verifier)` triple.
    #[test]
    fn a_matching_verifier_under_a_different_name_is_never_marked_as_a_shadow() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (
                    "one.txt",
                    Some(4),
                    Some(Verifier::Crc32(42)),
                    SalvageStatus::Intact,
                ),
                (
                    "two.txt",
                    Some(4),
                    Some(Verifier::Crc32(42)),
                    SalvageStatus::Intact,
                ),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(
            out.entries[1].shadows, None,
            "same checksum, different name — not a shadow"
        );
    }

    /// The degenerate case: every empty entry (and, in zip, every directory
    /// entry) checksums to the same fixed constant over zero declared
    /// bytes. Even under the SAME name, a zero-length checksum must never
    /// mark a shadow — the value proves nothing, unlike a real collision.
    #[test]
    fn a_zero_length_declared_verifier_never_shadows_even_under_a_matching_name() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (
                    "empty.txt",
                    Some(0),
                    Some(Verifier::Crc32(0)),
                    SalvageStatus::Complete,
                ),
                (
                    "empty.txt",
                    Some(0),
                    Some(Verifier::Crc32(0)),
                    SalvageStatus::Complete,
                ),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(out.entries[0].shadows, None);
        assert_eq!(
            out.entries[1].shadows, None,
            "a zero-byte checksum must never mark a shadow, even under an identical name"
        );
    }
}
