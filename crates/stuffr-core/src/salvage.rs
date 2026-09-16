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
//! Two things this task does NOT do, on purpose, because they need a real
//! decoder to do honestly:
//!
//! - **Verifying a candidate's checksum**, to decide [`SalvageStatus::Intact`]
//!   versus [`SalvageStatus::Complete`]. A candidate that clears the entry
//!   ceiling is recorded as `Complete` here — the header parsed and nothing
//!   is yet known to be missing — never `Intact`: nothing has read the
//!   payload back and compared it against [`Candidate::verifier`], and
//!   claiming otherwise is exactly what the salvage honesty oracle (a later
//!   task's `check_salvage_claim`) exists to catch.
//! - **Detecting a shadowed record**, i.e. setting [`SalvagedEntry::shadows`].
//!   That is also a checksum comparison across entries, so it stays `None`
//!   here.
//!
//! Both are real reconciliation work a later task adds; this module's job is
//! the loop that finds candidates, bounds what they declare, and collects
//! them — safely, against a hostile or merely corrupt input, before any of
//! that work exists.

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
    let mut entries = Vec::new();
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

        let scan_position = entries.len();
        entries.push(SalvagedEntry {
            scan_position,
            offset: candidate.offset,
            meta: candidate.meta,
            // Nothing has verified a checksum yet — see this module's doc
            // comment. `Complete`, never `Intact`, is the honest claim here.
            status: SalvageStatus::Complete,
            shadows: None,
        });

        // Advance strictly past this candidate so the scan always makes
        // progress, regardless of what the scanner reported `from` as or
        // whether it declared a length at all.
        let advance = candidate.declared_len.unwrap_or(1).max(1);
        from = candidate.offset.saturating_add(advance);
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
}
