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
//! - **Detecting a repeated NAME** ([`SalvagedEntry::collides_with`]) is a
//!   second, deliberately separate annotation, added after the final
//!   whole-branch review found the word "shadow" doing two jobs. The two
//!   facts are different and both worth printing: a shadow is a record
//!   MEASURED to be a copy of an earlier one, a collision is a record whose
//!   name an earlier one already used and whose content this scan could not
//!   prove identical. `stuffr list`'s own `Fidelity::EntryCountMismatch`
//!   warning is about the second, so on an archive whose duplicates differ,
//!   `list` reported two records shadowed while `salvage --list` marked
//!   none — one tool telling a user two contradictory things about the same
//!   eight records. None of the guards on shadow detection above apply to a
//!   collision, and applying them would be wrong: they exist because
//!   claiming two records are COPIES needs proof, and a collision claims
//!   nothing about content at all. The two are mutually exclusive — a
//!   proven copy is reported as a shadow and nothing else, since that is
//!   the strictly more informative claim.
//!
//! [`collect_candidates`] (the resync loop: find a candidate, advance) and
//! [`annotate_candidates`] (bound + verify + shadow, above) are both
//! exposed separately from [`salvage_all`] — which is just the two of them
//! run in sequence — so a format that reconciles more than one candidate
//! source (zip's central-directory fallback, `zip_salvage.rs`) can collect
//! from each source, merge, and annotate the merged list exactly once
//! rather than annotating twice and reconciling two already-decided
//! outcomes. The run's ceiling on a single entry is applied once, in
//! `annotate_candidates`, to whatever the merge produced — see
//! [`UnverifiedCause::OverEntryCeiling`] for why it is a status there
//! rather than a [`crate::Error`] anywhere.

use std::io::{Read, Write};

use crate::archive::EntryMeta;
use crate::error::Result;
use crate::source::SeekRead;

/// 4 GiB. A scanned length is untrustworthy TWICE over — attacker-controlled
/// AND possibly corrupt — so this is a structural ceiling, not a budget.
///
/// Applied per ENTRY, never to the run: an entry over it is reported
/// [`UnverifiedCause::OverEntryCeiling`] and skipped, and the rest of the
/// archive is recovered as usual. It used to abort the run outright, which
/// meant one absurd declaration cost every entry around it.
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
///
/// # Why this is `#[non_exhaustive]` AND has a constructor
///
/// Ruling S-I, deferred from Salvage Stage 2 Task 1 to Task 9 on purpose:
/// this struct is the one shape [`SalvageScan::next_candidate`] *forces* an
/// external implementor to build, so every field added to it used to break
/// every out-of-crate scanner at once — and at `0.5.0` all four crates are
/// published, so "out-of-crate" is not hypothetical. The attribute alone
/// would have been the wrong fix (`CONTRIBUTING.md`'s `#[non_exhaustive]`
/// section says why: it forbids `..` construction from another crate, which
/// is exactly what an implementor must do), which is why it waited for
/// [`Candidate::new`] — and for all five in-tree scanners to exist, so the
/// constructor's shape could be read off real callers rather than guessed.
///
/// The three arguments [`Candidate::new`] takes are the three facts every
/// scanner knows the instant it recognises a record. The four `with_*`
/// setters cover the rest, each taking the field's own type unchanged so
/// nothing is hidden behind a conversion.
#[derive(Debug)]
#[non_exhaustive]
pub struct Candidate {
    /// Byte offset of the record's header in the archive.
    pub offset: u64,
    /// Byte offset where this record's PAYLOAD begins — past whatever
    /// fixed and variable-length header fields this format's record
    /// carries (a zip local header's name/extra fields, ARC's fixed
    /// 28-byte record, and so on).
    ///
    /// Task 3c added this field after `entries.rs`'s write path hardcoded
    /// a ZIP local header's own 30-byte-plus-name-plus-extra layout as
    /// the way to locate every format's payload — which crashed
    /// (`Error::Io`, exit 1, the wildcard this project treats as a
    /// defect) the moment a non-zip scanner (ARC) reported a candidate
    /// near the end of the file, because reading 30 bytes from ITS offset
    /// ran past EOF. Each scanner already computes this value once, at
    /// discovery, to know where ITS OWN payload begins — this field
    /// carries that computation forward instead of a consumer re-deriving
    /// (and mis-deriving) it later. A future scanner (zoo, lha, arj) fills
    /// this the same way; nothing outside the scanner that discovered a
    /// candidate needs to know its record's own layout at all.
    pub payload_start: u64,
    pub meta: EntryMeta,
    /// Declared payload length. `None` when the header does not carry one.
    pub declared_len: Option<u64>,
    /// The checksum the ORIGINAL writer computed, when the format has one.
    /// `None` is what produces the intact/complete split honestly, rather
    /// than by a per-format convention someone has to remember.
    pub verifier: Option<Verifier>,
    /// How many of `declared_len`'s bytes the SOURCE actually holds, when
    /// it holds fewer — the truncated-tail case. `None` means the declared
    /// payload is entirely present (the ordinary case) or nothing was
    /// declared at all; `Some(n)` always means `n < declared_len`.
    ///
    /// # Why a scanner reports this instead of dropping the candidate
    ///
    /// A truncated archive — an interrupted download — is the single most
    /// common damaged zip there is, and it was the one shape salvage said
    /// nothing at all about. `zip_salvage.rs`'s validation gate refused any
    /// candidate whose declared payload ran past the end of the file, which
    /// is a correct refusal to INVENT the missing bytes (`zip -FF`
    /// fabricates them and reports success) implemented as SILENCE: no row,
    /// no note, no non-zero exit. Swept across six truncation points inside
    /// a three-header archive's last entry, every one reported "2 scanned"
    /// at exit 0 — the third header was not even counted.
    ///
    /// Reporting the candidate with this field set is what turns the
    /// refusal into a statement. Nothing is invented: the declared length
    /// stays exactly what the header said, so a reader can see both figures,
    /// and the bytes that ARE present are still a genuine prefix. What a
    /// scanner must NOT do is fold the shortfall into `declared_len` — that
    /// would make a truncated entry indistinguishable from a whole one of
    /// the smaller size, which is the same mistake in a different place.
    pub available_len: Option<u64>,
    /// The archive's own record marks this entry DELETED — the format's
    /// owner removed it and the writer left the record, and its payload,
    /// in place.
    ///
    /// `false` for every format that has no such flag (zip, tar, ar, cpio,
    /// arc), which is why it is a plain `bool` rather than an `Option`:
    /// "this format cannot express deletion" and "this record is not
    /// deleted" lead to the identical, unannotated row, and a third state
    /// would be a distinction no consumer could act on.
    ///
    /// # Why a scanner reports one rather than dropping it (Ruling S-R)
    ///
    /// Salvage Stage 2 Task 4, for ZOO — the first format here with the
    /// flag. `zoo d` marks an entry `deleted = 1` and leaves it whole in the
    /// file; `zoolist.c` neither lists nor extracts it, and `legacy::zoo`'s
    /// reader follows that exactly. The flag is ONE BYTE, so in a damaged
    /// archive a bit flip turns a live entry into one no ordinary verb will
    /// ever hand back — which is precisely the archive this verb exists for.
    /// So the scanner reports it.
    ///
    /// **And the report carries a marker, which is the part that took a
    /// review to get right.** Everywhere else salvage accepts less than an
    /// ordinary entry it says so on the artifact or in the row: a `Partial`
    /// lands as `NAME.partial` and never under its real name, a second
    /// record under a taken name lands as `NAME.salvaged-N`, a proven copy
    /// prints `[shadowed]`. A deleted record reported `Intact` under its
    /// real name at exit 0 was the one place that leniency was invisible —
    /// four verbs call the archive empty and the fifth writes the file, with
    /// nothing telling a user which it was.
    ///
    /// **The exit code deliberately does NOT move.** Recovering a deleted
    /// record is this verb working as designed, not degraded fidelity — see
    /// `stuffr::entries`'s own exit-code aggregation, which this field is
    /// invisible to.
    pub marked_deleted: bool,
}

impl Candidate {
    /// A candidate at `offset`, whose payload begins at `payload_start`,
    /// carrying `meta`.
    ///
    /// Nothing else is claimed. The four fields this does not take default
    /// to the answers that assert the least:
    ///
    /// * `declared_len: None` — the header carries no length, so nothing
    ///   bounds the payload and [`annotate_candidates`] reports
    ///   [`UnverifiedCause::NoDeclaredLength`] rather than reading it.
    /// * `verifier: None` — the format offers nothing to prove the content
    ///   with, so no shadow is ever claimed for this record (see
    ///   [`SalvagedEntry::shadows`], which needs a verifier to compare).
    /// * `available_len: None` — every declared byte is present, which is
    ///   the ordinary case; a scanner sets this only when it has MEASURED a
    ///   shortfall.
    /// * `marked_deleted: false` — the format has no deleted flag, or this
    ///   record is not marked. Four of the five in-tree scanners leave it.
    ///
    /// One default is worth naming because it is the lenient direction, not
    /// the strict one: with no `verifier`, [`SalvageScan::verify`]'s own
    /// default answers [`SalvageStatus::Complete`]. That is correct for a
    /// format with no checksum at all and wrong for one that has a checksum
    /// this scanner forgot to report — but a scanner carrying a checksum has
    /// to write its own `verify` regardless (the default checks nothing),
    /// and that `verify` reads this very field, so the omission fails in the
    /// scanner's own first test rather than silently.
    pub fn new(offset: u64, payload_start: u64, meta: EntryMeta) -> Self {
        Self {
            offset,
            payload_start,
            meta,
            declared_len: None,
            verifier: None,
            available_len: None,
            marked_deleted: false,
        }
    }

    /// Sets [`Self::declared_len`].
    #[must_use]
    pub fn with_declared_len(mut self, declared_len: Option<u64>) -> Self {
        self.declared_len = declared_len;
        self
    }

    /// Sets [`Self::verifier`].
    #[must_use]
    pub fn with_verifier(mut self, verifier: Option<Verifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Sets [`Self::available_len`] — the truncated-tail case, and only
    /// when the shortfall was measured. See that field's doc for why a
    /// scanner must never fold it into [`Self::declared_len`] instead.
    #[must_use]
    pub fn with_available_len(mut self, available_len: Option<u64>) -> Self {
        self.available_len = available_len;
        self
    }

    /// Sets [`Self::marked_deleted`] — Ruling S-R. See that field's doc.
    #[must_use]
    pub fn with_marked_deleted(mut self, marked_deleted: bool) -> Self {
        self.marked_deleted = marked_deleted;
        self
    }
}

/// Why an entry is [`SalvageStatus::Unverified`].
///
/// Three causes, and the STATUS does not distinguish them because the
/// decision they lead to is identical (listed, not written, exit 3) — the
/// same split [`crate::salvage`]'s consumers apply to
/// [`SalvageStatus::Partial`] via their own cause type (`entries.rs`'s
/// `PartialCause`, one crate up): **a tier carries a decision, a message
/// carries a cause.**
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
    /// The bytes this entry would have required are past the ceiling this
    /// run will read for ONE entry — `policy.max_entry` narrowed by the
    /// scanner's own [`SalvageScan::max_whole_entry`] — so nothing was read
    /// and nothing was decoded. See [`annotate_candidates`], which is the
    /// one place that decides this, for the whole rule.
    ///
    /// # Why this is a cause and not an `Err`
    ///
    /// Salvage Stage 2 Task 3c's fix round 3. This refusal used to be an
    /// [`crate::Error::ResourceLimit`] raised from two different places — the
    /// engine's own [`collect_candidates`], and (for ARC) the scanner's own
    /// `verify` — and an `Err` at either site **aborts the whole run**:
    /// measured at the CLI on a two-entry archive whose second entry was
    /// over the ceiling, `stuffr salvage --list` printed no rows at all and
    /// exited 6, and `salvage -C out` left the destination empty, losing a
    /// first entry that decodes perfectly. That is the one thing this verb
    /// exists not to do. Three fix rounds chased the shape from site to
    /// site; what actually closes it is that an over-ceiling entry has a
    /// STATUS, so there is no `Err` left to propagate.
    ///
    /// Distinct from [`SalvageStatus::Partial`], which is what this used to
    /// collapse into once the `Err` was folded away at the write layer: a
    /// truncated entry's genuine prefix IS recovered (as `NAME.partial`),
    /// while an over-ceiling entry has real bytes nobody read. Reporting it
    /// as `Partial (truncated)` stated two false things — the entry is not
    /// truncated, and the empty `NAME.partial` it produced said nothing
    /// survived.
    ///
    /// # Why it carries both figures (fix round 4, NEW-F)
    ///
    /// The `Err` this replaced carried a sentence naming the declared size
    /// and the ceiling; the first version of this variant was a unit, so a
    /// user meeting a container's own fixed ceiling was told neither number
    /// and could not tell whether `--max-entry` would help. The cause is
    /// the only place that knows both, so it carries both and the CLI row
    /// prints them — the project's own "a message carries a cause", with
    /// the numbers that make the message actionable.
    OverEntryCeiling {
        /// Bytes reading this entry would have required: the BOUNDED
        /// figure the comparison actually used — `available_len` when the
        /// payload is truncated, the header's `declared_len` otherwise —
        /// never the raw declaration when the file holds less than it.
        needed: u64,
        /// The ceiling in force for this run: [`SalvagePolicy::max_entry`]
        /// narrowed by [`SalvageScan::max_whole_entry`]. Equal to
        /// `max_entry` means `--max-entry` can raise it; below it means a
        /// whole-decoding container's own fixed ceiling decided, and no
        /// flag moves that.
        ceiling: u64,
    },
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
///
/// `#[non_exhaustive]` plus [`SalvagedEntry::new`], for the same reason
/// [`Candidate`] carries both — see that type's own doc. This one is built
/// by [`annotate_candidates`] in ordinary use, but every per-format scanner
/// crate builds one directly to drive its `write_payload` seam, so the
/// literal it used to need was an out-of-crate literal all the same.
#[derive(Debug)]
#[non_exhaustive]
pub struct SalvagedEntry {
    /// This entry's position in SCAN order — not an index any container's
    /// own format assigns, and never renumbered by what `list` would show.
    /// A later task's CLI surfaces this distinction explicitly (`--index`
    /// on `salvage` names a scan position, not a list index).
    pub scan_position: usize,
    pub offset: u64,
    /// Carried forward from [`Candidate::payload_start`] — see that
    /// field's doc for why a consumer must use this rather than
    /// re-deriving a payload's location from `offset` itself.
    pub payload_start: u64,
    pub meta: EntryMeta,
    pub status: SalvageStatus,
    /// Set when this record's `(name, declared_len, verifier)` all agree
    /// with an EARLIER record's — a measurement, never inferred from a
    /// repeated name alone, and never set for a degenerate zero-length
    /// checksum (every empty file and every directory entry shares one).
    /// See [`annotate_candidates`] for where this is computed.
    ///
    /// **This is the byte-identical duplicate, and ONLY that.** The other,
    /// weaker fact — an earlier record under the same name whose content
    /// this scan could not prove identical — is [`Self::collides_with`], and
    /// the two are mutually exclusive by construction. They were one word
    /// ("shadow") until the final whole-branch review measured what that
    /// cost: `stuffr list`'s own fidelity warning uses "shadowed" for a
    /// repeated NAME, so on an archive whose duplicates differ, `list` said
    /// two records were shadowed and `salvage --list` marked none.
    pub shadows: Option<usize>,
    /// Set when an EARLIER record carries the same `meta.name` and this one
    /// is not that record's [`Self::shadows`] — i.e. the name repeats but
    /// the content could not be proven identical.
    ///
    /// This is the fact `stuffr list`'s `Fidelity::EntryCountMismatch`
    /// warning is about: a later record repeating a name is what makes an
    /// earlier one unreachable through a central directory's name index,
    /// whatever the bytes under it. It is also the fact that decides
    /// anything on the WRITE side, because two records under one name and
    /// two different payloads cannot both land on one path.
    ///
    /// Deliberately NOT gated on a verifier, a declared length or the
    /// degenerate zero-length case the way [`Self::shadows`] is: those
    /// guards exist because claiming two records are COPIES of each other
    /// needs proof, and this annotation claims no such thing. A repeated
    /// name is directly observed, and `None` here means only that no
    /// earlier record used this name — never that one did and this could
    /// not tell.
    pub collides_with: Option<usize>,
    /// Carried forward unchanged from [`Candidate::marked_deleted`] — see
    /// that field for the whole ruling. Unlike [`Self::shadows`] and
    /// [`Self::collides_with`], this is not something this module MEASURES:
    /// it is a fact the archive's own record states, which only the scanner
    /// that read that record can know.
    pub marked_deleted: bool,
}

impl SalvagedEntry {
    /// An entry at scan position `scan_position`, found at `offset`, whose
    /// payload begins at `payload_start`, carrying `meta` and proven to
    /// `status`.
    ///
    /// The three fields this does not take default to "nothing was
    /// observed": no shadow, no name collision, not marked deleted. All
    /// three are annotations [`annotate_candidates`] adds (or, for
    /// `marked_deleted`, carries forward from [`Candidate`]), so a caller
    /// building one directly — every per-format `write_payload` test does —
    /// wants exactly those defaults.
    pub fn new(
        scan_position: usize,
        offset: u64,
        payload_start: u64,
        meta: EntryMeta,
        status: SalvageStatus,
    ) -> Self {
        Self {
            scan_position,
            offset,
            payload_start,
            meta,
            status,
            shadows: None,
            collides_with: None,
            marked_deleted: false,
        }
    }

    /// Sets [`Self::shadows`] — the byte-identical duplicate, and only
    /// that. See the field's own doc for what separates it from
    /// [`Self::collides_with`].
    #[must_use]
    pub fn with_shadows(mut self, shadows: Option<usize>) -> Self {
        self.shadows = shadows;
        self
    }

    /// Sets [`Self::collides_with`] — the weaker, name-only annotation.
    #[must_use]
    pub fn with_collides_with(mut self, collides_with: Option<usize>) -> Self {
        self.collides_with = collides_with;
        self
    }

    /// Sets [`Self::marked_deleted`], carried forward from
    /// [`Candidate::marked_deleted`] rather than measured here.
    #[must_use]
    pub fn with_marked_deleted(mut self, marked_deleted: bool) -> Self {
        self.marked_deleted = marked_deleted;
        self
    }
}

/// The result of a scan: every entry the scanner recovered, in scan order.
///
/// Later tasks may extend this struct; the `entries` field stays public,
/// and `#[non_exhaustive]` is what makes "extend" honest. No constructor is
/// paired with it, unlike [`Candidate`] and [`SalvagedEntry`]: this struct
/// is built by [`salvage_all`] alone, in this crate, and no scanner — in
/// this workspace or outside it — has any reason to build one.
#[derive(Debug)]
#[non_exhaustive]
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
    /// Structural ceiling on any one entry's length, refused BEFORE
    /// allocation — and refused as a per-entry
    /// [`UnverifiedCause::OverEntryCeiling`], never as an error that ends
    /// the run. [`SalvageScan::max_whole_entry`] narrows it further for a
    /// format that decodes an entry whole; the two compose as a minimum and
    /// are applied together, once, in [`annotate_candidates`].
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

    /// The largest single entry this scanner is willing to have read for it
    /// — the ceiling [`annotate_candidates`] applies, narrowed further by
    /// `policy.max_entry`, before it calls [`Self::verify`] at all.
    ///
    /// `u64::MAX` (the default) means "this scanner imposes none of its
    /// own": zip streams every payload it verifies through a `take`, so the
    /// only figure that bounds it is the policy's. A format that **decodes
    /// an entry whole** — ARC, and the legacy containers still to come —
    /// overrides this with its own container-side ceiling
    /// (`arc.rs`'s `MAX_ARC_ENTRY_LEN`, 256 MiB), because for those the
    /// figure really does become a single allocation.
    ///
    /// **Declaring a ceiling here is the ONLY way a scanner refuses an
    /// entry for its size**, and that is the point: the refusal is then a
    /// [`SalvageStatus`] the engine assigns
    /// ([`UnverifiedCause::OverEntryCeiling`]), not a [`crate::Error`] the
    /// scanner raises, so it can never abort a run over one entry. A
    /// scanner that instead checks a size inside [`Self::verify`] and
    /// `?`-propagates the failure reintroduces the exact defect three fix
    /// rounds of Task 3c chased.
    ///
    /// **That is documented, not enforced, and saying so is more useful
    /// than claiming otherwise.** An earlier wording here called the defect
    /// "unrepresentable"; it is not. [`Self::verify`] still returns
    /// `Result` — it must, so a scanner CAN report a genuine run-level
    /// fault — so the wrong thing is still expressible. What changed is
    /// that the right thing now exists, costs one method, and is written
    /// into [`Self::verify`]'s contract below.
    fn max_whole_entry(&self) -> u64 {
        u64::MAX
    }

    /// Decide what was actually proven about a candidate's payload, after
    /// discovery — called once per candidate, in file order, by
    /// [`annotate_candidates`].
    ///
    /// # The contract on `Err`
    ///
    /// **`Err` here aborts the WHOLE run**, discarding every entry already
    /// recovered, so it is reserved for a fault that really is about the
    /// run and not about this one entry (the destination is gone, the
    /// source handle itself failed). Everything a single candidate can be
    /// wrong about — a short read, a bad checksum, a method this build
    /// cannot decode, a device error partway through one payload — is a
    /// [`SalvageStatus`], never an `Err`. `zip_salvage.rs`'s own
    /// `verify_candidate` has stated this in prose since Stage 1 and folds
    /// every one of those; ARC's did not, for one case (its size ceiling),
    /// and that single `?` cost three fix rounds. The size ceiling now
    /// belongs to [`Self::max_whole_entry`], which the engine applies, so
    /// there is nothing left for an implementation to `?` on.
    ///
    /// # What an implementation may assume
    ///
    /// The candidate's bounded length (`available_len` if the payload was
    /// truncated, else `declared_len`) is already **at or below**
    /// [`Self::max_whole_entry`] — [`annotate_candidates`] answers
    /// [`UnverifiedCause::OverEntryCeiling`] itself, without calling this,
    /// for anything above it. So an implementation that decodes whole may
    /// size a buffer from that length without re-checking it.
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
/// Every candidate's length is bounded against the run's entry ceiling
/// (`policy.max_entry`, narrowed by [`SalvageScan::max_whole_entry`])
/// **before** anything is sized from it — in [`annotate_candidates`], one
/// step before the only place that could size anything, and as a per-entry
/// [`UnverifiedCause::OverEntryCeiling`] rather than a [`crate::Error`] that ends
/// the run.
pub fn salvage_all(
    scan: &mut dyn SalvageScan,
    src: &mut dyn SeekRead,
    policy: &SalvagePolicy,
) -> Result<SalvageOutcome> {
    let candidates = collect_candidates(scan, src)?;
    annotate_candidates(&*scan, src, candidates, policy)
}

/// The resync loop alone: find a candidate, advance strictly past it,
/// repeat. Never reads a payload, never sizes anything from a declared
/// length, and never calls [`SalvageScan::verify`] — see
/// [`annotate_candidates`] for both the entry ceiling and the verification.
///
/// Exposed separately from [`salvage_all`] so a format that reconciles more
/// than one candidate source (zip's central-directory fallback) can collect
/// from each source before merging, and annotate the merged list once.
///
/// # The entry ceiling used to be enforced here, and was an `Err`
///
/// Salvage Stage 2 Task 3c's fix round 3 moved it to
/// [`annotate_candidates`] and turned it into a status. Two things were
/// wrong with it here, and only the second is obvious:
///
/// 1. **It refused a whole archive over one entry.** Measured at the CLI on
///    a 78-byte two-entry ARC, `stuffr salvage --list --max-entry 4`
///    printed no rows and exited 6 — the healthy first entry, which the
///    same binary recovers byte-for-byte at the default ceiling, simply
///    lost. That is the same defect the ARC scanner's own ceiling had, in
///    the engine rather than in a format.
/// 2. **It was one of two ceilings, checked in two places**, so which
///    disposition an over-ceiling entry got depended on which check saw it
///    first. There is now one rule, applied once, to both figures.
///
/// Nothing is weakened by the move: this loop sizes nothing from a declared
/// length (it only advances `from` by it), so "bounded before anything is
/// sized from it" holds exactly as before — the bound simply sits one
/// function later, still strictly before the only allocation there is.
pub fn collect_candidates(
    scan: &mut dyn SalvageScan,
    src: &mut dyn SeekRead,
) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::new();
    let mut from = 0u64;

    while let Some(candidate) = scan.next_candidate(src, from)? {
        // Advance strictly past this candidate so the scan always makes
        // progress — but NEVER by a length this candidate merely CLAIMED.
        // `available_len.is_some()` means the header's own declared length
        // disagreed with the file (there were fewer bytes left than it
        // said), and a header that lied about its size once cannot be
        // trusted to say how much of the source its "payload" consumed
        // either. This used to advance by `available_len` — the bytes
        // actually present, not the declared figure — on the reasoning that
        // a truncated entry has nothing worth finding after it anyway. That
        // is true for a genuinely truncated REAL last entry, but the
        // engine cannot tell that case apart from a coincidental
        // false-positive header sitting on top of noise with a garbage
        // multi-hundred-megabyte declared length: `available_len` is the
        // same "everything left in the file" figure either way. Salvage
        // Stage 2 Task 3's fix round 1 found exactly this — one
        // coincidental marker+name match in an ARC noise corpus, with a
        // declared length far past the file, jumped the scan straight to
        // EOF in one step and silently dropped every real entry that
        // happened to sit between it and the end of the file: no error, no
        // `Partial`, no note, in the one verb whose entire job is not
        // losing entries silently. So a truncated candidate now advances
        // minimally — past its own marker byte only — so the very next
        // byte onward is examined for another header. That costs a few
        // bytes of re-scanning after a genuinely truncated real entry
        // (which has nothing left to find anyway, so the outcome is
        // unchanged); it is the entire fix for a phantom, whose lie no
        // longer costs the rest of the archive. An UNTRUNCATED candidate's
        // declared length was just checked against the file two lines
        // above — it fits, so it is not a lie, and advancing by it is
        // unchanged.
        let advance = if candidate.available_len.is_some() {
            1
        } else {
            candidate.declared_len.unwrap_or(1).max(1)
        };
        from = candidate.offset.saturating_add(advance);

        candidates.push(candidate);
    }

    Ok(candidates)
}

/// Turns already-discovered candidates — in file order — into the bounded,
/// verified, shadow-annotated entries a caller receives. See this module's
/// doc comment for what the passes (bound, verify, shadow) mean and why
/// they live here rather than per-format.
///
/// # The entry ceiling, in one place (fix round 3, Task 3c)
///
/// `policy.max_entry` narrowed by [`SalvageScan::max_whole_entry`] is the
/// run's ceiling on ONE entry, and this is the only place it is applied. A
/// candidate whose bounded length (`available_len` if the payload is
/// truncated, else `declared_len`) is over it is reported
/// [`SalvageStatus::Unverified`]`(`[`UnverifiedCause::OverEntryCeiling`]`)`
/// and [`SalvageScan::verify`] is **not called for it at all** — so nothing
/// is read and nothing is allocated, which was the whole purpose of the two
/// `Err`-raising checks this replaced, without their cost: neither the
/// engine's own nor a scanner's could refuse one entry without ending the
/// run and discarding every entry already recovered.
///
/// The bounded length, never the declared one, is what is compared — the
/// rule [`Candidate::available_len`]'s own doc argues for and the reason a
/// truncated tail's garbage declaration cannot decide anything: a candidate
/// whose payload ran out can never cost more than the bytes that exist.
pub fn annotate_candidates(
    scan: &dyn SalvageScan,
    src: &mut dyn SeekRead,
    candidates: Vec<Candidate>,
    policy: &SalvagePolicy,
) -> Result<SalvageOutcome> {
    let ceiling = policy.max_entry.min(scan.max_whole_entry());
    let mut entries = Vec::with_capacity(candidates.len());
    // Earliest scan_position to report each distinct (name, declared_len,
    // verifier) triple seen so far — a candidate reporting one already in
    // here is shadowing that position. A degenerate zero-length checksum
    // (every empty file, every directory entry) is never pushed here and
    // never looked up here — see `is_degenerate` below.
    let mut seen: Vec<(String, Option<u64>, Verifier, usize)> = Vec::new();
    // Earliest scan_position to report each distinct NAME, regardless of
    // anything else about the record — the weaker, directly-observed fact
    // `SalvagedEntry::collides_with` reports, and the one `stuffr list`'s
    // own fidelity warning is about. Kept separate from `seen` above rather
    // than folded into it: that list is deliberately full of guards against
    // over-claiming a COPY (a verifier must exist, the declared length must
    // agree, a zero-length checksum never counts), and every one of them
    // would be wrong here, where nothing about content is being claimed.
    let mut names_seen: Vec<(String, usize)> = Vec::new();

    for (scan_position, candidate) in candidates.into_iter().enumerate() {
        // Bounded length, then the ceiling, then — only if it fits —
        // verification. `verify` is what reads and (for a whole-decoding
        // format) allocates, so refusing above it is refusing before the
        // allocation, which is the property the two `Err`s this replaced
        // existed for.
        let bounded_len = candidate.available_len.or(candidate.declared_len);
        let status = match bounded_len {
            Some(needed) if needed > ceiling => {
                SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling { needed, ceiling })
            }
            _ => scan.verify(src, &candidate)?,
        };

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

        // The two annotations are mutually exclusive: a record proven to be
        // a copy is reported as a shadow and nothing else, because "this is
        // a duplicate of #2" is strictly more informative than "something
        // earlier used this name". Everything else that repeats a name is a
        // collision.
        let earliest_with_name = names_seen
            .iter()
            .find(|(name, _)| *name == candidate.meta.name)
            .map(|&(_, position)| position);
        let collides_with = if shadows.is_some() {
            None
        } else {
            earliest_with_name
        };
        if earliest_with_name.is_none() {
            names_seen.push((candidate.meta.name.clone(), scan_position));
        }

        let marked_deleted = candidate.marked_deleted;
        entries.push(
            SalvagedEntry::new(
                scan_position,
                candidate.offset,
                candidate.payload_start,
                candidate.meta,
                status,
            )
            .with_shadows(shadows)
            .with_collides_with(collides_with)
            .with_marked_deleted(marked_deleted),
        );
    }

    Ok(SalvageOutcome { entries })
}

/// Streams `reader` into `out`, bounded to `expected_len` bytes — the
/// entry's own declared uncompressed size — so a small compressed input
/// cannot expand arbitrarily far past what its own header claims. Never
/// buffers a growable copy of the payload, only a fixed 64 KiB window, and
/// never trusts the decoder to stop on its own.
///
/// Returns `true` when exactly `expected_len` bytes were produced, `false`
/// when `reader` ran out or errored first — [`crate`]'s own convention
/// throughout this module: "did not fully recover" is a fact a caller
/// reports (as [`SalvageStatus::Partial`]'s own two causes already are),
/// never a [`crate::Error`] that aborts the whole run over one entry.
///
/// Lives here, rather than duplicated once per format module, because it
/// has no format-specific knowledge at all — only `Read`/`Write` and a byte
/// count. Task 3c moved it up from `entries.rs`, where it was zip-shaped
/// plumbing bolted onto a zip-only write path; every [`SalvageScan`]
/// implementation's own `write_payload` (zip's, ARC's, and any later
/// format's) calls this same function once it has a decoded reader in
/// hand, so a truncated or overrunning decode is reported identically
/// regardless of which format produced it.
pub fn stream_bounded_copy(
    mut reader: impl Read,
    expected_len: u64,
    out: &mut dyn Write,
) -> Result<bool> {
    let mut buf = [0u8; 64 * 1024];
    let mut produced = 0u64;
    loop {
        if produced >= expected_len {
            return Ok(true);
        }
        let want = ((expected_len - produced) as usize).min(buf.len());
        let n = match reader.read(&mut buf[..want]) {
            Ok(0) => return Ok(false),
            Ok(n) => n,
            Err(_) => return Ok(false),
        };
        out.write_all(&buf[..n])?;
        produced += n as u64;
    }
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
                payload_start: 0,
                meta: EntryMeta::file("absurd"),
                declared_len: Some(self.0),
                verifier: None,
                available_len: None,
                marked_deleted: false,
            }))
        }
    }

    /// A scanner reporting one candidate whose header DECLARES `declared`
    /// bytes while the source holds only `available` of them — the
    /// truncated-tail shape, the one a real scanner reports by setting
    /// [`Candidate::available_len`].
    struct DeclaresMoreThanIsThere {
        declared: u64,
        available: u64,
    }

    impl SalvageScan for DeclaresMoreThanIsThere {
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
                payload_start: 0,
                meta: EntryMeta::file("cut-short"),
                declared_len: Some(self.declared),
                verifier: Some(Verifier::Crc32(1)),
                available_len: Some(self.available),
                marked_deleted: false,
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
    /// oversized read, so this test fails if the read happens at all — not
    /// merely if the wrong status comes back. See this module's
    /// falsification note in the task report for what happens when the
    /// bound is moved below a read.
    ///
    /// Fix round 3 (Task 3c): the refusal is a per-entry STATUS now, not an
    /// `Err` — so this asserts both halves, that nothing was read AND that
    /// the run completed with the entry reported. The old assertion
    /// (`unwrap_err()`, exit 6) proved only the first and was satisfied by
    /// the behaviour that lost every other entry in the archive.
    #[test]
    fn an_absurd_declared_length_is_refused_before_the_allocation_it_would_size() {
        let mut scan = DeclaresLength(u64::MAX);
        let out = salvage_all(
            &mut scan,
            &mut panicking_reader(4096),
            &SalvagePolicy::default(),
        )
        .expect("an entry over the ceiling must not abort the run");
        assert_eq!(out.entries.len(), 1, "the entry is still reported");
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: u64::MAX,
                ceiling: MAX_SALVAGE_ENTRY,
            })
        );
    }

    /// The other half of the same rule, and the one the CLI reaches:
    /// everything AROUND an over-ceiling entry is still recovered. Measured
    /// before this fix as `stuffr salvage --list --max-entry 4` over a
    /// 78-byte ARC — no rows at all, exit 6.
    #[test]
    fn an_entry_over_the_ceiling_does_not_cost_the_entries_around_it() {
        struct TwoCandidates;
        impl SalvageScan for TwoCandidates {
            fn next_candidate(
                &mut self,
                _src: &mut dyn SeekRead,
                from: u64,
            ) -> Result<Option<Candidate>> {
                let (offset, len, name) = match from {
                    0 => (0u64, 16u64, "small-first"),
                    1..=16 => (17u64, 4096u64, "huge-second"),
                    _ => return Ok(None),
                };
                Ok(Some(Candidate {
                    offset,
                    payload_start: offset,
                    meta: EntryMeta::file(name),
                    declared_len: Some(len),
                    verifier: Some(Verifier::Crc32(len as u32)),
                    available_len: None,
                    marked_deleted: false,
                }))
            }
        }

        let out = salvage_all(
            &mut TwoCandidates,
            &mut bytes(&[0u8; 8192]),
            &SalvagePolicy {
                max_entry: 64,
                ..SalvagePolicy::default()
            },
        )
        .expect("one over-ceiling entry must never abort the run");
        assert_eq!(out.entries.len(), 2);
        assert_eq!(out.entries[0].status, SalvageStatus::Complete);
        assert_eq!(
            out.entries[1].status,
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: 4096,
                ceiling: 64,
            })
        );
    }

    /// A scanner's own [`SalvageScan::max_whole_entry`] narrows the policy's
    /// ceiling — the composition ARC relies on, proven against a mock so it
    /// does not depend on ARC's own 256 MiB constant. The candidate here is
    /// well under `policy.max_entry` and over the scanner's own figure, so
    /// only the `min` can refuse it; the panicking reader proves it is
    /// refused without being read.
    #[test]
    fn a_scanners_own_whole_entry_ceiling_narrows_the_policys() {
        struct DecodesWhole;
        impl SalvageScan for DecodesWhole {
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
                    payload_start: 0,
                    meta: EntryMeta::file("whole"),
                    declared_len: Some(2048),
                    verifier: Some(Verifier::Crc32(7)),
                    available_len: None,
                    marked_deleted: false,
                }))
            }
            fn max_whole_entry(&self) -> u64 {
                1024
            }
            fn verify(&self, _src: &mut dyn SeekRead, _c: &Candidate) -> Result<SalvageStatus> {
                panic!("verify must not run for a candidate over the ceiling");
            }
        }

        let out = salvage_all(
            &mut DecodesWhole,
            &mut panicking_reader(4096),
            &SalvagePolicy::default(),
        )
        .expect("a scanner ceiling is a per-entry refusal, not a run failure");
        assert_eq!(
            out.entries[0].status,
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: 2048,
                // The SCANNER's figure, not the policy's 4 GiB — the `min`
                // is what this test is really pinning.
                ceiling: 1024,
            })
        );
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
        assert_eq!(entry.collides_with, None);
    }

    /// A truncated candidate is COLLECTED, not dropped — the whole point of
    /// [`Candidate::available_len`]. Before it existed, `zip_salvage.rs`
    /// refused such a candidate outright and a truncated archive's last
    /// entry vanished with no row, no note and exit 0.
    #[test]
    fn a_candidate_whose_payload_ran_out_is_still_collected() {
        let mut scan = DeclaresMoreThanIsThere {
            declared: 4000,
            available: 1950,
        };
        let out = salvage_all(
            &mut scan,
            &mut panicking_reader(4096),
            &SalvagePolicy::default(),
        )
        .unwrap();
        assert_eq!(
            out.entries.len(),
            1,
            "a header found but not completable is a fact worth reporting"
        );
    }

    /// The ceiling is checked against what could be READ, not against what
    /// a truncated header CLAIMED. Otherwise a garbage length in a tail the
    /// scan has already established is not there would abort the entire run
    /// at exit 6 — losing every earlier entry over an absent one, in the
    /// verb that exists to rescue exactly that archive.
    #[test]
    fn a_truncated_candidate_is_bounded_by_what_is_there_not_by_what_it_claimed() {
        let mut scan = DeclaresMoreThanIsThere {
            declared: u64::MAX,
            available: 2048,
        };
        let out = salvage_all(
            &mut scan,
            &mut panicking_reader(4096),
            &SalvagePolicy::default(),
        )
        .expect("an absent tail must not abort a run that recovered real entries");
        assert_eq!(out.entries.len(), 1);
    }

    /// The complement, so the rule above cannot be read as "truncated
    /// candidates are never bounded": what IS there is still bounded, and a
    /// truncated candidate holding more available bytes than the ceiling
    /// allows is refused exactly as an untruncated one would be — reported
    /// [`UnverifiedCause::OverEntryCeiling`], never read (the reader
    /// panics if it is), and never allowed to end the run.
    #[test]
    fn a_truncated_candidate_whose_available_bytes_exceed_the_ceiling_is_refused() {
        let mut scan = DeclaresMoreThanIsThere {
            declared: u64::MAX,
            available: 4096,
        };
        let out = salvage_all(
            &mut scan,
            &mut panicking_reader(4096),
            &SalvagePolicy {
                max_entry: 1024,
                ..SalvagePolicy::default()
            },
        )
        .expect("a bounded refusal is per-entry, never a run failure");
        assert_eq!(
            out.entries[0].status,
            // `needed` is 4096 — the bytes that ARE there — never the
            // `u64::MAX` this candidate's header declared. Fix round 4
            // (NEW-F): the figures a user is shown are the ones the
            // comparison used.
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: 4096,
                ceiling: 1024,
            }),
            "an over-ceiling entry is unverified, not truncated: nobody read it"
        );
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
                payload_start: offset,
                meta: EntryMeta::file(name),
                declared_len,
                verifier,
                available_len: None,
                marked_deleted: false,
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
        assert_eq!(
            out.entries[1].collides_with,
            Some(0),
            "the NAME still repeats, and that is a directly observed fact no checksum \
             guard applies to"
        );
    }

    // -----------------------------------------------------------------
    // Name collisions: the second annotation, separate from shadowing.
    // -----------------------------------------------------------------

    /// The finding this annotation closes: two records under one name whose
    /// content does NOT agree are what `stuffr list` calls shadowed, and
    /// what salvage marked in no way at all — because its own `shadows`
    /// means something stricter.
    #[test]
    fn a_repeated_name_with_different_content_is_reported_as_a_collision() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (
                    "dup.txt",
                    Some(21),
                    Some(Verifier::Crc32(7)),
                    SalvageStatus::Intact,
                ),
                (
                    "other.txt",
                    Some(21),
                    Some(Verifier::Crc32(9)),
                    SalvageStatus::Intact,
                ),
                (
                    "dup.txt",
                    Some(21),
                    Some(Verifier::Crc32(11)),
                    SalvageStatus::Intact,
                ),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(out.entries[2].shadows, None, "the content does not agree");
        assert_eq!(
            out.entries[2].collides_with,
            Some(0),
            "but the name does, and that is the fact `list` warns about"
        );
        assert_eq!(out.entries[0].collides_with, None);
        assert_eq!(out.entries[1].collides_with, None);
    }

    /// The two annotations are mutually exclusive: a record PROVEN to be a
    /// copy says so, and does not also report the weaker fact. Reporting
    /// both would make every shadow print two markers for one relationship.
    #[test]
    fn a_proven_shadow_is_not_also_reported_as_a_name_collision() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (
                    "dup.txt",
                    Some(21),
                    Some(Verifier::Crc32(7)),
                    SalvageStatus::Intact,
                ),
                (
                    "dup.txt",
                    Some(21),
                    Some(Verifier::Crc32(7)),
                    SalvageStatus::Intact,
                ),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(out.entries[1].shadows, Some(0));
        assert_eq!(out.entries[1].collides_with, None);
    }

    /// A third record under a name two earlier ones already used points at
    /// the EARLIEST of them, the same rule `shadows` follows — so a chain of
    /// collisions names one origin rather than each pointing at its
    /// predecessor.
    #[test]
    fn a_third_record_under_one_name_names_the_earliest_position() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                (
                    "dup",
                    Some(4),
                    Some(Verifier::Crc32(1)),
                    SalvageStatus::Intact,
                ),
                (
                    "dup",
                    Some(4),
                    Some(Verifier::Crc32(2)),
                    SalvageStatus::Intact,
                ),
                (
                    "dup",
                    Some(4),
                    Some(Verifier::Crc32(3)),
                    SalvageStatus::Intact,
                ),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(out.entries[1].collides_with, Some(0));
        assert_eq!(out.entries[2].collides_with, Some(0));
    }

    /// The negative double: distinct names must never be marked, however
    /// much else they share. Without this, an annotation that fired on
    /// everything would pass every test above.
    #[test]
    fn distinct_names_are_never_reported_as_colliding() {
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
        assert_eq!(out.entries[0].collides_with, None);
        assert_eq!(out.entries[1].collides_with, None);
    }

    /// A collision needs no verifier at all, unlike a shadow. A format with
    /// no checksum (tar, cpio, ar — and a zip data-descriptor entry) can
    /// still repeat a name, and that repetition is exactly as real there.
    #[test]
    fn a_repeated_name_collides_even_with_no_verifier_to_compare() {
        let mut scan = ScriptedCandidates {
            plan: vec![
                ("same", Some(4), None, SalvageStatus::Complete),
                ("same", Some(4), None, SalvageStatus::Complete),
            ],
            next: 0,
        };
        let out = salvage_all(&mut scan, &mut bytes(&[0u8; 16]), &SalvagePolicy::default())
            .expect("scripted candidates must annotate cleanly");
        assert_eq!(
            out.entries[1].shadows, None,
            "no verifier, so nothing proves they are copies"
        );
        assert_eq!(
            out.entries[1].collides_with,
            Some(0),
            "but the name repeats, which needs no verifier to observe"
        );
    }

    /// Ruling S-I. `Candidate` is `#[non_exhaustive]`, so an out-of-crate
    /// scanner reaches it only through `new` plus the `with_*` setters —
    /// which means the DEFAULTS are now public API, not an implementation
    /// detail of six struct literals. Each of the four must assert the
    /// least: nothing declared, nothing to verify with, nothing missing,
    /// nothing deleted.
    #[test]
    fn a_new_candidate_claims_nothing_it_was_not_told() {
        let c = Candidate::new(7, 42, EntryMeta::file("probe"));
        assert_eq!(c.offset, 7);
        assert_eq!(c.payload_start, 42);
        assert_eq!(c.declared_len, None, "no length was declared");
        assert_eq!(c.verifier, None, "nothing can prove the content");
        assert_eq!(
            c.available_len, None,
            "a shortfall is MEASURED, never assumed"
        );
        assert!(!c.marked_deleted, "no record is deleted until one says so");
    }

    /// The four setters are the only route to those fields from another
    /// crate, so each one is pinned rather than trusted to the compiler.
    #[test]
    fn each_candidate_setter_reaches_its_own_field() {
        let c = Candidate::new(0, 0, EntryMeta::file("probe"))
            .with_declared_len(Some(9))
            .with_verifier(Some(Verifier::Crc16(0xbeef)))
            .with_available_len(Some(4))
            .with_marked_deleted(true);
        assert_eq!(c.declared_len, Some(9));
        assert_eq!(c.verifier, Some(Verifier::Crc16(0xbeef)));
        assert_eq!(c.available_len, Some(4));
        assert!(c.marked_deleted);
    }

    /// Same ruling, same reason, for the type every per-format
    /// `write_payload` test builds directly. Its three defaults are the
    /// annotations `annotate_candidates` adds, so an entry built by hand
    /// must carry none of them.
    #[test]
    fn a_new_salvaged_entry_carries_no_annotations() {
        let e = SalvagedEntry::new(3, 7, 42, EntryMeta::file("probe"), SalvageStatus::Complete);
        assert_eq!(e.scan_position, 3);
        assert_eq!(e.offset, 7);
        assert_eq!(e.payload_start, 42);
        assert_eq!(e.status, SalvageStatus::Complete);
        assert_eq!(e.shadows, None);
        assert_eq!(e.collides_with, None);
        assert!(!e.marked_deleted);

        let annotated = SalvagedEntry::new(0, 0, 0, EntryMeta::file("p"), SalvageStatus::Intact)
            .with_shadows(Some(1))
            .with_collides_with(Some(2))
            .with_marked_deleted(true);
        assert_eq!(annotated.shadows, Some(1));
        assert_eq!(annotated.collides_with, Some(2));
        assert!(annotated.marked_deleted);
    }
}
