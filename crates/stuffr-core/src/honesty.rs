//! Invariants a decoder must satisfy on ANY input, hostile included.
//!
//! These live here rather than inside a fuzz target for one reason: a fuzz
//! target's checks cannot be unit-tested, so invariants written there are
//! indistinguishable from vacuous ones — and "ran 30 seconds, found nothing"
//! looks identical either way. Here each one has a broken double proving it
//! can fail, exactly as `conformance.rs`'s `broken_codecs` does.

pub use crate::salvage::Attestation;
use crate::salvage::SalvageStatus;
use crate::{EntryKind, Error, Fidelity, FidelityReport};

/// Hostile bytes may be refused, but never as an internal error.
///
/// `Error::exit_code`'s `_ => 1` wildcard means "stuffr failed". Anything
/// reaching it for a *bad input* is a misclassification: the input is the
/// problem, not the program. This guards the wildcard that has produced five
/// wrong exit codes in this project (`ChainTooDeep`, `EntryNotFound`,
/// `Unsupported`, the `UnknownFormat`/`AmbiguousFormat` pair, and
/// `NotSeekable` — the fifth, found by this very oracle before the fuzzer had
/// run once — each fixed after the fact).
///
/// It also applies [`check_display_has_no_raw_controls`] to the error's
/// rendering, so every call site in every fuzz target checks that an error
/// naming hostile bytes does not carry them raw to a terminal.
pub fn check_error_is_classified(e: &Error) -> Result<(), String> {
    match e.exit_code() {
        1 => Err(format!(
            "a decoder raised {e:?}, which maps to exit code 1 — that means \
             stuffr failed, not that the input was bad"
        )),
        _ => check_display_has_no_raw_controls(&e.to_string()),
    }
}

/// A rendered `Error` or `Fidelity` message never carries a raw control or
/// bidi character — the classes `display::fmt_name` escapes: C0
/// (U+0000–U+001F), DEL, C1 (U+0080–U+009F), and the bidi overrides
/// U+202A–U+202E and U+2066–U+2069.
///
/// An archive member's name is attacker-controlled and ends up inside
/// messages; a raw ESC or U+202E in one is terminal injection or a spoofed
/// line. Apply it to ONE rendered message, never to multi-line CLI output
/// (whose newlines are legitimate). `Err` names the first offender's
/// codepoint.
pub fn check_display_has_no_raw_controls(rendered: &str) -> Result<(), String> {
    match rendered.chars().find(|c| {
        matches!(*c,
            '\u{0000}'..='\u{001F}'
            | '\u{007F}'
            | '\u{0080}'..='\u{009F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}')
    }) {
        Some(c) => Err(format!(
            "a rendered message carries the raw control character U+{:04X}: {rendered:?}",
            c as u32
        )),
        None => Ok(()),
    }
}

/// A header that declares *n* bytes must deliver exactly *n* — **unless the
/// entry is a symlink**, whose payload its container consumed before the
/// caller ever saw it.
///
/// The exemption is not a softening of the invariant; without it the oracle
/// is simply wrong. A symlink's target IS its payload in both `zip` and
/// `cpio`, so both read it eagerly while the entry is still in hand, put it
/// in `EntryKind::Symlink { target }`, and hand the caller `io::empty()` —
/// with `EntryMeta::size` still carrying the declared target length, because
/// that is what the header said. Declared 8, produced 0, by design, on every
/// symlink in every archive this project writes. Measured: `stuffr pack tree
/// -o t.zip` over a directory holding one symlink, fed to the `container`
/// fuzz target, aborted with `entry "tree/link.txt" declared 8 bytes but
/// produced 0` — a legitimate archive stuffr had just written moments
/// earlier. An oracle that fires there cries wolf on the first valid archive
/// the corpus generator produces and buries every real finding behind it.
///
/// Nothing is lost by the exemption, which is the reason it is safe to make:
/// the eager read is the one place a truncated target COULD hide, and both
/// containers already check it there themselves — `zip.rs`'s and `cpio.rs`'s
/// `read_symlink_target` each raise [`Error::Corrupt`] when the payload runs
/// short of the declared length, before an `Entry` is ever handed back. The
/// check is not skipped; it has already happened.
///
/// A **`Hardlink`** is exempt for a different reason, stated by
/// [`EntryKind::Hardlink`] itself: its reader yields no bytes while
/// `EntryMeta::size` carries the SHARED content's size (cpio's data-last
/// group reports every name at the group's size; the name that holds the
/// bytes is the target). Declared 14, produced 0, by design. The fuzz
/// `container` target aborted on the first newc link-group seed for exactly
/// this until the exemption existed (0.10.0 Task 10). The link's bytes are
/// checked where they are read: on the target entry.
///
/// Every other kind stays in scope, `Dir` and `Other` included: a directory
/// entry declares zero and delivers zero, and an entry that cannot say what
/// it is has no eager-read convention to stand on.
///
/// # The exemption is keyed on the KIND, and is therefore wider than its reason
///
/// The justification above is specific to `zip` and `cpio`, the two
/// containers that consume a symlink's payload eagerly. `tar` does not: it
/// reports `EntryKind::Symlink` from its typeflag byte (`tar.rs`'s
/// `entry_kind`) while leaving the payload alone, and `ar` has no symlink
/// concept at all. So this `matches!` also disables the oracle for a tar
/// symlink entry, where "the container ate the payload" is simply not what
/// happened. That is an over-reach, not a considered scope — do not read the
/// exemption as evidence that tar symlinks were excluded on purpose.
///
/// It is tolerated rather than narrowed because nothing is currently lost by
/// it: `tar.rs`'s own `EntryPayload` raises [`Error::Corrupt`] for a symlink
/// payload shorter than its header declares, so a fuzz target meeting a
/// truncated tar symlink takes the error branch and never reaches this check
/// — the same "already checked, one layer down" argument the zip/cpio case
/// rests on, arrived at by accident rather than by design. Narrowing this to
/// "the container consumed the payload" would mean carrying that fact on the
/// `Entry` itself, which is a container-API change for no behaviour change
/// today. If a container is ever added that reports `Symlink` AND does not
/// check its own payload length, this is the line that must be narrowed
/// first.
pub fn check_entry_size(
    declared: Option<u64>,
    produced: u64,
    name: &str,
    kind: &EntryKind,
) -> Result<(), String> {
    if matches!(kind, EntryKind::Symlink { .. } | EntryKind::Hardlink { .. }) {
        return Ok(());
    }
    match declared {
        Some(d) if d != produced => Err(format!(
            "entry {name:?} declared {d} bytes but produced {produced}"
        )),
        _ => Ok(()),
    }
}

/// An index that states a total must be reachable in full — **or the shortfall
/// must be declared**.
///
/// The invariant is the conjunction, not the mismatch alone. A mismatch on its
/// own is a *supported outcome*: the project chose to raise
/// [`Fidelity::EntryCountMismatch`] rather than recover, so a zip whose index
/// claims 8 records while 6 are reachable returns those 6 plus a warning, and
/// `--strict-fidelity` turns that warning into exit 4. A fuzzer builds such a
/// zip within minutes, so an oracle firing on the mismatch alone would cry
/// wolf on every one of them and drown the real finding.
///
/// What is never acceptable is the mismatch reported as clean — the Notion.zip
/// bug: 8 declared, 6 enumerated, and a fidelity report that mentions neither.
/// So `report` is consulted for [`Fidelity::EntryCountMismatch`], and only its
/// absence makes a mismatch a violation.
///
/// **Counts are `usize`, but [`Fidelity::EntryCountMismatch`] carries `u64`.**
/// Callers converting from `u64` must **saturate**
/// (`usize::try_from(n).unwrap_or(usize::MAX)`), never cast: `as usize` on a
/// 32-bit target truncates, and a header declaring `2^32 + 6` would then
/// compare equal to 6 entries and pass this check silently.
pub fn check_entry_count(
    declared: Option<usize>,
    enumerated: usize,
    report: &FidelityReport,
) -> Result<(), String> {
    let Some(d) = declared else { return Ok(()) };
    if d == enumerated {
        return Ok(());
    }
    if report
        .warnings
        .iter()
        .any(|w| matches!(w, Fidelity::EntryCountMismatch { .. }))
    {
        return Ok(());
    }
    Err(format!(
        "the index declares {d} entries but {enumerated} were enumerated, and the \
         fidelity report does not carry an EntryCountMismatch warning saying so"
    ))
}

/// `Rung::Exact` with no warnings is a claim that nothing was approximated.
///
/// **`approximated` must be an independent observation, derived by the caller
/// from the same facts [`check_entry_size`] and [`check_entry_count`] consume**
/// — a short entry, an unreachable index record, a dropped attribute. Passing
/// `report.has_warnings()` makes this a tautology that cannot fail, and
/// passing a constant `false` disables the invariant outright, in both cases
/// silently: the check still runs, still returns `Ok`, and a target built on
/// either is indistinguishable from one that works.
pub fn check_fidelity_claim(report: &FidelityReport, approximated: bool) -> Result<(), String> {
    if report.is_lossless() && approximated {
        return Err(format!(
            "the report claims nothing was approximated ({:?}, no warnings) \
             but something was",
            report.rung
        ));
    }
    Ok(())
}

/// A conversion carries every entry its source reader enumerated — **or
/// names the one it left behind**.
///
/// `source` is what an independent walk of the source enumerated; `written`
/// is what a reader of the conversion's OUTPUT enumerated; `report` is the
/// conversion's own fidelity report. A name absent from `written` is a
/// supported outcome only when the report says why: a target with no shape
/// for the entry's kind (a directory in `ar`, a symlink, a device or fifo)
/// skips it with [`Fidelity::EntrySkipped`], as does a target whose names
/// cannot hold a NUL (`ContainerCaps::nul_in_names`), and a `unique_names`
/// target for every later entry of a repeated name. What is never acceptable
/// is an entry that silently fails to arrive.
///
/// **Matched by name, never by count.** `FidelityReport::merge` de-duplicates
/// identical warnings, so two skipped entries of one name leave ONE warning;
/// and a `unique_names` target legitimately holds a repeated name once. A
/// count comparison would cry wolf on both, so this asks only "did every name
/// either arrive or get named".
pub fn check_entries_carried(
    source: &[String],
    written: &[String],
    report: &FidelityReport,
) -> Result<(), String> {
    let arrived: std::collections::HashSet<&str> = written.iter().map(String::as_str).collect();
    let skipped: std::collections::HashSet<&str> = report
        .warnings
        .iter()
        .filter_map(|w| match w {
            Fidelity::EntrySkipped { entry, .. } | Fidelity::EncryptedEntrySkipped { entry } => {
                Some(entry.as_str())
            }
            _ => None,
        })
        .collect();
    match source
        .iter()
        .find(|n| !arrived.contains(n.as_str()) && !skipped.contains(n.as_str()))
    {
        Some(missing) => Err(format!(
            "the source held entry {missing:?}, the converted archive does not, and \
             the fidelity report names no skip for it"
        )),
        None => Ok(()),
    }
}

/// Never report a status that claims more evidence than the format offers
/// or the scan actually gathered.
///
/// This lives in the library rather than inside the fuzz target because a
/// fuzz target's own checks cannot be unit-tested, so a harness that runs
/// clean is indistinguishable from one whose invariants are vacuous — the
/// same reason the five checks above it live here.
///
/// # The two inputs
///
/// `attestation` is the FORMAT's class of evidence (see [`Attestation`]); it
/// is a per-format constant, never a per-candidate observation.
/// `verifier_was_checked` is whether that evidence was actually compared for
/// THIS candidate — the content checksum for [`Attestation::ContentChecksum`],
/// the header checksum for [`Attestation::HeaderChecksumOnly`], and
/// necessarily `false` for [`Attestation::Nothing`], which has nothing to
/// compare.
///
/// # The rules — each claim-bearing tier belongs to exactly one class
///
/// * [`SalvageStatus::Intact`] ⇔ `ContentChecksum` and checked. "A checksum
///   the original writer computed agrees" needs a content checksum to exist
///   and a comparison to have run. The `!verifier_was_checked` refusal is
///   this function's original Stage 1 invariant, unchanged.
/// * [`SalvageStatus::Complete`] ⇔ `HeaderChecksumOnly` and checked. Refused
///   for `Nothing` (cpio/ar asserting a header self-check they do not have
///   — the refusal Salvage Stage 3 exists for), and refused for
///   `ContentChecksum` whatever `verifier_was_checked` says: checked and
///   agreed is `Intact`, checked and disagreed is `Partial`, unchecked is
///   `Unverified`. `Complete` is never the honest answer for a format that
///   carries a content checksum, which is what the variant's own doc has
///   always said and what the one-bool oracle could not deliver.
/// * [`SalvageStatus::Unattested`] ⇔ `Nothing` and NOT checked. A format
///   that offers an attestation never reaches this tier; and "checked a
///   verifier the format does not have" is incoherent, refused here for the
///   same reason the `Intact` arm refuses it.
/// * [`SalvageStatus::Unverified`] and [`SalvageStatus::Partial`] are
///   unconstrained, and must stay so. The engine itself assigns
///   `Unverified(OverEntryCeiling)` to a candidate of ANY format, `cpio`
///   included, before a scanner is ever asked; and `Partial` folds a
///   comparison that never ran (truncation, a failed decode) with one that
///   ran and disagreed, so neither value of `verifier_was_checked` can be
///   refused for it — `stuffr::entries::PartialCause` separates those one
///   layer up, from a second decode.
///
/// Every cell of the 5 × 2 × 3 table is therefore either the one honest
/// tier for its class or refused, and
/// `the_whole_truth_table_permits_exactly_one_claim_per_class` pins it.
pub fn check_salvage_claim(
    status: &SalvageStatus,
    verifier_was_checked: bool,
    attestation: Attestation,
) -> Result<(), String> {
    match status {
        SalvageStatus::Intact => match attestation {
            Attestation::ContentChecksum if verifier_was_checked => Ok(()),
            Attestation::ContentChecksum => {
                Err("reported Intact without checking a checksum".into())
            }
            Attestation::HeaderChecksumOnly => Err(
                "reported Intact — a content checksum agreed — for a format whose only \
                 checksum covers the header; Complete is that format's tier"
                    .into(),
            ),
            Attestation::Nothing => Err(
                "reported Intact — a checksum agreed — for a format that offers nothing to \
                 check against"
                    .into(),
            ),
        },
        SalvageStatus::Complete => match attestation {
            Attestation::HeaderChecksumOnly if verifier_was_checked => Ok(()),
            Attestation::HeaderChecksumOnly => Err(
                "reported Complete without checking the header checksum this format offers; \
                 Unverified is the honest answer when it was not used"
                    .into(),
            ),
            Attestation::ContentChecksum => Err(
                "reported Complete for a format that carries a content checksum; the honest \
                 answer is Intact if it agreed, Partial if it did not, Unverified if it was \
                 never compared"
                    .into(),
            ),
            Attestation::Nothing => Err(
                "reported Complete — every declared byte present and the header \
                 self-verified — for a format with no checksum and no self-verifying header; \
                 Unattested is that format's tier"
                    .into(),
            ),
        },
        SalvageStatus::Unattested => match attestation {
            Attestation::Nothing if !verifier_was_checked => Ok(()),
            Attestation::Nothing => Err(
                "reported Unattested while claiming a verifier was checked, for a format \
                 that has none to check"
                    .into(),
            ),
            Attestation::ContentChecksum | Attestation::HeaderChecksumOnly => Err(
                "reported Unattested — nothing attests this is an entry — for a format that \
                 does offer an attestation"
                    .into(),
            ),
        },
        SalvageStatus::Unverified(_) | SalvageStatus::Partial => Ok(()),
    }
}

#[cfg(test)]
mod broken_honesty {
    use super::*;
    use crate::Error;
    use crate::fidelity::Rung;

    #[test]
    fn an_io_error_from_hostile_bytes_is_refused_because_it_exits_one() {
        // `Error::Io` falls through `exit_code`'s `_ => 1` wildcard, which
        // means "stuffr failed", not "your input was bad". Five wrong exit
        // codes in this project came through that wildcard — the fifth,
        // `NotSeekable`, found by this very oracle before the fuzzer had run
        // once. `Io` is the one variant that belongs there: an i/o failure
        // really is stuffr's problem, so raising it for hostile *bytes* is
        // the misclassification, which is what property 9 exists to prevent.
        let e = Error::Io(std::io::Error::other("boom"));
        let msg = check_error_is_classified(&e).expect_err("exit 1 must be refused");
        assert!(
            msg.contains("exit code 1"),
            "the failure must name why: {msg}"
        );
    }

    #[test]
    fn corrupt_unsupported_and_resource_limit_are_all_permitted() {
        // A memory-limit refusal is ResourceLimit (exit 6), NOT Corrupt — the
        // file is not damaged, this build will not allocate that much. An
        // oracle demanding Corrupt would be wrong.
        //
        // This is the only test here guarding against an OVER-strict oracle,
        // so neutering `check_error_is_classified` to `Ok(())` makes it pass
        // harder rather than fail. Its falsification is the opposite edit —
        // flipping the match to `_ => Err(..)` — and that has been run and
        // observed red; see the task report.
        //
        // `NotSeekable` is in this set deliberately: it is the mandated reply
        // to `by_index` on a forward-only source, which is what every read
        // from a pipe is, so an oracle refusing it would fire on the first
        // valid tar the fuzzer built. It is permitted because `error.rs` now
        // files it as exit 3 — a capability limit — not because this set
        // carves out an exception.
        for e in [
            Error::Corrupt("bad".into()),
            Error::Unsupported("nope".into()),
            Error::ResourceLimit("too big".into()),
            Error::NotSeekable {
                format: crate::FormatId::new("zip"),
            },
        ] {
            assert!(
                check_error_is_classified(&e).is_ok(),
                "{e:?} must be permitted"
            );
        }
    }

    #[test]
    fn a_declared_size_that_disagrees_with_bytes_produced_is_refused() {
        let msg = check_entry_size(Some(100), 42, "a.txt", &EntryKind::File)
            .expect_err("mismatch must fail");
        assert!(msg.contains("a.txt"), "must name the entry: {msg}");
        assert!(
            msg.contains("100") && msg.contains("42"),
            "must name both numbers: {msg}"
        );
        // An undeclared size cannot disagree with anything.
        assert!(check_entry_size(None, 42, "a.txt", &EntryKind::File).is_ok());
        assert!(check_entry_size(Some(42), 42, "a.txt", &EntryKind::File).is_ok());
        // And the exemption below is specific to symlinks, not to "any kind
        // that is not a file": a directory or an unclassifiable entry
        // declaring bytes it does not deliver is still a violation.
        for kind in [EntryKind::Dir, EntryKind::Other] {
            assert!(
                check_entry_size(Some(100), 42, "a.txt", &kind).is_err(),
                "{kind:?} must stay in scope"
            );
        }
    }

    #[test]
    fn a_symlink_whose_target_was_consumed_eagerly_is_permitted() {
        // `zip.rs` and `cpio.rs` both read a symlink's target out of its
        // payload while the entry is in hand and hand the caller
        // `io::empty()` afterwards, `EntryMeta::size` still carrying the
        // declared target length. Declared 8, produced 0, on every symlink in
        // every archive this project writes — a passing outcome by design.
        //
        // This is an OVER-strictness guard, so neutering `check_entry_size`
        // to `Ok(())` makes it pass harder rather than fail. Its falsification
        // is the opposite edit — deleting the `EntryKind::Symlink` arm — and
        // that has been made and observed red; see the task report. The
        // sibling test above is what reddens under the neutering edit.
        let link = EntryKind::Symlink {
            target: "real.txt".into(),
        };
        assert!(
            check_entry_size(Some(8), 0, "link.txt", &link).is_ok(),
            "a symlink's target is read by the container, not by the caller"
        );
    }

    #[test]
    fn a_declared_count_that_disagrees_with_entries_enumerated_is_refused() {
        // The Notion.zip bug: 8 records declared, 6 enumerated, reported as
        // exact fidelity. The silent report is the whole violation — see the
        // sibling test below for the same mismatch declared honestly.
        let silent = FidelityReport::new(Rung::Exact);
        let msg = check_entry_count(Some(8), 6, &silent).expect_err("mismatch must fail");
        assert!(
            msg.contains("8") && msg.contains("6"),
            "must name both: {msg}"
        );
        assert!(check_entry_count(None, 6, &silent).is_ok());
        assert!(check_entry_count(Some(6), 6, &silent).is_ok());
    }

    #[test]
    fn a_declared_count_mismatch_the_report_owns_up_to_is_permitted() {
        // `Fidelity::EntryCountMismatch` exists for exactly this, and the
        // project chose to RAISE it rather than recover: the read returns the
        // 6 reachable entries plus a warning, and `--strict-fidelity` makes
        // that exit 4. A passing outcome by design — and one a fuzzer
        // produces within minutes, so an oracle firing here would cry wolf on
        // every such zip and bury the real finding.
        //
        // The other over-strictness guard in this module — but, unlike
        // `corrupt_unsupported_and_resource_limit_are_all_permitted`, NOT
        // immune to neutering: this test's first assertion guards against
        // over-strictness (a shortfall the report owns up to must be
        // permitted) and is falsified by deleting the `EntryCountMismatch`
        // arm from `check_entry_count`, but its second assertion below (the
        // unrelated-warning check) still requires the function to REFUSE an
        // undeclared shortfall, so neutering it to `Ok(())` reddens that
        // assertion instead. Both edits have been made and observed red.
        let mut declared = FidelityReport::new(Rung::Exact);
        declared.warn(Fidelity::EntryCountMismatch {
            format: crate::FormatId::new("zip"),
            declared: 8,
            enumerated: 6,
            reason: "records sharing a name collapse into one".into(),
        });
        assert!(
            check_entry_count(Some(8), 6, &declared).is_ok(),
            "a shortfall the report owns up to is a supported outcome, not a violation"
        );
        // And the guard is specific to that warning, not to "any warning at
        // all": an unrelated note must not launder a silent shortfall.
        let mut unrelated = FidelityReport::new(Rung::Exact);
        unrelated.warn(Fidelity::MetadataIncomplete {
            entry: "a.txt".into(),
            fields: crate::MetaFields::default(),
        });
        assert!(
            check_entry_count(Some(8), 6, &unrelated).is_err(),
            "an unrelated warning does not declare a count shortfall"
        );
    }

    #[test]
    fn claiming_exact_with_no_warnings_while_approximating_is_refused() {
        let clean = FidelityReport::new(Rung::Exact);
        let msg = check_fidelity_claim(&clean, true).expect_err("a false claim must fail");
        assert!(
            msg.contains("approximated"),
            "must say what was claimed: {msg}"
        );
        assert!(check_fidelity_claim(&clean, false).is_ok());
    }

    #[test]
    fn an_entry_a_conversion_drops_silently_is_refused() {
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let clean = FidelityReport::new(Rung::Exact);
        let msg = check_entries_carried(&names(&["a", "b"]), &names(&["a"]), &clean)
            .expect_err("a dropped entry must fail");
        assert!(msg.contains("\"b\""), "must name the entry: {msg}");
        // A warning about a DIFFERENT entry does not launder the drop.
        let mut other = FidelityReport::new(Rung::Exact);
        other.warn(Fidelity::EntrySkipped {
            entry: "c".into(),
            reason: "special".into(),
        });
        assert!(check_entries_carried(&names(&["a", "b"]), &names(&["a"]), &other).is_err());
        assert!(check_entries_carried(&names(&["a", "b"]), &names(&["b", "a"]), &clean).is_ok());
    }

    #[test]
    fn an_entry_a_conversion_skips_and_names_is_permitted() {
        // Over-strictness guard. Neutering `check_entries_carried` to
        // `Ok(())` leaves this test GREEN — it cannot catch a vacuous
        // oracle; its sibling above does. It is falsified only by
        // over-strict behaviour: refusing a name a skip warning covers, or
        // matching on counts (two entries of one name, one arriving and ONE
        // merged warning, is a `unique_names` target's ordinary output).
        // Observed red under the first of those edits.
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut skipped = FidelityReport::new(Rung::Exact);
        skipped.warn(Fidelity::EntrySkipped {
            entry: "dir/".into(),
            reason: "no directory entries".into(),
        });
        assert!(
            check_entries_carried(&names(&["dir/", "x", "x"]), &names(&["x"]), &skipped).is_ok()
        );
        let mut encrypted = FidelityReport::new(Rung::Exact);
        encrypted.warn(Fidelity::EncryptedEntrySkipped {
            entry: "secret".into(),
        });
        assert!(check_entries_carried(&names(&["secret"]), &[], &encrypted).is_ok());
    }

    #[test]
    fn a_hardlink_declaring_the_shared_size_but_reading_empty_is_permitted() {
        // Over-strictness guard: the oracle must not fire on a cpio group's
        // links, whose size is the shared content's and whose reader is empty.
        let link = EntryKind::Hardlink {
            target: "grp/c".into(),
        };
        assert!(check_entry_size(Some(14), 0, "grp/a", &link).is_ok());
        // ... while a plain file declaring 14 and producing 0 is still refused.
        assert!(check_entry_size(Some(14), 0, "grp/a", &EntryKind::File).is_err());
    }

    #[test]
    fn a_rendered_message_with_a_raw_escape_fails() {
        for raw in [
            "bad \u{1b}[31m name",
            "nul\0",
            "del\u{7f}",
            "c1\u{85}",
            "rtl \u{202e}gpj",
            "iso \u{2066}",
        ] {
            let msg =
                check_display_has_no_raw_controls(raw).expect_err("a raw control must be refused");
            assert!(msg.contains("U+"), "must name the codepoint: {msg}");
        }
        let msg = check_display_has_no_raw_controls("a\u{202e}b").unwrap_err();
        assert!(msg.contains("U+202E"), "{msg}");
    }

    #[test]
    fn an_escaped_rendering_passes() {
        assert!(check_display_has_no_raw_controls("plain name.txt").is_ok());
        assert!(check_display_has_no_raw_controls("caf\u{e9} \u{4e2d}\u{6587}").is_ok());
        assert!(check_display_has_no_raw_controls("esc \\x1b and \\u{202e}").is_ok());
        let e = Error::Corrupt("bad \u{1b}[31m \0 \u{202e}name".into());
        assert!(check_display_has_no_raw_controls(&e.to_string()).is_ok());
        assert!(
            check_display_has_no_raw_controls("U+0041 and \u{a0}\u{2028}").is_ok(),
            "only the classes fmt_name escapes are refused"
        );
    }

    #[test]
    fn a_hardlink_is_carried_as_a_link_a_copy_or_a_named_skip() {
        // Over a name-keyed oracle the link's NAME is what is carried, whether
        // the output holds it as a link entry or as a file copy; the output
        // list cannot tell them apart and must not need to.
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let clean = FidelityReport::new(Rung::Exact);
        assert!(
            check_entries_carried(&names(&["a", "link"]), &names(&["a", "link"]), &clean).is_ok()
        );
        let mut skipped = FidelityReport::new(Rung::Exact);
        skipped.warn(Fidelity::EntrySkipped {
            entry: "link".into(),
            reason: "hard link target `a` was not written".into(),
        });
        assert!(check_entries_carried(&names(&["a", "link"]), &names(&["a"]), &skipped).is_ok());
        let msg = check_entries_carried(&names(&["a", "link"]), &names(&["a"]), &clean)
            .expect_err("a silently missing link must fail");
        assert!(msg.contains("\"link\""), "{msg}");
    }

    #[test]
    fn an_intact_status_whose_checksum_was_never_checked_is_refused() {
        // The base assertion, and what reddens under the neutered-to-`Ok(())`
        // edit: `SalvageStatus::Intact` is a claim that a checksum agreed,
        // and `verifier_was_checked = false` says outright that no
        // comparison ever ran.
        let msg = check_salvage_claim(&SalvageStatus::Intact, false, Attestation::ContentChecksum)
            .expect_err("Intact without a checked checksum must be refused");
        assert!(msg.contains("Intact"), "must name the status: {msg}");
        // The honest counterpart is permitted.
        assert!(
            check_salvage_claim(&SalvageStatus::Intact, true, Attestation::ContentChecksum).is_ok()
        );
    }

    #[test]
    fn an_intact_status_over_a_format_with_nothing_to_check_is_refused() {
        // A checksum cannot have agreed in a format that carries none.
        let msg = check_salvage_claim(&SalvageStatus::Intact, true, Attestation::Nothing)
            .expect_err("Intact over a format offering nothing must be refused");
        assert!(msg.contains("Intact"), "must name the status: {msg}");
    }

    #[test]
    fn an_intact_status_over_a_header_only_checksum_is_refused() {
        // Fix round 1, F1's first formerly-permitted cell: tar validates its
        // HEADER checksum, so `verifier_was_checked` is honestly `true` — and
        // under the one-bool oracle that made tar's `Intact` indistinguishable
        // from its honest `Complete`. tar has no content checksum; `Intact`
        // is a tier it can never earn.
        let msg = check_salvage_claim(
            &SalvageStatus::Intact,
            true,
            Attestation::HeaderChecksumOnly,
        )
        .expect_err("Intact over a header-only checksum must be refused");
        assert!(msg.contains("Intact"), "must name the status: {msg}");
        assert!(
            msg.contains("Complete"),
            "must name the tier that IS honest: {msg}"
        );
    }

    #[test]
    fn complete_without_the_attestation_it_claims_is_refused() {
        // `Complete` claims "every declared byte was present AND the header
        // self-verified". The second clause is a CHECK, so a header checksum
        // that was never compared has not earned the tier.
        let err = check_salvage_claim(
            &SalvageStatus::Complete,
            false,
            Attestation::HeaderChecksumOnly,
        )
        .expect_err("Complete whose header checksum went unchecked must be refused");
        assert!(
            err.contains("Complete"),
            "the message must name the tier it refused: {err}"
        );
    }

    #[test]
    fn complete_over_a_format_that_attests_nothing_is_refused() {
        // The refusal Salvage Stage 3 exists for. `cpio` and `ar` carry no
        // checksum AND no self-verifying header, so a scanner answering
        // `Complete` for one of their entries asserts a header self-check
        // that does not exist — at exit 0. `Unattested` is their tier.
        let err = check_salvage_claim(&SalvageStatus::Complete, false, Attestation::Nothing)
            .expect_err("Complete over a format with no attestation at all must be refused");
        assert!(err.contains("Complete"), "must name the tier: {err}");
        assert!(
            err.contains("Unattested"),
            "must name the tier that IS honest here: {err}"
        );
    }

    #[test]
    fn complete_over_a_content_checksum_is_refused_even_when_checked() {
        // Fix round 1, F1's second formerly-permitted cell, and the one live
        // against the five scanners shipped before Stage 3. A zip, arc, zoo,
        // lha or arj scanner that compared its CRC, found it DISAGREED, and
        // answered `Complete` would turn an exit-4 `Partial` into an exit-0
        // clean recovery — and the one-bool oracle passed it, because
        // (checked, offers) was exactly tar's legitimate cell. Both values of
        // `verifier_was_checked` are refused: checked is `Intact` or
        // `Partial`, unchecked is `Unverified`, and neither is `Complete`.
        for checked in [true, false] {
            let err = check_salvage_claim(
                &SalvageStatus::Complete,
                checked,
                Attestation::ContentChecksum,
            )
            .expect_err("Complete over a content checksum must be refused");
            assert!(err.contains("Complete"), "must name the tier: {err}");
        }
    }

    #[test]
    fn unattested_is_refused_when_the_format_can_self_verify() {
        // `tar` self-verifies its header, so a tar candidate is never
        // `Unattested` — the tier asserts the format has NOTHING. The same
        // holds for every format with a content checksum.
        for attestation in [
            Attestation::HeaderChecksumOnly,
            Attestation::ContentChecksum,
        ] {
            let err = check_salvage_claim(&SalvageStatus::Unattested, false, attestation)
                .expect_err("Unattested over an attesting format must be refused");
            assert!(
                err.contains("Unattested"),
                "message must name the tier: {err}"
            );
        }
    }

    #[test]
    fn unattested_claiming_a_checked_verifier_is_refused() {
        // Fix round 1, the review's minor cell: "checked a verifier the
        // format does not have" is incoherent, and the `Intact` arm already
        // refuses the identical shape. Consistency, not a live hazard.
        let err = check_salvage_claim(&SalvageStatus::Unattested, true, Attestation::Nothing)
            .expect_err("a checked verifier in a format with none must be refused");
        assert!(
            err.contains("Unattested"),
            "message must name the tier: {err}"
        );
    }

    #[test]
    fn unattested_is_permitted_where_nothing_attests() {
        // The OVER-STRICTNESS guard for the new tier — the same shape as
        // `a_symlink_whose_target_was_consumed_eagerly_is_permitted` above.
        // This is what `cpio` and `ar` legitimately report on every entry
        // they recover, so an oracle refusing it would fire on the first
        // valid cpio the fuzzer built and bury every real finding behind it.
        // Neutering `check_salvage_claim` to `Ok(())` makes this pass HARDER;
        // it is falsified by the opposite edit, and that has been observed
        // red; see the task report.
        check_salvage_claim(&SalvageStatus::Unattested, false, Attestation::Nothing)
            .expect("cpio and ar have no verifier of any kind");
    }

    #[test]
    fn each_class_is_permitted_its_one_honest_tier() {
        // Over-strictness guard for the three classes together. An edit
        // that applies one class's rule to another — `Intact`'s to `Complete`
        // (refusing tar), `Complete`'s to `Intact` (refusing zip) — reddens
        // here, while neutering the oracle makes it pass harder.
        assert!(
            check_salvage_claim(&SalvageStatus::Intact, true, Attestation::ContentChecksum).is_ok(),
            "zip/arc/zoo/lha/arj with an agreeing CRC"
        );
        assert!(
            check_salvage_claim(
                &SalvageStatus::Complete,
                true,
                Attestation::HeaderChecksumOnly
            )
            .is_ok(),
            "tar with a validated header checksum"
        );
        assert!(
            check_salvage_claim(&SalvageStatus::Unattested, false, Attestation::Nothing).is_ok(),
            "cpio/ar"
        );
    }

    #[test]
    fn unverified_and_partial_are_permitted_for_every_class() {
        // Over-strictness guard. The engine assigns
        // `Unverified(OverEntryCeiling)` to a candidate of ANY format before
        // its scanner is asked, and `Partial` folds a comparison that never
        // ran with one that disagreed — so neither may be refused by class or
        // by `verifier_was_checked`. An edit constraining them reddens here.
        use crate::salvage::UnverifiedCause;
        let statuses = [
            SalvageStatus::Partial,
            SalvageStatus::Unverified(UnverifiedCause::UndecodableMethod),
            SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength),
            SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling {
                needed: 2,
                ceiling: 1,
            }),
        ];
        for status in &statuses {
            for attestation in ALL_ATTESTATIONS {
                for checked in [true, false] {
                    assert!(
                        check_salvage_claim(status, checked, attestation).is_ok(),
                        "{status:?} / {attestation:?} / checked={checked} must be permitted"
                    );
                }
            }
        }
    }

    const ALL_ATTESTATIONS: [Attestation; 3] = [
        Attestation::ContentChecksum,
        Attestation::HeaderChecksumOnly,
        Attestation::Nothing,
    ];

    #[test]
    fn the_whole_truth_table_permits_exactly_one_claim_per_class() {
        // The review's truth table, made executable: every cell of the three
        // claim-bearing tiers × `verifier_was_checked` × class, asserted
        // against the ONE permitted cell per tier. A cell drifting either way
        // — a false claim let through, or an honest one refused — fails here
        // and names itself. The named doubles above are what make each
        // failure readable; this is what makes the table complete.
        let expected_ok = |status: &SalvageStatus, checked: bool, a: Attestation| match status {
            SalvageStatus::Intact => a == Attestation::ContentChecksum && checked,
            SalvageStatus::Complete => a == Attestation::HeaderChecksumOnly && checked,
            SalvageStatus::Unattested => a == Attestation::Nothing && !checked,
            SalvageStatus::Unverified(_) | SalvageStatus::Partial => true,
        };
        let mut permitted = 0;
        for status in [
            SalvageStatus::Intact,
            SalvageStatus::Complete,
            SalvageStatus::Unattested,
        ] {
            for attestation in ALL_ATTESTATIONS {
                for checked in [true, false] {
                    let got = check_salvage_claim(&status, checked, attestation).is_ok();
                    let want = expected_ok(&status, checked, attestation);
                    assert_eq!(
                        got, want,
                        "{status:?} / {attestation:?} / checked={checked}: oracle said {got}, \
                         the rule says {want}"
                    );
                    permitted += usize::from(got);
                }
            }
        }
        assert_eq!(
            permitted, 3,
            "exactly one cell per claim-bearing tier is honest — 18 cells, 3 permitted"
        );
    }
}
