//! Invariants a decoder must satisfy on ANY input, hostile included.
//!
//! These live here rather than inside a fuzz target for one reason: a fuzz
//! target's checks cannot be unit-tested, so invariants written there are
//! indistinguishable from vacuous ones — and "ran 30 seconds, found nothing"
//! looks identical either way. Here each one has a broken double proving it
//! can fail, exactly as `conformance.rs`'s `broken_codecs` does.

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
pub fn check_error_is_classified(e: &Error) -> Result<(), String> {
    match e.exit_code() {
        1 => Err(format!(
            "a decoder raised {e:?}, which maps to exit code 1 — that means \
             stuffr failed, not that the input was bad"
        )),
        _ => Ok(()),
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
    if matches!(kind, EntryKind::Symlink { .. }) {
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

/// Never report `Intact` for an entry whose checksum was not actually
/// checked.
///
/// This lives in the library rather than inside the fuzz target because a
/// fuzz target's own checks cannot be unit-tested, so a harness that runs
/// clean is indistinguishable from one whose invariants are vacuous — the
/// same reason the four checks above it live here.
///
/// **Only `Intact` is constrained.** [`SalvageStatus::Complete`] asserts the
/// OPPOSITE of "a checksum agreed" — the format carries no checksum at all,
/// so nothing was there to check — and requiring `verifier_was_checked` for
/// it would be wrong, not stricter: an over-strict oracle demanding a
/// checksum for `Complete` would refuse every tar, cpio or ar entry this
/// engine has ever recovered, none of which carries one. `Partial` is
/// deliberately loose in `stuffr-core`'s own enum: `zip_salvage.rs`'s
/// `stream_verify` folds "the payload ran out or the decoder failed
/// mid-stream" (no comparison was ever reached) and "every byte decoded but
/// disagreed with the checksum" (a comparison WAS reached and failed) into
/// the one status, so `verifier_was_checked` cannot be constrained either
/// way for it without splitting that status — which this project's own
/// `entries.rs::PartialCause` already does one layer up, by re-deriving the
/// cause from a second decode rather than widening this enum. `Unverified`
/// asserts its own opposite explicitly (nothing about the content was
/// verified, for either of its two causes), so it needs no constraint here
/// either — its own variant name already carries the claim this function
/// exists to police for `Intact`.
pub fn check_salvage_claim(
    status: SalvageStatus,
    verifier_was_checked: bool,
) -> Result<(), String> {
    if status == SalvageStatus::Intact && !verifier_was_checked {
        return Err("reported Intact without checking a checksum".into());
    }
    Ok(())
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
    fn an_intact_status_whose_checksum_was_never_checked_is_refused() {
        // The base assertion, and what reddens under the neutered-to-`Ok(())`
        // edit: `SalvageStatus::Intact` is a claim that a checksum agreed,
        // and `verifier_was_checked = false` says outright that no
        // comparison ever ran. Neutering `check_salvage_claim` to `Ok(())`
        // makes this `expect_err` panic instead — observed red before this
        // was restored; see the task report.
        let msg = check_salvage_claim(SalvageStatus::Intact, false)
            .expect_err("Intact without a checked checksum must be refused");
        assert!(msg.contains("Intact"), "must name the status: {msg}");
        // The honest counterpart is permitted.
        assert!(check_salvage_claim(SalvageStatus::Intact, true).is_ok());
    }

    #[test]
    fn a_status_asserting_no_checksum_exists_is_permitted_unchecked() {
        // Over-strictness guard, the same shape as
        // `a_symlink_whose_target_was_consumed_eagerly_is_permitted` above:
        // `Complete` is the status a format with NO checksum at all reports
        // (tar, cpio, ar), and `Unverified` asserts nothing was verified for
        // either of its two causes — neither claims a checksum agreed, so
        // neither may be constrained by `verifier_was_checked`. An
        // over-strict edit requiring `verifier_was_checked` for every status
        // (not just `Intact`) would refuse both of these, and has been made
        // and observed red — see the task report. Neutering
        // `check_salvage_claim` to `Ok(())` makes this pass HARDER, which is
        // why the sibling test above is the one that catches that edit.
        assert!(check_salvage_claim(SalvageStatus::Complete, false).is_ok());
        assert!(
            check_salvage_claim(
                SalvageStatus::Unverified(crate::salvage::UnverifiedCause::UndecodableMethod),
                false
            )
            .is_ok()
        );
        // `Partial` folds two causes into one status: a comparison that
        // never ran (truncation) and a comparison that ran and disagreed
        // (checksum mismatch). `stuffr-core` cannot tell which without
        // `entries.rs`'s own re-decode (`PartialCause`, a crate up), so
        // neither value of `verifier_was_checked` may be refused for it —
        // an over-strict edit requiring `true` here would refuse every
        // truncated-partial entry this engine has ever recovered.
        assert!(check_salvage_claim(SalvageStatus::Partial, false).is_ok());
        assert!(check_salvage_claim(SalvageStatus::Partial, true).is_ok());
    }
}
