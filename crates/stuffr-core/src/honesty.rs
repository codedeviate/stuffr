//! Invariants a decoder must satisfy on ANY input, hostile included.
//!
//! These live here rather than inside a fuzz target for one reason: a fuzz
//! target's checks cannot be unit-tested, so invariants written there are
//! indistinguishable from vacuous ones — and "ran 30 seconds, found nothing"
//! looks identical either way. Here each one has a broken double proving it
//! can fail, exactly as `conformance.rs`'s `broken_codecs` does.

use crate::{Error, Fidelity, FidelityReport};

/// Hostile bytes may be refused, but never as an internal error.
///
/// `Error::exit_code`'s `_ => 1` wildcard means "stuffr failed". Anything
/// reaching it for a *bad input* is a misclassification: the input is the
/// problem, not the program. This guards the wildcard that has produced four
/// wrong exit codes in this project (`ChainTooDeep`, `EntryNotFound`,
/// `Unsupported`, and the `UnknownFormat`/`AmbiguousFormat` pair, each fixed
/// after the fact).
pub fn check_error_is_classified(e: &Error) -> Result<(), String> {
    match e.exit_code() {
        1 => Err(format!(
            "a decoder raised {e:?}, which maps to exit code 1 — that means \
             stuffr failed, not that the input was bad"
        )),
        _ => Ok(()),
    }
}

/// A header that declares *n* bytes must deliver exactly *n*.
pub fn check_entry_size(declared: Option<u64>, produced: u64, name: &str) -> Result<(), String> {
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
/// (`u64::try_from(n).unwrap_or(usize::MAX)`), never cast: `as usize` on a
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
        let msg = check_entry_size(Some(100), 42, "a.txt").expect_err("mismatch must fail");
        assert!(msg.contains("a.txt"), "must name the entry: {msg}");
        assert!(
            msg.contains("100") && msg.contains("42"),
            "must name both numbers: {msg}"
        );
        // An undeclared size cannot disagree with anything.
        assert!(check_entry_size(None, 42, "a.txt").is_ok());
        assert!(check_entry_size(Some(42), 42, "a.txt").is_ok());
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
        // The other over-strictness guard in this module, so like
        // `corrupt_unsupported_and_resource_limit_are_all_permitted` it
        // cannot be reddened by neutering. Falsified by deleting the
        // `EntryCountMismatch` arm from `check_entry_count`; observed red.
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
}
