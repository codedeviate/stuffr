//! Invariants a decoder must satisfy on ANY input, hostile included.
//!
//! These live here rather than inside a fuzz target for one reason: a fuzz
//! target's checks cannot be unit-tested, so invariants written there are
//! indistinguishable from vacuous ones — and "ran 30 seconds, found nothing"
//! looks identical either way. Here each one has a broken double proving it
//! can fail, exactly as `conformance.rs`'s `broken_codecs` does.

use crate::{Error, FidelityReport};

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

/// An index that states a total must be reachable in full.
pub fn check_entry_count(declared: Option<usize>, enumerated: usize) -> Result<(), String> {
    match declared {
        Some(d) if d != enumerated => Err(format!(
            "the index declares {d} entries but {enumerated} were enumerated"
        )),
        _ => Ok(()),
    }
}

/// `Rung::Exact` with no warnings is a claim that nothing was approximated.
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
        // means "stuffr failed", not "your input was bad". Three wrong exit
        // codes in this project came through that wildcard.
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
        for e in [
            Error::Corrupt("bad".into()),
            Error::Unsupported("nope".into()),
            Error::ResourceLimit("too big".into()),
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
        // exact fidelity.
        let msg = check_entry_count(Some(8), 6).expect_err("mismatch must fail");
        assert!(
            msg.contains("8") && msg.contains("6"),
            "must name both: {msg}"
        );
        assert!(check_entry_count(None, 6).is_ok());
        assert!(check_entry_count(Some(6), 6).is_ok());
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
