use crate::common::*;

// ---------------------------------------------------------------------
// `list` reports its fidelity, through the same printer `test` uses.
// ---------------------------------------------------------------------

/// `list` used to drop the container's fidelity report entirely. On a piped
/// zip — the one shape whose forward read provably loses metadata — `test`
/// warned and `list` printed its rows in silence.
///
/// Fixed by handing `report_fidelity` the report, the same call `test` and
/// `unpack -C` make. Asserted against `test`'s own stderr on the identical
/// bytes so the two verbs cannot drift: whatever `test` says was lost,
/// `list` says too.
#[test]
fn list_reports_the_same_fidelity_warnings_test_does() {
    let dir = tmp_dir();
    let zip = write_zip_via_pack(&dir, &[("one.txt", b"first"), ("two.txt", b"second")]);
    let bytes = std::fs::read(&zip).unwrap();

    let listed = run_with_stdin_output(&["list", "-"], &bytes);
    assert!(
        listed.status.success(),
        "a warning is not a failure without --strict-fidelity"
    );
    let list_err = String::from_utf8_lossy(&listed.stderr).to_string();
    let tested = run_with_stdin_output(&["test", "-"], &bytes);
    let test_err = String::from_utf8_lossy(&tested.stderr).to_string();

    assert!(
        test_err.contains("fidelity warning(s)"),
        "the fixture must be a shape that really does lose something: {test_err}"
    );
    assert!(
        list_err.contains("fidelity warning(s)"),
        "`list` must report what it lost, not print rows in silence: {list_err}"
    );
    // Same warnings, verbatim, because it is the same printer over the same
    // report — not a second one that could word things differently.
    let warnings_of = |s: &str| -> Vec<String> {
        s.lines()
            .filter(|l| l.trim_start().starts_with("- "))
            .map(|l| l.trim().to_string())
            .collect()
    };
    assert_eq!(
        warnings_of(&list_err),
        warnings_of(&test_err),
        "list:\n{list_err}\ntest:\n{test_err}"
    );
}

/// And the gate: `list --strict-fidelity` exits 4 on the same archive it
/// exits 0 on without the flag, the same contract `test` and `unpack -C`
/// have.
#[test]
fn list_strict_fidelity_turns_a_warning_into_exit_four() {
    let dir = tmp_dir();
    let zip = write_zip_via_pack(&dir, &[("one.txt", b"first")]);
    let bytes = std::fs::read(&zip).unwrap();

    let lenient = run_with_stdin_output(&["list", "-"], &bytes);
    assert_eq!(lenient.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&lenient.stdout).contains("one.txt"),
        "the listing itself is still printed"
    );

    let strict = run_with_stdin_output(&["list", "-", "--strict-fidelity"], &bytes);
    assert_eq!(
        strict.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
    assert!(
        String::from_utf8_lossy(&strict.stdout).contains("one.txt"),
        "the gate is a verdict on a listing that was still produced"
    );

    // A read that loses nothing is still exit 0 under the flag — the gate is
    // on what was LOST, never on the rung.
    let clean = run_output(&["list", zip.to_str().unwrap(), "--strict-fidelity"]);
    assert_eq!(
        clean.status.code(),
        Some(0),
        "a seekable zip loses nothing: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
}
