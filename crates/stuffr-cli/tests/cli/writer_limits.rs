//! What a container WRITER cannot store (bug hunt 2026-11-15, Task 3): every
//! refusal is exit 3 with "<FORMAT> cannot store", leaves no output behind,
//! and never blames the (valid) input as corrupt.

use crate::common::*;

use std::path::Path;

/// A name of about 70 KiB: legal in a tar (GNU `L` long name), past what
/// zip, cpio and ar can hold or read back.
fn long_name() -> String {
    "d/".repeat(30_000) + &"n".repeat(10_000)
}

fn assert_refused_with_nothing_left(out: &std::process::Output, dst: &Path, format: &str) {
    let err = stderr_text(out);
    assert_eq!(out.status.code(), Some(3), "{format}: {err}");
    assert!(
        err.contains(&format!("{format} cannot store")),
        "{format}: {err}"
    );
    assert!(!err.contains("corrupt"), "{format}: {err}");
    assert!(!dst.exists(), "{format}: no output may be left behind");
}

/// Finding 1 (= 15, 21): `convert` of a valid tar whose entry name is too
/// long for a zip local header is exit 3, not exit 5 "archive is corrupt".
#[test]
fn convert_to_zip_of_a_name_too_long_for_zip_is_unsupported() {
    let dir = tmp_dir();
    let src = write_fixture_tar(&dir, &[(&long_name(), b"hello\n"), ("b", b"x")]);
    let dst = dir.join("out.zip");
    let out = run_output(&[
        "convert",
        src.to_str().unwrap(),
        "-o",
        dst.to_str().unwrap(),
    ]);
    assert_refused_with_nothing_left(&out, &dst, "zip");
}
