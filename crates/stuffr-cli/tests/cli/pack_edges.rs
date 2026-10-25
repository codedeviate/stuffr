use crate::common::*;
use std::process::Command;

// ---------------------------------------------------------------------------
// Three branches of `entries.rs` that were verified by reading, not by test.
// ---------------------------------------------------------------------------

/// `/` has no final component to name an entry after, and the refusal is a
/// usage error — not an `Io` error, and not an archive named `/`, which
/// `unpack` would then refuse at exit 7.
#[test]
fn packing_the_filesystem_root_is_a_usage_error_that_says_why() {
    let dir = tmp_dir();
    let out = dir.join("root.tar");
    let st = Command::new(STUFFR)
        .args(["pack", "/", "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(2),
        "packing `/` is the caller's mistake, not an i/o failure; stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let stderr = String::from_utf8_lossy(&st.stderr);
    assert!(
        stderr.contains("no final path component"),
        "the message must say what is wrong with `/`: {stderr}"
    );
    assert!(
        !out.exists(),
        "the refusal happens before the destination is opened"
    );
}

/// A path ending in `..` that does not exist fails as the `Io` error it is
/// (exit 1), not as a naming complaint.
///
/// `entry_name_for` reaches `canonicalize` for any path whose final component
/// is `.` or `..`, and that call is what reports a missing path here — a
/// deliberate exit-code decision (`Usage` before Phase 2c) with nothing
/// pinning it.
#[test]
fn a_nonexistent_dotdot_path_is_reported_as_an_io_error() {
    let dir = tmp_dir();
    let out = dir.join("dd.tar");
    let missing = dir.join("nosuch/..");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            missing.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(1),
        "a path that does not exist is an i/o error, whatever its final component; \
         stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    assert!(!out.exists());
}

/// `pack .` from a SYMLINKED working directory names entries after the
/// directory the link resolves to, not after the link.
///
/// Surprising the first time it happens (`cd proj && stuffr pack .` writes
/// `real/…`), and correct: `Path::file_name` gives `None` for `.`, so the name
/// comes from `canonicalize`, which resolves every symlink in the path. Pinned
/// because the obvious "fix" — using the shell's `$PWD` or the un-resolved cwd
/// — would silently change every such archive's entry names.
#[cfg(unix)]
#[test]
fn pack_of_dot_from_a_symlinked_directory_names_entries_after_the_real_one() {
    let dir = tmp_dir();
    std::fs::create_dir_all(dir.join("real/src")).unwrap();
    std::fs::write(dir.join("real/src/main.rs"), b"fn main() {}").unwrap();
    std::os::unix::fs::symlink("real", dir.join("proj")).unwrap();

    let out = dir.join("sym.tar");
    let st = Command::new(STUFFR)
        .current_dir(dir.join("proj"))
        .args(["pack", ".", "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("real/src/main.rs"),
        "`.` resolves through the symlink, so entries sit under the real directory's \
         name: {text}"
    );
    assert!(
        !text.contains("proj/"),
        "nothing may be named after the link itself: {text}"
    );
}
