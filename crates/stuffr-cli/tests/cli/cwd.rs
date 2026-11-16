//! `STUFFR_CWD` and `--cwd`: where stuffr stands before it dispatches.

use super::common::*;
use std::path::Path;
use std::process::Command;

/// A directory holding `t.tar.gz` (one entry, `a.txt`) and `p.txt.gz`.
fn fixture() -> Scratch {
    let dir = tmp_dir();
    write_fixture_tar_gz(&dir, "t.tar.gz", &[("a.txt", b"hello")]);
    std::fs::write(dir.join("p.txt.gz"), gzip_wrap(b"plain text\n")).unwrap();
    dir
}

fn stuffr_in(env: Option<&Path>, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(STUFFR);
    cmd.args(args);
    cmd.env_remove("STUFFR_CWD");
    if let Some(dir) = env {
        cmd.env("STUFFR_CWD", dir);
    }
    cmd.output().unwrap()
}

#[test]
fn stuffr_cwd_env_resolves_relative_input() {
    let dir = fixture();
    let out = stuffr_in(Some(&dir), &["list", "t.tar.gz"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("a.txt"));
}

#[test]
fn cwd_flag_resolves_relative_input() {
    let dir = fixture();
    let dir = dir.to_str().unwrap();
    let out = stuffr_in(None, &["--cwd", dir, "list", "t.tar.gz"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("a.txt"));
    // Also accepted after the verb (the flag is global).
    let out = stuffr_in(None, &["list", "t.tar.gz", "--cwd", dir]);
    assert!(out.status.success(), "{}", stderr_text(&out));
}

#[test]
fn cwd_flag_may_be_relative() {
    let dir = fixture();
    let parent = dir.parent().unwrap().to_path_buf();
    let leaf = dir.file_name().unwrap().to_str().unwrap().to_owned();
    let out = Command::new(STUFFR)
        .args(["--cwd", &leaf, "list", "t.tar.gz"])
        .current_dir(&parent)
        .env_remove("STUFFR_CWD")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr_text(&out));
}

#[test]
fn cwd_flag_ignores_env() {
    let dir = fixture();
    let missing = dir.join("no-such-dir");
    let out = stuffr_in(
        Some(&missing),
        &["--cwd", dir.to_str().unwrap(), "list", "t.tar.gz"],
    );
    assert!(out.status.success(), "{}", stderr_text(&out));
}

#[test]
fn stuffr_cwd_empty_is_ignored() {
    let dir = fixture();
    let out = Command::new(STUFFR)
        .args(["list", "t.tar.gz"])
        .current_dir(&dir)
        .env("STUFFR_CWD", "")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr_text(&out));
}

#[test]
fn stuffr_cwd_relative_is_refused() {
    let dir = fixture();
    let out = Command::new(STUFFR)
        .args(["list", "t.tar.gz"])
        .current_dir(&dir)
        .env("STUFFR_CWD", ".")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = stderr_text(&out);
    assert!(err.starts_with("stuffr: cannot enter .: "), "{err}");
    assert!(err.contains("must be an absolute path"), "{err}");
}

#[cfg(unix)]
fn personality(dir: &Path, name: &str) -> std::path::PathBuf {
    let link = dir.join(name);
    if link.symlink_metadata().is_err() {
        std::os::unix::fs::symlink(STUFFR, &link).unwrap();
    }
    link
}

#[cfg(unix)]
#[test]
fn stuffr_cwd_reaches_personality() {
    let dir = fixture();
    let bins = tmp_dir();
    let gzip = personality(&bins, "gzip");
    let out = Command::new(gzip)
        .args(["-dc", "p.txt.gz"])
        .env("STUFFR_CWD", &*dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr_text(&out));
    assert_eq!(out.stdout, b"plain text\n");
}

/// The failure exit code of each invoked name, written out here rather than
/// read back from the table under test.
#[cfg(unix)]
fn expected_code(name: &str) -> i32 {
    match name {
        "unzip" | "zipinfo" | "funzip" => 2,
        "zip" | "zipcloak" | "zipnote" | "zipsplit" => 16,
        _ => 1,
    }
}

#[cfg(unix)]
#[test]
fn missing_dir_fails_with_the_familys_exit_code() {
    let dir = tmp_dir();
    let missing = dir.join("no-such-dir");
    let bins = tmp_dir();
    for &name in stuffr_cli::compat::names() {
        let out = Command::new(personality(&bins, name))
            .env("STUFFR_CWD", &missing)
            .output()
            .unwrap();
        let err = stderr_text(&out);
        assert_eq!(
            out.status.code(),
            Some(expected_code(name)),
            "{name}: {err}"
        );
        assert!(
            err.starts_with(&format!("{name}: cannot enter ")),
            "{name}: {err}"
        );
    }
    // The native verbs: exit 2, via the env var and via the flag.
    let out = stuffr_in(Some(&missing), &["formats"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr_text(&out).starts_with("stuffr: cannot enter "));
    let out = stuffr_in(None, &["--cwd", missing.to_str().unwrap(), "formats"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr_text(&out).starts_with("stuffr: cannot enter "));
}

#[cfg(unix)]
#[test]
fn relative_env_is_refused_by_a_personality_too() {
    let bins = tmp_dir();
    let out = Command::new(personality(&bins, "zip"))
        .env("STUFFR_CWD", "rel")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(16));
    let err = stderr_text(&out);
    assert!(err.starts_with("zip: cannot enter rel: "), "{err}");
    assert!(err.contains("must be an absolute path"), "{err}");
}
