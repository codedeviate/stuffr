//! A closed standard error or standard output (bug hunt 2026-11-15,
//! findings 13, 35 and 14): the reader went away (`2>&1 | grep -q`,
//! `| head -1`). No verb may panic (exit 101) over it: stderr write
//! failures are ignored and the run keeps its real exit code; a closed
//! stdout ends the verb quietly, as `--examples` does. Unix only.
//!
//! Deterministic: the stream is the write end of a pipe whose read end is
//! closed before the child is spawned, so every write fails with EPIPE.
#![cfg(unix)]

use crate::common::*;
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};

/// The write end of a pipe nobody reads.
fn closed_pipe() -> Stdio {
    let mut fds = [0; 2];
    // SAFETY: `pipe` fills two fresh descriptors this function owns.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: both descriptors were just returned by `pipe` and are owned
    // here alone; the read end is dropped (closed) at once.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    drop(read);
    Stdio::from(write)
}

/// `stuffr ARGS` with stderr a closed pipe, stdout discarded: the exit code.
fn code_with_stderr_closed(args: &[&str]) -> Option<i32> {
    Command::new(STUFFR)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(closed_pipe())
        .status()
        .unwrap()
        .code()
}

/// The same run with stderr intact, as the control.
fn code(args: &[&str]) -> Option<i32> {
    run_output(args).status.code()
}

/// A gzip whose header is damaged: `test` exits 5.
fn corrupt_gz(dir: &std::path::Path) -> std::path::PathBuf {
    let mut bytes = gzip_wrap(b"hello hello hello\n");
    bytes[12..15].copy_from_slice(&[0, 0, 0]);
    let p = dir.join("c.gz");
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn a_closed_stderr_keeps_a_corrupt_archives_exit_code() {
    let dir = tmp_dir();
    let gz = corrupt_gz(&dir);
    let args = ["test", gz.to_str().unwrap()];
    assert_eq!(code(&args), Some(5), "the control");
    assert_eq!(code_with_stderr_closed(&args), Some(5));
}

#[test]
fn a_closed_stderr_keeps_a_usage_errors_exit_code() {
    let dir = tmp_dir();
    let missing = dir.join("nosuch.zip");
    let args = ["list", missing.to_str().unwrap()];
    assert_eq!(code(&args), Some(2), "the control");
    assert_eq!(code_with_stderr_closed(&args), Some(2));
}

#[test]
fn a_closed_stderr_does_not_fail_a_successful_pack_or_unpack() {
    let dir = tmp_dir();
    let input = dir.join("f1");
    std::fs::write(&input, b"some text\n").unwrap();
    let packed = dir.join("f1.gz");
    let pack = [
        "pack",
        input.to_str().unwrap(),
        "-o",
        packed.to_str().unwrap(),
    ];
    assert_eq!(code_with_stderr_closed(&pack), Some(0));
    let back = dir.join("back");
    let unpack = [
        "unpack",
        packed.to_str().unwrap(),
        "-o",
        back.to_str().unwrap(),
    ];
    assert_eq!(code_with_stderr_closed(&unpack), Some(0));
    assert_eq!(std::fs::read(&back).unwrap(), b"some text\n");

    let tar = write_fixture_tar(&dir, &[("a.txt", b"a"), ("b.txt", b"b")]);
    let out = dir.join("out");
    let unpack_tar = ["unpack", tar.to_str().unwrap(), "-C", out.to_str().unwrap()];
    assert_eq!(code_with_stderr_closed(&unpack_tar), Some(0));
    assert_eq!(std::fs::read(out.join("b.txt")).unwrap(), b"b");
    assert_eq!(
        code_with_stderr_closed(&["test", tar.to_str().unwrap()]),
        Some(0)
    );
}

/// Finding 14: `install-links` printed each action with `println!`.
#[test]
fn install_links_ends_quietly_on_a_closed_stdout() {
    let dir = tmp_dir();
    let out = Command::new(STUFFR)
        .args(["install-links", "--dir", dir.to_str().unwrap(), "--dry-run"])
        .stdin(Stdio::null())
        .stdout(closed_pipe())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
