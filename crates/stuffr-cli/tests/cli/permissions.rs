//! Restored permissions and the umask (security audit EXTRACT-2/EXTRACT-5).
//!
//! `unpack -C` masks an archived mode with the process umask, the default
//! `tar` and `bsdtar` apply to a non-root extraction; `-p` /
//! `--same-permissions` restores the archived bits as they are (setid and
//! sticky still dropped). A directory that was there before the run is never
//! re-moded or re-timed. Each child gets its umask from `pre_exec`, so the
//! test process's own umask is never touched.
#![cfg(unix)]

use crate::common::*;
use std::path::Path;
use std::process::Command;

/// `stuffr ARGS` with the child's umask set to `mask` before `exec`.
fn run_under_umask(mask: u32, args: &[&str]) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(STUFFR);
    cmd.args(args);
    // SAFETY: `umask` is async-signal-safe and touches only the child.
    unsafe {
        cmd.pre_exec(move || {
            libc::umask(mask as libc::mode_t);
            Ok(())
        });
    }
    cmd.output().unwrap()
}

/// A tar holding a 0777 directory `d/` and a 0777 file `d/x`.
fn world_writable_tar(path: &Path) {
    let mut builder = tar::Builder::new(std::fs::File::create(path).unwrap());
    let dir = raw_header("d/", tar::EntryType::Directory, None, 0, 0o777);
    builder.append(&dir, std::io::empty()).unwrap();
    let file = raw_header("d/x", tar::EntryType::Regular, None, 2, 0o777);
    builder.append(&file, &b"hi"[..]).unwrap();
    builder.finish().unwrap();
}

fn unpack_under_umask(mask: u32, archive: &Path, dest: &Path, extra: &[&str]) {
    let mut args = vec![
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let out = run_under_umask(mask, &args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_restored_mode_is_masked_by_the_umask() {
    let dir = tmp_dir();
    let archive = dir.join("w.tar");
    world_writable_tar(&archive);
    let dest = dir.join("out");
    unpack_under_umask(0o022, &archive, &dest, &[]);
    assert_eq!(mode_of(&dest.join("d/x")), 0o755);
    assert_eq!(mode_of(&dest.join("d")), 0o755);

    let dest = dir.join("out077");
    unpack_under_umask(0o077, &archive, &dest, &[]);
    assert_eq!(mode_of(&dest.join("d/x")), 0o700);
    assert_eq!(mode_of(&dest.join("d")), 0o700);
}

#[test]
fn same_permissions_restores_the_archived_mode_exactly() {
    let dir = tmp_dir();
    let archive = dir.join("w.tar");
    world_writable_tar(&archive);
    for flag in ["-p", "--same-permissions"] {
        let dest = dir.join(format!("out{flag}"));
        unpack_under_umask(0o022, &archive, &dest, &[flag]);
        assert_eq!(mode_of(&dest.join("d/x")), 0o777, "{flag}");
        assert_eq!(mode_of(&dest.join("d")), 0o777, "{flag}");
    }
}

#[test]
fn a_directory_that_existed_before_the_run_is_never_re_moded() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir();
    let archive = dir.join("w.tar");
    world_writable_tar(&archive);
    let dest = dir.join("out");
    std::fs::create_dir_all(dest.join("d")).unwrap();
    std::fs::set_permissions(dest.join("d"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let before = std::fs::metadata(dest.join("d"))
        .unwrap()
        .modified()
        .unwrap();
    // Even under -p: the archive's mode is for what the run creates.
    unpack_under_umask(0o022, &archive, &dest, &["-p"]);
    assert_eq!(mode_of(&dest.join("d")), 0o700);
    // Not re-timed to the archive's mtime either (the child write moved it
    // forward, never back to 2020).
    let after = std::fs::metadata(dest.join("d"))
        .unwrap()
        .modified()
        .unwrap();
    assert!(after >= before, "the directory was re-timed");
    assert_eq!(mode_of(&dest.join("d/x")), 0o777);
}

#[test]
fn same_permissions_needs_entry_extraction() {
    let dir = tmp_dir();
    let input = dir.join("a.gz");
    std::fs::write(&input, gzip_wrap(b"hello")).unwrap();
    let out = run_output(&["unpack", input.to_str().unwrap(), "-p"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dir.join("a").exists());
}

/// HOST-1: a single-stream output takes the input file's mode, as gzip does.
#[test]
fn pack_and_unpack_keep_a_private_inputs_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir();
    let src = dir.join("s.txt");
    std::fs::write(&src, b"secret").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).unwrap();
    let packed = dir.join("s.txt.gz");
    let out = run_under_umask(
        0o022,
        &[
            "pack",
            src.to_str().unwrap(),
            "-o",
            packed.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(mode_of(&packed), 0o600);
    let back = dir.join("back.txt");
    let out = run_under_umask(
        0o022,
        &[
            "unpack",
            packed.to_str().unwrap(),
            "-o",
            back.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(mode_of(&back), 0o600);
}
