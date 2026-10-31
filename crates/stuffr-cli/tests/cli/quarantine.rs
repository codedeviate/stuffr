//! macOS quarantine (security audit EXTRACT-3): `unpack`, `salvage` and a
//! single-stream decode give everything they make the input's
//! `com.apple.quarantine`, as libquarantine rewrites it for an archive, the
//! way Apple's tar and unzip do. Symlinks are not stamped.
#![cfg(target_os = "macos")]

use crate::common::*;
use std::path::Path;
use std::process::Command;

const ATTR: &str = "com.apple.quarantine";
/// What `xattr -w` puts on the archive; libquarantine keeps `0081` as is.
const VALUE: &str = "0081;5f000000;Safari;";

fn quarantine_of(path: &Path) -> Option<String> {
    let out = Command::new("/usr/bin/xattr")
        .args(["-p", ATTR])
        .arg(path)
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn quarantine(path: &Path) {
    let st = Command::new("/usr/bin/xattr")
        .args(["-w", ATTR, VALUE])
        .arg(path)
        .status()
        .unwrap();
    assert!(st.success());
}

/// A tar holding a directory, a file in it, a file whose parents have no
/// entry of their own, a hard link and a symlink.
fn tree_tar(path: &Path) {
    write_raw_tar(
        path,
        &[
            Raw::Dir("d/"),
            Raw::File("d/x", b"x"),
            Raw::File("g/h/i", b"i"),
            Raw::Hardlink("d/y", "d/x"),
            Raw::Symlink("d/link", "x"),
        ],
    );
}

/// Every node under `root` (and `root`), symlinks left out.
fn nodes(root: &Path) -> Vec<std::path::PathBuf> {
    let mut all = vec![root.to_path_buf()];
    let mut i = 0;
    while i < all.len() {
        let p = all[i].clone();
        if std::fs::symlink_metadata(&p).unwrap().is_dir() {
            for e in std::fs::read_dir(&p).unwrap() {
                all.push(e.unwrap().path());
            }
        }
        i += 1;
    }
    all.retain(|p| {
        !std::fs::symlink_metadata(p)
            .unwrap()
            .file_type()
            .is_symlink()
    });
    all
}

fn assert_all(root: &Path, want: Option<&str>, at_least: usize) {
    let nodes = nodes(root);
    assert!(nodes.len() >= at_least, "{nodes:?}");
    for n in nodes {
        assert_eq!(quarantine_of(&n).as_deref(), want, "{}", n.display());
    }
}

fn ok(args: &[&str]) {
    let out = run_output(args);
    assert!(
        out.status.code().is_some_and(|c| c == 0 || c == 4),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unpack_and_salvage_quarantine_everything_they_make() {
    let dir = tmp_dir();
    let archive = dir.join("q.tar");
    tree_tar(&archive);
    quarantine(&archive);

    let out = dir.join("out");
    ok(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        out.to_str().unwrap(),
    ]);
    // out, d, d/x, d/y, g, g/h, g/h/i
    assert_all(&out, Some(VALUE), 7);

    let salvaged = dir.join("salvaged");
    ok(&[
        "salvage",
        archive.to_str().unwrap(),
        "-C",
        salvaged.to_str().unwrap(),
    ]);
    assert_all(&salvaged, Some(VALUE), 4);

    // A pre-existing destination is the caller's, not the archive's.
    let pre = dir.join("pre");
    std::fs::create_dir(&pre).unwrap();
    ok(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        pre.to_str().unwrap(),
    ]);
    assert_eq!(quarantine_of(&pre), None);
    assert_eq!(quarantine_of(&pre.join("d/x")).as_deref(), Some(VALUE));
}

#[test]
fn an_unquarantined_archive_makes_nothing_quarantined() {
    let dir = tmp_dir();
    let archive = dir.join("clean.tar");
    tree_tar(&archive);
    let out = dir.join("out");
    ok(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        out.to_str().unwrap(),
    ]);
    assert_all(&out, None, 7);
}

#[test]
fn a_single_stream_decode_carries_the_quarantine() {
    let dir = tmp_dir();
    let gz = dir.join("tool.gz");
    std::fs::write(&gz, gzip_wrap(b"#!/bin/sh\necho hi\n")).unwrap();
    quarantine(&gz);
    let out = dir.join("tool");
    ok(&["unpack", gz.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    assert_eq!(quarantine_of(&out).as_deref(), Some(VALUE));

    let clean = dir.join("clean.gz");
    std::fs::write(&clean, gzip_wrap(b"data")).unwrap();
    let out = dir.join("clean");
    ok(&[
        "unpack",
        clean.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(quarantine_of(&out), None);
}
