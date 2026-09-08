//! `entries::extract`'s contract against a real `cpio` archive, specifically
//! for the symlink support `cpio.rs` added on top of Task 10: a symlink
//! entry must both MATERIALISE as a real symlink on disk (not be skipped,
//! the way an `EntryKind::Other` entry still is) and go THROUGH the exact
//! same containment check every other symlink source does —
//! `check_symlink_target`, exercised already for tar in
//! `entries_extract.rs`. A newly-materialising symlink type that bypassed
//! that check would be the exact kind of regression composition is supposed
//! to catch.
#![cfg(feature = "cpio")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use stuffr::entries::{self, ExtractOpts};
use stuffr::ops::Input;
use stuffr::{EntryKind, EntryMeta, Error, FormatId};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn tmp_dir() -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-extract-cpio-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Writes `entries` into a real `.cpio`, through the container API — the
/// same reason `entries_extract.rs`'s own `write_tar` does, doubled here:
/// property 12 (verbatim hostile names) and the mode-normalisation fix in
/// `cpio.rs` both apply on this exact path, not on a hand-rolled archive.
fn write_cpio(path: &std::path::Path, entries: &[(&str, EntryKind, &[u8])]) -> PathBuf {
    let cpio = FormatId::new("cpio");
    let container = stuffr::registry().require_container(cpio).unwrap();
    let file = std::fs::File::create(path).unwrap();
    let mut archive = container
        .create(Box::new(file), &Default::default())
        .unwrap();
    for (name, kind, data) in entries {
        let mut cursor = *data;
        archive
            .add(
                &EntryMeta {
                    name: name.to_string(),
                    size: Some(data.len() as u64),
                    kind: kind.clone(),
                    // Deliberately permission-only, no S_IFLNK/S_IFDIR bit —
                    // matching `entries_extract.rs`'s own tar fixtures
                    // exactly, and exercising `cpio.rs`'s mode-normalisation
                    // fix rather than assuming it away.
                    mode: Some(0o777),
                    ..Default::default()
                },
                &mut cursor,
            )
            .unwrap();
    }
    archive.finish().unwrap();
    path.to_path_buf()
}

#[test]
fn a_cpio_symlink_extracts_as_a_real_symlink() {
    let root = tmp_dir();
    let archive = write_cpio(
        &root.join("link.cpio"),
        &[
            ("target.txt", EntryKind::File, b"hello".as_slice()),
            (
                "mylink",
                EntryKind::Symlink {
                    target: "target.txt".into(),
                },
                b"".as_slice(),
            ),
        ],
    );
    let dest = root.join("out");

    entries::extract(Input::Path(archive), &dest, &[], &ExtractOpts::default())
        .expect("a same-directory symlink target must be accepted");

    let meta = std::fs::symlink_metadata(dest.join("mylink"))
        .expect("mylink must exist as a real symlink");
    assert!(
        meta.file_type().is_symlink(),
        "must be a symlink, not a skipped entry"
    );
    assert_eq!(
        std::fs::read_link(dest.join("mylink")).unwrap(),
        std::path::PathBuf::from("target.txt")
    );
    assert_eq!(
        std::fs::read(dest.join("mylink")).unwrap(),
        b"hello",
        "reading through the link must reach target.txt's contents"
    );
}

/// The same refusal `entries_extract.rs`'s
/// `an_escaping_symlink_target_is_refused_before_the_link_exists` proves for
/// tar, proven again for cpio — the point being that a NEW source of
/// `EntryKind::Symlink` entries goes through the SAME `check_symlink_target`
/// call, not around it.
#[test]
fn an_escaping_cpio_symlink_target_is_refused_before_the_link_exists() {
    let root = tmp_dir();
    let archive = write_cpio(
        &root.join("evil.cpio"),
        &[(
            "link",
            EntryKind::Symlink {
                target: "../../etc/passwd".into(),
            },
            b"".as_slice(),
        )],
    );
    let dest = root.join("out");

    let err = entries::extract(Input::Path(archive), &dest, &[], &ExtractOpts::default())
        .expect_err("an escaping symlink target must be refused");
    assert!(matches!(err, Error::UnsafePath { .. }), "got {err:?}");
    assert!(
        std::fs::symlink_metadata(dest.join("link")).is_err(),
        "the link must not have been created"
    );
}
