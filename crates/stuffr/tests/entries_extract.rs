//! `entries::extract`'s contract at the library level, where the CLI tests can
//! only see an exit code.
//!
//! The README's non-negotiable is that a hostile entry is **refused, not
//! silently sanitised**, and `stuffr-core`'s no-`anyhow` rule exists so a
//! caller can `match` on which refusal it got. That is what this file
//! asserts: the typed [`Error::UnsafePath`], carrying the offending name
//! verbatim.
//!
//! The hostile fixtures are built through the container API itself rather
//! than with the `tar` crate, which doubles as a check on container-harness
//! property 12: `tar`'s writer stores a name like `../escaped.txt`
//! unchanged, because refusal is this layer's job and it can only refuse
//! what it can still see.
#![cfg(feature = "tar")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use stuffr::entries::{self, ExtractOpts};
use stuffr::ops::{Input, Output};
use stuffr::{EntryKind, EntryMeta, Error, FormatId};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn tmp_dir() -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-extract-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// One entry to write into a fixture archive.
struct Fixture<'a> {
    name: &'a str,
    kind: EntryKind,
    data: &'a [u8],
}

fn file<'a>(name: &'a str, data: &'a [u8]) -> Fixture<'a> {
    Fixture {
        name,
        kind: EntryKind::File,
        data,
    }
}

fn dir(name: &str) -> Fixture<'_> {
    Fixture {
        name,
        kind: EntryKind::Dir,
        data: b"",
    }
}

fn symlink<'a>(name: &'a str, target: &str) -> Fixture<'a> {
    Fixture {
        name,
        kind: EntryKind::Symlink {
            target: target.to_string(),
        },
        data: b"",
    }
}

/// Writes `entries` into a real `.tar`, names stored verbatim.
fn write_tar(path: &Path, entries: &[Fixture<'_>]) -> PathBuf {
    let tar = FormatId::new("tar");
    let container = stuffr::registry().require_container(tar).unwrap();
    let file = std::fs::File::create(path).unwrap();
    let mut archive = container
        .create(Box::new(file), &Default::default())
        .unwrap();
    for entry in entries {
        let mut data = entry.data;
        archive
            .add(
                &EntryMeta {
                    name: entry.name.to_string(),
                    size: Some(entry.data.len() as u64),
                    kind: entry.kind.clone(),
                    ..Default::default()
                },
                &mut data,
            )
            .unwrap();
    }
    archive.finish().unwrap();
    path.to_path_buf()
}

#[test]
fn a_traversing_entry_is_refused_as_a_typed_unsafe_path_naming_itself() {
    let root = tmp_dir();
    let archive = write_tar(&root.join("evil.tar"), &[file("../escaped.txt", b"pwned")]);
    let dest = root.join("out");

    let err = entries::extract(Input::Path(archive), &dest, &[], &ExtractOpts::default())
        .expect_err("a traversing entry must be refused");

    match &err {
        Error::UnsafePath { path, reason } => {
            // Verbatim, not sanitised: a caller handed a cleaned-up name
            // would have no way to know it had been handed one.
            assert_eq!(path, "../escaped.txt");
            assert!(reason.contains("traversal"), "reason was {reason}");
        }
        other => panic!("expected UnsafePath, got {other:?}"),
    }
    assert!(
        !root.join("escaped.txt").exists(),
        "the entry escaped the destination"
    );
    assert_eq!(err.exit_code(), 7, "a hostile archive is exit 7");
}

#[test]
fn an_escaping_symlink_target_is_refused_before_the_link_exists() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("link.tar"),
        &[symlink("link", "../../etc/passwd")],
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

#[test]
fn a_dot_entry_names_the_destination_and_extracts_alongside_real_entries() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("dot.tar"),
        &[
            dir("./"),
            file("./a.txt", b"alpha"),
            dir("sub/"),
            file("sub/b.txt", b"beta"),
        ],
    );
    let dest = root.join("out");

    let outcome = entries::extract(Input::Path(archive), &dest, &[], &ExtractOpts::default())
        .expect("`./` names the destination and must be accepted");
    assert_eq!(outcome.bytes_out, 9, "alpha + beta");
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dest.join("sub/b.txt")).unwrap(), b"beta");
}

#[test]
fn patterns_select_entries_and_naming_none_of_them_is_an_error() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("pick.tar"),
        &[file("a.txt", b"alpha"), file("b.txt", b"beta")],
    );
    let dest = root.join("out");

    entries::extract(
        Input::Path(archive.clone()),
        &dest,
        &["b.txt".to_string()],
        &ExtractOpts::default(),
    )
    .unwrap();
    assert!(!dest.join("a.txt").exists());
    assert_eq!(std::fs::read(dest.join("b.txt")).unwrap(), b"beta");

    let err = entries::extract(
        Input::Path(archive),
        &root.join("out2"),
        &["nosuch.txt".to_string()],
        &ExtractOpts::default(),
    )
    .expect_err("a pattern matching nothing must not report success");
    assert!(matches!(err, Error::EntryNotFound(_)), "got {err:?}");
    assert_eq!(err.exit_code(), 2);
}

#[test]
fn an_entry_past_the_ratio_budget_is_a_resource_limit_not_a_containment_refusal() {
    let root = tmp_dir();
    // Past `RATIO_FLOOR`, which is the real ceiling for anything smaller —
    // deliberately, since nothing under a megabyte is a bomb. What is under
    // test here is which error a refusal surfaces as; the arithmetic has its
    // own tests on `ArchiveBudget`.
    let payload = vec![0u8; stuffr::RATIO_FLOOR as usize + 1];
    let archive = write_tar(&root.join("big.tar"), &[file("big.bin", &payload)]);
    let dest = root.join("out");

    let err = entries::extract(
        Input::Path(archive),
        &dest,
        &[],
        &ExtractOpts {
            max_ratio: 1,
            compressed_total: Some(1),
            ..Default::default()
        },
    )
    .expect_err("an entry past the budget must be refused");
    assert!(matches!(err, Error::ResourceLimit(_)), "got {err:?}");
    assert_eq!(err.exit_code(), 6, "a bomb is exit 6, never 5 or 7");
}

#[test]
fn create_archive_stores_final_components_so_its_output_can_be_extracted_again() {
    let root = tmp_dir();
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("one.txt"), b"first").unwrap();
    std::fs::write(src.join("two.txt"), b"second").unwrap();
    let archive = root.join("bundle.tar");

    let outcome = entries::create_archive(
        &[src.join("one.txt"), src.join("two.txt")],
        Output::Path(archive.clone()),
        FormatId::new("tar"),
        &Default::default(),
    )
    .unwrap();
    assert_eq!(outcome.bytes_in, 11);

    let names: Vec<String> = entries::list(Input::Path(archive.clone()), stuffr::DEFAULT_MAX_RATIO)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["one.txt".to_string(), "two.txt".to_string()]);

    // The round trip is the point: `pack` must not be able to write an
    // archive `extract` would refuse at exit 7.
    let dest = root.join("out");
    entries::extract(Input::Path(archive), &dest, &[], &ExtractOpts::default()).unwrap();
    assert_eq!(std::fs::read(dest.join("one.txt")).unwrap(), b"first");
    assert_eq!(std::fs::read(dest.join("two.txt")).unwrap(), b"second");
}
