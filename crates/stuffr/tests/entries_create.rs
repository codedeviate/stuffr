//! `entries::create_archive`'s write-side contract, at the level where the
//! CLI tests can only see an exit code.
//!
//! Two things are asserted here and nowhere else:
//!
//! 1. **Ownership reaches the archive.** Every container writer in this tree
//!    writes `meta.uid.unwrap_or(0)`, so an entry with no ids does not say
//!    "owner unknown" — it asserts `root:root`. `create_archive` used to hand
//!    the container a hand-built `EntryMeta` with no `uid`/`gid` at all while
//!    returning `FidelityReport::new(Rung::Exact)`, so `pack file.txt` claimed
//!    exact fidelity over a misstatement of ownership. The CLI cannot see this:
//!    `stuffr list` renders name, kind and size only.
//! 2. **The returned report carries real warnings**, rather than the hardcoded
//!    `Rung::Exact` with an empty list it carried before Phase 2c.
#![cfg(feature = "tar")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use stuffr::entries;
use stuffr::ops::{CompressOpts, Input, Output};
use stuffr::{EntryKind, Fidelity, FormatId};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn tmp_dir() -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-create-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn tar() -> FormatId {
    FormatId::new("tar")
}

/// A file named directly on the command line must carry the same ownership a
/// file found by the walk does. They take the same code path now precisely so
/// they cannot disagree; before that they did, and only the walked one was
/// right.
#[cfg(unix)]
#[test]
fn a_named_file_carries_its_ownership_into_the_archive() {
    use std::os::unix::fs::MetadataExt;

    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"notes").unwrap();
    let want = std::fs::metadata(&src).unwrap();

    let out = dir.join("one.tar");
    let report = entries::create_archive(
        std::slice::from_ref(&src),
        Output::Path(out.clone()),
        tar(),
        None,
        &CompressOpts::default(),
    )
    .unwrap();

    let listed = entries::list(Input::Path(out), stuffr::DEFAULT_MAX_RATIO, None).unwrap();
    let e = listed
        .iter()
        .find(|e| e.name == "notes.txt")
        .expect("the file is stored under its final component");
    assert_eq!(
        e.uid,
        Some(want.uid()),
        "the archive must record the file's real owner, not default to root"
    );
    assert_eq!(e.gid, Some(want.gid()), "and its real group");
    assert!(
        report.fidelity.is_lossless(),
        "nothing was lost packing one ordinary file: {:?}",
        report.fidelity.warnings
    );
}

/// The walked case, asserted alongside it: the two must agree, which is the
/// whole reason they share a code path.
#[cfg(unix)]
#[test]
fn a_walked_file_and_a_named_file_agree_about_ownership() {
    use std::os::unix::fs::MetadataExt;

    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("notes.txt"), b"notes").unwrap();
    let want = std::fs::metadata(root.join("notes.txt")).unwrap();

    let out = dir.join("tree.tar");
    entries::create_archive(
        &[root],
        Output::Path(out.clone()),
        tar(),
        None,
        &CompressOpts::default(),
    )
    .unwrap();

    let listed = entries::list(Input::Path(out), stuffr::DEFAULT_MAX_RATIO, None).unwrap();
    let e = listed
        .iter()
        .find(|e| e.name == "proj/notes.txt")
        .expect("the walked file is named beneath its root");
    assert_eq!(e.uid, Some(want.uid()));
    assert_eq!(e.gid, Some(want.gid()));
}

/// An empty directory is a real entry, not an absence: lose it and the tree
/// does not come back the shape it went in.
#[test]
fn an_empty_directory_reaches_the_archive_as_a_directory_entry() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("empty")).unwrap();

    let out = dir.join("empty.tar");
    entries::create_archive(
        &[root],
        Output::Path(out.clone()),
        tar(),
        None,
        &CompressOpts::default(),
    )
    .unwrap();

    let listed = entries::list(Input::Path(out), stuffr::DEFAULT_MAX_RATIO, None).unwrap();
    let e = listed
        .iter()
        .find(|e| e.name.trim_end_matches('/') == "proj/empty")
        .expect("an empty directory must still be stored");
    assert!(matches!(e.kind, EntryKind::Dir), "got {:?}", e.kind);
}

/// `ar` has no directory concept at all. The entry is dropped rather than
/// written as a zero-byte regular file — which would make every entry beneath
/// it unextractable, its parent being a file — and the report says so by name.
#[test]
#[cfg(feature = "ar")]
fn a_directory_packed_into_ar_is_reported_rather_than_written_as_a_file() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/a.txt"), b"a").unwrap();

    let out = dir.join("p.a");
    let report = entries::create_archive(
        &[root],
        Output::Path(out.clone()),
        FormatId::new("ar"),
        None,
        &CompressOpts::default(),
    )
    .unwrap();

    assert!(
        report.fidelity.has_warnings(),
        "dropping two directories silently is exactly the defect this closes"
    );
    let named: Vec<&String> = report
        .fidelity
        .warnings
        .iter()
        .filter_map(|w| match w {
            Fidelity::EntrySkipped { entry, .. } => Some(entry),
            _ => None,
        })
        .collect();
    assert!(
        named.iter().any(|n| *n == "proj") && named.iter().any(|n| *n == "proj/sub"),
        "each dropped directory must be named: {named:?}"
    );

    let listed = entries::list(Input::Path(out), stuffr::DEFAULT_MAX_RATIO, None).unwrap();
    let names: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["proj/sub/a.txt"],
        "the file survives; the directories do not become zero-byte files"
    );
}

/// The summary warning fires on links that are real losses — two names in the
/// archive for one inode — and the report names how many.
#[cfg(unix)]
#[test]
fn hardlinked_entries_are_reported_as_independent_copies() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"shared").unwrap();
    std::fs::hard_link(root.join("a.txt"), root.join("b.txt")).unwrap();

    let out = dir.join("links.tar");
    let report = entries::create_archive(
        &[root],
        Output::Path(out),
        tar(),
        None,
        &CompressOpts::default(),
    )
    .unwrap();

    let text: Vec<String> = report
        .fidelity
        .warnings
        .iter()
        .map(|w| w.to_string())
        .collect();
    assert!(
        text.iter()
            .any(|t| t.contains("hardlinked") && t.contains('2')),
        "two names for one inode must be reported once, with the count: {text:?}"
    );
}

/// A path named on the command line that is neither file nor directory is
/// still a usage error — the user asked for it by name, and there is no entry
/// shape for it. (Met incidentally inside a walk, the same thing is a warning;
/// the two are different questions.)
#[cfg(unix)]
#[test]
fn a_named_socket_is_still_a_usage_error_rather_than_an_empty_archive() {
    let dir = tmp_dir();
    let fifo = dir.join("pipe");
    // `mkfifo` rather than a Rust API: `std::fs` cannot create one, and the
    // test needs a real non-file, non-directory inode.
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must be present to run this test");
    assert!(made.success(), "mkfifo failed");

    let err = entries::create_archive(
        &[fifo],
        Output::Path(dir.join("fifo.tar")),
        tar(),
        None,
        &CompressOpts::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, stuffr::Error::Usage(_)),
        "a named fifo must be refused, not packed as an empty archive: {err}"
    );
}

/// The other half of that rule, and the one that matters more: a fifo met
/// INSIDE a walk is named in the report and **never written**. A skipped
/// item's `meta.name` deliberately carries lossy U+FFFD text where the real
/// name could not be decoded, so writing one would reintroduce exactly the
/// silent-substitution defect the walk exists to avoid — and here it would
/// also materialise a zero-byte regular file where a fifo was.
#[cfg(unix)]
#[test]
fn a_fifo_inside_the_walk_is_reported_and_never_becomes_an_entry() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"a").unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(root.join("pipe"))
        .status()
        .expect("mkfifo must be present to run this test");
    assert!(made.success(), "mkfifo failed");

    let out = dir.join("fifo-tree.tar");
    let report = entries::create_archive(
        &[root],
        Output::Path(out.clone()),
        tar(),
        None,
        &CompressOpts::default(),
    )
    .unwrap();

    let listed = entries::list(Input::Path(out), stuffr::DEFAULT_MAX_RATIO, None).unwrap();
    let names: Vec<String> = listed
        .iter()
        .map(|e| e.name.trim_end_matches('/').to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n == "proj/pipe"),
        "a skipped item must never be written: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "proj/a.txt"),
        "the rest of the tree is still packed: {names:?}"
    );

    let text: Vec<String> = report
        .fidelity
        .warnings
        .iter()
        .map(|w| w.to_string())
        .collect();
    assert!(
        text.iter().any(|t| t.contains("proj/pipe")),
        "what was dropped must be named: {text:?}"
    );
}
