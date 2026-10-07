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

use stuffr::entries::{self, ExtractOpts, Selection};
use stuffr::ops::{Input, Output};
use stuffr::{EntryKind, EntryMeta, Error, Fidelity, FormatId};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn tmp_dir() -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-extract-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// One entry to write into a fixture archive.
struct Fixture<'a> {
    name: &'a str,
    kind: EntryKind,
    data: &'a [u8],
    /// Set explicitly on every fixture: extraction restores an entry's mode,
    /// so a directory left to `tar`'s default (0o644, no execute bit) would
    /// extract into one nothing can be read out of afterwards.
    mode: u32,
}

fn file<'a>(name: &'a str, data: &'a [u8]) -> Fixture<'a> {
    Fixture {
        name,
        kind: EntryKind::File,
        data,
        mode: 0o644,
    }
}

fn dir(name: &str) -> Fixture<'_> {
    Fixture {
        name,
        kind: EntryKind::Dir,
        data: b"",
        mode: 0o755,
    }
}

fn symlink<'a>(name: &'a str, target: &str) -> Fixture<'a> {
    Fixture {
        name,
        kind: EntryKind::Symlink {
            target: target.to_string(),
        },
        data: b"",
        mode: 0o777,
    }
}

/// Writes `entries` into a real `.tar`, names stored verbatim.
fn write_tar(path: &Path, entries: &[Fixture<'_>]) -> PathBuf {
    let tar = FormatId::new("tar");
    let container = stuffr::registry().require_container(tar).unwrap();
    let file = std::fs::File::create(path).unwrap();
    let mut archive = container
        .create(stuffr::PlainSink::new(Box::new(file)), &Default::default())
        .unwrap();
    for entry in entries {
        let mut data = entry.data;
        archive
            .add(
                &EntryMeta {
                    name: entry.name.to_string(),
                    size: Some(entry.data.len() as u64),
                    kind: entry.kind.clone(),
                    mode: Some(entry.mode),
                    mtime: Some(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000),
                    ),
                    ..Default::default()
                },
                &mut data,
            )
            .unwrap();
    }
    archive.finish().unwrap().finish().unwrap();
    path.to_path_buf()
}

#[test]
fn a_traversing_entry_is_refused_as_a_typed_unsafe_path_naming_itself() {
    let root = tmp_dir();
    let archive = write_tar(&root.join("evil.tar"), &[file("../escaped.txt", b"pwned")]);
    let dest = root.join("out");

    let err = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
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

    let err = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
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

    let outcome = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
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
        &Selection::Names(vec!["b.txt".to_string()]),
        &ExtractOpts::default(),
    )
    .unwrap();
    assert!(!dest.join("a.txt").exists());
    assert_eq!(std::fs::read(dest.join("b.txt")).unwrap(), b"beta");

    let err = entries::extract(
        Input::Path(archive),
        &root.join("out2"),
        &Selection::Names(vec!["nosuch.txt".to_string()]),
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
        &Selection::All,
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
        None,
        &Default::default(),
    )
    .unwrap();
    assert_eq!(outcome.bytes_in, 11);

    let names: Vec<String> = entries::list(
        Input::Path(archive.clone()),
        stuffr::DEFAULT_MAX_RATIO,
        None,
    )
    .unwrap()
    .0
    .into_iter()
    .map(|e| e.name)
    .collect();
    assert_eq!(names, vec!["one.txt".to_string(), "two.txt".to_string()]);

    // The round trip is the point: `pack` must not be able to write an
    // archive `extract` would refuse at exit 7.
    let dest = root.join("out");
    entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
    .unwrap();
    assert_eq!(std::fs::read(dest.join("one.txt")).unwrap(), b"first");
    assert_eq!(std::fs::read(dest.join("two.txt")).unwrap(), b"second");
}

#[test]
fn what_extraction_could_not_restore_reaches_the_outcome_report() {
    // `--strict-fidelity` gates on `Outcome::fidelity`, so a warning recorded
    // anywhere else would be worse than none: it would look handled.
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("lossy.tar"),
        &[file("a.txt", b"alpha"), symlink("link", "a.txt")],
    );
    let dest = root.join("out");

    let outcome = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
    .unwrap();

    assert!(
        outcome.fidelity.has_warnings(),
        "a symlink's own mode and mtime cannot be restored, and that is a loss"
    );
    let named = outcome.fidelity.warnings.iter().any(|w| match w {
        Fidelity::MetadataIncomplete { entry, fields } => entry == "link" && fields.mtime,
        _ => false,
    });
    assert!(
        named,
        "the report must name the entry and the field: {:?}",
        outcome.fidelity.warnings
    );
    // The file entry lost nothing, so it must NOT appear: a report that
    // warned about everything would be as useless as one that warned about
    // nothing.
    let clean = outcome.fidelity.warnings.iter().any(|w| match w {
        Fidelity::MetadataIncomplete { entry, .. } => entry == "a.txt",
        _ => false,
    });
    assert!(!clean, "a fully restored entry must raise no warning");
}

/// Directory metadata used to be applied in ARCHIVE order (parent before
/// child, the order a real tar writer emits a tree in), which meant a parent
/// chmod'd to something without the execute bit ran BEFORE its child was
/// reopened to have its own metadata applied — and `File::open` needs execute
/// permission on every ancestor to traverse into a child at all, so the child
/// silently fell back to the umask default and was reported as having lost
/// its mtime and mode, when nothing about the child itself was ever the
/// problem. Fixed by sorting `deferred_dirs` deepest-path-first (by
/// component count) rather than merely reversing archive order — see
/// `an_out_of_order_archive_still_applies_children_before_their_parent`
/// below for why reversal alone was not enough.
#[test]
fn a_restrictive_parent_directory_does_not_block_its_childs_own_metadata() {
    let root = tmp_dir();
    let mut locked = dir("locked");
    locked.mode = 0o400; // read-only, no execute: makes the parent untraversable
    let child = dir("locked/child");
    let archive = write_tar(&root.join("restrictive.tar"), &[locked, child]);
    let dest = root.join("out");

    let outcome = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
    .unwrap();

    assert!(
        !outcome.fidelity.has_warnings(),
        "both directories' metadata are fully restorable once children are handled first: {:?}",
        outcome.fidelity.warnings
    );

    // Confirm the parent really did end up locked down, so this isn't just
    // "the mode was never applied at all" passing vacuously.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dest.join("locked"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o400,
            "the parent's own mode must have been applied"
        );
        // Restore execute so anything cleaning up the temp dir afterward can
        // still traverse it.
        std::fs::set_permissions(dest.join("locked"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
}

/// The reason sorting by depth replaced reversing archive order: `.rev()`
/// only fixes the bug above because a real tar writer lists a parent before
/// its children, so reversing encounter order happens to put children
/// first. An archive that lists the CHILD directory before its parent (this
/// fixture does exactly that) would make `.rev()` process the PARENT first
/// again — reinstating the original bug for this one ordering. Sorting by
/// component count is correct regardless of which order the archive lists
/// them in.
#[test]
fn an_out_of_order_archive_still_applies_children_before_their_parent() {
    let root = tmp_dir();
    let mut locked = dir("locked");
    locked.mode = 0o400; // read-only, no execute: makes the parent untraversable
    let child = dir("locked/child");
    // Child pushed BEFORE its parent — the encounter order `.rev()` alone
    // would get wrong.
    let archive = write_tar(&root.join("out-of-order.tar"), &[child, locked]);
    let dest = root.join("out");

    let outcome = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
    .unwrap();

    assert!(
        !outcome.fidelity.has_warnings(),
        "both directories' metadata must be restorable regardless of archive order: {:?}",
        outcome.fidelity.warnings
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dest.join("locked"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o400,
            "the parent's own mode must have been applied"
        );
        std::fs::set_permissions(dest.join("locked"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
}

#[test]
fn an_archive_whose_metadata_is_fully_restored_reports_no_warnings() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("clean.tar"),
        &[dir("sub/"), file("sub/a.txt", b"alpha")],
    );
    let dest = root.join("out");

    let outcome = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
    .unwrap();
    assert!(
        !outcome.fidelity.has_warnings(),
        "nothing was lost, so --strict-fidelity must pass: {:?}",
        outcome.fidelity.warnings
    );
}

// ---- Hard links (0.10.0 Task 8) ------------------------------------------

fn hardlink<'a>(name: &'a str, target: &str) -> Fixture<'a> {
    Fixture {
        name,
        kind: EntryKind::Hardlink {
            target: target.to_string(),
        },
        data: b"",
        mode: 0o644,
    }
}

fn extract_all(archive: PathBuf, dest: &Path) -> stuffr::ops::Outcome {
    entries::extract(
        Input::Path(archive),
        dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
    .unwrap()
}

fn skipped(entry: &str, reason: &str) -> Fidelity {
    Fidelity::EntrySkipped {
        entry: entry.into(),
        reason: reason.into(),
    }
}

#[cfg(unix)]
fn ino_nlink(p: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::symlink_metadata(p).unwrap();
    (md.ino(), md.nlink())
}

#[cfg(unix)]
#[test]
fn a_tar_hard_link_extracts_as_a_real_link() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("l.tar"),
        &[file("b", b"hello"), hardlink("a", "b")],
    );
    let dest = root.join("out");
    let outcome = extract_all(archive, &dest);

    assert!(
        outcome.fidelity.warnings.is_empty(),
        "a recreated link loses nothing: {:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"hello");
    let (ino_a, nlink_a) = ino_nlink(&dest.join("a"));
    let (ino_b, _) = ino_nlink(&dest.join("b"));
    assert_eq!(ino_a, ino_b, "the link and its target must share an inode");
    assert_eq!(nlink_a, 2);
}

/// A GNU-shaped `newc` group: the two empty names first, the data on the last
/// (`c`). The reader holds `a` and `b` back and yields them as links to `c`.
#[cfg(all(unix, feature = "cpio"))]
#[test]
fn a_cpio_group_extracts_as_real_links() {
    fn member(out: &mut Vec<u8>, name: &str, ino: u32, mode: u32, nlink: u32, data: &[u8]) {
        let namesize = name.len() + 1;
        let fields = [
            ino,
            mode,
            0,
            0,
            nlink,
            1_600_000_000,
            data.len() as u32,
            0,
            0,
            0,
            0,
            namesize as u32,
            0,
        ];
        out.extend_from_slice(b"070701");
        for f in fields {
            out.extend_from_slice(format!("{f:08X}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
    let mut bytes = Vec::new();
    member(&mut bytes, "a", 7, 0o100644, 3, b"");
    member(&mut bytes, "b", 7, 0o100644, 3, b"");
    member(&mut bytes, "c", 7, 0o100644, 3, b"hello");
    member(&mut bytes, "TRAILER!!!", 0, 0, 1, b"");

    let root = tmp_dir();
    let archive = root.join("g.cpio");
    std::fs::write(&archive, bytes).unwrap();
    let dest = root.join("out");
    let outcome = extract_all(archive, &dest);

    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    let (ino, nlink) = ino_nlink(&dest.join("c"));
    assert_eq!(nlink, 3, "three names, one inode");
    for name in ["a", "b", "c"] {
        assert_eq!(ino_nlink(&dest.join(name)).0, ino, "{name}");
        assert_eq!(std::fs::read(dest.join(name)).unwrap(), b"hello", "{name}");
    }
}

/// Review Focus 1: `gtar -C d -cf x.tar .` names entries `./b` and writes
/// link targets `./b`. The link resolves by the exact name extraction used.
#[cfg(unix)]
#[test]
fn a_dot_slash_link_resolves_to_its_dot_slash_target() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("l.tar"),
        &[dir("./"), file("./b", b"hello"), hardlink("./a", "./b")],
    );
    let dest = root.join("out");
    let outcome = extract_all(archive, &dest);

    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(ino_nlink(&dest.join("a")), ino_nlink(&dest.join("b")));
    assert_eq!(ino_nlink(&dest.join("a")).1, 2);
}

/// Review Focus 2: a link to an extracted symlink is recreated as a symlink
/// with the same target, never by following it into a link to the file.
#[cfg(unix)]
#[test]
fn a_link_to_a_symlink_becomes_a_symlink() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("l.tar"),
        &[file("t", b"hello"), symlink("s", "t"), hardlink("h", "s")],
    );
    let dest = root.join("out");
    extract_all(archive, &dest);

    let md = std::fs::symlink_metadata(dest.join("h")).unwrap();
    assert!(md.file_type().is_symlink(), "h must be a symlink");
    assert_eq!(
        std::fs::read_link(dest.join("h")).unwrap(),
        PathBuf::from("t")
    );
    assert_eq!(
        ino_nlink(&dest.join("t")).1,
        1,
        "the symlink's target was never hard-linked"
    );
}

#[test]
fn a_link_to_a_directory_is_skipped_and_named() {
    let root = tmp_dir();
    let archive = write_tar(&root.join("l.tar"), &[dir("d"), hardlink("h", "d")]);
    let dest = root.join("out");
    let outcome = extract_all(archive, &dest);

    assert!(
        outcome.fidelity.warnings.contains(&skipped(
            "h",
            "its hard-link target `d` is a directory, which cannot be hard-linked"
        )),
        "{:?}",
        outcome.fidelity.warnings
    );
    assert!(outcome.fidelity.has_warnings(), "--strict-fidelity exits 4");
    assert!(std::fs::symlink_metadata(dest.join("h")).is_err());
}

/// `--index` selects only the link: its target was never extracted.
#[test]
fn a_link_whose_target_was_not_selected_is_skipped_and_named() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("l.tar"),
        &[file("b", b"hello"), hardlink("a", "b")],
    );
    let dest = root.join("out");
    let outcome = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::Indices(vec![1]),
        &ExtractOpts::default(),
    )
    .unwrap();

    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("a", "its hard-link target `b` was not extracted")]
    );
    assert!(outcome.fidelity.has_warnings(), "--strict-fidelity exits 4");
    assert!(std::fs::symlink_metadata(dest.join("a")).is_err());
}

/// Review Focus 3: the link's own path runs through a symlink the archive
/// planted (`e -> d`), so `e/g` is refused exactly as a file entry would be,
/// and nothing is created through `e`.
#[test]
fn a_link_under_a_symlinked_ancestor_is_refused() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("l.tar"),
        &[
            dir("d"),
            file("d/f", b"hello"),
            symlink("e", "d"),
            hardlink("e/g", "d/f"),
        ],
    );
    let dest = root.join("out");
    let err = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
    .expect_err("a link written through a symlink must be refused");
    match &err {
        Error::UnsafePath { path, .. } => assert_eq!(path, "e/g"),
        other => panic!("expected UnsafePath, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 7);
    assert!(std::fs::symlink_metadata(dest.join("d/g")).is_err());
}

/// The map follows the PATH, not just the name: `a` is extracted as a file,
/// then replaced (under `--force`) by a directory entry spelt `./a`. A link
/// to `a` sees the directory, rather than a stale "file" record that would
/// hand `hard_link` and `copy` a directory and fail at exit 1.
#[test]
fn a_link_sees_what_its_target_path_holds_now() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("l.tar"),
        &[file("a", b"hello"), dir("./a"), hardlink("h", "a")],
    );
    let dest = root.join("out");
    let outcome = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts {
            force: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        outcome.fidelity.warnings.contains(&skipped(
            "h",
            "its hard-link target `a` is a directory, which cannot be hard-linked"
        )),
        "{:?}",
        outcome.fidelity.warnings
    );
}

/// An existing file at the link's path is refused without `--force`, as for
/// a file entry, and replaced with it.
#[cfg(unix)]
#[test]
fn a_link_over_an_existing_file_follows_the_force_rules() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("l.tar"),
        &[file("b", b"hello"), hardlink("a", "b")],
    );
    let dest = root.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("a"), b"old").unwrap();
    let err = entries::extract(
        Input::Path(archive.clone()),
        &dest,
        &Selection::Names(vec!["a".into(), "b".into()]),
        &ExtractOpts::default(),
    )
    .expect_err("an existing file is refused without --force");
    assert_eq!(err.exit_code(), 2);

    std::fs::remove_file(dest.join("b")).unwrap();
    entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts {
            force: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"hello");
    assert_eq!(ino_nlink(&dest.join("a")), ino_nlink(&dest.join("b")));
}

/// `test` verifies payloads; a link has none of its own and is not an error,
/// and a link whose target never appeared is not one either.
#[test]
fn test_passes_a_tar_with_hard_links() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("l.tar"),
        &[
            file("b", b"hello"),
            hardlink("a", "b"),
            hardlink("z", "gone"),
        ],
    );
    let outcome = entries::test(Input::Path(archive), stuffr::DEFAULT_MAX_RATIO, None).unwrap();
    assert_eq!(
        outcome.bytes_out, 5,
        "only the target's payload is verified"
    );
}

/// Fix round 1, I3: the spec's exit table has "a hard-link name or target
/// escapes the destination | 7". A relative escape and an absolute target
/// are both refused before anything is looked up, naming the link entry.
#[test]
fn an_escaping_hard_link_target_is_refused_as_unsafe() {
    for target in ["../outside", "/etc/passwd", "a/../../x"] {
        let root = tmp_dir();
        std::fs::write(root.join("outside"), b"outside").unwrap();
        let archive = write_tar(
            &root.join("l.tar"),
            &[file("a", b"hello"), hardlink("h", target)],
        );
        let dest = root.join("out");
        let err = entries::extract(
            Input::Path(archive),
            &dest,
            &Selection::All,
            &ExtractOpts::default(),
        )
        .expect_err("an escaping hard-link target must be refused");
        match &err {
            Error::UnsafePath { path, .. } => assert_eq!(path, "h", "{target}"),
            other => panic!("{target}: expected UnsafePath, got {other:?}"),
        }
        assert_eq!(err.exit_code(), 7, "{target}");
        assert!(
            std::fs::symlink_metadata(dest.join("h")).is_err(),
            "{target}"
        );
    }
}

// ---- Path conflicts (0.10.1 Task 2) --------------------------------------
//
// An archive that contradicts ITSELF on disk (a file onto a directory it
// made, an entry beneath a file it made) is skipped with a named warning and
// the rest is extracted. A conflict with what the DESTINATION already held
// is a usage error, exit 2. Neither is ever exit 1.

fn extract_with(archive: &Path, dest: &Path, force: bool) -> stuffr::Result<stuffr::ops::Outcome> {
    entries::extract(
        Input::Path(archive.to_path_buf()),
        dest,
        &Selection::All,
        &ExtractOpts {
            force,
            ..Default::default()
        },
    )
}

fn reason_not_a_directory(ancestor: &str, name: &str) -> String {
    format!(
        "`{ancestor}`, earlier in this archive, is not a directory, so `{name}` cannot be \
         placed beneath it"
    )
}

fn reason_directory_in_the_way(name: &str) -> String {
    format!("a directory `{name}` from earlier in this archive is in the way")
}

#[test]
fn a_file_onto_an_archive_directory_is_skipped_and_named() {
    let root = tmp_dir();
    let archive = write_tar(&root.join("c.tar"), &[dir("x"), file("x", b"hello")]);
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("a self-contradiction is a skip");

    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("x", &reason_directory_in_the_way("x"))]
    );
    assert!(std::fs::symlink_metadata(dest.join("x")).unwrap().is_dir());
}

#[test]
fn entries_beneath_an_archive_file_are_skipped_in_a_cascade() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("c.tar"),
        &[
            file("a", b"alpha"),
            file("a/b", b"beta"),
            file("a/b/c", b"gamma"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("a cascade is skips");

    assert_eq!(
        outcome.fidelity.warnings,
        [
            skipped("a/b", &reason_not_a_directory("a", "a/b")),
            skipped("a/b/c", &reason_not_a_directory("a", "a/b/c")),
        ]
    );
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"alpha");
}

#[test]
fn a_symlink_and_a_hard_link_beneath_an_archive_file_are_skipped() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("c.tar"),
        &[
            file("a", b"alpha"),
            symlink("a/s", "x"),
            hardlink("a/l", "a"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("both are skips");

    assert_eq!(
        outcome.fidelity.warnings,
        [
            skipped("a/s", &reason_not_a_directory("a", "a/s")),
            skipped("a/l", &reason_not_a_directory("a", "a/l")),
        ]
    );
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"alpha");
}

/// The 0.10.0 regression shape: the link's own path is a directory the
/// archive made. It used to reach `hard_link` and exit 1.
#[test]
fn a_hard_link_onto_an_archive_directory_is_skipped() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("c.tar"),
        &[dir("x"), file("f", b"hello"), hardlink("x", "f")],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("never exit 1");

    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("x", &reason_directory_in_the_way("x"))]
    );
    assert!(std::fs::symlink_metadata(dest.join("x")).unwrap().is_dir());
    assert_eq!(std::fs::read(dest.join("f")).unwrap(), b"hello");
}

/// Review Focus 4, end to end: file `a`, `l -> a`, file `d`, link `d/l2 -> a`.
/// `d/l2` is skipped with the not-a-directory reason; `l` is a real link.
/// (The unit test `a_blocked_link_path_never_reaches_the_copy_fallback` in
/// `entries.rs` proves the link primitive and the copy are never reached.)
#[test]
fn a_blocked_link_path_is_skipped_while_its_target_is_fine() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("c.tar"),
        &[
            file("a", b"alpha"),
            hardlink("l", "a"),
            file("d", b"delta"),
            hardlink("d/l2", "a"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("a skip");

    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("d/l2", &reason_not_a_directory("d", "d/l2"))]
    );
    assert_eq!(std::fs::read(dest.join("l")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dest.join("d")).unwrap(), b"delta");
}

/// Review Focus 3: `--force` never removes a directory the archive made.
#[test]
fn force_never_removes_an_archive_directory() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("c.tar"),
        &[dir("x"), file("x/keep", b"k"), file("x", b"hello")],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, true).expect("still a skip under --force");

    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("x", &reason_directory_in_the_way("x"))]
    );
    assert!(std::fs::symlink_metadata(dest.join("x")).unwrap().is_dir());
    assert_eq!(std::fs::read(dest.join("x/keep")).unwrap(), b"k");
}

/// Review Focus 3's other half: a directory the destination already had is a
/// usage error, with and without `--force`, and it survives.
#[test]
fn a_destination_directory_in_the_way_is_a_usage_error() {
    for force in [false, true] {
        let root = tmp_dir();
        let archive = write_tar(&root.join("c.tar"), &[file("x", b"hello")]);
        let dest = root.join("out");
        std::fs::create_dir_all(dest.join("x")).unwrap();
        std::fs::write(dest.join("x/mine"), b"m").unwrap();

        let err = extract_with(&archive, &dest, force).expect_err("a usage error");
        match &err {
            Error::Usage(msg) => assert_eq!(
                *msg,
                format!(
                    "`{}` is an existing directory; stuffr never removes a directory, even \
                     with --force",
                    dest.join("x").display()
                ),
                "force={force}"
            ),
            other => panic!("force={force}: expected Usage, got {other:?}"),
        }
        assert_eq!(err.exit_code(), 2, "force={force}");
        assert_eq!(std::fs::read(dest.join("x/mine")).unwrap(), b"m");
    }
}

#[test]
fn a_destination_file_above_an_entry_is_a_usage_error() {
    for force in [false, true] {
        let root = tmp_dir();
        let archive = write_tar(&root.join("c.tar"), &[file("a/b", b"beta")]);
        let dest = root.join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("a"), b"mine").unwrap();

        let err = extract_with(&archive, &dest, force).expect_err("a usage error");
        match &err {
            Error::Usage(msg) => assert_eq!(
                *msg,
                format!(
                    "`{}` exists and is not a directory, so `a/b` cannot be placed beneath it",
                    dest.join("a").display()
                ),
                "force={force}"
            ),
            other => panic!("force={force}: expected Usage, got {other:?}"),
        }
        assert_eq!(err.exit_code(), 2, "force={force}");
        assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"mine");
    }
}

/// 0.10.0's documented duplicate-name rule, pinned unchanged: a second file
/// under one name is a usage error without `--force`, and wins with it.
#[test]
fn duplicate_files_keep_the_force_rule() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("c.tar"),
        &[file("x", b"first"), file("x", b"second")],
    );

    let err = extract_with(&archive, &root.join("out1"), false).expect_err("refused");
    assert!(matches!(err, Error::Usage(_)), "{err:?}");
    assert_eq!(err.exit_code(), 2);
    assert!(
        err.to_string().contains("already exists; pass --force"),
        "{err}"
    );

    let dest = root.join("out2");
    let outcome = extract_with(&archive, &dest, true).expect("the later one wins");
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(std::fs::read(dest.join("x")).unwrap(), b"second");
}

/// Review Focus 2: once `a` is a file, every entry beneath it is skipped by
/// the same rule, and the walk is O(depth) per entry, never a rescan of
/// `MadeByRun`.
#[test]
fn a_deep_cascade_stays_linear() {
    let root = tmp_dir();
    let names: Vec<String> = (0..1000).map(|i| format!("a/n{i}")).collect();
    let mut fixtures = vec![file("a", b"alpha")];
    fixtures.extend(names.iter().map(|n| file(n, b"x")));
    let archive = write_tar(&root.join("c.tar"), &fixtures);
    let dest = root.join("out");

    let started = std::time::Instant::now();
    let outcome = extract_with(&archive, &dest, false).expect("every one a skip");
    let took = started.elapsed();

    assert_eq!(outcome.fidelity.warnings.len(), 1000);
    for (w, n) in outcome.fidelity.warnings.iter().zip(&names) {
        assert_eq!(*w, skipped(n, &reason_not_a_directory("a", n)));
    }
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"alpha");
    // Measured at ~23 ms in a debug build (0.10.1): the bound has ~85x
    // headroom, so it catches a quadratic rescan without flaking on a
    // loaded runner.
    assert!(
        took < std::time::Duration::from_secs(2),
        "1000 skips took {took:?}"
    );
}

/// Review Focus 1: directory `A` then file `a` on a case-insensitive volume.
/// `MadeByRun` is keyed by exact path and misses; the filesystem collides.
/// The rule falls through to "the destination's prior state": a usage
/// error, exit 2 — classified, never exit 1.
#[cfg(target_os = "macos")]
#[test]
fn case_insensitive_collision_is_classified() {
    let root = tmp_dir();
    std::fs::write(root.join("probe"), b"").unwrap();
    if !root.join("PROBE").exists() {
        return; // a case-sensitive volume: nothing collides
    }
    let archive = write_tar(&root.join("c.tar"), &[dir("A"), file("a", b"hello")]);
    let dest = root.join("out");
    let err = extract_with(&archive, &dest, false).expect_err("a classified refusal");
    assert!(matches!(err, Error::Usage(_)), "{err:?}");
    assert_eq!(err.exit_code(), 2, "{err}");
    assert!(std::fs::symlink_metadata(dest.join("A")).unwrap().is_dir());
}

// ---- Names the filesystem cannot hold (0.10.1 Task 2, fix round 1) -------

const PATH_TOO_LONG: &str = "its path is too long for this filesystem";

/// A 300-byte component is past every common filesystem's 255-byte limit.
/// It used to end the run at exit 1 ("File name too long"), losing `z.txt`.
#[test]
fn a_name_too_long_for_the_filesystem_is_skipped_and_the_rest_extracted() {
    let root = tmp_dir();
    let long = format!("{}.txt", "L".repeat(300));
    let archive = write_tar(
        &root.join("long.tar"),
        &[
            file("a.txt", b"alpha"),
            file(&long, b"long"),
            file("z.txt", b"zulu"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("a skip, never exit 1");

    assert_eq!(outcome.fidelity.warnings, [skipped(&long, PATH_TOO_LONG)]);
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dest.join("z.txt")).unwrap(), b"zulu");
}

/// Every component fits, the whole path does not: 25 components of 200
/// bytes is past PATH_MAX on macOS (1,024) and Linux (4,096) alike. A long
/// directory component and a symlink are skipped the same way.
#[test]
fn a_path_too_deep_for_the_filesystem_is_skipped_and_the_rest_extracted() {
    let root = tmp_dir();
    let deep = vec!["d".repeat(200); 25].join("/");
    let deep_file = format!("{deep}/f.txt");
    let long_dir = "D".repeat(300);
    let long_link = "S".repeat(300);
    let archive = write_tar(
        &root.join("deep.tar"),
        &[
            file("a.txt", b"alpha"),
            file(&deep_file, b"deep"),
            dir(&long_dir),
            symlink(&long_link, "a.txt"),
            file("z.txt", b"zulu"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("skips, never exit 1");

    assert_eq!(
        outcome.fidelity.warnings,
        [
            skipped(&deep_file, PATH_TOO_LONG),
            skipped(&long_dir, PATH_TOO_LONG),
            skipped(&long_link, PATH_TOO_LONG),
        ]
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dest.join("z.txt")).unwrap(), b"zulu");
}

/// Fix round 1, Minor 2: on a case-insensitive volume, file `A` then hard
/// link `a -> A` under `--force`. `dest/a` IS `dest/A`; removing it to make
/// room for the link used to delete the archive's own file, leaving an empty
/// directory at exit 0. Now the link is a self-link skip and `A` survives.
#[cfg(target_os = "macos")]
#[test]
fn a_case_folded_hard_link_onto_its_own_target_is_a_self_link_skip() {
    let root = tmp_dir();
    std::fs::write(root.join("probe"), b"").unwrap();
    if !root.join("PROBE").exists() {
        return; // a case-sensitive volume: `a` and `A` are two files
    }
    let archive = write_tar(
        &root.join("c.tar"),
        &[file("A", b"orig"), hardlink("a", "A")],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, true).expect("a skip");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("a", "it names itself as its hard-link target")]
    );
    assert_eq!(std::fs::read(dest.join("A")).unwrap(), b"orig");
}

/// The inode check must not mistake a genuine second link for a self-link:
/// a duplicate link entry under `--force` still replaces cleanly, silently.
#[cfg(unix)]
#[test]
fn a_repeated_link_entry_under_force_is_not_a_self_link() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("c.tar"),
        &[file("b", b"hello"), hardlink("a", "b"), hardlink("a", "b")],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, true).unwrap();
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(ino_nlink(&dest.join("a")), ino_nlink(&dest.join("b")));
}

/// Fix round 2, M2: the parent `n*` is MISSING, so `place_entry`'s probes
/// never reach the over-long final component; it is the arm's own create
/// (`File::create`, `create_symlink`, `create_dir_all`, and the hard-link
/// copy's create after `hard_link` fails) that meets the refusal, through
/// `skip_if_name_too_long`.
#[test]
fn an_over_long_final_name_under_a_new_parent_is_skipped_by_every_arm() {
    let root = tmp_dir();
    let long = "L".repeat(300);
    let f = format!("n1/{long}");
    let s = format!("n2/{long}");
    let d = format!("n3/{long}");
    let h = format!("n4/{long}");
    let archive = write_tar(
        &root.join("arms.tar"),
        &[
            file("a.txt", b"alpha"),
            file(&f, b"file"),
            symlink(&s, "x"),
            dir(&d),
            hardlink(&h, "a.txt"),
            file("z.txt", b"zulu"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("skips, never exit 1");

    assert_eq!(
        outcome.fidelity.warnings,
        [
            skipped(&f, PATH_TOO_LONG),
            skipped(&s, PATH_TOO_LONG),
            skipped(&d, PATH_TOO_LONG),
            skipped(&h, PATH_TOO_LONG),
        ]
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dest.join("z.txt")).unwrap(), b"zulu");
}

/// Fix round 2, M3: the self-link check is O(1) per link (the run's own
/// record), not a scan of the link's directory. 2,000 repeated `a -> b`
/// entries under `--force`, beside 2,000 other files. Measured in debug on
/// APFS: ~1.07 s (~0.27 s is the 2,000 files, then ~0.4 ms per link, which
/// is the unlink/link syscalls); the per-link directory scan it replaced
/// took ~2.69 s. The bound is generous on purpose: it catches a
/// catastrophic regression without flaking on a loaded runner.
#[cfg(unix)]
#[test]
fn repeated_links_in_a_large_directory_stay_linear() {
    let root = tmp_dir();
    let names: Vec<String> = (0..2000).map(|i| format!("f{i}")).collect();
    let mut fixtures: Vec<Fixture<'_>> = names.iter().map(|n| file(n, b"x")).collect();
    fixtures.push(file("b", b"hello"));
    fixtures.extend((0..2000).map(|_| hardlink("a", "b")));
    let archive = write_tar(&root.join("many.tar"), &fixtures);
    let dest = root.join("out");

    let started = std::time::Instant::now();
    let outcome = extract_with(&archive, &dest, true).unwrap();
    let took = started.elapsed();
    eprintln!("repeated_links_in_a_large_directory_stay_linear: {took:?}");

    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(ino_nlink(&dest.join("a")), ino_nlink(&dest.join("b")));
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
}

/// Fix round 3: the run's record is keyed by exact path and never
/// un-records. On a case-insensitive volume, file `a`, then file `A` (which
/// replaces `a` on disk under `--force`), then link `A -> a`: the record
/// holds both spellings for one file. The single-link inode check decides
/// first, so the link is a self-link skip and the file keeps `A`'s bytes;
/// trusting the record removed the one file and ended at exit 1.
#[cfg(target_os = "macos")]
#[test]
fn a_case_folded_link_after_a_case_folded_replace_is_a_self_link_skip() {
    let root = tmp_dir();
    std::fs::write(root.join("probe"), b"").unwrap();
    if !root.join("PROBE").exists() {
        return; // a case-sensitive volume: three distinct names
    }
    let archive = write_tar(
        &root.join("c.tar"),
        &[
            file("a", b"first"),
            file("A", b"second"),
            hardlink("A", "a"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, true).expect("never exit 1");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("A", "it names itself as its hard-link target")]
    );
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"second");
}

/// The skip reason `classify_symlink_target` gives a target with `..` after
/// a name. Restated as a literal: the pin must not be derived from the code
/// it checks.
const CLIMBS_AFTER_A_NAME: &str =
    "symlink target uses `..` after a name, which can climb out through another link";

/// The `EntrySkipped` warnings alone; a symlink's lost mode and mtime ride
/// alongside as `MetadataIncomplete`, which these tests do not pin.
fn skips_of(outcome: &stuffr::ops::Outcome) -> Vec<Fidelity> {
    outcome
        .fidelity
        .warnings
        .iter()
        .filter(|w| matches!(w, Fidelity::EntrySkipped { .. }))
        .cloned()
        .collect()
}

/// 0.10.1: a symlink target that climbs AFTER a name is SKIPPED, and the
/// rest of the archive extracted (user ruling 2026-10-07; it aborted the
/// whole unpack at exit 7 until the final fix wave).
///
/// `x/s2 -> ..` is contained (it names `dest`), and `s1 -> x/s2/..` nets to
/// `x` lexically — but the OS resolves `x/s2` first, so `dest/s1` would land
/// on `dest/..`. Both orders: `s1` ahead of `s2` would make a creation-time
/// existence check useless, which is why the rule is about the target's
/// SHAPE. The skipped link is never created, everything else is, and
/// nothing on disk resolves outside `dest`, lexically or physically.
#[cfg(unix)]
#[test]
fn a_symlink_target_climbing_through_another_link_is_skipped() {
    for (tag, s2_first) in [("s2-first", true), ("s1-first", false)] {
        let root = tmp_dir();
        let mut entries = vec![dir("x")];
        if s2_first {
            entries.push(symlink("x/s2", ".."));
            entries.push(symlink("s1", "x/s2/.."));
        } else {
            entries.push(symlink("s1", "x/s2/.."));
            entries.push(symlink("x/s2", ".."));
        }
        entries.push(file("after.txt", b"after"));
        let archive = write_tar(&root.join("chain.tar"), &entries);
        let dest = root.join("out");

        let outcome = entries::extract(
            Input::Path(archive.clone()),
            &dest,
            &Selection::All,
            &ExtractOpts::default(),
        )
        .unwrap_or_else(|e| panic!("{tag}: a skip, not a refusal: {e}"));
        assert_eq!(
            skips_of(&outcome),
            [skipped("s1", CLIMBS_AFTER_A_NAME)],
            "{tag}"
        );
        assert!(
            std::fs::symlink_metadata(dest.join("s1")).is_err(),
            "{tag}: the skipped link must not have been created"
        );
        assert_eq!(
            std::fs::read_link(dest.join("x/s2")).unwrap(),
            Path::new(".."),
            "{tag}: the contained link is extracted"
        );
        assert_eq!(
            std::fs::read(dest.join("after.txt")).unwrap(),
            b"after",
            "{tag}: extraction continues past the skip"
        );
        stuffr_core::testing::check_extraction_contained(&root, &dest, &[&archive])
            .unwrap_or_else(|e| panic!("{tag}: {e}"));
    }
}

/// 0.10.1: an empty symlink target is skipped on every platform — before
/// the fix round, macOS created `l -> ""` at exit 0 and Linux's
/// `symlink(2)` answered ENOENT, which surfaced as `Error::Io`, exit 1; the
/// fix round made it exit 7, and the final fix wave a skip.
#[test]
fn an_empty_symlink_target_is_skipped() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("empty.tar"),
        &[
            file("a.txt", b"alpha"),
            symlink("l", ""),
            file("z.txt", b"zulu"),
        ],
    );
    let dest = root.join("out");
    let outcome = entries::extract(
        Input::Path(archive),
        &dest,
        &Selection::All,
        &ExtractOpts::default(),
    )
    .expect("an empty target is a skip");
    assert_eq!(
        skips_of(&outcome),
        [skipped("l", "symlink target is empty")]
    );
    assert!(
        std::fs::symlink_metadata(dest.join("l")).is_err(),
        "the link must not have been created"
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dest.join("z.txt")).unwrap(), b"zulu");
}
