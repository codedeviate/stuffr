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

// ---- Identity, not spelling (0.10.2 Task 2) -------------------------------
//
// On a case-insensitive volume (APFS, the macOS default) `A` and `a` are one
// directory entry, and on a normalisation-insensitive one so are U+00E9 and
// U+0065 U+0301. `MadeByRun` recognises what this run made by `(dev, ino)`
// as well as by exact path, so a folded spelling of an archive-made path is
// the archive contradicting itself (a skip), never "the destination already
// held this" (a usage error). 0.10.1 answered `Usage`, exit 2, for these.

/// Whether `root`'s volume folds case: `probe` written, `PROBE` looked up.
#[cfg(target_os = "macos")]
fn folds_case(root: &Path) -> bool {
    std::fs::write(root.join("probe"), b"").unwrap();
    root.join("PROBE").exists()
}

/// Directory `A`, then file `a`: the archive's own directory is in the way.
/// 0.10.1 missed the exact-path record and answered `Usage`.
#[cfg(target_os = "macos")]
#[test]
fn a_case_folded_directory_conflict_is_attributed_to_the_archive() {
    let root = tmp_dir();
    if !folds_case(&root) {
        return; // a case-sensitive volume: `A` and `a` are two entries
    }
    let archive = write_tar(&root.join("c.tar"), &[dir("A"), file("a", b"hello")]);
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("a self-contradiction is a skip");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("a", &reason_directory_in_the_way("a"))]
    );
    assert!(std::fs::symlink_metadata(dest.join("A")).unwrap().is_dir());
}

/// File `A`, then `a/b`: the archive's own file is above the entry. The
/// ancestor is named as the entry spells it, `a`.
#[cfg(target_os = "macos")]
#[test]
fn a_case_folded_file_above_an_entry_is_attributed_to_the_archive() {
    let root = tmp_dir();
    if !folds_case(&root) {
        return; // a case-sensitive volume: `a/` is a new directory
    }
    let archive = write_tar(
        &root.join("c.tar"),
        &[file("A", b"alpha"), file("a/b", b"beta")],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("a self-contradiction is a skip");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("a/b", &reason_not_a_directory("a", "a/b"))]
    );
    assert_eq!(std::fs::read(dest.join("A")).unwrap(), b"alpha");
}

/// File `README`, then file `readme`: the duplicate rule, worded as the
/// duplicate rule (exit 2 without `--force`; the later entry wins with it),
/// never as a kind conflict with the destination.
#[cfg(target_os = "macos")]
#[test]
fn a_case_folded_duplicate_uses_the_duplicate_wording() {
    let root = tmp_dir();
    if !folds_case(&root) {
        return; // a case-sensitive volume: two distinct files
    }
    let archive = write_tar(
        &root.join("c.tar"),
        &[file("README", b"first"), file("readme", b"second")],
    );

    let dest = root.join("out1");
    let err = extract_with(&archive, &dest, false).expect_err("a duplicate");
    match &err {
        Error::Usage(msg) => {
            assert_eq!(
                *msg,
                format!(
                    "{} already exists; pass --force to overwrite",
                    dest.join("readme").display()
                )
            );
            assert!(!msg.contains("existing directory"), "{msg}");
            assert!(!msg.contains("is not a directory"), "{msg}");
        }
        other => panic!("expected Usage, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 2);
    assert_eq!(std::fs::read(dest.join("README")).unwrap(), b"first");

    let dest = root.join("out2");
    let outcome = extract_with(&archive, &dest, true).expect("the later one wins");
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(std::fs::read(dest.join("readme")).unwrap(), b"second");
}

/// Review Focus 3: U+00E9 (precomposed) and U+0065 U+0301 (decomposed) are
/// one name on a normalisation-insensitive volume. Identity, not spelling,
/// attributes both shapes to the archive.
#[cfg(target_os = "macos")]
#[test]
fn unicode_normalisation_folds_are_attributed_to_the_archive() {
    const PRECOMPOSED: &str = "\u{e9}";
    const DECOMPOSED: &str = "e\u{301}";
    let root = tmp_dir();
    std::fs::write(root.join(format!("probe{PRECOMPOSED}")), b"").unwrap();
    if !root.join(format!("probe{DECOMPOSED}")).exists() {
        return; // the volume distinguishes the two spellings
    }

    let archive = write_tar(
        &root.join("dir.tar"),
        &[dir(PRECOMPOSED), file(DECOMPOSED, b"hello")],
    );
    let dest = root.join("out1");
    let outcome = extract_with(&archive, &dest, false).expect("a self-contradiction is a skip");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped(
            DECOMPOSED,
            &reason_directory_in_the_way(DECOMPOSED)
        )]
    );
    assert!(
        std::fs::symlink_metadata(dest.join(PRECOMPOSED))
            .unwrap()
            .is_dir()
    );

    let below = format!("{DECOMPOSED}/b");
    let archive = write_tar(
        &root.join("above.tar"),
        &[file(PRECOMPOSED, b"alpha"), file(&below, b"beta")],
    );
    let dest = root.join("out2");
    let outcome = extract_with(&archive, &dest, false).expect("a self-contradiction is a skip");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped(&below, &reason_not_a_directory(DECOMPOSED, &below))]
    );
    assert_eq!(std::fs::read(dest.join(PRECOMPOSED)).unwrap(), b"alpha");
}

/// Review Focus 4: what the destination held BEFORE the run is not in the
/// identity index, so a folded spelling of it is still the destination's
/// prior state — a usage error naming the destination path, exit 2, and the
/// user's file or directory untouched. Three shapes: a same-kind duplicate,
/// a directory in the way, a file above the entry.
#[cfg(target_os = "macos")]
#[test]
fn a_destination_file_whose_spelling_folds_stays_destination_held() {
    let root = tmp_dir();
    if !folds_case(&root) {
        return; // a case-sensitive volume: nothing folds
    }

    // The duplicate: `dest/README`, then the archive's `readme`.
    let archive = write_tar(&root.join("dup.tar"), &[file("readme", b"archive")]);
    let dest = root.join("out1");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("README"), b"mine").unwrap();
    let err = extract_with(&archive, &dest, false).expect_err("the destination's file");
    match &err {
        Error::Usage(msg) => assert_eq!(
            *msg,
            format!(
                "{} already exists; pass --force to overwrite",
                dest.join("readme").display()
            )
        ),
        other => panic!("expected Usage, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 2);
    assert_eq!(std::fs::read(dest.join("README")).unwrap(), b"mine");

    // A directory the user had, in the way of the archive's file.
    for force in [false, true] {
        let dest = root.join(format!("out-dir-{force}"));
        std::fs::create_dir_all(dest.join("README")).unwrap();
        std::fs::write(dest.join("README/keep"), b"k").unwrap();
        let err = extract_with(&archive, &dest, force).expect_err("the destination's directory");
        match &err {
            Error::Usage(msg) => assert_eq!(
                *msg,
                format!(
                    "`{}` is an existing directory; stuffr never removes a directory, even \
                     with --force",
                    dest.join("readme").display()
                ),
                "force={force}"
            ),
            other => panic!("force={force}: expected Usage, got {other:?}"),
        }
        assert_eq!(err.exit_code(), 2, "force={force}");
        assert_eq!(std::fs::read(dest.join("README/keep")).unwrap(), b"k");
    }

    // A file the user had, above the archive's entry.
    let archive = write_tar(&root.join("above.tar"), &[file("a/b", b"beta")]);
    for force in [false, true] {
        let dest = root.join(format!("out-above-{force}"));
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("A"), b"mine").unwrap();
        let err = extract_with(&archive, &dest, force).expect_err("the destination's file");
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
        assert_eq!(std::fs::read(dest.join("A")).unwrap(), b"mine");
    }
}

/// Review Focus 1, the shape identity would break: file `a`, a genuine
/// second link `x -> a` (so `nlink` is 2 and the single-name shortcut does
/// not decide), then `A -> a` under `--force`. `dest/A` IS `dest/a`. The
/// self-link check must ask whether the EXACT path `A` was made by this run
/// (it was not), not whether its inode was (it was, as `a`): asked by
/// identity, the link reads as distinct, `--force` removes `a` to make room,
/// and the archive's own `a` is gone.
///
/// Fix round 2: nothing is removed for a same-inode pair whatever the record
/// says. With two names on the inode the run cannot tell a fold of `a` from
/// a fold of `x`, so the skip uses the wording that is true either way.
#[cfg(target_os = "macos")]
#[test]
fn a_case_folded_link_beside_a_second_link_is_skipped_removing_nothing() {
    let root = tmp_dir();
    if !folds_case(&root) {
        return; // a case-sensitive volume: `A` is a third name
    }
    let archive = write_tar(
        &root.join("c.tar"),
        &[file("a", b"alpha"), hardlink("x", "a"), hardlink("A", "a")],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, true).expect("never exit 1");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("A", ALREADY_HOLDS_TARGET)]
    );
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"alpha");
    assert_eq!(ino_nlink(&dest.join("a")), ino_nlink(&dest.join("x")));
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
/// a duplicate link entry under `--force` is satisfied silently. Since fix
/// round 2 that is a no-op — `a` is already `b`'s inode, so nothing is
/// removed or re-linked — and the caller records it as written.
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

/// Fix round 3: a repeated hard-link entry keeps 0.10.0's duplicate rule.
/// Without `--force` it is the usage error an exact duplicate file is
/// (exit 2, "already exists; pass --force"), and nothing is removed; with
/// it, the run succeeds silently. Fix round 2's "already linked" shortcut
/// answered success in BOTH modes, turning the exit 2 into a silent exit 0.
#[cfg(unix)]
#[test]
fn a_repeated_link_entry_keeps_the_force_rule() {
    let root = tmp_dir();
    let archive = write_tar(
        &root.join("c.tar"),
        &[file("a", b"hello"), hardlink("l", "a"), hardlink("l", "a")],
    );

    let plain = root.join("out1");
    let err = extract_with(&archive, &plain, false).expect_err("refused");
    assert!(matches!(err, Error::Usage(_)), "{err:?}");
    assert_eq!(err.exit_code(), 2);
    assert!(
        err.to_string().contains("already exists; pass --force"),
        "{err}"
    );
    assert_eq!(std::fs::read(plain.join("a")).unwrap(), b"hello");
    assert_eq!(ino_nlink(&plain.join("a")), ino_nlink(&plain.join("l")));

    let forced = root.join("out2");
    let outcome = extract_with(&archive, &forced, true).expect("exit 0");
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(std::fs::read(forced.join("l")).unwrap(), b"hello");
    assert_eq!(ino_nlink(&forced.join("a")), ino_nlink(&forced.join("l")));
}

/// Fix round 2, M2: the parent `n*` is MISSING, so `place_entry`'s probes
/// never reach the over-long final component; it is the arm's own create
/// (`File::create`, `create_symlink`, `create_dir_all`, and the hard-link
/// copy's create after `hard_link` fails) that meets the refusal, through
/// `skip_if_name_refused`.
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

/// 2,000 files, then 2,000 repeated `a -> b` hard-link entries: the archive
/// [`repeated_links_in_a_large_directory_stay_linear`] and its timed
/// reproducer both extract (under `--force`).
#[cfg(unix)]
fn extract_many_repeated_links() -> (PathBuf, stuffr::ops::Outcome, std::time::Duration) {
    let root = tmp_dir();
    let names: Vec<String> = (0..2000).map(|i| format!("f{i}")).collect();
    let mut fixtures: Vec<Fixture<'_>> = names.iter().map(|n| file(n, b"x")).collect();
    fixtures.push(file("b", b"hello"));
    fixtures.extend((0..2000).map(|_| hardlink("a", "b")));
    let archive = write_tar(&root.join("many.tar"), &fixtures);
    let dest = root.join("out");

    let started = std::time::Instant::now();
    let outcome = extract_with(&archive, &dest, true).unwrap();
    (dest, outcome, started.elapsed())
}

/// Fix round 2, M3: 2,000 repeated `a -> b` entries under `--force`, beside
/// 2,000 other files, all link `a` to `b` with no warning. The self-link
/// check is O(1) per link (the run's own record), not a scan of the link's
/// directory; the wall-clock half of that claim lives in the `#[ignore]`d
/// reproducer below, because a time bound in the gate can flake on a loaded
/// runner.
#[cfg(unix)]
#[test]
fn repeated_links_in_a_large_directory_stay_linear() {
    let (dest, outcome, _) = extract_many_repeated_links();
    assert!(
        outcome.fidelity.warnings.is_empty(),
        "{:?}",
        outcome.fidelity.warnings
    );
    assert_eq!(ino_nlink(&dest.join("a")), ino_nlink(&dest.join("b")));
}

/// The timing reproducer for the test above, on demand:
/// `cargo test -p stuffr --test entries_extract -- --ignored
/// repeated_links_timing`. Measured in debug on APFS at 0.10.1: ~1.07 s
/// (~0.27 s is the 2,000 files, then ~0.4 ms per link, which was the
/// unlink/link syscalls); the per-link directory scan it replaced took
/// ~2.69 s. Since 0.10.2's fix round 2 a repeated link is a no-op (two
/// `symlink_metadata` calls, no unlink or link), so the per-link cost is
/// lower still. The bound is generous: it catches a catastrophic
/// regression, not a 2x.
#[cfg(unix)]
#[test]
#[ignore = "wall-clock bound; run on demand, not in the gate"]
fn repeated_links_timing_reproducer() {
    let (_, outcome, took) = extract_many_repeated_links();
    eprintln!("repeated_links_timing_reproducer: {took:?}");
    assert!(outcome.fidelity.warnings.is_empty());
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
}

/// Fix round 3: the run's record is keyed by exact path and never
/// un-records. On a case-insensitive volume, file `a`, then file `A` (which
/// replaces `a` on disk under `--force`), then link `A -> a`: the record
/// holds both spellings for one file. The single-link inode check decides
/// first, so the link is a self-link skip and the file keeps `A`'s bytes.
/// Trusting the record (fix round 2) removed the one file, then found
/// nothing to link or copy and skipped the link: exit 0 with the file
/// silently gone — data loss reported as success, not an exit 1.
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

/// 0.10.2 final review, I1: file `A`, file `a`, link `l -> a`, link
/// `A -> a`, under `--force`, on a case-insensitive volume. `a` replaces the
/// run-made `A` (one directory entry), but the exact-path record kept a
/// STALE key `A`. `l` raised `a`'s link count to 2, so `A -> a` passed the
/// same-inode test, skipped the one-name return, and the stale key called
/// `A` a distinct name this run made. `--force` removed it — `a`'s only
/// directory entry — and `hard_link` and the copy fallback found nothing:
/// exit 0, only `l` left, and no warning naming `a`.
///
/// The correct semantics: `A` is `a` under another spelling, so the link
/// entry `A -> a` is skipped and named, removing nothing. `a` keeps its
/// bytes at `a`, and `l` is a genuine second link to it. The run succeeds
/// (exit 0 at the CLI; exit 4 only under `--strict-fidelity`, for the one
/// skip warning). With two names on the inode the run cannot tell a fold of
/// `a` from a fold of `l` (fix round 2), so the wording is the neutral one.
#[cfg(target_os = "macos")]
#[test]
fn a_stale_case_folded_record_never_removes_the_link_target() {
    let root = tmp_dir();
    if !folds_case(&root) {
        return; // a case-sensitive volume: `A` and `a` are two files
    }
    let archive = write_tar(
        &root.join("c.tar"),
        &[
            file("A", b"first"),
            file("a", b"second"),
            hardlink("l", "a"),
            hardlink("A", "a"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, true).expect("never an error");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("A", ALREADY_HOLDS_TARGET)]
    );
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"second");
    assert_eq!(std::fs::read(dest.join("l")).unwrap(), b"second");
    assert_eq!(ino_nlink(&dest.join("a")), ino_nlink(&dest.join("l")));
    assert_eq!(ino_nlink(&dest.join("a")).1, 2, "a and l, nothing else");
}

/// The skip reason for a link whose path already holds its target under a
/// spelling the run cannot attribute: a fold of the target, or of
/// another link to it. Restated as a literal, as the self-link reason is.
#[cfg(target_os = "macos")]
const ALREADY_HOLDS_TARGET: &str = "its path already holds its hard-link target";

/// Fix round 2: `a`, then `A` (which replaces it under `--force` on a
/// case-folding volume, leaving the TARGET's key `a` stale), `l -> a` (link
/// count 2), then `A -> a`. The link path and the target are one inode, so
/// the state the archive asks for already holds and nothing may be removed.
/// Before, the link's own record (`A`, current) called the pair distinct and
/// `--force` removed `A` — `a`'s only directory entry: exit 0, only `l` left.
/// Now `a`'s bytes (the later `A`'s, which replaced it) stay at `a` and `l`,
/// and the link is skipped and named. Exit 0 at the CLI (4 under
/// `--strict-fidelity`).
#[cfg(target_os = "macos")]
#[test]
fn a_stale_target_record_never_removes_the_link_target() {
    let root = tmp_dir();
    if !folds_case(&root) {
        return; // a case-sensitive volume: four plain names
    }
    let archive = write_tar(
        &root.join("c.tar"),
        &[
            file("a", b"first"),
            file("A", b"second"),
            hardlink("l", "a"),
            hardlink("A", "a"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, true).expect("never an error");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("A", ALREADY_HOLDS_TARGET)]
    );
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"second");
    assert_eq!(std::fs::read(dest.join("l")).unwrap(), b"second");
    assert_eq!(ino_nlink(&dest.join("a")), ino_nlink(&dest.join("l")));
    assert_eq!(ino_nlink(&dest.join("a")).1, 2, "A (alias a) and l");
}

/// Fix round 2: `a`, `l -> a`, `A` (replacing `a`'s directory entry; `l`
/// keeps the first file), `m -> a`, `A -> a`. The same loss as above by
/// another road: `A -> a` removed `A`, `m`'s only sibling name.
#[cfg(target_os = "macos")]
#[test]
fn a_stale_target_record_beside_an_older_link_loses_nothing() {
    let root = tmp_dir();
    if !folds_case(&root) {
        return;
    }
    let archive = write_tar(
        &root.join("c.tar"),
        &[
            file("a", b"first"),
            hardlink("l", "a"),
            file("A", b"second"),
            hardlink("m", "a"),
            hardlink("A", "a"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, true).expect("never an error");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("A", ALREADY_HOLDS_TARGET)]
    );
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"second");
    assert_eq!(std::fs::read(dest.join("m")).unwrap(), b"second");
    assert_eq!(std::fs::read(dest.join("l")).unwrap(), b"first");
    assert_eq!(ino_nlink(&dest.join("a")), ino_nlink(&dest.join("m")));
    assert_eq!(ino_nlink(&dest.join("a")).1, 2);
}

/// Fix round 2, minor: `a`, file `l`, `L -> a` (replacing `l` by fold), then
/// `l -> a`. `l` is really the link `L`, so "names itself" was false; the
/// run cannot tell a fold of the target from a fold of another link, so the
/// wording says only what is true. Nothing is removed.
#[cfg(target_os = "macos")]
#[test]
fn a_folded_name_of_another_link_is_not_called_a_self_link() {
    let root = tmp_dir();
    if !folds_case(&root) {
        return;
    }
    let archive = write_tar(
        &root.join("c.tar"),
        &[
            file("a", b"x"),
            file("l", b"y"),
            hardlink("L", "a"),
            hardlink("l", "a"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, true).expect("never an error");
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped("l", ALREADY_HOLDS_TARGET)]
    );
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"x");
    assert_eq!(std::fs::read(dest.join("L")).unwrap(), b"x");
    assert_eq!(
        ino_nlink(&dest.join("a")),
        (ino_nlink(&dest.join("L")).0, 2)
    );
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

/// The skip never swallows a genuine escape: an absolute target, a leading
/// `..` run past `dest`, and a `..`-after-a-name target that ALSO climbs out
/// lexically all stay exit 7. And the refusal names the ENTRY (the final
/// review's F2) — before, it named the target text (`../..`), which is not
/// a name `stuffr list` shows.
#[test]
fn an_escaping_symlink_target_is_refused_naming_the_entry() {
    for (target, reason) in [
        ("/etc/passwd", "absolute symlink target"),
        ("../../..", "symlink target climbs out of the destination"),
        (
            "../x/../../..",
            "symlink target climbs out of the destination",
        ),
    ] {
        let root = tmp_dir();
        let archive = write_tar(
            &root.join("l.tar"),
            &[dir("sub"), symlink("sub/link", target)],
        );
        let dest = root.join("out");
        let err = entries::extract(
            Input::Path(archive),
            &dest,
            &Selection::All,
            &ExtractOpts::default(),
        )
        .expect_err(&format!("{target}: an escape must be refused"));
        match &err {
            Error::UnsafePath { path, reason: r } => {
                assert_eq!(path, "sub/link", "{target}: names the entry");
                assert_eq!(*r, reason, "{target}");
            }
            other => panic!("{target}: expected UnsafePath, got {other:?}"),
        }
        assert_eq!(err.exit_code(), 7, "{target}");
        assert_eq!(
            err.to_string(),
            format!("unsafe entry path `sub/link` refused: {reason}"),
            "{target}"
        );
        assert!(
            std::fs::symlink_metadata(dest.join("sub/link")).is_err(),
            "{target}: the link must not have been created"
        );
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

/// A name APFS refuses (`EILSEQ`, os error 92): U+07B8 is an unassigned
/// code point it will not store. The entry is skipped with a named reason
/// and its neighbours are written, not an exit 1. Self-detecting: a volume
/// that accepts the name has nothing to skip, so the test returns early.
#[cfg(target_os = "macos")]
#[test]
fn a_name_the_filesystem_refuses_is_skipped_not_an_io_error() {
    let root = tmp_dir();
    let probe = root.join("probe\u{7b8}");
    if std::fs::File::create(&probe).is_ok() {
        return;
    }
    let bad = "bad\u{7b8}name";
    let nested = "new/dir\u{7b8}/f";
    let archive = write_tar(
        &root.join("illegal.tar"),
        &[
            file("a.txt", b"alpha"),
            file(bad, b"x"),
            file(nested, b"y"),
            file("z.txt", b"zulu"),
        ],
    );
    let dest = root.join("out");
    let outcome = extract_with(&archive, &dest, false).expect("skips, never exit 1");
    let reason = "its name is not valid on this filesystem";
    assert_eq!(
        outcome.fidelity.warnings,
        [skipped(bad, reason), skipped(nested, reason)]
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dest.join("z.txt")).unwrap(), b"zulu");
}

// ---- GNU long-name / long-link payloads (0.10.3 Task 5) -------------------
//
// A GNU `L` (long name) or `K` (long link) payload is read whole, so the
// ordinary reader caps its DECLARED size at 16 MiB (`MAX_GNU_LONG_NAME`):
// `ResourceLimit`, exit 6, through `unpack` as through `list`.

const GNU_CEILING: u64 = 16 * 1024 * 1024;

/// One raw GNU header block (`"ustar  \0"` magic), checksum included.
fn gnu_header(name: &str, typeflag: u8, size: u64, link: &str) -> [u8; 512] {
    let mut b = [0u8; 512];
    b[..name.len()].copy_from_slice(name.as_bytes());
    b[100..108].copy_from_slice(b"0000644\0");
    b[108..116].copy_from_slice(b"0000000\0");
    b[116..124].copy_from_slice(b"0000000\0");
    b[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    b[136..148].copy_from_slice(b"14371402000\0");
    b[148..156].copy_from_slice(b"        ");
    b[156] = typeflag;
    b[157..157 + link.len()].copy_from_slice(link.as_bytes());
    b[257..265].copy_from_slice(b"ustar  \0");
    let sum: u32 = b.iter().map(|&x| u32::from(x)).sum();
    b[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    b
}

/// A GNU `L`/`K` member: the header declaring `len`, then `len` payload bytes
/// (NUL-terminated, padded to a block).
fn gnu_long_member(typeflag: u8, len: u64) -> Vec<u8> {
    let mut out = gnu_header("././@LongLink", typeflag, len, "").to_vec();
    let mut payload = vec![b'n'; len as usize];
    if let Some(last) = payload.last_mut() {
        *last = 0;
    }
    payload.resize(payload.len().div_ceil(512) * 512, 0);
    out.extend_from_slice(&payload);
    out
}

/// A tar on disk: the `L` member of `len` bytes, a regular file `short`,
/// and the trailer.
fn tar_with_long_name(dir: &Path, len: u64) -> PathBuf {
    let mut bytes = gnu_long_member(b'L', len);
    bytes.extend_from_slice(&gnu_header("short", b'0', 0, ""));
    bytes.extend_from_slice(&[0u8; 1024]);
    let path = dir.join("long.tar");
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn a_long_name_over_the_ceiling_refuses_unpack_with_exit_6() {
    for typeflag in *b"LK" {
        let dir = tmp_dir();
        let mut bytes = gnu_long_member(typeflag, GNU_CEILING + 1);
        bytes.extend_from_slice(&gnu_header("short", b'0', 0, ""));
        bytes.extend_from_slice(&[0u8; 1024]);
        let archive = dir.join("over.tar");
        std::fs::write(&archive, bytes).unwrap();
        let dest = dir.join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let err =
            extract_with(&archive, &dest, false).expect_err("a long-name payload past the ceiling");
        assert!(matches!(err, Error::ResourceLimit(_)), "{err:?}");
        assert_eq!(err.exit_code(), 6, "{err}");
    }
}

#[test]
fn a_long_name_at_the_ceiling_is_not_a_resource_limit_for_unpack() {
    // A 16 MiB name cannot be created on any filesystem, so the entry is
    // skipped as too long (not an error); what matters is that the ceiling
    // itself is not refused.
    let dir = tmp_dir();
    let archive = tar_with_long_name(&dir, GNU_CEILING);
    let dest = dir.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    if let Err(err) = extract_with(&archive, &dest, false) {
        assert_ne!(err.exit_code(), 6, "exactly the ceiling is allowed: {err}");
    }
}

#[test]
fn a_member_with_both_a_long_name_and_a_long_link_extracts() {
    let dir = tmp_dir();
    let name = format!("{}/{}/link", "a".repeat(120), "b".repeat(120));
    let target = format!("{}/{}", "t".repeat(120), "u".repeat(120));
    let mut bytes = Vec::new();
    for (flag, text) in [(b'L', &name), (b'K', &target)] {
        let mut payload = text.clone().into_bytes();
        payload.push(0);
        bytes.extend_from_slice(&gnu_header("././@LongLink", flag, payload.len() as u64, ""));
        payload.resize(payload.len().div_ceil(512) * 512, 0);
        bytes.extend_from_slice(&payload);
    }
    bytes.extend_from_slice(&gnu_header("short", b'2', 0, "short-target"));
    bytes.extend_from_slice(&[0u8; 1024]);
    let archive = dir.join("both.tar");
    std::fs::write(&archive, bytes).unwrap();
    let dest = dir.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    extract_with(&archive, &dest, false).expect("L and K under the ceiling extract");
    let link = dest.join(&name);
    assert_eq!(std::fs::read_link(&link).unwrap(), Path::new(&target));
}
