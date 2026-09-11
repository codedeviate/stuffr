//! Turning a directory tree into archive entries.
//!
//! Split out of `entries.rs`, which is already ~1200 lines and does enough.
//!
//! `entries::create_archive` is the caller.

use std::path::{Path, PathBuf};

use stuffr_core::{EntryKind, EntryMeta, Result};

/// Where a walked entry's payload comes from, if it has one.
pub(crate) enum ItemSource {
    File(PathBuf),
    Dir,
    Symlink,
    /// Met, named, and deliberately not stored. The reason is a warning for
    /// the user, never an error: one oddly-named file must not fail a whole
    /// backup, and `--strict-fidelity` is what turns these into exit 4 for
    /// anyone who wants that.
    Skipped {
        reason: String,
    },
}

pub(crate) struct WalkItem {
    pub meta: EntryMeta,
    pub source: ItemSource,
    /// `(dev, ino)` for a regular file the filesystem says has more than one
    /// name; `None` for everything else, including a file with a single link.
    ///
    /// Captured DURING the walk, from the stat the walk already performed,
    /// rather than re-stat'ed later: a second stat sees a different instant,
    /// and a file deleted in between would silently change the answer.
    /// [`hardlink_count`] is the only consumer.
    pub link_id: Option<(u64, u64)>,
}

/// Every entry under `root`, named beneath `prefix`, in write order.
///
/// **Depth-first, pre-order, with each directory level sorted.** Both halves
/// are load-bearing:
///
/// - *Sorted*, because `readdir` order is filesystem-dependent and is not
///   alphabetical — on APFS this crate's own fixture comes back as
///   `["empty", "README.md", "src"]`. Sorting is what makes two runs over an
///   unchanged tree produce identical bytes on two machines, which is the
///   project's same-input-same-bytes promise.
/// - *Depth-first*, because it keeps a subtree contiguous. Breadth-first would
///   emit `proj, proj/a, proj/b, proj/a/z`, dropping `proj/b` between `proj/a`
///   and its own contents. GNU tar writes depth-first, and once a codec wraps
///   the tar, locality is exactly what the compressor exploits. Both orders
///   are deterministic, so this is not a reproducibility question.
///
/// A directory is always emitted before anything inside it, so extraction
/// creates parents first.
///
/// # The two symlink rules, which are opposites on purpose
///
/// `root` is stat'ed with [`std::fs::metadata`], which **follows** a symlink:
/// a path named on the command line is followed, so `stuffr pack link-to-dir`
/// packs the tree it points at. Everything *inside* the walk is stat'ed with
/// `symlink_metadata` and a link found there is **stored as a link**, never
/// followed.
///
/// Both are GNU tar's rules and they are not to be unified. `entries.rs` gives
/// the reason for the first (see its `std::fs::metadata` comment): storing the
/// link itself would let `pack` produce an archive `unpack` then refuses at
/// exit 7, and stuffr must not write what it will not read. The second is why
/// no loop detection appears here — a cycle cannot be entered in the first
/// place.
pub(crate) fn walk(root: &Path, prefix: &str) -> Result<Vec<WalkItem>> {
    let mut out = Vec::new();
    // `metadata`, not `symlink_metadata`: see the doc comment above. This is
    // the one stat in this function that follows a link, and it follows it
    // because the caller named this path.
    let root_md = std::fs::metadata(root)?;
    out.push(item_for(prefix.to_string(), root, &root_md));

    let mut stack: Vec<Child> = Vec::new();
    if root_md.is_dir() {
        descend(&mut stack, &mut out, root, prefix, &root_md);
    }

    while let Some(child) = stack.pop() {
        // `symlink_metadata`, never `metadata`: the latter follows the link
        // and would describe the target — wrong size, wrong mode, and a
        // dangling link would error instead of being stored.
        //
        // A failure here is a skip, not an error, for the same reason an
        // unlistable directory is (see `descend`): a directory readable but
        // not searchable (mode 0o444) lists its children's names and then
        // refuses to stat any of them, and one such directory must not fail
        // a whole backup. There is no metadata to carry, so the item exists
        // only to name what was missed.
        let md = match std::fs::symlink_metadata(&child.path) {
            Ok(md) => md,
            Err(e) => {
                out.push(WalkItem {
                    meta: EntryMeta {
                        name: child.name.text.clone(),
                        kind: EntryKind::Other,
                        ..Default::default()
                    },
                    source: ItemSource::Skipped {
                        reason: format!("could not be examined ({e}); it is not stored"),
                    },
                    link_id: None,
                });
                continue;
            }
        };
        if !child.name.is_utf8 {
            // Skipped rather than fatal, and skipped rather than stored under
            // the lossy name. A subtree under an undecodable directory goes
            // with it: naming its children would mean writing the replacement
            // character into the archive as if it were the real name.
            out.push(WalkItem {
                meta: EntryMeta {
                    kind: EntryKind::Other,
                    ..base_meta(child.name.text, &md)
                },
                source: ItemSource::Skipped {
                    reason: "name is not valid UTF-8; neither it nor anything \
                             below it is stored"
                        .into(),
                },
                link_id: None,
            });
            continue;
        }
        let is_dir = md.is_dir();
        out.push(item_for(child.name.text.clone(), &child.path, &md));
        if is_dir {
            descend(&mut stack, &mut out, &child.path, &child.name.text, &md);
        }
    }
    Ok(out)
}

/// Queues `dir`'s children for the walk, or records why there are none to
/// queue.
///
/// **An unlistable directory is a skip, never an error.** Backing up a home
/// directory with one root-owned subdirectory in it is the ordinary case, and
/// a `?` here turned that into a failed backup — which contradicts the
/// philosophy written into [`ItemSource::Skipped`]'s own doc comment, and
/// which every other thing this walk cannot store already follows.
///
/// The directory ITSELF has already been pushed by the caller and is stored,
/// so extraction still recreates it; what is lost is its contents, and the
/// warning says exactly that.
fn descend(
    stack: &mut Vec<Child>,
    out: &mut Vec<WalkItem>,
    dir: &Path,
    dir_name: &str,
    md: &std::fs::Metadata,
) {
    match children_of(dir, dir_name) {
        Ok(kids) => push_children(stack, kids),
        Err(e) => out.push(WalkItem {
            meta: EntryMeta {
                kind: EntryKind::Dir,
                ..base_meta(dir_name.to_string(), md)
            },
            source: ItemSource::Skipped {
                reason: format!(
                    "contents could not be listed ({e}); the directory itself is \
                     stored, nothing below it is"
                ),
            },
            link_id: None,
        }),
    }
}

/// An entry name, and whether it survived the trip out of the OS intact.
struct EntryName {
    /// Lossy when `is_utf8` is false, in which case the item is skipped and
    /// this text only ever reaches a warning message.
    text: String,
    is_utf8: bool,
}

/// One child not yet visited.
struct Child {
    path: PathBuf,
    name: EntryName,
}

/// `dir`'s children, named beneath `dir_name`, sorted.
fn children_of(dir: &Path, dir_name: &str) -> Result<Vec<Child>> {
    let mut kids: Vec<(std::ffi::OsString, PathBuf)> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| (e.file_name(), e.path())))
        .collect::<std::io::Result<Vec<_>>>()?;
    // Sorted on the raw OS bytes rather than on the lossy rendering: two
    // undecodable names can render identically and would then order
    // unpredictably, which is the determinism this sort exists to provide.
    kids.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(kids
        .into_iter()
        .map(|(file_name, path)| Child {
            name: name_for(dir_name, &file_name),
            path,
        })
        .collect())
}

/// The entry name for `file_name` inside `dir_name`, and whether the OS name
/// survived the trip intact.
///
/// Split out of [`children_of`] so the decision can be tested without a
/// filesystem that will hold an undecodable name — APFS will not: it rejects
/// `b"bad\xff"` at the syscall with `EILSEQ`, so the walk-level test for this
/// can only run on Linux.
fn name_for(dir_name: &str, file_name: &std::ffi::OsStr) -> EntryName {
    match file_name.to_str() {
        Some(s) => EntryName {
            text: format!("{dir_name}/{s}"),
            is_utf8: true,
        },
        None => EntryName {
            text: format!("{dir_name}/{}", file_name.to_string_lossy()),
            is_utf8: false,
        },
    }
}

/// Pushes a sorted child list so the first of them is visited first.
///
/// Reversed, because a `Vec` stack pops last-in first. This is the whole of
/// what makes the traversal depth-first *and* sorted at once.
fn push_children(stack: &mut Vec<Child>, kids: Vec<Child>) {
    stack.extend(kids.into_iter().rev());
}

/// The fields every walked entry carries, whatever its kind.
fn base_meta(name: String, md: &std::fs::Metadata) -> EntryMeta {
    let (uid, gid) = ids_of(md);
    EntryMeta {
        name,
        mtime: md.modified().ok(),
        mode: crate::entries::mode_of(md),
        uid,
        gid,
        ..Default::default()
    }
}

/// The owning user and group, where the platform has them.
///
/// Recorded rather than dropped because every container writer here already
/// consumes them — `tar.rs`, `ar.rs` and `cpio.rs` all call
/// `meta.uid.unwrap_or(0)` — so leaving these `None` does not mean "ownership
/// unknown", it means the archive claims `root:root`. That is a silent loss,
/// and `MetaFields::uid_gid` exists precisely so a loss can be declared.
fn ids_of(md: &std::fs::Metadata) -> (Option<u32>, Option<u32>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (Some(md.uid()), Some(md.gid()))
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        (None, None)
    }
}

fn item_for(name: String, path: &Path, md: &std::fs::Metadata) -> WalkItem {
    let base = base_meta(name, md);
    let ft = md.file_type();
    if ft.is_dir() {
        WalkItem {
            meta: EntryMeta {
                kind: EntryKind::Dir,
                ..base
            },
            source: ItemSource::Dir,
            link_id: None,
        }
    } else if ft.is_symlink() {
        match std::fs::read_link(path) {
            // `into_string`, not `to_string_lossy`. A lossy target is not a
            // near-miss, it is a different path: the restored link would point
            // somewhere else, with no error and a fidelity report still
            // claiming Exact. Refusing to store it is the only honest option.
            Ok(t) => match t.into_os_string().into_string() {
                Ok(target) => WalkItem {
                    meta: EntryMeta {
                        kind: EntryKind::Symlink { target },
                        ..base
                    },
                    source: ItemSource::Symlink,
                    link_id: None,
                },
                Err(raw) => WalkItem {
                    meta: EntryMeta {
                        kind: EntryKind::Other,
                        ..base
                    },
                    source: ItemSource::Skipped {
                        reason: format!(
                            "symlink target is not valid UTF-8 ({raw:?}); storing a \
                             lossy substitute would point the restored link elsewhere"
                        ),
                    },
                    link_id: None,
                },
            },
            Err(e) => WalkItem {
                meta: EntryMeta {
                    kind: EntryKind::Other,
                    ..base
                },
                source: ItemSource::Skipped {
                    reason: format!("unreadable symlink target: {e}"),
                },
                link_id: None,
            },
        }
    } else if ft.is_file() {
        WalkItem {
            meta: EntryMeta {
                size: Some(md.len()),
                kind: EntryKind::File,
                ..base
            },
            source: ItemSource::File(path.to_path_buf()),
            link_id: link_id_of(md),
        }
    } else {
        WalkItem {
            meta: EntryMeta {
                kind: EntryKind::Other,
                ..base
            },
            source: ItemSource::Skipped {
                reason: "not a regular file, directory or symlink (fifo, socket or device node)"
                    .into(),
            },
            link_id: None,
        }
    }
}

/// `(dev, ino)` for a regular file with more than one name, `None` otherwise.
///
/// The `nlink > 1` filter is only a cheap prefilter — it says a file has
/// other names SOMEWHERE, which on its own says nothing about whether any of
/// them is in this walk. [`hardlink_count`] does the grouping that settles
/// that.
fn link_id_of(md: &std::fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (md.nlink() > 1).then(|| (md.dev(), md.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        None
    }
}

/// How many walked entries share an inode with ANOTHER walked entry, and so
/// will be stored as independent copies of the same file.
///
/// Grouped by `(dev, ino)` over the items themselves, not counted from
/// `nlink`. `nlink > 1` says a file has other names somewhere — it says
/// nothing about whether any of them is in this walk — so counting it would
/// report a loss that did not happen for the extremely ordinary case of a
/// source file also linked from a build cache outside the tree being packed.
/// There is nothing to lose there: no archive format can express a link to a
/// name it does not contain, and extracting one file where the original had
/// two names in two places is what every tool does.
///
/// What IS lost, and what this counts, is two names INSIDE the archive that
/// were one inode on disk: no container here writes a hardlink entry, so
/// extraction produces two independent files.
///
/// Reported as ONE summary warning rather than one per entry: on a tree with
/// many links, per-entry warnings would bury every other message. Unix only —
/// `nlink`, `dev` and `ino` have no portable equivalent, so this is 0
/// elsewhere.
pub(crate) fn hardlink_count(items: &[WalkItem]) -> usize {
    let mut groups: std::collections::HashMap<(u64, u64), usize> = std::collections::HashMap::new();
    for id in items.iter().filter_map(|i| i.link_id) {
        *groups.entry(id).or_default() += 1;
    }
    groups.values().filter(|n| **n > 1).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("proj/src")).unwrap();
        std::fs::create_dir(r.join("proj/empty")).unwrap();
        std::fs::write(r.join("proj/README.md"), b"readme").unwrap();
        std::fs::write(r.join("proj/src/main.rs"), b"fn main() {}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("../README.md", r.join("proj/src/link")).unwrap();
        d
    }

    fn names(items: &[WalkItem]) -> Vec<String> {
        items.iter().map(|i| i.meta.name.clone()).collect()
    }

    #[test]
    fn the_named_path_becomes_the_prefix_and_every_entry_sits_under_it() {
        let d = fixture();
        let items = walk(&d.path().join("proj"), "proj").unwrap();
        let names = names(&items);
        assert!(
            names.iter().any(|n| n == "proj"),
            "the root itself is an entry: {names:?}"
        );
        assert!(names.iter().any(|n| n == "proj/README.md"), "{names:?}");
        assert!(names.iter().any(|n| n == "proj/src/main.rs"), "{names:?}");
        assert!(
            names.iter().all(|n| n == "proj" || n.starts_with("proj/")),
            "every entry must sit under the prefix: {names:?}"
        );
        assert!(
            names.iter().all(|n| !n.contains("..")),
            "no entry may contain `..`: {names:?}"
        );
    }

    #[test]
    fn each_directory_level_is_sorted_regardless_of_readdir_order() {
        // The exact slice, not a reproducibility check: `read_dir` over this
        // fixture is already stable within a process (APFS returns
        // `["empty", "README.md", "src"]` twice), so comparing two walks
        // passes with no sort at all. Only the byte order pins the sort —
        // `README.md` < `empty` < `src`, which readdir does NOT produce.
        let d = fixture();
        let items = walk(&d.path().join("proj"), "proj").unwrap();
        let level_1: Vec<String> = names(&items)
            .into_iter()
            .filter(|n| n.matches('/').count() == 1)
            .collect();
        assert_eq!(
            level_1,
            vec!["proj/README.md", "proj/empty", "proj/src"],
            "each level must be sorted by name, not left in readdir order"
        );
    }

    #[test]
    fn the_walk_is_reproducible() {
        let d = fixture();
        let once = names(&walk(&d.path().join("proj"), "proj").unwrap());
        let again = names(&walk(&d.path().join("proj"), "proj").unwrap());
        assert_eq!(once, again, "the walk must be reproducible");
    }

    #[test]
    fn a_subtree_is_contiguous_because_the_walk_is_depth_first() {
        // Its own fixture: the shared one cannot tell the two orders apart,
        // because `src` sorts last and depth-first and breadth-first then
        // coincide. This one puts a sibling AFTER the deep directory.
        //   depth-first:   proj, proj/a, proj/a/z.txt, proj/b.txt
        //   breadth-first: proj, proj/a, proj/b.txt, proj/a/z.txt
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("proj/a")).unwrap();
        std::fs::write(r.join("proj/a/z.txt"), b"z").unwrap();
        std::fs::write(r.join("proj/b.txt"), b"b").unwrap();

        let items = walk(&r.join("proj"), "proj").unwrap();
        assert_eq!(
            names(&items),
            vec!["proj", "proj/a", "proj/a/z.txt", "proj/b.txt"],
            "a directory's contents must follow it immediately, not after its siblings"
        );
    }

    #[test]
    fn a_directory_precedes_everything_inside_it() {
        let d = fixture();
        let names = names(&walk(&d.path().join("proj"), "proj").unwrap());
        let dir_at = names
            .iter()
            .position(|n| n == "proj/src")
            .expect("src listed");
        let file_at = names
            .iter()
            .position(|n| n == "proj/src/main.rs")
            .expect("main.rs listed");
        assert!(
            dir_at < file_at,
            "a directory must precede its contents: {names:?}"
        );
    }

    #[test]
    fn an_empty_directory_survives_the_walk() {
        let d = fixture();
        let items = walk(&d.path().join("proj"), "proj").unwrap();
        let e = items
            .iter()
            .find(|i| i.meta.name == "proj/empty")
            .expect("an empty directory must still be stored, or extraction loses it");
        assert!(matches!(e.meta.kind, EntryKind::Dir));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_stored_as_a_link_and_never_followed() {
        let d = fixture();
        let items = walk(&d.path().join("proj"), "proj").unwrap();
        let l = items
            .iter()
            .find(|i| i.meta.name == "proj/src/link")
            .expect("link listed");
        match &l.meta.kind {
            EntryKind::Symlink { target } => assert_eq!(target, "../README.md"),
            other => panic!("a symlink must be stored as one, got {other:?}"),
        }
        assert!(matches!(l.source, ItemSource::Symlink));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_the_walk_is_not_descended_into() {
        // The link resolves to a REAL directory with a file in it, so a
        // rewrite that followed links would terminate and add `proj/link/file`
        // — failing this equality cleanly. A dangling link would instead make
        // such a rewrite fail on an unrelated `?`, and a cycle would make it
        // hang rather than assert. The exact-names form also fails an
        // implementation that dropped symlinks altogether.
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir(r.join("proj")).unwrap();
        std::fs::create_dir(r.join("other")).unwrap();
        std::fs::write(r.join("other/file"), b"x").unwrap();
        std::os::unix::fs::symlink("../other", r.join("proj/link")).unwrap();

        let items = walk(&r.join("proj"), "proj").unwrap();
        assert_eq!(
            names(&items),
            vec!["proj", "proj/link"],
            "the walk descended through a symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_named_as_the_root_is_followed_like_the_command_line_expects() {
        // The opposite of the rule above, and deliberately so: `entries.rs`
        // follows a path named on the command line, because storing the link
        // itself would produce an archive `unpack` refuses at exit 7.
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir(r.join("real")).unwrap();
        std::fs::write(r.join("real/file"), b"x").unwrap();
        std::os::unix::fs::symlink("real", r.join("proj")).unwrap();

        let items = walk(&r.join("proj"), "proj").unwrap();
        assert_eq!(
            names(&items),
            vec!["proj", "proj/file"],
            "a symlink named as the root must be followed, not stored as a link"
        );
        assert!(matches!(items[0].meta.kind, EntryKind::Dir));
    }

    #[cfg(unix)]
    #[test]
    fn an_undecodable_filename_is_flagged_rather_than_silently_rendered() {
        // The half of the undecodable-name rule that needs no filesystem, and
        // so runs on every unix. `OsStr::from_bytes` is not a syscall — APFS
        // would refuse to *store* this name (EILSEQ), but nothing stops the
        // naming decision being made about it here.
        use std::os::unix::ffi::OsStrExt;
        let n = name_for("proj", std::ffi::OsStr::from_bytes(b"bad\xff"));
        assert!(
            !n.is_utf8,
            "an undecodable name must be flagged, not passed"
        );
        assert!(
            n.text.contains('\u{FFFD}'),
            "the lossy text is for the warning only: {}",
            n.text
        );

        let ok = name_for("proj", std::ffi::OsStr::new("good.txt"));
        assert!(ok.is_utf8);
        assert_eq!(ok.text, "proj/good.txt");
    }

    // Linux only, and not as a convenience: APFS enforces UTF-8 filenames and
    // rejects `b"bad\xff"` at the syscall with `EILSEQ` (errno 92, measured —
    // `std::fs::write` returns `Os { code: 92, message: "Illegal byte
    // sequence" }`), so this input cannot be constructed on macOS at all. A
    // `cfg` rather than a runtime skip, so that on CI's Linux runners it
    // always runs instead of being able to fail open.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_non_utf8_filename_is_skipped_not_fatal() {
        use std::os::unix::ffi::OsStrExt;
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir(r.join("proj")).unwrap();
        std::fs::write(r.join("proj/good.txt"), b"good").unwrap();
        std::fs::write(
            r.join("proj").join(std::ffi::OsStr::from_bytes(b"bad\xff")),
            b"bad",
        )
        .unwrap();

        let items = walk(&r.join("proj"), "proj").expect("one odd name must not fail the walk");
        assert!(
            items.iter().any(|i| i.meta.name == "proj/good.txt"),
            "the rest of the tree must still be packed: {:?}",
            names(&items)
        );
        let bad = items
            .iter()
            .find(|i| i.meta.name.contains('\u{FFFD}'))
            .expect("the undecodable name must still be reported");
        match &bad.source {
            ItemSource::Skipped { reason } => assert!(
                reason.contains("UTF-8"),
                "the reason must say why: {reason}"
            ),
            _ => panic!("an undecodable name must be skipped, not stored"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_symlink_target_is_skipped_never_lossily_substituted() {
        use std::os::unix::ffi::OsStrExt;
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir(r.join("proj")).unwrap();
        std::os::unix::fs::symlink(
            std::ffi::OsStr::from_bytes(b"\xff\xfe"),
            r.join("proj/link"),
        )
        .unwrap();

        let items = walk(&r.join("proj"), "proj").unwrap();
        let l = items
            .iter()
            .find(|i| i.meta.name == "proj/link")
            .expect("link listed");
        if let EntryKind::Symlink { target } = &l.meta.kind {
            panic!(
                "a lossy target was stored as fact: {target:?} — the restored \
                 link would point somewhere else"
            );
        }
        assert!(
            matches!(l.source, ItemSource::Skipped { .. }),
            "an undecodable target must be skipped"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ownership_is_recorded_where_the_platform_has_it() {
        // Every container writer calls `meta.uid.unwrap_or(0)`, so `None` here
        // does not mean "unknown" — it means the archive claims root:root.
        use std::os::unix::fs::MetadataExt;
        let d = fixture();
        let items = walk(&d.path().join("proj"), "proj").unwrap();
        let f = items
            .iter()
            .find(|i| i.meta.name == "proj/README.md")
            .unwrap();
        let md = std::fs::metadata(d.path().join("proj/README.md")).unwrap();
        assert_eq!(f.meta.uid, Some(md.uid()));
        assert_eq!(f.meta.gid, Some(md.gid()));
    }
    /// `hardlink_count` measures what the ARCHIVE loses, not what the
    /// filesystem happens to have: two names for one inode, both inside the
    /// walk, become two independent copies on extraction because no
    /// container here writes a hardlink entry.
    #[cfg(unix)]
    #[test]
    fn two_names_for_one_inode_inside_the_walk_are_counted() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir(r.join("proj")).unwrap();
        std::fs::write(r.join("proj/a.txt"), b"shared").unwrap();
        std::fs::hard_link(r.join("proj/a.txt"), r.join("proj/b.txt")).unwrap();

        let items = walk(&r.join("proj"), "proj").unwrap();
        assert_eq!(
            hardlink_count(&items),
            2,
            "both names are stored, and neither will share an inode after extraction"
        );
    }

    /// The over-count this function used to have. A file with a second name
    /// OUTSIDE the walk has `nlink > 1` and loses nothing: no archive format
    /// can express a link to a name it does not contain, so reporting it
    /// would be a warning about something that did not happen — on a source
    /// tree also linked from a build cache, on every single file.
    #[cfg(unix)]
    #[test]
    fn a_file_linked_only_outside_the_walk_is_not_counted() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir(r.join("proj")).unwrap();
        std::fs::create_dir(r.join("cache")).unwrap();
        std::fs::write(r.join("proj/a.txt"), b"shared").unwrap();
        std::fs::hard_link(r.join("proj/a.txt"), r.join("cache/a.txt")).unwrap();
        assert_eq!(
            std::fs::metadata(r.join("proj/a.txt")).unwrap().nlink(),
            2,
            "the premise of this test: the file really does have two names"
        );

        let items = walk(&r.join("proj"), "proj").unwrap();
        assert_eq!(
            hardlink_count(&items),
            0,
            "a link outside the walk costs the archive nothing"
        );
    }

    /// Backing up a home directory with one root-owned subdirectory in it is
    /// the ordinary case, and it must not fail.
    #[cfg(unix)]
    #[test]
    fn an_unlistable_directory_is_skipped_and_the_rest_of_the_tree_still_walks() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("proj/locked")).unwrap();
        std::fs::write(r.join("proj/locked/secret.txt"), b"s").unwrap();
        std::fs::write(r.join("proj/open.txt"), b"o").unwrap();
        std::fs::set_permissions(
            r.join("proj/locked"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        // Loud rather than skipped: running as root would make the directory
        // listable and prove nothing, and a silent skip is how a test starts
        // passing against a broken implementation.
        assert!(
            std::fs::read_dir(r.join("proj/locked")).is_err(),
            "this test needs a non-root user; the directory is still listable"
        );

        let items = walk(&r.join("proj"), "proj").expect("one locked directory must not fail");
        // Restored before the TempDir's own recursive delete runs.
        std::fs::set_permissions(
            r.join("proj/locked"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        assert!(
            items
                .iter()
                .any(|i| i.meta.name == "proj/open.txt" && matches!(i.source, ItemSource::File(_))),
            "the rest of the tree must still be packed: {:?}",
            names(&items)
        );
        assert!(
            items
                .iter()
                .any(|i| i.meta.name == "proj/locked" && matches!(i.source, ItemSource::Dir)),
            "the directory itself is stored, so extraction recreates it: {:?}",
            names(&items)
        );
        let skip = items
            .iter()
            .find(|i| matches!(i.source, ItemSource::Skipped { .. }))
            .expect("the loss must be reported, not swallowed");
        match &skip.source {
            ItemSource::Skipped { reason } => assert!(
                reason.contains("could not be listed"),
                "the reason must say what was missed: {reason}"
            ),
            _ => unreachable!(),
        }
    }

    /// The other half of the same rule: a directory that can be LISTED but
    /// not searched (mode 0o444) hands back its children's names and then
    /// refuses to stat any of them.
    #[cfg(unix)]
    #[test]
    fn a_child_that_cannot_be_stated_is_skipped_rather_than_failing_the_walk() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("proj/nosearch")).unwrap();
        std::fs::write(r.join("proj/nosearch/inner.txt"), b"i").unwrap();
        std::fs::set_permissions(
            r.join("proj/nosearch"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        assert!(
            std::fs::read_dir(r.join("proj/nosearch")).is_ok(),
            "the premise: a readable directory still lists its children"
        );
        assert!(
            std::fs::symlink_metadata(r.join("proj/nosearch/inner.txt")).is_err(),
            "this test needs a non-root user; the child is still stat-able"
        );

        let items = walk(&r.join("proj"), "proj").expect("an unstat-able child must not fail");
        std::fs::set_permissions(
            r.join("proj/nosearch"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        let skip = items
            .iter()
            .find(|i| i.meta.name == "proj/nosearch/inner.txt")
            .expect("the child must still be named in the report");
        match &skip.source {
            ItemSource::Skipped { reason } => assert!(
                reason.contains("could not be examined"),
                "the reason must say what was missed: {reason}"
            ),
            _ => panic!("a child that cannot be stat'ed must not be stored"),
        }
    }
}
