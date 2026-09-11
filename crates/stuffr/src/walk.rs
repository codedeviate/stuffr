//! Turning a directory tree into archive entries.
//!
//! Split out of `entries.rs`, which is already ~1200 lines and does enough.
//!
//! Nothing calls this yet — wiring it into `pack` is the next task, and until
//! then every item here is dead code that `make lint`'s `-D warnings` would
//! reject. The allow is scoped to this module and comes out with that wiring;
//! it is not a licence to leave genuinely unused code behind afterwards.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use stuffr_core::{EntryKind, EntryMeta, Error, Result};

/// Where a walked entry's payload comes from, if it has one.
pub(crate) enum ItemSource {
    File(PathBuf),
    Dir,
    Symlink,
    Skipped { reason: String },
}

pub(crate) struct WalkItem {
    pub meta: EntryMeta,
    pub source: ItemSource,
}

/// Every entry under `root`, named beneath `prefix`, in write order.
///
/// Breadth is sorted at each level and a directory is emitted before its
/// contents, so extraction creates parents first and two runs over an
/// unchanged tree produce identical bytes — `readdir` order is
/// filesystem-dependent and would silently break the project's
/// same-input-same-bytes promise.
///
/// Symlinks are stored, never followed, which is why no loop detection
/// appears here: a cycle cannot be entered in the first place. Note that this
/// is the opposite of what `entries.rs` does to a path **named on the command
/// line**, which it follows deliberately — see the `std::fs::metadata` comment
/// there. The two rules are GNU tar's, and are not to be unified.
pub(crate) fn walk(root: &Path, prefix: &str) -> Result<Vec<WalkItem>> {
    let mut out = Vec::new();
    let root_md = std::fs::symlink_metadata(root)?;
    out.push(item_for(prefix.to_string(), root, &root_md));

    let mut queue: VecDeque<(PathBuf, String)> = VecDeque::new();
    if root_md.is_dir() {
        queue.push_back((root.to_path_buf(), prefix.to_string()));
    }

    while let Some((dir, dir_name)) = queue.pop_front() {
        let mut kids: Vec<(std::ffi::OsString, PathBuf)> = std::fs::read_dir(&dir)?
            .map(|e| e.map(|e| (e.file_name(), e.path())))
            .collect::<std::io::Result<Vec<_>>>()?;
        kids.sort_by(|a, b| a.0.cmp(&b.0));

        for (file_name, path) in kids {
            let Some(name_str) = file_name.to_str() else {
                return Err(Error::Usage(format!(
                    "`{}` has a name that is not valid UTF-8; entry names must be",
                    path.display()
                )));
            };
            let child_name = format!("{dir_name}/{name_str}");
            // `symlink_metadata`, never `metadata`: the latter follows the
            // link and would describe the target — wrong size, wrong mode,
            // and a dangling link would error instead of being stored.
            let md = std::fs::symlink_metadata(&path)?;
            let is_dir = md.is_dir();
            out.push(item_for(child_name.clone(), &path, &md));
            if is_dir {
                queue.push_back((path, child_name));
            }
        }
    }
    Ok(out)
}

fn item_for(name: String, path: &Path, md: &std::fs::Metadata) -> WalkItem {
    let base = EntryMeta {
        name,
        mtime: md.modified().ok(),
        mode: crate::entries::mode_of(md),
        ..Default::default()
    };
    let ft = md.file_type();
    if ft.is_dir() {
        WalkItem {
            meta: EntryMeta {
                kind: EntryKind::Dir,
                ..base
            },
            source: ItemSource::Dir,
        }
    } else if ft.is_symlink() {
        match std::fs::read_link(path) {
            Ok(t) => {
                let target = t.to_string_lossy().into_owned();
                WalkItem {
                    meta: EntryMeta {
                        kind: EntryKind::Symlink { target },
                        ..base
                    },
                    source: ItemSource::Symlink,
                }
            }
            Err(e) => WalkItem {
                meta: EntryMeta {
                    kind: EntryKind::Other,
                    ..base
                },
                source: ItemSource::Skipped {
                    reason: format!("unreadable symlink target: {e}"),
                },
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
        }
    }
}

/// How many walked entries are hardlinked elsewhere.
///
/// Reported as ONE summary warning rather than one per entry: on a tree with
/// many links, per-entry warnings would bury every other message. Unix only —
/// `nlink` has no portable equivalent.
pub(crate) fn hardlink_count(items: &[WalkItem]) -> usize {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        items
            .iter()
            .filter_map(|i| match &i.source {
                ItemSource::File(p) => Some(p),
                _ => None,
            })
            .filter(|p| {
                std::fs::symlink_metadata(p)
                    .map(|m| m.nlink() > 1)
                    .unwrap_or(false)
            })
            .count()
    }
    #[cfg(not(unix))]
    {
        let _ = items;
        0
    }
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

    #[test]
    fn the_named_path_becomes_the_prefix_and_every_entry_sits_under_it() {
        let d = fixture();
        let items = walk(&d.path().join("proj"), "proj").unwrap();
        let names: Vec<&str> = items.iter().map(|i| i.meta.name.as_str()).collect();
        assert!(
            names.contains(&"proj"),
            "the root itself is an entry: {names:?}"
        );
        assert!(names.contains(&"proj/README.md"), "{names:?}");
        assert!(names.contains(&"proj/src/main.rs"), "{names:?}");
        assert!(
            names.iter().all(|n| *n == "proj" || n.starts_with("proj/")),
            "every entry must sit under the prefix: {names:?}"
        );
        assert!(
            names.iter().all(|n| !n.contains("..")),
            "no entry may contain `..`: {names:?}"
        );
    }

    #[test]
    fn entries_are_sorted_and_a_directory_precedes_everything_inside_it() {
        let d = fixture();
        let items = walk(&d.path().join("proj"), "proj").unwrap();
        let names: Vec<String> = items.iter().map(|i| i.meta.name.clone()).collect();

        // Deterministic: the same tree walked twice gives the same order.
        let again: Vec<String> = walk(&d.path().join("proj"), "proj")
            .unwrap()
            .iter()
            .map(|i| i.meta.name.clone())
            .collect();
        assert_eq!(names, again, "the walk must be reproducible");

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
    fn a_symlink_loop_cannot_hang_the_walk() {
        // Not "is detected" — never followed, so it cannot arise. This test
        // exists because the alternative design (dereference) needs loop
        // detection, and a future change back to it must fail here.
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir(r.join("proj")).unwrap();
        std::os::unix::fs::symlink("..", r.join("proj/up")).unwrap();
        std::os::unix::fs::symlink("proj", r.join("proj/self")).unwrap();
        let items = walk(&r.join("proj"), "proj").unwrap();
        assert!(
            items.len() < 10,
            "the walk recursed through a link: {} items",
            items.len()
        );
    }
}
