//! Entry-path containment: the single decision point for whether an
//! archive entry's name (or a symlink's target) may be written under a
//! destination directory.
//!
//! Pure and filesystem-free by design — see the module-level doc comments on
//! each function for why.

use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// Joins `entry_name` onto `dest`, refusing anything that escapes.
///
/// Resolved COMPONENT-WISE and without touching the filesystem, so the
/// decision cannot depend on what happens to exist — and so it is exhaustively
/// unit-testable with no archive and no temp directory. There is deliberately
/// no code path that returns a sanitised path for a hostile name: the README's
/// contract is "refused, not silently sanitised", and a caller that received a
/// cleaned-up path would have no way to know it had been handed one.
///
/// `.` and `./` name the destination directory itself and are ACCEPTED,
/// returning `dest` unchanged: `tar cf x.tar .` — the single most common way
/// a tarball gets produced — emits `./` as its first entry, and refusing it
/// would reject the majority of real-world tarballs at exit 7. Naming the
/// destination cannot escape it, and escaping is the only thing this
/// function exists to prevent. This is different from a name like `a/..`,
/// which also nets to the destination but only after actually consuming a
/// real component — see the `pushed_a_component` note below for why the two
/// are told apart rather than collapsed onto one "ends up empty" check.
pub fn safe_join(dest: &Path, entry_name: &str) -> Result<PathBuf> {
    if entry_name.is_empty() {
        return Err(Error::UnsafePath {
            path: entry_name.to_string(),
            reason: "empty entry name",
        });
    }

    let mut out = PathBuf::new();
    // Tracks whether any real (`Normal`) component was ever pushed, as
    // distinct from `out` being empty. `.` and `./` leave both false and
    // empty — never having accumulated anything to pop, they are the
    // destination itself. `a/..` leaves `out` empty too, but only after
    // pushing `a` and then popping it away again; collapsing these two onto
    // a single "is `out` empty at the end" check would silently start
    // accepting that second shape, which is real traversal that happens to
    // net to zero rather than a name for the destination.
    let mut pushed_a_component = false;
    for comp in Path::new(entry_name).components() {
        match comp {
            // An absolute path or a Windows drive prefix ignores `dest`
            // entirely — the classic "tar bomb writes to /etc" shape.
            Component::RootDir | Component::Prefix(_) => {
                return Err(Error::UnsafePath {
                    path: entry_name.to_string(),
                    reason: "absolute path",
                });
            }
            // `./` is noise, not an attack.
            Component::CurDir => {}
            // Pop only within what we have accumulated. `a/../b` is fine;
            // `../b` and `a/../../b` are not. Comparing against the
            // accumulated depth rather than canonicalising is what keeps this
            // filesystem-independent — and immune to a symlink that appears
            // between the check and the write.
            Component::ParentDir => {
                if !out.pop() {
                    return Err(Error::UnsafePath {
                        path: entry_name.to_string(),
                        reason: "path traversal above the destination",
                    });
                }
            }
            Component::Normal(part) => {
                out.push(part);
                pushed_a_component = true;
            }
        }
    }

    if out.as_os_str().is_empty() {
        return if pushed_a_component {
            // `a/..`, `a/b/../..`: a real component was consumed and then
            // popped away again. Never produced by a real archiver (which
            // emits bare `.`/`./` for the root, not this), so refusing it
            // costs nothing in compatibility and keeps the traversal check
            // from being second-guessed by a coincidental net-zero.
            Err(Error::UnsafePath {
                path: entry_name.to_string(),
                reason: "path traversal nets back to the destination",
            })
        } else {
            // `.` or `./`: nothing was ever pushed, so nothing was popped
            // away either — this names `dest` itself, not an escape from it.
            Ok(dest.to_path_buf())
        };
    }
    Ok(dest.join(out))
}

/// Refuses a symlink whose target would resolve outside `dest`.
///
/// The subtler escape: the link's own PATH can be perfectly contained while
/// its target is not, and a later entry written through that link lands
/// wherever it points. The target is resolved relative to the link's parent,
/// which is how the OS will resolve it.
pub fn check_symlink_target(dest: &Path, link_path: &Path, target: &str) -> Result<()> {
    if Path::new(target).is_absolute() {
        return Err(Error::UnsafePath {
            path: target.to_string(),
            reason: "absolute symlink target",
        });
    }
    let parent = link_path.parent().unwrap_or(dest);
    let rel = parent.strip_prefix(dest).unwrap_or(Path::new(""));
    // Re-use the same decision rather than a parallel one: two containment
    // implementations would be two chances to differ.
    safe_join(dest, &rel.join(target).to_string_lossy())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::error::Error;

    #[test]
    fn absolute_traversal_and_escaping_symlinks_are_all_refused() {
        let dest = Path::new("/tmp/out");
        for (name, why) in [
            ("../../etc/passwd", "traversal"),
            ("a/../../b", "traversal"),
            ("/etc/passwd", "absolute"),
            ("", "empty"),
        ] {
            let err = super::safe_join(dest, name).expect_err("{name} must be refused");
            match err {
                Error::UnsafePath { path, .. } => assert_eq!(path, name),
                other => panic!("expected UnsafePath for {name} ({why}), got {other:?}"),
            }
        }
    }

    #[test]
    fn ordinary_nested_names_are_accepted_unchanged() {
        let dest = Path::new("/tmp/out");
        assert_eq!(
            super::safe_join(dest, "a/b/c.txt").unwrap(),
            dest.join("a/b/c.txt")
        );
        // A leading `./` is noise, not an attack.
        assert_eq!(
            super::safe_join(dest, "./a.txt").unwrap(),
            dest.join("a.txt")
        );
    }

    #[test]
    fn refusal_never_rewrites_the_name_it_refuses() {
        // The README's non-negotiable, asserted directly: there is no code path
        // that returns a SANITISED PathBuf for a hostile entry. If sanitising were
        // ever added, this test is what fails.
        let dest = Path::new("/tmp/out");
        assert!(super::safe_join(dest, "../x").is_err());
        assert!(super::safe_join(dest, "/x").is_err());
    }

    #[test]
    fn a_symlink_whose_target_escapes_the_destination_is_refused() {
        let dest = Path::new("/tmp/out");
        assert!(super::check_symlink_target(dest, &dest.join("link"), "../../etc/passwd").is_err());
        assert!(super::check_symlink_target(dest, &dest.join("link"), "/etc/passwd").is_err());
        assert!(super::check_symlink_target(dest, &dest.join("a/link"), "b.txt").is_ok());
    }

    #[test]
    fn dot_only_and_dot_prefixed_names_are_ordinary_filenames_not_traversal() {
        // Component classification is exact-string equality against "." and
        // "..", not "contains dots": a name that is only three (or more)
        // dots, or merely starts with `..`, is a valid, if unusual, filename
        // on every filesystem this runs on — not a traversal variant. A
        // naive `contains("..")` check would reject these as false
        // positives; a naive strip-`..`-substrings sanitiser would corrupt
        // them. Neither applies here — all three are accepted unchanged.
        let dest = Path::new("/tmp/out");
        assert_eq!(super::safe_join(dest, "...").unwrap(), dest.join("..."));
        assert_eq!(
            super::safe_join(dest, "a/....b").unwrap(),
            dest.join("a/....b")
        );
        assert_eq!(super::safe_join(dest, "..foo").unwrap(), dest.join("..foo"));
    }

    #[test]
    fn backslash_heavy_names_stay_a_single_contained_component() {
        // `stuffr` builds for macOS/Linux (see CLAUDE.md); `\` is an ordinary
        // filename byte there, not a separator, so a Windows-shaped entry
        // name from a foreign archive cannot smuggle a traversal past this
        // function on this platform — it becomes one odd-looking but fully
        // contained filename.
        let dest = Path::new("/tmp/out");
        assert_eq!(
            super::safe_join(dest, "..\\..\\etc\\passwd").unwrap(),
            dest.join("..\\..\\etc\\passwd")
        );
    }

    #[test]
    fn embedded_nul_does_not_disguise_a_traversal_component() {
        let dest = Path::new("/tmp/out");
        // A NUL-poisoned segment that merely CONTAINS ".." is still classified
        // Normal, not ParentDir, because classification is exact-string
        // equality — a null-byte injection buys the attacker nothing here.
        assert_eq!(
            super::safe_join(dest, "safe.txt\0..").unwrap(),
            dest.join("safe.txt\0..")
        );
        // Nor can a poisoned segment hide a REAL `..` component in a
        // different `/`-separated position: each segment is classified on
        // its own regardless of what a sibling segment contains.
        assert!(super::safe_join(dest, "a\0/../../etc/passwd").is_err());
    }

    #[test]
    fn a_chain_of_parent_dirs_through_a_nested_symlink_is_refused() {
        // The brief's own symlink test only exercises one level of nesting.
        // A link two directories deep needs two `..` just to reach `dest`,
        // so a target with three escapes past it — the composition Task 9
        // actually relies on: `check_symlink_target` re-derives the correct
        // depth from the link's OWN path rather than assuming a fixed one.
        let dest = Path::new("/tmp/out");
        assert!(super::check_symlink_target(dest, &dest.join("a/b/link"), "../../b.txt").is_ok());
        assert!(
            super::check_symlink_target(dest, &dest.join("a/b/link"), "../../../etc/passwd")
                .is_err()
        );
    }

    #[test]
    fn dot_and_dot_slash_name_the_destination_itself() {
        // `tar cf x.tar .` emits `./` as its first entry — the single most
        // common way a tarball gets produced. Refusing it would refuse the
        // majority of real-world archives at exit 7, a security refusal, on
        // completely benign input. `.` and `./` cannot escape `dest`; they
        // name it.
        let dest = Path::new("/tmp/out");
        assert_eq!(super::safe_join(dest, ".").unwrap(), dest);
        assert_eq!(super::safe_join(dest, "./").unwrap(), dest);
    }

    #[test]
    fn a_trailing_dot_resolves_within_its_parent_not_to_the_destination() {
        let dest = Path::new("/tmp/out");
        assert_eq!(super::safe_join(dest, "sub/.").unwrap(), dest.join("sub"));
    }

    #[test]
    fn empty_name_is_still_refused_even_though_dot_is_now_accepted() {
        // An empty string is malformed, not merely redundant with `.` — it
        // stays refused with its own reason.
        let dest = Path::new("/tmp/out");
        assert!(super::safe_join(dest, "").is_err());
    }

    #[test]
    fn traversal_that_nets_to_empty_is_still_refused_not_confused_with_naming_the_destination() {
        // The regression this change could plausibly introduce: accepting
        // `.` must not widen into accepting anything that merely RESOLVES to
        // empty. `..`, `./..` and `a/../..` all attempt to pop past what was
        // ever pushed — refused exactly as before, by the same
        // pop-fails-immediately path this change did not touch.
        let dest = Path::new("/tmp/out");
        assert!(super::safe_join(dest, "..").is_err());
        assert!(super::safe_join(dest, "./..").is_err());
        assert!(super::safe_join(dest, "a/../..").is_err());
        // `a/..` is the subtler case: it never pops past zero, so the old
        // "pop fails" guard does not catch it — it is refused only because
        // a real component was pushed and then popped away again, which is
        // exactly the distinction `pushed_a_component` exists to draw.
        assert!(super::safe_join(dest, "a/..").is_err());
    }
}
