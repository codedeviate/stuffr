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
    // A name no path can hold, refused HERE rather than by the filesystem —
    // the final whole-branch review's F3.
    //
    // `std::fs` rejects an interior NUL as `io::ErrorKind::InvalidInput`,
    // which becomes `Error::Io` and falls through `Error::exit_code`'s
    // `_ => 1` wildcard. Measured on a mutated `stuffr pack` zip whose entry
    // name is `zt\0ee\0a.txt` (an ordinary zeroed run): `stuffr list` and
    // `stuffr test` both exited 0, and `stuffr unpack -C out` answered
    //
    //     stuffr: i/o error: file name contained an unexpected NUL byte
    //     exit=1
    //
    // — the code this project reserves for *stuffr* failing, on input the
    // archive chose. It was the ONLY exit 1 in the review's 31,460-run
    // corruption sweep across all five salvageable formats, and closing it
    // makes that result a clean zero.
    //
    // # Why here, and why `UnsafePath`
    //
    // `Error::exit_code`'s own doc says a wrong code landing in that
    // wildcard is as likely to mean the wrong VARIANT was constructed
    // upstream as it is to mean the match is wrong, and that is the case
    // here: `Error::Io` is not what an unrepresentable archive-supplied name
    // is. The alternative — matching `io::ErrorKind` at the extraction call
    // site — is the fix-the-site shape Task 3c shipped twice and had to undo
    // twice.
    //
    // This function is the single decision point for whether an entry name
    // may become a path under `dest`, it is pure, and every refusal it
    // already makes is `UnsafePath`: absolute, traversal, net-zero
    // traversal, and — the exact precedent — an EMPTY name, which is no more
    // an escape attempt than this is. Splitting one function's verdict
    // across two exit codes would leave a caller unable to predict either.
    // Exit 7 at the CLI reads "an entry's name was refused and nothing was
    // written under it", which is precisely what happens. Exit 5 was
    // considered and rejected: it claims the ARCHIVE is corrupt, a stronger
    // claim than stuffr can make from a name alone, and `list`/`test` verify
    // the same file's bytes without complaint.
    if entry_name.contains('\0') {
        return Err(Error::UnsafePath {
            path: entry_name.to_string(),
            reason: "entry name contains a NUL byte",
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
    walk_within(&mut out, &mut pushed_a_component, Path::new(entry_name)).map_err(|reason| {
        Error::UnsafePath {
            path: entry_name.to_string(),
            reason,
        }
    })?;

    if out.as_os_str().is_empty() {
        return if pushed_a_component {
            // `a/..`, `a/b/../..`: a real component was consumed and then
            // popped away again. Never produced by a real archiver (which
            // emits bare `.`/`./` for the root, not this), so refusing it
            // costs nothing in compatibility and keeps the traversal check
            // from being second-guessed by a coincidental net-zero.
            //
            // This rule is about ENTRY NAMES specifically, which is why
            // `check_symlink_target` below does not go through this
            // function any more — see its own doc.
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

/// Walks `path`'s components onto `out`, popping for each `..`.
///
/// The single component-classification loop both public functions share, so
/// there is exactly ONE place that decides what `..`, `.`, a root and a
/// normal component mean. Returns the refusal `reason` rather than a full
/// `Error`, so each caller builds its own: `safe_join` names the entry with
/// this reason, and `classify_symlink_target` replaces it with
/// `CLIMBS_OUT_OF_DEST` and names the ENTRY too (0.10.1) — never the composed
/// string, which is not something the user can find in their archive.
///
/// Operates on `Path` components rather than a re-joined string, so nothing
/// round-trips through `to_string_lossy` on the way. A lossy conversion was
/// never a bypass here (`.`, `..` and `/` are ASCII and survive it) but it
/// could mangle a non-UTF-8 target into a DIFFERENT contained name, and
/// there is no reason to keep it now that the composition is component-wise.
fn walk_within(
    out: &mut PathBuf,
    pushed_a_component: &mut bool,
    path: &Path,
) -> std::result::Result<(), &'static str> {
    for comp in path.components() {
        match comp {
            // An absolute path or a Windows drive prefix ignores `dest`
            // entirely — the classic "tar bomb writes to /etc" shape.
            Component::RootDir | Component::Prefix(_) => return Err("absolute path"),
            // `./` is noise, not an attack.
            Component::CurDir => {}
            // Pop only within what we have accumulated. `a/../b` is fine;
            // `../b` and `a/../../b` are not. Comparing against the
            // accumulated depth rather than canonicalising is what keeps this
            // filesystem-independent — and immune to a symlink that appears
            // between the check and the write.
            Component::ParentDir => {
                if !out.pop() {
                    return Err("path traversal above the destination");
                }
            }
            Component::Normal(part) => {
                out.push(part);
                *pushed_a_component = true;
            }
        }
    }
    Ok(())
}

/// [`classify_symlink_target`]'s skip reason for an empty target.
pub(crate) const EMPTY_SYMLINK_TARGET: &str = "symlink target is empty";

/// [`classify_symlink_target`]'s skip reason for a target holding `..` after
/// a name.
pub(crate) const CLIMBS_AFTER_A_NAME: &str =
    "symlink target uses `..` after a name, which can climb out through another link";

/// [`classify_symlink_target`]'s refusal for a leading `..` run that climbs
/// past the destination.
pub(crate) const CLIMBS_OUT_OF_DEST: &str = "symlink target climbs out of the destination";

/// What extraction may do with one symlink entry, decided by
/// [`classify_symlink_target`]. A genuine escape is not a verdict: it is
/// `Err(Error::UnsafePath)`, exit 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SymlinkVerdict {
    /// Create the link: its target resolves inside the destination.
    Allowed,
    /// Do not create the link; name the entry in an
    /// [`crate::Fidelity::EntrySkipped`] with this reason and carry on. The
    /// target's SHAPE is one this extraction cannot prove contained (`..`
    /// after a name) or names nothing (empty). Nothing is created, so
    /// nothing can escape.
    Skip(&'static str),
}

/// Refuses a symlink whose target would resolve outside `dest`.
///
/// The original, all-or-nothing form of [`classify_symlink_target`], kept
/// for its callers: a [`SymlinkVerdict::Skip`] is reported here as
/// `Error::UnsafePath` too, so anything this accepts is a link
/// `classify_symlink_target` would create. The refusal names the TARGET,
/// as it always has; extraction calls `classify_symlink_target`, which names
/// the entry.
pub fn check_symlink_target(dest: &Path, link_path: &Path, target: &str) -> Result<()> {
    match classify_symlink_target(dest, link_path, target, target)? {
        SymlinkVerdict::Allowed => Ok(()),
        SymlinkVerdict::Skip(reason) => Err(Error::UnsafePath {
            path: target.to_string(),
            reason,
        }),
    }
}

/// Decides one symlink entry named `entry`, to be created at `link_path`
/// (what `safe_join` produced for it) pointing at `target`: create it,
/// skip it, or refuse the extraction. **The one owner of that rule** —
/// extraction, the hard-link-to-a-symlink path and the fuzz oracle's
/// lexical rule all ask it.
///
/// - `Err(Error::UnsafePath)`, exit 7, naming `entry`: a genuine escape. An
///   absolute target, a `..` run that climbs deeper than the link's own
///   depth below `dest` (lexically — checked before the shape, so a target
///   that escapes is never merely skipped), or a NUL byte.
/// - `Ok(Skip(reason))`: a SHAPE this extraction will not create — `..`
///   after a name (`CLIMBS_AFTER_A_NAME`) or an empty target
///   (`EMPTY_SYMLINK_TARGET`). Skipped, not refused (user ruling,
///   2026-10-07): GNU tar's `--transform 's,^,pkg-1.0/,'` rewrites symlink
///   targets as well as names, so `bin/foo -> ../lib/foo` arrives as
///   `pkg-1.0/../lib/foo`, and aborting the whole unpack over it left a
///   half-written tree where 0.10.0 and GNU tar extract everything.
/// - `Ok(Allowed)`: anything else.
///
/// The link's own PATH can be perfectly contained while its target is not,
/// and a later entry written through that link lands wherever it points.
/// The target is resolved relative to the link's parent, which is how the
/// OS will resolve it.
///
/// # Why this does not call `safe_join`
///
/// It used to: it composed `rel.join(target)` into a string and handed that
/// to `safe_join`, which meant a symlink target inherited a refusal written
/// for entry NAMES. `safe_join` refuses a name that nets back to `dest`
/// after consuming a real component (`a/..`), on the reasoning that no real
/// archiver emits one. That reasoning does not carry over: `sub/top -> ..`
/// is an ordinary symlink pointing at the extraction root, which bsdtar and
/// GNU tar both extract without comment, and `dest` is trivially inside
/// `dest`. stuffr aborted the whole extraction at exit 7 — naming a path
/// (`sub/..`) that is not an entry in the archive at all, so the user could
/// not find it.
///
/// The component walk is shared (`walk_within`); only the net-to-`dest`
/// verdict differs, which is the whole point. Every genuine escape is still
/// refused by the same walk: an absolute target, and any `..` run deeper
/// than the link's own depth below `dest`.
///
/// # `..` only as a leading run (0.10.1)
///
/// A target may hold `..` only as a LEADING prefix — `..`, `../..`,
/// `../../a/b` — never after a name: `x/s2/..`, `a/../b` and `./a/..` are
/// skipped (`CLIMBS_AFTER_A_NAME`) whatever they net to. `.` components
/// are noise, exactly as `walk_within` treats them, so a leading `./` is
/// harmless and `./..` is still a leading run. An EMPTY target is skipped
/// too (`EMPTY_SYMLINK_TARGET`): it names nothing, and Linux's `symlink(2)`
/// rejects it with ENOENT, which would otherwise surface as exit 1.
///
/// Why: lexical normalisation reads `x/s2/..` as `x`, but the OS resolves
/// `x/s2` FIRST, and if `x/s2` is itself a symlink the `..` climbs from
/// wherever IT points. A tar holding `x/`, `x/s2 -> ..` (contained: it names
/// `dest`) and `s1 -> x/s2/..` unpacked at exit 0 with `dest/s1` resolving
/// to `dest/..`. Entry order is no defence — `s1` can precede `s2`, so no
/// creation-time existence check sees the link it climbs through. The rule
/// is therefore about the target's SHAPE, and needs no filesystem.
///
/// # Why that is sound — by induction over the links a run creates
///
/// Only links that are CREATED have to obey the shape: a skipped link
/// creates nothing, so it adds nothing to resolve through. Every link that
/// is created sits at a path with no symlinked ancestor (the extraction
/// refuses one before creating anything — `stuffr`'s
/// `refuse_symlinked_ancestors` — and never removes a directory it would
/// have to replace with a link), so the link's own directory is a REAL
/// directory inside `dest`. Resolving its target from there:
///
/// 1. The leading `..` run climbs through real directories only, so its
///    lexical depth check above IS its physical answer: it ends at a real
///    directory inside `dest`, or is refused.
/// 2. Every component after that run is a name (or `.`). A name either is a
///    real directory entry — descending, so still inside `dest` — or is
///    another link this run created, which by the induction hypothesis
///    resolves inside `dest`, and the walk continues from there, again only
///    by names.
/// 3. No `..` ever follows a name, so the walk never climbs out of whatever
///    a link handed it. Hence every created link resolves inside `dest`.
///
/// What the argument does not cover, by design: a symlink that was in
/// `dest` before the run started, which a target could name through a plain
/// component — that is the destination's owner's link, not the archive's —
/// and a concurrent local writer, the check-then-use window
/// `refuse_symlinked_ancestors` documents. The `container` fuzz target's
/// oracle checks the result PHYSICALLY (`check_extraction_contained`), so a
/// hole in this argument would be a finding there.
pub fn classify_symlink_target(
    dest: &Path,
    link_path: &Path,
    entry: &str,
    target: &str,
) -> Result<SymlinkVerdict> {
    let refuse = |reason: &'static str| Error::UnsafePath {
        path: entry.to_string(),
        reason,
    };
    let target_path = Path::new(target);
    // The sibling door to `safe_join`'s own NUL refusal, closed in the same
    // change and for the same reason: `std::os::unix::fs::symlink` rejects
    // an interior NUL as `InvalidInput`, so a symlink TARGET carrying one
    // reached the identical `Error::Io`/exit-1 path an entry NAME did.
    // Closing only the half the review measured would leave the class open
    // through a door two lines away.
    if target.contains('\0') {
        return Err(refuse("symlink target contains a NUL byte"));
    }
    // An empty target names nothing and has no components, so every rule
    // below would accept it — and `symlink(2)` on Linux answers ENOENT,
    // which reached the CLI as `Error::Io`, exit 1, on a target the archive
    // chose (macOS creates `l -> ""` instead). Skipped: nothing is created.
    if target.is_empty() {
        return Ok(SymlinkVerdict::Skip(EMPTY_SYMLINK_TARGET));
    }
    // Checked before the walk purely so the reason names symlinks — the
    // walk's own `RootDir` arm would refuse it anyway.
    if target_path.is_absolute() {
        return Err(refuse("absolute symlink target"));
    }

    let parent = link_path.parent().unwrap_or(dest);
    let rel = parent.strip_prefix(dest).unwrap_or(Path::new(""));

    let mut out = PathBuf::new();
    let mut pushed = false;
    // `rel` came out of `safe_join`, so it holds only `Normal` components
    // and cannot fail — walked rather than asserted so the depth it
    // contributes is computed by the same code that consumes it.
    walk_within(&mut out, &mut pushed, rel).map_err(|_| refuse(CLIMBS_OUT_OF_DEST))?;

    // The depth walk BEFORE the shape rule: a target whose lexical walk
    // leaves `dest` is a genuine escape (exit 7) whatever its shape, and
    // must not be downgraded to a skip by a `..` after a name — `../..`,
    // and `a/../../..` alike.
    walk_within(&mut out, &mut pushed, target_path).map_err(|_| refuse(CLIMBS_OUT_OF_DEST))?;

    // The shape rule: a `..` after a name is skipped even when it nets
    // inside `dest`, because only the OS knows where the name before it
    // leads.
    let mut named = false;
    for comp in target_path.components() {
        match comp {
            Component::Normal(_) => named = true,
            Component::ParentDir if named => {
                return Ok(SymlinkVerdict::Skip(CLIMBS_AFTER_A_NAME));
            }
            _ => {}
        }
    }
    // No net-to-`dest` check here, deliberately: a target resolving to
    // `dest` itself is contained.
    Ok(SymlinkVerdict::Allowed)
}

/// Why a filesystem refused a NAME: the one definition of "the filesystem
/// refuses this name", shared by extraction (which skips the entry) and the
/// fuzz containment oracle (which cannot resolve such a link physically).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameRefusal {
    /// A component, or the whole path, is past the filesystem's limit
    /// (`ENAMETOOLONG`).
    TooLong,
    /// The name is not valid on this filesystem (`EILSEQ`: APFS refuses a
    /// name that is not valid Unicode in its required form).
    InvalidOnThisFilesystem,
}

/// Whether `e` is the filesystem refusing a NAME, and why.
///
/// `ENAMETOOLONG` is recognised as `ErrorKind::InvalidFilename` (what `std`
/// maps it to, stable since 1.87), with the raw errno as the fallback for a
/// platform that reports it otherwise (63 on macOS and the BSDs, 36 on
/// Linux). `EILSEQ` is matched by its raw number, since `std` maps it to no
/// stable `ErrorKind`: 92 on macOS and iOS, 84 on Linux. An unknown platform
/// matches no `EILSEQ`, so the error is `None` and the caller fails closed.
#[must_use]
pub fn name_refused_by_filesystem(e: &std::io::Error) -> Option<NameRefusal> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    const ENAMETOOLONG: i32 = 63;
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    const ENAMETOOLONG: i32 = 36;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const EILSEQ: Option<i32> = Some(92);
    #[cfg(target_os = "linux")]
    const EILSEQ: Option<i32> = Some(84);
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
    const EILSEQ: Option<i32> = None;
    if e.kind() == std::io::ErrorKind::InvalidFilename || e.raw_os_error() == Some(ENAMETOOLONG) {
        Some(NameRefusal::TooLong)
    } else if EILSEQ.is_some() && e.raw_os_error() == EILSEQ {
        Some(NameRefusal::InvalidOnThisFilesystem)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_filesystem_refusing_a_name_is_classified() {
        use super::{NameRefusal, name_refused_by_filesystem};
        use std::io::{Error as IoError, ErrorKind};
        #[cfg(target_os = "macos")]
        const EILSEQ: i32 = 92;
        #[cfg(target_os = "linux")]
        const EILSEQ: i32 = 84;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert_eq!(
            name_refused_by_filesystem(&IoError::from_raw_os_error(EILSEQ)),
            Some(NameRefusal::InvalidOnThisFilesystem)
        );
        assert_eq!(
            name_refused_by_filesystem(&IoError::from(ErrorKind::InvalidFilename)),
            Some(NameRefusal::TooLong)
        );
        assert_eq!(
            name_refused_by_filesystem(&IoError::from(ErrorKind::PermissionDenied)),
            None
        );
    }

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

    /// A name carrying a NUL is refused outright, and a symlink target
    /// carrying one is too.
    ///
    /// **This test asserted the opposite for its first shape until the final
    /// whole-branch review's F3**: `safe.txt\0..` used to be ACCEPTED and
    /// joined verbatim, on the reasoning that a NUL-poisoned segment is
    /// classified `Normal` rather than `ParentDir` (classification is
    /// exact-string equality), so the injection buys an attacker no
    /// traversal. That reasoning was and is correct — it is simply not the
    /// whole question. The accepted path then reached `std::fs`, which
    /// rejects an interior NUL as `InvalidInput`, and `stuffr unpack` ended
    /// at **exit 1** — the code reserved for stuffr itself failing — on a
    /// name the ARCHIVE chose. That was the only exit 1 in the review's
    /// 31,460-run corruption sweep.
    ///
    /// A refusal is strictly stronger than the property this test used to
    /// pin, so nothing is lost by the change: `walk_within` is never reached
    /// with a NUL-bearing string from either public entry point any more,
    /// because both refuse one first.
    #[test]
    fn a_nul_bearing_name_or_symlink_target_is_refused_before_the_filesystem_sees_it() {
        let dest = Path::new("/tmp/out");
        for name in ["safe.txt\0..", "a\0/../../etc/passwd", "zt\0ee\0a.txt"] {
            match super::safe_join(dest, name) {
                Err(Error::UnsafePath { path, reason }) => {
                    assert_eq!(path, name);
                    assert!(
                        // The second shape holds a genuine `..` component as
                        // well, and either refusal is correct for it — what
                        // must never happen is an `Ok`.
                        reason == "entry name contains a NUL byte"
                            || reason == "path traversal above the destination",
                        "unexpected reason for {name:?}: {reason}"
                    );
                }
                other => panic!("expected UnsafePath for {name:?}, got {other:?}"),
            }
        }
        // The sibling door: a symlink TARGET reaches `symlink(2)`, which
        // rejects an interior NUL the same way `File::create` does.
        match super::check_symlink_target(dest, &dest.join("sub/link"), "tar\0get") {
            Err(Error::UnsafePath { path, reason }) => {
                assert_eq!(path, "tar\0get");
                assert_eq!(reason, "symlink target contains a NUL byte");
            }
            other => panic!("expected UnsafePath, got {other:?}"),
        }
    }

    /// The Phase 2 final review's I1. `sub/top -> ..` is a symlink pointing
    /// at the extraction root: contained, since `dest` is inside `dest`, and
    /// both bsdtar and GNU tar extract it without comment. It was refused
    /// (exit 7, aborting the whole extraction) because
    /// `check_symlink_target` composed `sub/..` and handed it to
    /// `safe_join`, inheriting a rule written for entry NAMES — and the path
    /// the refusal named, `sub/..`, is not an entry in the archive, so there
    /// was nothing for the user to go and look at.
    #[test]
    fn a_symlink_target_that_resolves_to_the_destination_itself_is_contained() {
        let dest = Path::new("/tmp/out");
        // One level deep, netting exactly to `dest`.
        assert!(super::check_symlink_target(dest, &dest.join("sub/top"), "..").is_ok());
        // Two levels deep, netting exactly to `dest`.
        assert!(super::check_symlink_target(dest, &dest.join("a/b/top"), "../..").is_ok());
        // (`../sub/..`, down and back up again, was accepted here until
        // 0.10.1: a `..` after a name is now skipped whatever it nets to —
        // see `a_symlink_target_climbing_after_a_name_is_skipped`.)
        // A link directly under `dest` pointing at `dest`.
        assert!(super::check_symlink_target(dest, &dest.join("here"), ".").is_ok());
        // And the sibling shapes that already worked must keep working.
        assert!(super::check_symlink_target(dest, &dest.join("sub/self"), "../sub").is_ok());
    }

    /// The regression the fix above could plausibly introduce, pinned
    /// separately: accepting a net-to-`dest` TARGET must not widen into
    /// accepting one that goes a single step further.
    #[test]
    fn a_symlink_target_one_step_past_the_destination_is_still_refused() {
        let dest = Path::new("/tmp/out");
        for (link, target) in [
            (dest.join("sub/top"), "../.."),
            (dest.join("top"), ".."),
            (dest.join("a/b/top"), "../../.."),
            (dest.join("sub/top"), "../../etc/passwd"),
            (dest.join("sub/top"), "../sub/../.."),
            (dest.join("sub/top"), "/etc/passwd"),
        ] {
            let err = super::check_symlink_target(dest, &link, target)
                .expect_err("{target} from {link:?} must be refused");
            match err {
                // The refusal names the TARGET the archive actually
                // contains, never the composed path — which the user has no
                // way to find. That was half of I1.
                Error::UnsafePath { path, .. } => assert_eq!(
                    path, target,
                    "the refusal must name the archive's own target string"
                ),
                other => panic!("expected UnsafePath for {target}, got {other:?}"),
            }
        }
    }

    /// 0.10.1: a `..` after a name is SKIPPED, wherever the walk would land
    /// (user ruling 2026-10-07 — it was exit 7 until the final fix wave).
    ///
    /// Lexical normalisation reads `x/s2/..` as `x`, but the OS resolves
    /// `x/s2` FIRST — and when `x/s2` is itself a symlink (`x/s2 -> ..`, an
    /// ordinary contained link), the `..` climbs from wherever it points. A
    /// tar holding `x/`, `x/s2 -> ..` and `s1 -> x/s2/..` unpacked at exit 0
    /// and left `dest/s1` resolving to `dest/..`. Every shape here nets
    /// INSIDE `dest` lexically, which is exactly why the depth walk alone
    /// accepted them. The last is GNU tar's `--transform 's,^,pkg-1.0/,'`
    /// rewrite of `bin/foo -> ../lib/foo`.
    #[test]
    fn a_symlink_target_climbing_after_a_name_is_skipped() {
        let dest = Path::new("/tmp/out");
        for (link, target) in [
            (dest.join("s1"), "x/s2/.."),
            (dest.join("s1"), "a/../b"),
            (dest.join("s1"), "./a/.."),
            (dest.join("sub/top"), "../sub/.."),
            (dest.join("a/b/l"), "../../x/y/../z"),
            (dest.join("s1"), "a/./.."),
            (dest.join("pkg-1.0/bin/foo"), "pkg-1.0/../lib/foo"),
        ] {
            assert_eq!(
                super::classify_symlink_target(dest, &link, "e", target).unwrap(),
                super::SymlinkVerdict::Skip(super::CLIMBS_AFTER_A_NAME),
                "{target} from {link:?}"
            );
            // The all-or-nothing wrapper still refuses it, naming the target.
            match super::check_symlink_target(dest, &link, target) {
                Err(Error::UnsafePath { path, reason }) => {
                    assert_eq!(path, target);
                    assert_eq!(reason, super::CLIMBS_AFTER_A_NAME, "{target}");
                }
                other => panic!("{target} from {link:?} must be refused, got {other:?}"),
            }
        }
    }

    /// The skip never swallows a genuine escape: a target that ALSO climbs
    /// out of `dest` lexically is exit 7 whatever its shape, and every
    /// refusal names the ENTRY (F2 of the 0.10.1 final review), never the
    /// target text, which is not something the user can find with `list`.
    #[test]
    fn an_escape_is_refused_naming_the_entry_even_when_its_shape_would_skip() {
        let dest = Path::new("/tmp/out");
        for (link, target, reason) in [
            (dest.join("l"), "a/../../..", super::CLIMBS_OUT_OF_DEST),
            (
                dest.join("sub/l"),
                "../sub/../..",
                super::CLIMBS_OUT_OF_DEST,
            ),
            (dest.join("sub/l"), "../..", super::CLIMBS_OUT_OF_DEST),
            (
                dest.join("sub/l"),
                "../../x/../y",
                super::CLIMBS_OUT_OF_DEST,
            ),
            (dest.join("l"), "/etc/passwd", "absolute symlink target"),
            (
                dest.join("l"),
                "a\0/..",
                "symlink target contains a NUL byte",
            ),
        ] {
            match super::classify_symlink_target(dest, &link, "the/entry", target) {
                Err(Error::UnsafePath { path, reason: r }) => {
                    assert_eq!(path, "the/entry", "{target:?}");
                    assert_eq!(r, reason, "{target:?}");
                }
                other => panic!("{target:?} from {link:?} must be refused, got {other:?}"),
            }
        }
    }

    /// 0.10.1 fix round 1, then the final fix wave: an EMPTY target names
    /// nothing and has no components, so the walk accepted it — and
    /// `symlink(2)` on Linux answers ENOENT, which reached the CLI as
    /// `Error::Io`, exit 1. (macOS creates `l -> ""` at exit 0.) Skipped.
    #[test]
    fn an_empty_symlink_target_is_skipped() {
        let dest = Path::new("/tmp/out");
        assert_eq!(
            super::classify_symlink_target(dest, &dest.join("sub/l"), "sub/l", "").unwrap(),
            super::SymlinkVerdict::Skip(super::EMPTY_SYMLINK_TARGET)
        );
        match super::check_symlink_target(dest, &dest.join("sub/l"), "") {
            Err(Error::UnsafePath { path, reason }) => {
                assert_eq!(path, "");
                assert_eq!(reason, super::EMPTY_SYMLINK_TARGET);
            }
            other => panic!("the wrapper must still refuse it, got {other:?}"),
        }
    }

    /// The over-strictness guard for the rule above: a LEADING `..` run
    /// within the link's depth, plain names, and `.` anywhere stay accepted.
    #[test]
    fn a_leading_parent_run_and_plain_names_are_still_accepted() {
        let dest = Path::new("/tmp/out");
        for (link, target) in [
            (dest.join("sub/top"), ".."),
            (dest.join("sub/l"), "../a"),
            (dest.join("a/b/l"), "../../a/b"),
            (dest.join("a/b/l"), "./../.."),
            (dest.join("l"), "a/b"),
            (dest.join("l"), "./a"),
            (dest.join("l"), "a/./b"),
            (dest.join("l"), "a/b/."),
            (dest.join("l"), "."),
            (dest.join("l"), "..foo/...b"),
        ] {
            assert!(
                super::check_symlink_target(dest, &link, target).is_ok(),
                "{target} from {link:?} must be accepted"
            );
            assert_eq!(
                super::classify_symlink_target(dest, &link, "e", target).unwrap(),
                super::SymlinkVerdict::Allowed,
                "{target} from {link:?}"
            );
        }
    }

    /// `safe_join`'s own net-to-destination rule is untouched by I1's fix:
    /// an ENTRY NAME that pops back to the destination is still refused.
    /// The two functions now disagree on purpose, and that is the fix.
    #[test]
    fn an_entry_name_that_nets_to_the_destination_is_still_refused_after_the_symlink_fix() {
        let dest = Path::new("/tmp/out");
        assert!(super::safe_join(dest, "sub/..").is_err());
        assert!(super::safe_join(dest, "a/b/../..").is_err());
        // While the same string as a symlink TARGET is fine.
        assert!(super::check_symlink_target(dest, &dest.join("sub/top"), "..").is_ok());
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
