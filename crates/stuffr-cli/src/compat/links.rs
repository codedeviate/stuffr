//! `stuffr install-links`: opt-in compatibility symlinks.
//!
//! Each name in [`super::names`] becomes a symlink in one directory, pointing
//! at the stuffr binary, so that invoking it dispatches to the compatibility
//! family of that name. Nothing here runs unless the user asks for it.

use std::path::{Path, PathBuf};

/// What `install_links` did, or with `dry_run` would do, to one link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkAction {
    /// A new link was created.
    Created(PathBuf),
    /// The link already points at this stuffr; nothing was changed.
    AlreadyPresent(PathBuf),
    /// An existing file or foreign link was replaced (`--force`).
    Replaced(PathBuf),
    /// One of stuffr's links was removed (`--remove`).
    Removed(PathBuf),
    /// Dry run: the link would be created (or replaced).
    WouldCreate(PathBuf),
    /// Dry run: the link would be removed.
    WouldRemove(PathBuf),
}

impl LinkAction {
    /// The one output line for this action, given the link target.
    pub fn describe(&self, target: &Path) -> String {
        let t = target.display();
        match self {
            LinkAction::Created(p) => format!("created {} -> {t}", p.display()),
            LinkAction::AlreadyPresent(p) => format!("already present {} -> {t}", p.display()),
            LinkAction::Replaced(p) => format!("replaced {} -> {t}", p.display()),
            LinkAction::Removed(p) => format!("removed {}", p.display()),
            LinkAction::WouldCreate(p) => format!("would create {} -> {t}", p.display()),
            LinkAction::WouldRemove(p) => format!("would remove {}", p.display()),
        }
    }
}

/// The path links should point at: this binary, fully resolved.
pub fn current_target() -> stuffr::Result<PathBuf> {
    Ok(std::env::current_exe()?.canonicalize()?)
}

/// Create (or with `remove`, delete) the compatibility links `names` in `dir`,
/// each pointing at `target`. Every name is checked before anything is
/// changed, so a refusal leaves the directory as it was.
#[cfg(unix)]
pub fn install_links(
    dir: &Path,
    names: &[&str],
    force: bool,
    remove: bool,
    dry_run: bool,
    target: &Path,
) -> stuffr::Result<Vec<LinkAction>> {
    use std::io::ErrorKind;
    use stuffr::Error;

    for n in names {
        if !super::names().contains(n) {
            return Err(Error::Usage(format!(
                "`{n}` is not a compatibility name (known: {})",
                super::names().join(", ")
            )));
        }
    }
    let dir = match dir.canonicalize() {
        Ok(d) if d.is_dir() => d,
        Ok(_) => {
            return Err(Error::Usage(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(Error::Usage(format!(
                "directory {} does not exist",
                dir.display()
            )));
        }
        Err(e) => return Err(e.into()),
    };
    // Whether the link at `p` leads to this stuffr.
    let ours = |p: &Path| -> bool {
        std::fs::read_link(p).is_ok_and(|t| t == target)
            || p.canonicalize().is_ok_and(|c| c == target)
    };

    enum Step {
        Create,
        Keep,
        Replace,
        Remove,
    }
    let mut plan = Vec::new();
    for &name in names {
        let path = dir.join(name);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let step = match (&meta, remove) {
            (None, true) => continue,
            (None, false) => Step::Create,
            (Some(m), true) => {
                if m.file_type().is_symlink() && ours(&path) {
                    Step::Remove
                } else {
                    continue;
                }
            }
            (Some(m), false) => {
                let is_link = m.file_type().is_symlink();
                if is_link && ours(&path) {
                    Step::Keep
                } else if m.is_dir() {
                    return Err(Error::Usage(format!(
                        "{} is a directory; refusing to replace it",
                        path.display()
                    )));
                } else if force {
                    Step::Replace
                } else {
                    return Err(Error::Usage(format!(
                        "{} already exists and is not a link to this stuffr; \
                         pass --force to replace it",
                        path.display()
                    )));
                }
            }
        };
        plan.push((path, step));
    }

    let mut actions = Vec::new();
    for (path, step) in plan {
        actions.push(match step {
            Step::Keep => LinkAction::AlreadyPresent(path),
            Step::Create | Step::Replace if dry_run => LinkAction::WouldCreate(path),
            Step::Remove if dry_run => LinkAction::WouldRemove(path),
            Step::Create => {
                std::os::unix::fs::symlink(target, &path)?;
                LinkAction::Created(path)
            }
            Step::Replace => {
                std::fs::remove_file(&path)?;
                std::os::unix::fs::symlink(target, &path)?;
                LinkAction::Replaced(path)
            }
            Step::Remove => {
                std::fs::remove_file(&path)?;
                LinkAction::Removed(path)
            }
        });
    }
    Ok(actions)
}

/// Symlinks are not available here.
#[cfg(not(unix))]
pub fn install_links(
    _dir: &Path,
    _names: &[&str],
    _force: bool,
    _remove: bool,
    _dry_run: bool,
    _target: &Path,
) -> stuffr::Result<Vec<LinkAction>> {
    Err(stuffr::Error::Unsupported(
        "install-links needs symlinks; Windows is not supported".into(),
    ))
}
