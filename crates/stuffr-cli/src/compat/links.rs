//! `stuffr install-links`: opt-in compatibility symlinks.
//!
//! Each name in [`super::names`] becomes a symlink in one directory, pointing
//! at the stuffr binary, so that invoking it dispatches to the compatibility
//! family of that name. Nothing here runs unless the user asks for it.

use std::path::{Path, PathBuf};

/// What `install_links` did, or with `dry_run` would do, to one link.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkAction {
    /// A new link was created.
    Created(PathBuf),
    /// The link already points at this stuffr; nothing was changed.
    AlreadyPresent(PathBuf),
    /// An existing entry was replaced: a stale stuffr link, or with
    /// `--force` a file or foreign link.
    Replaced(PathBuf),
    /// One of stuffr's links was removed (`--remove`).
    Removed(PathBuf),
    /// Dry run: the link would be created.
    WouldCreate(PathBuf),
    /// Dry run: an existing entry would be replaced.
    WouldReplace(PathBuf),
    /// Dry run: the link would be removed.
    WouldRemove(PathBuf),
    /// `--remove` left this entry alone, for the stated reason.
    Left(PathBuf, &'static str),
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
            LinkAction::WouldReplace(p) => format!("would replace {} -> {t}", p.display()),
            LinkAction::WouldRemove(p) => format!("would remove {}", p.display()),
            LinkAction::Left(p, why) => format!("left {}: {why}", p.display()),
        }
    }
}

/// The path links should point at: this binary, by a path that survives
/// an upgrade where one exists (see [`stable_target`]).
pub fn current_target() -> stuffr::Result<PathBuf> {
    let exe = std::env::current_exe()?.canonicalize()?;
    Ok(stable_target(&exe, |p| p.canonicalize().ok()))
}

/// Choose the link target for the binary at the canonical path `exe`.
///
/// Homebrew installs into `<prefix>/Cellar/stuffr/<ver>/bin/stuffr`, and
/// `brew upgrade` plus cleanup deletes that directory, so a link to it
/// dangles after every upgrade. Homebrew's stable alias for the current
/// version is `<prefix>/opt/stuffr/bin/stuffr`: when `exe` has the Cellar
/// shape and `resolve` (canonicalisation, injected for testing) takes the
/// opt path to `exe` itself, that is the target. Otherwise it is `exe`.
pub fn stable_target(exe: &Path, resolve: impl Fn(&Path) -> Option<PathBuf>) -> PathBuf {
    use std::path::Component;
    let parts: Vec<Component<'_>> = exe.components().collect();
    let n = parts.len();
    let is = |c: &Component<'_>, s: &str| c.as_os_str() == s;
    if n >= 5
        && is(&parts[n - 5], "Cellar")
        && is(&parts[n - 4], "stuffr")
        && matches!(parts[n - 3], Component::Normal(_))
        && is(&parts[n - 2], "bin")
        && is(&parts[n - 1], "stuffr")
    {
        let prefix: PathBuf = parts[..n - 5].iter().collect();
        let opt = prefix.join("opt/stuffr/bin/stuffr");
        if resolve(&opt).is_some_and(|r| r == exe) {
            return opt;
        }
    }
    exe.to_path_buf()
}

/// Create (or with `remove`, delete) the compatibility links `names` in `dir`,
/// each pointing at `target`. Every name is checked before anything is
/// changed, so a refusal leaves the directory as it was.
///
/// An existing link is stuffr's when its text is `target`, when it resolves
/// to the same file as `target`, or when it dangles and its target's file
/// name is `stuffr` (a link into a version an upgrade has since deleted).
/// Only those are kept, replaced without `--force`, or removed.
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

    let mut seen = std::collections::HashSet::new();
    let names: Vec<&str> = names.iter().copied().filter(|n| seen.insert(*n)).collect();
    for n in &names {
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
        Err(e) => return Err(at(dir, e)),
    };
    let file = target.canonicalize().ok();

    /// What an existing symlink is, as far as stuffr is concerned.
    enum Kind {
        /// Its text is `target`, or it resolves to the same file.
        Live,
        /// It dangles, and names a file called `stuffr`.
        Stale,
        /// Anything else: the user's own.
        Foreign,
    }
    let classify = |p: &Path| -> Kind {
        let Ok(text) = std::fs::read_link(p) else {
            return Kind::Foreign;
        };
        if text == target {
            return Kind::Live;
        }
        match p.canonicalize() {
            Ok(c) => {
                if file.as_ref() == Some(&c) {
                    Kind::Live
                } else {
                    Kind::Foreign
                }
            }
            Err(e)
                if e.kind() == ErrorKind::NotFound
                    && text.file_name().is_some_and(|f| f == "stuffr") =>
            {
                Kind::Stale
            }
            Err(_) => Kind::Foreign,
        }
    };

    enum Step {
        Create,
        Keep,
        Replace,
        Remove,
        Leave(&'static str),
    }
    let mut plan = Vec::new();
    for &name in &names {
        let path = dir.join(name);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(at(&path, e)),
        };
        let kind = match &meta {
            Some(m) if m.file_type().is_symlink() => Some(classify(&path)),
            _ => None,
        };
        let step = match (&meta, remove) {
            (None, true) => continue,
            (None, false) => Step::Create,
            (Some(_), true) => match kind {
                Some(Kind::Live | Kind::Stale) => Step::Remove,
                Some(Kind::Foreign) => Step::Leave("not a stuffr link"),
                None => Step::Leave("not a link"),
            },
            (Some(m), false) => match kind {
                Some(Kind::Live) => Step::Keep,
                Some(Kind::Stale) => Step::Replace,
                _ if m.is_dir() => {
                    return Err(Error::Usage(format!(
                        "{} is a directory; refusing to replace it",
                        path.display()
                    )));
                }
                _ if force => Step::Replace,
                _ => {
                    return Err(Error::Usage(format!(
                        "{} already exists and is not a link to this stuffr; \
                         pass --force to replace it",
                        path.display()
                    )));
                }
            },
        };
        plan.push((path, step));
    }

    let mut actions = Vec::new();
    for (path, step) in plan {
        actions.push(match step {
            Step::Keep => LinkAction::AlreadyPresent(path),
            Step::Leave(why) => LinkAction::Left(path, why),
            Step::Create if dry_run => LinkAction::WouldCreate(path),
            Step::Replace if dry_run => LinkAction::WouldReplace(path),
            Step::Remove if dry_run => LinkAction::WouldRemove(path),
            Step::Create => {
                std::os::unix::fs::symlink(target, &path).map_err(|e| at(&path, e))?;
                LinkAction::Created(path)
            }
            Step::Replace => {
                // Atomic: build the new link beside the old entry, then
                // rename over it, so a failure leaves the original intact.
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                let tmp = path.with_file_name(format!(".{name}.stuffr-tmp-{}", std::process::id()));
                let _ = std::fs::remove_file(&tmp);
                std::os::unix::fs::symlink(target, &tmp).map_err(|e| at(&tmp, e))?;
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(at(&path, e));
                }
                LinkAction::Replaced(path)
            }
            Step::Remove => {
                std::fs::remove_file(&path).map_err(|e| at(&path, e))?;
                LinkAction::Removed(path)
            }
        });
    }
    Ok(actions)
}

/// An I/O failure on `path`, with the path in its message. Still
/// [`stuffr::Error::Io`], exit 1: an unwritable directory is the
/// environment refusing, not hostile input.
#[cfg(unix)]
fn at(path: &Path, e: std::io::Error) -> stuffr::Error {
    stuffr::Error::Io(std::io::Error::new(
        e.kind(),
        format!("{}: {e}", path.display()),
    ))
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

#[cfg(test)]
mod tests {
    use super::stable_target;
    use std::path::{Path, PathBuf};

    const CELLAR: &str = "/opt/homebrew/Cellar/stuffr/0.11.0/bin/stuffr";
    const OPT: &str = "/opt/homebrew/opt/stuffr/bin/stuffr";

    #[test]
    fn a_cellar_path_whose_opt_resolves_to_it_targets_opt() {
        let got = stable_target(Path::new(CELLAR), |p| {
            (p == Path::new(OPT)).then(|| PathBuf::from(CELLAR))
        });
        assert_eq!(got, Path::new(OPT));
    }

    #[test]
    fn a_cellar_path_whose_opt_points_elsewhere_stays_canonical() {
        let elsewhere = |_: &Path| {
            Some(PathBuf::from(
                "/opt/homebrew/Cellar/stuffr/0.10.4/bin/stuffr",
            ))
        };
        assert_eq!(
            stable_target(Path::new(CELLAR), elsewhere),
            Path::new(CELLAR)
        );
        assert_eq!(
            stable_target(Path::new(CELLAR), |_| None),
            Path::new(CELLAR)
        );
    }

    #[test]
    fn a_non_homebrew_path_stays_canonical() {
        let any = |_: &Path| Some(PathBuf::from("/usr/local/bin/stuffr"));
        for p in [
            "/usr/local/bin/stuffr",
            "/home/u/.cargo/bin/stuffr",
            // Right words, wrong shape: not matched by substring.
            "/x/Cellar/stuffr/bin/stuffr",
            "/x/Cellar/other/0.1/bin/stuffr",
            "/x/NotCellar/stuffr/0.1/bin/stuffr",
            "/x/Cellar/stuffr/0.1/libexec/stuffr",
        ] {
            assert_eq!(stable_target(Path::new(p), any), Path::new(p), "{p}");
        }
    }

    #[test]
    fn the_prefix_is_whatever_precedes_cellar() {
        let exe = "/usr/local/Cellar/stuffr/1.0/bin/stuffr";
        let opt = "/usr/local/opt/stuffr/bin/stuffr";
        let got = stable_target(Path::new(exe), |p| {
            (p == Path::new(opt)).then(|| PathBuf::from(exe))
        });
        assert_eq!(got, Path::new(opt));
    }
}
