//! Helpers shared by the `salvage_*` integration tests.

use std::path::{Path, PathBuf};

/// A scratch directory that removes itself, contents and all, when dropped, a
/// panicking test's unwind included. Backed by `tempfile::TempDir`, so the
/// name is unique per call and no two tests or runs can collide.
///
/// `.0` is the directory's path, which the tests join onto.
#[allow(dead_code)]
pub struct Scratch(pub PathBuf, #[allow(dead_code)] tempfile::TempDir);

#[allow(dead_code)]
impl Scratch {
    pub fn new(tag: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("stuffr-salvage-{}-{tag}-", std::process::id()))
            .tempdir()
            .unwrap();
        Scratch(dir.path().to_path_buf(), dir)
    }
}

/// A scratch directory that removes its tree when dropped, a panicking
/// test's unwind included. Unlike [`Scratch`] it first restores user write
/// permission on every directory under it, so a test that leaves a
/// read-only directory behind (`work/ro/x.txt` with `ro` at 0o555) still
/// cleans up.
///
/// Derefs to the directory's [`Path`].
#[allow(dead_code)]
#[derive(Debug)]
pub struct ScratchDir(PathBuf);

#[allow(dead_code)]
impl ScratchDir {
    /// Creates `<temp dir>/<name>`, replacing anything already there. `name`
    /// must carry the process id (`stuffr-<what>-<pid>-<n>`), which is how
    /// the leak check tells a live run's folders from stale ones.
    pub fn create(name: &str) -> Self {
        let p = std::env::temp_dir().join(name);
        remove_tree(&p);
        std::fs::create_dir_all(&p).unwrap();
        ScratchDir(p)
    }
}

impl std::ops::Deref for ScratchDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        remove_tree(&self.0);
    }
}

/// Restores user rwx on every directory under `p`, without following
/// symlinks. Read-only files are left alone: only directories block removal.
// keep in sync with the copies in tests/cli.rs, compat_harness/mod.rs (stuffr-cli),
// tests/zip_on_a_pipe.rs (stuffr-formats), tests/common/mod.rs and src/entries.rs (stuffr)
#[cfg(unix)]
fn make_dirs_writable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(p) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let mut perms = meta.permissions();
    perms.set_mode(perms.mode() | 0o700);
    let _ = std::fs::set_permissions(p, perms);
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            make_dirs_writable(&e.path());
        }
    }
}

#[cfg(not(unix))]
fn make_dirs_writable(_p: &Path) {}

fn remove_tree(p: &Path) {
    make_dirs_writable(p);
    let _ = std::fs::remove_dir_all(p);
}
