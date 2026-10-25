//! The lib tests' scratch directories for both personalities: a directory
//! of its own per call, `stuffr-compress-<pid>-<n>-<tag>` (the pid the first
//! all-digit field, as `scripts/tmp-leaks.sh` reads it), removed when
//! dropped, a panicking test's unwind included, with write permission put
//! back on every directory first, so a test that made one unreadable or
//! read-only cannot leak it.

use std::path::{Path, PathBuf};

pub(super) struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        make_dirs_writable(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A new, empty scratch directory; `tag` names the test (no all-digit
/// field).
pub(super) fn scratch(tag: &str) -> Scratch {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("stuffr-compress-{}-{n}-{tag}", std::process::id()));
    let s = Scratch(d);
    make_dirs_writable(&s.0);
    let _ = std::fs::remove_dir_all(&s.0);
    std::fs::create_dir_all(&s.0).unwrap();
    s
}

/// Restores user rwx on every directory under `p`, without following
/// symlinks.
// keep in sync with the copies in tests/cli/common.rs, compat_harness/mod.rs (stuffr-cli),
// src/compat/compress/test_scratch.rs (stuffr-cli), tests/zip_on_a_pipe.rs (stuffr-formats),
// tests/common/mod.rs and src/entries.rs (stuffr)
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
