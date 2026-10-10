//! Compatibility links: the `stuffr` binary behaving as another tool when
//! invoked through a symlink named after it.

#[cfg(unix)]
mod unix {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// A scratch directory holding `stuffr` and the symlink chain
    /// `bzcat` -> `bzip2` -> `stuffr`.
    fn link_chain(dir: &Path) -> PathBuf {
        let stuffr = dir.join("stuffr");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &stuffr).unwrap();
        let bzip2 = dir.join("bzip2");
        std::os::unix::fs::symlink(&stuffr, &bzip2).unwrap();
        let bzcat = dir.join("bzcat");
        std::os::unix::fs::symlink(&bzip2, &bzcat).unwrap();
        bzcat
    }

    #[test]
    fn symlink_named_bzcat_dispatches_to_the_compat_stub() {
        let dir = std::env::temp_dir().join(format!("stuffr-compat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bzcat = link_chain(&dir);
        let out = Command::new(&bzcat).output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(out.status.code(), Some(3));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("bzcat: not yet implemented"), "stderr: {err}");
    }
}
