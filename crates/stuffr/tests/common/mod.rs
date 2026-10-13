//! Helpers shared by the `salvage_*` integration tests.

use std::path::PathBuf;

/// A scratch directory that removes itself, contents and all, when dropped, a
/// panicking test's unwind included. Backed by `tempfile::TempDir`, so the
/// name is unique per call and no two tests or runs can collide.
///
/// `.0` is the directory's path, which the tests join onto.
pub struct Scratch(pub PathBuf, #[allow(dead_code)] tempfile::TempDir);

impl Scratch {
    pub fn new(tag: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("stuffr-salvage-{tag}-"))
            .tempdir()
            .unwrap();
        Scratch(dir.path().to_path_buf(), dir)
    }
}
