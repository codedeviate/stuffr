//! Compiles the vendored libbrotli 1.2.1 (`c/brotli-1.2.1/`) for the
//! `brotli-c` feature: every `.c` file under `common`, `enc` and `dec`, with
//! `include` on the path, into `libbrotli_vendored.a` at `-O2`. Nothing
//! happens without the feature, and the `pure` graph never sees `cc`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "brotli-c")]
    brotli::compile();
}

#[cfg(feature = "brotli-c")]
mod brotli {
    use std::path::{Path, PathBuf};

    const ROOT: &str = "c/brotli-1.2.1";

    pub fn compile() {
        println!("cargo:rerun-if-changed={ROOT}");
        let root = Path::new(ROOT);
        let mut build = cc::Build::new();
        build.include(root.join("include")).opt_level(2);
        for dir in ["common", "enc", "dec"] {
            for file in sources(&root.join(dir)) {
                build.file(file);
            }
        }
        build.compile("brotli_vendored");
    }

    /// The directory's `.c` files, sorted so the archive's member order
    /// never depends on the filesystem.
    fn sources(dir: &Path) -> Vec<PathBuf> {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        let mut files: Vec<PathBuf> = entries
            .map(|e| {
                e.unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
                    .path()
            })
            .filter(|p| p.extension().is_some_and(|x| x == "c"))
            .collect();
        files.sort();
        files
    }
}
