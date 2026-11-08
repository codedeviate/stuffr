//! Compiles the vendored libbrotli 1.2.1 (`c/brotli-1.2.1/`) for the
//! `brotli-c` feature: every `.c` file under `common`, `enc` and `dec`, with
//! `include` on the path, into `libbrotli_vendored.a` at `-O2`. Nothing
//! happens without the feature, and the `pure` graph never sees `cc`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[allow(unused_mut)]
    let mut archives: Vec<std::path::PathBuf> = Vec::new();
    #[cfg(feature = "brotli-c")]
    archives.push(brotli::compile());
    // The symbol test (`tests/vendored_symbols.rs`) reads this.
    if !archives.is_empty() {
        let joined: Vec<String> = archives.iter().map(|p| p.display().to_string()).collect();
        println!(
            "cargo:rustc-env=STUFFR_VENDORED_ARCHIVES={}",
            joined.join(":")
        );
    }
}

/// Force-includes `header` into every translation unit of `build` (`-include`
/// for gcc and clang, `/FI` for MSVC). The vendored libraries' prefix headers
/// (`c/<lib>/stuffr-prefix.h`, made by `scripts/gen-prefix-header.sh`) go in
/// this way, so the sources themselves stay byte-identical to upstream.
#[cfg(any(feature = "brotli-c", feature = "lz4-c"))]
fn force_include(build: &mut cc::Build, header: &std::path::Path) {
    let header = std::fs::canonicalize(header)
        .unwrap_or_else(|e| panic!("resolving {}: {e}", header.display()));
    println!("cargo:rerun-if-changed={}", header.display());
    if build.get_compiler().is_like_msvc() {
        build.flag(format!("/FI{}", header.display()));
    } else {
        build
            .flag("-include")
            .flag(header.to_str().expect("utf-8 path"));
    }
}

#[cfg(feature = "brotli-c")]
mod brotli {
    use std::path::{Path, PathBuf};

    const ROOT: &str = "c/brotli-1.2.1";

    /// Builds the archive and returns its path.
    pub fn compile() -> PathBuf {
        println!("cargo:rerun-if-changed={ROOT}");
        let root = Path::new(ROOT);
        let mut build = cc::Build::new();
        build.include(root.join("include")).opt_level(2);
        super::force_include(&mut build, &root.join("stuffr-prefix.h"));
        for dir in ["common", "enc", "dec"] {
            for file in sources(&root.join(dir)) {
                build.file(file);
            }
        }
        build.compile("brotli_vendored");
        let out = std::env::var_os("OUT_DIR").expect("OUT_DIR");
        let name = if build.get_compiler().is_like_msvc() {
            "brotli_vendored.lib"
        } else {
            "libbrotli_vendored.a"
        };
        PathBuf::from(out).join(name)
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
