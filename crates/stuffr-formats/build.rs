//! Compiles the vendored C libraries:
//!
//! - libbrotli 1.2.1 (`c/brotli-1.2.1/`) for the `brotli-c` feature: every
//!   `.c` file under `common`, `enc` and `dec`, with `include` on the path,
//!   into `libbrotli_vendored.a` at `-O2`.
//! - liblz4 1.11.0 (`c/lz4-1.11.0/`) for the `lz4-c` feature: `lz4.c`,
//!   `lz4hc.c`, `lz4frame.c` and `xxhash.c` into `liblz4_vendored.a` at
//!   `-O3` (upstream's default), with `LZ4F_MULTITHREAD=1` and `-pthread` on
//!   unix targets and `LZ4F_MULTITHREAD=0` elsewhere.
//!
//! Nothing happens without the features, and the `pure` graph never sees
//! `cc`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[allow(unused_mut)]
    let mut archives: Vec<std::path::PathBuf> = Vec::new();
    #[cfg(feature = "brotli-c")]
    archives.push(brotli::compile());
    #[cfg(feature = "lz4-c")]
    archives.push(lz4::compile());
    // The symbol test (`tests/vendored_symbols.rs`) reads this. The `:`
    // separator is unix-only, as the test is (a Windows path has a drive
    // colon).
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
    // Built from `CARGO_MANIFEST_DIR`, not `canonicalize`: on Windows that
    // yields a `\\?\` path, which MSVC's `/FI` does not accept.
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let header = std::path::Path::new(&manifest).join(header);
    assert!(header.is_file(), "missing {}", header.display());
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

#[cfg(feature = "lz4-c")]
mod lz4 {
    use std::path::{Path, PathBuf};

    const ROOT: &str = "c/lz4-1.11.0";

    /// Builds the archive and returns its path.
    ///
    /// `LZ4F_MULTITHREAD=1` gives `nbWorkers >= 1` real worker threads (the
    /// lz4 1.11.0 CLI's `-T#`); the bytes are the same without it (liblz4
    /// then runs the jobs serially on the calling thread), so Windows, where
    /// it would need the Vista API, builds without it. The target, not the
    /// host, decides: this script runs on the host.
    pub fn compile() -> PathBuf {
        println!("cargo:rerun-if-changed={ROOT}");
        let root = Path::new(ROOT);
        let unix = std::env::var("CARGO_CFG_TARGET_FAMILY")
            .is_ok_and(|f| f.split(',').any(|f| f == "unix"));
        let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        let mut build = cc::Build::new();
        build.include(root).opt_level(3);
        if unix {
            build.define("LZ4F_MULTITHREAD", "1").flag("-pthread");
            if os == "linux" {
                println!("cargo:rustc-link-lib=pthread");
            }
        } else {
            build.define("LZ4F_MULTITHREAD", "0");
        }
        super::force_include(&mut build, &root.join("stuffr-prefix.h"));
        for file in ["lz4.c", "lz4hc.c", "lz4frame.c", "xxhash.c"] {
            build.file(root.join(file));
        }
        build.compile("lz4_vendored");
        let out = std::env::var_os("OUT_DIR").expect("OUT_DIR");
        let name = if build.get_compiler().is_like_msvc() {
            "lz4_vendored.lib"
        } else {
            "liblz4_vendored.a"
        };
        PathBuf::from(out).join(name)
    }
}
