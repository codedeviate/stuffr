//! `stuffr version` and `stuffr version --json`.
//!
//! The JSON form describes the running build so a host that embeds stuffr
//! (for example as a wasm module) can learn what it holds without parsing
//! human text.

use crate::bench::levels::backend_of;

/// Every feature `stuffr-cli`'s `Cargo.toml` declares, with whether this
/// build has it on. One `cfg!` per key: `CARGO_FEATURE_*` is upper-cased and
/// loses its hyphens, so it cannot be mapped back reliably. The
/// `version_json_features_cover_manifest` test fails if a manifest feature is
/// missing here.
pub const FEATURES: &[(&str, bool)] = &[
    ("pure", cfg!(feature = "pure")),
    ("c-backed", cfg!(feature = "c-backed")),
    ("zlib-c", cfg!(feature = "zlib-c")),
    ("xz-c", cfg!(feature = "xz-c")),
    ("lzma-c", cfg!(feature = "lzma-c")),
    ("zstd-c", cfg!(feature = "zstd-c")),
    ("lz4-c", cfg!(feature = "lz4-c")),
    ("brotli-c", cfg!(feature = "brotli-c")),
    ("legacy", cfg!(feature = "legacy")),
    ("full", cfg!(feature = "full")),
    ("lha", cfg!(feature = "lha")),
    ("arj", cfg!(feature = "arj")),
    ("compress", cfg!(feature = "compress")),
    ("arc", cfg!(feature = "arc")),
    ("zoo", cfg!(feature = "zoo")),
];

/// What `stuffr --version` prints.
pub fn plain() -> String {
    format!("stuffr {}", env!("CARGO_PKG_VERSION"))
}

/// The `version --json` document.
///
/// `tiers` covers every codec in the registry (via [`backend_of`], the label
/// `stuffr bench` and `formats --json` use). `host_fs_abi` is reserved for a
/// future host-import ABI and is `null` until one exists.
pub fn json() -> serde_json::Value {
    let features: Vec<&str> = FEATURES
        .iter()
        .filter(|&&(_, on)| on)
        .map(|&(name, _)| name)
        .collect();
    let tiers: serde_json::Map<String, serde_json::Value> = stuffr::registry()
        .matrix()
        .into_iter()
        .filter(|r| r.kind == stuffr::FormatKind::Codec)
        .map(|r| {
            (
                r.id.as_str().to_string(),
                serde_json::Value::from(backend_of(r.id.as_str())),
            )
        })
        .collect();
    serde_json::json!({
        "schema": 1,
        "version": env!("CARGO_PKG_VERSION"),
        "target": env!("TARGET"),
        "features": features,
        "tiers": tiers,
        "personalities": crate::compat::names(),
        "host_fs_abi": serde_json::Value::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_json_fields() {
        let v = json();
        assert_eq!(v["schema"], 1);
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        assert!(!v["target"].as_str().unwrap().is_empty());
        assert!(v["host_fs_abi"].is_null());
        let p = v["personalities"].as_array().unwrap();
        assert!(p.iter().any(|n| n == "gzip"));
        assert!(p.iter().any(|n| n == "unzip"));
        assert!(
            v["tiers"]
                .as_object()
                .unwrap()
                .values()
                .all(|t| t == "pure" || t == "c")
        );
        assert!(v["tiers"]["gzip"].is_string());
    }

    /// Adding a feature to `Cargo.toml` without listing it in [`FEATURES`]
    /// fails here. The manifest is read as text, as `hygiene.rs` does.
    #[test]
    fn version_json_features_cover_manifest() {
        let manifest =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        let keys: Vec<String> = manifest
            .split("\n[")
            .find(|s| s.starts_with("features]"))
            .expect("stuffr-cli declares a [features] section")
            .lines()
            .filter_map(|l| l.split_once('='))
            .filter(|(_, rhs)| rhs.trim_start().starts_with('['))
            .map(|(k, _)| k.trim().to_string())
            .collect();
        assert!(keys.len() > 5, "manifest parse found {keys:?}");
        for k in &keys {
            assert!(
                FEATURES.iter().any(|(n, _)| n == k),
                "Cargo.toml declares feature `{k}` but version::FEATURES omits it"
            );
        }
        for (n, _) in FEATURES {
            assert!(keys.iter().any(|k| k == n), "FEATURES names unknown `{n}`");
        }
    }
}
