//! Universal compression and archive toolkit — the library behind the `stuffr`
//! command.
//!
//! Re-exports [`stuffr_core`] and owns the feature taxonomy: `pure` (default),
//! `c-backed`, `legacy`, `full`, plus one granular feature per format.
//!
//! **This crate has no binary.** `cargo install stuffr` fails with "no
//! binaries"; the `stuffr` command lives in the `stuffr-cli` package, so the
//! working spelling is `cargo install stuffr-cli`.

pub use stuffr_core as core;
pub use stuffr_core::*;

/// bzip2 one stream at a time, with libbzip2's own error classes — what the
/// `stuffr` binary's `bzip2` compatibility mode drives to reproduce
/// `bzip2(1)`'s messages, and (`RawStream`, a call at a time) its Apple
/// gzip personality's `unbzip2`. Not part of the stable API.
#[cfg(feature = "bzip2")]
#[doc(hidden)]
pub mod bzip2_stream {
    pub use stuffr_formats::bzip2::{RawStream, StreamError, StreamReader};
}
/// Info-ZIP UnZip 6.0's own decoders — traditional PKWARE decryption so
/// far, inflate, explode and unshrink to follow — what the `stuffr` binary's
/// unzip compatibility family decodes entries with, failing where unzip
/// fails. Ported under the Info-ZIP licence. Not part of the stable API.
#[doc(hidden)]
pub mod infozip {
    pub use stuffr_formats::infozip::*;
}
/// The old Unix `pack` (`.z`) decoder — what the `stuffr` binary's gzip
/// compatibility personalities use for the pack files both references read.
/// Not part of the stable API.
#[doc(hidden)]
pub mod pack_stream {
    pub use stuffr_formats::pack::{PackError, PackReader};
}
/// `.xz` an `lzma_code` call at a time through liblzma — what the `stuffr`
/// binary's Apple gzip personality runs `unxz` over on the C tier. Not
/// part of the stable API.
#[cfg(feature = "xz-c")]
#[doc(hidden)]
pub mod xz_stream {
    pub use stuffr_formats::xz_c::RawXz;
}
/// The `xz` tool's options seam — filter chains, checks, threads, block
/// lists — and the streaming coder over them, what the `stuffr` binary's xz
/// compatibility family runs. Not part of the stable API.
#[cfg(any(feature = "xz-c", feature = "xz-pure"))]
#[doc(hidden)]
pub mod xz_opts {
    pub use stuffr_formats::xz_opts::*;
}
/// The `zstd` tool's options seam — levels, compression parameters,
/// threads, dictionaries, training — and the streaming coder over them,
/// what the `stuffr` binary's zstd compatibility family runs. Not part of
/// the stable API.
#[cfg(any(feature = "zstd-c", feature = "zstd-pure"))]
#[doc(hidden)]
pub mod zstd_opts {
    pub use stuffr_formats::zstd_opts::*;
}
/// Raw deflate through C zlib, byte-identical to stock zlib's — what the
/// `stuffr` binary's Apple gzip personality compresses with on the C tier —
/// and zlib's `inflate`, which its zstd family decodes gzip members with.
/// Not part of the stable API.
#[cfg(feature = "zlib-c")]
#[doc(hidden)]
pub mod zlib_c {
    pub use stuffr_formats::zlib_c::{Inflate, RawDeflate};
}
/// The `lz4` tool's options seam — levels, block sizes and modes,
/// checksums, dictionaries, the legacy format — and the streaming coder over
/// them, what the `stuffr` binary's lz4 compatibility family runs: liblz4
/// 1.10.0 under `lz4-c`, else its own frame writer and reader. Not part of
/// the stable API.
#[cfg(feature = "lz4")]
#[doc(hidden)]
pub mod lz4_opts {
    pub use stuffr_formats::lz4_opts::*;
}
pub mod entries;
mod link_cache;
pub mod ops;
mod walk;

/// Builds a registry containing every format this build was compiled with.
fn build_registry() -> stuffr_core::Registry {
    let mut r = stuffr_core::Registry::new();
    stuffr_formats::register_all(&mut r);
    r
}

/// The registry this build ships, built once.
///
/// `stuffr formats` renders this, which is how a user tells a missing feature flag
/// from a corrupt file.
///
/// Returns a shared reference rather than a fresh value: it was rebuilding five
/// HashMaps on every ops call. A consumer wanting a different set — an
/// out-of-tree format, or a deliberately reduced one — builds their own and
/// passes it to the `_with` variants.
pub fn registry() -> &'static stuffr_core::Registry {
    static REG: std::sync::OnceLock<stuffr_core::Registry> = std::sync::OnceLock::new();
    REG.get_or_init(build_registry)
}
