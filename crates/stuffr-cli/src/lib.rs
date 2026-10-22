//! Library surface behind the `stuffr` binary.
//!
//! Two reasons it exists. [`cli::Cli`] is here so `tests/cli.rs` can
//! introspect it through `clap::CommandFactory`: the examples page's test
//! asserts every flag and subcommand clap knows about is mentioned on the
//! page, and doing that against the real `Cli` (rather than a hand-copied
//! list of flag names) keeps the assertion honest as the surface grows.
//! [`compat`] is here so that `main`, the integration tests and the `compat`
//! fuzz target all drive the same compatibility families (`bzip2` and
//! friends) and `install-links`. [`bench`](mod@bench) is here so its
//! harness, scoring and renderers can be tested with injected times: the CLI
//! tests run a debug binary, where `stuffr bench` refuses to time anything.
//! [`format_by_name`] is the `--format`/`--formats` lookup `main` and
//! `bench` share.
//!
//! None of this is a stable API; it is the binary's own code, kept public
//! for those callers. `bench` and `format_by_name` stay documented, as
//! `cli`, `compat` and `size` are, rather than `#[doc(hidden)]`: this
//! crate's docs are the binary's internals docs, and hiding two of its
//! modules would only make them harder to find.

pub mod bench;
pub mod cli;
pub mod compat;
pub mod size;

/// Resolves a `--format` name against the registry. Shared by
/// `main`'s verbs and `stuffr bench`.
///
/// `FormatId` holds a `&'static str` so the registry can be built from
/// constants without allocation, but a flag value arrives at runtime as a
/// `String`. Rather than leak it to reach `'static`, look it up: the registry
/// already holds the `'static` id, and an unknown name gets a real error
/// naming what this build does have.
pub fn format_by_name(name: &str) -> stuffr::Result<stuffr::FormatId> {
    stuffr::registry()
        .matrix()
        .into_iter()
        .find(|r| r.id.as_str() == name)
        .map(|r| r.id)
        .ok_or_else(|| {
            let known: Vec<&str> = stuffr::registry()
                .matrix()
                .iter()
                .map(|r| r.id.as_str())
                .collect();
            stuffr::Error::Usage(format!(
                "unknown format `{name}`; this build has: {}",
                if known.is_empty() {
                    "none".to_string()
                } else {
                    known.join(", ")
                }
            ))
        })
}
