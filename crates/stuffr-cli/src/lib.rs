//! Library surface behind the `stuffr` binary.
//!
//! Two reasons it exists. [`cli::Cli`] is here so `tests/cli.rs` can
//! introspect it through `clap::CommandFactory`: the examples page's test
//! asserts every flag and subcommand clap knows about is mentioned on the
//! page, and doing that against the real `Cli` (rather than a hand-copied
//! list of flag names) keeps the assertion honest as the surface grows.
//! [`compat`] is here so that `main`, the integration tests and the `compat`
//! fuzz target all drive the same compatibility families (`bzip2` and
//! friends) and `install-links`.

pub mod cli;
pub mod compat;
pub mod size;
