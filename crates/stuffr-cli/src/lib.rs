//! Library surface behind the `stf` binary.
//!
//! Exists solely so `tests/cli.rs` can reach [`cli::Cli`] and introspect it
//! through `clap::CommandFactory` — the examples page's test asserts every
//! flag and subcommand clap knows about is mentioned on the page, and doing
//! that against the real `Cli` (rather than a hand-copied list of flag names)
//! is what keeps the assertion honest as the surface grows.

pub mod cli;
