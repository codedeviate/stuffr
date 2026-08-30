//! The `stf` command's argument surface.
//!
//! Pulled out of `main.rs` and re-exported from `lib.rs` so an integration
//! test can ask clap itself — via [`clap::CommandFactory`] — what flags and
//! subcommands exist, rather than keeping a second, hand-maintained list that
//! the examples page could silently drift out of sync with. `main.rs` still
//! owns everything that isn't the argument shape: parsing, dispatch, and the
//! examples text itself.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "stf",
    version,
    about = "Universal compression and archive toolkit"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Print detailed usage examples covering every feature, then exit.
    #[arg(long)]
    pub examples: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Compress a file.
    Pack {
        /// Input path, or `-` for stdin.
        input: String,
        /// Output path. Defaults to INPUT plus the format's extension.
        #[arg(short, long)]
        output: Option<String>,
        /// Use this format instead of inferring one from the output name.
        #[arg(long)]
        format: Option<String>,
        /// Compression level. gzip accepts 0-9.
        #[arg(long)]
        level: Option<i32>,
        /// Overwrite an existing output.
        #[arg(long)]
        force: bool,
        /// Skip the fsync that makes the output durable before it is published.
        #[arg(long)]
        no_sync: bool,
    },
    /// Decompress a file.
    Unpack {
        /// Input path, or `-` for stdin.
        input: String,
        /// Output path. Defaults to INPUT with its extension removed.
        #[arg(short, long)]
        output: Option<String>,
        /// Overwrite an existing output.
        #[arg(long)]
        force: bool,
        /// Refuse a decode expanding by more than this ratio.
        #[arg(long)]
        max_ratio: Option<u64>,
        /// Skip the fsync that makes the output durable before it is published.
        #[arg(long)]
        no_sync: bool,
    },
    /// Decompress a file and write it to stdout.
    Cat {
        /// Input path, or `-` for stdin.
        input: String,
    },
    /// Identify a stream without decoding it.
    Info {
        /// Input path, or `-` for stdin.
        input: String,
        /// Emit machine-readable JSON instead of the human-readable report.
        #[arg(long)]
        json: bool,
    },
    /// List the formats this build contains.
    Formats,
}
