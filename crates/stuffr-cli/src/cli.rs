//! The `stuffr` command's argument surface.
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
    name = "stuffr",
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
        /// Use a weak fallback encoder that this build ships in place of the
        /// format's real one. Worse ratio, and buffers the whole input.
        #[arg(long)]
        allow_weak_encoder: bool,
        /// Encode with N worker threads. 0 means auto-detect.
        ///
        /// OMITTING this flag is not the same as passing 0: without it, stuffr
        /// encodes single-threaded, so the same input always produces the same
        /// bytes on any machine. Multi-threaded xz and zstd split the input
        /// per worker, so their output depends on the worker count.
        #[arg(long)]
        threads: Option<usize>,
        /// Use the full detected CPU budget, uncapped.
        ///
        /// Lifts the CPU cap only — `--memory-limit` still binds. Turbo means
        /// "use my cores", not "ignore the OOM killer".
        #[arg(long)]
        turbo: bool,
        /// Cap the memory stuffr will ask for, e.g. 512M or 2G.
        ///
        /// On encode this bounds the worker count. Defaults to 25% of
        /// available RAM, honouring cgroup limits.
        #[arg(long, value_name = "SIZE")]
        memory_limit: Option<String>,
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
        /// Use this format instead of detecting one. Required for formats with
        /// no magic bytes and no extension.
        #[arg(long)]
        format: Option<String>,
        /// Refuse a decode expanding by more than this ratio.
        #[arg(long)]
        max_ratio: Option<u64>,
        /// Skip the fsync that makes the output durable before it is published.
        #[arg(long)]
        no_sync: bool,
        /// Cap the memory stuffr will ask for, e.g. 512M or 2G.
        ///
        /// Defaults to 25% of available RAM, honouring cgroup limits.
        #[arg(long, value_name = "SIZE")]
        memory_limit: Option<String>,
    },
    /// Decompress a file and write it to stdout.
    Cat {
        /// Input path, or `-` for stdin.
        input: String,
        /// Use this format instead of detecting one. Required for formats with
        /// no magic bytes and no extension.
        #[arg(long)]
        format: Option<String>,
        /// Refuse a decode expanding by more than this ratio.
        #[arg(long)]
        max_ratio: Option<u64>,
        /// Cap the memory stuffr will ask for, e.g. 512M or 2G.
        ///
        /// Defaults to 25% of available RAM, honouring cgroup limits.
        #[arg(long, value_name = "SIZE")]
        memory_limit: Option<String>,
    },
    /// Identify a stream without decoding it.
    Info {
        /// Input path, or `-` for stdin.
        input: String,
        /// Emit machine-readable JSON instead of the human-readable report.
        #[arg(long)]
        json: bool,
        /// Cap the memory stuffr will ask for, e.g. 512M or 2G.
        ///
        /// Defaults to 25% of available RAM, honouring cgroup limits.
        #[arg(long, value_name = "SIZE")]
        memory_limit: Option<String>,
    },
    /// List the formats this build contains.
    Formats,
    /// List an archive's entries without extracting.
    #[command(alias = "ls")]
    List {
        /// Archive path, or `-` for stdin.
        input: String,
        /// Emit machine-readable JSON instead of one entry per line.
        #[arg(long)]
        json: bool,
    },
    /// Verify every entry's integrity without extracting.
    Test {
        /// Archive path, or `-` for stdin.
        input: String,
    },
}
