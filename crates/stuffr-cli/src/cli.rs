//! The `stuffr` command's argument surface.
//!
//! Pulled out of `main.rs` and re-exported from `lib.rs` so an integration
//! test can ask clap itself — via [`clap::CommandFactory`] — what flags and
//! subcommands exist, rather than keeping a second, hand-maintained list that
//! the examples page could silently drift out of sync with. `main.rs` still
//! owns everything that isn't the argument shape: parsing, dispatch, and the
//! examples text itself.

use clap::{Args, Parser, Subcommand};

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
    /// Compress a file, or collect several into an archive.
    Pack {
        /// Input paths, or `-` for stdin.
        ///
        /// More than one path needs an output that names a CONTAINER (`-o
        /// bundle.tar`, or `--format tar`): a codec compresses one stream and
        /// has nowhere to put a second.
        #[arg(required = true, num_args = 1.., value_name = "PATHS")]
        paths: Vec<String>,
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
        /// Fail (exit 4) if anything was approximated or lost.
        ///
        /// On the pack side that means something the walk met and could not
        /// store — a socket, an undecodable name, an unreadable directory —
        /// or an entry shape this container has none of, such as a directory
        /// or a symlink in an `ar`.
        #[arg(long)]
        strict_fidelity: bool,
    },
    /// Decompress a file, or extract an archive's entries.
    Unpack {
        /// Input path, or `-` for stdin.
        input: String,
        /// Entries to extract; every entry when none are given.
        ///
        /// An exact entry name, or a directory selecting everything beneath
        /// it. Needs -C, which is what asks for entry-aware extraction.
        #[arg(value_name = "PATTERNS")]
        patterns: Vec<String>,
        /// Extract the entry at this position instead of naming it. Repeatable.
        ///
        /// 0-BASED, counting in archive order — the same number `stuffr list`
        /// prints in its first column. This is how you reach an entry whose
        /// name you cannot type: `Makefile` and `makefile` from a
        /// case-sensitive filesystem on a case-insensitive one. Needs -C,
        /// like PATTERNS, and cannot be combined with them — they are two
        /// ways of saying the same thing.
        ///
        /// It does NOT reach a record a zip's own index shadows: `unpack`
        /// counts the entries the index enumerates, so a record a later one
        /// hides is not at any index here — it has no number at all. `stuffr
        /// salvage --list` finds those, and `salvage --index N` selects them
        /// by SCAN position, which is a different numbering.
        #[arg(long, value_name = "N")]
        index: Vec<usize>,
        /// Extract the archive's entries into this directory.
        ///
        /// Absolute entry paths, `..` traversal and symlinks escaping this
        /// directory are refused (exit 7), never silently sanitised.
        #[arg(short = 'C', long, value_name = "DIR")]
        directory: Option<String>,
        /// Fail (exit 4) if anything was approximated or lost.
        ///
        /// On extraction that means an entry whose mode or mtime could not be
        /// restored, or one skipped for having no shape on disk.
        #[arg(long)]
        strict_fidelity: bool,
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
    /// Change a file's compression or its archive format, without unpacking
    /// it to disk.
    ///
    /// Codec mode — the container is kept (`.tar.gz` -> `.tar.zst`, `.gz` ->
    /// `.xz`, `.tar.xz` -> `.tar`): the container, or the plain stream, is
    /// copied byte for byte and only the codec around it changes.
    ///
    /// Entry mode — the container changes (`.tgz` -> `.zip`, `.zip` ->
    /// `.tar.xz`): every entry is read from the source and written into the
    /// target under pack's rules, and what the target cannot hold (a
    /// directory or symlink in an ar, a device anywhere) is skipped with a
    /// fidelity warning. A hard link stays a link into tar and is written
    /// as a copy of its target elsewhere, or skipped, named, when no copy
    /// is available.
    ///
    /// The input's chain is detected by content, never by its name; the
    /// target's comes from OUT's name or --format.
    Convert {
        /// Input path, or `-` for stdin.
        input: String,
        /// Output path; the same as -o. Give one or the other, not both.
        #[arg(value_name = "OUT")]
        output_pos: Option<String>,
        /// Output path, or `-` for stdout (which needs --format).
        #[arg(short, long)]
        output: Option<String>,
        /// Use this target format instead of inferring one from the output
        /// name. A codec or a container; one the name contradicts is refused.
        #[arg(long)]
        format: Option<String>,
        /// Compression level for the target codec. gzip accepts 0-9.
        ///
        /// Also what makes converting a file to the chain it already has
        /// (`.tar.gz` -> `.tar.gz`) a re-encode rather than "nothing to
        /// convert".
        #[arg(long)]
        level: Option<i32>,
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
        /// Use a weak fallback encoder that this build ships in place of the
        /// format's real one. Worse ratio, and buffers the whole input.
        #[arg(long)]
        allow_weak_encoder: bool,
        /// Overwrite an existing output.
        #[arg(long)]
        force: bool,
        /// Fail (exit 4) if anything was approximated or lost.
        ///
        /// In codec mode the container is copied byte for byte and nothing
        /// is lost. In entry mode every skipped entry or missing field is a
        /// warning, and this turns any of them into exit 4 — with the output
        /// still written, as with pack.
        #[arg(long)]
        strict_fidelity: bool,
        /// Refuse a decode expanding by more than this ratio.
        #[arg(long)]
        max_ratio: Option<u64>,
        /// Cap the memory stuffr will ask for, e.g. 512M or 2G.
        ///
        /// Bounds every source codec layer's decoder and the encoder's worker
        /// count. Defaults to 25% of available RAM, honouring cgroup limits.
        #[arg(long, value_name = "SIZE")]
        memory_limit: Option<String>,
        /// Skip the fsync that makes the output durable before it is published.
        #[arg(long)]
        no_sync: bool,
    },
    /// Decompress a file, or stream an archive's entries, to stdout.
    Cat {
        /// Input path, or `-` for stdin.
        input: String,
        /// Entries whose bytes to stream, in archive order.
        ///
        /// An exact entry name, or a directory selecting everything beneath
        /// it. Naming one is what asks for entry-aware streaming; without
        /// any, `cat` decodes the input as a single stream.
        #[arg(value_name = "PATTERNS")]
        patterns: Vec<String>,
        /// Stream the entry at this position instead of naming it. Repeatable.
        ///
        /// 0-BASED, counting in archive order — the same number `stuffr list`
        /// prints in its first column. `stuffr cat a.zip --index 6 > out.sh`
        /// is how you pull out an entry whose name is ambiguous or
        /// untypeable. Like PATTERNS, naming one asks for entry-aware
        /// streaming; the two cannot be combined.
        #[arg(long, value_name = "N")]
        index: Vec<usize>,
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
    /// Compare compression formats on your own files: size, ratio, and
    /// compress and decompress time for each one.
    ///
    /// Every format runs under the same conditions: the same input (all in
    /// memory, or all streamed from disk when it is over half of
    /// --memory-limit), the same thread setting, and one untimed warm-up
    /// read first. Only codec work is timed, except the temp file's writes
    /// for a codec whose worst-case output is too large for memory; such a
    /// row is marked. A format that fails is a row
    /// marked failed, not an exit code. Each row is then run once more,
    /// untimed, in a child process to measure its peak compress and
    /// decompress memory (resident; see --no-memory). Timings need a
    /// release build.
    Bench(BenchArgs),
    /// Create compatibility symlinks (`bzip2`, `bunzip2`, `bzcat`,
    /// `bzip2recover`) to this binary in a directory. Opt-in, never automatic.
    InstallLinks {
        /// Directory to put the links in. It must already exist.
        #[arg(long, value_name = "DIR")]
        dir: std::path::PathBuf,
        /// Only these names, comma-separated or repeated. Default: all.
        #[arg(long, value_name = "NAME", value_delimiter = ',')]
        names: Vec<String>,
        /// Replace an existing file or foreign link of the same name.
        #[arg(long)]
        force: bool,
        /// Remove stuffr's links instead of creating them.
        #[arg(long)]
        remove: bool,
        /// Say what would change, and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// List an archive's entries without extracting.
    ///
    /// The first column is the entry's 0-based position in archive order,
    /// which is what `cat --index` and `unpack --index` select by.
    List {
        /// Archive path, or `-` for stdin.
        input: String,
        /// Emit machine-readable JSON instead of one entry per line.
        #[arg(long)]
        json: bool,
        /// Refuse a codec layer beneath the container expanding by more
        /// than this ratio (e.g. a `.tar.gz` bomb).
        #[arg(long)]
        max_ratio: Option<u64>,
        /// Cap the memory stuffr will ask for, e.g. 512M or 2G.
        ///
        /// Bounds the codec layer beneath the container, which `--max-ratio`
        /// cannot see: a pure xz/lzma/lzip decoder sizes its dictionary from
        /// a value the file declares in its own header, before producing any
        /// output. Defaults to 25% of available RAM, honouring cgroup limits.
        #[arg(long, value_name = "SIZE")]
        memory_limit: Option<String>,
        /// Fail (exit 4) if the read approximated or lost anything.
        ///
        /// A listing can be incomplete — a zip whose index shadows records
        /// enumerates fewer entries than the archive declares — so `list`
        /// gates on fidelity for the same reason `test` and `unpack -C` do.
        #[arg(long)]
        strict_fidelity: bool,
    },
    /// List what a folder holds that stuffr can open, or an archive's entries.
    ///
    /// Given a folder, or nothing (the current folder): one row per file
    /// stuffr can open, newest first, as `FORMAT  SIZE  DATE  NAME`, plus
    /// every subfolder as a `[FOLDER]` row. A file is listed when its first
    /// bytes carry a readable format's magic; nothing is decoded. A footer
    /// `N of M files shown, K not openable` counts the rest. A file or
    /// subfolder that cannot be read is named on stderr and the exit is 4.
    ///
    /// Given an archive or compressed file, or `-`: exactly `stuffr list`,
    /// with its options. `files` is a second name for the folder listing
    /// only.
    #[command(alias = "files")]
    Ls(LsArgs),
    /// Verify every entry's integrity without extracting.
    Test {
        /// Archive path, or `-` for stdin.
        input: String,
        /// Refuse a codec layer beneath the container expanding by more
        /// than this ratio (e.g. a `.tar.gz` bomb).
        #[arg(long)]
        max_ratio: Option<u64>,
        /// Cap the memory stuffr will ask for, e.g. 512M or 2G.
        ///
        /// Bounds the codec layer beneath the container, which `--max-ratio`
        /// cannot see: a pure xz/lzma/lzip decoder sizes its dictionary from
        /// a value the file declares in its own header, before producing any
        /// output. Defaults to 25% of available RAM, honouring cgroup limits.
        #[arg(long, value_name = "SIZE")]
        memory_limit: Option<String>,
        /// Fail (exit 4) if the read approximated or lost anything.
        #[arg(long)]
        strict_fidelity: bool,
    },
    /// Recover what a damaged zip's scan can prove, even where its central
    /// directory alone would show less — or would wrongly unify two records
    /// that happen to share a name.
    ///
    /// The one recovery-biased verb in this tool. `list`, `cat`, `unpack` and
    /// `test` all stay exactly as uncompromising as they already are, and it
    /// is salvage's willingness to accept less-than-proven content that buys
    /// them that freedom.
    Salvage {
        /// Input path.
        ///
        /// Salvage scans back and forth over the archive, which needs real
        /// random access — unlike every other verb here, this one does not
        /// accept `-` for stdin.
        input: String,
        /// Print every record the scan found, including ones this build
        /// never writes (a shadow, a skipped partial, an unverified entry).
        ///
        /// A record that repeats an earlier record's name is marked one of
        /// two ways, and they mean different things. `[shadowed: dup of #N]`
        /// is a MEASUREMENT: name, declared length and checksum all agree
        /// with record N, so nothing is lost by not writing this one.
        /// `[name collision: #N uses this name too]` is the weaker fact:
        /// the name repeats but the content was not proven identical, so
        /// both records are worth having and `-C` writes the second one as
        /// `name.salvaged-N`, never over the first. It is the marker
        /// `stuffr list`'s own "repeat a name … and are shadowed" fidelity
        /// warning corresponds to.
        ///
        /// `stuffr list` on the same archive can print FEWER rows than this:
        /// a record a later one shadows is invisible to `list`, which only
        /// ever sees what the central directory's own name index kept. Works
        /// with no destination at all (neither `-C` nor `-o`) — listing is
        /// not recovering, and this is the diagnostic half of the feature:
        /// seeing what an archive holds without extracting anything.
        #[arg(long)]
        list: bool,
        /// Recover entries into this directory.
        ///
        /// One of `-C`, `-o` or `--list` is required. Mutually exclusive
        /// with `-o`: a directory tree and one named file are two different
        /// destinations.
        ///
        /// A damaged archive can hold two records under one name. The
        /// second one recovered lands as `name.salvaged-N`, where N is its
        /// scan position, rather than over the first — both records exist,
        /// both are worth having, and the run exits 4 so a script knows a
        /// name had to be changed.
        #[arg(short = 'C', long, value_name = "DIR")]
        directory: Option<String>,
        /// Recover exactly one entry's bytes to this file, naming it with
        /// exactly one `--index N`.
        ///
        /// A `Partial` entry still lands under `FILE.partial`, never `FILE`
        /// itself — the same rule `-C` follows, for the same reason: a
        /// truncated file under the name you asked for would be
        /// indistinguishable from a whole one. Refused (exit 2) with more
        /// than one `--index`, or together with `-C`.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
        /// Recover only the record at this SCAN position instead of every
        /// one found. Repeatable with `-C`; `-o` takes exactly one.
        ///
        /// A scan position is 0-based and counts every record the scan
        /// found, shadowed ones included — a DIFFERENT numbering from
        /// `stuffr list`'s own index, which never counts a shadowed record at
        /// all. On an archive where a name is duplicated, `list --index 6`
        /// and `salvage --index 6` can name different entries, or `list`'s
        /// may not exist at all. Always a scan position, never a list index.
        #[arg(long, value_name = "N")]
        index: Vec<usize>,
        /// What to do with an entry whose payload could not be fully proven:
        /// `keep` (default) writes it as `name.partial`, never under its
        /// real name; `skip` recovers nothing for it; `ask` has no terminal
        /// to ask from at this layer and is read conservatively as `skip`.
        #[arg(long, value_name = "POLICY")]
        partial: Option<String>,
        /// Raise the structural ceiling on a single entry's declared length,
        /// e.g. 8G. A declaration over the ceiling is refused before
        /// anything is allocated on its say-so, either way.
        #[arg(long, value_name = "SIZE")]
        max_entry: Option<String>,
        /// Demand proof: skip every partial entry regardless of `--partial`,
        /// and every unattested one (a format with no checksum and no header
        /// self-check, whose entries are otherwise written under their real
        /// names). The strict path every other verb in this tool already
        /// stands on, applied here on request instead of by default.
        #[arg(long)]
        strict: bool,
        /// Use this format instead of detecting one.
        ///
        /// Selects among the formats this build's salvage can attempt to
        /// scan — `zip`, `tar`, `ar`, `cpio`, `arc`, `zoo`, `lha`, `arj` — not
        /// merely accepted or rejected as in an earlier stage. Naming one
        /// this build has no salvage scanner for is refused at exit 3,
        /// exactly as an undetected archive of that same format would be.
        /// `ar`'s scanner walks members in order and cannot cross a damaged
        /// header; it says on stderr where it stopped.
        ///
        /// Scanners exist for: zip, arc, zoo, lha, arj, tar, cpio, ar.
        #[arg(long)]
        format: Option<String>,
    },
}

/// The arguments of `stuffr ls` (alias `files`).
#[derive(Args, Debug)]
pub struct LsArgs {
    /// A folder (default: the current one), or an archive path or `-` to
    /// list its entries as `stuffr list` does.
    #[arg(value_name = "PATH")]
    pub path: Option<String>,
    /// Folder: also list inside subfolders, one block per folder that holds
    /// something stuffr can open. Symlinked folders are not followed.
    #[arg(short, long)]
    pub recursive: bool,
    /// Folder: include names starting with `.`.
    #[arg(short, long)]
    pub all: bool,
    /// Folder: sort by name instead of newest first.
    #[arg(short = 'n', long = "by-name")]
    pub by_name: bool,
    /// Emit machine-readable JSON: for a folder one object
    /// `{entries, shown, skipped, warnings}`; for an archive what `list
    /// --json` prints.
    #[arg(long)]
    pub json: bool,
    /// Archive only: refuse a codec layer beneath the container expanding
    /// by more than this ratio (e.g. a `.tar.gz` bomb).
    #[arg(long)]
    pub max_ratio: Option<u64>,
    /// Archive only: cap the memory stuffr will ask for, e.g. 512M or 2G.
    ///
    /// Bounds the codec layer beneath the container, which `--max-ratio`
    /// cannot see: a pure xz/lzma/lzip decoder sizes its dictionary from
    /// a value the file declares in its own header, before producing any
    /// output. Defaults to 25% of available RAM, honouring cgroup limits.
    #[arg(long, value_name = "SIZE")]
    pub memory_limit: Option<String>,
    /// Archive only: fail (exit 4) if the read approximated or lost
    /// anything.
    #[arg(long)]
    pub strict_fidelity: bool,
}

/// The arguments of `stuffr bench`.
#[derive(Args, Debug)]
pub struct BenchArgs {
    /// Files to benchmark, or quoted glob patterns (`'logs/*.log'`).
    ///
    /// A path that exists is used as is; one that does not and contains
    /// `*`, `?` or `[` is expanded, its matches sorted. A directory is
    /// refused: name its files instead. So is a pipe or device: bench needs
    /// each file's size, so write a pipe to a file first. A file it cannot
    /// open, a dangling symlink or an unreadable directory on the way is
    /// refused too, naming the path.
    #[arg(required = true, num_args = 1.., value_name = "INPUTS")]
    pub inputs: Vec<String>,
    /// Only these formats, comma-separated or repeated. Default: every codec
    /// this build can write with its real encoder.
    #[arg(long, value_name = "FORMAT", value_delimiter = ',')]
    pub formats: Vec<String>,
    /// Run every level of each format instead of its default level only.
    #[arg(long)]
    pub levels: bool,
    /// Compress each file as its own stream instead of all of them as one.
    #[arg(long)]
    pub per_file: bool,
    /// Compress with N worker threads. 0 means auto-detect.
    ///
    /// Threads apply to compression only: decompression is always timed
    /// single-threaded. OMITTING this flag is not the same as passing 0:
    /// without it, stuffr compresses single-threaded, so the same input
    /// always produces the same bytes on any machine. Multi-threaded xz and
    /// zstd split the input per worker, so their output depends on the
    /// worker count. bench ignores STUFFR_THREADS: threads come only from
    /// this flag.
    #[arg(long)]
    pub threads: Option<usize>,
    /// Cap the memory stuffr will ask for, e.g. 512M or 2G.
    ///
    /// Input over half of it is streamed from disk rather than held in
    /// memory. Each codec gets the output destination its own worst case
    /// allows: a codec whose worst-case output is too large for the rest
    /// writes to a temp file, whose writes then count in its compress time,
    /// and its row is marked (`*`; `output: disk`). Defaults to 25%
    /// of available RAM, honouring cgroup limits.
    #[arg(long, value_name = "SIZE")]
    pub memory_limit: Option<String>,
    /// Time each row N times and report the medians.
    #[arg(long, value_name = "N", default_value_t = 1,
          value_parser = clap::value_parser!(u32).range(1..))]
    pub repeat: u32,
    /// Emit one machine-readable JSON object instead of the table.
    #[arg(long, conflicts_with = "csv")]
    pub json: bool,
    /// Emit CSV, one line per row, instead of the table.
    #[arg(long)]
    pub csv: bool,
    /// Print the table alone: no input line, no winners, no progress.
    #[arg(short = 'q', long, conflicts_with_all = ["json", "csv"])]
    pub table_only: bool,
    /// Skip the memory columns: by default each row is run once more,
    /// untimed, in a child process to measure its peak compress and
    /// decompress memory (resident set).
    #[arg(long)]
    pub no_memory: bool,
}
