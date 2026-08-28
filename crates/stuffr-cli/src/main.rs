//! The `stf` command.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use stuffr::FormatId;
use stuffr::ops::{self, CompressOpts, DecompressOpts, Input, Output};

#[derive(Parser)]
#[command(
    name = "stf",
    version,
    about = "Universal compression and archive toolkit"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    },
    /// List the formats this build contains.
    Formats,
}

/// `-` means the stream, everywhere.
fn input_of(s: &str) -> Input {
    if s == "-" {
        Input::Stdin
    } else {
        Input::Path(PathBuf::from(s))
    }
}

fn output_of(s: &str) -> Output {
    if s == "-" {
        Output::Stdout
    } else {
        Output::Path(PathBuf::from(s))
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("stf: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

fn run() -> stuffr::Result<()> {
    match Cli::parse().command {
        Command::Pack {
            input,
            output,
            format,
            level,
            force,
        } => {
            let fmt = match format.as_deref() {
                Some(name) => Some(format_by_name(name)?),
                None => None,
            };
            let opts = CompressOpts {
                format: fmt,
                level,
                force,
            };
            let dst = match output {
                Some(o) => output_of(&o),
                None => {
                    let path = match input_of(&input) {
                        Input::Path(p) => p,
                        Input::Stdin => {
                            return Err(stuffr::Error::Usage(
                                "reading stdin needs an explicit -o".into(),
                            ));
                        }
                    };
                    let chosen = match fmt {
                        Some(f) => f,
                        None => ops::default_format()?,
                    };
                    Output::Path(ops::suggest_packed(&path, chosen)?)
                }
            };
            let out = ops::compress(input_of(&input), dst, &opts)?;
            eprintln!(
                "{} -> {} ({} -> {} bytes)",
                input, out.format, out.bytes_in, out.bytes_out
            );
            Ok(())
        }
        Command::Unpack {
            input,
            output,
            force,
            max_ratio,
        } => {
            let mut opts = DecompressOpts {
                force,
                ..Default::default()
            };
            if let Some(r) = max_ratio {
                opts.max_ratio = r;
            }
            let dst = match output {
                Some(o) => output_of(&o),
                None => match input_of(&input) {
                    Input::Path(p) => Output::Path(ops::suggest_unpacked(&p)?),
                    Input::Stdin => {
                        return Err(stuffr::Error::Usage(
                            "reading stdin needs an explicit -o".into(),
                        ));
                    }
                },
            };
            let out = ops::decompress(input_of(&input), dst, &opts)?;
            eprintln!("{} -> {} bytes", out.format, out.bytes_out);
            Ok(())
        }
        Command::Formats => {
            print_formats();
            Ok(())
        }
    }
}

/// Resolves a `--format` name against the registry.
///
/// `FormatId` holds a `&'static str` so the registry can be built from
/// constants without allocation, but a flag value arrives at runtime as a
/// `String`. Rather than leak it to reach `'static`, look it up: the registry
/// already holds the `'static` id, and an unknown name gets a real error
/// naming what this build does have.
fn format_by_name(name: &str) -> stuffr::Result<FormatId> {
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

fn print_formats() {
    let rows = stuffr::registry().matrix();
    if rows.is_empty() {
        println!("This build contains 0 formats.");
        println!("(Phase 0 validates the core against mock formats; Phase 1 adds real ones.)");
        return;
    }
    println!(
        "{:<16} {:<10} {:<5} {:<5} {:<8} EXTENSIONS",
        "FORMAT", "KIND", "READ", "WRITE", "PARALLEL"
    );
    for r in rows {
        println!(
            "{:<16} {:<10} {:<5} {:<5} {:<8} {}",
            r.id.as_str(),
            match r.kind {
                stuffr::FormatKind::Codec => "codec",
                stuffr::FormatKind::Container => "container",
            },
            if r.read { "yes" } else { "-" },
            if r.write { "yes" } else { "-" },
            if r.parallel { "yes" } else { "-" },
            r.extensions.join(", "),
        );
    }
}
