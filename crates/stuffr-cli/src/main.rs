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
        Command::Cat { input } => {
            // The motivating case: `curl … | stf cat - | grep pattern`.
            ops::decompress(input_of(&input), Output::Stdout, &DecompressOpts::default())?;
            Ok(())
        }
        Command::Info { input, json } => {
            let i = ops::inspect(input_of(&input))?;
            if json {
                print_info_json(&i);
            } else {
                println!("format:   {}", i.format);
                println!("chain:    {}", i.chain);
                println!("rung:     {}", i.rung);
                match i.bytes_in {
                    Some(n) => println!("size:     {n} bytes"),
                    None => println!("size:     unknown (stream)"),
                }
                if i.fidelity.has_warnings() {
                    println!("fidelity: {} warning(s)", i.fidelity.warnings.len());
                    for w in &i.fidelity.warnings {
                        println!("  - {w}");
                    }
                } else {
                    println!("fidelity: nothing approximated");
                }
            }
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

/// Escapes a string for embedding in the hand-rolled JSON below.
///
/// At minimum: `"`, `\`, and the control characters (`\n`, `\r`, `\t`, and any
/// other byte below 0x20 as `\u00XX`).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Hand-rolled rather than serde: the payload is a handful of fields, so a
/// dozen lines of escaping is cheaper than the dependency. It is NOT true that
/// there is nothing to escape, though — `warnings` holds `Fidelity` values,
/// and several of its variants (`SizeFromDataDescriptor`, `MetadataIncomplete`,
/// `EncryptedEntrySkipped`) embed entry names read from the archive itself, so
/// a hostile or merely unlucky entry name could otherwise break or forge this
/// JSON. `format` and `chain` are escaped too, on the same principle: nothing
/// that can ever originate outside this binary should be trusted to already
/// be valid JSON. Revisit this once Phase 2 makes the payload structurally
/// bigger than escaping-by-hand can comfortably cover.
fn print_info_json(i: &ops::Inspection) {
    let warnings: Vec<String> = i
        .fidelity
        .warnings
        .iter()
        .map(|w| format!("\"{}\"", json_escape(&w.to_string())))
        .collect();
    println!(
        "{{\"format\":\"{}\",\"chain\":\"{}\",\"rung\":\"{}\",\"bytes_in\":{},\"warnings\":[{}]}}",
        json_escape(&i.format.to_string()),
        json_escape(&i.chain),
        i.rung,
        i.bytes_in.map_or("null".to_string(), |n| n.to_string()),
        warnings.join(",")
    );
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

#[cfg(test)]
mod tests {
    use super::json_escape;

    #[test]
    fn json_escape_handles_quotes_backslashes_and_newlines() {
        assert_eq!(json_escape("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("line1\nline2"), "line1\\nline2");
        assert_eq!(json_escape("tab\ttab"), "tab\\ttab");
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("\u{0001}"), "\\u0001");
    }
}
