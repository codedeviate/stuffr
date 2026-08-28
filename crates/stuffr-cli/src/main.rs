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

/// Whether a command's output goes to stdout — the only case in which a
/// `BrokenPipe` is the reader's decision rather than this program's failure.
///
/// `Cat`, `Info` and `Formats` never write anywhere else. `Pack` and `Unpack`
/// write to stdout only when `-o -` was passed explicitly; every other
/// destination is a real file, where a `BrokenPipe` mid-write would mean
/// something is actually wrong and must not be swallowed (see `run`).
fn destination_is_stdout(cmd: &Command) -> bool {
    match cmd {
        Command::Cat { .. } | Command::Info { .. } | Command::Formats => true,
        Command::Pack {
            output: Some(o), ..
        }
        | Command::Unpack {
            output: Some(o), ..
        } => o == "-",
        _ => false,
    }
}

fn run() -> stuffr::Result<()> {
    let command = Cli::parse().command;
    let stdout_dest = destination_is_stdout(&command);
    match dispatch(command) {
        Ok(()) => Ok(()),
        // Rust ignores SIGPIPE, so a write to a closed stdout surfaces as an
        // EPIPE `io::Error` rather than terminating the process outright. An
        // early-exiting consumer — `stf cat huge.gz | head`, `| grep -m1`,
        // `| less` — is the flagship workflow for a `cat`-shaped tool, and
        // every conventional Unix filter (zcat, gzip -d, cat itself) treats
        // that as normal termination, not a failure. Success, no message: the
        // consumer closing the pipe is the party that decided it had seen
        // enough.
        //
        // This must NOT fire for a file destination: `stf unpack a.gz -o
        // file` hitting BrokenPipe (e.g. a full disk manifesting oddly) would
        // otherwise map a real failure to exit 0 — `run` returning `Err`
        // still triggers `discard`, so the temp file is removed and the
        // process would report success having produced nothing at all.
        Err(stuffr::Error::Io(e)) if stdout_dest && e.kind() == std::io::ErrorKind::BrokenPipe => {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn dispatch(command: Command) -> stuffr::Result<()> {
    match command {
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
                "{} -> {} ({} -> {} bytes, {} fidelity)",
                input, out.format, out.bytes_in, out.bytes_out, out.fidelity.rung
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
///
/// Returns the built string rather than printing it directly, so a test can
/// inspect what it produced instead of only what `json_escape` alone
/// produces in isolation — see `builder_survives_a_hostile_warning_entry`
/// below.
fn build_info_json(i: &ops::Inspection) -> String {
    let warnings: Vec<String> = i
        .fidelity
        .warnings
        .iter()
        .map(|w| format!("\"{}\"", json_escape(&w.to_string())))
        .collect();
    format!(
        "{{\"format\":\"{}\",\"chain\":\"{}\",\"rung\":\"{}\",\"bytes_in\":{},\"warnings\":[{}]}}",
        json_escape(&i.format.to_string()),
        json_escape(&i.chain),
        i.rung,
        i.bytes_in.map_or("null".to_string(), |n| n.to_string()),
        warnings.join(",")
    )
}

fn print_info_json(i: &ops::Inspection) {
    println!("{}", build_info_json(i));
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
    use super::{build_info_json, json_escape};
    use stuffr::FormatId;
    use stuffr::ops::Inspection;
    use stuffr::{Fidelity, FidelityReport, Rung};

    #[test]
    fn json_escape_handles_quotes_backslashes_and_newlines() {
        assert_eq!(json_escape("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("line1\nline2"), "line1\\nline2");
        assert_eq!(json_escape("cr\rcr"), "cr\\rcr");
        assert_eq!(json_escape("tab\ttab"), "tab\\ttab");
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("\u{0001}"), "\\u0001");
    }

    /// F1's actual point: prove `build_info_json` (and therefore
    /// `print_info_json`) calls `json_escape` on data it does not control,
    /// not merely that `json_escape` behaves correctly in isolation. A
    /// black-box CLI test cannot reach this today — Phase 1b has no
    /// containers, so no CLI-reachable `Inspection` ever carries a warning —
    /// but the fields are public, so a synthetic one pins it right now and
    /// keeps working the moment Phase 2 adds real entry names.
    #[test]
    fn builder_survives_a_hostile_warning_entry() {
        // A warning entry name crafted to look like it's trying to close the
        // warning string and inject a sibling key into the top-level object.
        let hostile = "evil\", \"format\": \"pwned".to_string();

        let mut fidelity = FidelityReport::new(Rung::ForwardOnly);
        fidelity.warn(Fidelity::EncryptedEntrySkipped {
            entry: hostile.clone(),
        });

        let inspection = Inspection {
            format: FormatId::new("gzip"),
            chain: "gzip".to_string(),
            rung: Rung::ForwardOnly,
            fidelity,
            bytes_in: None,
        };

        let text = build_info_json(&inspection);
        let value: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("builder output was not valid JSON: {e}\n{text}"));

        // Exactly the five fields this payload has ever had — a successful
        // break-out would add or rename keys, not just corrupt one value.
        let obj = value.as_object().expect("top level must be a JSON object");
        assert_eq!(
            obj.len(),
            5,
            "a break-out would add/rename keys rather than just corrupt a value: {text}"
        );
        assert_eq!(value.get("format").and_then(|v| v.as_str()), Some("gzip"));
        assert_eq!(value.get("chain").and_then(|v| v.as_str()), Some("gzip"));
        assert!(value.get("pwned").is_none(), "no injected key: {text}");

        let warnings = value
            .get("warnings")
            .and_then(|w| w.as_array())
            .expect("warnings must still be an array");
        assert_eq!(warnings.len(), 1);
        let warning_text = warnings[0]
            .as_str()
            .expect("the warning must still be a single JSON string, not broken into pieces");
        assert!(
            warning_text.contains(&hostile),
            "the hostile entry text must survive intact as DATA: {warning_text}"
        );
    }
}
