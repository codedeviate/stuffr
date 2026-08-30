//! The `stf` command.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use stuffr::FormatId;
use stuffr::ops::{self, CompressOpts, DecompressOpts, Input, Output};
use stuffr_cli::cli::{Cli, Command};

/// The `--examples` page. A static asset rather than an inline literal so it
/// reads (and diffs) like the terminal page it is, not like Rust source.
const EXAMPLES: &str = include_str!("examples.txt");

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
    let cli = Cli::parse();

    if cli.examples {
        print!("{EXAMPLES}");
        return ExitCode::SUCCESS;
    }

    let command = match cli.command {
        Some(c) => c,
        // `command` is `Option` (rather than clap enforcing a required
        // subcommand itself) purely so `--examples` can be given with no
        // subcommand at all. Absent both, reproduce clap's own behaviour for
        // a missing required subcommand by hand: the full help, on exit 2.
        None => {
            let _ = Cli::command().print_help();
            println!();
            return ExitCode::from(2);
        }
    };

    match run(command) {
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

fn run(command: Command) -> stuffr::Result<()> {
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
            no_sync,
        } => {
            let fmt = match format.as_deref() {
                Some(name) => Some(format_by_name(name)?),
                None => None,
            };
            let opts = CompressOpts {
                format: fmt,
                level,
                force,
                sync: !no_sync,
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
            no_sync,
        } => {
            let mut opts = DecompressOpts {
                force,
                sync: !no_sync,
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
            use std::io::Write;
            let i = ops::inspect(input_of(&input))?;
            let mut out = std::io::stdout();
            if json {
                writeln!(
                    out,
                    "{}",
                    serde_json::to_string(&i).expect("Inspection serializes")
                )?;
            } else {
                writeln!(out, "format:   {}", i.format)?;
                writeln!(out, "chain:    {}", i.chain)?;
                writeln!(out, "rung:     {}", i.fidelity.rung)?;
                match i.bytes_in {
                    Some(n) => writeln!(out, "size:     {n} bytes")?,
                    None => writeln!(out, "size:     unknown (stream)")?,
                }
                if i.fidelity.has_warnings() {
                    writeln!(out, "fidelity: {} warning(s)", i.fidelity.warnings.len())?;
                    for w in &i.fidelity.warnings {
                        writeln!(out, "  - {w}")?;
                    }
                } else {
                    writeln!(out, "fidelity: nothing approximated")?;
                }
            }
            Ok(())
        }
        Command::Formats => print_formats(),
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

/// Writes through `std::io::stdout()` and propagates a write failure rather
/// than `println!`ing it, so `run`'s `BrokenPipe`-to-success mapping can
/// actually see it.
///
/// `println!`/`print!` panic on a write error instead of returning one — see
/// the doc on `destination_is_stdout` — so `stf formats` and `stf info`
/// (which `destination_is_stdout` already lists as stdout destinations) used
/// to exit 101 with "failed printing to stdout: Broken pipe" instead of
/// exiting cleanly like every other early-closed-reader case.
fn print_formats() -> stuffr::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout();
    let rows = stuffr::registry().matrix();
    if rows.is_empty() {
        writeln!(out, "This build contains 0 formats.")?;
        writeln!(
            out,
            "(Phase 0 validates the core against mock formats; Phase 1 adds real ones.)"
        )?;
        return Ok(());
    }
    writeln!(
        out,
        "{:<16} {:<10} {:<5} {:<5} {:<8} EXTENSIONS",
        "FORMAT", "KIND", "READ", "WRITE", "PARALLEL"
    )?;
    for r in rows {
        writeln!(
            out,
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
        )?;
    }
    Ok(())
}
