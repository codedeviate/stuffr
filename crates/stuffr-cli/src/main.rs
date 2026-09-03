//! The `stuffr` command.

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
            eprintln!("stuffr: {e}");
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
        // early-exiting consumer — `stuffr cat huge.gz | head`, `| grep -m1`,
        // `| less` — is the flagship workflow for a `cat`-shaped tool, and
        // every conventional Unix filter (zcat, gzip -d, cat itself) treats
        // that as normal termination, not a failure. Success, no message: the
        // consumer closing the pipe is the party that decided it had seen
        // enough.
        //
        // This must NOT fire for a file destination: `stuffr unpack a.gz -o
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

/// Parses `--memory-limit` once, so all four subcommands report the same
/// message for the same bad input.
///
/// Was duplicated verbatim across every `dispatch` arm. Kept as a named
/// function rather than inlined because a size that parses differently
/// depending on which subcommand you typed would be a genuinely confusing bug,
/// and one copy cannot drift from another.
fn parse_memory_limit(raw: Option<String>) -> stuffr::Result<Option<u64>> {
    match raw {
        Some(s) => Ok(Some(
            stuffr_cli::size::parse_size(&s).map_err(stuffr::Error::Usage)?,
        )),
        None => Ok(None),
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
            allow_weak_encoder,
            threads,
            turbo,
            memory_limit,
        } => {
            // Parsing (and thus validating) `--memory-limit` here, ahead of
            // `ops::resolved_budget`, is deliberate: a malformed value must
            // be caught before anything else runs.
            let memory_limit = parse_memory_limit(memory_limit)?;
            let fmt = match format.as_deref() {
                Some(name) => Some(format_by_name(name)?),
                None => None,
            };
            let opts = CompressOpts {
                format: fmt,
                level,
                force,
                sync: !no_sync,
                allow_weak_encoder,
                threads,
                turbo,
                memory_limit,
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
            format,
            max_ratio,
            no_sync,
            memory_limit,
        } => {
            // Decode has no worker count to govern (multi-threaded decode is
            // out of scope this phase), but it does bound dictionary
            // allocation for the pure codecs that size a buffer from a value
            // the file declares in its own header — see
            // `stuffr_core::DecodeOpts::memory_limit`. The CLI default is
            // the bound, not unbounded: a bound that defaults off closes
            // nothing.
            let memory_limit = Some(
                parse_memory_limit(memory_limit)?.unwrap_or_else(stuffr::default_memory_limit),
            );
            let fmt = match format.as_deref() {
                Some(name) => Some(format_by_name(name)?),
                None => None,
            };
            let mut opts = DecompressOpts {
                force,
                sync: !no_sync,
                memory_limit,
                ..Default::default()
            };
            opts.format = fmt;
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
        Command::Cat {
            input,
            format,
            max_ratio,
            memory_limit,
        } => {
            // Same as `unpack`: bounds dictionary allocation for the pure
            // codecs; the CLI default is the bound, not unbounded.
            let memory_limit = Some(
                parse_memory_limit(memory_limit)?.unwrap_or_else(stuffr::default_memory_limit),
            );
            let fmt = match format.as_deref() {
                Some(name) => Some(format_by_name(name)?),
                None => None,
            };
            let mut opts = DecompressOpts {
                format: fmt,
                memory_limit,
                ..Default::default()
            };
            if let Some(r) = max_ratio {
                opts.max_ratio = r;
            }
            // The motivating case: `curl … | stuffr cat - | grep pattern`.
            ops::decompress(input_of(&input), Output::Stdout, &opts)?;
            Ok(())
        }
        Command::Info {
            input,
            json,
            memory_limit,
        } => {
            use std::io::Write;
            // `info` takes no `--threads`, so there is no worker count to
            // resolve or print here — only the memory limit a subsequent
            // pack/unpack would use, the same value `--memory-limit`
            // resolves to on those subcommands (an explicit value, or
            // `default_memory_limit()`'s 25%-of-available-RAM reading).
            let memory_limit =
                parse_memory_limit(memory_limit)?.unwrap_or_else(stuffr::default_memory_limit);
            let i = ops::inspect(input_of(&input))?;
            let mut out = std::io::stdout();
            if json {
                let mut v = serde_json::to_value(&i).expect("Inspection serializes");
                if let serde_json::Value::Object(ref mut map) = v {
                    map.insert("memory_limit".into(), serde_json::json!(memory_limit));
                }
                writeln!(out, "{v}")?;
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
                writeln!(
                    out,
                    "memory:   {}",
                    stuffr_cli::size::format_size(memory_limit)
                )?;
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
/// the doc on `destination_is_stdout` — so `stuffr formats` and `stuffr info`
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
    writeln!(
        out,
        "(WRITE shows `weak` for a codec whose encoder in this build is a fallback markedly \
         worse than the format's usual one — see --allow-weak-encoder.)"
    )?;
    let registry = stuffr::registry();
    for r in rows {
        // A codec's own capabilities, not the matrix row's read/write/parallel
        // summary, are what carry `weak_encoder` — look it up directly rather
        // than growing FormatRow for one column only `stuffr formats` reads.
        let weak = r.write
            && r.kind == stuffr::FormatKind::Codec
            && registry.codec(r.id).is_some_and(|c| c.caps().weak_encoder);
        writeln!(
            out,
            "{:<16} {:<10} {:<5} {:<5} {:<8} {}",
            r.id.as_str(),
            match r.kind {
                stuffr::FormatKind::Codec => "codec",
                stuffr::FormatKind::Container => "container",
            },
            if r.read { "yes" } else { "-" },
            if weak {
                "weak"
            } else if r.write {
                "yes"
            } else {
                "-"
            },
            if r.parallel { "yes" } else { "-" },
            r.extensions.join(", "),
        )?;
    }
    Ok(())
}
