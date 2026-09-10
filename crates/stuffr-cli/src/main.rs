//! The `stuffr` command.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use stuffr::FormatId;
use stuffr::entries::{self, ExtractOpts};
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
/// `Cat`, `Info`, `Formats` and `List` never write anywhere else — `List`
/// prints one line per entry (or a JSON array) straight to stdout, the same
/// early-closing-reader shape as `Cat` (e.g. `stuffr list big.tar | head`).
/// `Pack` and `Unpack` write to stdout only when `-o -` was passed
/// explicitly; every other destination is a real file, where a `BrokenPipe`
/// mid-write would mean something is actually wrong and must not be
/// swallowed (see `run`).
fn destination_is_stdout(cmd: &Command) -> bool {
    match cmd {
        Command::Cat { .. } | Command::Info { .. } | Command::Formats | Command::List { .. } => {
            true
        }
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
            paths,
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

            // A container output collects every path into one archive; a
            // codec output compresses exactly one stream.
            if let Some(container) = container_output(fmt, output.as_deref()) {
                refuse_unhonoured_pack_flags(&opts)?;
                let inputs = pack_inputs(&paths)?;
                let dst = match output {
                    Some(o) => output_of(&o),
                    // One path can still name its own archive
                    // (`notes.txt` + `--format tar` -> `notes.txt.tar`);
                    // several have no single name to derive from.
                    None if inputs.len() == 1 => {
                        Output::Path(ops::suggest_packed(&inputs[0], container)?)
                    }
                    None => {
                        return Err(stuffr::Error::Usage(
                            "collecting several paths into an archive needs an explicit                              -o NAME.tar"
                                .into(),
                        ));
                    }
                };
                let out = entries::create_archive(&inputs, dst, container, &opts)?;
                eprintln!(
                    "{} entries -> {} ({} -> {} bytes, {} fidelity)",
                    inputs.len(),
                    out.format,
                    out.bytes_in,
                    out.bytes_out,
                    out.fidelity.rung
                );
                return Ok(());
            }

            if paths.len() > 1 {
                return Err(stuffr::Error::Usage(format!(
                    "packing {} paths needs an output naming a container (`-o bundle.tar`,                      or --format tar); a codec compresses one stream and has nowhere to                      put a second. A container inside a codec (`bundle.tar.gz`) cannot be                      written in one step yet: pack the .tar, then pack that.",
                    paths.len()
                )));
            }
            let input = paths.into_iter().next().expect("clap requires one path");
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
            patterns,
            directory,
            output,
            force,
            format,
            max_ratio,
            no_sync,
            memory_limit,
            strict_fidelity,
        } => {
            // -C is what asks for entry-aware extraction. It is a flag rather
            // than something inferred from the input because the decision has
            // to be made before a byte is read: a pipe cannot be probed and
            // then re-dispatched.
            if let Some(dir) = directory {
                refuse_unhonoured_extract_flags(output.is_some(), format.is_some())?;
                let opts = ExtractOpts {
                    max_ratio: max_ratio.unwrap_or(stuffr::DEFAULT_MAX_RATIO),
                    force,
                    // Honoured now, not refused: `open_archive` threads it
                    // into `resolve_chain_deep_with`, so the codec layer
                    // beneath the container gets the same bound the
                    // single-stream path has always had. As there, the CLI
                    // default is the bound rather than unbounded.
                    memory_limit: Some(
                        parse_memory_limit(memory_limit)?
                            .unwrap_or_else(stuffr::default_memory_limit),
                    ),
                    ..Default::default()
                };
                let out = entries::extract(input_of(&input), Path::new(&dir), &patterns, &opts)?;
                eprintln!(
                    "{} -> {} bytes extracted into {dir} ({} fidelity)",
                    out.format, out.bytes_out, out.fidelity.rung
                );
                return report_fidelity(&out.fidelity, strict_fidelity);
            }
            if !patterns.is_empty() {
                return Err(stuffr::Error::Usage(format!(
                    "`{}` names an archive entry; pass -C DIR to say where entries                      should be extracted to",
                    patterns[0]
                )));
            }
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
            report_fidelity(&out.fidelity, strict_fidelity)
        }
        Command::Cat {
            input,
            patterns,
            format,
            max_ratio,
            memory_limit,
        } => {
            // Naming an entry is what asks for entry-aware streaming — the
            // same "decide before reading a byte" reasoning as `unpack`'s -C.
            if !patterns.is_empty() {
                refuse_unhonoured_extract_flags(false, format.is_some())?;
                // Honoured now, not refused — see `unpack -C` above.
                let memory_limit = Some(
                    parse_memory_limit(memory_limit)?.unwrap_or_else(stuffr::default_memory_limit),
                );
                // The motivating case: `curl … | stuffr cat - log.txt`.
                let mut out = std::io::stdout();
                entries::cat(
                    input_of(&input),
                    &patterns,
                    max_ratio.unwrap_or(stuffr::DEFAULT_MAX_RATIO),
                    memory_limit,
                    &mut out,
                )?;
                return Ok(());
            }
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
                // Three cases, not two. `info` identifies a stream without
                // decoding it, so where a forward read of the container COULD
                // have approximated something it has not looked and must not
                // say — asserting "nothing approximated" there was a false
                // positive, contradicted by `stuffr test` on the very same
                // bytes for a piped zip. Withholding it for every container
                // instead would be a false NEGATIVE, since a forward read of
                // a tar genuinely loses nothing; the rule is narrowed to the
                // cases where loss is possible. The rung above is real in all
                // three. See `ops::Inspection::fidelity_evaluated`.
                if !i.fidelity_evaluated {
                    writeln!(
                        out,
                        "fidelity: not evaluated (info does not open the archive; \
                         run `stuffr test` for that)"
                    )?;
                } else if i.fidelity.has_warnings() {
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
        Command::List {
            input,
            json,
            max_ratio,
            memory_limit,
        } => {
            // `list` advertises reading nothing and extracting nothing, but
            // reaching the container's first header still decodes whatever
            // codec sits above it — so it needs the same bound every other
            // decoding verb has, defaulted the same way.
            let memory_limit = Some(
                parse_memory_limit(memory_limit)?.unwrap_or_else(stuffr::default_memory_limit),
            );
            print_list(
                input_of(&input),
                json,
                max_ratio.unwrap_or(stuffr::DEFAULT_MAX_RATIO),
                memory_limit,
            )
        }
        Command::Test {
            input,
            max_ratio,
            memory_limit,
            strict_fidelity,
        } => {
            let memory_limit = Some(
                parse_memory_limit(memory_limit)?.unwrap_or_else(stuffr::default_memory_limit),
            );
            let out = entries::test(
                input_of(&input),
                max_ratio.unwrap_or(stuffr::DEFAULT_MAX_RATIO),
                memory_limit,
            )?;
            eprintln!(
                "{} -> {} bytes verified ({} fidelity)",
                out.format, out.bytes_out, out.fidelity.rung
            );
            report_fidelity(&out.fidelity, strict_fidelity)
        }
    }
}

/// Prints what an operation approximated, and fails under --strict-fidelity.
///
/// The report is printed either way: a caller who did not ask for the gate
/// still needs to be able to SEE that an entry's mode was dropped, and a
/// caller who did needs to know which entries to look at — `FidelityDegraded`
/// carries only a count.
///
/// Capped at ten lines: an archive of ten thousand symlinks would otherwise
/// bury the summary line under ten thousand identical ones. The count in the
/// header is the complete figure regardless.
fn report_fidelity(report: &stuffr::FidelityReport, strict: bool) -> stuffr::Result<()> {
    if !report.has_warnings() {
        return Ok(());
    }
    const SHOWN: usize = 10;
    eprintln!("stuffr: {} fidelity warning(s):", report.warnings.len());
    for w in report.warnings.iter().take(SHOWN) {
        eprintln!("  - {w}");
    }
    if let Some(rest) = report.warnings.len().checked_sub(SHOWN).filter(|n| *n > 0) {
        eprintln!("  … and {rest} more");
    }
    if strict {
        return Err(stuffr::Error::FidelityDegraded(report.warnings.len()));
    }
    Ok(())
}

/// The container an output names, if it names one at all — `--format tar`, or
/// an extension that resolves to a container (`-o bundle.tar`).
///
/// `None` means the output names a codec (or nothing yet), which is the
/// single-stream path `pack` has always taken.
fn container_output(fmt: Option<FormatId>, output: Option<&str>) -> Option<FormatId> {
    let registry = stuffr::registry();
    if let Some(id) = fmt {
        // An explicit --format wins outright, exactly as it does for a codec.
        return registry.container(id).map(|_| id);
    }
    let ext = Path::new(output?).extension()?.to_str()?;
    let id = registry.by_extension(ext)?;
    registry.container(id).map(|_| id)
}

/// The paths `pack` will store as entries.
///
/// `-` is refused here: a pipe has no name, and every entry in an archive
/// needs one. The single-stream path still accepts it.
fn pack_inputs(paths: &[String]) -> stuffr::Result<Vec<PathBuf>> {
    if paths.iter().any(|p| p == "-") {
        return Err(stuffr::Error::Usage(
            "stdin has no name to store an entry under; name files instead of `-`".into(),
        ));
    }
    Ok(paths.iter().map(PathBuf::from).collect())
}

/// Refuses the flags the entry-aware path cannot honour.
///
/// The tree's rule, already applied to `--threads` on the decode subcommands:
/// a flag that would be silently accepted and ignored is refused instead.
///
/// `--no-sync` is deliberately NOT in this list. Extraction writes each entry
/// straight to its final path with no fsync at all, so "skip the fsync" is
/// already what happens — a flag asking for the behaviour you are getting
/// cannot mislead anybody.
fn refuse_unhonoured_extract_flags(output: bool, format: bool) -> stuffr::Result<()> {
    if output {
        return Err(stuffr::Error::Usage(
            "-o writes one decoded stream to one file; -C extracts entries into a \
             directory. Pass one or the other."
                .into(),
        ));
    }
    if format {
        return Err(stuffr::Error::Usage(
            "--format names a codec for a single-stream decode; entry-aware extraction \
             detects the container (and any codec above it) from the archive itself"
                .into(),
        ));
    }
    Ok(())
}

/// Refuses the flags the container `pack` path cannot honour.
///
/// `entries::create_archive` builds `CreateOpts { level, ..Default::default() }`
/// — no governor, no worker count, no weak-encoder consent — because none of
/// the four registered containers compresses anything itself. Accepting
/// `--threads`, `--turbo` or `--allow-weak-encoder` there and silently
/// dropping them is the exact shape `refuse_unhonoured_extract_flags` above
/// exists to prevent, and the extract side already refuses rather than
/// accepts. `--memory-limit` is deliberately NOT here: it is honoured on
/// every decode path, and on the container pack path it is simply inert in
/// the same way `--no-sync` is (nothing allocates a dictionary), so it costs
/// nothing to accept.
fn refuse_unhonoured_pack_flags(opts: &CompressOpts) -> stuffr::Result<()> {
    if opts.threads.is_some() {
        return Err(stuffr::Error::Usage(
            "--threads governs a codec's parallel encoder; no container in this build \
             compresses anything itself, so there is no worker count to hand it"
                .into(),
        ));
    }
    if opts.turbo {
        return Err(stuffr::Error::Usage(
            "--turbo lifts the CPU cap for a codec's parallel encoder; no container in \
             this build compresses anything itself"
                .into(),
        ));
    }
    if opts.allow_weak_encoder {
        return Err(stuffr::Error::Usage(
            "--allow-weak-encoder consents to a codec's fallback encoder; no container \
             in this build compresses anything itself"
                .into(),
        ));
    }
    Ok(())
}

/// The kind column `list` prints — `EntryKind` is `#[non_exhaustive]`, so a
/// future variant added upstream falls into the wildcard rather than failing
/// to compile.
fn entry_kind_str(kind: &stuffr::EntryKind) -> &'static str {
    match kind {
        stuffr::EntryKind::File => "file",
        stuffr::EntryKind::Dir => "dir",
        stuffr::EntryKind::Symlink { .. } => "symlink",
        stuffr::EntryKind::Other => "other",
        _ => "other",
    }
}

/// `list`'s output. Written through `std::io::stdout()` and propagated with
/// `?` rather than `println!`, matching `print_formats`/`Info` above — the
/// same reason: `println!` panics on a write error, which would defeat
/// `run`'s `BrokenPipe`-to-success mapping for `stuffr list big.tar | head`.
fn print_list(
    src: Input,
    json: bool,
    max_ratio: u64,
    memory_limit: Option<u64>,
) -> stuffr::Result<()> {
    use std::io::Write;
    let entries = entries::list(src, max_ratio, memory_limit)?;
    let mut out = std::io::stdout();
    if json {
        let rows: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.name,
                    "kind": entry_kind_str(&e.kind),
                    "size": e.size,
                })
            })
            .collect();
        writeln!(out, "{}", serde_json::Value::Array(rows))?;
    } else {
        for e in &entries {
            match e.size {
                Some(n) => writeln!(out, "{n:>12}  {}", e.name)?,
                None => writeln!(out, "{:>12}  {}", "-", e.name)?,
            }
        }
    }
    Ok(())
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
    // Below the table, not between the header and the first row. Inline, it
    // separated the column headings from the data they label, which made the
    // whole table hard to scan.
    writeln!(out)?;
    writeln!(
        out,
        "(WRITE shows `weak` for a codec whose encoder in this build is a fallback markedly \
         worse than the format's usual one — see --allow-weak-encoder.)"
    )?;
    Ok(())
}
