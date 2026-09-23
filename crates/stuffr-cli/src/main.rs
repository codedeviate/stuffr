//! The `stuffr` command.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use stuffr::FormatId;
use stuffr::entries::{self, ExtractOpts, SalvageOpts, Selection};
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
        // Only the `--list` row-per-record report is the "big data to
        // stdout" shape `Cat`/`List` are; the default summary line goes to
        // stderr the same way `unpack`/`test` print theirs.
        Command::Salvage { list, .. } => *list,
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
            strict_fidelity,
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
            if let Some((container, codec)) = resolve_pack_chain(fmt, output.as_deref())? {
                refuse_unhonoured_pack_flags(&opts, codec.is_some())?;
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
                            "collecting several paths into an archive needs an explicit \
                             -o NAME.tar"
                                .into(),
                        ));
                    }
                };
                let out = entries::create_archive(&inputs, dst, container, codec, &opts)?;
                // `inputs.len()` is the number of paths NAMED, which since
                // Phase 2c is no longer the number of entries written: one
                // named directory is a whole tree. Saying "paths" rather than
                // "entries" is the one-word fix; the entry count is not on
                // `Outcome` and is not worth a field there.
                // NOT `out.fidelity.rung`. `Rung` describes the adaptive READ
                // ladder; on the write side `entries::create_archive` sets it
                // to the constant `Rung::Exact`, so printing it made
                // `pack proj -o out.ar` announce "exact fidelity" and then
                // name four losses on the next four lines. A count of what
                // was actually lost is the one number here that is true, and
                // it agrees with the list `report_fidelity` prints below it.
                let losses = out.fidelity.warnings.len();
                eprintln!(
                    "{} path(s) -> {} ({} -> {} bytes, {})",
                    inputs.len(),
                    out.format,
                    out.bytes_in,
                    out.bytes_out,
                    match losses {
                        0 => "no fidelity loss".to_string(),
                        n => format!("{n} fidelity loss(es)"),
                    }
                );
                // Said every run, and deliberately NOT routed through
                // `report_fidelity`: a note is something stuffr did correctly
                // that the user should know about, not something they lost,
                // so it must not reach the --strict-fidelity gate. See
                // `Outcome::notes`.
                for note in &out.notes {
                    eprintln!("stuffr: note: {note}");
                }
                // The same call the read side makes, not a second printer:
                // pack's fidelity report now carries real warnings (what the
                // walk could not store, what this container has no shape
                // for), and --strict-fidelity turns them into exit 4 here
                // exactly as it does for `unpack -C` and `test`.
                return report_fidelity(&out.fidelity, strict_fidelity);
            }

            if paths.len() > 1 {
                return Err(stuffr::Error::Usage(format!(
                    "packing {} paths needs an output naming a container (`-o bundle.tar`, \
                     or --format tar); a codec compresses one stream and has nowhere to \
                     put a second. A container INSIDE a codec does work in one step — \
                     `-o bundle.tar.gz` and `-o bundle.tgz` both name a container.",
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
            // Honoured on the single-stream path too, rather than accepted
            // and ignored — the tree's rule for a flag that would otherwise
            // mislead. A codec encode loses nothing today, so this reports
            // nothing today; a codec that ever does will be heard.
            report_fidelity(&out.fidelity, strict_fidelity)
        }
        Command::Unpack {
            input,
            patterns,
            index,
            directory,
            output,
            force,
            format,
            max_ratio,
            no_sync,
            memory_limit,
            strict_fidelity,
        } => {
            let named_entries = !patterns.is_empty() || !index.is_empty();
            // -C is what asks for entry-aware extraction. It is a flag rather
            // than something inferred from the input because the decision has
            // to be made before a byte is read: a pipe cannot be probed and
            // then re-dispatched.
            if let Some(dir) = directory {
                let selection = selection_of(patterns, index)?;
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
                let out = entries::extract(input_of(&input), Path::new(&dir), &selection, &opts)?;
                eprintln!(
                    "{} -> {} bytes extracted into {dir} ({} fidelity)",
                    out.format, out.bytes_out, out.fidelity.rung
                );
                return report_fidelity(&out.fidelity, strict_fidelity);
            }
            if named_entries {
                // `--index 6` needs the same refusal a pattern gets, and for
                // the same reason: it selects entries, and without -C there is
                // nowhere for entries to go. Naming the selector the user
                // actually typed keeps the message actionable.
                let named = match patterns.first() {
                    Some(p) => format!("`{p}`"),
                    None => format!("`--index {}`", index[0]),
                };
                return Err(stuffr::Error::Usage(format!(
                    "{named} names an archive entry; pass -C DIR to say where entries \
                     should be extracted to"
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
            index,
            format,
            max_ratio,
            memory_limit,
        } => {
            // Naming an entry is what asks for entry-aware streaming — the
            // same "decide before reading a byte" reasoning as `unpack`'s -C.
            // `--index 6` says it just as explicitly as a name does.
            if !patterns.is_empty() || !index.is_empty() {
                let selection = selection_of(patterns, index)?;
                refuse_unhonoured_extract_flags(false, format.is_some())?;
                // Honoured now, not refused — see `unpack -C` above.
                let memory_limit = Some(
                    parse_memory_limit(memory_limit)?.unwrap_or_else(stuffr::default_memory_limit),
                );
                // The motivating case: `curl … | stuffr cat - log.txt`.
                let mut out = std::io::stdout();
                entries::cat(
                    input_of(&input),
                    &selection,
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
            strict_fidelity,
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
                strict_fidelity,
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
            // The rung is worth printing here, unlike on the write side where
            // it is a constant — a read really did land on one of four rungs,
            // and which one it was is diagnostic. What it must not do is
            // stand in for the LOSS. "exact fidelity" describes the access
            // path, and an exact read of a zip whose index shadows two of its
            // own records loses those two records anyway, so announcing
            // "exact fidelity" on a report that carries warnings makes
            // exactly the claim this tool exists not to make. Same ruling
            // `pack`'s summary line already carries, for the same reason: when
            // something was lost, the honest number is how much.
            let losses = out.fidelity.warnings.len();
            eprintln!(
                "{} -> {} bytes verified ({})",
                out.format,
                out.bytes_out,
                match losses {
                    0 => format!("{} fidelity", out.fidelity.rung),
                    n => format!("{} access, {n} fidelity loss(es)", out.fidelity.rung),
                }
            );
            report_fidelity(&out.fidelity, strict_fidelity)
        }
        Command::Salvage {
            input,
            list,
            directory,
            output,
            index,
            partial,
            max_entry,
            strict,
            format,
        } => {
            let code = dispatch_salvage(SalvageArgs {
                input,
                list,
                directory,
                output,
                index,
                partial,
                max_entry,
                strict,
                format,
            })?;
            // `code` is the aggregate bucket `entries::salvage_exit_code`
            // computed over a run that COMPLETED (`Ok`) — 0, 3, 4 or 5, per
            // Ruling R-N. It is not an `Error`: a completed salvage run that
            // recovered something partial or skipped a shadow is not this
            // program failing, so there is no `stuffr::Error` variant to
            // carry the number honestly (every existing one whose exit code
            // matches also carries a Display string tied to a DIFFERENT
            // shape, e.g. `FidelityDegraded`'s "under strict mode", which
            // salvage's own `--strict` does not mean). `run`'s own
            // Ok/Err-to-`ExitCode` mapping has no third option, so a
            // non-zero bucket here exits directly rather than round-tripping
            // through it — the report was already printed by
            // `dispatch_salvage`, so nothing is lost by not returning.
            //
            // Exit 7 (path escape) never reaches here: `entries::salvage`
            // raises it as `Err` before a `SalvageOutcome` exists at all
            // (see `salvage_exit_code`'s own doc), and the `?` above already
            // propagated it through the normal `Error::exit_code` path.
            // Exit 6 used to be in this sentence — an entry over the ceiling
            // aborted the run the same way — and since Task 3c's fix round 3
            // it is not raised by salvage at all: such an entry is reported
            // `Unverified (over the ceiling)` and lands in bucket 3, so one
            // oversized declaration no longer costs every other entry.
            //
            // Safe despite every `--list` row having already gone to stdout
            // by this point: `std::io::Stdout` is an unconditional
            // `LineWriter`, never block-buffered even for a pipe (unlike C's
            // stdio), and every row this module prints ends in `\n` — so the
            // bytes are already on the fd before `process::exit` runs.
            // Measured directly, not merely reasoned about: 8 rows and 501
            // rows (a 500-file archive), through both a pipe and a file
            // redirect, landed every row with the correct trailing content
            // and exit code. The safety is INCIDENTAL to every write ending
            // in a newline, not structural — a future edit that writes a
            // partial line on this path (a `write!` in place of a
            // `writeln!`) would silently reintroduce the hazard, with
            // nothing here to catch it.
            if code == 0 {
                Ok(())
            } else {
                std::process::exit(code)
            }
        }
    }
}

/// One record's status, named the way [`stuffr::salvage::SalvageStatus`]
/// itself is proven, before anything the write side decided is layered on.
///
/// `Partial` carries no cause on the status alone — [`describe_salvage_row`]
/// overrides it with one whenever [`entries::SalvageDisposition::
/// WrittenPartial`] or (fix round 1, REQUIRED 3)
/// [`entries::SalvageDisposition::SkippedPartial`] has one to give, which is
/// always, now that both variants carry a cause. `Unverified` is different:
/// its cause is part of the status itself, proven at scan time, so it is
/// always known here directly.
fn describe_salvage_status(status: stuffr::salvage::SalvageStatus) -> &'static str {
    use stuffr::salvage::{SalvageStatus, UnverifiedCause};
    match status {
        SalvageStatus::Intact => "Intact",
        SalvageStatus::Complete => "Complete",
        SalvageStatus::Partial => "Partial",
        SalvageStatus::Unverified(UnverifiedCause::UndecodableMethod) => {
            "Unverified (undecodable method)"
        }
        SalvageStatus::Unverified(UnverifiedCause::NoDeclaredLength) => {
            "Unverified (no declared length)"
        }
        // The entry is larger than this run will read for one entry
        // (`--max-entry`, narrowed by a whole-decoding container's own
        // ceiling), so nothing was read and nothing was decoded. It used to
        // be reported by ABORTING at exit 6 with a sentence naming both
        // figures, which cost every other entry in the archive; it is a row
        // like any other now. The two FIGURES are not dropped with the
        // sentence — [`describe_salvage_row`] appends them as a tag, so the
        // status column stays the fixed width every other row uses while a
        // user still learns what the entry needed and what the run allowed.
        SalvageStatus::Unverified(UnverifiedCause::OverEntryCeiling { .. }) => {
            "Unverified (over the ceiling)"
        }
    }
}

/// One `--list` row: scan position, status (refined with a `Partial` cause
/// whenever the disposition has one to give — [`entries::SalvageDisposition::
/// WrittenPartial`] or, since fix round 1's REQUIRED 3,
/// [`entries::SalvageDisposition::SkippedPartial`] too, so `--partial=skip
/// --list` no longer shows bare "Partial" with no "why" on exactly the
/// entries the flag caused to be dropped), name, and — the naming rule this
/// whole feature is built around — a `[shadowed: dup of #N]` suffix naming
/// the EARLIER scan position, never "index", when this record shadows one.
/// `[not selected]` marks a scan position `--index` excluded.
///
/// `[name collision: #N uses this name too]` is the SECOND, weaker
/// annotation, and the two never appear on one row: a shadow is a record
/// measured to be a byte-identical copy, a collision is a record whose name
/// an earlier one already used and whose content was not proven identical.
/// Until the final whole-branch review they shared one word, and the cost
/// was measurable: on an archive whose duplicates differ, `stuffr list`
/// warned that two records repeat a name and were shadowed, while this row
/// marked nothing at all.
///
/// `[deleted: the archive marks this entry removed]` is Ruling S-R (Salvage
/// Stage 2 Task 4). ZOO is the first format here whose records carry a
/// deleted flag, and `salvage` reports such a record where every other verb
/// skips it — `zoo d` leaves the payload in the file, and one flipped byte
/// in that flag turns a live entry into one the ordinary reader will never
/// hand back. Reporting it is right; reporting it as a bare `Intact` under
/// its real name at exit 0 was not, because it made this the ONE place
/// salvage's leniency carried no marker at all. **The exit code does not
/// move** — recovering a deleted record is the verb working as designed,
/// not degraded fidelity — so the annotation is the whole signal, which is
/// why it is worth having.
fn describe_salvage_row(record: &entries::SalvagedRecord) -> String {
    let status = match &record.disposition {
        entries::SalvageDisposition::WrittenPartial { cause, .. }
        | entries::SalvageDisposition::SkippedPartial(cause)
        | entries::SalvageDisposition::WrittenDisambiguated {
            partial: Some(cause),
            ..
        } => match cause {
            entries::PartialCause::Truncated => "Partial (truncated)",
            // Ruling S-AA. Distinct from `truncated` because nothing is
            // missing from the FILE — every declared byte is there and the
            // decoder could not turn them into the declared content. The
            // row used to say `truncated` for this, over archives from
            // which nothing had been cut.
            entries::PartialCause::DecodeFailed => "Partial (decode failed)",
            entries::PartialCause::ChecksumMismatch => "Partial (checksum mismatch)",
        },
        entries::SalvageDisposition::WrittenDisambiguated { partial: None, .. }
        | entries::SalvageDisposition::Written(_)
        | entries::SalvageDisposition::Directory(_)
        | entries::SalvageDisposition::SkippedUnverified
        | entries::SalvageDisposition::SkippedNotBuiltIn
        | entries::SalvageDisposition::SkippedShadow(_)
        | entries::SalvageDisposition::SkippedUnsupportedKind
        | entries::SalvageDisposition::SkippedUnwritable { .. }
        | entries::SalvageDisposition::SkippedUnsafePath { .. }
        | entries::SalvageDisposition::NotSelected
        | entries::SalvageDisposition::NotWritten => describe_salvage_status(record.status),
    };
    let mut line = format!("{:<4} {:<32} {}", record.scan_position, status, record.name);
    if let Some(earlier) = record.shadows {
        line.push_str(&format!(" [shadowed: dup of #{earlier}]"));
    }
    if let Some(earlier) = record.collides_with {
        line.push_str(&format!(" [name collision: #{earlier} uses this name too]"));
    }
    if record.marked_deleted {
        line.push_str(" [deleted: the archive marks this entry removed]");
    }
    // The path actually written, named only when it is NOT the entry's own
    // name — a row a user reads to find their file must say where it went.
    if let entries::SalvageDisposition::WrittenDisambiguated { path, .. } = &record.disposition {
        line.push_str(&format!(
            " [written as {}]",
            path.file_name().unwrap_or(path.as_os_str()).display()
        ));
    }
    if matches!(record.disposition, entries::SalvageDisposition::NotSelected) {
        line.push_str(" [not selected]");
    }
    // Fix round 4, NEW-F: the two figures the old exit-6 sentence carried.
    // Without them a user meeting a whole-decoding container's own fixed
    // ceiling learns neither what the entry needed nor what the run allowed,
    // and cannot tell whether `--max-entry` would help — which is the whole
    // difference between the two ceilings that compose here.
    if let stuffr::salvage::SalvageStatus::Unverified(
        stuffr::salvage::UnverifiedCause::OverEntryCeiling { needed, ceiling },
    ) = record.status
    {
        line.push_str(&format!(
            " [needs {needed} bytes; this run reads at most {ceiling} per entry]"
        ));
    }
    // Fix round 4, NEW-B: an entry whose bytes could not be placed on disk
    // names the reason on its own row. It used to end the run instead — at
    // exit 1, on a name the ARCHIVE chose.
    if let entries::SalvageDisposition::SkippedUnwritable { reason } = &record.disposition {
        line.push_str(&format!(" [not written: {reason}]"));
    }
    // Final fix wave, F1: the same shape, for the refusal stuffr makes
    // itself rather than the one the OS hands back. Worded "refused" rather
    // than "not written" precisely so the two are distinguishable on a row:
    // one is a destination that would not take the name, the other is this
    // tool declining to write outside where it was pointed.
    if let entries::SalvageDisposition::SkippedUnsafePath { reason } = &record.disposition {
        line.push_str(&format!(" [refused: unsafe entry path: {reason}]"));
    }
    line
}

/// `--list`: one line per scanned record, to stdout — the same destination
/// `stuffr list` itself writes to, and for the same reason (`stuffr salvage
/// … --list | head` is as legitimate a pipeline as `stuffr list x | head`).
///
/// Fix round 1, REQUIRED 2: always the FULL scan (`&outcome.entries`
/// directly, never a caller-filtered slice) — `--index` narrows what is
/// WRITTEN, never what `--list` reports, so a selection is visible here only
/// as the `[not selected]` tag [`describe_salvage_row`] adds.
fn print_salvage_list(entries: &[entries::SalvagedRecord]) -> stuffr::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout();
    for record in entries {
        writeln!(out, "{}", describe_salvage_row(record))?;
    }
    Ok(())
}

/// Names every entry this run could not place on disk, on **stderr, every
/// run** — not only under `--list`.
///
/// # Why this exists (fix round 5, NEW-G)
///
/// Task 3c's fix round 4 made a filesystem failure a per-entry skip instead
/// of an aborted run, and rested that ruling on "the reason is on its own
/// row, so nothing is silent". It was on its own row **only under
/// `--list`**. Measured on the shipped binary against a `chmod 555`
/// destination and against a genuine ENOSPC volume, plain `salvage -C DIR`
/// — the invocation somebody recovering an archive actually types —
/// printed:
///
/// ```text
/// salvage -> 3 scanned: 0 written, … 3 skipped, 0 unverified, …
/// exit=4                                          # and nothing else
/// ```
///
/// A wholly unusable destination was a bare `3 skipped`, where before the
/// fold it was `stuffr: i/o error: Permission denied (os error 13)` at
/// exit 1 — so a user could not tell a full disk from an entry the archive
/// itself made unwritable, which is the exact question the fold's own trade
/// turns on. A skip nobody can see is Stage 1's vanishing truncated tail
/// wearing a different hat.
///
/// `pack`'s directory walk is the precedent the ruling already cited, and it
/// prints its skips on stderr every run — which is what makes `CLAUDE.md`'s
/// "the skip is named, not silent" true there. This is the same, in the same
/// shape [`report_fidelity`] uses for the same reason: a count, up to ten
/// lines, then how many were elided.
///
/// **Printed even under `--list`, which also tags these rows.** The rows go
/// to stdout and this goes to stderr, so `salvage --list … | less` still
/// shows the failure, and a terminal user reading both sees one restated
/// fact rather than a missing one.
///
/// Takes the FULL scan rather than `--index`'s subset, and nothing is lost
/// by that: an unselected position is reported `NotSelected` and never
/// reaches a filesystem call, so it can never be one of these.
fn print_salvage_write_failures(entries: &[entries::SalvagedRecord]) {
    // Final fix wave, F1: BOTH placement failures, not only the OS's. A
    // containment refusal used to end the run with its own message on
    // stderr, so widening this filter alongside that change is what keeps
    // "nothing is silent" true — a refusal that became a row and nothing
    // else would be NEW-G's defect reintroduced through the door F1 opened.
    let failed: Vec<&entries::SalvagedRecord> = entries
        .iter()
        .filter(|r| {
            matches!(
                r.disposition,
                entries::SalvageDisposition::SkippedUnwritable { .. }
                    | entries::SalvageDisposition::SkippedUnsafePath { .. }
            )
        })
        .collect();
    if failed.is_empty() {
        return;
    }
    const SHOWN: usize = 10;
    eprintln!(
        "salvage -> {} entr{} could not be written:",
        failed.len(),
        if failed.len() == 1 { "y" } else { "ies" }
    );
    for record in failed.iter().take(SHOWN) {
        // One arm each, no wildcard: a third placement outcome added later
        // must decide how it prints rather than inheriting a default.
        let reason = match &record.disposition {
            entries::SalvageDisposition::SkippedUnwritable { reason } => reason.clone(),
            entries::SalvageDisposition::SkippedUnsafePath { reason } => {
                format!("refused: unsafe entry path: {reason}")
            }
            other => unreachable!("filtered above, got {other:?}"),
        };
        eprintln!("  - #{} {}: {reason}", record.scan_position, record.name);
    }
    if let Some(rest) = failed.len().checked_sub(SHOWN).filter(|n| *n > 0) {
        eprintln!("  … and {rest} more");
    }
}

/// The default (non-`--list`) report: counts only, to stderr — the same
/// destination `unpack`'s and `test`'s own summary lines use. Takes whatever
/// slice the caller passes — [`dispatch_salvage`] narrows it to `--index`'s
/// selection when one was given, unlike [`print_salvage_list`], which always
/// takes the full scan.
fn print_salvage_summary(entries: &[entries::SalvagedRecord]) {
    let (mut written, mut partial, mut skipped, mut unverified, mut not_selected, mut not_written) =
        (0, 0, 0, 0, 0, 0);
    // An ADDITIONAL tally, not a bucket of its own: a disambiguated record
    // is already counted as written (or as a `.partial`), so the first six
    // counts still sum to the number of rows. Disambiguation is a fact
    // ABOUT a write, the same way a `Partial` cause is a fact about one —
    // giving it its own bucket would make the summary stop adding up, which
    // is precisely the defect this whole change exists to fix.
    let mut renamed = 0;
    for record in entries {
        match &record.disposition {
            entries::SalvageDisposition::Written(_) | entries::SalvageDisposition::Directory(_) => {
                written += 1;
            }
            entries::SalvageDisposition::WrittenDisambiguated { partial: cause, .. } => {
                renamed += 1;
                match cause {
                    Some(_) => partial += 1,
                    None => written += 1,
                }
            }
            entries::SalvageDisposition::WrittenPartial { .. } => partial += 1,
            entries::SalvageDisposition::SkippedPartial(_)
            | entries::SalvageDisposition::SkippedNotBuiltIn
            | entries::SalvageDisposition::SkippedShadow(_)
            | entries::SalvageDisposition::SkippedUnsupportedKind
            // Counted as skipped, not as a bucket of its own: the summary's
            // six counts must keep summing to the number of rows, and the
            // per-entry reason is on the row (`[not written: …]`).
            | entries::SalvageDisposition::SkippedUnwritable { .. }
            // Counted as skipped for the same reason, and the exit code —
            // not the summary — is what carries the severity: a containment
            // refusal is bucket 7 in `salvage_exit_code`, above every other.
            | entries::SalvageDisposition::SkippedUnsafePath { .. } => skipped += 1,
            entries::SalvageDisposition::SkippedUnverified => unverified += 1,
            entries::SalvageDisposition::NotSelected => not_selected += 1,
            entries::SalvageDisposition::NotWritten => not_written += 1,
        }
    }
    eprintln!(
        "salvage -> {} scanned: {written} written, {partial} written as .partial, {skipped} \
         skipped, {unverified} unverified, {not_selected} not selected, {not_written} not \
         written (no destination), {renamed} renamed to avoid a name collision",
        entries.len()
    );
}

/// Validates `--index` against the scan positions the archive actually has.
///
/// Lenient the same way `unpack --index`/`cat --index` already are (see
/// `entries::extract`'s own `Selection::missed`): refuses only when NONE of
/// the requested positions exist at all, rather than the first one that
/// doesn't — a mix of a real position and a typo silently recovers the real
/// one, the same bargain `unpack` already makes. Names the mistake as a scan
/// position — never "index" — per this feature's own naming rule: `stuffr
/// list`'s numbering and salvage's are two different things, and a message
/// that said "index" here could be misread as `list`'s.
fn validate_scan_positions(requested: &[usize], total: usize) -> stuffr::Result<()> {
    if !requested.is_empty() && requested.iter().all(|&pos| pos >= total) {
        return Err(stuffr::Error::Usage(format!(
            "no requested scan position exists; this archive's scan found {total} record(s) \
             (valid scan positions are 0-{})",
            total.saturating_sub(1)
        )));
    }
    Ok(())
}

/// Removes a temporary directory when dropped. `-o FILE` recovers into one
/// of these (via [`entries::salvage`]'s ordinary directory mode, `select`
/// narrowed to the one requested entry) and then moves the single result
/// out to `FILE`; wrapping the directory in a guard means an early return
/// through `?` anywhere in between — a validation failure, an I/O error —
/// still cleans it up, without a `remove_dir_all` at every return site.
struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A fresh, empty directory under the system temp root, for [`TempDirGuard`]
/// to own. No dependency on the `tempfile` crate: that is a dev-dependency
/// of `stuffr` (used by `entries.rs`'s own unit tests), not available to
/// this crate's production code.
fn fresh_temp_dir(label: &str) -> stuffr::Result<TempDirGuard> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "stuffr-salvage-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(TempDirGuard(dir))
}

/// `-o FILE`'s second half: given the outcome of a `select = {scan_position}`
/// run into a temporary directory, moves that one entry's recovered bytes
/// (if any) out to `output_path` and reports what happened.
///
/// A `Partial` entry still lands under `output_path` with `.partial`
/// appended, never `output_path` itself — the exact rule `-C` already
/// follows (see [`entries::salvage`]'s own doc and Ruling R-J), applied to a
/// caller-named path instead of an entry-named one for the identical reason:
/// a truncated file under the name asked for is indistinguishable from a
/// whole one to every tool downstream.
fn finish_single_file_recovery(
    outcome: &entries::SalvageOutcome,
    scan_position: usize,
    output_path: &Path,
) -> stuffr::Result<()> {
    let record = outcome
        .entries
        .iter()
        .find(|r| r.scan_position == scan_position)
        .expect("validate_scan_positions already confirmed this scan position was scanned");

    let (from, is_partial) = match &record.disposition {
        entries::SalvageDisposition::Written(path) => (path.clone(), false),
        entries::SalvageDisposition::WrittenPartial { path, .. } => (path.clone(), true),
        // Unreachable in practice — `-o` narrows `select` to exactly one
        // scan position and recovers into a FRESH temporary directory, so
        // no earlier entry in the run can have claimed a name. Handled
        // rather than lumped into the "nothing written" arm below, which
        // would silently report a recovered file as not recovered if that
        // ever stopped being true. The disambiguated on-disk name does not
        // survive the move: `-o FILE` means FILE, and the caller named one
        // entry, so there is nothing left to disambiguate against.
        entries::SalvageDisposition::WrittenDisambiguated { path, partial, .. } => {
            (path.clone(), partial.is_some())
        }
        entries::SalvageDisposition::Directory(_) => {
            return Err(stuffr::Error::Usage(format!(
                "scan position {scan_position} is a directory entry; -o recovers one file's \
                 bytes — use -C to recover a directory"
            )));
        }
        entries::SalvageDisposition::SkippedShadow(_)
        | entries::SalvageDisposition::SkippedUnverified
        | entries::SalvageDisposition::SkippedNotBuiltIn
        | entries::SalvageDisposition::SkippedPartial(_)
        | entries::SalvageDisposition::SkippedUnsupportedKind
        | entries::SalvageDisposition::SkippedUnwritable { .. }
        // Final fix wave, F1. Reached under `-o FILE` the same way every
        // other skip is: `describe_salvage_row` names the refusal, and the
        // run still exits 7 because `salvage_exit_code` gives this variant
        // its own bucket — so `-o` on an escaping name reports exactly what
        // it did before, minus the aborted run.
        | entries::SalvageDisposition::SkippedUnsafePath { .. }
        | entries::SalvageDisposition::NotSelected
        | entries::SalvageDisposition::NotWritten => {
            eprintln!(
                "salvage -> nothing written for scan position {scan_position}: {}",
                describe_salvage_row(record)
            );
            return Ok(());
        }
    };

    let mut final_path = output_path.to_path_buf();
    if is_partial {
        let mut name = final_path
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_default();
        name.push(".partial");
        final_path = final_path.with_file_name(name);
    }
    if let Some(parent) = final_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    // No `--force` concept exists for salvage, same as `-C`'s own write path:
    // recovery is meant to be re-run, and a stale file from a previous
    // attempt must not block this one.
    let _ = std::fs::remove_file(&final_path);
    if std::fs::rename(&from, &final_path).is_err() {
        // `from` lives in a temp directory that may sit on a different
        // filesystem than `final_path`'s — `rename(2)` refuses that
        // (`EXDEV`), so fall back to copying the bytes across and removing
        // the source.
        std::fs::copy(&from, &final_path)?;
        std::fs::remove_file(&from)?;
    }
    eprintln!("salvage -> wrote {}", final_path.display());
    Ok(())
}

/// [`Command::Salvage`]'s fields, bundled so [`dispatch_salvage`] takes one
/// argument instead of nine (clippy's own `too_many_arguments` threshold).
struct SalvageArgs {
    input: String,
    list: bool,
    directory: Option<String>,
    output: Option<String>,
    index: Vec<usize>,
    partial: Option<String>,
    max_entry: Option<String>,
    strict: bool,
    format: Option<String>,
}

/// Implements `salvage` end to end: builds the policy, runs the scan-and-
/// recover engine (`entries::salvage`), prints the report, and returns the
/// aggregate exit-code bucket (0/3/4/5) for the calling match arm to act on.
///
/// A plain function rather than inlined in the `dispatch` arm purely so the
/// arm above reads as a dispatch table, matching the shape every other verb
/// here already has.
///
/// # The three surface forms (fix round 1, REQUIRED 2)
///
/// - `--list` alone: report-only, `dest: None` — nothing touches the
///   filesystem, not even to create a directory.
/// - `-C DIR`: recover a whole tree (optionally narrowed by `--index`,
///   repeatable) into `DIR`.
/// - `-o FILE --index N`: recover exactly the one entry at scan position `N`
///   to `FILE`. There is no separate single-file write path in
///   `entries.rs`: this still goes through `entries::salvage`'s ordinary
///   directory mode, into a [`TempDirGuard`]'s temporary directory with
///   `select` narrowed to `{N}`, and [`finish_single_file_recovery`] moves
///   the single result out to `FILE` afterward.
///
/// # `--list` reports the full scan; the summary and exit code report the selection
///
/// `entries::salvage` always returns a record for every scan position, `-o`
/// included — an unselected one comes back `NotSelected` rather than
/// omitted. `--list` prints exactly that full outcome, unfiltered, because a
/// diagnostic listing must not narrow just because `--index` narrowed what
/// gets WRITTEN. The default summary and the exit code below are the other
/// way around: both are filtered down to `select` when one was given
/// (`None` when it was not, so the whole scan either way), because those two
/// answer "how did the entries I asked to recover fare", not "what does this
/// archive hold" — `--index 6` on an otherwise-clean archive reports
/// `1 scanned, 1 skipped` and exits 4 even though the archive's OTHER seven
/// entries are all fine, because entry 6 is the only one the caller asked
/// about.
///
/// At least one of `-C`, `-o` or `--list` is required; `-C` and `-o` are
/// mutually exclusive; `-o` requires exactly one `--index`.
fn dispatch_salvage(args: SalvageArgs) -> stuffr::Result<i32> {
    let SalvageArgs {
        input,
        list,
        directory,
        output,
        index,
        partial,
        max_entry,
        strict,
        format,
    } = args;
    let format = match format.as_deref() {
        Some(name) => Some(salvage_format_by_name(name)?),
        None => None,
    };
    if directory.is_some() && output.is_some() {
        return Err(stuffr::Error::Usage(
            "-C and -o both name a destination; pass one or the other, not both".into(),
        ));
    }
    if directory.is_none() && output.is_none() && !list {
        return Err(stuffr::Error::Usage(
            "pass -C DIR to recover into a directory, -o FILE to recover one entry by \
             --index, or --list to see what the scan found without writing anything"
                .into(),
        ));
    }
    if output.is_some() && index.len() != 1 {
        return Err(stuffr::Error::Usage(
            "-o recovers exactly one entry; pass exactly one --index N naming its scan \
             position"
                .into(),
        ));
    }
    let path = match input_of(&input) {
        Input::Path(p) => p,
        Input::Stdin => {
            return Err(stuffr::Error::Usage(
                "salvage scans back and forth over the archive, which needs a real seekable \
                 file; pass a path, not `-`"
                    .into(),
            ));
        }
    };
    let partial_policy = match partial.as_deref() {
        None | Some("keep") => stuffr::salvage::PartialPolicy::Keep,
        Some("skip") => stuffr::salvage::PartialPolicy::Skip,
        Some("ask") => stuffr::salvage::PartialPolicy::Ask,
        Some(other) => {
            return Err(stuffr::Error::Usage(format!(
                "unknown --partial value `{other}`; expected keep, skip or ask"
            )));
        }
    };
    let mut policy = stuffr::salvage::SalvagePolicy {
        partial: partial_policy,
        strict,
        ..Default::default()
    };
    if let Some(raw) = max_entry {
        policy.max_entry = stuffr_cli::size::parse_size(&raw).map_err(stuffr::Error::Usage)?;
    }

    let select: Option<HashSet<usize>> = if index.is_empty() {
        None
    } else {
        Some(index.iter().copied().collect())
    };

    // `-o` recovers into a throwaway directory (cleaned up on every path out
    // of this function, including an early `?`, by `TempDirGuard`'s `Drop`)
    // and moves the one result out afterward; `-C` recovers directly into
    // the caller's own directory; `--list` alone recovers nowhere.
    let temp_guard = if output.is_some() {
        Some(fresh_temp_dir("one")?)
    } else {
        None
    };
    let dest = match (&directory, &temp_guard) {
        (Some(dir), _) => Some(PathBuf::from(dir)),
        (None, Some(guard)) => Some(guard.0.clone()),
        (None, None) => None,
    };

    let opts = SalvageOpts {
        dest,
        policy,
        select: select.clone(),
        format,
    };
    let outcome = entries::salvage(&path, &opts)?;

    // Computed on the FULL scan: "nothing recoverable at all" is a fact
    // about the archive, not about which scan positions the caller happened
    // to ask for.
    if entries::salvage_exit_code(&outcome) == 5 {
        eprintln!("salvage -> the scan found nothing recoverable in this archive");
        return Ok(5);
    }

    validate_scan_positions(&index, outcome.entries.len())?;

    // Before anything else this run prints: an entry that could not be put
    // on disk is named on stderr on EVERY invocation, not only under
    // `--list`. See `print_salvage_write_failures` for what a missing
    // stderr line measured before this existed.
    print_salvage_write_failures(&outcome.entries);

    // `--list` always reports the FULL scan, `--index` included — narrowing
    // WHAT IS WRITTEN must never narrow what a diagnostic listing shows.
    if list {
        print_salvage_list(&outcome.entries)?;
    }

    if let Some(output_path) = &output {
        finish_single_file_recovery(&outcome, index[0], Path::new(output_path))?;
    } else if !list {
        // The default summary — like the exit code below — reports on what
        // the CALLER asked about: the whole scan when no `--index` was
        // given, or just the selected subset when it was. `--list` above is
        // the one place the full scan is shown regardless of `--index`.
        let subset: Vec<entries::SalvagedRecord> = match &select {
            None => outcome.entries.clone(),
            Some(set) => outcome
                .entries
                .iter()
                .filter(|r| set.contains(&r.scan_position))
                .cloned()
                .collect(),
        };
        print_salvage_summary(&subset);
    }

    // Same reasoning as the summary: the exit code is about what the caller
    // asked to recover, not the whole archive. `-o` already narrowed
    // `select` to exactly the one requested entry, so this naturally
    // matches what `finish_single_file_recovery` just reported.
    let subset: Vec<entries::SalvagedRecord> = match &select {
        None => outcome.entries,
        Some(set) => outcome
            .entries
            .into_iter()
            .filter(|r| set.contains(&r.scan_position))
            .collect(),
    };
    Ok(entries::salvage_exit_code(&entries::SalvageOutcome {
        entries: subset,
    }))
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

/// The `(container, codec)` pair a pack output names, if it names a container
/// at all — `--format tar`, or an extension chain that resolves to one
/// (`-o bundle.tar`, `-o bundle.tar.gz`, `-o bundle.tgz`).
///
/// `None` means the output names a codec (or nothing yet), which is the
/// single-stream path `pack` has always taken.
///
/// `Path::extension()` is NOT enough, and was the bug: for `x.tar.gz` it
/// returns `"gz"`, so the whole command took the single-stream codec path and
/// the `.tar` was never honoured — v0.2.0 wrote a plain gzip under a name
/// promising a tar, at exit 0. With an explicit `--format tar` the mirror
/// image happened: an uncompressed tar named `.tar.gz`, which `gunzip`
/// rejects. `chain_for_new_path` reads the whole chain, and shares its
/// extension table with the read side so `.tar.gz` cannot mean one thing to
/// `pack` and another to `list`.
///
/// `Err` is the case where the two sources of truth CONTRADICT each other:
/// `--format zip -o x.tar.gz` asks for a zip inside gzip under a name
/// promising a tar. Writing it is worse than refusing — the file is perfectly
/// good gzip, so `pack` exits 0 and `list` on the very same path then exits 5
/// calling stuffr's own output corrupt, because reading resolves the outer
/// layer by magic and the inner one by name. Exit 2 before anything is
/// written is the only honest answer.
fn resolve_pack_chain(
    fmt: Option<FormatId>,
    output: Option<&str>,
) -> stuffr::Result<Option<(FormatId, Option<FormatId>)>> {
    let registry = stuffr::registry();

    // An explicit --format names the CONTAINER; any codec still comes from
    // the output's name, so `--format tar -o x.gz` is tar over gzip.
    if let Some(id) = fmt {
        if registry.container(id).is_none() {
            return Ok(None);
        }
        let chain = output.map(|o| stuffr::chain_for_new_path(registry, Path::new(o)));
        if let Some(chain) = &chain
            && let Some(named) = chain.container()
            && named != id
        {
            let out = output.unwrap_or_default();
            return Err(stuffr::Error::Usage(format!(
                "--format {id} asks for a {id} archive, but the output name `{out}` says \
                 {named}. Writing it would exit 0 and leave a file `stuffr list` \
                 then calls corrupt, because a reader takes the container from \
                 the name. Rename the output, or drop --format and let the name \
                 decide."
            )));
        }
        let codec = chain.and_then(|c| c.outermost_codec());
        return Ok(Some((id, codec)));
    }

    // Otherwise the output name carries the whole chain, and the two cannot
    // disagree because there is only one of them.
    let Some(output) = output else {
        return Ok(None);
    };
    let chain = stuffr::chain_for_new_path(registry, Path::new(output));
    match chain.container() {
        Some(container) => Ok(Some((container, chain.outermost_codec()))),
        None => Ok(None),
    }
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

/// Refuses encoder flags only where the resolved chain has no codec layer to
/// hand them to.
///
/// Phase 2 refused these for any container output, correctly at the time:
/// none of the four registered containers compresses anything itself, so
/// there was genuinely nothing to hand a worker count, a CPU-cap lift or a
/// weak-encoder consent to. Accepting them there and silently dropping them
/// is the exact shape `refuse_unhonoured_extract_flags` above exists to
/// prevent.
///
/// Phase 2c makes `-o out.tar.xz` a real composed write with a codec layer
/// underneath the container, and that codec DOES honour a worker count —
/// `entries::create_archive` now builds its `EncodeOpts.governor` from
/// `ops::resolved_budget(o)` exactly as the single-stream path does. An
/// unconditional refusal would now reject a legitimate command, the shape
/// this project has hit repeatedly. `has_codec` is `resolve_pack_chain`'s
/// second tuple element: `Some` means the chain has a codec above the
/// container, `None` means a bare container with nothing to compress it.
///
/// `--memory-limit` is deliberately NOT here, in either case: it is honoured
/// on every decode path, and on a bare container pack it is simply inert in
/// the same way `--no-sync` is (nothing allocates a dictionary), so it costs
/// nothing to accept.
///
/// **All three sentences used to say "no container in this build compresses
/// anything itself", and that was already false when it was written:** `zip`
/// deflates its entries. Phase 3c Task 6 made it plainly false — `pack -o
/// x.lzh` runs a real `-lh5-` compressor (measured: 100 KB of text → 315
/// bytes) and `-o x.lzh --threads 4` meets this refusal. The honest reason
/// is narrower and is what they say now: no container here has a PARALLEL
/// encoder, so `--threads`/`--turbo` have nothing to govern, and none has a
/// weak fallback encoder for `--allow-weak-encoder` to consent to. The
/// refusals themselves are unchanged and still correct.
///
/// Worth recording because of what did NOT catch this: the examples-page
/// count guard derives its numbers from the LIVE registry, but the registry
/// tells it how many rows there are, never what any row's WRITE column says.
/// Every stale "read-only" sentence in this task had to be found by hand for
/// the same reason.
fn refuse_unhonoured_pack_flags(opts: &CompressOpts, has_codec: bool) -> stuffr::Result<()> {
    if has_codec {
        return Ok(());
    }
    if opts.threads.is_some() {
        return Err(stuffr::Error::Usage(
            "--threads governs a codec's parallel encoder; no container in this build has \
             a parallel encoder of its own, so there is no worker count to hand it"
                .into(),
        ));
    }
    if opts.turbo {
        return Err(stuffr::Error::Usage(
            "--turbo lifts the CPU cap for a codec's parallel encoder; no container in \
             this build has a parallel encoder of its own"
                .into(),
        ));
    }
    if opts.allow_weak_encoder {
        return Err(stuffr::Error::Usage(
            "--allow-weak-encoder consents to a codec's fallback encoder; no container in \
             this build has an encoder that can fall back"
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
///
/// # The index column
///
/// The first column is the entry's 0-based position in archive order. It is
/// simply the position in the `Vec` `entries::list` returned, which that
/// function fills from one forward walk — the same walk `--index` counts. So
/// `list` and `cat --index`/`unpack --index` cannot disagree about what
/// entry 6 is; there is only one enumeration and both read it.
///
/// # The fidelity report
///
/// Printed through `report_fidelity`, the same call `test` and `unpack -C`
/// make, rather than a second printer here. `list` dropped the report
/// entirely until this was added: on a zip whose central directory holds 8
/// records under 6 names, `stuffr test` warned that 2 were shadowed while
/// `stuffr list` printed 6 rows and said nothing — the verb a user reaches
/// for first, silent about the one way its own output was incomplete.
///
/// Warnings go to stderr AFTER the listing goes to stdout, so `stuffr list a
/// | head` is unaffected by them and a redirected listing keeps the warning
/// visible on the terminal.
fn print_list(
    src: Input,
    json: bool,
    max_ratio: u64,
    memory_limit: Option<u64>,
    strict_fidelity: bool,
) -> stuffr::Result<()> {
    use std::io::Write;
    let (entries, outcome) = entries::list(src, max_ratio, memory_limit)?;
    let mut out = std::io::stdout();
    if json {
        let rows: Vec<serde_json::Value> = entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                serde_json::json!({
                    "index": i,
                    "name": e.name,
                    "kind": entry_kind_str(&e.kind),
                    "size": e.size,
                })
            })
            .collect();
        writeln!(out, "{}", serde_json::Value::Array(rows))?;
    } else {
        for (i, e) in entries.iter().enumerate() {
            match e.size {
                Some(n) => writeln!(out, "{i:>5}  {n:>12}  {}", e.name)?,
                None => writeln!(out, "{i:>5}  {:>12}  {}", "-", e.name)?,
            }
        }
    }
    out.flush()?;
    report_fidelity(&outcome.fidelity, strict_fidelity)
}

/// The one selector a read verb acts on, built from the two spellings a user
/// can type.
///
/// `--index` and PATTERNS are **mutually exclusive**, not combinable. They
/// are two ways of saying "which entries", and a command that says it both
/// ways has no meaning anybody would agree on: is `unpack a.zip README
/// --index 3` the union (two entries) or the intersection (README, but only
/// if it happens to sit at 3)? Either reading silently does something the
/// user did not mean half the time. Exit 2, before a byte is read, is the
/// only answer that cannot be wrong.
///
/// Refused here rather than with clap's own `conflicts_with` so the message
/// is stuffr-shaped and says WHY, the same way
/// `refuse_unhonoured_extract_flags` does; and below this function the
/// ambiguity is unrepresentable, because `stuffr::entries::Selection` has no
/// variant that can hold both.
fn selection_of(patterns: Vec<String>, index: Vec<usize>) -> stuffr::Result<Selection> {
    match (patterns.is_empty(), index.is_empty()) {
        (true, true) => Ok(Selection::All),
        (false, true) => Ok(Selection::Names(patterns)),
        (true, false) => Ok(Selection::Indices(index)),
        (false, false) => Err(stuffr::Error::Usage(
            "--index and entry patterns are two ways of choosing the same thing; \
             pass one or the other, not both"
                .into(),
        )),
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

/// Resolves `salvage --format` against the set of container formats salvage
/// could ever be asked to scan — deliberately NOT [`format_by_name`], which
/// only recognises what THIS build's live registry has compiled.
///
/// Salvage's own contract (Task 2) is that naming a format this build has
/// not compiled is still [`stuffr::Error::Unsupported`]/[`stuffr::Error::
/// FormatNotEnabled`] (exit 3, "this build cannot do that") — the same
/// build-capability shape `require_container_writer` answers with elsewhere
/// — never [`stuffr::Error::Usage`] (exit 2, "you typed something wrong").
/// `format_by_name` cannot make that distinction: an uncompiled format is
/// simply absent from its registry lookup, so it reports "unknown format"
/// exactly as it would for a genuine typo. Matching against this fixed,
/// static table instead is also what sidesteps `FormatId`'s `'static`
/// requirement without leaking the runtime `String` — see
/// `format_by_name`'s own doc for the leak this avoids.
///
/// A name outside this table names no archive format `stuffr salvage` will
/// ever recognise, compiled or not, so that case stays [`stuffr::Error::
/// Usage`] — a caller typo, not a build limitation.
fn salvage_format_by_name(name: &str) -> stuffr::Result<FormatId> {
    match name {
        "zip" => Ok(FormatId::new("zip")),
        "tar" => Ok(FormatId::new("tar")),
        "ar" => Ok(FormatId::new("ar")),
        "cpio" => Ok(FormatId::new("cpio")),
        "arc" => Ok(FormatId::new("arc")),
        "zoo" => Ok(FormatId::new("zoo")),
        "lha" => Ok(FormatId::new("lha")),
        "arj" => Ok(FormatId::new("arj")),
        other => Err(stuffr::Error::Usage(format!(
            "unknown format `{other}`; salvage recognizes: zip, tar, ar, cpio, arc, zoo, lha, \
             arj"
        ))),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `salvage_format_by_name`'s own doc explains why its table cannot be
    /// gated by feature (naming an uncompiled format must still answer
    /// `Unsupported`/`FormatNotEnabled`, never `Usage`) — but that also
    /// means nothing has ever forced the table to grow alongside the
    /// registry it stands in for. It was a hand-maintained eight-name list
    /// with no test pinning it to anything live. Salvage Stage 2 Task 3
    /// wired a real scanner behind the `arc` entry the table already held,
    /// which is exactly the moment such drift would have gone unnoticed —
    /// so this derives the expectation from the LIVE registry instead of
    /// restating the list by hand: the next container format to register
    /// (`zoo`, most likely) fails THIS test the day it lands, rather than
    /// silently falling through to salvage's own `Usage` catch-all forever.
    #[test]
    fn salvage_format_by_name_recognises_every_registered_container() {
        let containers: Vec<_> = stuffr::registry()
            .matrix()
            .into_iter()
            .filter(|row| row.kind == stuffr::FormatKind::Container)
            .collect();
        assert!(
            !containers.is_empty(),
            "sanity: this build must register at least one container format"
        );
        for row in &containers {
            let name = row.id.as_str();
            assert!(
                salvage_format_by_name(name).is_ok(),
                "salvage_format_by_name does not recognise `{name}`, which this build's own \
                 registry reports as a live container — `salvage_format_by_name` needs a new \
                 arm for it"
            );
        }
    }
}
