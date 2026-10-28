//! `stuffr ls`: list the files in a folder that stuffr can open.
//!
//! `stuffr ls` decides by its argument: a folder, or none (the current
//! folder), is the folder listing; a file or `-` is `stuffr list`, through
//! the very function `Command::List` calls. `stuffr files` is the folder
//! listing only.

pub mod identify;

pub mod format;

pub mod render;

pub mod walk;

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::time::SystemTime;

use stuffr::Error;
use stuffr_cli::cli::LsArgs;

/// How a folder listing ended. An `Err` from [`run`] is the other outcome.
pub enum LsStatus {
    Complete,
    /// Something inside could not be read (exit 4); each was warned about.
    Degraded,
}

/// The name the verb was typed as, `ls` or `files`.
///
/// clap reports an alias by its subcommand's own name, so this reads argv:
/// the top level takes only flags, so the first argument that is not one is
/// the subcommand.
pub fn invoked_as(args: &[OsString]) -> &'static str {
    match args
        .iter()
        .skip(1)
        .find(|a| !a.as_encoded_bytes().starts_with(b"-"))
    {
        Some(a) if a == "files" => "files",
        _ => "ls",
    }
}

pub fn run(args: LsArgs, invoked_as: &str) -> stuffr::Result<LsStatus> {
    let folder = match args.path.as_deref() {
        None => Some(PathBuf::from(".")),
        Some("-") => None,
        Some(p) => match std::fs::metadata(p) {
            Ok(md) if md.is_dir() => Some(PathBuf::from(p)),
            Ok(_) => None,
            Err(e) => {
                return Err(Error::Usage(format!(
                    "cannot read {}: {e}",
                    stuffr::fmt_name(p)
                )));
            }
        },
    };
    match folder {
        Some(root) => list_folder(args, &root),
        None => {
            if invoked_as == "files" {
                return Err(Error::Usage(
                    "files lists a folder; use stuffr list for an archive".into(),
                ));
            }
            let folder_only = [
                (args.recursive, "-r"),
                (args.all, "-a"),
                (args.by_name, "-n"),
            ];
            if let Some((_, flag)) = folder_only.iter().find(|(given, _)| *given) {
                return Err(Error::Usage(format!(
                    "{flag} applies to a folder, not a file"
                )));
            }
            crate::run_list(
                args.path.as_deref().unwrap_or("-"),
                args.json,
                args.max_ratio,
                args.memory_limit,
                args.strict_fidelity,
            )?;
            Ok(LsStatus::Complete)
        }
    }
}

fn list_folder(args: LsArgs, root: &std::path::Path) -> stuffr::Result<LsStatus> {
    let archive_only = [
        (args.max_ratio.is_some(), "--max-ratio"),
        (args.memory_limit.is_some(), "--memory-limit"),
        (args.strict_fidelity, "--strict-fidelity"),
    ];
    if let Some((_, flag)) = archive_only.iter().find(|(given, _)| *given) {
        return Err(Error::Usage(format!(
            "{flag} applies to an archive, not a folder"
        )));
    }
    let opts = walk::WalkOptions {
        recursive: args.recursive,
        all: args.all,
        by_name: args.by_name,
    };
    let listing = walk::walk(stuffr::registry(), root, &opts);
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    if args.json {
        writeln!(out, "{}", render::render_json(&listing))?;
    } else {
        render::render_text(&listing, SystemTime::now(), &mut out)?;
    }
    out.flush()?;
    drop(out);
    for w in &listing.warnings {
        eprintln!("{w}");
    }
    Ok(if listing.warnings.is_empty() {
        LsStatus::Complete
    } else {
        LsStatus::Degraded
    })
}
