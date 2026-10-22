//! `stuffr bench`: compares codecs on the user's own files.
//!
//! [`run`] wires the pieces together in order: expand the operands, check
//! `--formats`, refuse a debug build, load and warm the input once, then
//! measure every row strictly one after another (there is one process-wide
//! signal-cleanup slot, so two `measure` calls must never overlap) and
//! render the result.

pub mod levels;
pub mod measure;
pub mod report;
pub mod score;

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use stuffr::{Error, FormatKind};

use crate::cli::BenchArgs;
use levels::{benchable_codecs, levels_of};
use measure::{Input, Mode, Plan, RealClock, governor_for, load_input, measure, warm};
use report::Conditions;
use score::Row;

/// The refusal `main` prints, verbatim, for [`Ran::RefusedDebugBuild`] (exit
/// 2). Not an `Error::Usage`, whose display would prefix "usage error:".
pub const DEBUG_REFUSAL: &str =
    "stuffr: bench: timings from a debug build are meaningless; build with --release";

/// How a [`run`] that raised no error ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ran {
    /// The rows ran and the report reached stdout.
    Measured,
    /// The arguments were valid, but this is a debug build, so nothing was
    /// timed, written or created.
    RefusedDebugBuild,
}

/// Runs `stuffr bench`. Usage problems are `Error::Usage` (exit 2); a format
/// that fails is a failed row, never an error here.
pub fn run(args: BenchArgs) -> stuffr::Result<Ran> {
    let paths = expand_inputs(&args.inputs)?;
    let codecs = chosen_codecs(&args.formats)?;
    let memory_limit = match &args.memory_limit {
        Some(s) => crate::size::parse_size(s).map_err(Error::Usage)?,
        None => stuffr::default_memory_limit(),
    };
    // After validation, so a debug build still reports usage errors.
    if cfg!(debug_assertions) {
        return Ok(Ran::RefusedDebugBuild);
    }

    let (input, bytes_in) = load_input(&paths, memory_limit)?;
    warm(&input)?;
    let plan = Plan {
        mode: if args.per_file {
            Mode::PerFile
        } else {
            Mode::OneStream
        },
        repeat: args.repeat,
        threads: args.threads,
        memory_limit,
    };
    let planned = plan_rows(&codecs, args.levels);
    let mut meter = Meter {
        on: io::stderr().is_terminal() && !(args.json || args.csv || args.table_only),
        shown: false,
    };
    let mut clock = RealClock::new();
    let mut rows = Vec::with_capacity(planned.len());
    for (k, p) in planned.iter().enumerate() {
        // Between rows only: `measure` owns every timed region.
        meter.show(k + 1, planned.len(), p.format, p.label);
        let outcome = measure(p.format, p.level, &input, &plan, &mut clock);
        rows.push(Row {
            format: p.format,
            level: p.label,
            outcome,
        });
    }
    meter.clear();

    let conditions = Conditions {
        files: paths.len(),
        bytes_in,
        mode: plan.mode,
        threads: plan.threads,
        // The budget every row's encoder is given; no governor is one.
        workers: governor_for(&plan).map_or(1, |g| g.workers()),
        repeat: plan.repeat,
        // zstd is the codec whose tier decides benchability: its pure-Rust
        // encoder is the weak fallback, so only the C tier benchmarks it.
        tier: if cfg!(feature = "zstd-c") {
            "c-backed"
        } else {
            "pure"
        },
        streamed: matches!(input, Input::Files(_)),
    };
    let mut out = io::stdout().lock();
    if args.json {
        report::json(&conditions, &rows, &mut out)?;
    } else if args.csv {
        report::csv(&rows, conditions.bytes_in, &mut out)?;
    } else if args.table_only {
        report::table_only(&rows, conditions.bytes_in, &mut out)?;
    } else {
        report::human(&conditions, &rows, &mut out)?;
    }
    out.flush()?;
    Ok(Ran::Measured)
}

/// The row-count progress meter on stderr: `[k/N] <format> <level>` before
/// each row, cleared before anything reaches stdout.
struct Meter {
    on: bool,
    shown: bool,
}

impl Meter {
    fn show(&mut self, k: usize, n: usize, format: &str, level: Option<i32>) {
        if !self.on {
            return;
        }
        let level = level.map_or_else(|| "-".to_string(), |l| l.to_string());
        // `\x1b[K` after the text clears what a longer previous line left.
        eprint!("\r[{k}/{n}] {format} {level}\x1b[K");
        self.shown = true;
    }

    fn clear(&mut self) {
        if self.shown {
            eprint!("\r\x1b[K");
            self.shown = false;
        }
    }
}

/// One row to run: `level` is what `measure` gets (`None`: the encoder's
/// own default), `label` what the table shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Planned {
    format: &'static str,
    level: Option<i32>,
    label: Option<i32>,
}

/// One default row per codec, or with `sweep` one row per sweep level; a
/// codec without levels gets its one row either way.
fn plan_rows(codecs: &[&'static str], sweep: bool) -> Vec<Planned> {
    let mut rows = Vec::new();
    for &format in codecs {
        let lv = levels_of(format);
        match lv.map(|l| l.sweep).filter(|s| sweep && !s.is_empty()) {
            Some(levels) => rows.extend(levels.iter().map(|&l| Planned {
                format,
                level: Some(l),
                label: Some(l),
            })),
            None => rows.push(Planned {
                format,
                level: None,
                label: lv.and_then(|l| l.default),
            }),
        }
    }
    rows
}

/// The codecs to run: `names` in order without repeats, each checked, or
/// every benchable codec when none are named.
fn chosen_codecs(names: &[String]) -> stuffr::Result<Vec<&'static str>> {
    let benchable = benchable_codecs();
    if names.is_empty() {
        return Ok(benchable);
    }
    let mut chosen = Vec::new();
    for name in names {
        let id = crate::format_by_name(name)?;
        let Some(&codec) = benchable.iter().find(|c| **c == id.as_str()) else {
            return Err(Error::Usage(format!(
                "{name} cannot be benchmarked in this build ({})",
                why_not_benchable(name)
            )));
        };
        if !chosen.contains(&codec) {
            chosen.push(codec);
        }
    }
    Ok(chosen)
}

/// Why a registered format is not in `benchable_codecs`.
fn why_not_benchable(name: &str) -> &'static str {
    let row = stuffr::registry()
        .matrix()
        .into_iter()
        .find(|r| r.id.as_str() == name);
    match row {
        Some(r) => why_not(r.kind, r.write),
        None => why_not(FormatKind::Codec, true),
    }
}

/// The reason, from the matrix facts: a container, a codec that cannot
/// write, or (`benchable_codecs`' remaining filter) a weak encoder.
fn why_not(kind: FormatKind, write: bool) -> &'static str {
    match (kind, write) {
        (FormatKind::Container, _) => "container",
        (_, false) => "read-only",
        _ => "weak fallback encoder",
    }
}

fn has_glob_chars(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// The operands as files, in order. An existing path is used as is; a
/// missing one with glob characters is expanded (sorted, dot files only
/// when the pattern spells the dot, as a shell does). Directories a pattern
/// matches are passed over; one named outright, or the only kind of match a
/// pattern has, is refused. A FIFO, device or socket, named or matched, is
/// refused from its metadata (it is never opened): bench needs each file's
/// size up front. A symlink counts as what it points to.
fn expand_inputs(operands: &[String]) -> stuffr::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for op in operands {
        let path = Path::new(op);
        if path.exists() {
            if path.is_dir() {
                return Err(directory_error(path));
            }
            files.push(regular(path)?);
            continue;
        }
        if !has_glob_chars(op) {
            return Err(no_match(op));
        }
        let opts = glob::MatchOptions {
            require_literal_leading_dot: true,
            ..Default::default()
        };
        let matches = glob::glob_with(op, opts)
            .map_err(|e| Error::Usage(format!("bad pattern {op}: {e}")))?;
        let mut found = Vec::new();
        let mut first_dir = None;
        for m in matches {
            let m = m.map_err(|e| Error::Io(e.into()))?;
            if m.is_dir() {
                first_dir.get_or_insert(m);
            } else {
                found.push(regular(&m)?);
            }
        }
        if found.is_empty() {
            return Err(first_dir.map_or_else(|| no_match(op), |d| directory_error(&d)));
        }
        found.sort();
        files.extend(found);
    }
    Ok(files)
}

/// `path` if it is (or links to) a regular file, else the usage error.
fn regular(path: &Path) -> stuffr::Result<PathBuf> {
    if std::fs::metadata(path)?.is_file() {
        Ok(path.to_path_buf())
    } else {
        Err(Error::Usage(format!(
            "{} is not a regular file; bench needs files whose size it can read",
            path.display()
        )))
    }
}

fn no_match(op: &str) -> Error {
    Error::Usage(format!("no input matched {op}"))
}

fn directory_error(path: &Path) -> Error {
    let p = path.display();
    Error::Usage(format!("{p} is a directory; name its files (e.g. {p}/*)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A scratch directory `stuffr-benchrun-<pid>-<n>`, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("stuffr-benchrun-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn file(&self, name: &str) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, b"x").unwrap();
            p
        }

        fn s(&self, rest: &str) -> String {
            format!("{}/{rest}", self.0.display())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn usage(r: stuffr::Result<Vec<PathBuf>>) -> String {
        match r {
            Err(Error::Usage(m)) => m,
            other => panic!("expected a usage error, got {other:?}"),
        }
    }

    #[test]
    fn a_default_row_runs_the_encoders_default_labelled_with_the_table_default() {
        let rows = plan_rows(&["bzip2", "compress", "lz4"], false);
        assert_eq!(
            rows,
            vec![
                Planned {
                    format: "bzip2",
                    level: None,
                    label: Some(6)
                },
                Planned {
                    format: "compress",
                    level: None,
                    label: Some(16)
                },
                Planned {
                    format: "lz4",
                    level: None,
                    label: None
                },
            ]
        );
    }

    #[test]
    fn a_sweep_runs_every_level_and_one_row_for_a_codec_without_levels() {
        let rows = plan_rows(&["compress", "snappy"], true);
        let got: Vec<_> = rows.iter().map(|r| (r.format, r.level, r.label)).collect();
        let mut want: Vec<_> = (9..=16).map(|l| ("compress", Some(l), Some(l))).collect();
        want.push(("snappy", None, None));
        assert_eq!(got, want);
    }

    #[test]
    fn a_glob_expands_sorted_and_skips_dot_files_and_directories() {
        let s = Scratch::new();
        s.file("b.log");
        s.file("a.log");
        s.file(".hidden.log");
        fs::create_dir(s.0.join("dir.log")).unwrap();
        let got = expand_inputs(&[s.s("*.log")]).unwrap();
        assert_eq!(got, vec![s.0.join("a.log"), s.0.join("b.log")]);
    }

    #[test]
    fn an_existing_path_is_used_as_is_even_with_glob_characters() {
        let s = Scratch::new();
        let odd = s.file("a[1].log");
        assert_eq!(expand_inputs(&[s.s("a[1].log")]).unwrap(), vec![odd]);
    }

    #[test]
    fn no_match_and_a_missing_path_are_usage_errors() {
        let s = Scratch::new();
        let pat = s.s("nomatch*.log");
        assert_eq!(
            usage(expand_inputs(std::slice::from_ref(&pat))),
            format!("no input matched {pat}")
        );
        let missing = s.s("absent.log");
        assert!(usage(expand_inputs(&[missing])).starts_with("no input matched"));
    }

    #[test]
    fn a_directory_is_refused_named_or_as_a_patterns_only_match() {
        let s = Scratch::new();
        fs::create_dir(s.0.join("logs")).unwrap();
        let named = usage(expand_inputs(&[s.s("logs")]));
        let dir = s.s("logs");
        assert_eq!(
            named,
            format!("{dir} is a directory; name its files (e.g. {dir}/*)")
        );
        assert!(usage(expand_inputs(&[s.s("lo*")])).contains("is a directory"));
    }

    #[cfg(unix)]
    #[test]
    fn a_device_is_refused_and_a_symlink_to_a_file_is_not() {
        let s = Scratch::new();
        let want = "/dev/null is not a regular file; bench needs files whose size it can read";
        assert_eq!(usage(expand_inputs(&["/dev/null".into()])), want);
        assert_eq!(usage(expand_inputs(&["/dev/nul?".into()])), want);
        let target = s.file("real.log");
        let link = s.0.join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(expand_inputs(&[s.s("link.log")]).unwrap(), vec![link]);
    }

    #[test]
    fn formats_are_checked_and_deduplicated() {
        let all = benchable_codecs();
        assert_eq!(chosen_codecs(&[]).unwrap(), all);
        let gz = vec!["gzip".to_string(), "bzip2".into(), "gzip".into()];
        assert_eq!(chosen_codecs(&gz).unwrap(), vec!["gzip", "bzip2"]);
        let msg = |n: &str| match chosen_codecs(&[n.to_string()]) {
            Err(Error::Usage(m)) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            msg("tar"),
            "tar cannot be benchmarked in this build (container)"
        );
        assert!(msg("nosuch").starts_with("unknown format `nosuch`"));
        if !all.contains(&"zstd") {
            assert_eq!(
                msg("zstd"),
                "zstd cannot be benchmarked in this build (weak fallback encoder)"
            );
        }
    }

    #[test]
    fn the_reason_follows_the_matrix_facts() {
        // No codec in today's builds is read-only, so the classifier is
        // tested on the facts rather than on a registered format.
        assert_eq!(why_not(FormatKind::Container, true), "container");
        assert_eq!(why_not(FormatKind::Container, false), "container");
        assert_eq!(why_not(FormatKind::Codec, false), "read-only");
        assert_eq!(why_not(FormatKind::Codec, true), "weak fallback encoder");
        assert_eq!(why_not_benchable("tar"), "container");
    }
}
