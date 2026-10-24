//! `stuffr bench`: compares codecs on the user's own files.
//!
//! [`run`] wires the pieces together in order: expand the operands, check
//! `--formats`, refuse a debug build, load and warm the input once, then
//! measure every row strictly one after another (there is one process-wide
//! signal-cleanup slot, so two `measure` calls must never overlap) and
//! render the result.

pub mod levels;
pub mod measure;
pub mod memory;
pub mod report;
pub mod score;

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use stuffr::{Error, FormatKind};

use crate::cli::BenchArgs;
use levels::{backend_of, benchable_codecs, levels_of};
use measure::{
    Clock, Input, Mode, Phase, Plan, RealClock, governor_for, load_input, measure, warm,
};
use report::{Conditions, MemoryMode};
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
    let on = io::stderr().is_terminal() && !(args.json || args.csv || args.table_only);
    let mut meter = Meter::new(
        on.then(|| Box::new(io::stderr()) as Box<dyn Write>),
        Box::new(RealClock::new()),
        plan.repeat,
        terminal_width,
    );
    let mut clock = RealClock::new();
    let mut rows = Vec::with_capacity(planned.len());
    for (k, p) in planned.iter().enumerate() {
        meter.row(RowLabel {
            k: k + 1,
            n: planned.len(),
            format: p.format,
            level: p.label,
        });
        // `measure` reports only between its timed pieces.
        let outcome = measure(
            p.format,
            p.level,
            &input,
            &plan,
            &mut clock,
            &mut |ph, d, t| meter.progress(ph, d, t),
        );
        rows.push(Row {
            format: p.format,
            level: p.label,
            backend: backend_of(p.format),
            outcome,
            // Wired in a later task; until then nothing is measured.
            memory: None,
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
        streamed: matches!(input, Input::Files(_)),
        // Wired in a later task, with the measuring itself.
        memory: MemoryMode::Skipped,
    };
    let mut out = io::stdout().lock();
    if args.json {
        report::json(&conditions, &rows, &mut out)?;
    } else if args.csv {
        report::csv(&conditions, &rows, &mut out)?;
    } else if args.table_only {
        report::table_only(&rows, conditions.bytes_in, conditions.memory, &mut out)?;
    } else {
        report::human(&conditions, &rows, &mut out)?;
    }
    out.flush()?;
    Ok(Ran::Measured)
}

/// The least time between two redraws of the bar, in nanoseconds.
const REDRAW_NS: u64 = 100_000_000;

/// The bar's cells.
const CELLS: u64 = 20;

/// The spinner after the bar, one frame per redraw.
const SPINNER: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// The row a bar line is about.
#[derive(Clone, Copy, Debug)]
struct RowLabel {
    k: usize,
    n: usize,
    format: &'static str,
    level: Option<i32>,
}

/// The progress meter on stderr: one bar line for the row being measured,
/// redrawn from `measure`'s reports (which come only between its timed
/// pieces) at most every [`REDRAW_NS`], and cleared before anything reaches
/// stdout. `out` is `None` when the meter is off.
struct Meter {
    out: Option<Box<dyn Write>>,
    /// Read only between timed pieces, for the throttle.
    clock: Box<dyn Clock>,
    repeats: u32,
    row: Option<RowLabel>,
    /// The repeat in progress, counted from its opening report.
    repeat: u32,
    /// When this row's bar was last drawn; `None` before its first draw.
    drawn_at: Option<u64>,
    frame: usize,
    shown: bool,
    /// The terminal's width in columns, asked at each draw.
    width: fn() -> usize,
}

impl Meter {
    fn new(
        out: Option<Box<dyn Write>>,
        clock: Box<dyn Clock>,
        repeats: u32,
        width: fn() -> usize,
    ) -> Self {
        Self {
            out,
            clock,
            width,
            repeats: repeats.max(1),
            row: None,
            repeat: 0,
            drawn_at: None,
            frame: 0,
            shown: false,
        }
    }

    /// The next row; its first report is drawn at once.
    fn row(&mut self, row: RowLabel) {
        self.row = Some(row);
        self.repeat = 0;
        self.drawn_at = None;
    }

    /// One report from `measure`. `(Compress, 0, _)` opens a repeat.
    fn progress(&mut self, phase: Phase, done: u64, total: u64) {
        let (Some(out), Some(row)) = (self.out.as_mut(), self.row) else {
            return;
        };
        if phase == Phase::Compress && done == 0 {
            self.repeat = (self.repeat + 1).min(self.repeats);
        }
        let now = self.clock.now();
        if let Some(at) = self.drawn_at
            && now.saturating_sub(at) < REDRAW_NS
        {
            return;
        }
        let repeat = (self.repeats > 1).then_some((self.repeat.max(1), self.repeats));
        let line = bar_line(&row, phase, repeat, done, total, self.frame);
        // One column short of the width: a line that wrapped would leave
        // its first part behind on the line above at the next redraw, and
        // one filling the last column leaves some terminals pending a wrap.
        let line = fit(&line, (self.width)().saturating_sub(1));
        // `\x1b[K` after the text clears what a longer previous line left.
        let _ = write!(out, "\r{line}\x1b[K");
        let _ = out.flush();
        self.frame = (self.frame + 1) % SPINNER.len();
        self.drawn_at = Some(now);
        self.shown = true;
    }

    fn clear(&mut self) {
        if let Some(out) = self.out.as_mut()
            && self.shown
        {
            let _ = write!(out, "\r\x1b[K");
            let _ = out.flush();
            self.shown = false;
        }
    }
}

/// `[k/N] <format> <level>  <phase> ▕<bar>▏<spinner> <pct>%`, `<phase>`
/// followed by ` r/N` when `repeat` is given. `done` past `total` counts
/// as `total`; a `total` of 0 is 100%, with nothing divided.
fn bar_line(
    row: &RowLabel,
    phase: Phase,
    repeat: Option<(u32, u32)>,
    done: u64,
    total: u64,
    frame: usize,
) -> String {
    let done = done.min(total);
    // Widened, so `done * 100` cannot overflow; no division when total is 0.
    let share = |scale: u64| {
        if total == 0 {
            scale
        } else {
            u64::try_from(u128::from(done) * u128::from(scale) / u128::from(total)).unwrap_or(scale)
        }
    };
    let cells = share(CELLS);
    let bar: String = (0..CELLS)
        .map(|i| if i < cells { '█' } else { '░' })
        .collect();
    let RowLabel {
        k,
        n,
        format,
        level,
    } = *row;
    let level = level.map_or_else(|| "-".to_string(), |l| l.to_string());
    let phase = match phase {
        Phase::Compress => "compress",
        Phase::Decompress => "decompress",
    };
    let repeat = repeat.map_or_else(String::new, |(r, n)| format!(" {r}/{n}"));
    let spinner = SPINNER[frame % SPINNER.len()];
    let pct = share(100);
    format!("[{k}/{n}] {format} {level}  {phase}{repeat} ▕{bar}▏{spinner} {pct}%")
}

/// stderr's width in columns (`TIOCGWINSZ`); 80 when the ioctl fails or
/// reports no width.
#[cfg(unix)]
fn terminal_width() -> usize {
    // SAFETY: winsize is plain data, filled by the ioctl.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes one winsize we own.
    let ok = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0;
    if ok && ws.ws_col > 0 {
        usize::from(ws.ws_col)
    } else {
        80
    }
}

/// 80 columns: no window-size query off unix.
#[cfg(not(unix))]
fn terminal_width() -> usize {
    80
}

/// The directories a pattern spells before its first glob character: the
/// part up to the last `/` before it (`/` itself when that is the first
/// character). `None` when the glob character is in the first component.
fn literal_prefix(pattern: &str) -> Option<&Path> {
    let first_glob = pattern.find(['*', '?', '['])?;
    let cut = pattern[..first_glob].rfind('/')?;
    Some(Path::new(&pattern[..cut.max(1)]))
}

/// The bar line fitted to `cols` columns: whole when it fits; otherwise
/// the row's label alone (`[k/N] format level`, the bar dropped), itself
/// cut to `cols` when even that is too wide. Every character [`bar_line`]
/// draws is one column wide.
fn fit(line: &str, cols: usize) -> String {
    if line.chars().count() <= cols {
        return line.to_string();
    }
    // The label ends at the two spaces before the phase.
    let label = line.split_once("  ").map_or(line, |(l, _)| l);
    truncate_cols(label, cols).to_string()
}

/// `s` cut to its first `cols` columns, one per character (never inside
/// a character's bytes).
fn truncate_cols(s: &str, cols: usize) -> &str {
    match s.char_indices().nth(cols) {
        Some((at, _)) => &s[..at],
        None => s,
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
/// size up front. A symlink counts as what it points to. A path that
/// cannot be read, named, matched or on a pattern's literal prefix, is
/// refused naming it (exit 2), never reported as no match.
fn expand_inputs(operands: &[String]) -> stuffr::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for op in operands {
        let path = Path::new(op);
        // A dangling symlink does not "exist" but is named: it is reported
        // as unreadable, not as a missing path; so is a named path whose
        // lookup fails for any reason but its absence (a directory without
        // search permission on the way). A pattern goes on to the glob,
        // which reports such a directory itself.
        match path.symlink_metadata() {
            Ok(_) => {
                if path.is_dir() {
                    return Err(directory_error(path));
                }
                files.push(regular(path)?);
                continue;
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound && !has_glob_chars(op) => {
                return Err(unreadable(path, &e));
            }
            Err(_) => {}
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
            let m = m.map_err(|e| unreadable(e.path(), e.error()))?;
            if m.is_dir() {
                first_dir.get_or_insert(m);
            } else {
                found.push(regular(&m)?);
            }
        }
        if found.is_empty() {
            if let Some(d) = first_dir {
                return Err(directory_error(&d));
            }
            // glob drops a literal directory it cannot stat, so a prefix
            // under an unreadable directory looks like no match.
            if let Some(prefix) = literal_prefix(op)
                && let Err(e) = prefix.symlink_metadata()
                && !matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                )
            {
                return Err(unreadable(prefix, &e));
            }
            return Err(no_match(op));
        }
        found.sort();
        files.extend(found);
    }
    Ok(files)
}

/// `path` if it is (or links to) a regular file, else the usage error. A
/// path whose metadata cannot be read (a dangling symlink, no permission)
/// is a usage error too, and so is a regular file that cannot be opened
/// (it is opened once here, and closed, so a debug build reports it too).
fn regular(path: &Path) -> stuffr::Result<PathBuf> {
    let meta = std::fs::metadata(path).map_err(|e| unreadable(path, &e))?;
    if meta.is_file() {
        std::fs::File::open(path).map_err(|e| unreadable(path, &e))?;
        Ok(path.to_path_buf())
    } else {
        Err(Error::Usage(format!(
            "{} is not a regular file; bench needs files whose size it can read",
            path.display()
        )))
    }
}

fn unreadable(path: &Path, e: &io::Error) -> Error {
    Error::Usage(format!("{}: cannot read it ({e})", path.display()))
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

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_a_usage_error() {
        let s = Scratch::new();
        s.file("real.log");
        let link = s.0.join("dangling.log");
        std::os::unix::fs::symlink(s.0.join("gone.log"), &link).unwrap();
        let named = usage(expand_inputs(&[s.s("dangling.log")]));
        assert!(
            named.starts_with(&format!("{}: cannot read it (", link.display())),
            "{named}"
        );
        // Matched by a pattern, beside a real file.
        let globbed = usage(expand_inputs(&[s.s("*.log")]));
        assert!(
            globbed.starts_with(&format!("{}: cannot read it (", link.display())),
            "{globbed}"
        );
    }

    /// Restores the mode so `Scratch`'s removal can enter the directory.
    #[cfg(unix)]
    struct Mode000(PathBuf);

    #[cfg(unix)]
    impl Drop for Mode000 {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_under_a_pattern_is_a_usage_error() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new();
        s.file("a.log");
        let locked = s.0.join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("b.log"), b"x").unwrap();
        let _restore = Mode000(locked.clone());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads it anyway; there is nothing to test.
        if fs::read_dir(&locked).is_ok() {
            return;
        }
        let m = usage(expand_inputs(&[s.s("*/*.log")]));
        assert!(m.contains("locked"), "{m}");
        assert!(m.contains(": cannot read it ("), "{m}");
    }

    #[cfg(unix)]
    #[test]
    fn a_named_path_in_an_unreadable_directory_cannot_be_read() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new();
        let locked = s.0.join("locked");
        fs::create_dir(&locked).unwrap();
        fs::write(locked.join("b.log"), b"x").unwrap();
        let _restore = Mode000(locked.clone());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads it anyway; there is nothing to test.
        if fs::read_dir(&locked).is_ok() {
            return;
        }
        let named = locked.join("b.log");
        let m = usage(expand_inputs(&[s.s("locked/b.log")]));
        assert!(
            m.starts_with(&format!("{}: cannot read it (", named.display())),
            "{m}"
        );
        // Named by a pattern, the glob reports the directory.
        let m = usage(expand_inputs(&[s.s("locked/*.log")]));
        assert!(m.contains(": cannot read it ("), "{m}");
    }

    /// The bar's text goes here, for the tests to read.
    #[derive(Clone, Default)]
    struct Captured(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(b);
            Ok(b.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        /// Each drawn line, without its `\r` and `\x1b[K`.
        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.0.borrow().clone())
                .unwrap()
                .split('\r')
                .map(|l| l.trim_end_matches("\x1b[K").to_string())
                .filter(|l| !l.is_empty())
                .collect()
        }
    }

    /// A clock the test moves by hand.
    struct HandClock(std::rc::Rc<std::cell::Cell<u64>>);

    impl Clock for HandClock {
        fn now(&mut self) -> u64 {
            self.0.get()
        }
    }

    fn label(k: usize, n: usize, format: &'static str, level: Option<i32>) -> RowLabel {
        RowLabel {
            k,
            n,
            format,
            level,
        }
    }

    #[test]
    fn the_bar_renders_blocks_and_a_spinner() {
        let xz = label(3, 8, "xz", Some(6));
        assert_eq!(
            bar_line(&xz, Phase::Compress, None, 0, 1000, 0),
            "[3/8] xz 6  compress ▕░░░░░░░░░░░░░░░░░░░░▏⠋ 0%"
        );
        assert_eq!(
            bar_line(&xz, Phase::Compress, None, 370, 1000, 1),
            "[3/8] xz 6  compress ▕███████░░░░░░░░░░░░░▏⠙ 37%"
        );
        assert_eq!(
            bar_line(&xz, Phase::Decompress, Some((2, 3)), 370, 1000, 2),
            "[3/8] xz 6  decompress 2/3 ▕███████░░░░░░░░░░░░░▏⠹ 37%"
        );
        let lz4 = label(8, 8, "lz4", None);
        assert_eq!(
            bar_line(&lz4, Phase::Decompress, None, 1000, 1000, 9),
            "[8/8] lz4 -  decompress ▕████████████████████▏⠏ 100%"
        );
        // Past the total is still 100%, never more.
        assert_eq!(
            bar_line(&lz4, Phase::Decompress, None, 2000, 1000, 9),
            "[8/8] lz4 -  decompress ▕████████████████████▏⠏ 100%"
        );
        // The spinner wraps after its ten frames.
        assert_eq!(
            bar_line(&lz4, Phase::Compress, None, 0, 1, 10),
            bar_line(&lz4, Phase::Compress, None, 0, 1, 0)
        );

        // Through the meter: the first report of a row draws at once, the
        // next ones at most every 100 ms, the spinner one frame per draw.
        let out = Captured::default();
        let t = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut meter = Meter::new(
            Some(Box::new(out.clone())),
            Box::new(HandClock(t.clone())),
            3,
            || 80,
        );
        meter.row(xz);
        meter.progress(Phase::Compress, 0, 1000);
        t.set(REDRAW_NS - 1);
        meter.progress(Phase::Compress, 370, 1000);
        t.set(REDRAW_NS);
        meter.progress(Phase::Compress, 370, 1000);
        t.set(2 * REDRAW_NS);
        meter.progress(Phase::Compress, 0, 1000);
        assert_eq!(
            out.lines(),
            vec![
                "[3/8] xz 6  compress 1/3 ▕░░░░░░░░░░░░░░░░░░░░▏⠋ 0%",
                "[3/8] xz 6  compress 1/3 ▕███████░░░░░░░░░░░░░▏⠙ 37%",
                "[3/8] xz 6  compress 2/3 ▕░░░░░░░░░░░░░░░░░░░░▏⠹ 0%",
            ]
        );
        // A new row draws at once, whatever the clock says.
        meter.row(lz4);
        meter.progress(Phase::Compress, 0, 1000);
        assert_eq!(
            out.lines().last().unwrap(),
            "[8/8] lz4 -  compress 1/3 ▕░░░░░░░░░░░░░░░░░░░░▏⠸ 0%"
        );
        meter.clear();
        assert!(out.0.borrow().ends_with(b"\r\x1b[K"));
    }

    #[test]
    fn an_empty_input_draws_full_and_divides_nothing() {
        let out = Captured::default();
        let mut meter = Meter::new(
            Some(Box::new(out.clone())),
            Box::new(RealClock::new()),
            1,
            || 80,
        );
        meter.row(label(1, 1, "gzip", Some(6)));
        let input = Input::Memory(vec![Vec::new()]);
        let plan = Plan {
            mode: Mode::OneStream,
            repeat: 1,
            threads: None,
            memory_limit: 1 << 30,
        };
        let mut seen = Vec::new();
        let o = measure(
            "gzip",
            None,
            &input,
            &plan,
            &mut RealClock::new(),
            &mut |ph, d, t| {
                seen.push((ph, d, t));
                meter.progress(ph, d, t)
            },
        );
        assert!(matches!(o, score::Outcome::Ok(_)), "{o:?}");
        assert_eq!(seen.first(), Some(&(Phase::Compress, 0, 0)));
        assert_eq!(seen.last(), Some(&(Phase::Decompress, 0, 0)));
        // The row's first report draws at once, full.
        assert_eq!(
            out.lines().first().map(String::as_str),
            Some("[1/1] gzip 6  compress ▕████████████████████▏⠋ 100%")
        );
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

    #[cfg(unix)]
    #[test]
    fn a_file_that_cannot_be_opened_is_a_usage_error_named_or_matched() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new();
        s.file("a.log");
        let locked = s.file("locked.log");
        let _restore = Mode000(locked.clone());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        // Root opens it anyway; there is nothing to test.
        if fs::File::open(&locked).is_ok() {
            return;
        }
        let want = format!("{}: cannot read it (", locked.display());
        let named = usage(expand_inputs(&[s.s("locked.log")]));
        assert!(named.starts_with(&want), "{named}");
        let globbed = usage(expand_inputs(&[s.s("*.log")]));
        assert!(globbed.starts_with(&want), "{globbed}");
    }

    /// glob drops a literal component it cannot stat, so a pattern under
    /// an unreadable directory would match nothing; the literal prefix is
    /// checked instead.
    #[cfg(unix)]
    #[test]
    fn a_pattern_under_an_unreadable_directory_names_the_prefix() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new();
        let locked = s.0.join("locked");
        fs::create_dir_all(locked.join("sub")).unwrap();
        fs::write(locked.join("sub/b.log"), b"x").unwrap();
        let _restore = Mode000(locked.clone());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads it anyway; there is nothing to test.
        if fs::read_dir(&locked).is_ok() {
            return;
        }
        let m = usage(expand_inputs(&[s.s("locked/sub/*.log")]));
        let prefix = locked.join("sub");
        assert!(
            m.starts_with(&format!("{}: cannot read it (", prefix.display())),
            "{m}"
        );
        // A prefix that is simply absent is still no match.
        let pat = s.s("absent/sub/*.log");
        assert_eq!(
            usage(expand_inputs(std::slice::from_ref(&pat))),
            format!("no input matched {pat}")
        );
    }

    #[test]
    fn the_literal_prefix_stops_before_the_first_glob_component() {
        assert_eq!(literal_prefix("a/b/*.log"), Some(Path::new("a/b")));
        assert_eq!(literal_prefix("/x/l?ck/sub/*.log"), Some(Path::new("/x")));
        assert_eq!(literal_prefix("/*.log"), Some(Path::new("/")));
        assert_eq!(literal_prefix("*.log"), None);
        assert_eq!(literal_prefix("a/[b]/c"), Some(Path::new("a")));
    }

    #[test]
    fn the_bar_line_is_cut_to_the_terminal_width() {
        let full = bar_line(
            &label(3, 8, "xz", Some(6)),
            Phase::Decompress,
            Some((2, 3)),
            370,
            1000,
            2,
        );
        // 54 columns, all of them one column wide.
        assert_eq!(full.chars().count(), 54);
        assert_eq!(fit(&full, 80), full);
        assert_eq!(fit(&full, 54), full);
        // Too narrow for the bar: the row's label alone.
        assert_eq!(fit(&full, 53), "[3/8] xz 6");
        assert_eq!(fit(&full, 40), "[3/8] xz 6");
        assert_eq!(fit(&full, 20), "[3/8] xz 6");
        // Narrower than the label: the label is cut too.
        assert_eq!(fit(&full, 5), "[3/8]");
        assert_eq!(fit(&full, 0), "");
        let long = bar_line(
            &label(12, 34, "compress", Some(16)),
            Phase::Compress,
            None,
            0,
            1,
            0,
        );
        assert_eq!(fit(&long, 20), "[12/34] compress 16");
        assert_eq!(fit(&long, 10), "[12/34] co");
    }

    #[test]
    fn truncation_counts_columns_not_bytes() {
        let line = "ab ▕██░▏⠹ 37%";
        // Each block, bar end and spinner is three bytes and one column.
        assert_eq!(truncate_cols(line, 3), "ab ");
        assert_eq!(truncate_cols(line, 4), "ab ▕");
        assert_eq!(truncate_cols(line, 6), "ab ▕██");
        assert_eq!(truncate_cols(line, 9), "ab ▕██░▏⠹");
        assert_eq!(truncate_cols(line, 100), line);
        assert_eq!(truncate_cols(line, 0), "");
    }

    #[test]
    fn the_meter_draws_within_the_terminal_width() {
        let out = Captured::default();
        let mut meter = Meter::new(
            Some(Box::new(out.clone())),
            Box::new(HandClock(std::rc::Rc::new(std::cell::Cell::new(0)))),
            1,
            || 30,
        );
        meter.row(label(3, 8, "xz", Some(6)));
        meter.progress(Phase::Compress, 0, 1000);
        // One column kept free, so the cursor never sits past the edge.
        assert_eq!(out.lines(), vec!["[3/8] xz 6"]);
    }

    /// A clock that counts its reads.
    struct CountClock(std::rc::Rc<std::cell::Cell<u32>>);

    impl Clock for CountClock {
        fn now(&mut self) -> u64 {
            self.0.set(self.0.get() + 1);
            0
        }
    }

    /// Off (no terminal, or a machine-readable report), the meter neither
    /// writes nor reads its clock, so it costs a run nothing.
    #[test]
    fn a_meter_that_is_off_writes_nothing_and_reads_no_clock() {
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut meter = Meter::new(None, Box::new(CountClock(reads.clone())), 3, || {
            panic!("an off meter asked for the width")
        });
        meter.row(label(1, 2, "gzip", Some(6)));
        meter.progress(Phase::Compress, 0, 1000);
        meter.progress(Phase::Compress, 500, 1000);
        meter.progress(Phase::Decompress, 1000, 1000);
        meter.row(label(2, 2, "xz", Some(6)));
        meter.progress(Phase::Compress, 0, 1000);
        meter.clear();
        assert_eq!(reads.get(), 0, "an off meter read its clock");
        assert!(!meter.shown);
    }
}
