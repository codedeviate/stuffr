//! Output renderers for `stuffr bench`: the human table (layout B), JSON and
//! CSV. Pure formatting over already-measured rows; no timing happens here.
//!
//! The size formatter is local: `stuffr_core::format_size` prints exact
//! multiples without a decimal and uses `bytes` as the unit, while the table
//! wants a uniform one-decimal `38.1 MiB` and `512 B`.

use std::io::{self, Write};

use serde_json::{Value, json};

use super::measure::Mode;
use super::score::{Measured, Outcome, Row, balance_scores, winners};

/// The conditions the run was made under, shown on the input line and in
/// JSON and CSV. The backend is per row (`Row::backend`), not here: one
/// build can bench some codecs through C and others in pure Rust.
#[derive(Clone, Debug)]
pub struct Conditions {
    pub files: usize,
    pub bytes_in: u64,
    pub mode: Mode,
    /// `--threads` as given.
    pub threads: Option<usize>,
    /// The worker budget that setting resolved to (1 without `--threads`).
    pub workers: usize,
    pub repeat: u32,
    pub streamed: bool,
}

/// The winners block's label column: the longest label plus two spaces.
/// Padded by format rather than spelled with spaces in the literal, which
/// the workspace's collapsed-indentation guard would flag.
const LABEL: usize = 21;

const HEADER: [&str; 6] = ["format", "level", "size", "ratio", "compress", "decompress"];

/// `512 B`, else one decimal of the largest unit up to GiB. The unit is
/// chosen on the rounded value, so 1023.96 KiB reads `1.0 MiB`, never
/// `1024.0 KiB`.
fn size_text(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    const UNITS: [&str; 3] = ["KiB", "MiB", "GiB"];
    let mut tenths = 0u128;
    for (i, name) in UNITS.iter().enumerate() {
        let unit = 1u128 << (10 * (i + 1));
        tenths = (u128::from(bytes) * 10 + unit / 2) / unit;
        if tenths < 10_240 || i == UNITS.len() - 1 {
            return format!("{}.{} {name}", tenths / 10, tenths % 10);
        }
    }
    unreachable!("the last unit always returns ({tenths})")
}

/// `bytes_in / bytes_out`, `None` when either is 0.
fn ratio_of(bytes_in: u64, bytes_out: u64) -> Option<f64> {
    (bytes_in > 0 && bytes_out > 0).then(|| bytes_in as f64 / bytes_out as f64)
}

fn ratio_text(bytes_in: u64, bytes_out: u64) -> String {
    ratio_of(bytes_in, bytes_out).map_or_else(|| "-".into(), |r| format!("{r:.1}x"))
}

/// `0.4 ms` below 10 ms, `850 ms` below one second, otherwise `1.3 s`:
/// rounded half up, in integers, and each form chosen on its rounded value,
/// so 9.96 ms reads `10 ms` and 999.6 ms reads `1.0 s`.
fn time_text(ns: u64) -> String {
    let ns = u128::from(ns);
    let tenth_ms = (ns + 50_000) / 100_000;
    if tenth_ms < 100 {
        return format!("{}.{} ms", tenth_ms / 10, tenth_ms % 10);
    }
    let ms = (ns + 500_000) / 1_000_000;
    if ms < 1000 {
        return format!("{ms} ms");
    }
    let tenths = (ns + 50_000_000) / 100_000_000;
    format!("{}.{} s", tenths / 10, tenths % 10)
}

/// A failure reason fit for one table line: its first line, any other
/// control character escaped, and `…` when lines were dropped. JSON and CSV
/// keep the whole text.
fn one_line(why: &str) -> String {
    let mut lines = why.lines();
    let first = lines.next().unwrap_or("");
    let mut out = String::with_capacity(first.len());
    for c in first.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    if lines.next().is_some() {
        out.push_str(" …");
    }
    out
}

/// The input line's backend: `pure` when every row ran in pure Rust, else
/// `C: ` and the codecs that ran through a C library, in table order.
fn backend_text(rows: &[Row]) -> String {
    let mut c: Vec<&str> = Vec::new();
    for r in rows.iter().filter(|r| r.backend == "c") {
        if !c.contains(&r.format) {
            c.push(r.format);
        }
    }
    if c.is_empty() {
        "pure".into()
    } else {
        format!("C: {}", c.join(", "))
    }
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::OneStream => "one-stream",
        Mode::PerFile => "per-file",
    }
}

fn name_of(row: &Row) -> String {
    match row.level {
        Some(l) => format!("{} -{l}", row.format),
        None => row.format.to_string(),
    }
}

/// The resolved compression worker budget; `(auto)` when `--threads 0`
/// chose it. Decompression is always single-threaded.
fn threads_text(threads: Option<usize>, workers: usize) -> String {
    let unit = if workers == 1 {
        "compress thread"
    } else {
        "compress threads"
    };
    match threads {
        Some(0) => format!("{workers} {unit} (auto)"),
        _ => format!("{workers} {unit}"),
    }
}

fn input_line(c: &Conditions, rows: &[Row]) -> String {
    let mode = match c.mode {
        Mode::OneStream => "one stream",
        Mode::PerFile => "per file",
    };
    let files = if c.files == 1 { "file" } else { "files" };
    let runs = if c.repeat == 1 { "run" } else { "runs" };
    format!(
        "input: {} {files}, {} · {mode} · {} · {} · {} {runs}{}",
        c.files,
        size_text(c.bytes_in),
        threads_text(c.threads, c.workers),
        backend_text(rows),
        c.repeat,
        if c.streamed {
            ", streamed from disk"
        } else {
            ""
        },
    )
}

/// The footnote under a table with a marked row.
const DISK_NOTE: &str = "* output written to a temp file while timed (too large for memory)";

/// The compress-time cell's mark: `*` for a row whose output went to the
/// temp file, a space for the others when any row is marked (so the
/// column stays aligned), nothing when none is.
fn disk_mark(on_disk: bool, any: bool) -> &'static str {
    match (any, on_disk) {
        (false, _) => "",
        (true, true) => "*",
        (true, false) => " ",
    }
}

fn any_on_disk(rows: &[Row]) -> bool {
    rows.iter().filter_map(measured).any(|m| m.on_disk)
}

fn output_name(m: &Measured) -> &'static str {
    if m.on_disk { "disk" } else { "memory" }
}

fn table_lines(rows: &[Row], bytes_in: u64) -> Vec<String> {
    let any = any_on_disk(rows);
    let mut header: Vec<String> = HEADER.iter().map(|s| s.to_string()).collect();
    header[4].push_str(disk_mark(false, any));
    let mut cells: Vec<Vec<String>> = vec![header];
    let mut failures: Vec<Option<String>> = vec![None];
    for row in rows {
        let level = row.level.map_or_else(|| "-".into(), |l| l.to_string());
        match &row.outcome {
            Outcome::Ok(m) => {
                cells.push(vec![
                    row.format.into(),
                    level,
                    size_text(m.bytes_out),
                    ratio_text(bytes_in, m.bytes_out),
                    format!("{}{}", time_text(m.compress_ns), disk_mark(m.on_disk, any)),
                    time_text(m.decompress_ns),
                ]);
                failures.push(None);
            }
            Outcome::Failed(why) => {
                cells.push(vec![row.format.into(), level]);
                failures.push(Some(format!("failed: {}", one_line(why))));
            }
        }
    }
    let widths: Vec<usize> = (0..6)
        .map(|i| {
            cells
                .iter()
                .filter_map(|r| r.get(i))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    cells
        .iter()
        .zip(&failures)
        .map(|(r, failed)| {
            let mut line = format!("{:<w$}", r[0], w = widths[0]);
            for (i, cell) in r.iter().enumerate().skip(1) {
                line.push_str(&format!("  {:>w$}", cell, w = widths[i]));
            }
            if let Some(f) = failed {
                line.push_str("  ");
                line.push_str(f);
            }
            line
        })
        .collect()
}

/// The table, then the footnote when a row is marked.
fn write_table(rows: &[Row], bytes_in: u64, out: &mut dyn Write) -> io::Result<()> {
    for line in table_lines(rows, bytes_in) {
        writeln!(out, "{}", line.trim_end())?;
    }
    if any_on_disk(rows) {
        writeln!(out, "{DISK_NOTE}")?;
    }
    Ok(())
}

fn measured(row: &Row) -> Option<&Measured> {
    match &row.outcome {
        Outcome::Ok(m) => Some(m),
        Outcome::Failed(_) => None,
    }
}

/// The input line, the table and the winners block.
pub fn human(c: &Conditions, rows: &[Row], out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{}", input_line(c, rows))?;
    writeln!(out)?;
    write_table(rows, c.bytes_in, out)?;
    writeln!(out)?;
    let w = winners(rows);
    let pick = |i: Option<usize>| i.map(|i| (name_of(&rows[i]), measured(&rows[i]).copied()));
    let (Some((sn, Some(sm))), Some((cn, Some(cm))), Some((dn, Some(dm))), Some((bn, Some(bm)))) = (
        pick(w.smallest),
        pick(w.fastest_compress),
        pick(w.fastest_decompress),
        pick(w.balance),
    ) else {
        return writeln!(out, "no format succeeded");
    };
    let width = [&sn, &cn, &dn, &bn]
        .iter()
        .map(|s| s.chars().count() + 2)
        .max()
        .unwrap_or(0)
        .max(12);
    writeln!(
        out,
        "{:<LABEL$}{sn:<width$}{} ({})",
        "smallest:",
        size_text(sm.bytes_out),
        ratio_text(c.bytes_in, sm.bytes_out)
    )?;
    writeln!(
        out,
        "{:<LABEL$}{cn:<width$}{}",
        "fastest compress:",
        time_text(cm.compress_ns)
    )?;
    writeln!(
        out,
        "{:<LABEL$}{dn:<width$}{}",
        "fastest decompress:",
        time_text(dm.decompress_ns)
    )?;
    writeln!(
        out,
        "{:<LABEL$}{bn:<width$}{} at {} / {}",
        "best balance:",
        ratio_text(c.bytes_in, bm.bytes_out),
        time_text(bm.compress_ns),
        time_text(bm.decompress_ns)
    )
}

/// The table alone: header, rows and the footnote when a row is marked.
pub fn table_only(rows: &[Row], bytes_in: u64, out: &mut dyn Write) -> io::Result<()> {
    write_table(rows, bytes_in, out)
}

fn finite(x: Option<f64>) -> Value {
    x.filter(|x| x.is_finite())
        .map_or(Value::Null, |x| json!(x))
}

/// One JSON object: conditions, rows and winners. Scores are relative to
/// this run.
pub fn json(c: &Conditions, rows: &[Row], out: &mut dyn Write) -> io::Result<()> {
    let scores = balance_scores(rows);
    let w = winners(rows);
    let who = |i: Option<usize>| {
        i.map_or(
            Value::Null,
            |i| json!({"format": rows[i].format, "level": rows[i].level}),
        )
    };
    let jrows: Vec<Value> = rows
        .iter()
        .zip(&scores)
        .map(|(r, score)| match &r.outcome {
            Outcome::Ok(m) => json!({
                "format": r.format, "level": r.level, "backend": r.backend, "ok": true,
                "bytes_out": m.bytes_out,
                "ratio": finite(ratio_of(c.bytes_in, m.bytes_out)),
                "compress_ns": m.compress_ns, "decompress_ns": m.decompress_ns,
                "balance": finite(*score), "error": null,
                "output": output_name(m),
            }),
            Outcome::Failed(why) => json!({
                "format": r.format, "level": r.level, "backend": r.backend, "ok": false,
                "bytes_out": null, "ratio": null,
                "compress_ns": null, "decompress_ns": null,
                "balance": null, "error": why, "output": null,
            }),
        })
        .collect();
    let doc = json!({
        "conditions": {
            "files": c.files,
            "bytes_in": c.bytes_in,
            "mode": mode_name(c.mode),
            "threads": c.threads,
            "workers": c.workers,
            "repeat": c.repeat,
            "streamed": c.streamed,
        },
        "rows": jrows,
        "winners": {
            "smallest": who(w.smallest),
            "fastest_compress": who(w.fastest_compress),
            "fastest_decompress": who(w.fastest_decompress),
            "balance": who(w.balance),
        },
    });
    writeln!(out, "{doc}")
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Header plus one line per row; empty fields stand for none. The run's
/// conditions follow the measurements on every line, then the row's
/// backend, and last its `output` (`memory` or `disk`, empty for a failed
/// row).
pub fn csv(c: &Conditions, rows: &[Row], out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "format,level,ok,bytes_in,bytes_out,ratio,compress_ns,decompress_ns,balance,error,\
         files,mode,threads,workers,repeat,streamed,backend,output"
    )?;
    let bytes_in = c.bytes_in;
    let threads = c.threads.map_or(String::new(), |t| t.to_string());
    let conditions = format!(
        "{},{},{threads},{},{},{}",
        c.files,
        mode_name(c.mode),
        c.workers,
        c.repeat,
        c.streamed
    );
    for (r, score) in rows.iter().zip(balance_scores(rows)) {
        let level = r.level.map_or(String::new(), |l| l.to_string());
        match &r.outcome {
            Outcome::Ok(m) => {
                let ratio =
                    ratio_of(bytes_in, m.bytes_out).map_or(String::new(), |x| x.to_string());
                let bal = score.map_or(String::new(), |x| x.to_string());
                writeln!(
                    out,
                    "{},{level},true,{bytes_in},{},{ratio},{},{},{bal},,{conditions},{},{}",
                    r.format,
                    m.bytes_out,
                    m.compress_ns,
                    m.decompress_ns,
                    r.backend,
                    output_name(m)
                )?;
            }
            Outcome::Failed(why) => writeln!(
                out,
                "{},{level},false,{bytes_in},,,,,,{},{conditions},{},",
                r.format,
                csv_field(why),
                r.backend
            )?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn ok(format: &'static str, level: Option<i32>, out: u64, c_ms: u64, d_ms: u64) -> Row {
        Row {
            format,
            level,
            backend: "pure",
            outcome: Outcome::Ok(Measured {
                bytes_out: out,
                compress_ns: c_ms * 1_000_000,
                decompress_ns: d_ms * 1_000_000,
                on_disk: false,
            }),
        }
    }

    fn rows() -> Vec<Row> {
        vec![
            ok("zstd", Some(3), 40 * MIB, 900, 300),
            ok("lz4", None, 100 * MIB, 600, 200),
            ok("xz", Some(6), 25 * MIB, 8200, 1250),
            Row {
                format: "bzip2",
                level: Some(9),
                backend: "pure",
                outcome: Outcome::Failed("no c tier".into()),
            },
        ]
    }

    fn cond() -> Conditions {
        Conditions {
            files: 3,
            bytes_in: 412 * MIB,
            mode: Mode::OneStream,
            threads: None,
            workers: 1,
            repeat: 1,
            streamed: false,
        }
    }

    fn render(f: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> String {
        let mut v = Vec::new();
        f(&mut v).unwrap();
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn human_output_is_layout_b() {
        let got = render(|o| human(&cond(), &rows(), o));
        // A file, not a literal: the table's column runs would trip the
        // workspace's collapsed-indentation guard, which scans `.rs` files.
        let want = include_str!("testdata/human-layout-b.txt");
        assert_eq!(got, want);
    }

    #[test]
    fn table_only_has_no_input_line_or_winners() {
        let got = render(|o| table_only(&rows(), 412 * MIB, o));
        assert!(got.starts_with("format"));
        assert!(!got.contains("input:") && !got.contains("smallest"));
        assert_eq!(got.lines().count(), 5);
    }

    #[test]
    fn json_parses_and_carries_conditions() {
        let got = render(|o| json(&cond(), &rows(), o));
        let v: Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["conditions"]["mode"], "one-stream");
        assert!(v["conditions"]["tier"].is_null(), "the backend is per row");
        assert_eq!(v["rows"][0]["backend"], "pure");
        assert_eq!(v["rows"].as_array().unwrap().len(), 4);
        assert_eq!(v["winners"]["smallest"]["format"], "xz");
        assert_eq!(v["rows"][3]["ok"], false);
        assert!(!v["rows"][3]["error"].is_null());
        assert!(v["rows"][1]["level"].is_null());
    }

    #[test]
    fn csv_quotes_a_comma_in_an_error() {
        let rows = vec![Row {
            format: "xz",
            level: Some(6),
            backend: "c",
            outcome: Outcome::Failed("bad, \"very\" bad".into()),
        }];
        let c = Conditions {
            bytes_in: 10,
            ..cond()
        };
        let got = render(|o| csv(&c, &rows, o));
        let mut lines = got.lines();
        assert_eq!(
            lines.next().unwrap(),
            "format,level,ok,bytes_in,bytes_out,ratio,compress_ns,decompress_ns,balance,error,\
             files,mode,threads,workers,repeat,streamed,backend,output"
        );
        assert_eq!(
            lines.next().unwrap(),
            "xz,6,false,10,,,,,,\"bad, \"\"very\"\" bad\",3,one-stream,,1,1,false,c,"
        );
    }

    #[test]
    fn zero_input_prints_a_dash_ratio() {
        let rows = vec![ok("lz4", None, 0, 1, 1)];
        let got = render(|o| table_only(&rows, 0, o));
        assert!(got.lines().nth(1).unwrap().contains("  -  "), "{got}");
        let mut c = cond();
        c.bytes_in = 0;
        let j = render(|o| json(&c, &rows, o));
        assert!(serde_json::from_str::<Value>(&j).unwrap()["rows"][0]["ratio"].is_null());
    }

    #[test]
    fn no_success_prints_no_format_succeeded() {
        let rows = vec![Row {
            format: "xz",
            level: Some(1),
            backend: "pure",
            outcome: Outcome::Failed("x".into()),
        }];
        let got = render(|o| human(&cond(), &rows, o));
        assert!(got.ends_with("\nno format succeeded\n"), "{got}");
        assert!(!got.contains("smallest"));
    }

    #[test]
    fn the_input_line_shows_the_resolved_worker_count() {
        assert_eq!(threads_text(None, 1), "1 compress thread");
        assert_eq!(threads_text(Some(1), 1), "1 compress thread");
        assert_eq!(threads_text(Some(4), 4), "4 compress threads");
        assert_eq!(threads_text(Some(0), 8), "8 compress threads (auto)");
        let c = Conditions {
            threads: Some(0),
            workers: 8,
            ..cond()
        };
        assert!(input_line(&c, &rows()).contains(" · 8 compress threads (auto) · "));
        let j = render(|o| json(&c, &[], o));
        let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["conditions"]["threads"], 0);
        assert_eq!(v["conditions"]["workers"], 8);
    }

    #[test]
    fn ms_below_a_second_s_above() {
        assert_eq!(time_text(850_000_000), "850 ms");
        assert_eq!(time_text(1_250_000_000), "1.3 s");
        assert_eq!(time_text(900_000_000), "900 ms");
    }

    #[test]
    fn csv_carries_the_conditions_and_each_rows_backend() {
        let mut rows = rows();
        rows[0].backend = "c";
        let c = Conditions {
            mode: Mode::PerFile,
            threads: Some(0),
            workers: 8,
            repeat: 5,
            streamed: true,
            ..cond()
        };
        let got = render(|o| csv(&c, &rows, o));
        let lines: Vec<&str> = got.lines().collect();
        let header: Vec<&str> = lines[0].split(',').collect();
        assert_eq!(header.len(), 18);
        assert_eq!(header[17], "output");
        assert_eq!(
            &header[..10],
            &[
                "format",
                "level",
                "ok",
                "bytes_in",
                "bytes_out",
                "ratio",
                "compress_ns",
                "decompress_ns",
                "balance",
                "error"
            ]
        );
        for line in &lines[1..] {
            let f: Vec<&str> = line.split(',').collect();
            assert_eq!(f.len(), 18, "{line}");
            assert_eq!(
                &f[10..16],
                &["3", "per-file", "0", "8", "5", "true"],
                "{line}"
            );
        }
        assert!(lines[1].starts_with("zstd,3,true,"), "{}", lines[1]);
        assert!(lines[1].ends_with(",c,memory"), "{}", lines[1]);
        assert!(lines[2].ends_with(",pure,memory"), "{}", lines[2]);
        // No --threads: an empty field, not 0.
        let got = render(|o| csv(&cond(), &rows, o));
        assert!(
            got.lines()
                .nth(1)
                .unwrap()
                .contains(",3,one-stream,,1,1,false,")
        );
    }

    #[test]
    fn the_input_line_names_the_c_backed_codecs() {
        let mut rows = rows();
        assert!(input_line(&cond(), &rows).contains(" · pure · "));
        rows[0].backend = "c";
        rows[1].backend = "c";
        rows.push(ok("zstd", Some(19), MIB, 1, 1));
        rows.last_mut().unwrap().backend = "c";
        let line = input_line(&cond(), &rows);
        assert!(line.contains(" · C: zstd, lz4 · "), "{line}");
        let j = render(|o| json(&cond(), &rows, o));
        let v: Value = serde_json::from_str(&j).unwrap();
        let backends: Vec<&str> = v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["backend"].as_str().unwrap())
            .collect();
        assert_eq!(backends, ["c", "c", "pure", "pure", "c"]);
    }

    #[test]
    fn a_multi_line_failure_keeps_to_one_table_line() {
        let mut rows = rows();
        rows[3].outcome = Outcome::Failed("first\nsecond\tthird\u{1b}[31m".into());
        let table = render(|o| table_only(&rows, 412 * MIB, o));
        assert_eq!(table.lines().count(), 5, "{table}");
        let last = table.lines().last().unwrap();
        assert!(last.ends_with("failed: first …"), "{last}");
        rows[3].outcome = Outcome::Failed("tab\there\u{1b}[31m".into());
        let table = render(|o| table_only(&rows, 412 * MIB, o));
        let last = table.lines().last().unwrap();
        assert!(last.ends_with("failed: tab\\there\\u{1b}[31m"), "{last}");
        // JSON and CSV keep the whole text.
        let j = render(|o| json(&cond(), &rows, o));
        let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["rows"][3]["error"], "tab\there\u{1b}[31m");
    }

    #[test]
    fn times_under_10_ms_keep_a_decimal_and_edges_round_up_a_unit() {
        assert_eq!(time_text(40_000), "0.0 ms");
        assert_eq!(time_text(400_000), "0.4 ms");
        assert_eq!(time_text(9_940_000), "9.9 ms");
        // 9.96 ms rounds to 10.0, so it takes the whole-ms form.
        assert_eq!(time_text(9_960_000), "10 ms");
        assert_eq!(time_text(10_000_000), "10 ms");
        // 999.6 ms rounds to 1000 ms: a second.
        assert_eq!(time_text(999_600_000), "1.0 s");
        assert_eq!(time_text(999_400_000), "999 ms");
        assert_eq!(time_text(59_950_000_000), "60.0 s");
    }

    #[test]
    fn sizes_round_up_a_unit_at_the_edge() {
        assert_eq!(size_text(1023), "1023 B");
        assert_eq!(size_text(1024), "1.0 KiB");
        // 1023.96 KiB and MiB print as 1024.0 of the unit below otherwise.
        assert_eq!(size_text(1_048_535), "1.0 MiB");
        assert_eq!(size_text((1023.96 * MIB as f64) as u64), "1.0 GiB");
        assert_eq!(size_text((1023.9 * MIB as f64) as u64), "1023.9 MiB");
        assert_eq!(size_text(2 << 30), "2.0 GiB");
        assert_eq!(size_text(412 * MIB), "412.0 MiB");
    }

    /// `rows()` with xz's output on the temp file.
    fn marked_rows() -> Vec<Row> {
        let mut rows = rows();
        if let Outcome::Ok(m) = &mut rows[2].outcome {
            m.on_disk = true;
        }
        rows
    }

    #[test]
    fn a_row_timed_with_disk_output_is_marked_with_a_footnote() {
        let got = render(|o| human(&cond(), &marked_rows(), o));
        let want = include_str!("testdata/human-marked.txt");
        assert_eq!(got, want);
        let got = render(|o| table_only(&marked_rows(), 412 * MIB, o));
        let want = include_str!("testdata/table-only-marked.txt");
        assert_eq!(got, want);
        // No marked row: no mark column, no footnote.
        let plain = render(|o| table_only(&rows(), 412 * MIB, o));
        assert!(!plain.contains('*'), "{plain}");
    }

    #[test]
    fn json_and_csv_say_where_each_rows_output_went() {
        let got = render(|o| json(&cond(), &marked_rows(), o));
        let v: Value = serde_json::from_str(&got).unwrap();
        assert_eq!(v["rows"][0]["output"], "memory");
        assert_eq!(v["rows"][2]["output"], "disk");
        assert!(v["rows"][3]["output"].is_null(), "a failed row");
        let got = render(|o| csv(&cond(), &marked_rows(), o));
        let lines: Vec<&str> = got.lines().collect();
        assert!(lines[0].ends_with(",backend,output"), "{}", lines[0]);
        assert!(lines[1].ends_with(",pure,memory"), "{}", lines[1]);
        assert!(lines[3].ends_with(",pure,disk"), "{}", lines[3]);
        assert!(lines[4].ends_with(",pure,"), "{}", lines[4]);
        for line in &lines {
            assert_eq!(line.split(',').count(), 18, "{line}");
        }
    }
}
