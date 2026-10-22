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
/// JSON. `tier` is `"pure"` or `"c-backed"`.
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
    pub tier: &'static str,
    pub streamed: bool,
}

/// The winners block's label column: the longest label plus two spaces.
/// Padded by format rather than spelled with spaces in the literal, which
/// the workspace's collapsed-indentation guard would flag.
const LABEL: usize = 21;

const HEADER: [&str; 6] = ["format", "level", "size", "ratio", "compress", "decompress"];

fn size_text(bytes: u64) -> String {
    const UNITS: [(u64, &str); 3] = [(1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")];
    for (unit, name) in UNITS {
        if bytes >= unit {
            return format!("{:.1} {name}", bytes as f64 / unit as f64);
        }
    }
    format!("{bytes} B")
}

/// `bytes_in / bytes_out`, `None` when either is 0.
fn ratio_of(bytes_in: u64, bytes_out: u64) -> Option<f64> {
    (bytes_in > 0 && bytes_out > 0).then(|| bytes_in as f64 / bytes_out as f64)
}

fn ratio_text(bytes_in: u64, bytes_out: u64) -> String {
    ratio_of(bytes_in, bytes_out).map_or_else(|| "-".into(), |r| format!("{r:.1}x"))
}

/// `850 ms` below one second, otherwise `0.9 s`-style with one decimal
/// (rounded half up, in integers, so 1.25 s reads `1.3 s`).
fn time_text(ns: u64) -> String {
    if ns < 1_000_000_000 {
        return format!("{} ms", (ns + 500_000) / 1_000_000);
    }
    let tenths = (ns + 50_000_000) / 100_000_000;
    format!("{}.{} s", tenths / 10, tenths % 10)
}

fn name_of(row: &Row) -> String {
    match row.level {
        Some(l) => format!("{} -{l}", row.format),
        None => row.format.to_string(),
    }
}

/// The resolved worker budget; `(auto)` when `--threads 0` chose it.
fn threads_text(threads: Option<usize>, workers: usize) -> String {
    let unit = if workers == 1 { "thread" } else { "threads" };
    match threads {
        Some(0) => format!("{workers} {unit} (auto)"),
        _ => format!("{workers} {unit}"),
    }
}

fn input_line(c: &Conditions) -> String {
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
        c.tier,
        c.repeat,
        if c.streamed {
            ", streamed from disk"
        } else {
            ""
        },
    )
}

fn table_lines(rows: &[Row], bytes_in: u64) -> Vec<String> {
    let mut cells: Vec<Vec<String>> = vec![HEADER.iter().map(|s| s.to_string()).collect()];
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
                    time_text(m.compress_ns),
                    time_text(m.decompress_ns),
                ]);
                failures.push(None);
            }
            Outcome::Failed(why) => {
                cells.push(vec![row.format.into(), level]);
                failures.push(Some(format!("failed: {why}")));
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

fn write_table(rows: &[Row], bytes_in: u64, out: &mut dyn Write) -> io::Result<()> {
    for line in table_lines(rows, bytes_in) {
        writeln!(out, "{}", line.trim_end())?;
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
    writeln!(out, "{}", input_line(c))?;
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

/// The table alone: header and rows.
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
                "format": r.format, "level": r.level, "ok": true,
                "bytes_out": m.bytes_out,
                "ratio": finite(ratio_of(c.bytes_in, m.bytes_out)),
                "compress_ns": m.compress_ns, "decompress_ns": m.decompress_ns,
                "balance": finite(*score), "error": null,
            }),
            Outcome::Failed(why) => json!({
                "format": r.format, "level": r.level, "ok": false,
                "bytes_out": null, "ratio": null,
                "compress_ns": null, "decompress_ns": null,
                "balance": null, "error": why,
            }),
        })
        .collect();
    let doc = json!({
        "conditions": {
            "files": c.files,
            "bytes_in": c.bytes_in,
            "mode": match c.mode { Mode::OneStream => "one-stream", Mode::PerFile => "per-file" },
            "threads": c.threads,
            "workers": c.workers,
            "repeat": c.repeat,
            "tier": c.tier,
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

/// Header plus one line per row; empty fields stand for none.
pub fn csv(rows: &[Row], bytes_in: u64, out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "format,level,ok,bytes_in,bytes_out,ratio,compress_ns,decompress_ns,balance,error"
    )?;
    for (r, score) in rows.iter().zip(balance_scores(rows)) {
        let level = r.level.map_or(String::new(), |l| l.to_string());
        match &r.outcome {
            Outcome::Ok(m) => {
                let ratio =
                    ratio_of(bytes_in, m.bytes_out).map_or(String::new(), |x| x.to_string());
                let bal = score.map_or(String::new(), |x| x.to_string());
                writeln!(
                    out,
                    "{},{level},true,{bytes_in},{},{ratio},{},{},{bal},",
                    r.format, m.bytes_out, m.compress_ns, m.decompress_ns
                )?;
            }
            Outcome::Failed(why) => writeln!(
                out,
                "{},{level},false,{bytes_in},,,,,,{}",
                r.format,
                csv_field(why)
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
            outcome: Outcome::Ok(Measured {
                bytes_out: out,
                compress_ns: c_ms * 1_000_000,
                decompress_ns: d_ms * 1_000_000,
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
            tier: "pure",
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
        assert_eq!(v["conditions"]["tier"], "pure");
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
            outcome: Outcome::Failed("bad, \"very\" bad".into()),
        }];
        let got = render(|o| csv(&rows, 10, o));
        let mut lines = got.lines();
        assert_eq!(
            lines.next().unwrap(),
            "format,level,ok,bytes_in,bytes_out,ratio,compress_ns,decompress_ns,balance,error"
        );
        assert_eq!(
            lines.next().unwrap(),
            "xz,6,false,10,,,,,,\"bad, \"\"very\"\" bad\""
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
            outcome: Outcome::Failed("x".into()),
        }];
        let got = render(|o| human(&cond(), &rows, o));
        assert!(got.ends_with("\nno format succeeded\n"), "{got}");
        assert!(!got.contains("smallest"));
    }

    #[test]
    fn the_input_line_shows_the_resolved_worker_count() {
        assert_eq!(threads_text(None, 1), "1 thread");
        assert_eq!(threads_text(Some(1), 1), "1 thread");
        assert_eq!(threads_text(Some(4), 4), "4 threads");
        assert_eq!(threads_text(Some(0), 8), "8 threads (auto)");
        let c = Conditions {
            threads: Some(0),
            workers: 8,
            ..cond()
        };
        assert!(input_line(&c).contains(" · 8 threads (auto) · "));
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
}
