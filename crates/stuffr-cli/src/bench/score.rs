//! Scoring and winners for `stuffr bench`. Pure: no I/O, no timing.
//!
//! Each metric (`bytes_out`, `compress_ns`, `decompress_ns`) is scored
//! `best / value` over the rows that succeeded, a value of 0 counting as 1.
//! `balance` is the mean of the three scores. Failed rows score `None` and
//! never win. Ties go to the smaller `bytes_out`, then to the earlier row.

/// What one successful format/level run produced.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Measured {
    pub bytes_out: u64,
    pub compress_ns: u64,
    pub decompress_ns: u64,
}

/// The result of one row: measured, or failed with a reason.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    Ok(Measured),
    Failed(String),
}

/// One line of the table. `level` is `None` for codecs without levels
/// (lz4, snappy).
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub format: &'static str,
    pub level: Option<i32>,
    pub outcome: Outcome,
}

/// Indices into the rows slice, one per column; `None` when no row succeeded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Winners {
    pub smallest: Option<usize>,
    pub fastest_compress: Option<usize>,
    pub fastest_decompress: Option<usize>,
    pub balance: Option<usize>,
}

fn measured(row: &Row) -> Option<&Measured> {
    match &row.outcome {
        Outcome::Ok(m) => Some(m),
        Outcome::Failed(_) => None,
    }
}

/// `best / value`, a zero counting as 1 on both sides.
fn ratio(best: u64, value: u64) -> f64 {
    best.max(1) as f64 / value.max(1) as f64
}

/// The balance score of every row: the mean of the three per-metric scores,
/// `None` for a failed row.
pub fn balance_scores(rows: &[Row]) -> Vec<Option<f64>> {
    let best = |f: fn(&Measured) -> u64| rows.iter().filter_map(measured).map(f).min();
    let (Some(b_out), Some(b_c), Some(b_d)) = (
        best(|m| m.bytes_out),
        best(|m| m.compress_ns),
        best(|m| m.decompress_ns),
    ) else {
        return vec![None; rows.len()];
    };
    rows.iter()
        .map(|row| {
            measured(row).map(|m| {
                (ratio(b_out, m.bytes_out)
                    + ratio(b_c, m.compress_ns)
                    + ratio(b_d, m.decompress_ns))
                    / 3.0
            })
        })
        .collect()
}

/// The winner of each column. Ties go to the smaller `bytes_out`, then to
/// the earlier row.
pub fn winners(rows: &[Row]) -> Winners {
    let scores = balance_scores(rows);
    let by_min = |key: fn(&Measured) -> u64| {
        rows.iter()
            .enumerate()
            .filter_map(|(i, r)| measured(r).map(|m| (i, m)))
            .min_by_key(|(i, m)| (key(m), m.bytes_out, *i))
            .map(|(i, _)| i)
    };
    let balance = rows
        .iter()
        .enumerate()
        .filter_map(|(i, r)| Some((i, measured(r)?, scores[i]?)))
        .reduce(|best, cand| {
            // Replace only on a strictly higher score, or an equal score
            // with strictly smaller output; otherwise the earlier row stays.
            if cand.2 > best.2 || (cand.2 == best.2 && cand.1.bytes_out < best.1.bytes_out) {
                cand
            } else {
                best
            }
        })
        .map(|(i, _, _)| i);
    Winners {
        smallest: by_min(|m| m.bytes_out),
        fastest_compress: by_min(|m| m.compress_ns),
        fastest_decompress: by_min(|m| m.decompress_ns),
        balance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(bytes_out: u64, compress_ns: u64, decompress_ns: u64) -> Row {
        Row {
            format: "x",
            level: Some(1),
            outcome: Outcome::Ok(Measured {
                bytes_out,
                compress_ns,
                decompress_ns,
            }),
        }
    }

    fn failed() -> Row {
        Row {
            format: "x",
            level: None,
            outcome: Outcome::Failed("boom".into()),
        }
    }

    fn abc() -> Vec<Row> {
        vec![ok(100, 10, 10), ok(50, 20, 20), ok(200, 5, 40)]
    }

    fn close(got: Option<f64>, want: f64) {
        let got = got.expect("a score");
        assert!((got - want).abs() < 1e-9, "{got} vs {want}");
    }

    #[test]
    fn balance_weights_the_three_metrics_equally() {
        let rows = abc();
        let s = balance_scores(&rows);
        close(s[0], (0.5 + 0.5 + 1.0) / 3.0);
        close(s[1], (1.0 + 0.25 + 0.5) / 3.0);
        close(s[2], (0.25 + 1.0 + 0.25) / 3.0);
        assert_eq!(winners(&rows).balance, Some(0));
    }

    #[test]
    fn winners_name_each_column() {
        let w = winners(&abc());
        assert_eq!(w.smallest, Some(1));
        assert_eq!(w.fastest_compress, Some(2));
        assert_eq!(w.fastest_decompress, Some(0));
    }

    #[test]
    fn failed_rows_never_score_or_win() {
        let mut rows = abc();
        rows.insert(0, failed());
        assert_eq!(balance_scores(&rows)[0], None);
        let w = winners(&rows);
        for idx in [
            w.smallest,
            w.fastest_compress,
            w.fastest_decompress,
            w.balance,
        ] {
            assert!(idx.expect("a winner") > 0);
        }
    }

    #[test]
    fn ties_go_to_the_smaller_output() {
        let rows = vec![ok(100, 10, 10), ok(60, 10, 10)];
        assert_eq!(winners(&rows).fastest_compress, Some(1));
        assert_eq!(winners(&rows).fastest_decompress, Some(1));
        assert_eq!(winners(&rows).balance, Some(1));
    }

    #[test]
    fn ties_on_everything_go_to_the_earlier_row() {
        let rows = vec![ok(7, 7, 7), ok(7, 7, 7)];
        let w = winners(&rows);
        assert_eq!(w.smallest, Some(0));
        assert_eq!(w.balance, Some(0));
    }

    #[test]
    fn all_failed_gives_no_winners() {
        let rows = vec![failed(), failed()];
        assert_eq!(winners(&rows), Winners::default());
        assert_eq!(balance_scores(&rows), vec![None, None]);
        assert_eq!(winners(&[]), Winners::default());
    }

    #[test]
    fn zero_values_do_not_divide_by_zero() {
        let rows = vec![ok(10, 10, 10), ok(0, 0, 0)];
        for s in balance_scores(&rows) {
            assert!(s.expect("a score").is_finite());
        }
        let w = winners(&rows);
        assert_eq!(w.smallest, Some(1));
        assert_eq!(w.fastest_compress, Some(1));
        assert_eq!(w.fastest_decompress, Some(1));
        assert_eq!(w.balance, Some(1));
    }
}
