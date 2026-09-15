//! MS-DOS packed timestamps, shared by the legacy containers.
//!
//! ARJ and ARC both store a modification time as DOS's packed date/time
//! fields, and turning one into a `SystemTime` needs a proleptic-Gregorian
//! day count that nothing in this workspace otherwise provides —
//! `stuffr-core` takes no date/calendar dependency, and this is the only
//! corner of `stuffr-formats` that needs one. It lived inside `arj.rs`
//! until ARC arrived in Phase 3c and needed the identical routine; a second
//! copy of a calendar algorithm is exactly the shape that drifts.
//!
//! The FIELD layout is deliberately NOT here: ARJ and ARC pack the two
//! halves into their `u32` in opposite orders, and hiding that behind a
//! shared "parse a DOS timestamp" helper would bury the one detail each
//! caller actually has to get right. Each container unpacks its own fields
//! and hands the six calendar numbers over.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Builds a `SystemTime` from the six calendar fields a DOS timestamp
/// carries, or `None` when they do not describe a date at all.
///
/// A packed value of zero — the shape a minimal or hand-built entry uses to
/// say "no timestamp" — has month and day zero and lands here as `None`,
/// which is how both containers report an absent mtime.
pub(crate) fn mtime(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<SystemTime> {
    if month == 0 || month > 12 || day == 0 || day > 31 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;
    u64::try_from(secs)
        .ok()
        .map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

/// Days since the Unix epoch (1970-01-01) for a proleptic-Gregorian
/// `(year, month, day)` — Howard Hinnant's `days_from_civil` algorithm
/// (public domain; <http://howardhinnant.github.io/date_algorithms.html>).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (i64::from(m) + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two fixed points with externally known answers: the epoch itself,
    /// and a date whose day count can be checked against `date -u`. An
    /// off-by-one in the era arithmetic would move both.
    #[test]
    fn days_from_civil_matches_known_points() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1980, 1, 1), 3652); // 10 years, two of them leap
        // `date -u -j -f '%Y-%m-%d %H:%M:%S' '1985-11-20 00:00:00' +%s`
        // -> 501292800
        assert_eq!(days_from_civil(1985, 11, 20) * 86_400, 501_292_800);
    }

    #[test]
    fn an_impossible_month_or_day_has_no_time() {
        assert!(mtime(1980, 0, 19, 0, 0, 0).is_none());
        assert!(mtime(1980, 13, 1, 0, 0, 0).is_none());
        assert!(mtime(1980, 1, 0, 0, 0, 0).is_none());
        assert!(mtime(1980, 1, 32, 0, 0, 0).is_none());
    }

    #[test]
    fn a_date_before_the_epoch_has_no_time() {
        // `SystemTime` here is built from a `u64` second count past the
        // epoch, so a 1969 stamp has nowhere to go and reports absent
        // rather than wrapping to some far-future instant.
        assert!(mtime(1969, 12, 31, 0, 0, 0).is_none());
    }

    #[test]
    fn a_real_stamp_round_trips_to_its_unix_second() {
        let t = mtime(1985, 11, 20, 0, 1, 52).expect("a valid date");
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            501_292_800 + 112
        );
    }
}
