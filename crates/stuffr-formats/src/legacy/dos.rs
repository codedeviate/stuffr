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

/// The inverse of [`mtime`]: the six calendar fields for a `SystemTime`,
/// in UTC.
///
/// Added in Phase 3c Task 6, when LHA gained an encoder and became the first
/// legacy format in this tree that has to WRITE a DOS timestamp rather than
/// only read one. The bit layout still stays with the caller, for exactly the
/// reason the module doc gives — this hands back the six numbers, and
/// `lha.rs` packs them into LHA's own `YYYYYYYM MMMDDDDD hhhhhmmm mmmsssss`
/// word.
///
/// `None` for an instant before the epoch, which is the same boundary
/// [`mtime`] refuses in the other direction.
#[allow(dead_code)]
pub(crate) fn civil_fields(t: SystemTime) -> Option<(i64, u32, u32, u32, u32, u32)> {
    let secs = t.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let days = i64::try_from(secs / 86_400).ok()?;
    let rem = u32::try_from(secs % 86_400).ok()?;
    let (y, m, d) = civil_from_days(days);
    Some((y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60))
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

/// `(year, month, day)` for a day count since the Unix epoch — the exact
/// inverse of [`days_from_civil`], from the same public-domain source. Kept
/// beside it deliberately: an era-arithmetic mistake in one is only visible
/// against the other, which is what
/// `every_day_of_a_leap_cycle_round_trips_through_both_directions` checks.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
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

    /// The two directions have to agree at every date, not merely at the
    /// three fixed points above: LHA's encoder turns a `SystemTime` into
    /// calendar fields with [`civil_fields`] and its reader turns them back
    /// with [`mtime`], so a disagreement anywhere shows up as an archive
    /// whose stored date is not the one that was packed. A full 400-year
    /// Gregorian cycle is swept, which is the period after which the
    /// leap-year pattern repeats — an era-boundary error therefore cannot
    /// hide between two sampled points.
    #[test]
    fn every_day_of_a_leap_cycle_round_trips_through_both_directions() {
        // 1970-01-01 through 2369-12-31: one whole 400-year cycle.
        for day in 0..146_097i64 {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(
                days_from_civil(y, m, d),
                day,
                "day {day} -> {y:04}-{m:02}-{d:02} -> and back"
            );
        }
    }

    /// The seconds-of-day half of the same claim, through the public pair.
    #[test]
    fn civil_fields_is_the_inverse_of_mtime() {
        for secs in [
            0u64,
            1,
            59,
            60,
            3600,
            86_399,
            86_400,
            501_292_912,
            1_700_000_000,
        ] {
            let t = UNIX_EPOCH + Duration::from_secs(secs);
            let (y, mo, d, h, mi, s) = civil_fields(t).expect("after the epoch");
            assert_eq!(
                mtime(y, mo, d, h, mi, s),
                Some(t),
                "{secs} -> {y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}"
            );
        }
    }

    #[test]
    fn an_instant_before_the_epoch_has_no_civil_fields() {
        assert!(civil_fields(UNIX_EPOCH - Duration::from_secs(1)).is_none());
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
