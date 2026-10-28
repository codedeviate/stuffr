//! Pure formatting helpers for `stuffr ls`: size, date, RFC 3339, format text.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// Seconds between a recent file's mtime and `now` beyond which `ls -l` shows
/// the year instead of the time: 6 x 30.436875 days (BSD `ls` uses half of
/// 365.2425 days).
const RECENT_SECS: i64 = 15_778_476;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Size as macOS `ls -lh` prints it, on every platform.
///
/// Rule (derived from measured `ls -lh` output, i.e. `humanize_number`):
/// below 1000 bytes, `NB`. Otherwise scale by successive integer division by
/// 1024, keeping only the LAST remainder `r` (so 1101005 bytes is `1.0M`,
/// not `1.1M`: 1101005 / 1024 = 1075, and 1075 / 1024 = 1 rem 51). Pick the
/// smallest unit K, M, G, T, P, E whose quotient, rounded half-up on `r`
/// (`q + (r >= 512)`), is below 1000 (capped at E). Show one decimal
/// (`q*10 + round(r*10/1024)` tenths) when that is below 10.0, else the
/// rounded integer. So 1000..=1023 is `1.0K` and 1023488 (999.5 K) is `1.0M`.
pub fn human_size(bytes: u64) -> String {
    if bytes < 1000 {
        return format!("{bytes}B");
    }
    for (unit, suffix) in ['K', 'M', 'G', 'T', 'P', 'E'].into_iter().enumerate() {
        let shift = 10 * (unit as u32 + 1);
        let q = bytes >> shift;
        let r = (bytes >> (shift - 10)) % 1024;
        let whole = q + u64::from(r >= 512);
        if whole < 1000 || suffix == 'E' {
            let tenths = q * 10 + (r * 10 + 512) / 1024;
            return if tenths < 100 {
                format!("{}.{}{suffix}", tenths / 10, tenths % 10)
            } else {
                format!("{whole}{suffix}")
            };
        }
    }
    unreachable!("the E step always returns")
}

/// Whole seconds since the epoch, negative before 1970 (floored).
fn epoch_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => {
            let d = e.duration();
            let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            if d.subsec_nanos() > 0 {
                -secs - 1
            } else {
                -secs
            }
        }
    }
}

/// (year, month 1-12, day 1-31) of a day count since 1970-01-01
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// `ls -l` date for `mtime` shown at `offset_secs` from UTC: `Mon %e HH:MM`
/// when `now - 15_778_476 s <= mtime <= now`, else `Mon %e  YYYY`.
pub fn ls_date_with_offset(mtime: SystemTime, now: SystemTime, offset_secs: i64) -> String {
    let m = epoch_secs(mtime);
    let n = epoch_secs(now);
    let local = m.saturating_add(offset_secs);
    let (y, mon, d) = civil_from_days(local.div_euclid(86_400));
    let month = MONTHS[(mon - 1) as usize];
    if m <= n && m >= n.saturating_sub(RECENT_SECS) {
        let rem = local.rem_euclid(86_400);
        format!("{month} {d:>2} {:02}:{:02}", rem / 3600, rem % 3600 / 60)
    } else {
        format!("{month} {d:>2}  {y}")
    }
}

/// UTC offset in seconds of the local zone at the instant `mtime`.
#[cfg(unix)]
fn local_offset(t: SystemTime) -> i64 {
    // `time_t` is i64 on 64-bit unix; on 32-bit it is the platform range.
    let tt = epoch_secs(t) as libc::time_t;
    // SAFETY: `tm` is plain data, fully written by `localtime_r` on success;
    // both pointers are valid for the call.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&tt, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff as i64
    }
}

/// Non-unix: no portable local-zone lookup without a new dependency, so
/// dates are shown in UTC.
#[cfg(not(unix))]
fn local_offset(_t: SystemTime) -> i64 {
    0
}

/// [`ls_date_with_offset`] in the local time zone (UTC on non-unix).
pub fn ls_date(mtime: SystemTime, now: SystemTime) -> String {
    ls_date_with_offset(mtime, now, local_offset(mtime))
}

/// `YYYY-MM-DDTHH:MM:SSZ`, seconds precision, UTC.
pub fn rfc3339_utc(t: SystemTime) -> String {
    let s = epoch_secs(t);
    let (y, mo, d) = civil_from_days(s.div_euclid(86_400));
    let rem = s.rem_euclid(86_400);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// `info`'s chain text with `" over "` shortened to `"+"`: `tar+gzip`.
pub fn compact_format(chain: &stuffr::probe::Chain) -> String {
    chain.describe().replace(" over ", "+")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: i64) -> SystemTime {
        if secs >= 0 {
            UNIX_EPOCH + Duration::from_secs(secs as u64)
        } else {
            UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
        }
    }

    #[test]
    fn human_size_matches_ls_h() {
        // measured 2026-10-28, macOS ls -lh
        let table: &[(u64, &str)] = &[
            (0, "0B"),
            (1, "1B"),
            (9, "9B"),
            (999, "999B"),
            (1000, "1.0K"),
            (1023, "1.0K"),
            (1024, "1.0K"),
            (1025, "1.0K"),
            (1075, "1.0K"),
            (1126, "1.1K"),
            (1127, "1.1K"),
            (1228, "1.2K"),
            (1229, "1.2K"),
            (5631, "5.5K"),
            (5632, "5.5K"),
            (5683, "5.5K"),
            (5684, "5.6K"),
            (9420, "9.2K"),
            (9421, "9.2K"),
            (9728, "9.5K"),
            (9932, "9.7K"),
            (9933, "9.7K"),
            (10188, "9.9K"),
            (10189, "10K"),
            (10239, "10K"),
            (10240, "10K"),
            (10241, "10K"),
            (10291, "10K"),
            (10548, "10K"),
            (101887, "99K"),
            (101888, "100K"),
            (102297, "100K"),
            (102400, "100K"),
            (102452, "100K"),
            (831488, "812K"),
            (999999, "977K"),
            (1000000, "977K"),
            (1023487, "999K"),
            (1023488, "1.0M"),
            (1023999, "1.0M"),
            (1048575, "1.0M"),
            (1048576, "1.0M"),
            (1101005, "1.0M"),
            (1153434, "1.1M"),
            (4351590, "4.1M"),
            (4404019, "4.2M"),
            (10485759, "10M"),
            (10485760, "10M"),
            (11010047, "10M"),
            (11010048, "11M"),
            (18874368, "18M"),
            (104333312, "100M"),
            (104333313, "100M"),
            (1072955391, "1.0G"),
            (1073741823, "1.0G"),
            (1073741824, "1.0G"),
            (10737418239, "10G"),
            (11811160064, "11G"),
            (1099511627776, "1.0T"),
            (1125899906842624, "1.0P"),
        ];
        for &(n, want) in table {
            assert_eq!(human_size(n), want, "{n}");
        }
        // Beyond P: capped at E, never panics.
        assert_eq!(human_size(u64::MAX), "16E");
    }

    #[test]
    fn ls_date_recent_and_old() {
        // 2026-10-28T12:00Z = 1793188800
        let now = at(1793188800);
        // 2026-10-27T14:03Z
        assert_eq!(ls_date_with_offset(at(1793109780), now, 0), "Oct 27 14:03");
        // 2026-03-03T08:00Z
        assert_eq!(ls_date_with_offset(at(1772524800), now, 0), "Mar  3  2026");
        // future 2026-11-01T00:00Z
        assert_eq!(ls_date_with_offset(at(1793491200), now, 0), "Nov  1  2026");
        // A fixed offset moves the clock reading.
        assert_eq!(
            ls_date_with_offset(at(1793109780), now, 3600),
            "Oct 27 15:03"
        );
        // Boundary: exactly 15_778_476 s old is recent, one more is not.
        assert_eq!(
            ls_date_with_offset(at(1793188800 - 15_778_476), now, 0),
            "Apr 28 21:05"
        );
        assert_eq!(
            ls_date_with_offset(at(1793188800 - 15_778_477), now, 0),
            "Apr 28  2026"
        );
        // Before 1970 does not panic.
        assert_eq!(ls_date_with_offset(at(-86400), now, 0), "Dec 31  1969");
        let _ = ls_date(at(1793109780), now);
    }

    #[test]
    fn rfc3339_utc_is_seconds_z() {
        // python3: datetime.fromtimestamp(1793102580, UTC) -> 2026-10-27 12:03:00
        // (the brief's 13:23:00 was a miscalculation).
        assert_eq!(rfc3339_utc(at(1793102580)), "2026-10-27T12:03:00Z");
        assert_eq!(rfc3339_utc(at(0)), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(at(-1)), "1969-12-31T23:59:59Z");
        assert_eq!(rfc3339_utc(at(951782400)), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn compact_format_joins_with_plus() {
        use stuffr::format::FormatId;
        use stuffr::probe::Chain;
        let tar_gz = Chain::Codec {
            codec: FormatId::new("gzip"),
            inner: Box::new(Chain::Container {
                container: FormatId::new("tar"),
            }),
        };
        assert_eq!(compact_format(&tar_gz), "tar+gzip");
        let zip = Chain::Container {
            container: FormatId::new("zip"),
        };
        assert_eq!(compact_format(&zip), "zip");
        let bare = Chain::Codec {
            codec: FormatId::new("gzip"),
            inner: Box::new(Chain::Raw),
        };
        assert_eq!(compact_format(&bare), "gzip");
    }
}
