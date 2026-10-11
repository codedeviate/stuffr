//! `-l` and `-lv`: GNU gzip 1.15's listing, established by running the
//! binary (`gzip -l`, `-lv`, `-lq` over single, several, multi-member,
//! failing and non-gzip inputs). GNU's source is never read.
//!
//! - **Columns:** compressed and uncompressed sizes right-aligned in 19,
//!   the ratio as `-v` prints it, then the name (quoted as diagnostics are).
//!   `-v` adds the last member's method (`defla`, `store`, `compr`, `pack `),
//!   its CRC (`%08x` when it was gzip, else `-1` as a 64-bit hex number)
//!   and the date (`Mon dd HH:MM`, local time, never the year).
//! - **Sizes:** the input decoded in full (GNU 1.12 onwards), so the
//!   uncompressed column is the true length; the compressed one is the
//!   file's size (bytes read, for standard input).
//! - **The ratio** subtracts the header and trailer only when the input
//!   was exactly one gzip member ([`decode::Done::header_bytes`]); the
//!   totals line subtracts the *last* listed input's.
//! - **The header line** is printed before the first listed input (never
//!   under `-q`). An input that decoded but not cleanly (a CRC or length
//!   error, or anything after its last member, zero bytes included) is not
//!   listed and prints a totals line instead, once anything was listed
//!   (under `-q` just its ratio and name), and its header bytes are the
//!   ones the totals then subtract. After the last operand the totals are
//!   printed when there were several operands, not under `-q`; a run that
//!   stops early prints none.
//!
//! [`decode::Done::header_bytes`]: super::decode::Done

use std::io::Write;

use super::decode::Method;
use super::messages::{self as m, ratio};

/// One input's line.
pub(super) struct Entry<'a> {
    pub(super) method: Method,
    pub(super) crc: Option<u32>,
    /// Seconds since the epoch, for `-v`'s date.
    pub(super) time: i64,
    pub(super) compressed: u64,
    pub(super) uncompressed: u64,
    pub(super) header_bytes: u64,
    /// Already quoted.
    pub(super) name: &'a [u8],
}

/// The listing's running state.
#[derive(Default)]
pub(super) struct Lister {
    header_out: bool,
    compressed: u64,
    uncompressed: u64,
    last_header_bytes: u64,
}

fn method_name(m: Method) -> &'static str {
    match m {
        Method::Deflate | Method::Copy => m::METHOD_DEFLATE,
        Method::Stored => m::METHOD_STORED,
        Method::Compress => m::METHOD_COMPRESS,
        Method::Pack => m::METHOD_PACK,
    }
}

/// The ratio as `-l` prints it: `-v`'s, of the uncompressed size against
/// the compressed size less `header_bytes`.
fn list_ratio(uncompressed: u64, compressed: u64, header_bytes: u64) -> String {
    ratio(uncompressed, compressed.saturating_sub(header_bytes))
}

impl Lister {
    /// List one input.
    pub(super) fn line(&mut self, out: &mut dyn Write, verbose: bool, quiet: bool, e: &Entry) {
        self.header(out, verbose, quiet);
        let mut line = Vec::new();
        if verbose {
            let crc = e
                .crc
                .map_or_else(|| m::NO_CRC.to_owned(), |c| format!("{c:08x}"));
            line.extend_from_slice(
                format!("{} {crc} {} ", method_name(e.method), date(e.time)).as_bytes(),
            );
        }
        line.extend_from_slice(
            format!(
                "{:>19} {:>19} {} ",
                e.compressed,
                e.uncompressed,
                list_ratio(e.uncompressed, e.compressed, e.header_bytes)
            )
            .as_bytes(),
        );
        line.extend_from_slice(e.name);
        line.push(b'\n');
        let _ = out.write_all(&line);
        self.compressed += e.compressed;
        self.uncompressed += e.uncompressed;
        self.last_header_bytes = e.header_bytes;
    }

    /// An input that decoded but not cleanly: the totals so far, except
    /// for standard input, which prints nothing (observed: `gzip -l a.gz -
    /// b.gz` with a CRC error or trailing data on standard input lists `a`,
    /// `b` and the totals, once). The failed input's `header_bytes` become
    /// the ones the totals subtract, as a listed one's do.
    pub(super) fn failed(
        &mut self,
        out: &mut dyn Write,
        verbose: bool,
        quiet: bool,
        stdin: bool,
        header_bytes: u64,
    ) {
        if !stdin {
            self.last_header_bytes = header_bytes;
            self.totals(out, verbose, quiet);
        }
    }

    /// After the last operand of a run that was not stopped: the totals,
    /// when there were several operands and not under `-q`.
    pub(super) fn finish(
        &mut self,
        out: &mut dyn Write,
        verbose: bool,
        quiet: bool,
        operands: usize,
    ) {
        if operands > 1 && !quiet {
            self.totals(out, verbose, quiet);
        }
    }

    fn header(&mut self, out: &mut dyn Write, verbose: bool, quiet: bool) {
        if self.header_out || quiet {
            return;
        }
        self.header_out = true;
        let h = if verbose {
            m::LIST_HEADER_VERBOSE
        } else {
            m::LIST_HEADER
        };
        let _ = out.write_all(h.as_bytes());
    }

    /// The totals line, once anything was listed. Under `-q` only its
    /// ratio and name (observed: `gzip -lq a.gz crc.gz` prints `a`'s line,
    /// then ` 99.5% (totals)`).
    fn totals(&mut self, out: &mut dyn Write, verbose: bool, quiet: bool) {
        if self.compressed == 0 {
            return;
        }
        let mut line = Vec::new();
        if verbose {
            // Blank method, CRC and date columns.
            line.extend_from_slice(&[b' '; 28]);
        }
        if !quiet {
            line.extend_from_slice(
                format!("{:>19} {:>19} ", self.compressed, self.uncompressed).as_bytes(),
            );
        }
        line.extend_from_slice(
            list_ratio(self.uncompressed, self.compressed, self.last_header_bytes).as_bytes(),
        );
        line.push(b' ');
        line.extend_from_slice(m::LIST_TOTALS);
        line.push(b'\n');
        let _ = out.write_all(&line);
    }
}

/// `-lv`'s date: `Mon dd HH:MM` in local time.
fn date(t: i64) -> String {
    let (month, day, hour, minute) = local(t);
    format!("{} {day:2} {hour:02}:{minute:02}", m::MONTHS[month.min(11)])
}

/// Month (0-11), day of month, hour and minute of `t` in local time.
#[cfg(unix)]
fn local(t: i64) -> (usize, u32, u32, u32) {
    let tt = t as libc::time_t;
    // SAFETY: `tm` is plain data that `localtime_r` fills in; both
    // pointers are valid for the call.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&tt, &mut tm).is_null() {
            return utc(t);
        }
        tm
    };
    (
        usize::try_from(tm.tm_mon).unwrap_or(0),
        u32::try_from(tm.tm_mday).unwrap_or(0),
        u32::try_from(tm.tm_hour).unwrap_or(0),
        u32::try_from(tm.tm_min).unwrap_or(0),
    )
}

#[cfg(not(unix))]
fn local(t: i64) -> (usize, u32, u32, u32) {
    utc(t)
}

/// Month (0-11), day, hour and minute of `t` in UTC (the civil-from-days
/// algorithm).
fn utc(t: i64) -> (usize, u32, u32, u32) {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 2 } else { mp - 10 } as usize;
    (month, day, (secs / 3600) as u32, (secs % 3600 / 60) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0), (0, 1, 0, 0));
        assert_eq!(utc(1_234_567_890), (1, 13, 23, 31));
        assert_eq!(utc(1_500_000_000), (6, 14, 2, 40));
        assert_eq!(utc(-1), (11, 31, 23, 59));
    }

    /// `n` spaces: the expected lines below are written with it, so no
    /// literal carries a run of spaces (the workspace lint's rule).
    fn sp(n: usize) -> String {
        " ".repeat(n)
    }

    /// The layouts the binary printed for `gzip -l good.gz rand.gz` and
    /// `-lv` (the differential suite compares them byte for byte too).
    #[test]
    fn lines_and_totals_have_gnus_layout() {
        let e = |name: &'static [u8], c, u| Entry {
            method: Method::Deflate,
            crc: Some(0x0a19_3db3),
            time: 0,
            compressed: c,
            uncompressed: u,
            header_bytes: 0,
            name,
        };
        let mut l = Lister::default();
        let mut out = Vec::new();
        l.line(&mut out, false, false, &e(b"good", 206, 60000));
        l.line(&mut out, false, false, &e(b"rand", 100_053, 100_000));
        l.finish(&mut out, false, false, 2);
        let want = [
            m::LIST_HEADER.to_owned(),
            format!("{}206{}60000  99.7% good\n", sp(16), sp(15)),
            format!("{}100053{}100000  -0.1% rand\n", sp(13), sp(14)),
            format!("{}100259{}160000  37.3% (totals)\n", sp(13), sp(14)),
        ]
        .concat();
        assert_eq!(String::from_utf8(out).unwrap(), want);
        let mut l = Lister::default();
        let mut out = Vec::new();
        l.line(&mut out, true, false, &e(b"good", 206, 60000));
        l.failed(&mut out, true, false, false, 0);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[1].starts_with("defla 0a193db3 "), "{text}");
        let sizes = format!("{}206{}60000  99.7% ", sp(16), sp(15));
        assert!(lines[1].ends_with(&format!(" {sizes}good")), "{text}");
        assert_eq!(lines[2], format!("{}{sizes}(totals)", sp(28)));
        // Quiet: no header and no final totals; a failure's totals are
        // the ratio and name only.
        let mut l = Lister::default();
        let mut out = Vec::new();
        l.line(&mut out, false, true, &e(b"good", 206, 60000));
        l.finish(&mut out, false, true, 2);
        l.failed(&mut out, false, true, false, 0);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{sizes}good\n 99.7% (totals)\n")
        );
    }
}
