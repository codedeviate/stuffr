//! fileio_common.h's display layer: `DISPLAYLEVEL`, `EXM_THROW`'s format
//! and the progress line's refresh gate (`DISPLAYUPDATE`, `REFRESH_RATE`,
//! `g_displayClock`), plus the two progress lines themselves as pure
//! functions of their counters so unit tests can pin their bytes from a
//! fixed clock (ruling R4; fixtures in `tests/fixtures/zstd_progress/`).

use std::io::Write;

use super::messages::{self as m, printf};
use super::util::{FILESIZE_UNKNOWN, human_size};

/// `REFRESH_RATE`: `SEC_TO_MICRO / 6`, in microseconds.
const REFRESH_RATE_MICROS: u64 = 1_000_000 / 6;

/// `g_display_prefs` and `g_displayClock`: the notification level (0:
/// nothing, 1: errors, 2: results, interaction and warnings, 3: progress,
/// 4: information) and when the progress line last refreshed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Display {
    /// `displayLevel`.
    pub level: i32,
    /// `g_displayClock`, in the caller's milliseconds; `None` before the
    /// first update (zstd's clock starts at zero, far in the past).
    last_ms: Option<u64>,
}

impl Display {
    pub(crate) fn new(level: i32) -> Self {
        Display {
            level,
            last_ms: None,
        }
    }

    /// `DISPLAYLEVEL(l, fmt, args)`: `fmt` (a messages.rs format) on
    /// standard error when the level is at least `l`.
    pub(crate) fn at(&self, l: i32, err: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
        if self.level >= l {
            printf(err, fmt, args);
        }
    }

    /// `READY_FOR_UPDATE()` at `now_ms`: more than `REFRESH_RATE` since the
    /// last update, or display level 4.
    pub(crate) fn ready_for_update(&self, now_ms: u64) -> bool {
        self.level >= 4
            || self
                .last_ms
                .is_none_or(|t| now_ms.saturating_sub(t).saturating_mul(1000) > REFRESH_RATE_MICROS)
    }

    /// `DELAY_NEXT_UPDATE()`.
    pub(crate) fn delay_next_update(&mut self, now_ms: u64) {
        self.last_ms = Some(now_ms);
    }

    /// `DISPLAYUPDATE(1, ...)`: when the level is at least 1 and the
    /// refresh rate allows, restart the clock, let `render` write the
    /// line to `err` and, from level 4, flush. (The progress-setting test,
    /// `progressSetting != FIO_ps_never`, is the caller's: it lives in the
    /// preferences, not here; and `err` is a parameter because a `Display`
    /// owns no stream.)
    pub(crate) fn update(
        &mut self,
        now_ms: u64,
        err: &mut dyn Write,
        render: impl FnOnce(&mut dyn Write),
    ) {
        if self.level >= 1 && self.ready_for_update(now_ms) {
            self.delay_next_update(now_ms);
            render(err);
            if self.level >= 4 {
                let _ = err.flush();
            }
        }
    }
}

/// `FIO_compressZstdFrame`'s progress notification: the counters of
/// `ZSTD_getFrameProgression` and what the line names.
pub(crate) struct CompressProgress<'a> {
    /// `g_display_prefs.displayLevel` (3 and up: the verbose form).
    pub display_level: i32,
    /// `g_utilDisplayLevel`.
    pub util_level: i32,
    /// `fCtx->nbFilesTotal`.
    pub nb_files_total: usize,
    /// `fCtx->currFileIdx` (zero based).
    pub curr_file_idx: usize,
    pub src_name: &'a [u8],
    /// `fileSize`, `FILESIZE_UNKNOWN` when not known.
    pub file_size: u64,
    pub level: i32,
    pub ingested: u64,
    pub consumed: u64,
    pub produced: u64,
}

/// The bytes of one compression progress refresh: the clearing
/// `"\r%79s\r"` and then the verbose or the summarised line.
pub(crate) fn compress_progress_line(p: &CompressProgress) -> Vec<u8> {
    let hrs = |n: u64| human_size(n, p.util_level);
    let c_share = p.produced as f64 / (p.consumed + u64::from(p.consumed == 0)) as f64 * 100.0;
    let (buffered, consumed, produced) = (
        hrs(p.ingested - p.consumed),
        hrs(p.consumed),
        hrs(p.produced),
    );
    let mut v = Vec::new();
    printf(&mut v, m::CLEAR_LINE, &[" ".repeat(79).as_bytes()]);
    if p.display_level >= 3 {
        let w5 = |h: &super::util::Hrs| format!("{}{}", h.value_w(5), h.suffix);
        let (l, b, c, o, s) = (
            p.level.to_string(),
            w5(&buffered),
            w5(&consumed),
            w5(&produced),
            format!("{c_share:.2}"),
        );
        printf(
            &mut v,
            m::PROGRESS_VERBOSE,
            &[
                l.as_bytes(),
                b.as_bytes(),
                c.as_bytes(),
                o.as_bytes(),
                s.as_bytes(),
            ],
        );
        return v;
    }
    if p.nb_files_total > 1 {
        let (i, t) = (
            (p.curr_file_idx + 1).to_string(),
            p.nb_files_total.to_string(),
        );
        if p.src_name.len() > 18 {
            let tail = &p.src_name[p.src_name.len() - 15..];
            printf(
                &mut v,
                m::PROGRESS_FILES_LONG,
                &[i.as_bytes(), t.as_bytes(), tail],
            );
        } else {
            // `%*s` with width `18 - len`: the name right-aligned in a
            // field that is wider than it only for a name under 9 bytes.
            let w = 18 - p.src_name.len();
            let mut padded = vec![b' '; w.saturating_sub(p.src_name.len())];
            padded.extend_from_slice(p.src_name);
            printf(
                &mut v,
                m::PROGRESS_FILES,
                &[i.as_bytes(), t.as_bytes(), &padded],
            );
        }
    }
    let r = format!("{}{:>4}", consumed.value_w(6), consumed.suffix);
    printf(&mut v, m::PROGRESS_READ, &[r.as_bytes()]);
    if p.file_size != FILESIZE_UNKNOWN {
        let f = hrs(p.file_size);
        let f = format!("{}{:>4}", f.value_w(6), f.suffix);
        printf(&mut v, m::PROGRESS_OF, &[f.as_bytes()]);
    }
    let s = format!("{c_share:2.0}");
    printf(&mut v, m::PROGRESS_RATIO, &[s.as_bytes()]);
    v
}

/// The bytes of one decompression progress refresh
/// (`FIO_decompressZstdFrame`): `bytes` is what the frame has produced
/// so far, `src` the file name as given.
pub(crate) fn decompress_progress_line(
    display_level: i32,
    util_level: i32,
    nb_files_total: usize,
    curr_file_idx: usize,
    src: &[u8],
    bytes: u64,
) -> Vec<u8> {
    // The last 20 characters only when not `--verbose`.
    let src20 = if src.len() > 20 && display_level < 3 {
        &src[src.len() - 20..]
    } else {
        src
    };
    let h = human_size(bytes, util_level).plain();
    let mut v = Vec::new();
    if nb_files_total > 1 {
        let (i, t) = (
            format!("{:2}", curr_file_idx + 1),
            format!("{nb_files_total:2}"),
        );
        printf(
            &mut v,
            m::PROGRESS_DECOMPRESS_FILES,
            &[i.as_bytes(), t.as_bytes(), src20, h.as_bytes()],
        );
    } else {
        // `%-20.20s`.
        let mut name = src20.to_vec();
        name.truncate(20);
        while name.len() < 20 {
            name.push(b' ');
        }
        printf(&mut v, m::PROGRESS_DECOMPRESS, &[&name, h.as_bytes()]);
    }
    v
}

/// fileio_common.h: `EXM_THROW(code, msg)`: `zstd: error <code> : <msg> \n`
/// at display level 1, returning `code` for the caller to exit with. `msg`
/// is the formatted message. The level-5 "Error defined at <file>, line
/// <n>" line names zstd's own source position, which a port has no
/// equivalent of; it is not printed.
pub(crate) fn exm_throw(d: &Display, err: &mut dyn Write, code: i32, msg: &[u8]) -> i32 {
    d.at(1, err, m::EXM_PREFIX, &[]);
    d.at(1, err, m::EXM_ERROR, &[code.to_string().as_bytes()]);
    if d.level >= 1 {
        let _ = err.write_all(msg);
    }
    d.at(1, err, m::EXM_END, &[]);
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `tests/fixtures/zstd_progress/table.txt`: zstd 1.5.7's own printf
    /// layouts over fixed counters (`gen.c`; see the README there).
    const TABLE: &str = include_str!("../../../tests/fixtures/zstd_progress/table.txt");

    fn unescape(s: &str) -> Vec<u8> {
        s.replace("\\r", "\r").replace("\\n", "\n").into_bytes()
    }

    /// One table row's input rendered by the port.
    fn render(row: &str) -> Vec<u8> {
        let f: Vec<&str> = row.split(' ').collect();
        let n = |i: usize| f[i].parse::<u64>().unwrap();
        let level = n(1) as i32;
        match f[0] {
            "compress" => compress_progress_line(&CompressProgress {
                display_level: level,
                util_level: level,
                nb_files_total: n(2) as usize,
                curr_file_idx: n(3) as usize,
                src_name: f[4].as_bytes(),
                file_size: f[5].parse::<i64>().unwrap() as u64,
                level: f[6].parse().unwrap(),
                ingested: n(7),
                consumed: n(8),
                produced: n(9),
            }),
            "decompress" => decompress_progress_line(
                level,
                level,
                n(2) as usize,
                n(3) as usize,
                f[4].as_bytes(),
                n(5),
            ),
            k => panic!("unknown row kind {k}"),
        }
    }

    #[test]
    fn every_table_row_is_the_references_bytes() {
        let mut rows = 0;
        for line in TABLE.lines() {
            let (input, expected) = line.split_once('\t').unwrap();
            assert_eq!(
                String::from_utf8_lossy(&render(input)),
                String::from_utf8_lossy(&unescape(expected)),
                "row `{input}`"
            );
            rows += 1;
        }
        assert!(rows >= 35, "{rows} rows");
    }

    #[test]
    fn the_table_covers_every_form() {
        let has = |kind: &str, dl: &str, multi: bool| {
            TABLE.lines().any(|l| {
                let f: Vec<&str> = l.split('\t').next().unwrap().split(' ').collect();
                f[0] == kind && f[1] == dl && (f[2] != "1") == multi
            })
        };
        for kind in ["compress", "decompress"] {
            for dl in ["2", "3", "4"] {
                for multi in [false, true] {
                    // The verbose compression line carries no file counter,
                    // so a second file adds no form at level 3 or 4 (the
                    // table has one level-3 multi row as a witness).
                    if kind == "compress" && dl == "4" && multi {
                        continue;
                    }
                    assert!(has(kind, dl, multi), "{kind} level {dl} multi {multi}");
                }
            }
        }
        assert!(TABLE.contains("compress 2 1 0 a.txt -1 "), "unknown size");
    }

    /// Digits to `9`, runs of blanks to one, decimals and units to `9` and `U`: the shape of a
    /// line, whatever the counters and widths of the run that made it.
    fn shape(s: &[u8]) -> String {
        let t = String::from_utf8_lossy(s);
        let mut out = String::new();
        for c in t.chars() {
            let c = if c.is_ascii_digit() { '9' } else { c };
            if (c == '9' || c == ' ') && out.ends_with(c) {
                continue;
            }
            out.push(c);
        }
        out = out.replace("9.9", "9");
        for unit in [" EiB", " PiB", " TiB", " GiB", " MiB", " KiB", " B"] {
            out = out.replace(unit, " U");
        }
        out
    }

    /// The progress refreshes a real run wrote to a terminal: the
    /// `\r`-separated chunks that are not blank and not the final summary.
    fn recorded(raw: &'static [u8]) -> Vec<&'static [u8]> {
        raw.split(|&b| b == b'\r')
            .filter(|c| !c.iter().all(|&b| b == b' ' || b == b'\n'))
            .filter(|c| !c.ends_with(b"\n"))
            .collect()
    }

    #[test]
    fn recorded_terminal_runs_have_the_ports_shapes() {
        const C1: &[u8] = include_bytes!("../../../tests/fixtures/zstd_progress/c1_default.raw");
        const C1V: &[u8] = include_bytes!("../../../tests/fixtures/zstd_progress/c1_v.raw");
        const CN: &[u8] = include_bytes!("../../../tests/fixtures/zstd_progress/cn_default.raw");
        const D1: &[u8] = include_bytes!("../../../tests/fixtures/zstd_progress/d1_default.raw");
        const DN: &[u8] = include_bytes!("../../../tests/fixtures/zstd_progress/dn_default.raw");
        fn compress(dl: i32, files: usize, name: &[u8]) -> CompressProgress<'_> {
            CompressProgress {
                display_level: dl,
                util_level: dl,
                nb_files_total: files,
                curr_file_idx: 0,
                src_name: name,
                file_size: 25_165_827,
                level: 19,
                ingested: 2 << 20,
                consumed: 3 << 19,
                produced: 1 << 19,
            }
        }
        let second = CompressProgress {
            curr_file_idx: 1,
            ..compress(2, 2, b"report-2024-final.txt")
        };
        // (recording, our renderings of the forms it holds)
        let cases: [(&[u8], Vec<Vec<u8>>); 5] = [
            (
                C1,
                vec![compress_progress_line(&compress(2, 1, b"one.txt"))],
            ),
            (
                C1V,
                vec![compress_progress_line(&compress(3, 1, b"one.txt"))],
            ),
            (
                CN,
                vec![
                    compress_progress_line(&compress(2, 2, b"one.txt")),
                    compress_progress_line(&second),
                ],
            ),
            (
                D1,
                vec![decompress_progress_line(
                    2,
                    2,
                    1,
                    0,
                    b"one.txt.zst",
                    1 << 20,
                )],
            ),
            (
                DN,
                vec![
                    decompress_progress_line(2, 2, 2, 0, b"one.txt.zst", 1 << 20),
                    decompress_progress_line(2, 2, 2, 1, b"report-2024-final.txt.zst", 1 << 20),
                ],
            ),
        ];
        for (raw, ours) in cases {
            let want: Vec<String> = ours
                .iter()
                .map(|o| shape(o.split(|&b| b == b'\r').next_back().unwrap()))
                .collect();
            let mut seen = 0;
            for c in recorded(raw) {
                let c = shape(c);
                // The recording also holds zstd's final lines (a banner,
                // the file summary): only a progress form is compared.
                let progress = ["Read:", "Compress:", "(L", "Decompress:"]
                    .iter()
                    .any(|p| c.starts_with(p))
                    || c.contains(" : 9");
                if progress && !c.contains("bytes") && !c.contains("% (") {
                    assert!(want.contains(&c), "recorded line `{c}` is none of {want:?}");
                    seen += 1;
                }
            }
            assert!(seen > 0, "no progress line in a recording");
        }
    }

    #[test]
    fn the_gate_lets_one_update_through_per_refresh_rate() {
        let mut d = Display::new(3);
        let mut err = Vec::new();
        let mut line = |d: &mut Display, now: u64, text: &'static str| {
            d.update(now, &mut err, |w| {
                let _ = w.write_all(text.as_bytes());
            });
        };
        line(&mut d, 1000, "a"); // the first always shows
        line(&mut d, 1100, "b"); // 100 ms < 166.67 ms
        line(&mut d, 1166, "c"); // 166 ms: not more than REFRESH_RATE
        line(&mut d, 1167, "d"); // 167 ms > 166.666 ms
        line(&mut d, 1200, "e");
        line(&mut d, 1334, "f"); // 167 ms after "d"
        assert_eq!(err, b"adf");
    }

    #[test]
    fn level_4_updates_every_time_and_level_0_never() {
        let mut d = Display::new(4);
        let mut err = Vec::new();
        for now in [5, 5, 6] {
            d.update(now, &mut err, |w| {
                let _ = w.write_all(b"x");
            });
        }
        assert_eq!(err, b"xxx");
        let mut d = Display::new(0);
        let mut err = Vec::new();
        d.update(1000, &mut err, |w| {
            let _ = w.write_all(b"x");
        });
        assert!(err.is_empty());
    }

    #[test]
    fn delaying_the_next_update_restarts_the_clock() {
        let mut d = Display::new(2);
        assert!(d.ready_for_update(0));
        d.delay_next_update(10_000);
        assert!(!d.ready_for_update(10_100));
        assert!(d.ready_for_update(10_167));
    }

    #[test]
    fn exm_throw_prints_at_level_1_and_returns_its_code() {
        let mut err = Vec::new();
        let code = exm_throw(&Display::new(1), &mut err, 11, b"Parameter is out of bound");
        assert_eq!(code, 11);
        assert_eq!(err, b"zstd: error 11 : Parameter is out of bound \n");
        let mut err = Vec::new();
        assert_eq!(exm_throw(&Display::new(0), &mut err, 1, b"x"), 1);
        assert!(err.is_empty());
    }
}
