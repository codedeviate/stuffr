//! lz4's display layer: the `\r`-refreshed progress line and its refresh
//! gate, the summaries, the thread line and `Done in`, as functions of
//! their figures so that unit tests can pin their bytes from an injected
//! clock (ruling R10; the recordings are in
//! `tests/fixtures/lz4_progress/`, each with the command that made it).
//!
//! **Clean room:** every rule here is from the binary's own output (`//
//! probe:`), never from lz4's source.
//!
//! - **The refresh gate.** Display levels 2 and 3 redraw the progress line
//!   when at least [`REFRESH_MS`] have passed since the last redraw (the
//!   first one is always drawn: a run that ends within the interval still
//!   shows one); level 4 and up redraws at every chance. A "chance" is a
//!   chunk the run finished: 4 MiB of input compressed, 8 MiB of a legacy
//!   frame, 4 MiB decoded (here: each new MiB decoded). How many redraws a
//!   run makes is therefore its timing, which spec deviation 2 leaves out of
//!   the promise.
//! - **`Done in`.** Seconds since the run started, megabytes per second of
//!   the bytes read (compressing) or decoded, and the CPU time the process
//!   used per second of that. Under a sandbox the clock is frozen at zero,
//!   so a fuzzed run's output does not depend on how fast it ran (as xz's
//!   does).

use std::io::Write;
use std::time::Instant;

use super::cli::{Plan, Target};
use super::io::{Run, Stats};
use super::messages::{self as m, printf};

/// probe: `script`-recorded runs of `lz4 -v -T1 -12` over 200 MB of
/// executables (fixtures `compress_t1_12.rec`, `compress_t1_9.rec`,
/// `decode_slow.rec`): across 130 redraws at levels 6, 9 and 12 and a slow
/// consumer's decode, the shortest gap between two redraws was 200 ms (one
/// chunk took 170-190 ms and was skipped, two chunks took 340-380 ms and
/// drew). Wall time: a decode blocked on a slow pipe kept the same cadence.
pub(crate) const REFRESH_MS: u64 = 200;

/// The display level and the refresh gate (`g_displayLevel` and the last
/// redraw's time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Display {
    /// The display level: 0 nothing, 1 errors, 2 results and warnings, 3
    /// verbose, 4 and up information.
    pub level: i32,
    /// When the progress line was last drawn, in the caller's milliseconds.
    last_ms: Option<u64>,
}

impl Display {
    pub(crate) fn new(level: i32) -> Display {
        Display {
            level,
            last_ms: None,
        }
    }

    /// Whether a redraw at `now_ms` is due: display level 2 or more, and
    /// the first, or [`REFRESH_MS`] since the last, or level 4 or more
    /// (probe: `lz4 -vv` over 200 MB drew 48 redraws for 48 chunks).
    pub(crate) fn ready(&self, now_ms: u64) -> bool {
        self.level >= 2
            && (self.level >= 4
                || self
                    .last_ms
                    .is_none_or(|t| now_ms.saturating_sub(t) >= REFRESH_MS))
    }

    /// The progress line at `now_ms`, if a redraw is due: restart the
    /// clock and let `render` write the line to `err`.
    pub(crate) fn update(
        &mut self,
        now_ms: u64,
        err: &mut dyn Write,
        render: impl FnOnce(&mut dyn Write),
    ) {
        if self.ready(now_ms) {
            self.last_ms = Some(now_ms);
            render(err);
        }
    }
}

/// The run's clocks: wall time for the gate and `Done in`, and the
/// process's CPU time for the load.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timer {
    /// `None` for a sandbox: time does not pass.
    started: Option<(Instant, f64)>,
}

impl Timer {
    /// A timer from now; `real` false is the sandbox's frozen one.
    pub(crate) fn start(real: bool) -> Timer {
        Timer {
            started: real.then(|| (Instant::now(), cpu_seconds())),
        }
    }

    /// Milliseconds since the start.
    pub(crate) fn now_ms(&self) -> u64 {
        self.started.map_or(0, |(t, _)| {
            u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
        })
    }

    /// Seconds and CPU seconds since the start.
    pub(crate) fn elapsed(&self) -> (f64, f64) {
        self.started.map_or((0.0, 0.0), |(t, cpu)| {
            (t.elapsed().as_secs_f64(), cpu_seconds() - cpu)
        })
    }
}

/// The process's CPU time so far (`clock()`), in seconds.
fn cpu_seconds() -> f64 {
    #[cfg(unix)]
    {
        // SAFETY: a zeroed rusage is a valid out-parameter; getrusage only
        // writes it.
        let ru = unsafe {
            let mut ru: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_SELF, &mut ru);
            ru
        };
        let t = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6;
        t(ru.ru_utime) + t(ru.ru_stime)
    }
    #[cfg(not(unix))]
    {
        0.0
    }
}

// ---- level 2: the progress line and the summaries (ruling P3) ----

/// `%.2f` of `part` over `whole` as a percentage, `whole` at least 1
/// (probe: `lz4 e` says `1500.00%` for 15 bytes out of none).
pub(crate) fn percent(part: u64, whole: u64) -> String {
    format!("{:.2}", part as f64 / whole.max(1) as f64 * 100.0)
}

/// A `Read :` refresh while compressing: MiB read and the ratio so far
/// (deviation 2: how many are drawn is lz4's timing).
pub(crate) fn read_progress(w: &mut dyn Write, read: u64, written: u64) {
    let mib = (read >> 20).to_string();
    let ratio = percent(written, read);
    printf(w, m::READ_PROGRESS, &[mib.as_bytes(), ratio.as_bytes()]);
}

/// A `Decompressed :` refresh: MiB decoded so far.
pub(crate) fn decode_progress(w: &mut dyn Write, written: u64) {
    printf(
        w,
        m::DECODE_PROGRESS,
        &[(written >> 20).to_string().as_bytes()],
    );
}

/// The cleared line, then `Compressed A bytes into B bytes ==> R%` (a legacy
/// frame's has a blank more).
pub(crate) fn compress_summary(w: &mut dyn Write, legacy: bool, read: u64, written: u64) {
    let fmt = if legacy {
        m::COMPRESSED_LEGACY_SUMMARY
    } else {
        m::COMPRESSED_SUMMARY
    };
    let (read_s, written_s) = (read.to_string(), written.to_string());
    let ratio = percent(written, read);
    printf(w, m::CLEAR_LINE, &[]);
    printf(
        w,
        fmt,
        &[read_s.as_bytes(), written_s.as_bytes(), ratio.as_bytes()],
    );
}

/// The cleared line, then `NAME : decoded N bytes`, the name cut or padded
/// to 30 bytes (`%-30.30s`).
pub(crate) fn decode_summary(w: &mut dyn Write, name: &[u8], written: u64) {
    let mut shown = name[..name.len().min(30)].to_vec();
    shown.resize(30, b' ');
    printf(w, m::CLEAR_LINE, &[]);
    printf(
        w,
        m::DECODED_SUMMARY,
        &[&shown, written.to_string().as_bytes()],
    );
}

// ---- levels 3 and 4 ----

/// The thread line of a compression (probe: `lz4 -v -T3 a`): `Using N
/// threads for compression` for 2 to 200 workers, the cap's own line when
/// the count asked for was above 200, nothing for one worker.
pub(crate) fn threads_line(w: &mut dyn Write, threads: u32, reduced_from: Option<u32>) {
    if let Some(asked) = reduced_from {
        printf(
            w,
            m::THREADS_REDUCED,
            &[asked.to_string().as_bytes(), threads.to_string().as_bytes()],
        );
    } else if threads > 1 {
        printf(w, m::USING_THREADS, &[threads.to_string().as_bytes()]);
    }
}

/// `Done in S s ==> T MiB/s  (cpu load : L%)` for a run of `secs` wall
/// seconds and `cpu` CPU seconds that handled `bytes`. A run that took no
/// time at all (a sandbox's) has no speed and a load of 100.
pub(crate) fn done_line(w: &mut dyn Write, secs: f64, cpu: f64, bytes: u64) {
    let (speed, load) = if secs > 0.0 {
        (
            bytes as f64 / (1u64 << 20) as f64 / secs,
            cpu / secs * 100.0,
        )
    } else {
        (0.0, 100.0)
    };
    let (secs, speed, load) = (
        format!("{secs:.2}"),
        format!("{speed:.2}"),
        format!("{load:.0}"),
    );
    printf(
        w,
        m::DONE_IN,
        &[secs.as_bytes(), speed.as_bytes(), load.as_bytes()],
    );
}

// ---- the run's lines ----

impl Run<'_> {
    /// A `Read :` refresh while compressing (the gate decides whether it is
    /// drawn: one per piece compressed is offered).
    pub(super) fn show_read_progress(&mut self, s: &Stats) {
        let now = self.timer.now_ms();
        self.display
            .update(now, &mut *self.err, |w| read_progress(w, s.read, s.written));
    }

    /// The cleared line, then the compression summary (level 2).
    pub(super) fn show_compress_summary(&mut self, s: &Stats) {
        if self.level >= 2 {
            compress_summary(&mut *self.err, self.cmd.opts.legacy, s.read, s.written);
        }
    }

    /// The cleared line, then `NAME : decoded N bytes` (level 2).
    pub(super) fn show_decode_summary(&mut self, name: &[u8], s: &Stats) {
        if self.level >= 2 {
            decode_summary(&mut *self.err, name, s.written);
        }
    }

    /// `Done in ...` (level 3), for everything the run handled.
    pub(super) fn show_done(&mut self) {
        if self.level >= 3 {
            let (secs, cpu) = self.timer.elapsed();
            done_line(&mut *self.err, secs, cpu, self.total);
        }
    }

    /// What a run says once, before its first input (probes: `lz4 -vv -r
    /// d`, `lz4 -v -T3 a`, `lz4 -v -l a`, `lz4 -vv -dc a.lz4`), in this
    /// order:
    /// - display level 4, `-r`: the list it made, each name after its index
    ///   from 0 (printed for the names as expanded, missing ones too);
    /// - display level 3, compressing: the thread line, then the legacy
    ///   notice for `-l`;
    /// - display level 4, decoding: the standard output note, when the
    ///   output is standard output or there are `-m` operands (the note is
    ///   printed though they write files: `lz4 -vv -d -m a.lz4` says it).
    ///
    /// `names` is the expanded list of a run with `-m` operands.
    pub(super) fn announce_run(&mut self, plan: &Plan, names: &[Vec<u8>]) {
        if self.cmd.recursive {
            for (i, name) in names.iter().enumerate() {
                self.say(4, m::LIST_ENTRY, &[i.to_string().as_bytes(), name]);
            }
        }
        if plan.op == super::cli::Op::Compress {
            if self.level >= 3 {
                threads_line(
                    &mut *self.err,
                    self.cmd.threads,
                    self.cmd.threads_reduced_from,
                );
            }
            if self.cmd.opts.legacy {
                self.say(3, m::GENERATING_LEGACY, &[]);
            }
        } else if plan.target == Target::Stdout || self.cmd.from_list {
            self.stdout_note();
        }
    }
}

/// A `Decompressed :` refresh: drawn when the decoded total reaches a new
/// MiB and the gate allows (deviation 2). `frame` is a modern frame's: it
/// draws one even before its first byte (probe: `lz4 -t empty.lz4`, a frame
/// of nothing, draws one; `lz4 -t` of a legacy frame of nothing, of a
/// skippable frame or of an empty file draws none).
pub(super) fn show_decode_progress(
    run: &mut Run,
    written: u64,
    frame: bool,
    shown: &mut Option<u64>,
) {
    let mib = written >> 20;
    if (written == 0 && !frame) || *shown == Some(mib) {
        return;
    }
    let now = run.timer.now_ms();
    if run.display.ready(now) {
        *shown = Some(mib);
    }
    run.display
        .update(now, &mut *run.err, |w| decode_progress(w, written));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(f: impl FnOnce(&mut dyn Write)) -> String {
        let mut v = Vec::new();
        f(&mut v);
        String::from_utf8(v).unwrap()
    }

    /// One recording: `(milliseconds, bytes)` of each read from the pty
    /// standard error (`record.py`).
    fn rec(raw: &str) -> Vec<(u64, Vec<u8>)> {
        raw.lines()
            .map(|l| {
                let (t, b) = l.split_once('\t').unwrap();
                let lit = b.strip_prefix("b'").unwrap().strip_suffix('\'').unwrap();
                let mut out = Vec::new();
                let mut it = lit.bytes();
                while let Some(c) = it.next() {
                    if c != b'\\' {
                        out.push(c);
                        continue;
                    }
                    match it.next().unwrap() {
                        b'r' => out.push(b'\r'),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'\\' => out.push(b'\\'),
                        b'\'' => out.push(b'\''),
                        b'x' => {
                            let h: Vec<u8> = it.by_ref().take(2).collect();
                            out.push(
                                u8::from_str_radix(std::str::from_utf8(&h).unwrap(), 16).unwrap(),
                            );
                        }
                        other => panic!("escape {other}"),
                    }
                }
                (t.parse().unwrap(), out)
            })
            .collect()
    }

    const C_T1_12: &str = include_str!("../../../tests/fixtures/lz4_progress/compress_t1_12.rec");
    const C_T1_9: &str = include_str!("../../../tests/fixtures/lz4_progress/compress_t1_9.rec");
    const C_LEGACY: &str =
        include_str!("../../../tests/fixtures/lz4_progress/compress_legacy_9.rec");
    const C_VV: &str = include_str!("../../../tests/fixtures/lz4_progress/compress_vv_9.rec");
    const D_SLOW: &str = include_str!("../../../tests/fixtures/lz4_progress/decode_slow.rec");
    const SMALL_V: &str = include_str!("../../../tests/fixtures/lz4_progress/small_v.rec");
    const SMALL_M: &str = include_str!("../../../tests/fixtures/lz4_progress/small_m.rec");
    const SMALL_D: &str = include_str!("../../../tests/fixtures/lz4_progress/small_decode_m.rec");

    /// The times of a recording's refreshes (its chunks holding `marker`).
    fn refresh_times(r: &[(u64, Vec<u8>)], marker: &str) -> Vec<u64> {
        r.iter()
            .filter(|(_, b)| String::from_utf8_lossy(b).contains(marker))
            .map(|(t, _)| *t)
            .collect()
    }

    /// The gate, from the recordings: no two redraws closer than the
    /// interval, in every recorded run of levels 2 and 3; the interval is
    /// the shortest gap seen.
    #[test]
    fn recorded_refreshes_are_never_closer_than_the_interval() {
        let mut shortest = u64::MAX;
        for (name, raw, marker) in [
            ("compress -12", C_T1_12, "Read :"),
            ("compress -9", C_T1_9, "Read :"),
            ("legacy -9", C_LEGACY, "Read :"),
            ("decode", D_SLOW, "Decompressed :"),
        ] {
            let times = refresh_times(&rec(raw), marker);
            assert!(times.len() > 8, "{name}");
            for w in times.windows(2) {
                shortest = shortest.min(w[1] - w[0]);
                assert!(w[1] - w[0] >= REFRESH_MS, "{name}: {w:?}");
            }
        }
        // 200 ms is also the shortest gap that was recorded: the interval
        // is not lower than that.
        assert!(shortest < REFRESH_MS + 30, "{shortest}");
    }

    /// Display level 4 and up: every chunk draws (51 lines of the
    /// recording: the banner, the `_POSIX` lines, the threads, the 48
    /// chunks, the summary).
    #[test]
    fn level_four_draws_at_every_chance() {
        let r = rec(C_VV);
        let n = refresh_times(&r, "Read :").len();
        assert_eq!(n, 48, "the recording: 200 MB in 4 MiB chunks");
        let mut d = Display::new(4);
        let mut out = Vec::new();
        for i in 0..48 {
            d.update(i, &mut out, |w| w.write_all(b".").unwrap());
        }
        assert_eq!(out.len(), 48);
    }

    /// Levels 2 and 3: the first update draws whenever it comes, the next
    /// only an interval later, and an update that did not draw leaves the
    /// clock alone; level 1 and below never draw.
    #[test]
    fn the_gate_draws_the_first_then_one_per_interval() {
        for level in [2, 3] {
            let mut d = Display::new(level);
            let mut out = Vec::new();
            let mut at = |d: &mut Display, t: u64| {
                let n = out.len();
                d.update(t, &mut out, |w| w.write_all(b"x").unwrap());
                out.len() > n
            };
            assert!(at(&mut d, 5000), "the first, wherever the clock stands");
            assert!(!at(&mut d, 5000));
            assert!(!at(&mut d, 5000 + REFRESH_MS - 1));
            assert!(at(&mut d, 5000 + REFRESH_MS));
            // The skipped update did not restart the clock.
            assert!(!at(&mut d, 5000 + REFRESH_MS + 199));
            assert!(at(&mut d, 5000 + 2 * REFRESH_MS));
            // A clock that went back (it is monotonic; never panic anyway).
            assert!(!at(&mut d, 0));
        }
        for level in [0, 1] {
            let mut d = Display::new(level);
            let mut out = Vec::new();
            d.update(0, &mut out, |w| w.write_all(b"x").unwrap());
            d.update(10_000, &mut out, |w| w.write_all(b"x").unwrap());
            assert!(out.is_empty(), "level {level}");
        }
    }

    /// The gate over a recorded run: it draws at each time the reference
    /// drew, and refuses a chance 100 ms after any of them (the chunks the
    /// reference skipped fell that soon after a refresh).
    #[test]
    fn the_gate_replays_a_recorded_run() {
        for (raw, marker) in [(C_T1_12, "Read :"), (D_SLOW, "Decompressed :")] {
            let times = refresh_times(&rec(raw), marker);
            let mut d = Display::new(3);
            let mut sink = Vec::new();
            let mut at = |d: &mut Display, now: u64| {
                let n = sink.len();
                d.update(now, &mut sink, |w| w.write_all(b"x").unwrap());
                sink.len() > n
            };
            for &t in &times {
                if t != times[0] {
                    // The chance the reference skipped.
                    let skipped = d.last_ms.unwrap() + 100;
                    assert!(!at(&mut d, skipped), "{raw:.20}");
                }
                assert!(at(&mut d, t), "drawn at {t}");
            }
        }
    }

    /// Each recorded line that holds no timing: the progress forms, the
    /// cleared line and the summaries are what our renderers write, the
    /// figures being the recording's own.
    #[test]
    fn rendered_lines_are_the_recorded_ones() {
        let small = rec(SMALL_V);
        let all: Vec<u8> = small.iter().flat_map(|(_, b)| b.clone()).collect();
        let all = String::from_utf8(all).unwrap().replace("\r\n", "\n");
        // The recording: `lz4 -f -v -T3 a a.lz4` over a 1760-byte input.
        let want_threads = text(|w| threads_line(w, 3, None));
        assert!(all.contains(&want_threads), "{all:?}");
        let progress = text(|w| read_progress(w, 0, 1));
        // The reference's first refresh is drawn before the output exists
        // (`0 MiB ==> inf%` for a large input, the ratio of the one chunk
        // for a small one): the shape is `\rRead : N MiB   ==> R%   `.
        let blanks = " ".repeat(3);
        assert!(
            progress.starts_with(&format!("\rRead : 0 MiB{blanks}==> "))
                && progress.ends_with(&format!("%{blanks}"))
        );
        let summary = text(|w| compress_summary(w, false, 1760, 82));
        assert!(all.contains(&summary), "{summary:?} in {all:?}");
        // Done in: the 200 MB run's line (`compress_t1_12.rec`: 9.28 s,
        // 20.56 MiB/s, 99%) is what the figures give.
        let long = String::from_utf8(rec(C_T1_12).pop().unwrap().1).unwrap();
        assert_eq!(
            long.trim_end(),
            "Done in 9.28 s ==> 20.56 MiB/s  (cpu load : 99%)"
        );
        assert_eq!(
            text(|w| done_line(w, 9.277, 9.277 * 0.99, 200_000_000)),
            "Done in 9.28 s ==> 20.56 MiB/s  (cpu load : 99%)\n"
        );
        // The small run's line has the same shape (its figures are timing).
        let done = all.lines().find(|l| l.starts_with("Done in ")).unwrap();
        assert!(
            done.ends_with("%)")
                && done.contains(" s ==> ")
                && done.contains(" MiB/s  (cpu load : ")
        );
    }

    /// Several files (`-m`): each file's cleared line and summary, one
    /// `Done in` after the last; the thread line comes before the first.
    #[test]
    fn several_files_have_one_thread_line_and_one_done() {
        let all: Vec<u8> = rec(SMALL_M).into_iter().flat_map(|(_, b)| b).collect();
        let all = String::from_utf8(all).unwrap().replace("\r\n", "\n");
        // Refreshes sit between: take them out of the recording.
        let stripped: String = all
            .split('\r')
            .filter(|c| !c.starts_with("Read :"))
            .collect::<Vec<_>>()
            .join("\r");
        assert_eq!(
            stripped
                .matches("Compressed 1760 bytes into 82 bytes ==> 4.66%\n")
                .count(),
            2,
            "{stripped:?}"
        );
        assert_eq!(stripped.matches("Using 1 threads").count(), 0);
        assert_eq!(all.matches("Done in ").count(), 1);
        assert!(
            all.trim_end()
                .rsplit('\n')
                .next()
                .unwrap()
                .starts_with("Done in ")
        );
    }

    /// Decoding: the `Decompressed :` refresh, the name's field and the
    /// cleared line (`lz4 -f -v -d -m a.lz4 b.lz4`: `Done in` too).
    #[test]
    fn decoding_summaries_are_the_recorded_ones() {
        let all: Vec<u8> = rec(SMALL_D).into_iter().flat_map(|(_, b)| b).collect();
        let all = String::from_utf8(all).unwrap().replace("\r\n", "\n");
        assert!(all.contains(&text(|w| decode_progress(w, 1760))), "{all:?}");
        let summary = text(|w| decode_summary(w, b"a.lz4", 1760));
        assert!(all.contains(&summary), "{summary:?} in {all:?}");
        assert!(all.contains("\nDone in "));
        // The name is cut at 30 bytes and padded to 30 (`%-30.30s`).
        let long = text(|w| decode_summary(w, &[b'x'; 40], 1));
        assert_eq!(
            long,
            format!("{}{} : decoded 1 bytes \n", m::CLEAR_LINE, "x".repeat(30))
        );
        let short = text(|w| decode_summary(w, b"s", 0));
        assert!(short.ends_with(&format!("s{} : decoded 0 bytes \n", " ".repeat(29))));
    }

    /// The thread line: counts to the cap, the cap's own line, none for one
    /// worker (probe: `-T1`, `-T2`, `-T200`, `-T201`, `-T300`).
    #[test]
    fn the_thread_line() {
        assert_eq!(text(|w| threads_line(w, 1, None)), "");
        assert_eq!(
            text(|w| threads_line(w, 2, None)),
            "Using 2 threads for compression \n"
        );
        assert_eq!(
            text(|w| threads_line(w, 200, None)),
            "Using 200 threads for compression \n"
        );
        assert_eq!(
            text(|w| threads_line(w, 200, Some(201))),
            "Requested 201 threads too large => automatically reduced to 200 \n"
        );
        assert_eq!(
            text(|w| threads_line(w, 200, Some(300))),
            "Requested 300 threads too large => automatically reduced to 200 \n"
        );
    }

    /// `Done in`: the speed of the bytes over the seconds, the load of the
    /// CPU seconds over them, and a zero-time run's figures.
    #[test]
    fn done_in_figures() {
        assert_eq!(
            text(|w| done_line(w, 2.0, 1.0, 8 << 20)),
            "Done in 2.00 s ==> 4.00 MiB/s  (cpu load : 50%)\n"
        );
        assert_eq!(
            text(|w| done_line(w, 0.5, 1.2, 0)),
            "Done in 0.50 s ==> 0.00 MiB/s  (cpu load : 240%)\n"
        );
        assert_eq!(
            text(|w| done_line(w, 0.0, 0.0, 99)),
            "Done in 0.00 s ==> 0.00 MiB/s  (cpu load : 100%)\n"
        );
    }

    /// A sandbox's timer never moves; a real one does.
    #[test]
    fn timers() {
        let t = Timer::start(false);
        assert_eq!((t.now_ms(), t.elapsed()), (0, (0.0, 0.0)));
        let t = Timer::start(true);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(t.now_ms() >= 20);
        assert!(t.elapsed().0 >= 0.02);
    }

    /// The ratio is `%.2f` of at least one byte (probe: `lz4 e` says
    /// `1500.00%`).
    #[test]
    fn percent_of_nothing() {
        assert_eq!(percent(15, 0), "1500.00");
        assert_eq!(percent(1, 3), "33.33");
        assert_eq!(percent(0, 0), "0.00");
    }
}
