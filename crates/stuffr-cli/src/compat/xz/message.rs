//! `message.c` (errors, warnings, the progress indicator, the help texts
//! and `--version`), `mytime.c`'s elapsed time, `main.c`'s exit status
//! (`set_exit_status`, `--no-warn`) and `tuklib_exit.c`, from XZ Utils
//! 5.8.4 (0BSD, `LICENSE-xz`).
//!
//! **The progress indicator.** At `-v` on a terminal standard error
//! (`progress_automatic`), each file's name is printed as it starts and a
//! line is rewritten in place every second; elsewhere `-v` prints one line
//! per file when it ends. A progress signal (SIGALRM, SIGINFO, SIGUSR1:
//! `host::install_progress_signals`) asks for a line at any verbosity; its
//! handler only sets a flag, which the coder loop polls after each coder
//! call (`message_progress_update`), as xz's does. Every message said while
//! a file is being coded is preceded by the indicator's line
//! (`progress_flush` in `vmessage`).
//!
//! The one-second timer is polled against the clock rather than driven by
//! `alarm(2)` (message.c's own path for systems without SIGALRM): the line
//! is the same and is printed at the same moments, and no process-wide
//! timer is set. The clock is injected ([`Clock`]): the real process's is
//! monotonic less any time stopped (`host::running_ms`), a sandbox's is
//! always zero, so its lines never carry a speed or an elapsed time.

use std::cell::Cell;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use stuffr::xz_opts::{self, Filter, XzError};

use super::hardware::round_up_to_mib;
use super::messages::{self as m, printf};
use super::options;
use crate::compat::host;

/// `enum message_verbosity`, in its order: a message prints when its level
/// is at most the current one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Verbosity {
    /// `V_SILENT`: `-qq`.
    Silent = 0,
    /// `V_ERROR`: `-q`.
    Error = 1,
    /// `V_WARNING`: the default.
    Warning = 2,
    /// `V_VERBOSE`: `-v`.
    Verbose = 3,
    /// `V_DEBUG`: `-vv`.
    Debug = 4,
}

impl Verbosity {
    /// `message_verbosity_increase`.
    pub(crate) fn increase(self) -> Self {
        match self {
            Verbosity::Silent => Verbosity::Error,
            Verbosity::Error => Verbosity::Warning,
            Verbosity::Warning => Verbosity::Verbose,
            Verbosity::Verbose | Verbosity::Debug => Verbosity::Debug,
        }
    }

    /// `message_verbosity_decrease`.
    pub(crate) fn decrease(self) -> Self {
        match self {
            Verbosity::Silent | Verbosity::Error => Verbosity::Silent,
            Verbosity::Warning => Verbosity::Error,
            Verbosity::Verbose => Verbosity::Warning,
            Verbosity::Debug => Verbosity::Verbose,
        }
    }
}

/// `enum exit_status_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    /// `E_SUCCESS`.
    Success = 0,
    /// `E_ERROR`.
    Error = 1,
    /// `E_WARNING`.
    Warning = 2,
}

/// mytime.c: mytime_now: milliseconds from some fixed point.
pub(crate) type Clock = fn() -> u64;

/// The sandbox's clock: time never passes, so a fuzzed run's output does
/// not depend on how fast it ran.
pub(crate) fn frozen_clock() -> u64 {
    0
}

/// The state `message.c` and `main.c` keep in globals: the program name,
/// the verbosity, the exit status so far, `--no-warn`, and the progress
/// indicator's.
pub(crate) struct Messages {
    /// `progname`: the full `argv[0]` (`tuklib_progname_init`).
    pub(crate) progname: Vec<u8>,
    pub(crate) verbosity: Verbosity,
    /// `exit_status` in main.c.
    pub(crate) status: Status,
    /// `-Q`/`--no-warn`.
    pub(crate) no_warn: bool,
    /// `files_total` (message_set_files): the operands' count, 0 when
    /// `--files`/`--files0` makes it unknown.
    pub(crate) files_total: u32,
    /// `opt_robot`: no file names are printed.
    pub(crate) robot: bool,
    /// `opt_mode == MODE_LIST`: names go to standard output, and at `-v`
    /// whether or not the indicator updates itself.
    pub(crate) list: bool,
    /// `progress_automatic`: standard error is a terminal (message_init).
    pub(crate) automatic: bool,
    /// The clock the elapsed time is read from.
    pub(crate) clock: Clock,
    /// `progress_needs_updating`'s signal half: set by a progress signal.
    pub(crate) requested: &'static AtomicBool,
    /// `files_pos`: the file being processed, from 1.
    files_pos: u32,
    /// `filename`: the current file (`None`: standard input).
    filename: Option<Vec<u8>>,
    /// `first_filename_printed`.
    first_filename_printed: bool,
    /// `current_filename_printed`.
    current_filename_printed: bool,
    /// `progress_started`.
    started: bool,
    /// `progress_active`: a line is on the terminal, the cursor after it.
    active: Cell<bool>,
    /// `opt_mode == MODE_COMPRESS`: the coder's input is the uncompressed
    /// side (progress_pos).
    compressing: bool,
    /// `expected_in_size`: the input's size, 0 when unknown.
    expected_in_size: u64,
    /// The coder's `lzma_get_progress` after its latest call.
    pos: Cell<xz_opts::Progress>,
    /// `start_time` (mytime_set_start_time).
    start: u64,
    /// `progress_next_update`: the elapsed time of the next automatic line.
    next_update: u64,
}

impl Messages {
    pub(crate) fn new(progname: &[u8]) -> Self {
        Messages {
            progname: progname.to_vec(),
            verbosity: Verbosity::Warning,
            status: Status::Success,
            no_warn: false,
            files_total: 0,
            robot: false,
            list: false,
            automatic: false,
            clock: host::running_ms,
            requested: &host::PROGRESS_REQUESTED,
            files_pos: 0,
            filename: None,
            first_filename_printed: false,
            current_filename_printed: false,
            started: false,
            active: Cell::new(false),
            compressing: false,
            expected_in_size: 0,
            pos: Cell::new(xz_opts::Progress::default()),
            start: 0,
            next_update: 0,
        }
    }

    /// message.c: message_filename (`name` `None` for standard input): the
    /// file is counted and, at `-v` and above under `--list` or with the
    /// indicator updating itself, its name printed by print_filename to
    /// `file`, standard output under `--list` and standard error otherwise.
    pub(crate) fn filename(&mut self, file: &mut dyn Write, name: Option<&[u8]>) {
        self.files_pos = self.files_pos.wrapping_add(1);
        self.filename = name.map(<[u8]>::to_vec);
        if self.verbosity >= Verbosity::Verbose && (self.automatic || self.list) {
            self.print_filename(file);
        } else {
            self.current_filename_printed = false;
        }
    }

    /// message.c: print_filename: never under `--robot`, nor for standard
    /// input when it is the only file.
    fn print_filename(&mut self, file: &mut dyn Write) {
        if self.robot || (self.files_total == 1 && self.filename.is_none()) {
            return;
        }
        let mut line = Vec::new();
        if self.first_filename_printed {
            printf(&mut line, m::FILENAME_GAP, &[]);
        }
        self.first_filename_printed = true;
        self.current_filename_printed = true;
        let shown = mask_nonprint(self.filename.as_deref().unwrap_or(m::STDIN_NAME));
        let pos = self.files_pos.to_string();
        if self.files_total == 0 {
            printf(&mut line, m::FILENAME_NTH, &[&shown, pos.as_bytes()]);
        } else {
            let total = self.files_total.to_string();
            printf(
                &mut line,
                m::FILENAME_OF,
                &[&shown, pos.as_bytes(), total.as_bytes()],
            );
        }
        let _ = file.write_all(&line);
    }

    /// mytime.c: mytime_get_elapsed.
    fn elapsed(&self) -> u64 {
        (self.clock)().saturating_sub(self.start)
    }

    /// mytime.c: mytime_set_start_time, then message.c:
    /// message_progress_start: the coder (`compressing` or not) is about to
    /// run over an input of `in_size` bytes (0: unknown), having done `pos`
    /// so far.
    pub(crate) fn progress_start(
        &mut self,
        compressing: bool,
        in_size: u64,
        pos: xz_opts::Progress,
    ) {
        self.start = (self.clock)();
        self.compressing = compressing;
        self.expected_in_size = in_size;
        self.pos.set(pos);
        self.started = true;
        if self.verbosity >= Verbosity::Verbose && self.automatic {
            // alarm(0); progress_needs_updating = false; alarm(1).
            self.requested.store(false, Ordering::Relaxed);
            self.next_update = 1000;
        }
    }

    /// The coder's position (`lzma_get_progress`), after each of its calls.
    pub(crate) fn progress_pos(&self, pos: xz_opts::Progress) {
        self.pos.set(pos);
    }

    /// message.c: progress_pos, and the fields every line is made of.
    fn snapshot(&self, elapsed: u64) -> Progress {
        let p = self.pos.get();
        let (compressed, uncompressed) = if self.compressing {
            (p.out_bytes, p.in_bytes)
        } else {
            (p.in_bytes, p.out_bytes)
        };
        Progress {
            expected_in_size: self.expected_in_size,
            in_pos: p.in_bytes,
            compressed,
            uncompressed,
            elapsed,
        }
    }

    /// message.c: message_progress_update, polled after each coder call: a
    /// line when a progress signal asked for one, or when the automatic
    /// indicator's second has passed.
    pub(crate) fn progress_update(&mut self, err: &mut dyn Write) {
        let auto = self.verbosity >= Verbosity::Verbose && self.automatic;
        let signalled =
            self.requested.load(Ordering::Relaxed) && self.requested.swap(false, Ordering::Relaxed);
        if !signalled && !auto {
            return;
        }
        let elapsed = self.elapsed();
        if !signalled && elapsed < self.next_update {
            return;
        }
        if auto {
            self.next_update = elapsed.saturating_add(1000);
        }
        if !self.current_filename_printed {
            self.print_filename(err);
        }
        let mut line = self.snapshot(elapsed).update_line();
        if auto {
            // Mark that an error must first end this line.
            self.active.set(true);
        } else {
            // A signal's line, not updated in place: a line of its own.
            printf(&mut line, m::PROGRESS_SIGNAL_END, &[]);
        }
        let _ = err.write_all(&line);
    }

    /// message.c: progress_flush: the line as it stands, ended (and
    /// `finished`: the file done). Not before any output unless a line is
    /// already shown, so an error at the very start has none.
    fn progress_flush(&self, finished: bool, err: &mut dyn Write) {
        if !self.started || self.verbosity < Verbosity::Verbose {
            return;
        }
        let p = self.snapshot(0);
        if !finished && !self.active.get() && (p.compressed == 0 || p.uncompressed == 0) {
            return;
        }
        self.active.set(false);
        let p = Progress {
            elapsed: self.elapsed(),
            ..p
        };
        let name = mask_nonprint(self.filename.as_deref().unwrap_or(m::STDIN_NAME));
        let _ = err.write_all(&p.final_line(self.automatic, finished, &name));
    }

    /// message.c: message_progress_end.
    pub(crate) fn progress_end(&mut self, success: bool, err: &mut dyn Write) {
        self.progress_flush(success, err);
        self.started = false;
    }

    /// `message(v, fmt, ...)`: `"progname: "`, the text and a newline, when
    /// `v` is at most the verbosity.
    pub(crate) fn message(&self, err: &mut dyn Write, v: Verbosity, fmt: &str, args: &[&[u8]]) {
        if v <= self.verbosity {
            self.progress_flush(false, err);
            let mut line = Vec::with_capacity(fmt.len() + 64);
            printf(&mut line, m::PREFIX, &[&self.progname]);
            printf(&mut line, fmt, args);
            line.push(b'\n');
            let _ = err.write_all(&line);
        }
    }

    /// `message_warning`: at `V_WARNING`, and the exit status becomes a
    /// warning unless it is already an error.
    pub(crate) fn warning(&mut self, err: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
        self.message(err, Verbosity::Warning, fmt, args);
        self.set_status(Status::Warning);
    }

    /// `message_error`: at `V_ERROR`, and the exit status becomes an error.
    pub(crate) fn error(&mut self, err: &mut dyn Write, fmt: &str, args: &[&[u8]]) {
        self.message(err, Verbosity::Error, fmt, args);
        self.set_status(Status::Error);
    }

    /// `message_fatal`: at `V_ERROR`; the caller then exits 1
    /// (`tuklib_exit(E_ERROR, E_ERROR, false)`, which closes nothing).
    pub(crate) fn fatal(&self, err: &mut dyn Write, fmt: &str, args: &[&[u8]]) -> u8 {
        self.message(err, Verbosity::Error, fmt, args);
        Status::Error as u8
    }

    /// message.c: message_mem_needed: `memusage` rounded up to MiB, against
    /// `memlimit` (`hardware_memlimit_get(opt_mode)`, `u64::MAX` for none).
    pub(crate) fn mem_needed(
        &self,
        err: &mut dyn Write,
        v: Verbosity,
        memusage: u64,
        memlimit: u64,
    ) {
        if v > self.verbosity {
            return;
        }
        let usage = round_up_to_mib(memusage).to_string();
        if memlimit == u64::MAX {
            self.message(err, v, m::MEM_NEEDED_NO_LIMIT, &[usage.as_bytes()]);
            return;
        }
        let mut limit = Vec::new();
        if memlimit < 1 << 20 {
            printf(
                &mut limit,
                m::MEM_LIMIT_BYTES,
                &[memlimit.to_string().as_bytes()],
            );
        } else {
            let mib = round_up_to_mib(memlimit).to_string();
            printf(&mut limit, m::MEM_LIMIT_MIB, &[mib.as_bytes()]);
        }
        self.message(err, v, m::MEM_NEEDED, &[usage.as_bytes(), &limit]);
    }

    /// message.c: message_filters_show: the chain as
    /// `lzma_str_from_filters(LZMA_STR_ENCODER | LZMA_STR_GETOPT_LONG)`
    /// spells it.
    pub(crate) fn filters_show(&self, err: &mut dyn Write, v: Verbosity, chain: &[Filter]) {
        if v > self.verbosity {
            return;
        }
        printf(
            err,
            m::FILTER_CHAIN,
            &[&self.progname, &options::str_from_filters(chain)],
        );
    }

    /// `message_try_help`, at `V_WARNING` so that `-q` hides it.
    pub(crate) fn try_help(&self, err: &mut dyn Write) {
        self.message(err, Verbosity::Warning, m::TRY_HELP, &[&self.progname]);
    }

    /// main.c: set_exit_status. `E_ERROR` is never lowered.
    pub(crate) fn set_status(&mut self, s: Status) {
        if self.status != Status::Error {
            self.status = s;
        }
    }

    /// main.c's last step: the status, with a warning made a success under
    /// `--no-warn`.
    pub(crate) fn final_status(&self) -> Status {
        if self.status == Status::Warning && self.no_warn {
            Status::Success
        } else {
            self.status
        }
    }
}

/// tuklib_exit.c: `tuklib_exit(status, E_ERROR, show_error)` for a
/// `status` other than `E_ERROR`: standard output is flushed (`fclose`),
/// and a failure makes the exit an error, reported unless `show_error` is
/// false. An `E_ERROR` exit touches nothing.
pub(crate) fn exit(
    status: Status,
    progname: &[u8],
    out: &mut dyn Write,
    err: &mut dyn Write,
    show_error: bool,
) -> u8 {
    if status == Status::Error {
        return Status::Error as u8;
    }
    match out.flush() {
        Ok(()) => status as u8,
        Err(e) => {
            if show_error {
                let reason = crate::compat::host::strerror(&e);
                printf(err, m::WRITE_FAILED, &[progname, &reason]);
            }
            Status::Error as u8
        }
    }
}

/// message.c: message_help, then `tuklib_exit(E_SUCCESS, E_ERROR,
/// verbosity != V_SILENT)`.
pub(crate) fn help(msg: &Messages, long: bool, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let text = if long { m::LONG_HELP } else { m::HELP };
    printf(out, text, &[&msg.progname]);
    exit(
        Status::Success,
        &msg.progname,
        out,
        err,
        msg.verbosity != Verbosity::Silent,
    )
}

/// message.c: message_version. The first line names stuffr; `--robot`'s
/// form is the reference's.
pub(crate) fn version(msg: &Messages, robot: bool, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    if robot {
        printf(out, m::VERSION_ROBOT, &[]);
    } else {
        printf(
            out,
            m::VERSION_FIRST_LINE,
            &[env!("CARGO_PKG_VERSION").as_bytes()],
        );
        printf(out, m::VERSION_LIBLZMA, &[]);
    }
    exit(
        Status::Success,
        &msg.progname,
        out,
        err,
        msg.verbosity != Verbosity::Silent,
    )
}

/// message.c: message_filters_help: the explanation (not under `--robot`)
/// and the encoder's filter list.
pub(crate) fn filters_help(
    msg: &Messages,
    robot: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    if !robot {
        printf(out, m::FILTERS_HELP_INTRO, &[]);
    }
    printf(out, m::FILTERS_HELP_LIST, &[]);
    exit(
        Status::Success,
        &msg.progname,
        out,
        err,
        msg.verbosity != Verbosity::Silent,
    )
}

/// message.c: message_strm: what xz says for the return code `e` stands
/// for. Never `XzError`'s own `Display`.
pub(crate) fn strm(e: &XzError) -> Vec<u8> {
    let text: &str = match e {
        XzError::Mem { .. } => return enomem(),
        XzError::MemLimit { .. } => m::STRM_MEMLIMIT,
        XzError::Format => m::STRM_FORMAT,
        XzError::Options => m::STRM_OPTIONS,
        XzError::Data => m::STRM_DATA,
        XzError::BufError => m::STRM_BUF,
        XzError::UnsupportedCheck(_) => m::STRM_UNSUPPORTED_CHECK,
        XzError::Prog | XzError::Io(_) => m::BUG,
    };
    text.as_bytes().to_vec()
}

/// `strerror(ENOMEM)`, message_strm's `LZMA_MEM_ERROR`.
pub(crate) fn enomem() -> Vec<u8> {
    #[cfg(unix)]
    {
        crate::compat::host::errno_text(libc::ENOMEM)
    }
    #[cfg(not(unix))]
    {
        crate::compat::host::strerror(&std::io::Error::from(std::io::ErrorKind::OutOfMemory))
    }
}

/// tuklib_mbstr_nonprint.c: tuklib_mask_nonprint in the C locale: every
/// byte that is not printable ASCII becomes `?` (observed on 5.8.4 with
/// `LC_ALL=C`: `-F $'\xc3\xa9\x01\x7f'` prints `????`).
pub(crate) fn mask_nonprint(s: &[u8]) -> Vec<u8> {
    s.iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b } else { b'?' })
        .collect()
}

// ---- util.c ----

/// util.c: `enum nicestr_unit`'s `NICESTR_B` and `NICESTR_MIB`.
pub(crate) const NICESTR_B: usize = 0;
pub(crate) const NICESTR_MIB: usize = 2;

/// util.c: uint64_to_nicestr from `unit_min` to `NICESTR_TIB` (no
/// thousands separators in the C locale).
pub(crate) fn nicestr(value: u64, unit_min: usize, always_also_bytes: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let (shown, unit) = if unit_min == NICESTR_B && value < 10000 {
        (value.to_string().into_bytes(), NICESTR_B)
    } else {
        let mut d = value as f64;
        let mut unit = NICESTR_B;
        loop {
            d /= 1024.0;
            unit += 1;
            if !(unit < unit_min || (d > 9999.9 && unit < 4)) {
                break;
            }
        }
        (format!("{d:.1}").into_bytes(), unit)
    };
    printf(
        &mut out,
        m::NICESTR,
        &[&shown, m::NICESTR_UNITS[unit].as_bytes()],
    );
    if always_also_bytes && value >= 10000 {
        printf(&mut out, m::NICESTR_BYTES, &[value.to_string().as_bytes()]);
    }
    out
}

// ---- message.c: the progress line ----

/// What message.c's progress line is made of: the input's expected size
/// (0: unknown), how much of it was read (`in_pos`), both sides' counts
/// and the elapsed time in milliseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) expected_in_size: u64,
    pub(crate) in_pos: u64,
    pub(crate) compressed: u64,
    pub(crate) uncompressed: u64,
    pub(crate) elapsed: u64,
}

/// `%*s`: `s` right-aligned in `w` columns (`tuklib_mbstr_fw` is the
/// plain width for ASCII).
fn right(s: &[u8], w: usize) -> Vec<u8> {
    let mut v = vec![b' '; w.saturating_sub(s.len())];
    v.extend_from_slice(s);
    v
}

impl Progress {
    /// message.c: progress_percentage. Never 100.0 before the end.
    fn percentage(&self) -> Vec<u8> {
        if self.expected_in_size == 0 || self.in_pos > self.expected_in_size {
            return m::PROGRESS_PERCENT_UNKNOWN.as_bytes().to_vec();
        }
        let pct = self.in_pos as f64 / self.expected_in_size as f64 * 99.9;
        let mut out = Vec::new();
        printf(
            &mut out,
            m::PROGRESS_PERCENT,
            &[format!("{pct:.1}").as_bytes()],
        );
        out
    }

    /// message.c: progress_sizes: MiB while running, the plainest unit at
    /// the end (`last`).
    fn sizes(&self, last: bool) -> Vec<u8> {
        let unit_min = if last { NICESTR_B } else { NICESTR_MIB };
        let mut out = Vec::new();
        printf(
            &mut out,
            m::PROGRESS_SIZES,
            &[
                &nicestr(self.compressed, unit_min, false),
                &nicestr(self.uncompressed, unit_min, false),
            ],
        );
        let ratio = if self.uncompressed > 0 {
            self.compressed as f64 / self.uncompressed as f64
        } else {
            16.0
        };
        if ratio > 9.999 {
            printf(&mut out, m::PROGRESS_RATIO_OVER, &[]);
        } else {
            printf(
                &mut out,
                m::PROGRESS_RATIO,
                &[format!("{ratio:.3}").as_bytes()],
            );
        }
        out
    }

    /// message.c: progress_speed: nothing for the first three seconds, or
    /// past 999 GiB/s.
    fn speed(&self) -> Vec<u8> {
        if self.elapsed < 3000 {
            return Vec::new();
        }
        let mut speed = self.uncompressed as f64 / (self.elapsed as f64 * (1024.0 / 1000.0));
        let mut unit = 0;
        while speed > 999.0 {
            speed /= 1024.0;
            unit += 1;
            if unit == m::PROGRESS_SPEED_UNITS.len() {
                return Vec::new();
            }
        }
        let shown = if speed > 9.9 {
            format!("{speed:.0}")
        } else {
            format!("{speed:.1}")
        };
        let mut out = Vec::new();
        printf(
            &mut out,
            m::PROGRESS_SPEED,
            &[shown.as_bytes(), m::PROGRESS_SPEED_UNITS[unit].as_bytes()],
        );
        out
    }

    /// message.c: progress_time: `M:SS` or `H:MM:SS`; nothing under a
    /// second or past 9999 hours.
    fn time(&self) -> Vec<u8> {
        let mut seconds = (self.elapsed / 1000) as u32;
        if seconds == 0 || seconds > ((9999 * 60) + 59) * 60 + 59 {
            return Vec::new();
        }
        let mut minutes = seconds / 60;
        seconds %= 60;
        let mut out = Vec::new();
        let ss = format!("{seconds:02}");
        if minutes >= 60 {
            let hours = minutes / 60;
            minutes %= 60;
            printf(
                &mut out,
                m::PROGRESS_TIME_HMS,
                &[
                    hours.to_string().as_bytes(),
                    format!("{minutes:02}").as_bytes(),
                    ss.as_bytes(),
                ],
            );
        } else {
            printf(
                &mut out,
                m::PROGRESS_TIME_MS,
                &[minutes.to_string().as_bytes(), ss.as_bytes()],
            );
        }
        out
    }

    /// message.c: progress_remaining: an estimate once at least 512 KiB of
    /// a known size and eight seconds have passed, rounded up coarser the
    /// longer it is.
    fn remaining(&self) -> Vec<u8> {
        let (size, pos) = (self.expected_in_size, self.in_pos);
        if size == 0 || pos > size || pos < 1 << 19 || self.elapsed < 8000 {
            return Vec::new();
        }
        // C converts the double with `(uint32_t)`, undefined past 2^32 - 1
        // (an input of exabytes); the conversion here saturates, and such
        // an estimate is past 999 days either way.
        let est = (size - pos) as f64 * (self.elapsed as f64 / 1000.0) / pos as f64;
        let mut r = (est as u32).max(1);
        let n = |v: u32| v.to_string().into_bytes();
        let mut out = Vec::new();
        if r <= 10 {
            printf(&mut out, m::REMAINING_S, &[&n(r)]);
        } else if r <= 50 {
            r = r.div_ceil(5) * 5;
            printf(&mut out, m::REMAINING_S, &[&n(r)]);
        } else if r <= 590 {
            r = r.div_ceil(10) * 10;
            printf(&mut out, m::REMAINING_MIN_S, &[&n(r / 60), &n(r % 60)]);
        } else if r <= 59 * 60 {
            r = r.div_ceil(60);
            printf(&mut out, m::REMAINING_MIN, &[&n(r)]);
        } else if r <= 9 * 3600 + 50 * 60 {
            r = r.div_ceil(600) * 10;
            printf(&mut out, m::REMAINING_H_MIN, &[&n(r / 60), &n(r % 60)]);
        } else if r <= 23 * 3600 {
            r = r.div_ceil(3600);
            printf(&mut out, m::REMAINING_H, &[&n(r)]);
        } else if r <= 9 * 24 * 3600 + 23 * 3600 {
            r = r.div_ceil(3600);
            printf(&mut out, m::REMAINING_D_H, &[&n(r / 24), &n(r % 24)]);
        } else if r <= 999 * 24 * 3600 {
            r = r.div_ceil(24 * 3600);
            printf(&mut out, m::REMAINING_D, &[&n(r)]);
        }
        out
    }

    /// The five padded columns of a terminal line.
    fn columns(&self, pct: &[u8], last: bool, remaining: &[u8]) -> [Vec<u8>; 5] {
        [
            right(pct, 6),
            right(&self.sizes(last), 35),
            right(&self.speed(), 9),
            right(&self.time(), 10),
            right(remaining, 10),
        ]
    }

    /// message.c: message_progress_update's line, rewritten in place.
    pub(crate) fn update_line(&self) -> Vec<u8> {
        let c = self.columns(&self.percentage(), false, &self.remaining());
        let mut out = Vec::new();
        printf(
            &mut out,
            m::PROGRESS_LINE,
            &[&c[0], &c[1], &c[2], &c[3], &c[4]],
        );
        out
    }

    /// message.c: progress_flush's line: on a terminal (`automatic`) the
    /// indicator's own, ended; elsewhere `name`, then the fields that are
    /// known. `finished`: the file is done.
    pub(crate) fn final_line(&self, automatic: bool, finished: bool, name: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if automatic {
            let (pct, rem) = if finished {
                (m::PROGRESS_PERCENT_DONE.as_bytes().to_vec(), Vec::new())
            } else {
                (self.percentage(), self.remaining())
            };
            let c = self.columns(&pct, true, &rem);
            printf(
                &mut out,
                m::PROGRESS_FINAL_LINE,
                &[&c[0], &c[1], &c[2], &c[3], &c[4]],
            );
            return out;
        }
        printf(&mut out, m::PROGRESS_NAME, &[name]);
        if !finished {
            let pct = self.percentage();
            if pct.first() != Some(&b'-') {
                printf(&mut out, m::PROGRESS_PERCENT_FIELD, &[&pct]);
            }
        }
        out.extend_from_slice(&self.sizes(true));
        for field in [self.speed(), self.time()] {
            if !field.is_empty() {
                printf(&mut out, m::PROGRESS_FIELD, &[&field]);
            }
        }
        printf(&mut out, m::PROGRESS_END, &[]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(v: Vec<u8>) -> String {
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn messages_print_at_or_below_the_verbosity() {
        let mut msg = Messages::new(b"/x/xz");
        let mut err = Vec::new();
        msg.message(&mut err, Verbosity::Warning, "a %s", &[b"b"]);
        msg.message(&mut err, Verbosity::Verbose, "hidden", &[]);
        assert_eq!(text(err), "/x/xz: a b\n");
        msg.verbosity = Verbosity::Error;
        let mut err = Vec::new();
        msg.try_help(&mut err);
        msg.warning(&mut err, "w", &[]);
        assert!(err.is_empty());
        assert_eq!(msg.status, Status::Warning);
        msg.error(&mut err, "e", &[]);
        msg.warning(&mut err, "w", &[]);
        assert_eq!(
            (text(err), msg.status),
            ("/x/xz: e\n".into(), Status::Error)
        );
    }

    #[test]
    fn no_warn_turns_only_a_warning_into_success() {
        let mut msg = Messages::new(b"xz");
        msg.no_warn = true;
        assert_eq!(msg.final_status(), Status::Success);
        msg.set_status(Status::Warning);
        assert_eq!(msg.final_status(), Status::Success);
        msg.set_status(Status::Error);
        assert_eq!(msg.final_status(), Status::Error);
    }

    #[test]
    fn verbosity_saturates() {
        assert_eq!(Verbosity::Silent.decrease(), Verbosity::Silent);
        assert_eq!(Verbosity::Debug.increase(), Verbosity::Debug);
        assert_eq!(Verbosity::Warning.increase(), Verbosity::Verbose);
    }

    #[test]
    fn version_names_stuffr_and_the_robot_form_is_the_references() {
        let msg = Messages::new(b"xz");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(version(&msg, false, &mut out, &mut err), 0);
        assert_eq!(
            text(out),
            format!(
                "xz (stuffr {}; XZ Utils 5.8.4 compatible)\nliblzma 5.8.4\n",
                env!("CARGO_PKG_VERSION")
            )
        );
        let mut out = Vec::new();
        assert_eq!(version(&msg, true, &mut out, &mut err), 0);
        assert_eq!(text(out), "XZ_VERSION=50080042\nLIBLZMA_VERSION=50080042\n");
    }

    /// A standard output that cannot be flushed fails the exit, said
    /// unless silent.
    #[test]
    fn a_failed_flush_is_an_error() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::from_raw_os_error(28))
            }
        }
        let mut err = Vec::new();
        assert_eq!(exit(Status::Success, b"xz", &mut Broken, &mut err, true), 1);
        assert!(
            text(err.clone()).starts_with("xz: Writing to standard output failed: "),
            "{}",
            text(err)
        );
        let mut err = Vec::new();
        assert_eq!(
            exit(Status::Warning, b"xz", &mut Broken, &mut err, false),
            1
        );
        assert!(err.is_empty());
        assert_eq!(exit(Status::Error, b"xz", &mut Broken, &mut err, true), 1);
        assert!(err.is_empty());
    }

    #[test]
    fn masking_keeps_printable_ascii_only() {
        assert_eq!(mask_nonprint(b"\xc3\xa9x\x01\x7f ~"), b"??x?? ~");
    }

    // ---- the progress indicator (R4: fixed counters, a fixed clock) ----

    /// The fixtures recorded from xz 5.8.4: see
    /// `tests/fixtures/xz_progress/README.md` for how each was made.
    const TABLE: &str = include_str!("../../../tests/fixtures/xz_progress/table.txt");
    const TWO_FILES: &[u8] = include_bytes!("../../../tests/fixtures/xz_progress/two_files.txt");
    const CORRUPT: &[u8] = include_bytes!("../../../tests/fixtures/xz_progress/corrupt.txt");
    const STDIN: &[u8] = include_bytes!("../../../tests/fixtures/xz_progress/stdin.txt");
    const FILES: &[u8] = include_bytes!("../../../tests/fixtures/xz_progress/files.txt");
    const SIGNALS: &[u8] = include_bytes!("../../../tests/fixtures/xz_progress/signals.txt");

    thread_local! {
        static NOW: Cell<u64> = const { Cell::new(0) };
    }

    /// The test's clock: this thread's `NOW`.
    fn test_clock() -> u64 {
        NOW.with(Cell::get)
    }

    fn at(ms: u64) {
        NOW.with(|c| c.set(ms));
    }

    /// Messages as a run with standard error on a terminal (`automatic`)
    /// or not would hold them, at `v`, over `files` operands, with its own
    /// signal flag.
    fn progress_msgs(automatic: bool, v: Verbosity, files: u32) -> Messages {
        let mut msg = Messages::new(b"xz");
        msg.automatic = automatic;
        msg.verbosity = v;
        msg.files_total = files;
        msg.clock = test_clock;
        msg.requested = Box::leak(Box::new(AtomicBool::new(false)));
        msg
    }

    fn pos(in_bytes: u64, out_bytes: u64) -> xz_opts::Progress {
        xz_opts::Progress {
            in_bytes,
            out_bytes,
        }
    }

    /// A terminal line from its five columns, laid out as message.c's
    /// `"\r %*s %*s   %*s %10s   %10s"` and `end`.
    fn tty(c: [&str; 5], end: char) -> String {
        format!(
            "\r {:>6} {:>35}{:>12} {:>10}{:>13}{end}",
            c[0], c[1], c[2], c[3], c[4]
        )
    }

    fn unescape(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut it = s.bytes();
        while let Some(b) = it.next() {
            if b != b'\\' {
                out.push(b);
                continue;
            }
            out.push(match it.next() {
                Some(b'r') => b'\r',
                Some(b'n') => b'\n',
                Some(b'\\') => b'\\',
                other => panic!("bad escape {other:?}"),
            });
        }
        out
    }

    /// Every field of the line in every form: 0, 50 and 100 % of a known
    /// size and an unknown one, under a second, 1:02 and 1:02:03, the speed
    /// in each unit, the remaining time in each precision, the sizes in each
    /// unit. `table.txt` is message.c's own functions run over the same
    /// counters (`gen.c`).
    #[test]
    fn the_progress_line_is_message_c_s() {
        let mut rows = 0;
        for line in TABLE.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 7, "{line}");
            let n = |i: usize| f[i].parse::<u64>().unwrap();
            let p = Progress {
                expected_in_size: n(0),
                in_pos: n(1),
                compressed: n(2),
                uncompressed: n(3),
                elapsed: n(4),
            };
            let got = match f[5] {
                "update" => p.update_line(),
                "auto-finished" => p.final_line(true, true, b"f"),
                "auto-unfinished" => p.final_line(true, false, b"f"),
                "plain-finished" => p.final_line(false, true, b"f"),
                "plain-unfinished" => p.final_line(false, false, b"f"),
                k => panic!("kind {k}"),
            };
            assert_eq!(text(got), text(unescape(f[6])), "{} for {p:?}", f[5]);
            rows += 1;
        }
        assert_eq!(rows, 200);
    }

    /// One file compressed under `-v` with standard error a terminal, as
    /// coder.c drives message.c: the name as it starts, the final line.
    fn one_file(msg: &mut Messages, err: &mut Vec<u8>, name: Option<&[u8]>) {
        msg.filename(err, name);
        msg.progress_start(true, if name.is_some() { 1760 } else { 0 }, pos(0, 0));
        msg.progress_pos(pos(1760, 132));
        msg.progress_update(err);
        msg.progress_end(true, err);
    }

    /// `xz -v -k a b`, `xz -v < a`, and `--files` (the count unknown), on
    /// a terminal, under a second: byte for byte the reference's.
    #[test]
    fn terminal_runs_are_the_references() {
        at(0);
        let mut msg = progress_msgs(true, Verbosity::Verbose, 2);
        let mut err = Vec::new();
        one_file(&mut msg, &mut err, Some(b"a"));
        one_file(&mut msg, &mut err, Some(b"b"));
        assert_eq!(text(err), text(TWO_FILES.to_vec()));

        let mut msg = progress_msgs(true, Verbosity::Verbose, 1);
        let mut err = Vec::new();
        one_file(&mut msg, &mut err, None);
        assert_eq!(text(err), text(STDIN.to_vec()));

        let mut msg = progress_msgs(true, Verbosity::Verbose, 0);
        let mut err = Vec::new();
        one_file(&mut msg, &mut err, Some(b"a"));
        one_file(&mut msg, &mut err, Some(b"b"));
        assert_eq!(text(err), text(FILES.to_vec()));
    }

    /// `xz -dv -k cut.xz` on a terminal: the error ends the indicator's
    /// line first, and the end of the file prints it once more.
    #[test]
    fn an_error_ends_the_line_first() {
        at(0);
        let mut msg = progress_msgs(true, Verbosity::Verbose, 1);
        let mut err = Vec::new();
        msg.filename(&mut err, Some(b"cut.xz"));
        msg.progress_start(false, 100, pos(0, 0));
        msg.progress_pos(pos(100, 1760));
        msg.error(
            &mut err,
            m::NAME_COLON,
            &[b"cut.xz", m::STRM_BUF.as_bytes()],
        );
        msg.progress_end(false, &mut err);
        assert_eq!(text(err), text(CORRUPT.to_vec()));
        assert_eq!(msg.status, Status::Error);

        // Elsewhere, the same in the plain form.
        let mut msg = progress_msgs(false, Verbosity::Verbose, 1);
        let mut err = Vec::new();
        msg.filename(&mut err, Some(b"cut.xz"));
        msg.progress_start(false, 100, pos(0, 0));
        msg.progress_pos(pos(100, 1760));
        msg.error(
            &mut err,
            m::NAME_COLON,
            &[b"cut.xz", m::STRM_BUF.as_bytes()],
        );
        msg.progress_end(false, &mut err);
        assert_eq!(
            text(err),
            "cut.xz: 99.9 %, 100 B / 1760 B = 0.057\n\
             xz: cut.xz: Unexpected end of input\n\
             cut.xz: 99.9 %, 100 B / 1760 B = 0.057\n"
        );

        // Before any output on either side there is no line to end.
        let mut msg = progress_msgs(false, Verbosity::Verbose, 1);
        let mut err = Vec::new();
        msg.filename(&mut err, Some(b"e"));
        msg.progress_start(false, 0, pos(0, 0));
        msg.progress_pos(pos(32, 0));
        msg.error(&mut err, m::NAME_COLON, &[b"e", m::STRM_FORMAT.as_bytes()]);
        msg.progress_end(false, &mut err);
        assert_eq!(text(err), "xz: e: File format not recognized\n");
    }

    /// The automatic indicator: nothing for the first second, then a line
    /// each second, rewritten in place (`\r`); an error ends the line it
    /// left before speaking.
    #[test]
    fn the_indicator_updates_every_second() {
        at(10_000);
        let mut msg = progress_msgs(true, Verbosity::Verbose, 1);
        let mut err = Vec::new();
        msg.filename(&mut err, Some(b"big"));
        assert_eq!(text(err.clone()), "big (1/1)\n");
        err.clear();
        msg.progress_start(true, 4 << 20, pos(0, 0));
        let at_pos = |msg: &Messages, ms: u64, i: u64| {
            at(10_000 + ms);
            msg.progress_pos(pos(i, i / 2));
        };
        at_pos(&msg, 999, 1 << 20);
        msg.progress_update(&mut err);
        assert!(err.is_empty(), "a line before the first second");
        at_pos(&msg, 1000, 1 << 20);
        msg.progress_update(&mut err);
        at_pos(&msg, 1999, 2 << 20);
        msg.progress_update(&mut err);
        at_pos(&msg, 2000, 2 << 20);
        msg.progress_update(&mut err);
        let line = |i: u64, ms: u64| {
            Progress {
                expected_in_size: 4 << 20,
                in_pos: i,
                compressed: i / 2,
                uncompressed: i,
                elapsed: ms,
            }
            .update_line()
        };
        let mut want = line(1 << 20, 1000);
        want.extend(line(2 << 20, 2000));
        assert_eq!(text(err.clone()), text(want.clone()));
        assert_eq!(
            text(line(1 << 20, 1000)),
            tty(
                ["25.0 %", "0.5 MiB / 1.0 MiB = 0.500", "", "0:01", ""],
                '\r'
            )
        );
        at_pos(&msg, 2500, 3 << 20);
        msg.message(&mut err, Verbosity::Warning, "w", &[]);
        msg.progress_end(false, &mut err);
        let ended = Progress {
            expected_in_size: 4 << 20,
            in_pos: 3 << 20,
            compressed: 3 << 19,
            uncompressed: 3 << 20,
            elapsed: 2500,
        }
        .final_line(true, false, b"big");
        want.extend(&ended);
        want.extend(b"xz: w\n");
        want.extend(&ended);
        assert_eq!(text(err), text(want));
    }

    /// SIGINFO/SIGUSR1/SIGALRM at the default verbosity: the name once,
    /// then each signal's line on a line of its own; the shape of the
    /// reference's (`signals.txt`, whose figures depend on its timing) and
    /// the figures of message.c's line.
    #[test]
    fn a_signal_asks_for_a_line_at_any_verbosity() {
        at(0);
        let mut msg = progress_msgs(true, Verbosity::Warning, 1);
        let mut err = Vec::new();
        msg.filename(&mut err, Some(b"big"));
        msg.progress_start(true, 20_000_000, pos(0, 0));
        msg.progress_pos(pos(3_000_000, 1_500_000));
        msg.progress_update(&mut err);
        assert!(err.is_empty(), "a line without a signal");
        for ms in [500, 800] {
            at(ms);
            msg.requested.store(true, Ordering::Relaxed);
            msg.progress_update(&mut err);
            assert!(
                !msg.requested.load(Ordering::Relaxed),
                "the request is kept"
            );
        }
        msg.progress_end(true, &mut err);
        let line = |ms| {
            let mut l = Progress {
                expected_in_size: 20_000_000,
                in_pos: 3_000_000,
                compressed: 1_500_000,
                uncompressed: 3_000_000,
                elapsed: ms,
            }
            .update_line();
            l.push(b'\n');
            l
        };
        let mut want = b"big (1/1)\n".to_vec();
        want.extend(line(500));
        want.extend(line(800));
        assert_eq!(text(err.clone()), text(want));
        let shape = |b: &[u8]| -> Vec<u8> {
            let body = b.iter().position(|&c| c == b'\n').unwrap() + 1;
            let mut s = b[..body].to_vec();
            s.extend(
                b[body..]
                    .iter()
                    .map(|&c| if c == b'\r' || c == b'\n' { c } else { b'.' }),
            );
            s
        };
        assert_eq!(text(shape(&err)), text(shape(SIGNALS)));

        // Not on a terminal, the same; a request made between files waits
        // for the next one, unless the indicator updates itself.
        let mut msg = progress_msgs(false, Verbosity::Warning, 1);
        let mut err = Vec::new();
        msg.requested.store(true, Ordering::Relaxed);
        msg.filename(&mut err, None);
        msg.progress_start(false, 0, pos(0, 0));
        msg.progress_pos(pos(100, 1000));
        msg.progress_update(&mut err);
        msg.progress_end(true, &mut err);
        assert_eq!(
            text(err),
            tty(["--- %", "0.0 MiB / 0.0 MiB = 0.100", "", "", ""], '\r') + "\n"
        );
        let mut msg = progress_msgs(true, Verbosity::Verbose, 1);
        msg.requested.store(true, Ordering::Relaxed);
        msg.filename(&mut Vec::new(), Some(b"a"));
        msg.progress_start(false, 0, pos(0, 0));
        assert!(!msg.requested.load(Ordering::Relaxed));
    }

    /// `-v` elsewhere: one line per file once it ends, the name always in
    /// it (standard input's too), nothing at the start; `--robot` (only
    /// with `--list`) never names a file; under `--list` the names go to
    /// standard output whether or not standard error is a terminal.
    #[test]
    fn names_and_the_plain_final_line() {
        at(0);
        let mut msg = progress_msgs(false, Verbosity::Verbose, 1);
        let mut err = Vec::new();
        one_file(&mut msg, &mut err, None);
        assert_eq!(text(err), "(stdin): 132 B / 1760 B = 0.075\n");

        let mut msg = progress_msgs(false, Verbosity::Verbose, 2);
        let mut err = Vec::new();
        one_file(&mut msg, &mut err, Some(b"a\x01"));
        at(62_000);
        one_file(&mut msg, &mut err, Some(b"b"));
        assert_eq!(
            text(err),
            "a?: 132 B / 1760 B = 0.075\nb: 132 B / 1760 B = 0.075\n"
        );

        let mut msg = progress_msgs(true, Verbosity::Verbose, 2);
        msg.robot = true;
        let mut err = Vec::new();
        msg.filename(&mut err, Some(b"a"));
        assert!(err.is_empty());

        let mut msg = progress_msgs(false, Verbosity::Verbose, 0);
        msg.list = true;
        let mut out = Vec::new();
        msg.filename(&mut out, Some(b"a.xz"));
        msg.filename(&mut out, None);
        assert_eq!(text(out), "a.xz (1)\n\n(stdin) (2)\n");
        let mut msg = progress_msgs(false, Verbosity::Warning, 0);
        msg.list = true;
        let mut out = Vec::new();
        msg.filename(&mut out, Some(b"a.xz"));
        assert!(out.is_empty());
    }

    #[test]
    fn nicestr_from_mib() {
        assert_eq!(text(nicestr(132, NICESTR_MIB, false)), "0.0 MiB");
        assert_eq!(text(nicestr(10 << 20, NICESTR_MIB, false)), "10.0 MiB");
        assert_eq!(text(nicestr(9999, NICESTR_B, false)), "9999 B");
    }
}
