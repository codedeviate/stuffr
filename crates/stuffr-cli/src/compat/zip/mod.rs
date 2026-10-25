//! The zip family (`zip`, `zipcloak`, `zipnote`, `zipsplit`): stuffr
//! behaving as the platform's Info-ZIP Zip 3.0.
//!
//! **A port** of Info-ZIP Zip 3.0 (July 5th 2008; the Info-ZIP licence,
//! `LICENSE-infozip`: this is an altered version, marked as such by every
//! banner) in two builds, Apple's (`zip-33`, `zip30/`, default on macOS and
//! the BSDs) and Ubuntu's (`3.0-13ubuntu0.2`, default elsewhere), chosen by
//! [`default_flavour`] or `STUFFR_ZIP_FLAVOR=apple|ubuntu` ([`run`] reads
//! it once; anything else in it is refused, exit 1, in stuffr's own
//! words). Each ported function carries `// port: <file>.c:<function>`;
//! Ubuntu's differences are checks in `flavour.rs`, one function per
//! behaviour. Every string is in `messages.rs`.
//!
//! **What is here (Task 4 of 0.19.0):** the names, the flavour, the
//! command lines of all four programs (`cli.rs`: `zip.c`'s option table and
//! `main()`'s loop and checks, `fileio.c`'s `get_option()`, `util.c`'s
//! `envargs()` for `ZIPOPT` and `ZIP`, and the three helpers' own
//! parsing), and every help, licence, version and option-listing screen.
//!
//! **Task 5 (`scan.rs`, `unix.rs`):** which names `zip` operates on: the
//! operands and `-R`, `-i`/`-x`/`-R` patterns, `-r`, `-j`, `-k`, `-D`, `-y`,
//! `-t`/`-tt`, `-@`, duplicates and the archive itself, and `-sf`'s listing
//! (`fileio.c`, `util.c`'s matcher, `unix/unix.c`); also the unix extra
//! fields Task 6 writes (`unix::extra_fields`). A command line that gets
//! past all of it and would archive answers `messages::NOT_BUILT` (exit 1)
//! until Task 6 writes the archive, and the helpers' work answers it until
//! theirs.
//!
//! **Zr is `G`:** zip's globals are one value per run (`Zr`, with its
//! options `o`), so a sandboxed run ([`run_in_counted`]) touches nothing of
//! the process.
//!
//! Known deviations (the source of truth; the README and the spec mirror
//! this list):
//!
//! 1. SIGPIPE: [`run`] restores SIGPIPE's default action, as the other
//!    families do; under a parent that ignores SIGPIPE, zip sees `EPIPE`
//!    and stuffr still dies of the signal (the Rust runtime ignores it
//!    before `main`).
//! 2. The banner line of `-v` and the header line of each program's help
//!    name stuffr and say it is altered (Info-ZIP licence clause 3):
//!    `This is Zip 3.0 (July 5th 2008), by stuffr X.Y.Z (altered; original
//!    by Info-ZIP, with modifications by Apple Inc.).` (Ubuntu: `(altered;
//!    Debian's build, original by Info-ZIP)`), likewise `Zip 3.0 (July 5th
//!    2008), by stuffr ... Usage:` and the helpers' `ZipCloak 3.0 (July
//!    5th 2008), by stuffr ...`. `-v`'s `Compiled with` line is the
//!    recorded reference build's (Apple: macOS 27's), so another macOS
//!    build prints a different one.
//! 3. Undefined behaviour and endless loops are not reproduced (the
//!    record's rulings, in the code's `// ruling:` comments); 5 and 6 are
//!    the ones the command line meets.
//! 4. The encryption prompt (`zip -e`, `zipcloak`) is the later tasks';
//!    until then a terminal on standard error answers `NOT_BUILT`, and
//!    without one the answer is zip's own (`stderr is not a tty`, 16).
//! 5. `get_option`'s error text is built in a 50-byte buffer
//!    (`optionerr`'s `char optname[50]`, `sprintf`). An error about an
//!    option whose `'name' (description)` needs 50 bytes or more (`-lf`,
//!    `--output-file`, `--junk-paths=x`, `--recurse-patterns-`: 59 forms in
//!    all, listed by `cli/tests.rs`) aborts both references (Apple: SIGTRAP
//!    from `__sprintf_chk`, Ubuntu: glibc's "buffer overflow detected" and
//!    zip's SIGABRT handler, exit 9). stuffr prints the whole message,
//!    exit 16, as the C would with room.
//! 6. `-O` (`--output-file`) with no archive name at all: the C compares a
//!    NULL `in_path` (`namecmp(in_path, out_path)`) and dies of SIGSEGV,
//!    which zip's handler answers in both builds with a blank line and
//!    `zip error: Interrupted (aborting)`, exit 9. stuffr gives that answer
//!    without the dereference.
//! 7. The "Scanning files" progress message `newname` prints when a scan
//!    of 100 or more names takes over five seconds, with a dot every two
//!    seconds after, is not made (it depends on the clock, not on the
//!    names).
//! 8. A name that is `//host` or `//host/share` and nothing more makes
//!    `ex2in` dereference NULL in both references: SIGSEGV, which zip's
//!    handler answers with a blank line and `Interrupted (aborting)`, exit
//!    9. stuffr gives that answer without the dereference (as for 6), also
//!    for an `-i`/`-x`/`-R` pattern of that shape. The order of two equal
//!    names in the found list follows each libc's `qsort` (Ubuntu's stable
//!    merge sort, Apple's BSD quicksort ported in `scan.rs`); the port
//!    orders 6 of 4000 random arrays with many equal keys differently from
//!    macOS (a known gap: which of two equal names is dropped, when the
//!    same operand is given twice among many).

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::CountedRun;
use super::host::{self, Host, SANDBOX_OUTPUT_CAP, Sandbox};

pub(crate) mod cli;
pub(crate) mod flavour;
mod messages;
pub(crate) mod scan;
pub(crate) mod unix;

pub use flavour::Flavour;
use messages::{self as m, printf};

/// The environment variable that overrides [`default_flavour`].
const FLAVOR_VAR: &str = "STUFFR_ZIP_FLAVOR";

/// The exit codes the family can return (`ziperr.h`, the plan's Global
/// Constraints), for the `compat` fuzz target.
#[doc(hidden)]
pub const EXIT_CODES: &[i32] = &[
    0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19,
];

/// How a run ends: the exit code (`ziperr()`'s, `EXIT()`'s, or a screen
/// asked for with exit 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit {
    pub code: i32,
}

/// The flavour a build uses when `STUFFR_ZIP_FLAVOR` is unset or empty:
/// Apple on macOS and the BSDs, Ubuntu everywhere else, Windows included.
pub fn default_flavour() -> Flavour {
    if cfg!(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )) {
        Flavour::Apple
    } else {
        Flavour::Ubuntu
    }
}

/// The flavour `STUFFR_ZIP_FLAVOR`'s value selects: `apple` or `ubuntu`,
/// the default when unset or empty, and `Err(value)` for anything else.
pub(crate) fn flavour_from(value: Option<OsString>) -> Result<Flavour, OsString> {
    match value {
        None => Ok(default_flavour()),
        Some(v) if v.is_empty() => Ok(default_flavour()),
        Some(v) if v == "apple" => Ok(Flavour::Apple),
        Some(v) if v == "ubuntu" => Ok(Flavour::Ubuntu),
        Some(v) => Err(v),
    }
}

/// One run's state: zip's globals (`noisy`, `mesg`, `zipfile` and the
/// rest are in `o` and here), the message layer and the host.
pub(crate) struct Zr<'a> {
    /// The process, or a sandbox's stand-ins for it.
    pub(crate) host: Host,
    /// Which reference this run behaves as.
    pub(crate) flavour: Flavour,
    /// `getenv`: the process's environment, or a sandbox's stand-in.
    pub(crate) env: &'a dyn Fn(&str) -> Option<OsString>,
    /// Standard output, flushed after every message.
    pub(crate) out: BufWriter<Box<dyn Write + Send>>,
    /// Standard error.
    pub(crate) err: &'a mut dyn Write,
    /// The options (zip.c's globals; the helpers read `noisy` here too).
    pub(crate) o: cli::Options,
    /// `mesg` is standard error (the archive goes to standard output, or a
    /// helper keeps standard output for data).
    pub(crate) mesg_err: bool,
    /// `mesg_line_started`: a message began a line it has not ended.
    pub(crate) mesg_line_started: bool,
    /// The log file (`-lf`), once opened.
    pub(crate) log: Option<Box<dyn Write>>,
    /// `logfile_line_started`
    pub(crate) log_line_started: bool,
    /// `seen_doubledash`: the first `--` was met.
    pub(crate) seen_doubledash: bool,
    /// The program, as `ziperr` of a helper names it.
    pub(crate) program: &'static str,
}

impl<'a> Zr<'a> {
    pub(crate) fn new(
        host: Host,
        flavour: Flavour,
        program: &'static str,
        env: &'a dyn Fn(&str) -> Option<OsString>,
        err: &'a mut dyn Write,
    ) -> Zr<'a> {
        let out = host.out_writer(None);
        Zr {
            host,
            flavour,
            env,
            out,
            err,
            o: cli::Options::new(),
            mesg_err: false,
            mesg_line_started: false,
            log: None,
            log_line_started: false,
            seen_doubledash: false,
            program,
        }
    }

    /// Text written to standard output directly (`printf`, `puts`).
    pub(crate) fn stdout_write(&mut self, b: &[u8]) {
        let _ = self.out.write_all(b);
        let _ = self.out.flush();
    }

    /// Text written to `mesg` (`fprintf(mesg, ...)` + `fflush`).
    pub(crate) fn mesg_write(&mut self, b: &[u8]) {
        if self.mesg_err {
            let _ = self.err.write_all(b);
            let _ = self.err.flush();
        } else {
            self.stdout_write(b);
        }
    }

    /// Text written to the log file, when there is one.
    pub(crate) fn log_write(&mut self, b: &[u8]) {
        if let Some(l) = self.log.as_mut() {
            let _ = l.write_all(b);
            let _ = l.flush();
        }
    }

    /// zip.c:zipwarn: `\tzip warning: a b` to `mesg` (when noisy) and to
    /// the log.
    pub(crate) fn zipwarn(&mut self, a: &[u8], b: &[u8]) {
        let mut line = Vec::new();
        printf(&mut line, m::ZIP_WARNING, &[a, b]);
        if self.o.noisy {
            if self.mesg_line_started {
                self.mesg_write(b"\n");
            }
            self.mesg_write(&line);
            self.mesg_line_started = false;
        }
        if self.log.is_some() {
            if self.log_line_started {
                self.log_write(b"\n");
            }
            self.log_write(&line);
            self.log_line_started = false;
        }
    }

    /// zip.c:zipmessage: `a` and `b` as one line to `mesg` (when noisy) and
    /// the log.
    pub(crate) fn zipmessage(&mut self, a: &[u8], b: &[u8]) {
        let mut line = a.to_vec();
        line.extend_from_slice(b);
        line.push(b'\n');
        if self.o.noisy {
            if self.mesg_line_started {
                self.mesg_write(b"\n");
            }
            self.mesg_write(&line);
            self.mesg_line_started = false;
        }
        if self.log.is_some() {
            if self.log_line_started {
                self.log_write(b"\n");
            }
            self.log_write(&line);
            self.log_line_started = false;
        }
    }

    /// zip.c:ziperr: the message for `code` and `h`, to `mesg` and the log;
    /// the exit it ends the run with is returned.
    // port: zip.c:ziperr
    pub(crate) fn ziperr(&mut self, code: i32, h: &[u8]) -> Exit {
        self.ziperr_with(code, h, None)
    }

    /// [`Zr::ziperr`] for a code whose message also says why the system
    /// refused (`ZE_S_PERR`: `zip I/O error: <strerror>`).
    pub(crate) fn ziperr_os(&mut self, code: i32, h: &[u8], e: &io::Error) -> Exit {
        self.ziperr_with(code, h, Some(host::strerror(e)))
    }

    fn ziperr_with(&mut self, code: i32, h: &[u8], why: Option<Vec<u8>>) -> Exit {
        if self.mesg_line_started {
            self.mesg_write(b"\n");
            self.mesg_line_started = false;
        }
        if self.log.is_some() && self.log_line_started {
            self.log_write(b"\n");
            self.log_line_started = false;
        }
        let text = usize::try_from(code)
            .ok()
            .and_then(|c| m::ZIPERRORS.get(c))
            .copied()
            .unwrap_or("");
        let mut line = Vec::new();
        printf(&mut line, m::ZIP_ERROR, &[text.as_bytes(), h]);
        let mut io_line = Vec::new();
        if let Some(why) = &why {
            printf(&mut io_line, m::ZIP_IO_ERROR, &[why]);
            self.mesg_write(&io_line);
        }
        self.mesg_write(&line);
        if self.log.is_some() {
            if why.is_some() {
                io_line.push(b'\n');
                self.log_write(&io_line);
            }
            self.log_write(&line);
            self.log_line_started = false;
        }
        Exit { code }
    }

    /// The helpers' `ziperr` (`zipcloak error: text (h)`, to `mesg`).
    pub(crate) fn helper_err(&mut self, code: i32, h: &[u8]) -> Exit {
        let text = usize::try_from(code)
            .ok()
            .and_then(|c| m::ZIPERRORS.get(c))
            .copied()
            .unwrap_or("");
        let mut line = Vec::new();
        printf(
            &mut line,
            m::HELPER_ERROR,
            &[self.program.as_bytes(), text.as_bytes(), h],
        );
        self.mesg_write(&line);
        Exit { code }
    }

    /// stuffr's own answer to a command line whose work is not built yet.
    pub(crate) fn not_built(&mut self) -> Exit {
        let mut line = Vec::new();
        printf(
            &mut line,
            m::NOT_BUILT,
            &[
                self.program.as_bytes(),
                env!("CARGO_PKG_VERSION").as_bytes(),
            ],
        );
        let _ = self.err.write_all(&line);
        let _ = self.err.flush();
        Exit { code: 1 }
    }
}

/// A broken-down local time (`struct tm`, the fields zip reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tm {
    /// The full year (`tm_year + 1900`).
    pub(crate) year: i64,
    /// 0 to 11.
    pub(crate) mon: u32,
    pub(crate) mday: u32,
    pub(crate) hour: u32,
    pub(crate) min: u32,
    pub(crate) sec: u32,
    /// 0 is Sunday.
    pub(crate) wday: u32,
}

/// `localtime(&t)`: the process's zone under `Host::Real` on unix, UTC for a
/// sandbox (and for any other target).
pub(crate) fn localtime(host: &Host, t: i64) -> Tm {
    #[cfg(unix)]
    if matches!(host, Host::Real) {
        // SAFETY: `tm` is plain data that a successful `localtime_r` fills
        // in whole; both pointers are valid for the call.
        let tt = t as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
            return Tm {
                year: i64::from(tm.tm_year) + 1900,
                mon: tm.tm_mon as u32 % 12,
                mday: tm.tm_mday as u32,
                hour: tm.tm_hour as u32,
                min: tm.tm_min as u32,
                sec: tm.tm_sec as u32,
                wday: tm.tm_wday as u32 % 7,
            };
        }
    }
    let _ = host;
    // UTC, from the civil calendar
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mo <= 2 { y + 1 } else { y };
    Tm {
        year,
        mon: (mo - 1) as u32,
        mday: d as u32,
        hour: (secs / 3600) as u32,
        min: (secs / 60 % 60) as u32,
        sec: (secs % 60) as u32,
        wday: ((days + 4).rem_euclid(7)) as u32,
    }
}

/// `asctime(localtime(t))` with its newline: `Sun Sep 16 01:03:52 1973\n`.
/// A sandbox's zone is UTC; so is any other target's.
pub(crate) fn asctime(host: &Host, t: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let tm = localtime(host, t);
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {}\n",
        DAYS[tm.wday as usize], MONTHS[tm.mon as usize], tm.mday, tm.hour, tm.min, tm.sec, tm.year
    )
}

/// The current time as [`asctime`] shows it.
pub(crate) fn asctime_now(z: &Zr) -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    asctime(&z.host, t)
}

/// Entry point for `zip`, `zipcloak`, `zipnote` and `zipsplit`; `name` is
/// the canonical invoked name, `argv0` the program as invoked (`-sc` shows
/// it) and `args` the arguments after it.
pub fn run(name: &'static str, argv0: &OsStr, args: Vec<OsString>) -> ExitCode {
    // Deviation 1: as the other families.
    host::reset_sigpipe();
    let env = |k: &str| std::env::var_os(k);
    let mut err = io::stderr();
    let flavour = match flavour_from(env(FLAVOR_VAR)) {
        Ok(f) => f,
        Err(v) => {
            printf(
                &mut err,
                m::FLAVOR_REFUSED,
                &[name.as_bytes(), v.as_encoded_bytes()],
            );
            return ExitCode::from(1);
        }
    };
    let argv0 = if argv0.is_empty() {
        name.as_bytes()
    } else {
        argv0.as_encoded_bytes()
    };
    let code = main(flavour, name, argv0, &args, &env, Host::Real, &mut err);
    // The exit status is the code's low byte, as `exit()` makes it (every
    // code here is below 256).
    ExitCode::from(code as u8)
}

/// [`run`] without the process: operands resolve against `dir`, standard
/// input is `stdin` (a pipe of bytes), standard output and error are
/// captured and returned with the exit code, neither is a terminal, the
/// environment is not read (`ZIP` and `ZIPOPT` are unset;
/// `STUFFR_ZIP_FLAVOR` is not consulted), no signal is touched, and
/// standard output and output files share the sandbox's output budget.
/// For the fuzz target and the tests; not a stable interface.
#[doc(hidden)]
pub fn run_in(
    dir: &Path,
    name: &str,
    args: Vec<OsString>,
    stdin: &[u8],
    flavour: Flavour,
) -> (i32, Vec<u8>, Vec<u8>) {
    let (code, out, err, _) = run_in_counted(flavour, dir, name, &args, stdin);
    (code, out, err)
}

/// [`run_in`] in the shape the other families' sandboxed entries have, also
/// returning what each input read (empty until a task counts them).
#[doc(hidden)]
pub fn run_in_counted(
    flavour: Flavour,
    dir: &Path,
    name: &str,
    args: &[OsString],
    stdin: &[u8],
) -> CountedRun {
    let name: &'static str = match name {
        "zipcloak" => "zipcloak",
        "zipnote" => "zipnote",
        "zipsplit" => "zipsplit",
        _ => "zip",
    };
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let reads = Arc::new(Mutex::new(BTreeMap::new()));
    let host = Host::Sandbox(Sandbox {
        dir: dir.to_path_buf(),
        stdin: Some(stdin.to_vec()),
        stdout: stdout.clone(),
        budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
        reads: reads.clone(),
    });
    let mut err = Vec::new();
    let env = |_: &str| None;
    let code = main(flavour, name, name.as_bytes(), args, &env, host, &mut err);
    let out = std::mem::take(&mut *stdout.lock().unwrap_or_else(|p| p.into_inner()));
    let reads = std::mem::take(&mut *reads.lock().unwrap_or_else(|p| p.into_inner()));
    (code, out, err, reads)
}

/// The run below the process boundary. Returns the exit code.
fn main(
    flavour: Flavour,
    name: &'static str,
    argv0: &[u8],
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    host: Host,
    err: &mut dyn Write,
) -> i32 {
    let mut z = Zr::new(host, flavour, name, env, err);
    let args: Vec<Vec<u8>> = args.iter().map(|a| a.as_encoded_bytes().to_vec()).collect();
    let result = match name {
        "zipcloak" => cli::parse_cloak(&mut z, argv0, &args).map(|_| ()),
        "zipnote" => cli::parse_note(&mut z, &args).map(|_| ()),
        "zipsplit" => cli::parse_split(&mut z, &args).map(|_| ()),
        _ => cli::parse_zip(&mut z, argv0, &args),
    };
    let code = match result {
        Err(Exit { code }) => code,
        // A `zip` command line the checks accepted: the names, and (Task 6)
        // the archive.
        Ok(()) if name == "zip" => scan::run(&mut z).code,
        // The helpers' work is not built yet.
        Ok(()) => z.not_built().code,
    };
    let _ = z.out.flush();
    code
}

#[cfg(test)]
mod tests;
