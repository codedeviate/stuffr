//! `message.c` (errors, warnings, the help texts and `--version`),
//! `main.c`'s exit status (`set_exit_status`, `--no-warn`) and
//! `tuklib_exit.c`, from XZ Utils 5.8.4 (0BSD, `LICENSE-xz`).
//!
//! The progress indicator, the `--robot` error forms and the signal-driven
//! progress line are Task 8's; this module holds what argument handling
//! and the coder need.

use std::io::Write;

use stuffr::xz_opts::{Filter, XzError};

use super::hardware::round_up_to_mib;
use super::messages::{self as m, printf};
use super::options;

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

/// The state `message.c` and `main.c` keep in globals: the program name,
/// the verbosity, the exit status so far and `--no-warn`.
pub(crate) struct Messages {
    /// `progname`: the full `argv[0]` (`tuklib_progname_init`).
    pub(crate) progname: Vec<u8>,
    pub(crate) verbosity: Verbosity,
    /// `exit_status` in main.c.
    pub(crate) status: Status,
    /// `-Q`/`--no-warn`.
    pub(crate) no_warn: bool,
}

impl Messages {
    pub(crate) fn new(progname: &[u8]) -> Self {
        Messages {
            progname: progname.to_vec(),
            verbosity: Verbosity::Warning,
            status: Status::Success,
            no_warn: false,
        }
    }

    /// `message(v, fmt, ...)`: `"progname: "`, the text and a newline, when
    /// `v` is at most the verbosity.
    pub(crate) fn message(&self, err: &mut dyn Write, v: Verbosity, fmt: &str, args: &[&[u8]]) {
        if v <= self.verbosity {
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
}
