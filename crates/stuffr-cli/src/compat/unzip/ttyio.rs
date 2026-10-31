//! `ttyio.c`: the password prompt (`getp()`, the `ATH_BEO_UNX` one that
//! reads `/dev/tty`), the pager's key (`zgetch()`, `FGETCH(0)`) and the
//! screen size (`screensize()`). Apple's tree has upstream's file
//! unchanged, and no Ubuntu patch touches it.
//!
//! The terminal's mode is changed through [`TtyMode`], which puts it back
//! on every path (ruling T11-1); a typed password lives in a [`Password`],
//! zeroed when it is dropped and never printed.
//!
//! Under `Host::Sandbox` there is no terminal: [`getp`] answers as `open()`
//! of `/dev/tty` failing (R7), [`zgetch`] reads the run's standard input
//! and [`screensize`] gives `ioctl()`'s failure answer.

#[cfg(unix)]
use std::io::Write;

use super::Uz;
#[cfg(unix)]
use super::messages as m;
use crate::compat::host::Host;
#[cfg(unix)]
use crate::compat::host::TtyMode;

/// crypt.h:IZ_PWLEN, the password buffer's size less its terminator
/// (`getp()` is given `IZ_PWLEN+1`).
#[cfg(unix)]
pub(crate) const IZ_PWLEN: usize = 80;

/// A password, given with `-P` or typed at the prompt: zeroed when dropped,
/// so it is kept no longer than the run needs it (`G.key` lives for one
/// archive, as the C's does).
pub(crate) struct Password(Vec<u8>);

impl Password {
    /// `bytes`, kept until dropped.
    pub(crate) fn new(bytes: &[u8]) -> Password {
        Password(bytes.to_vec())
    }

    /// `bytes` itself, taken over without a copy (zip's `-P` value as the
    /// option parser returned it), so no unzeroed copy is left behind.
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Password {
        Password(bytes)
    }

    /// The password as `init_keys()` reads it: a C string, up to its first
    /// NUL.
    pub(crate) fn key(&self) -> &[u8] {
        match self.0.iter().position(|&b| b == 0) {
            Some(n) => &self.0[..n],
            None => &self.0,
        }
    }

    /// `*pwbuf == '\0'`: the answer was empty (or began with a NUL).
    pub(crate) fn is_empty_answer(&self) -> bool {
        self.0.first().is_none_or(|&b| b == 0)
    }

    /// Zero the bytes held, then forget them (`i = 0` before a retry).
    /// Volatile writes, so the zeroing is not optimised away as dead
    /// stores before the buffer is freed.
    fn clear(&mut self) {
        wipe(&mut self.0);
        self.0.clear();
    }
}

/// Zero `bytes` with volatile writes, so the zeroing is not optimised away
/// as dead stores before the memory is freed or reused: for a copy of a
/// password that is not a [`Password`] (zip's `-lf` redaction).
pub(crate) fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference to a byte of
        // the slice.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

impl Drop for Password {
    fn drop(&mut self) {
        // The whole capacity: what a shorter later answer left past its end
        // was zeroed by `clear`, so the live bytes are all that is left.
        self.clear();
    }
}

impl std::fmt::Debug for Password {
    /// Never shows the password itself.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(..)")
    }
}

/// Why [`getp`] has no password: `getp()` returning `NULL`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PwError {
    /// `open(_PATH_TTY)` failed: no controlling terminal (a sandbox, cron).
    NoTerminal,
    /// ruling: T11-3. The terminal hung up while the prompt read it.
    #[cfg(unix)]
    HungUp,
}

/// What one `read(f, &c, 1)` gave.
#[cfg(unix)]
enum Got {
    Byte(u8),
    /// It returned 0 (a `^D`), or a non-terminal at its end.
    Nothing,
    /// The terminal is gone: `read()` failed, or returned 0 with `poll()`
    /// reporting a hang-up.
    Gone,
}

/// `read(f, &c, 1)`, retried when a signal interrupts it.
#[cfg(unix)]
fn read_one(fd: libc::c_int) -> Got {
    let mut b = 0u8;
    loop {
        // SAFETY: a one-byte read into a byte we own.
        let n = unsafe { libc::read(fd, (&mut b as *mut u8).cast(), 1) };
        if n == 1 {
            return Got::Byte(b);
        }
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Got::Gone;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on one pollfd we own, without waiting.
        let r = unsafe { libc::poll(&mut pfd, 1, 0) };
        let hung = libc::POLLHUP | libc::POLLERR | libc::POLLNVAL;
        return if r > 0 && pfd.revents & hung != 0 {
            Got::Gone
        } else {
            Got::Nothing
        };
    }
}

// port: ttyio.c:getp
/// `getp(m, p, IZ_PWLEN+1)`: `prompt` on standard error, then a line read
/// from `/dev/tty` with echo off; a line longer than the buffer is asked
/// for again after "(line too long--try again)". The newline is not part
/// of the answer.
pub(crate) fn getp(uz: &mut Uz, prompt: &[u8]) -> Result<Password, PwError> {
    if matches!(uz.host, Host::Sandbox(_)) {
        return Err(PwError::NoTerminal);
    }
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // turn off echo on tty
        // SAFETY: a NUL-terminated path; the descriptor, if any, is owned
        // by the `OwnedFd` below, which closes it (`close(f)`).
        let f = unsafe { libc::open(m::PATH_TTY.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if f == -1 {
            return Err(PwError::NoTerminal);
        }
        // SAFETY: `f` is a descriptor we just opened and own.
        let f = unsafe { OwnedFd::from_raw_fd(f) };
        getp_on(&mut *uz.err, f.as_raw_fd(), prompt, IZ_PWLEN + 1)
    }
    #[cfg(not(unix))]
    {
        // No `/dev/tty` off unix (R8): as when it cannot be opened.
        let _ = prompt;
        Err(PwError::NoTerminal)
    }
}

/// [`getp`]'s loop over the open terminal `f`, keeping `n` bytes of a line
/// (the newline included).
///
/// ruling: T11-2. The C ignores `read()`'s result: a read that gives nothing
/// leaves `c` as it was and stores it again (defined: `abc^D` then `d` is
/// `abccd` on macOS, whose terminal returns 0 for a `^D` ending a non-empty
/// line; Linux's returns nothing there). Before the first byte of a line
/// `c` is uninitialised; the binaries take that as an empty answer, so it
/// reads as a newline here. A terminal that has hung up returns nothing
/// for ever, which the C stores for ever: here it ends the prompt
/// ([`PwError::HungUp`], ruling T11-3).
#[cfg(unix)]
pub(crate) fn getp_on(
    err: &mut dyn Write,
    f: libc::c_int,
    prompt: &[u8],
    n: usize,
) -> Result<Password, PwError> {
    let mut p = Password(Vec::with_capacity(n));
    let mut w: &[u8] = b"";
    loop {
        let _ = err.write_all(w); // warning if back again
        let _ = err.write_all(prompt); // prompt
        let _ = err.flush();
        p.clear();
        {
            let _echo = TtyMode::set(f, |t| t.c_lflag &= !libc::ECHO); // echoff(f)
            let mut c: Option<u8> = None;
            loop {
                // read line, keeping n
                match read_one(f) {
                    Got::Byte(b) => c = Some(b),
                    Got::Nothing => {
                        c.get_or_insert(b'\n');
                    }
                    Got::Gone => return Err(PwError::HungUp),
                }
                let ch = c.unwrap_or(b'\n');
                if p.0.len() < n {
                    p.0.push(ch);
                }
                if ch == b'\n' {
                    break;
                }
            }
        } // echon()
        let _ = err.write_all(m::GETP_NEWLINE.as_bytes());
        let _ = err.flush();
        w = m::LINE_TOO_LONG.as_bytes();
        if p.0.last() == Some(&b'\n') {
            break;
        }
    }
    // terminate at newline
    if let Some(last) = p.0.last_mut() {
        *last = 0;
    }
    p.0.pop();
    Ok(p)
}

// port: ttyio.c:zgetch
/// `FGETCH(0)`: one key from standard input, with the terminal (if it is
/// one) in cbreak mode without echo for the read. `None` at the end of
/// input or on an error: the C's `c` is then uninitialised, ruled on by
/// its caller (`fileio::more_pause`).
pub(crate) fn zgetch(uz: &mut Uz) -> Option<u8> {
    #[cfg(unix)]
    if matches!(uz.host, Host::Real) {
        let _cbreak = TtyMode::set(0, |t| {
            t.c_cc[libc::VMIN] = 1; // need only one char to return read()
            t.c_cc[libc::VTIME] = 0; // no timeout
            t.c_lflag &= !(libc::ICANON | libc::ECHO); // canonical mode off, echo off
        });
        return match read_one(0) {
            Got::Byte(b) => Some(b),
            Got::Nothing | Got::Gone => None,
        };
    }
    // A sandbox's standard input is one stream of bytes, shared with the
    // questions' `fgets()`; off unix (R8) so is the process's, which the
    // questions may hold.
    let input = uz.stdin();
    let c = *input.fill_buf().ok()?.first()?;
    input.consume(1);
    Some(c)
}

// port: ttyio.c:screensize
/// `screensize(&rows, &cols)`: standard output's window size
/// (`TIOCGWINSZ`), a zero dimension read as 24 rows or 80 columns; when
/// the ioctl fails (not a terminal, a sandbox), 24 by 80.
pub(crate) fn screensize(host: &Host) -> (i32, i32) {
    #[cfg(unix)]
    if matches!(host, Host::Real) {
        // SAFETY: winsize is plain data, filled by the ioctl.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: TIOCGWINSZ writes one winsize we own.
        if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 {
            let rows = if ws.ws_row > 0 {
                i32::from(ws.ws_row)
            } else {
                24
            };
            let cols = if ws.ws_col > 0 {
                i32::from(ws.ws_col)
            } else {
                80
            };
            return (rows, cols);
        }
    }
    let _ = host;
    // VT-100 assumed to be minimal hardware
    (24, 80)
}

#[cfg(all(test, unix))]
mod tests;
