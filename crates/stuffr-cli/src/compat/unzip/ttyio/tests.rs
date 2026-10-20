//! `getp_on` and `TtyMode` over a pseudo-terminal: the answer, the retry of
//! a line too long, and the terminal's mode put back on every path.

use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::compat::host::{TtyMode, restore_saved_tty};

/// One `TtyMode` exists at a time in a process: these tests take turns.
static LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// A pseudo-terminal: (master, slave).
fn pty() -> (OwnedFd, OwnedFd) {
    let (mut m, mut s) = (-1, -1);
    // SAFETY: openpty fills two descriptors we then own; the name, mode and
    // size arguments may be null.
    let rc = unsafe {
        libc::openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: both descriptors were just returned by openpty.
    unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) }
}

fn lflag(fd: &OwnedFd) -> libc::tcflag_t {
    // SAFETY: termios is plain data filled by tcgetattr.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr writes the termios we own.
    assert_eq!(unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut t) }, 0);
    t.c_lflag
}

/// Standard error for `getp_on`, shared with the typing thread.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn text(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

/// Types `lines` on the master, line k once the prompt has been written
/// k+1 times and the terminal has echo off: the read is then waiting, past
/// `echoff()`'s flush.
fn type_at_prompts(master: &OwnedFd, slave: &OwnedFd, err: &Shared, lines: &[&[u8]]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    for (k, line) in lines.iter().enumerate() {
        loop {
            let prompts = err.text().windows(4).filter(|w| w == b"pw: ").count();
            if prompts > k && lflag(slave) & libc::ECHO == 0 {
                break;
            }
            assert!(Instant::now() < deadline, "prompt {k} never waited");
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut f = std::fs::File::from(master.try_clone().unwrap());
        f.write_all(line).unwrap();
    }
}

/// `getp_on` over `slave` with `lines` typed at its prompts: the answer and
/// what it wrote to standard error.
fn getp_typed(
    master: &OwnedFd,
    slave: &OwnedFd,
    lines: &'static [&'static [u8]],
) -> (Result<Password, PwError>, Vec<u8>) {
    let err = Shared::default();
    let typer = {
        let (m, s, e) = (
            master.try_clone().unwrap(),
            slave.try_clone().unwrap(),
            err.clone(),
        );
        std::thread::spawn(move || type_at_prompts(&m, &s, &e, lines))
    };
    let mut w = err.clone();
    let r = getp_on(&mut w, slave.as_raw_fd(), b"pw: ", IZ_PWLEN + 1);
    typer.join().unwrap();
    (r, err.text())
}

#[test]
fn a_typed_password_is_returned_and_echo_comes_back() {
    let _l = lock();
    let (master, slave) = pty();
    let before = lflag(&slave);
    assert_ne!(before & libc::ECHO, 0);
    let (r, err) = getp_typed(&master, &slave, &[b"secret\n"]);
    assert_eq!(r.unwrap().key(), b"secret");
    assert_eq!(err, b"pw: \n");
    assert_eq!(lflag(&slave), before);
}

#[test]
fn a_line_longer_than_the_buffer_is_asked_for_again() {
    let _l = lock();
    let (master, slave) = pty();
    const LONG: &[u8] =
        b"ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp\n";
    const FITS: &[u8] =
        b"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n";
    assert_eq!((LONG.len(), FITS.len()), (82, 81));
    let (r, err) = getp_typed(&master, &slave, &[LONG, FITS]);
    assert_eq!(r.unwrap().key(), &FITS[..80]);
    assert_eq!(err, b"pw: \n(line too long--try again)\npw: \n");
}

/// The brief's pin: the mode is put back when the read fails. A
/// write-only descriptor of the terminal takes `TtyMode` (its mode is the
/// terminal's) but cannot be read, so `getp_on` ends with an error inside
/// the echo-off scope.
#[test]
fn the_terminal_mode_is_restored_after_an_error() {
    let _l = lock();
    let (_master, slave) = pty();
    let before = lflag(&slave);
    let path = {
        let mut buf = [0 as libc::c_char; 256];
        // SAFETY: ttyname_r writes the slave's name, NUL-terminated, into
        // our buffer of `buf.len()` bytes.
        let rc = unsafe { libc::ttyname_r(slave.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
        assert_eq!(rc, 0);
        // SAFETY: ttyname_r NUL-terminated the name within `buf`.
        unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_owned()
    };
    // SAFETY: a NUL-terminated path; the descriptor is owned below.
    let wo = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NOCTTY) };
    assert!(wo >= 0, "{}", std::io::Error::last_os_error());
    // SAFETY: `wo` was just opened.
    let wo = unsafe { OwnedFd::from_raw_fd(wo) };
    let mut err = Vec::new();
    let r = getp_on(&mut err, wo.as_raw_fd(), b"pw: ", IZ_PWLEN + 1);
    assert_eq!(r.unwrap_err(), PwError::HungUp);
    assert_eq!(lflag(&slave), before, "echo left off after the error");
}

#[test]
fn the_terminal_mode_is_restored_when_a_panic_unwinds() {
    let _l = lock();
    let (_master, slave) = pty();
    let before = lflag(&slave);
    let fd = slave.as_raw_fd();
    let r = std::panic::catch_unwind(|| {
        let _m = TtyMode::set(fd, |t| t.c_lflag &= !(libc::ECHO | libc::ICANON)).unwrap();
        assert_eq!(
            lflag(&slave) & (libc::ECHO | libc::ICANON),
            0,
            "the mode was not changed"
        );
        panic!("inside the read");
    });
    assert!(r.is_err());
    assert_eq!(lflag(&slave), before);
}

/// The interrupt handler's restore (`restore_saved_tty`, what
/// `on_interrupt_exit_code` calls before `_exit`) puts back the mode a live
/// `TtyMode` saved; with none alive it does nothing.
#[test]
fn the_signal_path_restores_the_saved_mode() {
    let _l = lock();
    let (_master, slave) = pty();
    let before = lflag(&slave);
    let m = TtyMode::set(slave.as_raw_fd(), |t| t.c_lflag &= !libc::ECHO).unwrap();
    assert_eq!(lflag(&slave) & libc::ECHO, 0);
    restore_saved_tty();
    assert_eq!(lflag(&slave), before);
    drop(m);
    // SAFETY: termios is plain data filled by tcgetattr.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr and tcsetattr on the slave we own.
    unsafe {
        libc::tcgetattr(slave.as_raw_fd(), &mut t);
        t.c_lflag &= !libc::ECHO;
        libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &t);
    }
    restore_saved_tty(); // no TtyMode alive: leaves the terminal alone
    assert_eq!(lflag(&slave) & libc::ECHO, 0);
}

/// ruling: T11-2. A `^D` that ends a non-empty line repeats the last byte
/// where the terminal returns 0 for it (macOS), as the C's ignored `read()`
/// result does; one at the start of a line is an empty answer.
#[cfg(target_os = "macos")]
#[test]
fn an_end_of_file_read_repeats_the_last_byte() {
    let _l = lock();
    let (master, slave) = pty();
    let (r, _) = getp_typed(&master, &slave, &[b"abc\x04d\n"]);
    assert_eq!(r.unwrap().key(), b"abccd");
    let (r, _) = getp_typed(&master, &slave, &[b"\x04"]);
    assert!(r.unwrap().is_empty_answer());
}

#[test]
fn a_password_shows_nothing_and_is_zeroed() {
    let p = Password::new(b"hunter2\0tail");
    assert_eq!(p.key(), b"hunter2");
    assert_eq!(format!("{p:?}"), "Password(..)");
    let mut q = Password::new(b"abc");
    q.clear();
    assert!(q.is_empty_answer());
}
