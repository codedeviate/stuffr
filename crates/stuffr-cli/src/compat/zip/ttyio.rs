//! zip's `ttyio.c`: the password prompt (`getp()`, the `ATH_BEO_UNX` one
//! that reads `/dev/tty` with echo off), and the random bytes of an
//! encryption header. zip's `ttyio.c` is unzip's (Apple's tree and
//! upstream's are the same file, and no Ubuntu patch touches it), so the
//! prompt's loop is unzip's port (`unzip::ttyio::getp_on`): the prompt on
//! standard error, a line read a byte at a time keeping `IZ_PWLEN + 1`
//! bytes, `(line too long--try again)` and the prompt again for a longer
//! one, a newline to standard error after each line. The terminal's mode
//! is put back on every path (`host::TtyMode`), also by zip's interrupt
//! handler (`host::install_zip_abort`), as `echon()` does.
//!
//! Under `Host::Sandbox` there is no terminal: [`getp`] answers as
//! `open()` of `/dev/tty` failing (the tests can type answers through
//! `TYPED`, test builds only).

use crate::compat::host::Host;
use crate::compat::unzip::ttyio::Password;

use super::Zr;

/// crypt.h:IZ_PWLEN: the password buffer is `IZ_PWLEN + 1` bytes.
pub(crate) const IZ_PWLEN: usize = 80;

#[cfg(test)]
thread_local! {
    /// The answers a sandboxed test types at the prompts, in order; none
    /// left is no terminal.
    pub(crate) static TYPED: std::cell::RefCell<std::collections::VecDeque<Vec<u8>>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

// port: ttyio.c:getp
/// `getp(prompt, buf, IZ_PWLEN+1)`: the answer typed at the controlling
/// terminal, `None` where the C returns `NULL` (no terminal to open; a
/// terminal that hangs up meanwhile, ruling T11-3 of unzip's port).
pub(crate) fn getp(z: &mut Zr, prompt: &[u8]) -> Option<Password> {
    if matches!(z.host, Host::Sandbox(_)) {
        #[cfg(test)]
        if let Some(answer) = TYPED.with(|t| t.borrow_mut().pop_front()) {
            let _ = z.err.write_all(prompt);
            let _ = z.err.write_all(b"\n");
            return Some(Password::new(&answer));
        }
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // SAFETY: a NUL-terminated path; the descriptor, if any, is owned
        // by the `OwnedFd` below, which closes it (`close(f)`).
        let f = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if f == -1 {
            return None;
        }
        // SAFETY: `f` is a descriptor we just opened and own.
        let f = unsafe { OwnedFd::from_raw_fd(f) };
        crate::compat::unzip::ttyio::getp_on(&mut *z.err, f.as_raw_fd(), prompt, IZ_PWLEN + 1).ok()
    }
    #[cfg(not(unix))]
    {
        // no `/dev/tty` off unix: as when it cannot be opened
        let _ = prompt;
        None
    }
}

/// The ten random bytes of an encryption header (crypt.c:crypthead's
/// `rand()` draws): from the system's generator (`/dev/urandom`), never
/// from a seeded `rand()`. Off unix, or if that cannot be read, the
/// standard library's randomly keyed hasher.
pub(crate) fn random_header() -> [u8; 10] {
    let mut b = [0u8; 10];
    #[cfg(unix)]
    {
        use std::io::Read;
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut b))
            .is_ok()
        {
            return b;
        }
    }
    use std::hash::{BuildHasher, Hasher};
    let s = std::collections::hash_map::RandomState::new();
    for (i, chunk) in b.chunks_mut(8).enumerate() {
        let mut h = s.build_hasher();
        h.write_usize(i);
        let v = h.finish().to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    b
}
