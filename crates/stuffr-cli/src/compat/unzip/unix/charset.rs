//! ubuntu: 20-unzip60-alt-iconv-utf8.patch. Its `unix/unix.c` part:
//! `OEM_CP` and `ISO_CP` (`-O`/`-I`, `MAX_CP_NAME` bytes each), their
//! default from the locale (`init_conversion_charsets()`), and the
//! conversion of a name or comment from one of them into the locale's
//! character set through `iconv(3)` (`charset_to_intern()`), which
//! `Ext_ASCII_TO_Native()` calls in place of upstream's OEM 850 table
//! (`fileio::ext_ascii_to_native`).
//!
//! Deviation 5: `iconv(3)` is the system's (glibc on Linux, libiconv on
//! macOS), called under `Host::Real` on unix only.
//! ruling: T14-4. Under `Host::Sandbox` (the fuzz target) the locale is C
//! and no codeset is asked of the system: no default `OEM_CP` is guessed and
//! nothing is converted, `-O`/`-I` or not, so a sandbox run never depends on
//! the host's iconv tables. That is what Ubuntu's own build answers under C
//! for any name that is not plain ASCII (CP850 to `ANSI_X3.4-1968` fails, and
//! a failed conversion leaves the name as stored).
//! ruling: T14-5. Off unix (Windows) there is no `iconv(3)`: the options
//! are parsed as Ubuntu parses them and every conversion answers as one
//! Ubuntu cannot make, silently and leaving the name as stored (the patch
//! prints nothing when `iconv_open()` fails).

use super::super::{Host, Uz};

/// unxcfg.h's `MAX_CP_NAME`: the size of `OEM_CP` and `ISO_CP`.
pub(crate) const MAX_CP_NAME: usize = 25;

/// unix.c's `dos_charset_map`: the locale's character set (compared
/// ignoring case) and the code page DOS, Windows and OS/2 archives are
/// taken to use there.
const DOS_CHARSET_MAP: &[(&[u8], &[u8])] = &[
    (b"ANSI_X3.4-1968", b"CP850"),
    (b"ISO-8859-1", b"CP850"),
    (b"CP1252", b"CP850"),
    (b"UTF-8", b"CP866"),
    (b"KOI8-R", b"CP866"),
    (b"KOI8-U", b"CP866"),
    (b"ISO-8859-5", b"CP866"),
];

/// `strncpy(CP, s, sizeof(CP))`: the first `MAX_CP_NAME` bytes of `s`, up
/// to its NUL.
/// ruling: T14-6. A name of `MAX_CP_NAME` bytes or more leaves the C array
/// without its NUL, and reading it runs into the next global (undefined
/// behaviour); here it is its first 25 bytes, what the C reads when the
/// byte after the array is a NUL (probe: `-O` of 24 and of 29 bytes both
/// convert nothing, as no such character set exists).
pub(crate) fn cp_name(s: &[u8]) -> Vec<u8> {
    let s = s.split(|&b| b == 0).next().unwrap_or(&[]);
    s[..s.len().min(MAX_CP_NAME)].to_vec()
}

// port: unix.c:init_conversion_charsets
/// Try to guess the default value of `OEM_CP` based on the current locale
/// (only if it is not already set). `ISO_CP` is left alone.
pub(crate) fn init_conversion_charsets(uz: &mut Uz) {
    if uz.o.oem_cp.is_empty()
        && let Some(local) = local_charset(&uz.host)
        && let Some((_, archive)) = DOS_CHARSET_MAP
            .iter()
            .find(|(l, _)| l.eq_ignore_ascii_case(&local))
    {
        uz.o.oem_cp = cp_name(archive);
    }
}

// port: unix.c:charset_to_intern
/// Convert the C string `string` from `from` to the current locale using
/// `iconv()`; `None` (leave the string intact) when `from` is empty, the
/// conversion cannot be opened, or `iconv()` fails anywhere in it (an
/// invalid or incomplete sequence, or more than `buflen - 1` bytes of
/// output). The result is what `strncpy(string, buf, buflen)` leaves: the
/// output up to its first NUL. `buflen` is the C's `FILNAMSIZ` (`OUTBUFSIZ +
/// 1` is larger on unix).
pub(crate) fn charset_to_intern(
    host: &Host,
    string: &[u8],
    from: &[u8],
    buflen: usize,
) -> Option<Vec<u8>> {
    if from.is_empty() {
        return None;
    }
    let local = local_charset(host)?;
    let string = string.split(|&b| b == 0).next().unwrap_or(&[]);
    let out = iconv(&local, from, string, buflen)?;
    let end = out.iter().position(|&b| b == 0).unwrap_or(out.len());
    Some(out[..end].to_vec())
}

/// `nl_langinfo(CODESET)` in the locale `fileio::init_locale` set, under
/// `Host::Real` on unix; `None` elsewhere (T14-4, T14-5).
fn local_charset(host: &Host) -> Option<Vec<u8>> {
    if !matches!(host, Host::Real) {
        return None;
    }
    real_codeset()
}

#[cfg(unix)]
fn real_codeset() -> Option<Vec<u8>> {
    // SAFETY: `nl_langinfo` returns a pointer to a NUL-terminated string
    // valid until the next locale call; the run is single-threaded and it
    // is copied out at once.
    unsafe {
        let p = libc::nl_langinfo(libc::CODESET);
        if p.is_null() {
            return None;
        }
        Some(std::ffi::CStr::from_ptr(p).to_bytes().to_vec())
    }
}

#[cfg(not(unix))]
fn real_codeset() -> Option<Vec<u8>> {
    None
}

/// One `iconv_open(to, from)` / `iconv()` / `iconv_close()` over `input`,
/// as the C makes it: no final flush, output into a zeroed `buflen`-byte
/// buffer whose last byte is never written. `None` when the conversion
/// cannot be opened or `iconv()` returns `(size_t)-1`.
#[cfg(unix)]
// apple: libc marks its bindings of macOS's libiconv deprecated (to drop
// the link in libc 1.0); glibc's are not. They are the system's iconv(3)
// deviation 5 names.
#[allow(deprecated)]
fn iconv(to: &[u8], from: &[u8], input: &[u8], buflen: usize) -> Option<Vec<u8>> {
    use std::ffi::CString;
    let to = CString::new(to).ok()?;
    let from = CString::new(from).ok()?;
    let mut inbuf = input.to_vec();
    let mut buf = vec![0u8; buflen.max(1)];
    // SAFETY: both names are NUL-terminated `CString`s that outlive the call.
    let cd = unsafe { libc::iconv_open(to.as_ptr(), from.as_ptr()) };
    if cd as isize == -1 {
        return None;
    }
    let mut s = inbuf.as_mut_ptr().cast::<libc::c_char>();
    let mut slen: libc::size_t = inbuf.len();
    let mut d = buf.as_mut_ptr().cast::<libc::c_char>();
    let mut dlen: libc::size_t = buf.len() - 1;
    // SAFETY: `cd` is the open descriptor; `s` points at `slen` readable
    // bytes of `inbuf` and `d` at `dlen` writable bytes of `buf` (one byte
    // short of its end), both alive for the call; iconv moves the pointers
    // and counts within those bounds only.
    let r = unsafe { libc::iconv(cd, &mut s, &mut slen, &mut d, &mut dlen) };
    // SAFETY: `cd` came from `iconv_open` above and is closed once.
    unsafe { libc::iconv_close(cd) };
    if r == libc::size_t::MAX {
        return None;
    }
    Some(buf)
}

#[cfg(not(unix))]
fn iconv(_to: &[u8], _from: &[u8], _input: &[u8], _buflen: usize) -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_charset_name_is_kept_to_its_first_25_bytes() {
        assert_eq!(cp_name(b"CP866"), b"CP866");
        assert_eq!(cp_name(&[b'x'; 30]), vec![b'x'; 25]);
        assert_eq!(cp_name(b""), b"");
    }

    #[test]
    fn a_sandbox_converts_nothing() {
        use crate::compat::host::{SANDBOX_OUTPUT_CAP, Sandbox};
        use std::sync::atomic::AtomicU64;
        use std::sync::{Arc, Mutex};
        let host = Host::Sandbox(Sandbox {
            dir: std::env::temp_dir(),
            stdin: None,
            stdout: Arc::new(Mutex::new(Vec::new())),
            budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
            reads: Arc::new(Mutex::new(Default::default())),
        });
        assert_eq!(charset_to_intern(&host, b"\x82.txt", b"CP866", 4096), None);
        assert_eq!(local_charset(&host), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn iconv_converts_and_refuses_as_glibc_does() {
        let cp866 = iconv(b"UTF-8", b"CP866", b"\x82t", 4096).unwrap();
        assert_eq!(&cp866[..4], "\u{412}t".as_bytes());
        // output longer than the buffer: E2BIG, the string stays
        assert_eq!(iconv(b"UTF-8", b"CP866", &[0x82; 3000], 4096), None);
        assert_eq!(iconv(b"ANSI_X3.4-1968", b"CP850", b"\x82", 4096), None);
        assert_eq!(iconv(b"UTF-8", b"NO-SUCH-SET", b"a", 4096), None);
    }
}
