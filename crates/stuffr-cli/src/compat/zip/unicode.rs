//! Ubuntu's `UNICODE_SUPPORT` (fileio.c's Unicode functions and
//! zipfile.c's Unicode Path extra field): what zip does with a name that is
//! not ASCII. Apple's build has none of it; every caller asks
//! [`flavour::unicode_support`](super::flavour::unicode_support) first.
//!
//! **The locale.** zip.c, zipnote.c, zipsplit.c and zipcloak.c call
//! `setlocale(LC_CTYPE, "en_US.UTF-8")` and nothing else (`SETLOCALE(LC_CTYPE,
//! "")` is a no-op without `_MBCS`): the environment's locale never
//! matters. Where `en_US.UTF-8` is installed (the reference image, CI's
//! runner, macOS) the run is `using_utf8` and its `mbstowcs`/`wctomb` are
//! glibc's UTF-8; where it is not, the C locale stays, and no name but an
//! ASCII one converts (measured with `LOCPATH` pointing nowhere: no bit 11,
//! no Unicode path field). [`utf8_locale`] asks the C library whether that
//! locale loads (`newlocale`, which leaves the process's locale alone); a
//! sandbox is the reference image.
//!
//! The conversions are modelled, not delegated to the C library, so the
//! answer is glibc's on every host (probe 2026-10-26, glibc 2.39
//! `en_US.UTF-8`): `mbstowcs` takes UTF-8 sequences of one to six bytes,
//! rejects overlong forms and surrogates, accepts code points past
//! U+10FFFF; `wctomb` refuses only surrogates. zip's own UTF-8 coder
//! (`ucs4_char_from_utf8`, `utf8_from_ucs4_char`) accepts overlong forms and
//! surrogates and writes U+007F as the two bytes `C1 BF`.
//!
//! **Undefined behaviour (deviation 28).** Where the C converts a string
//! that does not convert and then reads through the NULL it got back
//! (`utf8_to_local_string`, `utf8_to_escape_string`,
//! `local_to_escape_string`), and where a Unicode path field with an empty
//! name makes it copy the entry's not-yet-set name, both crash with SIGSEGV
//! and zip's handler answers `Interrupted (aborting)`, exit 9. The
//! functions here return `None` there and the callers give that answer
//! without the crash ([`segv`]).

use super::Zr;
use super::messages::{self as m, printf};
use super::readzip::{cstr, get_extra_field, lg, sh};
use crate::compat::host::Host;

/// zipfile.c:UTF8_PATH_EF_TAG, the Unicode Path extra field (`up`).
pub(crate) const UTF8_PATH_EF_TAG: u16 = 0x7075;
/// The UTF-8 flag of the general-purpose bits.
pub(crate) const UTF8_BIT: u16 = 1 << 11;

/// Whether `setlocale(LC_CTYPE, "en_US.UTF-8")` succeeds (zip's
/// `using_utf8`): the C library's answer under `Host::Real` on unix, true
/// in a sandbox (the reference image has the locale), false off unix.
pub(crate) fn utf8_locale(host: &Host) -> bool {
    if !matches!(host, Host::Real) {
        return true;
    }
    real_utf8_locale()
}

#[cfg(unix)]
fn real_utf8_locale() -> bool {
    // SAFETY: `newlocale` takes a NUL-terminated name and a null base and
    // returns a locale object or null; the object is freed at once and the
    // process's own locale is never touched.
    unsafe {
        let l = libc::newlocale(
            libc::LC_CTYPE_MASK,
            c"en_US.UTF-8".as_ptr(),
            std::ptr::null_mut(),
        );
        if l.is_null() {
            return false;
        }
        libc::freelocale(l);
        true
    }
}

#[cfg(not(unix))]
fn real_utf8_locale() -> bool {
    false
}

/// fileio.c:is_ascii_string (false for NULL, as there).
pub(crate) fn is_ascii(s: Option<&[u8]>) -> bool {
    s.is_some_and(|s| cstr(s).iter().all(|&c| c <= 0x7f))
}

/// `mbstowcs` of the C string `s` in the run's locale (`utf8`: glibc's
/// `en_US.UTF-8`, else the C locale): `None` when a byte sequence does not
/// convert (fileio.c:local_to_wide_string's NULL).
// port: fileio.c:local_to_wide_string
pub(crate) fn local_to_wide(utf8: bool, s: &[u8]) -> Option<Vec<u32>> {
    let s = cstr(s);
    let mut w = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let lead = s[i];
        if lead < 0x80 {
            w.push(u32::from(lead));
            i += 1;
            continue;
        }
        if !utf8 {
            return None;
        }
        let (n, min, first) = match lead {
            0xc2..=0xdf => (2, 0x80, lead & 0x1f),
            0xe0..=0xef => (3, 0x800, lead & 0x0f),
            0xf0..=0xf7 => (4, 0x1_0000, lead & 0x07),
            0xf8..=0xfb => (5, 0x20_0000, lead & 0x03),
            0xfc..=0xfd => (6, 0x400_0000, lead & 0x01),
            _ => return None,
        };
        if i + n > s.len() {
            return None;
        }
        let mut c = u32::from(first);
        for &t in &s[i + 1..i + n] {
            if t & 0xc0 != 0x80 {
                return None;
            }
            c = (c << 6) | u32::from(t & 0x3f);
        }
        if c < min || (0xd800..=0xdfff).contains(&c) {
            return None;
        }
        w.push(c);
        i += n;
    }
    Some(w)
}

/// `wctomb` of `c` in the run's locale: `None` for -1.
fn wctomb(utf8: bool, c: u32) -> Option<Vec<u8>> {
    if c <= 0x7f {
        return Some(vec![c as u8]);
    }
    if !utf8 || (0xd800..=0xdfff).contains(&c) || c > 0x7fff_ffff {
        return None;
    }
    let mut b = Vec::with_capacity(6);
    utf8_encode(c, &mut b);
    Some(b)
}

/// The UTF-8 bytes of `c` (up to six), the standard form.
fn utf8_encode(c: u32, b: &mut Vec<u8>) {
    let n = match c {
        0..=0x7f => {
            b.push(c as u8);
            return;
        }
        0x80..=0x7ff => 2,
        0x800..=0xffff => 3,
        0x1_0000..=0x1f_ffff => 4,
        0x20_0000..=0x3ff_ffff => 5,
        _ => 6,
    };
    let lead_mask: u8 = match n {
        2 => 0xc0,
        3 => 0xe0,
        4 => 0xf0,
        5 => 0xf8,
        _ => 0xfc,
    };
    b.push(lead_mask | (c >> (6 * (n - 1))) as u8);
    for k in (0..n - 1).rev() {
        b.push(0x80 | ((c >> (6 * k)) & 0x3f) as u8);
    }
}

/// fileio.c:wide_char_to_escape_string: `#U` and four hex digits for a
/// character of up to two bytes, else `#L` and six (its low three bytes).
// port: fileio.c:wide_char_to_escape_string
pub(crate) fn wide_char_to_escape(c: u32) -> Vec<u8> {
    if c < 0x1_0000 {
        format!("#U{:04x}", c).into_bytes()
    } else {
        format!("#L{:06x}", c & 0xff_ffff).into_bytes()
    }
}

/// fileio.c:wide_to_local_string: each character as the locale writes it,
/// an escape where it cannot (or, with `-UN escape`, for anything but
/// ASCII).
// port: fileio.c:wide_to_local_string
pub(crate) fn wide_to_local(utf8: bool, escape_all: bool, w: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(w.len());
    for &c in w.iter().take_while(|&&c| c != 0) {
        let b = wctomb(utf8, c);
        match b {
            Some(b) if escape_all && !(b.len() == 1 && b[0] <= 0x7f) => {
                out.extend_from_slice(&wide_char_to_escape(c));
            }
            Some(b) => out.extend_from_slice(&b),
            None => out.extend_from_slice(&wide_char_to_escape(c)),
        }
    }
    out
}

/// fileio.c:wide_to_escape_string: printable ASCII as is, everything else
/// escaped.
// port: fileio.c:wide_to_escape_string
pub(crate) fn wide_to_escape(w: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(w.len());
    for &c in w.iter().take_while(|&&c| c != 0) {
        if (0x20..0x7f).contains(&c) {
            out.push(c as u8);
        } else {
            out.extend_from_slice(&wide_char_to_escape(c));
        }
    }
    out
}

/// fileio.c:utf8_to_wide_string (zip's own decoder, `ucs4_char_from_utf8`):
/// `None` for a sequence it cannot read. Overlong forms and surrogates
/// pass.
// port: fileio.c:utf8_to_ucs4_string
pub(crate) fn utf8_to_wide(s: &[u8]) -> Option<Vec<u32>> {
    let s = cstr(s);
    let mut w = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let lead = s[i];
        let n = match lead {
            0x00..=0x7f => 1,
            0x80..=0xbf => return None,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            0xf8..=0xfb => 5,
            0xfc..=0xfd => 6,
            _ => return None,
        };
        // the trailing bytes are checked before any is used (a NUL ends
        // the string, and is not a trailing byte)
        for k in 1..n {
            let t = *s.get(i + k)?;
            if !(0x80..0xc0).contains(&t) {
                return None;
            }
        }
        let mut c = if n == 1 {
            u32::from(lead)
        } else {
            u32::from(lead & (0x7f >> n))
        };
        for &t in &s[i + 1..i + n] {
            c = (c << 6) | u32::from(t & 0x3f);
        }
        w.push(c);
        i += n;
    }
    Some(w)
}

/// fileio.c:wide_to_utf8_string (`utf8_from_ucs4_char`): `None` for a
/// character past 31 bits. U+007F is written `C1 BF`, as the C does.
// port: fileio.c:utf8_from_ucs4_char
pub(crate) fn wide_to_utf8(w: &[u32]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(w.len());
    for &ch in w.iter().take_while(|&&c| c != 0) {
        if ch > 0x7fff_ffff {
            return None;
        }
        if ch < 0x7f {
            out.push(ch as u8);
            continue;
        }
        let mut trailing = 0u32;
        let mut leadmask: u32 = 0x80;
        let mut leadbits: u32 = 0x3f;
        let mut tch = ch;
        loop {
            trailing += 1;
            leadmask = (leadmask >> 1) | 0x80;
            leadbits >>= 1;
            tch >>= 6;
            if tch & !leadbits == 0 {
                break;
            }
        }
        out.push((leadmask | (ch >> (6 * trailing))) as u8);
        for k in (0..trailing).rev() {
            out.push((0x80 | ((ch >> (6 * k)) & 0x3f)) as u8);
        }
    }
    Some(out)
}

/// fileio.c:local_to_utf8_string: `None` when the name does not convert.
pub(crate) fn local_to_utf8(utf8: bool, s: &[u8]) -> Option<Vec<u8>> {
    wide_to_utf8(&local_to_wide(utf8, s)?)
}

/// fileio.c:utf8_to_local_string: `None` is the C's crash (a name zip's
/// decoder cannot read).
pub(crate) fn utf8_to_local(utf8: bool, escape_all: bool, s: &[u8]) -> Option<Vec<u8>> {
    Some(wide_to_local(utf8, escape_all, &utf8_to_wide(s)?))
}

/// fileio.c:utf8_to_escape_string: `None` is the C's crash.
pub(crate) fn utf8_to_escape(s: &[u8]) -> Option<Vec<u8>> {
    Some(wide_to_escape(&utf8_to_wide(s)?))
}

/// fileio.c:local_to_escape_string: `None` is the C's crash (a name the
/// locale cannot convert).
pub(crate) fn local_to_escape(utf8: bool, s: &[u8]) -> Option<Vec<u8>> {
    Some(wide_to_escape(&local_to_wide(utf8, s)?))
}

/// The answer of a run whose C crashes on a NULL from the functions above
/// (SIGSEGV, which the handler answers `Interrupted (aborting)`, exit 9;
/// deviation 28): zip's blank line and error, or the helpers'.
pub(crate) fn segv(z: &mut Zr) -> super::Exit {
    if z.program == "zip" {
        super::scan::crashed(z)
    } else {
        super::readzip::null_out_crash(z)
    }
}

/// zipfile.c:add_Unicode_Path_local_extra_field (and its central twin):
/// the Unicode Path field for `uname` in `extra`, where a field of the
/// same length is, else at the end. An old field of another length is
/// taken out first (deviation 28: the C's copy of what follows it runs
/// four bytes long).
// port: zipfile.c:add_Unicode_Path_local_extra_field
pub(crate) fn add_unicode_path_field(extra: &mut Vec<u8>, iname: &[u8], uname: &[u8]) {
    let uname = cstr(uname);
    let ulen = uname.len() as u16;
    let data_len = 1u16.wrapping_add(4).wrapping_add(ulen);
    let mut field = Vec::with_capacity(usize::from(data_len) + 4);
    field.extend_from_slice(&UTF8_PATH_EF_TAG.to_le_bytes());
    field.extend_from_slice(&data_len.to_le_bytes());
    field.push(1);
    let mut crc = flate2::Crc::new();
    crc.update(cstr(iname));
    field.extend_from_slice(&crc.sum().to_le_bytes());
    field.extend_from_slice(uname);
    match get_extra_field(UTF8_PATH_EF_TAG, extra) {
        None => extra.extend_from_slice(&field),
        Some(at) => {
            let blocksize = usize::from(sh(extra, at + 2));
            let end = (at + 4 + blocksize).min(extra.len());
            if blocksize == usize::from(data_len) && end - at == field.len() {
                extra[at..end].copy_from_slice(&field);
            } else {
                extra.drain(at..end);
                extra.extend_from_slice(&field);
            }
        }
    }
}

/// Which reader of a Unicode Path field: the central directory
/// (`read_Unicode_Path_entry`, which also prints `unicode_mismatch = N` on
/// a mismatch; its entry has no name or oname yet), `-FF`'s match of a
/// central header (the same function, the entry's names set), a local
/// header copied (`zipcopy`'s, whose name is set), or `readlocal`'s
/// (whose is not).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathReader<'a> {
    Central,
    /// `-FF`: the entry's oname, and its name for a field with none.
    CentralFix(&'a [u8]),
    Copy,
    ReadLocal,
}

/// zipfile.c:read_Unicode_Path_entry / read_Unicode_Path_local_entry: the
/// UTF-8 name a Unicode Path field in `extra` gives the entry stored as
/// `iname`, `None` when there is none or it is skipped (with the warning
/// `-UN` asks for). `Err` ends the run: `-UN quit` on a mismatch
/// (`ZE_FORM`, `Unicode path error`) or the C's crash on a field with no
/// name where the entry's name is not set yet (deviation 28). A field
/// shorter than it says is read as zeros past its end (deviation 28).
// port: zipfile.c:read_Unicode_Path_entry
pub(crate) fn read_unicode_path(
    z: &mut Zr,
    extra: &[u8],
    iname: &[u8],
    reader: PathReader<'_>,
) -> Result<Option<Vec<u8>>, super::Exit> {
    let Some(at) = get_extra_field(UTF8_PATH_EF_TAG, extra) else {
        return Ok(None);
    };
    let mut head = extra[at..].to_vec();
    head.resize(head.len().max(9), 0);
    let elen = sh(&head, 2);
    let version = head[4];
    // the entry's oname is not set yet but under -FF (glibc's `(null)`)
    let oname: &[u8] = match reader {
        PathReader::CentralFix(o) => o,
        _ => b"(null)",
    };
    if version > 1 {
        z.zipwarn(m::UNICODE_VERSION_SKIP.as_bytes(), oname);
        return Ok(None);
    }
    let chksum = lg(&head, 5);
    let mut crc = flate2::Crc::new();
    crc.update(cstr(iname));
    if crc.sum() != chksum {
        if matches!(reader, PathReader::Central | PathReader::CentralFix(_)) {
            let mut l = Vec::new();
            printf(
                &mut l,
                m::UNICODE_MISMATCH_DEBUG,
                &[z.o.unicode_mismatch.to_string().as_bytes()],
            );
            z.stdout_write(&l);
        }
        match z.o.unicode_mismatch {
            1 => z.zipwarn(m::UNICODE_MISMATCH_WARN.as_bytes(), oname),
            0 => {
                let mut l = Vec::new();
                printf(&mut l, m::UNICODE_MISMATCH_QUIT, &[oname]);
                z.zipwarn(&l, b"");
                return Err(z.ziperr(super::readzip::ZE_FORM, m::UNICODE_PATH_ERROR.as_bytes()));
            }
            _ => {}
        }
        return Ok(None);
    }
    let ulen = elen.wrapping_sub(5);
    if ulen == 0 {
        // the standard path is UTF-8: strcpy of the entry's name
        return match reader {
            PathReader::Copy => Ok(Some(cstr(iname).to_vec())),
            PathReader::CentralFix(_) => Ok(Some(cstr(iname).to_vec())),
            _ => Err(segv(z)),
        };
    }
    let from = (at + 9).min(extra.len());
    let to = (at + 9 + usize::from(ulen)).min(extra.len());
    // strncpy: up to the first NUL
    Ok(Some(cstr(&extra[from..to]).to_vec()))
}

#[cfg(test)]
mod tests;
