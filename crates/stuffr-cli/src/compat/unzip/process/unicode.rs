//! ubuntu: -DUNICODE_SUPPORT -DUNICODE_WCHAR. process.c's Unicode part:
//! `getUnicodeData()`, which finds an entry's UTF-8 name in its Unicode
//! Path extra block (`0x7075`), and the conversions `do_string()` runs a
//! UTF-8 name through when the locale is not UTF-8 (or `-U` asks for
//! escapes): UTF-8 to UCS-4, then each character through the C library's
//! `wctomb()`, or as an escape (`#U00e9`, `#L01f600`) where the locale has
//! no encoding for it.
//!
//! ruling: T13-1. This code exists only in Ubuntu's build (Apple's has no
//! `UNICODE_SUPPORT`), so it has one form in any reference, Ubuntu's
//! patched one: CVE-2021-4217.patch (a Unicode block with no name read is
//! `PK_ERR`) and 28-cve-2022-0529-and-cve-2022-0530.patch (a name that is
//! not UTF-8 is "Unicode filename corrupt"; an escape that would overflow
//! the buffer is cut short with a warning) are ported as they apply, under
//! `// ubuntu:` comments, without a Task 14 hook: no flavour runs this
//! code without them.

use super::super::fileio;
use super::super::messages as m;
use super::super::{PK_COOL, PK_ERR, Uz};
use crate::compat::host::Host;

/// unzpriv.h's `EF_UNIPATH`: the Info-ZIP Unicode Path extra block.
const EF_UNIPATH: u16 = 0x7075;

/// The largest escape `wide_to_escape_string()` writes is 10 bytes
/// (`#L` and eight hex digits); `MAX_ESCAPE_BYTES` budgets 8 a character.
const MAX_ESCAPE_BYTES: usize = 8;

/// What `getUnicodeData()` leaves in `G.unipath_filename`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UniPath {
    /// `NULL`: no Unicode Path block, or one that failed its checks.
    None,
    /// `""`: the block says the standard name is UTF-8.
    Standard,
    /// The block's UTF-8 name (up to its first NUL).
    Name(Vec<u8>),
}

/// `ef[at]`, or 0 past the field's end.
/// ruling: T13-5. `getUnicodeData()` reads a block's version and checksum
/// (its first five bytes) and copies `eb_len - 5` bytes of name as an
/// unsigned short, so a block shorter than 5 bytes, last in its field,
/// reads past the field's heap buffer (undefined behaviour) and copies up
/// to 65535 bytes from there. Here a byte past the field is 0: such a
/// block's version is 0 and its name ends at the field's end. probe:
/// `unzip -l` of a block of length 0 (`s0.txt`) and one of length 3 with
/// version 1 (`s3.txt`) said "Unicode Path checksum invalid" for both in
/// one archive, and "Unicode Path version > 1" for `s0.txt` in another
/// laid out otherwise (the heap's stale bytes). Pinned by
/// `extract::tests::unicode_rulings`.
fn at(ef: &[u8], at: usize) -> u8 {
    ef.get(at).copied().unwrap_or(0)
}

// port: process.c:getUnicodeData
/// `getUnicodeData(ef_buf, ef_len)`: the extra field scanned for Unicode
/// Path blocks. A block of a version above 1, or whose checksum is not the
/// CRC of the entry's whole stored name (`G.filename_full`, `full`), is
/// reported and ends the scan with `PK_ERR` (which `do_string()` ignores),
/// keeping what an earlier block set; a later good block replaces an
/// earlier one. Returns the code and `G.unipath_filename`.
pub(crate) fn get_unicode_data(uz: &mut Uz, ef: &[u8], full: Option<&[u8]>) -> (i32, UniPath) {
    let mut unipath = UniPath::None;
    let mut ef = ef;
    while ef.len() >= 4 {
        let eb_id = fileio::makeword(ef);
        let eb_len = usize::from(fileio::makeword(&ef[2..]));
        if eb_len > ef.len() - 4 {
            // discovered some extra field inconsistency!
            break;
        }
        if eb_id == EF_UNIPATH {
            let mut offset = 4usize;
            let ulen = (eb_len as u16).wrapping_sub(5); // ush ULen = eb_len - 5
            // version
            let version = at(ef, offset);
            offset += 1;
            if version > 1 {
                // can do only version 1
                uz.info(0x401, m::UNICODE_VERSION_ERROR.as_bytes());
                return (PK_ERR, unipath);
            }
            // filename CRC
            let checksum = u32::from_le_bytes([
                at(ef, offset),
                at(ef, offset + 1),
                at(ef, offset + 2),
                at(ef, offset + 3),
            ]);
            offset += 4;
            // ubuntu: CVE-2021-4217.patch
            let Some(full) = full else {
                // Check if we have a unicode extra section but no filename
                // set
                return (PK_ERR, unipath);
            };
            // Compute 32-bit crc
            let mut crc = flate2::Crc::new();
            crc.update(fileio::c_str(full));
            // If the checksums's don't match then likely filename has been
            // modified and the Unicode Path is no longer valid.
            if crc.sum() != checksum {
                uz.info(0x401, m::UNICODE_MISMATCH_ERROR.as_bytes());
                return (PK_ERR, unipath);
            }
            // UTF-8 Path
            unipath = if ulen == 0 {
                // standard path is UTF-8 so use that
                UniPath::Standard
            } else {
                // UTF-8 path: strncpy() of ULen bytes, to the first NUL
                let name: Vec<u8> = (offset..offset + usize::from(ulen))
                    .map(|i| at(ef, i))
                    .take_while(|&b| b != 0)
                    .collect();
                if name.is_empty() {
                    UniPath::Standard
                } else {
                    UniPath::Name(name)
                }
            };
        }
        // Skip this extra field block
        ef = &ef[4 + eb_len..];
    }
    (PK_COOL, unipath)
}

// port: process.c:utf8_char_bytes
/// The length of the UTF-8 sequence `utf8` starts with (1 to 6), or `None`
/// for a trailing byte, an invalid lead byte, or a missing or out-of-range
/// trailing byte (the C's NUL ends it: `utf8` is a C string).
fn utf8_char_bytes(utf8: &[u8]) -> Option<usize> {
    let lead = at(utf8, 0);
    let r = match lead {
        0x00..=0x7f => 1,           // an ascii-7 character
        0x80..=0xbf => return None, // error: trailing byte without lead byte
        0xc0..=0xdf => 2,           // an 11 bit character
        0xe0..=0xef => 3,           // a 16 bit character
        0xf0..=0xf7 => 4,           // a 21 bit character (the most currently used)
        0xf8..=0xfb => 5,           // a 26 bit character (shouldn't happen)
        0xfc..=0xfd => 6,           // a 31 bit character (shouldn't happen)
        _ => return None,           // error: invalid lead byte
    };
    if (1..r).any(|t| !(0x80..0xc0).contains(&at(utf8, t))) {
        return None; // error: not enough valid trailing bytes
    }
    Some(r)
}

// port: process.c:utf8_to_ucs4_string
/// `utf8_to_wide_string()` (with `ucs4_char_from_utf8()`): the C string
/// `utf8` as UCS-4 characters, or `None` when it is not UTF-8.
pub(crate) fn utf8_to_wide_string(utf8: &[u8]) -> Option<Vec<u32>> {
    let mut wide = Vec::new();
    let mut s = utf8;
    loop {
        let bytes = utf8_char_bytes(s)?;
        let lead = at(s, 0);
        let mut ch = if bytes == 1 {
            u32::from(lead) // ascii-7
        } else {
            // lead byte of a multibyte sequence
            u32::from(lead & (0x7f >> bytes))
        };
        for t in 1..bytes {
            // consume trailing bytes
            ch = (ch << 6) | u32::from(at(s, t) & 0x3f);
        }
        if ch == 0 {
            return Some(wide);
        }
        wide.push(ch);
        s = &s[bytes.min(s.len())..];
    }
}

// port: process.c:wide_to_escape_string
/// `wide_to_escape_string(w)`: `#U` and four hex digits for a character of
/// up to two bytes, `#L` and two digits a byte for a wider one.
fn wide_to_escape_string(w: u32) -> Vec<u8> {
    let mut b = Vec::new();
    // get bytes in right to left order
    let mut v = w;
    while v != 0 {
        b.push((v % 0x100) as u8);
        v /= 0x100;
    }
    // either 2 bytes or 3 bytes
    let mut e = b"#".to_vec();
    if b.len() <= 2 {
        b.resize(2, 0);
        e.push(b'U');
    } else {
        e.push(b'L');
    }
    for byte in b.iter().rev() {
        e.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    e
}

// port: process.c:wide_to_local_string
/// `wide_to_local_string(wide, escape_all)`: each character in the
/// locale's multibyte encoding (`wctomb()`), or escaped where it has none;
/// with `escape_all` (`-U`), everything but ASCII escaped.
fn wide_to_local_string(uz: &mut Uz, wide: &[u32], escape_all: bool) -> Vec<u8> {
    // `MB_CUR_MAX` is at most 6 (glibc's UTF-8), below `MAX_ESCAPE_BYTES`
    let buffer_size = wide.len() * MAX_ESCAPE_BYTES + 1;
    let mut buffer: Vec<u8> = Vec::new();
    // set initial state if state-dependent encoding
    let _state_dependent = wctomb(uz, None);
    for &w in wide {
        // `sizeof(wchar_t)` is 4: no character takes the default one
        let mb = wctomb(uz, Some(w));
        if escape_all {
            match mb.as_deref() {
                // ASCII
                Some([c]) if *c <= 0x7f => buffer.push(*c),
                // use escape for wide character
                // ruling: T13-6. This branch appends the whole escape
                // (unpatched `strcat`), which can pass the buffer's end
                // (a 10-byte `#L` escape in a one-character name's 9
                // bytes: a heap overflow, undefined behaviour). probe:
                // `unzip -U -l` of a Unicode Path holding one 5-byte
                // character prints `*** buffer overflow detected ***:
                // terminated` (glibc's fortify check aborts it, and the
                // SIGABRT handler exits 80). Here the whole escape is
                // kept, as if the buffer had room.
                _ => buffer.extend_from_slice(&wide_to_escape_string(w)),
            }
        } else if let Some(mb) = mb {
            // multi-byte char
            buffer.extend_from_slice(&mb);
        } else {
            // no MB for this wide: use escape for wide character
            // ubuntu: 28-cve-2022-0529-and-cve-2022-0530.patch
            let escape = wide_to_escape_string(w);
            let room = buffer_size.saturating_sub(buffer.len() + 1);
            let n = if escape.len() > room {
                // Append escape string, as space allows.
                uz.info(0x401, m::UFILENAME_TOO_LONG_P1.as_bytes());
                room
            } else {
                escape.len()
            };
            buffer.extend_from_slice(&escape[..n]);
        }
    }
    buffer
}

// port: process.c:utf8_to_local_string
/// `utf8_to_local_string(utf8, escape_all)`: the C string `utf8` in the
/// locale's encoding; `None` when it is not UTF-8.
/// ubuntu: 28-cve-2022-0529-and-cve-2022-0530.patch (`NULL` for a name
/// that does not convert, where upstream went on with a null pointer).
pub(crate) fn utf8_to_local_string(uz: &mut Uz, utf8: &[u8], escape_all: bool) -> Option<Vec<u8>> {
    let wide = utf8_to_wide_string(utf8)?;
    Some(wide_to_local_string(uz, &wide, escape_all))
}

/// `wctomb(buf, wc)` in the run's locale: the bytes, or `None` for `-1`
/// (no encoding). `None` as `wc` is `wctomb(NULL, 'a')`, which resets the
/// shift state. Under `Host::Real` on unix it is the C library's (the
/// locale [`fileio::init_locale`] set); a sandbox, and a build off unix,
/// is the C locale, which encodes ASCII only.
fn wctomb(uz: &Uz, wc: Option<u32>) -> Option<Vec<u8>> {
    if matches!(uz.host, Host::Real) {
        return libc_wctomb(wc);
    }
    match wc {
        Some(c) if c <= 0x7f => Some(vec![c as u8]),
        Some(_) => None,
        None => Some(Vec::new()),
    }
}

#[cfg(unix)]
unsafe extern "C" {
    /// ISO C's `wctomb()` (not in the `libc` crate's unix bindings).
    #[link_name = "wctomb"]
    fn c_wctomb(s: *mut libc::c_char, wc: libc::wchar_t) -> libc::c_int;
}

#[cfg(unix)]
fn libc_wctomb(wc: Option<u32>) -> Option<Vec<u8>> {
    let Some(c) = wc else {
        // SAFETY: a null `s` only resets `wctomb()`'s shift state; the
        // run is single-threaded under `Host::Real`.
        unsafe { c_wctomb(std::ptr::null_mut(), libc::wchar_t::from(b'a')) };
        return Some(Vec::new());
    };
    // Every character is below 2^31 (six UTF-8 bytes carry 31 bits), so it
    // fits `wchar_t` (an `i32` on Linux and macOS).
    let wc = libc::wchar_t::try_from(c).ok()?;
    // 16 bytes: more than `MB_CUR_MAX` in any locale.
    let mut buf = [0 as libc::c_char; 16];
    // SAFETY: `buf` has room for `MB_CUR_MAX` bytes, all `wctomb()` writes;
    // the run is single-threaded under `Host::Real` (its static state).
    let n = unsafe { c_wctomb(buf.as_mut_ptr(), wc) };
    let n = usize::try_from(n).ok()?;
    Some(buf[..n.min(buf.len())].iter().map(|&b| b as u8).collect())
}

#[cfg(not(unix))]
fn libc_wctomb(wc: Option<u32>) -> Option<Vec<u8>> {
    match wc {
        Some(c) if c <= 0x7f => Some(vec![c as u8]),
        Some(_) => None,
        None => Some(Vec::new()),
    }
}
