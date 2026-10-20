//! `fileio.c`'s archive input and strings: `open_input_file()`, `readbuf()`,
//! `seek_zipf()`, `do_string()`, `makeword()`/`makelong()`/`makeint64()`,
//! `dos_to_unix_time()`; `extract.c`'s `fnfilter()`; the `localtime()` the
//! listings call.
//!
//! The archive is read as the C reads it: `read(2)` of `INBUFSIZ` blocks
//! into `G.inbuf`, `lseek(2)` to block boundaries, with `G.incnt`,
//! `G.inptr` and `G.cur_zipfile_bufstart` kept as the C keeps them, so a
//! short read, a seek past the end or a seek that fails leaves the same
//! state behind. Every allocation is bounded by a field's width (a name, an
//! extra field or a comment is at most 64 KiB) or by a constant.

use std::io::{Read, Seek, SeekFrom};

use super::messages as m;
use super::{PK_COOL, PK_EOF, PK_OK, PK_WARN, Uz, flavour};
use crate::compat::host::{Host, InFile};

/// unzpriv.h's `INBUFSIZ` ("larger buffers for real OSes").
pub(crate) const INBUFSIZ: usize = 8192;
/// unzpriv.h's `OUTBUFSIZ` (`lenEOL*WSIZE`).
pub(crate) const OUTBUFSIZ: usize = stuffr::infozip::WSIZE;
/// unzpriv.h's `WSIZE`.
pub(crate) const WSIZE: usize = stuffr::infozip::WSIZE;

/// unzpriv.h's `CR`.
const CR: u8 = 13;
/// unzpriv.h's `LF`.
const LF: u8 = 10;

/// unzpriv.h's version-made-by host numbers this file reads.
pub(crate) const FS_FAT_: u8 = 0;
pub(crate) const FS_HPFS_: u8 = 6;
pub(crate) const FS_NTFS_: u8 = 11;

/// `do_string()`'s options (unzpriv.h `SKIP` .. `DS_FN_L`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DoString {
    /// `SKIP`: step over the string.
    Skip,
    /// `DISPLAY`: print it (the archive comment).
    Display,
    /// `DISPL_8`: print it after the host's code page conversion (an
    /// entry's comment).
    Displ8,
}

/// `G.pInfo`'s fields that `do_string()` reads (list.c's `min_info info`):
/// set by `process_cdir_file_hdr()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PInfo {
    /// `hostver`: the version-made-by's low byte.
    pub hostver: u8,
    /// `hostnum`: the version-made-by's high byte, at most `NUM_HOSTS`.
    pub hostnum: u8,
    /// `lcflag`: lowercase the name (`-L`, `-LL`).
    pub lcflag: bool,
    /// `vollabel`: the entry is an MS-DOS volume label.
    pub vollabel: bool,
    /// `HasUxAtt`: the external attributes' high 16 bits are set.
    pub has_ux_att: bool,
}

/// The archive input: `G.zipfd` and `readbuf()`'s buffer state.
pub(crate) struct ZipIn {
    /// `G.zipfd`: the open archive.
    pub(crate) fd: Option<InFile>,
    /// `G.inbuf`, `INBUFSIZ + 4` bytes (the last 4 are `G.hold`, for a
    /// signature that spans two blocks of `rec_find()`'s backward search).
    /// ruling: process_zipfiles' `malloc(INBUFSIZ + 4)` leaves it
    /// uninitialised, and `rec_find()` can compare `G.hold` before writing
    /// it (a tail shorter than a record); a fresh buffer reads as zeros
    /// here. It lives across archives, as the C's does.
    pub(crate) inbuf: Box<[u8]>,
    /// `G.incnt`: bytes left in `inbuf` from `inptr` (a C `int`; negative
    /// after a failed `read()`).
    pub(crate) incnt: i64,
    /// `G.inptr`, as an index into `inbuf`.
    pub(crate) inptr: usize,
    /// `G.cur_zipfile_bufstart`: the file offset `inbuf` was read from.
    pub(crate) cur_zipfile_bufstart: i64,
    /// `G.extra_bytes`: bytes before the archive proper (a preamble).
    pub(crate) extra_bytes: i64,
    /// `G.ziplen`: the archive's size by `stat()`.
    pub(crate) ziplen: i64,
    /// `G.inptr_leftover`, `G.incnt_leftover`: the buffer's bytes past the
    /// entry being decoded (`defer_leftover_input()`).
    pub(crate) inptr_leftover: usize,
    pub(crate) incnt_leftover: i64,
}

impl Default for ZipIn {
    /// A stand-in while the extraction holds the real one (no buffer, no
    /// archive).
    fn default() -> ZipIn {
        ZipIn {
            fd: None,
            inbuf: Box::default(),
            incnt: 0,
            inptr: 0,
            cur_zipfile_bufstart: 0,
            extra_bytes: 0,
            ziplen: 0,
            inptr_leftover: 0,
            incnt_leftover: 0,
        }
    }
}

impl ZipIn {
    pub(crate) fn new() -> ZipIn {
        ZipIn {
            fd: None,
            inbuf: vec![0u8; INBUFSIZ + 4].into_boxed_slice(),
            incnt: 0,
            inptr: 0,
            cur_zipfile_bufstart: 0,
            extra_bytes: 0,
            ziplen: 0,
            inptr_leftover: 0,
            incnt_leftover: 0,
        }
    }

    /// `read(G.zipfd, G.inbuf + at, n)`: the count, 0 at the end, -1 on an
    /// error (or with no archive open).
    pub(crate) fn read_at(&mut self, at: usize, n: usize) -> i64 {
        let Some(fd) = self.fd.as_mut() else {
            return -1;
        };
        loop {
            match fd.read(&mut self.inbuf[at..at + n]) {
                Ok(k) => return k as i64,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return -1,
            }
        }
    }

    /// `read(G.zipfd, buf, buf.len())` into a caller's buffer.
    pub(crate) fn read_into(&mut self, buf: &mut [u8]) -> i64 {
        let Some(fd) = self.fd.as_mut() else {
            return -1;
        };
        loop {
            match fd.read(buf) {
                Ok(k) => return k as i64,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return -1,
            }
        }
    }

    /// `lseek(G.zipfd, off, SEEK_SET)`: the new offset, or -1 (a negative
    /// offset, or the system's refusal), the position then unchanged.
    pub(crate) fn lseek(&mut self, off: i64) -> i64 {
        let Some(fd) = self.fd.as_mut() else {
            return -1;
        };
        if off < 0 {
            return -1;
        }
        fd.seek(SeekFrom::Start(off as u64))
            .map_or(-1, |p| p as i64)
    }
}

// port: fileio.c:makeword
/// A little-endian 16-bit field.
pub(crate) fn makeword(b: &[u8]) -> u16 {
    u16::from(b[0]) | (u16::from(b[1]) << 8)
}

// port: fileio.c:makelong
/// A little-endian 32-bit field.
pub(crate) fn makelong(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

// port: fileio.c:makeint64
/// A little-endian 64-bit field, as `LARGE_FILE_SUPPORT`'s `makeint64()`
/// assembles it: upstream's leaves out byte 5 (bits 40..47), so Apple's
/// unzip reads `0x0000_ff00_0000_0000` as 0.
/// ubuntu: 21-fix-warning-messages-on-big-files.patch adds byte 5
/// (`flavour::makeint64_reads_byte_5`).
pub(crate) fn makeint64(f: flavour::Flavour, b: &[u8]) -> u64 {
    let mut v = (u64::from(b[7]) << 56)
        .wrapping_add(u64::from(b[6]) << 48)
        .wrapping_add(u64::from(b[4]) << 32)
        .wrapping_add(u64::from(makelong(b)));
    if flavour::makeint64_reads_byte_5(f) {
        v = v.wrapping_add(u64::from(b[5]) << 40);
    }
    v
}

// port: fileio.c:readbuf
/// Up to `buf.len()` bytes of the archive from the buffer, refilling it a
/// block at a time: the count read (short only at the end; 0 after a read
/// error, which `ReadError` reports).
pub(crate) fn readbuf(uz: &mut Uz, buf: &mut [u8]) -> usize {
    let n = buf.len();
    let mut size = n;
    let mut at = 0usize;
    while size > 0 {
        if uz.zin.incnt <= 0 {
            uz.zin.incnt = uz.zin.read_at(0, INBUFSIZ);
            if uz.zin.incnt == 0 {
                return n - size;
            } else if uz.zin.incnt < 0 {
                // another hack, but no real harm copying same thing twice
                uz.info(0x401, m::READ_ERROR.as_bytes());
                return 0; // discarding some data; better than lock-up
            }
            // buffer ALWAYS starts on a block boundary:
            uz.zin.cur_zipfile_bufstart = uz.zin.cur_zipfile_bufstart.wrapping_add(INBUFSIZ as i64);
            uz.zin.inptr = 0;
        }
        let count = size.min(uz.zin.incnt as usize);
        let from = uz.zin.inptr;
        // ruling: `find_ecrec64()` sets `G.incnt` to what it read into its
        // own buffer, and when the directory starts in the block it last
        // seeked to, `seek_zipf()` keeps `G.inbuf` and adds to that count:
        // `G.inptr + G.incnt` can then pass the buffer's end by up to 52
        // bytes, which the C reads from beyond its allocation (undefined
        // behaviour). Those bytes read as zeros here.
        for (k, b) in buf[at..at + count].iter_mut().enumerate() {
            *b = uz.zin.inbuf.get(from + k).copied().unwrap_or(0);
        }
        at += count;
        uz.zin.inptr += count;
        uz.zin.incnt -= count as i64;
        size -= count;
    }
    n
}

// port: fileio.c:seek_zipf
/// Position the buffer at `abs_offset` (an offset as if there were no
/// extra bytes): `PK_BADERR` before the start of the file, `PK_EOF` past
/// its end, else `PK_OK`.
pub(crate) fn seek_zipf(uz: &mut Uz, abs_offset: i64) -> i32 {
    let request = abs_offset.wrapping_add(uz.zin.extra_bytes);
    let inbuf_offset = request.wrapping_rem(INBUFSIZ as i64);
    let bufstart = request.wrapping_sub(inbuf_offset);

    if request < 0 {
        let msg = {
            let mut b = Vec::new();
            m::printf(
                &mut b,
                m::SEEK_MSG,
                &[&uz.zipfn.clone(), m::REPORT_MSG.as_bytes()],
            );
            b
        };
        uz.info(1, &msg);
        return super::PK_BADERR;
    } else if bufstart != uz.zin.cur_zipfile_bufstart {
        uz.zin.cur_zipfile_bufstart = uz.zin.lseek(bufstart);
        uz.zin.incnt = uz.zin.read_at(0, INBUFSIZ);
        if uz.zin.incnt <= 0 {
            return PK_EOF;
        }
        uz.zin.incnt -= inbuf_offset;
        uz.zin.inptr = inbuf_offset as usize;
    } else {
        uz.zin.incnt += uz.zin.inptr as i64 - inbuf_offset;
        uz.zin.inptr = inbuf_offset as usize;
    }
    PK_OK
}

/// The offset `seek_zipf()` takes for the byte at `G.inptr` plus `length`
/// (`G.cur_zipfile_bufstart - G.extra_bytes + (G.inptr-G.inbuf) + length`).
fn here_plus(uz: &Uz, length: usize) -> i64 {
    uz.zin
        .cur_zipfile_bufstart
        .wrapping_sub(uz.zin.extra_bytes)
        .wrapping_add(uz.zin.inptr as i64)
        .wrapping_add(length as i64)
}

/// unzpriv.h's `Ext_ASCII_TO_Native()` on unix (`CRTL_CP_IS_ISO`): names
/// and comments from MS-DOS FAT (except PKZIP 2.5, 2.6 and 4.0 with Unix
/// attributes or in a local header), OS/2 HPFS and Windows NT 5.0 are OEM
/// code page 850 (`_OEM_INTERN`, `oem2iso_850`); everything else is ISO
/// 8859-1 already (`_ISO_INTERN` is `A_TO_N`, nothing on ASCII). In
/// place, up to the string's NUL.
/// ubuntu: 20-unzip60-alt-iconv-utf8.patch replaces this conversion (Task
/// 14; `flavour::iconv_charsets`).
pub(crate) fn ext_ascii_to_native(s: &mut [u8], p: &PInfo, islochdr: bool) {
    let oem = (p.hostnum == FS_FAT_
        && !((islochdr || p.has_ux_att)
            && (p.hostver == 25 || p.hostver == 26 || p.hostver == 40)))
        || p.hostnum == FS_HPFS_
        || (p.hostnum == FS_NTFS_ && p.hostver == 50);
    if oem {
        for b in s.iter_mut() {
            if *b == 0 {
                break;
            }
            if *b & 0x80 != 0 {
                *b = m::OEM2ISO_850[usize::from(*b & 0x7f)];
            }
        }
    }
}

/// unzpriv.h's `STRLOWER` (unix `isupper`/`tolower`, ASCII in every locale
/// deviation 6 admits), in place up to the string's NUL.
pub(crate) fn strlower(s: &mut [u8]) {
    for b in s.iter_mut() {
        if *b == 0 {
            break;
        }
        b.make_ascii_lowercase();
    }
}

/// The C string in `buf`: up to its first NUL.
pub(crate) fn c_str(buf: &[u8]) -> &[u8] {
    match buf.iter().position(|&b| b == 0) {
        Some(n) => &buf[..n],
        None => buf,
    }
}

// port: fileio.c:do_string
/// `do_string(length, SKIP | DISPLAY | DISPL_8)`: step over the `length`
/// bytes at the archive's current position, or print them (CRs dropped,
/// `ESC` shown as `^[`, `^S` dropped, `DISPL_8` after the host's code page
/// conversion), then a newline if the text did not end one. `pinfo` is
/// `G.pInfo`, which `DISPL_8` reads.
///
/// The text is formatted into `uz.slide`, as the C formats into `slide[]`.
/// ruling: the C strips CRs with `while (*p) { while (*p == CR) ++p; *q++ =
/// *p++; }`, which steps past the terminator when a block ends in CRs and
/// then scans bytes after it (past `G.outbuf`'s end for a full block);
/// what it prints is the block up to its first NUL with the CRs taken out
/// either way, and that is what is printed here, without reading further.
pub(crate) fn do_string(
    uz: &mut Uz,
    length: usize,
    option: DoString,
    pinfo: Option<&PInfo>,
) -> i32 {
    if length == 0 {
        return PK_COOL;
    }
    match option {
        DoString::Display | DoString::Displ8 => {
            let mut comment_bytes_left = length;
            let mut block_len = OUTBUFSIZ; // for the while statement, first time
            let mut outbuf = vec![0u8; OUTBUFSIZ.min(length)];
            while comment_bytes_left > 0 && block_len > 0 {
                let want = OUTBUFSIZ.min(comment_bytes_left);
                block_len = readbuf(uz, &mut outbuf[..want]);
                if block_len == 0 {
                    return PK_EOF;
                }
                comment_bytes_left -= block_len;

                // the block as a C string, with every CR removed
                let mut text: Vec<u8> = c_str(&outbuf[..block_len])
                    .iter()
                    .copied()
                    .filter(|&b| b != CR)
                    .collect();
                if option == DoString::Displ8
                    && let Some(p) = pinfo
                {
                    ext_ascii_to_native(&mut text, p, false);
                }
                // ASCII, filter out ANSI escape sequences and handle ^S
                let mut q = 0usize;
                let mut i = 0usize;
                while i < text.len() {
                    let mut pause = false;
                    let c = text[i];
                    if c == 0x1b {
                        // ASCII escape char
                        uz.slide[q] = b'^';
                        uz.slide[q + 1] = b'[';
                        q += 2;
                    } else if c == 0x13 {
                        // ASCII ^S (pause)
                        pause = true;
                        let at = |k: usize| text.get(k).copied().unwrap_or(0);
                        if at(i + 1) == LF {
                            i += 1;
                            uz.slide[q] = text[i];
                            q += 1;
                        } else if at(i + 1) == CR && at(i + 2) == LF {
                            // (no CR is left in `text`: never taken)
                            i += 1;
                            uz.slide[q] = text[i];
                            i += 1;
                            uz.slide[q + 1] = text[i];
                            q += 2;
                        }
                    } else {
                        uz.slide[q] = c;
                        q += 1;
                    }
                    if q > WSIZE - 3 || pause {
                        // flush
                        let out = uz.slide[..q].to_vec();
                        uz.info(0, &out);
                        q = 0;
                        // `if (pause && G.extract_flag)` the C asks
                        // UzpMorePause (`--- Press `Q' to quit...`) here;
                        // a listing never does. Task 11 ports it.
                    }
                    i += 1;
                }
                let out = uz.slide[..q].to_vec();
                uz.info(0, &out);
            }
            // add '\n' if not at start of line
            uz.info(super::MSG_TNEWLN, b"");
            PK_COOL
        }
        DoString::Skip => {
            // cur_zipfile_bufstart already takes account of extra_bytes, so
            // don't correct for it twice
            let to = here_plus(uz, length);
            seek_zipf(uz, to);
            PK_COOL
        }
    }
}

// port: fileio.c:do_string
/// `do_string(length, DS_FN)` (`islochdr` false) or `DS_FN_L`: read the
/// entry's name into `G.filename` (`uz.filename`, `FILNAMSIZ` bytes that
/// keep what an earlier name left past the new one's terminator, as the
/// C's array does), truncated to `FILNAMSIZ - 1` bytes with a warning,
/// converted from the host's code page, lowercased under `lcflag`, and a
/// volume label's dot after 8 characters removed. Returns the PK code
/// (`PK_WARN` for a truncated name, `PK_EOF` when nothing could be read).
pub(crate) fn read_filename(uz: &mut Uz, length: usize, pinfo: &PInfo, islochdr: bool) -> i32 {
    if length == 0 {
        return PK_COOL;
    }
    // ubuntu: -DUNICODE_SUPPORT (Task 13) reads the whole name into
    // `G.filename_full` first, for the Unicode path's checksum.
    let filnamsiz = uz.filename.len();
    let mut error = PK_OK;
    let mut length = length;
    let block_len = if length >= filnamsiz {
        uz.info(0x401, m::FILENAME_TOO_LONG_TRUNC.as_bytes());
        error = PK_WARN;
        // remember excess length in block_len
        let excess = length - (filnamsiz - 1);
        length = filnamsiz - 1;
        excess
    } else {
        0 // no excess size
    };
    let mut name = std::mem::take(&mut uz.filename);
    let got = readbuf(uz, &mut name[..length]);
    if got == 0 {
        uz.filename = name;
        return PK_EOF;
    }
    // A short read keeps the bytes past it from the earlier name.
    name[length] = 0; // terminate w/zero:  ASCIIZ

    // translate the Zip entry filename coded in host-dependent "extended
    // ASCII" into the compiler's (system's) internal text code page
    ext_ascii_to_native(&mut name, pinfo, islochdr);

    if pinfo.lcflag {
        // replace with lowercase filename
        strlower(&mut name);
    }

    if pinfo.vollabel && length > 8 && name[8] == b'.' {
        // disk label, and 8th char is dot:  remove dot
        let mut i = 8;
        while name[i] != 0 {
            name[i] = name[i + 1];
            i += 1;
        }
    }
    uz.filename = name;

    if block_len == 0 {
        // no overflow, we're done here
        return error;
    }

    // We truncated the filename, so print what's left and then fall
    // through to the SKIP routine.
    let name = uz.filename.clone();
    let shown = fnfilter1(uz, c_str(&name));
    let mut msg = Vec::new();
    m::printf(&mut msg, m::TRUNCATED_NAME, &[&shown]);
    uz.info(0x401, &msg);
    let to = here_plus(uz, block_len);
    seek_zipf(uz, to);
    error
}

// port: unzip.c:unzip
/// unzip.c's `SETLOCALE(LC_CTYPE, "")` and its `UTF8_MAYBE_NATIVE` test
/// (`nl_langinfo(CODESET)` is `"UTF-8"`): whether the run's character type
/// locale is UTF-8 (`G.native_is_utf8`). Under `Host::Real` on unix this
/// sets the process's `LC_CTYPE` from the environment as unzip does, so
/// [`is_print`] then answers as the reference's `isprint()`; a sandbox, and
/// a build off unix, is the C locale (R7, R8).
/// probe: Apple's `unzip -l` of a name holding 0xe9 shows it raw under
/// `LC_CTYPE=UTF-8` (a macOS locale), `LANG=en_US.UTF-8`, `C.UTF-8` and
/// `LC_CTYPE=en_US.ISO8859-1`, and `?` under `LANG=C` and `LANG=xx_XX.UTF-8`
/// (no such locale: setlocale fails and C stays).
pub(crate) fn init_locale(host: &Host) -> bool {
    if !matches!(host, Host::Real) {
        return false;
    }
    real_locale_is_utf8()
}

#[cfg(unix)]
fn real_locale_is_utf8() -> bool {
    // SAFETY: called once, from the run's single thread, before anything
    // else reads the locale (unzip.c does it first thing too); the strings
    // passed are NUL-terminated, and the one `nl_langinfo` returns is valid
    // until the next locale call, read at once here.
    unsafe {
        libc::setlocale(libc::LC_CTYPE, c"".as_ptr());
        let codeset = libc::nl_langinfo(libc::CODESET);
        !codeset.is_null() && std::ffi::CStr::from_ptr(codeset).to_bytes() == b"UTF-8"
    }
}

#[cfg(not(unix))]
fn real_locale_is_utf8() -> bool {
    false
}

/// unix `isprint()` (`HAVE_WORKING_ISPRINT`) in the locale [`init_locale`]
/// set: the C library's answer under `Host::Real` on unix (Apple's counts
/// 0xa0..0xff but 0xad printable under a UTF-8 locale, and the Latin-1
/// letters under ISO8859-1; glibc's no byte above 0x7e under UTF-8), the C
/// locale's (printable ASCII) in a sandbox and off unix.
pub(crate) fn is_print(uz: &Uz, c: u8) -> bool {
    if matches!(uz.host, Host::Real) {
        return libc_isprint(c);
    }
    (0x20..0x7f).contains(&c)
}

#[cfg(unix)]
fn libc_isprint(c: u8) -> bool {
    // SAFETY: `isprint` takes any `unsigned char` value as an `int` and
    // reads only the locale's character table.
    unsafe { libc::isprint(libc::c_int::from(c)) != 0 }
}

#[cfg(not(unix))]
fn libc_isprint(c: u8) -> bool {
    (0x20..0x7f).contains(&c)
}

// port: extract.c:fnfilter
/// `fnfilter(raw, space, size)`: `raw` (a C string) in printable form,
/// written into `uz.slide[at..at + size]` as the C writes its `space`, and
/// returned. A control byte becomes `^` and its letter; another byte
/// `isprint()` refuses becomes `?`; past `size - 4` bytes the text ends in
/// `...`.
/// ubuntu: -DNO_WORKING_ISPRINT escapes control bytes only
/// (`flavour::no_working_isprint`, Task 13).
pub(crate) fn fnfilter_at(uz: &mut Uz, raw: &[u8], at: usize, size: usize) -> Vec<u8> {
    let raw = c_str(raw);
    let working_isprint = !flavour::no_working_isprint(uz.flavour);
    let mut out: Vec<u8> = Vec::with_capacity(raw.len().min(size));
    let slim = size.saturating_sub(4);
    let mut se: Option<usize> = None;
    let mut have_overflow = false;
    let mut r = 0usize;
    while r < raw.len() {
        let s = out.len();
        if size > 0 && s >= slim && se.is_none() {
            se = Some(s);
        }
        let c = raw[r];
        let printable = !working_isprint || is_print(uz, c);
        if c < 32 {
            // ASCII control codes are escaped as "^{letter}".
            if se.is_some() && s + 4 > size {
                have_overflow = true;
                break;
            }
            out.push(b'^');
            out.push(64 + c);
            r += 1;
        } else if !printable {
            // Other unprintable codes are replaced by the placeholder
            // character.
            if se.is_some() && s + 3 > size {
                have_overflow = true;
                break;
            }
            out.push(b'?');
            r += 1;
        } else {
            if se.is_some() && s + 3 > size {
                have_overflow = true;
                break;
            }
            out.push(c);
            r += 1;
        }
    }
    if have_overflow {
        let se = se.unwrap_or(out.len());
        out.truncate(se);
        out.extend_from_slice(b"...");
    }
    // The text never passes `size` bytes; its NUL can sit at `size`.
    let n = out.len().min(size);
    uz.put_slide_at(at, &out[..n], true);
    out
}

/// unzpriv.h's `FnFilter1(fname)`: `fnfilter()` into `slide + WSIZE/2`,
/// `WSIZE/4` bytes.
pub(crate) fn fnfilter1(uz: &mut Uz, raw: &[u8]) -> Vec<u8> {
    fnfilter_at(uz, raw, WSIZE >> 1, WSIZE >> 2)
}

/// unzpriv.h's `FnFilter2(fname)`: `fnfilter()` into `slide + WSIZE/2 +
/// WSIZE/4`, `WSIZE/4` bytes.
pub(crate) fn fnfilter2(uz: &mut Uz, raw: &[u8]) -> Vec<u8> {
    fnfilter_at(uz, raw, (WSIZE >> 1) + (WSIZE >> 2), WSIZE >> 2)
}

// port: extract.c:fnfilterp
/// apple: extract.c:2788, `fnfilterp(pfx, raw, slide + WSIZE/2, WSIZE/4)`:
/// `pfx` (when given and not empty) filtered, a `/`, then `raw` filtered
/// in the space left.
pub(crate) fn fnfilterp(uz: &mut Uz, pfx: Option<&[u8]>, raw: &[u8]) -> Vec<u8> {
    let (mut at, mut size) = (WSIZE >> 1, WSIZE >> 2);
    let mut out = Vec::new();
    if let Some(pfx) = pfx.filter(|p| !p.is_empty()) {
        let p = fnfilter_at(uz, pfx, at, size);
        let n = c_str(&p).len().min(size);
        at += n;
        size -= n;
        out.extend_from_slice(&p[..n]);
        uz.put_slide_at(at, b"/", false);
        out.push(b'/');
        at += 1;
        size = size.saturating_sub(1);
    }
    out.extend_from_slice(&fnfilter_at(uz, raw, at, size));
    out
}

// port: list.c:fnprint
/// `fnprint()`: the entry's name (`G.filename`) filtered into `slide`
/// (`WSIZE/2` bytes) and printed, then a newline.
pub(crate) fn fnprint(uz: &mut Uz) {
    let name = uz.filename.clone();
    let shown = fnfilter_at(uz, &name, 0, WSIZE >> 1);
    uz.info(0, &shown);
    uz.info(0, b"\n");
}

/// The fields of a `struct tm` the listings print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tm {
    /// `tm_year + 1900`.
    pub year: i64,
    /// `tm_mon + 1`.
    pub mon: u32,
    pub mday: u32,
    pub hour: u32,
    pub min: u32,
    /// `tm_sec` (zipinfo's long times show it).
    pub sec: u32,
    /// `tm_gmtoff`: seconds east of UTC.
    pub gmtoff: i64,
}

/// `localtime(&t)`: the local time of `t` (`None` where the C gets
/// `NULL`). In a sandbox the zone is UTC (R7); off unix too (R8).
pub(crate) fn localtime(uz: &Uz, t: i64) -> Option<Tm> {
    if matches!(uz.host, crate::compat::host::Host::Real) {
        return localtime_real(t);
    }
    Some(utc(t))
}

#[cfg(unix)]
unsafe extern "C" {
    /// POSIX `tzset()`, which the `libc` crate does not declare on every
    /// unix.
    fn tzset();
}

#[cfg(unix)]
fn localtime_real(t: i64) -> Option<Tm> {
    let tt = t as libc::time_t;
    // SAFETY: `tm` is plain data that a successful `localtime_r` fills in
    // whole; both pointers are valid for the call. `tzset` has no
    // arguments (process_zipfiles() calls it first, as here).
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        tzset();
        !libc::localtime_r(&tt, &mut tm).is_null()
    };
    ok.then(|| Tm {
        year: i64::from(tm.tm_year) + 1900,
        mon: (tm.tm_mon + 1) as u32,
        mday: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        min: tm.tm_min as u32,
        sec: tm.tm_sec as u32,
        gmtoff: tm.tm_gmtoff as i64,
    })
}

#[cfg(not(unix))]
fn localtime_real(t: i64) -> Option<Tm> {
    Some(utc(t))
}

/// `gmtime(&t)`: `t` in UTC (zipinfo's `-v` shows both).
pub(crate) fn gmtime(t: i64) -> Tm {
    utc(t)
}

/// `t` in UTC (days from the civil calendar).
fn utc(t: i64) -> Tm {
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
    Tm {
        year: if mo <= 2 { y + 1 } else { y },
        mon: mo as u32,
        mday: d as u32,
        hour: (secs / 3600) as u32,
        min: (secs / 60 % 60) as u32,
        sec: (secs % 60) as u32,
        gmtoff: 0,
    }
}

/// unzpriv.h's `DOSTIME_2038_01_18`.
pub(crate) const DOSTIME_2038_01_18: u32 = 0x7432_0000;
/// unzpriv.h's `U_TIME_T_MAX` and `S_TIME_T_MAX` (as unzpriv.h defines
/// them for a 64-bit `time_t`: the 32-bit limits).
const U_TIME_T_MAX: i64 = 0xffff_ffff;
const S_TIME_T_MAX: i64 = 0x7fff_ffff;

/// fileio.c's `ydays[]`: days before each month (and the year's total).
const YDAYS: [u32; 13] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];

// port: fileio.c:dos_to_unix_time
/// An MS-DOS date and time (local time) as a `time_t`, as the `BSD4_4`
/// build computes it (no `HAVE_MKTIME`): days and seconds from 1970, the
/// zone's offset (`tm_gmtoff` of the result) taken off, saturated at the
/// 32-bit limits.
/// ruling: `ydays[mo]` with a month field of 0, 14 or 15 reads outside the
/// 13-entry table (undefined behaviour: Apple's unzip `-T` gives month 0 ten
/// extra days and month 15 a date in 2090); here month 0 counts no days
/// before it and months 14 and 15 the whole year (`ydays[12]`, which month
/// 13 reads).
/// ubuntu: the Linux build (no `BSD4_4`) adds `timezone` and takes an hour
/// off under DST instead (Task 13); the two agree in UTC.
pub(crate) fn dos_to_unix_time(uz: &Uz, dosdatetime: u32) -> i64 {
    const YRBASE: i64 = 1970;
    let yr = i64::from((dosdatetime >> 25) & 0x7f) + (1980 - YRBASE);
    let mo = i64::from((dosdatetime >> 21) & 0x0f) - 1;
    let dy = i64::from((dosdatetime >> 16) & 0x1f) - 1;
    let hh = i64::from((dosdatetime >> 11) & 0x1f);
    let mm = i64::from((dosdatetime >> 5) & 0x3f);
    let ss = i64::from(dosdatetime & 0x1f) * 2;

    // leap = # of leap yrs from YRBASE up to but not including current year
    let leap = (yr + YRBASE - 1) / 4; // leap year base factor
    let ydays = if mo < 0 {
        0
    } else {
        i64::from(YDAYS[(mo as usize).min(12)])
    };
    // calculate days from BASE to this year and add expired days this year
    // (`unsigned days`: the sum is never negative here)
    let mut days = (yr * 365) + (leap - 492) + ydays;
    // if year is a leap year and month is after February, add another day
    if mo > 1 && (yr + YRBASE) % 4 == 0 && (yr + YRBASE) != 2100 {
        days += 1; // OK through 2199
    }
    // convert date & time to seconds relative to 00:00:00, 01/01/YRBASE
    let mut m_time = (days + dy) * 86_400 + hh * 3600 + (mm * 60 + ss);

    // Adjust for local standard timezone offset.
    let saturate = |t: i64| -> i64 {
        let mut t = t;
        if dosdatetime >= DOSTIME_2038_01_18 && t < 0x7000_0000 {
            t = U_TIME_T_MAX; // saturate in case of (unsigned) overflow
        }
        if t < 0 {
            t = S_TIME_T_MAX; // a converted DOS time cannot be negative
        }
        t
    };
    m_time = saturate(m_time);
    if let Some(tm) = localtime(uz, m_time) {
        m_time -= tm.gmtoff; // sec. EAST of GMT: subtr.
    }
    saturate(m_time)
}

#[cfg(test)]
mod tests;
