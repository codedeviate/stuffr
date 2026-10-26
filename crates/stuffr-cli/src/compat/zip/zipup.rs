//! `zipup.c`: one entry of a new archive. The method (`-n`'s suffixes,
//! `-0`, a directory or a link stored), the local header, the data stored
//! or deflated (`stuffr::infozip::ZipDeflater`), `-l`/`-ll`'s line ends,
//! then the data descriptor or the rewritten local header, and the line
//! zip ends the entry's message with. The run around it is `write.rs`'s,
//! the archive's sinks `sink.rs`'s, the records `zipfile.rs`'s.
//!
//! **Inputs are opened through `Host::track`**, so a sandboxed run counts
//! every byte it reads. Reads are zipup's: one `read` per request
//! (`zread`), so a pipe's short reads reach deflate as they reach the C's,
//! and `-l`/`-ll` translate each request as `file_read` does. A read error
//! is the end of the input, as there (`file_read` returns `EOF`): a stored
//! entry then warns "could not read input file", a deflated one does not
//! (zipup's `zerr()` looks at the stored loop's `k` only), and both warn
//! that the size changed. **A write that fails** ends the run as
//! `bfwrite` ends it: `ZE_WRITE`, "write error on zip file", exit 14.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use stuffr::infozip::{BlockVanished, ZipDeflater, ZipOut};

use super::cli::{Method, ZE_PARMS};
use super::messages::{self as m, printf};
use super::scan::Found;
use super::unix::{self, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use super::zipfile::{
    Bf, LOCHEAD, PutError, ZEntry, ZOut, putextended, putlocal, putlocal_rewrite,
};
use super::{Exit, Zr};
use crate::compat::host::{self, Host};

/// ziperr.h codes this file raises.
const ZE_LOGIC: i32 = 5;
const ZE_BIG: i32 = 6;
const ZE_TEMP: i32 = 10;
const ZE_READ: i32 = 11;
const ZE_WRITE: i32 = 14;

/// zip.h's methods.
const STORE: u16 = 0;
const DEFLATE: u16 = 8;
/// tailor.h:SBSZ, the stored entries' copy buffer.
const SBSZ: usize = 16384;
/// deflate.c's window half, for `-dd`'s dots.
const WSIZE: i64 = 0x8000;
/// zip.h:MSDOS_DIR_ATTR
const MSDOS_DIR_ATTR: u32 = 0x10;

/// Whether a ziperr code also prints `zip I/O error: <strerror>`
/// (`ZE_S_PERR` in ziperr.h).
pub(crate) fn perr(code: i32) -> bool {
    matches!(code, 10 | 11 | 14 | 15 | 18)
}

/// `ZIPERR(code, h)` with the system's answer `e` where the code prints one.
pub(crate) fn zerr(z: &mut Zr, code: i32, h: &[u8], e: Option<&io::Error>) -> Exit {
    match e {
        Some(e) if perr(code) => z.ziperr_os(code, h, e),
        _ => z.ziperr(code, h),
    }
}

// ---- the archive's sinks ----

// ---- the input ----

/// What an entry's data is read from: a file opened through `Host::track`,
/// or standard input.
pub(crate) enum Src {
    File(host::InFile),
    Stdin(Box<dyn Read>),
}

impl Read for Src {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Src::File(f) => f.read(buf),
            Src::Stdin(s) => s.read(buf),
        }
    }
}

/// zipup.c:file_read: one `zread` per request, `-l`/`-ll`'s translation of
/// it, and a read error taken for the end of the input (kept in `err`).
pub(crate) struct FileRead<'a> {
    src: &'a mut dyn Read,
    /// 0, 1 `-l`, 2 `-ll`.
    translate_eol: u8,
    /// `file_binary`: -1 until the first read, then 1 when it was not text.
    file_binary: i8,
    /// The read error that ended the input, if one did.
    err: Option<io::Error>,
    scratch: Vec<u8>,
}

impl<'a> FileRead<'a> {
    pub(crate) fn new(src: &'a mut dyn Read, translate_eol: u8) -> FileRead<'a> {
        FileRead {
            src,
            translate_eol,
            file_binary: -1,
            err: None,
            scratch: Vec::new(),
        }
    }

    /// `zread()`: one `read`, `Interrupted` retried; an error is recorded
    /// and read as the end (the C's `(unsigned)EOF`).
    fn zread(&mut self, buf: &mut [u8]) -> usize {
        if self.err.is_some() {
            return 0;
        }
        loop {
            match self.src.read(buf) {
                Ok(n) => return n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.err = Some(e);
                    return 0;
                }
            }
        }
    }

    // port: zipup.c:file_read (the crc and isize are the caller's)
    fn file_read(&mut self, buf: &mut [u8]) -> usize {
        let size = buf.len();
        match self.translate_eol {
            0 => self.zread(buf),
            1 => {
                // LF to CR LF: read half the room, expand into it
                let half = size >> 1;
                let mut raw = std::mem::take(&mut self.scratch);
                raw.resize(half, 0);
                let n = self.zread(&mut raw[..half]);
                if n == 0 {
                    self.scratch = raw;
                    return 0;
                }
                if self.file_binary == -1 {
                    self.file_binary = i8::from(!is_text_buf(&raw[..n]));
                }
                let len = if self.file_binary != 1 {
                    let mut o = 0;
                    for &c in &raw[..n] {
                        if c == b'\n' {
                            buf[o] = b'\r';
                            buf[o + 1] = b'\n';
                            o += 2;
                        } else {
                            buf[o] = c;
                            o += 1;
                        }
                    }
                    o
                } else {
                    buf[..n].copy_from_slice(&raw[..n]);
                    n
                };
                self.scratch = raw;
                len
            }
            _ => {
                // CR LF to LF, a final ^Z dropped
                if size == 0 {
                    return 0;
                }
                let n = self.zread(&mut buf[..size - 1]);
                if n == 0 {
                    return 0;
                }
                if self.file_binary == -1 {
                    self.file_binary = i8::from(!is_text_buf(&buf[..n]));
                }
                if self.file_binary == 1 {
                    return n;
                }
                // `buf[len] = '\n'`: a CR at the end of the read is taken
                // for half of a CR LF, as the C takes it
                buf[n] = b'\n';
                let mut o = 0;
                let mut i = 0;
                while i < n {
                    let c = buf[i];
                    buf[o] = c;
                    o += 1;
                    i += 1;
                    if c == b'\r' && buf[i] == b'\n' {
                        o -= 1;
                    }
                }
                let mut len = o;
                if len == 0 {
                    // keep a single CR at the end of the input
                    let _ = self.zread(&mut buf[..1]);
                    len = 1;
                } else if buf[len - 1] == 0x1a {
                    len -= 1;
                }
                len
            }
        }
    }
}

impl Read for FileRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(self.file_read(buf))
    }
}

/// util.c:is_text_buf
pub(crate) fn is_text_buf(b: &[u8]) -> bool {
    let mut result = false;
    for &c in b {
        if c >= 32 {
            result = true;
        } else if c <= 6 || (14..=25).contains(&c) || (28..=31).contains(&c) {
            return false;
        }
    }
    result
}

// ---- numbers as zip prints them ----

/// zipup.c:percent: the reduction from `n` to `m` in whole percent,
/// rounded, signed (64-bit `zoff_t`: no scaling).
// port: zipup.c:percent
pub(crate) fn percent(n: u64, m: u64) -> i64 {
    if n == 0 {
        return 0;
    }
    let (n, m) = (n as i64, m as i64);
    (200i64.wrapping_mul(n.wrapping_sub(m)) / n + 1) / 2
}

/// util.c:WriteNumString: a size in at most four characters, `2.1K`.
// port: util.c:WriteNumString
pub(crate) fn write_num_string(mut num: u64) -> String {
    let mut mult = 0;
    while num >= 10240 {
        num >>= 10;
        mult += 1;
    }
    let mut digits = [b' '; 4];
    digits[0] = b'0';
    let mut i;
    if num >= 1000 {
        i = 3;
        num *= 10;
        num >>= 10;
        mult += 1;
        digits[0] = (num % 10) as u8 + b'0';
        digits[1] = b'.';
        digits[2] = (num / 10) as u8 + b'0';
    } else {
        i = 0;
        while num != 0 {
            digits[i] = (num % 10) as u8 + b'0';
            num /= 10;
            i += 1;
        }
    }
    if i == 0 {
        i = 1;
    }
    let mut s: String = digits[..i].iter().rev().map(|&b| b as char).collect();
    match mult {
        0 => {}
        1 => s.push('K'),
        2 => s.push('M'),
        3 => s.push('G'),
        4 => s.push('T'),
        _ => s.push('?'),
    }
    s
}

// ---- the run's state ----

/// What is being written and the run's counters (zip.c's globals for it).
pub(crate) struct Wr {
    pub(crate) out: ZOut,
    pub(crate) deflater: Option<ZipDeflater>,
    /// `use_descriptors`: `-fd`, or an archive that cannot be rewound.
    pub(crate) use_descriptors: bool,
    /// `tempzn`: bytes written so far, by zip's own count.
    pub(crate) tempzn: u64,
    pub(crate) files_total: u64,
    pub(crate) files_so_far: u64,
    pub(crate) bytes_total: u64,
    pub(crate) bytes_so_far: u64,
    pub(crate) good_bytes_so_far: u64,
    pub(crate) bad_files_so_far: u64,
    pub(crate) bad_bytes_so_far: u64,
}

/// What zipup made of one name.
pub(crate) enum Zipped {
    /// The entry, written.
    Entry(ZEntry),
    /// `ZE_OPEN`: it could not be stat'ed or opened (the system's answer),
    /// and the entry as zipup left it (an old entry being updated keeps
    /// those changes: its size, unknown attributes, new extra fields).
    Open(io::Error, Box<ZEntry>),
    /// `ZE_MISS`: a directory in the scan is a file now, or the other way.
    Miss,
}

/// What an entry's data comes from.
enum Data {
    /// A directory: none.
    None,
    /// A symbolic link kept as a link (`-y`): its text.
    Link,
    /// A file or standard input.
    Read(Src),
}

/// Pass on the dots `bfwrite` printed for `-dg`.
pub(crate) fn drain_dots(z: &mut Zr, out: &mut ZOut) {
    if !out.dots.is_empty() {
        let d = std::mem::take(&mut out.dots);
        z.mesg_write(&d);
        // the leading space does not start a line; a dot does
        if d.contains(&b'.') {
            z.set_line(true);
        }
    }
}

/// deflate.c:fill_window and zipup.c's stored loop: the per-file dots of
/// `-dd`/`-ds`, once per `unit` bytes handled.
pub(crate) fn file_dot(z: &mut Zr, unit: i64) {
    if z.o.display_globaldots {
        return;
    }
    if z.o.dot_size > 0 {
        // initial space
        if z.o.noisy && z.o.dot_count == -1 {
            z.mesg_write(b" ");
            z.o.dot_count += 1;
        }
        z.o.dot_count += 1;
        if z.o.dot_size <= (z.o.dot_count + 1).saturating_mul(unit) {
            z.o.dot_count = 0;
        }
    }
    if (z.o.verbose > 0 || z.o.noisy) && z.o.dot_size != 0 && z.o.dot_count == 0 {
        z.mesg_write(b".");
        z.set_line(true);
    }
}

/// `perror(prefix)`: standard error, and the log's copy.
pub(crate) fn perror(z: &mut Zr, fmt: &str, e: &io::Error) {
    let mut line = Vec::new();
    printf(&mut line, fmt, &[&host::strerror(e)]);
    let _ = z.err.write_all(&line);
    let _ = z.err.flush();
    z.log_write(&line);
}

/// unix.c:filetime for zipup: the attributes (`st_mode << 16`, the
/// MS-DOS read-only and directory bits), the size (-1 for anything but a
/// regular file), the stat and its MS-DOS time.
pub(crate) struct FileTime {
    a: u32,
    q: i64,
    tim: u32,
}

// port: unix/unix.c:filetime
pub(crate) fn filetime(z: &Zr, name: &[u8]) -> Result<FileTime, io::Error> {
    let meta = if name == b"-" {
        // `error("fstat(stdin)")` cannot happen on an open descriptor
        unix::stdin_meta(z).ok_or_else(|| io::Error::from_raw_os_error(9))?
    } else {
        let stripped = name.strip_suffix(b"/").unwrap_or(name);
        let p = z.host.path(stripped);
        let md = if stripped.is_empty() {
            Err(io::Error::from_raw_os_error(2))
        } else if z.o.linkput {
            std::fs::symlink_metadata(&p)
        } else {
            std::fs::metadata(&p)
        }?;
        unix::meta_of(&md)
    };
    let mut a = (meta.mode << 16) | u32::from(meta.mode & 0o200 == 0);
    if meta.mode & S_IFMT == S_IFDIR {
        a |= MSDOS_DIR_ATTR;
    }
    let q = if meta.mode & S_IFMT == S_IFREG {
        meta.size as i64
    } else {
        -1
    };
    Ok(FileTime {
        a,
        q,
        tim: unix::unix2dostime(z, meta.mtime) as u32,
    })
}

/// zipup.c:suffixes: whether `a` ends in one of the `:`/`;` separated
/// suffixes of `s` (case kept: `case_map` is the identity on unix).
// port: zipup.c:suffixes
pub(crate) fn suffixes(a: &[u8], s: &[u8]) -> bool {
    let mut m = true;
    let mut q = a.len() as isize - 1;
    for p in (0..s.len()).rev() {
        if s[p] == b':' || s[p] == b';' {
            if m {
                return true;
            }
            m = true;
            q = a.len() as isize - 1;
        } else {
            m = m && q >= 0 && s[p] == a[q as usize];
            q -= 1;
        }
    }
    m
}

/// A test's hook on an opened input.
#[cfg(test)]
pub(crate) type AfterOpen = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    /// Called once an input is open and before it is read: the tests'
    /// way to make a file grow while zip reads it (Review Focus 1).
    pub(crate) static AFTER_OPEN: std::cell::RefCell<Option<AfterOpen>> =
        std::cell::RefCell::new(None);
}

/// zipup.c:zipup: compress the file `f` into a new entry and write it
/// (local header, data, descriptor or rewritten header). The entry's
/// message line was begun by the caller.
// port: zipup.c:zipup
pub(crate) fn add(z: &mut Zr, w: &mut Wr, f: &Found) -> Result<Zipped, Exit> {
    let e = ZEntry {
        name: f.name.clone(),
        iname: f.zname.clone(),
        oname: f.oname.clone(),
        ..ZEntry::default()
    };
    add_entry(z, w, e, &f.disk)
}

/// [`add`] for an entry `e` (its names, and its comment when it is an old
/// entry being updated; every other field is zipup's), the file at `disk`.
/// Under `-X-` the old entry's extra fields (`e.extra` as its local header
/// had it, `e.cextra`) are kept where zip writes no field of their tag
/// (`copy_nondup_extra_fields`).
pub(crate) fn add_entry(
    z: &mut Zr,
    w: &mut Wr,
    mut e: ZEntry,
    disk: &Path,
) -> Result<Zipped, Exit> {
    // the old extra fields are probably obsolete
    let old_extra = std::mem::take(&mut e.extra);
    let old_cextra = std::mem::take(&mut e.cextra);
    let isdir = e.iname.last() == Some(&b'/');
    let ft = match filetime(z, &e.name) {
        Ok(t) => t,
        Err(err) => {
            // nothing of the entry changed yet
            e.extra = old_extra;
            e.cextra = old_cextra;
            return Ok(Zipped::Open(err, Box::new(e)));
        }
    };
    let mut q = ft.q;
    let a = ft.a;
    if isdir != (a & MSDOS_DIR_ATTR != 0) {
        // don't overwrite a directory with a file and vice-versa
        return Ok(Zipped::Miss);
    }
    // reset dot_count for each file
    if !z.o.display_globaldots {
        z.o.dot_count = -1;
    }
    // display the uncompressed size
    let uq = if q < 0 { 0 } else { q as u64 };
    if z.o.display_usize {
        let mut s = Vec::new();
        printf(&mut s, m::USIZE, &[write_num_string(uq).as_bytes()]);
        if z.o.noisy {
            z.mesg_write(&s);
            z.set_line(true);
        }
        if z.o.logall {
            z.log_write(&s);
            z.log_line_started = true;
        }
    }
    e.len = uq;
    // Select the method by the suffix and the global method.
    let method = match z.o.method {
        Method::Store => STORE,
        // Method::Bzip2 is refused before any entry (Task 11)
        _ => DEFLATE,
    };
    let mut m_: u16 = match &z.o.special {
        Some(s) if suffixes(&e.name, s) => STORE,
        _ => method,
    };

    // What the data is read from: nothing (a directory), the link's text, or
    // an open input.
    let mut data = Data::None;
    if e.name == b"-" {
        data = Data::Read(Src::Stdin(stdin_reader(&mut z.host)));
        e.tim = ft.tim;
    } else {
        if z.o.extra_fields != 0 {
            // set_extra_field: the file is stat'ed again for the times
            let stripped = e.name.strip_suffix(b"/").unwrap_or(&e.name).to_vec();
            let p = z.host.path(&stripped);
            let md = if z.o.linkput {
                std::fs::symlink_metadata(&p)
            } else {
                std::fs::metadata(&p)
            };
            if let Ok(md) = md {
                let meta = unix::meta_of(&md);
                e.extra = unix::extra_fields(z.flavour, &meta, true);
                e.cextra = unix::extra_fields(z.flavour, &meta, false);
            }
        }
        if (a >> 16) & S_IFMT == S_IFLNK {
            data = Data::Link;
            m_ = STORE;
        } else if isdir {
            m_ = STORE;
            q = 0;
        } else {
            let p = disk.to_path_buf();
            match File::open(&p) {
                Ok(file) => data = Data::Read(Src::File(z.host.track(&p, file))),
                Err(err) => {
                    // zipup has set these before its open
                    e.att = 0xffff;
                    e.atx = 0;
                    return Ok(Zipped::Open(err, Box::new(e)));
                }
            }
        }
        e.tim = ft.tim;
        #[cfg(test)]
        if !isdir {
            AFTER_OPEN.with(|h| {
                if let Some(h) = h.borrow_mut().as_mut() {
                    h(disk);
                }
            });
        }
    }

    if z.o.extra_fields == 2 {
        // -X-: step through the old extra fields and copy any not already
        // in the new ones
        e.extra = super::readzip::copy_nondup_extra_fields(&old_extra, &e.extra);
        e.cextra = super::readzip::copy_nondup_extra_fields(&old_cextra, &e.cextra);
    }
    if q == 0 {
        m_ = STORE;
    }
    // (m == BEST is DEFLATE here: the method is STORE or DEFLATE already)
    e.vem = if z.o.dosify { 20 } else { 0x300 + 30 };
    e.ver = if m_ == STORE { 10 } else { 20 };
    e.crc = 0;
    // assume first that an extended local header is needed
    e.flg = if isdir { 0 } else { 8 };
    e.lflg = e.flg;
    e.how = m_;
    e.siz = if m_ == STORE && q >= 0 { q as u64 } else { 0 };
    e.len = if q != -1 { q.max(0) as u64 } else { 0 };
    // BINARY in the header for now; set_type: deflate decides
    e.att = 0;
    e.atx = if z.o.dosify { a & 0xff } else { a };

    let r = putlocal(&mut e, &mut w.out);
    drain_dots(z, &mut w.out);
    if let Err(pe) = r {
        return Err(put_failed(z, &e, pe));
    }
    // an earlier write's error (stdio's flag), now that a header is out
    if let Some(err) = w.out.w.ferror() {
        return Err(z.ziperr_os(ZE_WRITE, m::UNEXPECTED_ERROR_ON_ZIP.as_bytes(), &err));
    }
    e.off = w.out.current_local_offset;
    e.dsk = 0;
    w.tempzn += 4 + LOCHEAD + e.iname.len() as u64 + e.extra.len() as u64;

    // Write stored or deflated file to zip file
    let mut isize: u64 = 0;
    let s: u64;
    let mut crc = flate2::Crc::new();
    match data {
        Data::None => s = 0,
        Data::Read(mut src) if m_ != STORE => {
            let level = z.o.level;
            if !(1..=9).contains(&level) {
                return Err(z.ziperr(ZE_LOGIC, m::BAD_PACK_LEVEL.as_bytes()));
            }
            let d = w.deflater.get_or_insert_with(|| {
                let mut d = ZipDeflater::new(level);
                d.set_one_read(true);
                d
            });
            d.set_store_fallback(!w.use_descriptors);
            let mut fr = FileRead::new(&mut src, z.o.translate_eol);
            let mut sink = DataSink { out: &mut w.out };
            let r = d.compress_to(&mut fr, &mut sink);
            drain_dots(z, &mut w.out);
            let sum = match r {
                Ok(sum) => sum,
                Err(err) if err.get_ref().is_some_and(|i| i.is::<BlockVanished>()) => {
                    return Err(z.ziperr(ZE_LOGIC, m::BLOCK_VANISHED.as_bytes()));
                }
                // FileRead takes a read error for the end: this is a write
                Err(err) => return Err(write_failed(z, &err)),
            };
            for _ in 0..sum.slides {
                file_dot(z, WSIZE);
            }
            e.flg |= sum.gp_flags;
            e.att = u16::from(sum.text);
            if sum.stored {
                m_ = STORE;
            }
            isize = sum.in_bytes;
            s = sum.out_bytes;
            e.crc = sum.crc32;
            if e.att == 0 && z.o.translate_eol != 0 {
                // `file_binary` is -1 (true) when nothing was read
                let text = match (fr.file_binary != 0, z.o.translate_eol) {
                    (true, 1) => m::L_BINARY_IGNORED,
                    (true, _) => m::LL_BINARY_IGNORED,
                    (false, 1) => m::L_CORRUPTED,
                    (false, _) => m::LL_CORRUPTED,
                };
                z.zipwarn(text.as_bytes(), b"");
            }
        }
        Data::Link => {
            // deviation 11: a link gone between the stat and here (the C's
            // readlink() -1 is undefined behaviour) is stored empty
            let mut b = match std::fs::read_link(z.host.path(&e.name)) {
                Ok(t) => t.into_os_string().into_encoded_bytes(),
                Err(_) => Vec::new(),
            };
            b.truncate(SBSZ);
            crc.update(&b);
            let r = w.out.bfwrite(&b, Bf::Data);
            drain_dots(z, &mut w.out);
            if let Err(err) = r {
                return Err(write_failed(z, &err));
            }
            isize = b.len() as u64;
            s = isize;
            e.crc = crc.sum();
        }
        Data::Read(mut src) => {
            let mut fr = FileRead::new(&mut src, z.o.translate_eol);
            let mut b = vec![0u8; SBSZ];
            loop {
                let k = fr.file_read(&mut b);
                if k == 0 {
                    break;
                }
                crc.update(&b[..k]);
                isize += k as u64;
                let r = w.out.bfwrite(&b[..k], Bf::Data);
                drain_dots(z, &mut w.out);
                if let Err(err) = r {
                    return Err(write_failed(z, &err));
                }
                file_dot(z, SBSZ as i64);
            }
            if let Some(err) = fr.err.take() {
                // zerr(ifile): the stored loop's k was EOF
                perror(z, m::PERROR_WARNING_NL, &err);
                z.zipwarn(m::COULD_NOT_READ.as_bytes(), &e.oname.clone());
            }
            s = isize;
            e.crc = crc.sum();
        }
    }

    w.tempzn += s;
    // Check the input size (the size changed while zipping)
    if z.o.translate_eol == 0 && q != -1 && isize != q as u64 {
        z.zipwarn(m::SIZE_CHANGED.as_bytes(), &e.name.clone());
    }

    if isdir {
        // a directory
        e.siz = 0;
        e.len = 0;
        e.how = STORE;
        e.ver = 10;
        // never encrypted, so no extended local header
        e.flg &= !8;
        e.lflg &= !8;
    } else {
        // Try to rewrite the local header with the right information
        e.siz = s;
        e.len = isize;
        // zfseeko() flushes the stream: a write that fails there makes the
        // seek fail, and zip writes a descriptor instead
        if w.use_descriptors || w.out.w.seek_to(e.off).is_err() {
            if e.how != m_ {
                return Err(z.ziperr(ZE_LOGIC, m::CANT_REWRITE_METHOD.as_bytes()));
            }
            if m_ == STORE && q < 0 {
                return Err(z.ziperr(ZE_PARMS, m::NO_STORE_ON_PIPES.as_bytes()));
            }
            let r = putextended(&e, &mut w.out);
            drain_dots(z, &mut w.out);
            if let Err(err) = r {
                return Err(write_failed(z, &err));
            }
            w.tempzn += if w.out.zip64_entry { 24 } else { 16 };
            // ruling Z7: the flags as the local header has them (deflate's
            // level bits 1-2 cleared)
            e.flg = e.lflg;
        } else {
            e.how = m_;
            e.ver = if m_ == STORE { 10 } else { 20 };
            // not encrypting, so no extended local header
            if e.flg & 1 == 0 {
                e.flg &= !8;
            }
            e.lflg = e.flg;
            match putlocal_rewrite(&mut e, &mut w.out) {
                Ok(()) => {}
                // putlocal's own `return ZE_TEMP` for its fwrite
                Err(PutError::Write(err)) => return Err(was_zipping(z, ZE_TEMP, &e, &err)),
                Err(pe) => return Err(put_failed(z, &e, pe)),
            }
            if let Err(err) = w.out.w.seek_end() {
                return Err(was_zipping(z, ZE_READ, &e, &err));
            }
        }
    }
    // the local extra field is no longer needed
    e.extra.clear();

    // Display statistics
    if z.o.noisy {
        if z.o.verbose > 0 {
            let mut l = Vec::new();
            printf(
                &mut l,
                m::IN_OUT,
                &[isize.to_string().as_bytes(), s.to_string().as_bytes()],
            );
            z.mesg_write(&l);
        }
        let mut l = Vec::new();
        stat_line(&mut l, m_, isize, s);
        z.mesg_write(&l);
        z.set_line(false);
    }
    if z.o.logall {
        let mut l = Vec::new();
        stat_line(&mut l, m_, isize, s);
        z.log_write(&l);
        z.log_line_started = false;
    }
    Ok(Zipped::Entry(e))
}

/// ` (deflated N%)` or ` (stored 0%)`, with the newline.
pub(crate) fn stat_line(l: &mut Vec<u8>, method: u16, isize: u64, s: u64) {
    if method == DEFLATE {
        printf(l, m::DEFLATED, &[percent(isize, s).to_string().as_bytes()]);
    } else {
        printf(l, m::STORED, &[]);
    }
}

/// A header that could not be written: `ZE_BIG` with putlocal's warning
/// and message, or a failed write (`bfwrite`'s `ZE_WRITE`).
pub(crate) fn put_failed(z: &mut Zr, e: &ZEntry, pe: PutError) -> Exit {
    match pe {
        PutError::Big { warn, why } => {
            if !warn.is_empty() {
                z.zipwarn(warn.as_bytes(), &e.oname);
            }
            z.ziperr(ZE_BIG, why.as_bytes())
        }
        PutError::Write(err) => write_failed(z, &err),
    }
}

/// zip.c:main, `ZIPERR(r, "was zipping <name>")` for a code zipup returns.
fn was_zipping(z: &mut Zr, code: i32, e: &ZEntry, err: &io::Error) -> Exit {
    let mut h = Vec::new();
    printf(&mut h, m::WAS_ZIPPING, &[&e.oname]);
    zerr(z, code, &h, Some(err))
}

/// fileio.c:bfwrite (and zipup.c:flush_outbuf): a write to the archive
/// that failed ends the run with `ziperr(ZE_WRITE, "write error on zip
/// file")`, whatever was being written (zipup's own `return ZE_TEMP` after
/// a failed `zfwrite` is never reached in the C).
pub(crate) fn write_failed(z: &mut Zr, err: &io::Error) -> Exit {
    z.ziperr_os(ZE_WRITE, m::WRITE_ERROR_ON_ZIP.as_bytes(), err)
}

/// deflate's output, each piece one `zfwrite` (`bfwrite(..., BFWRITE_DATA)`).
pub(crate) struct DataSink<'a> {
    out: &'a mut ZOut,
}

impl ZipOut for DataSink<'_> {
    /// zipup.c:seekable: `fseekable(y)`, `ftello` and `fseeko` there, which
    /// flushes the stream (a pipe cannot seek; a failing write fails it).
    /// The position is the stream's own, so standard output that started
    /// past 0 stays where it is (`zip - f` after other output).
    fn seekable(&mut self) -> bool {
        self.out.w.seekable() && self.out.w.seek_here().is_ok()
    }
}

impl Write for DataSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.out.bfwrite(buf, Bf::Data)?;
        // flush_outbuf: `if (ferror(y)) ziperr(ZE_WRITE, ...)`
        if let Some(err) = self.out.w.ferror() {
            return Err(err);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Standard input as an entry's data: descriptor 0 read directly (one
/// `read` per request, as `zread(zstdin, ...)`), or a sandbox's bytes.
pub(crate) fn stdin_reader(host: &mut Host) -> Box<dyn Read> {
    match host {
        Host::Real => match host::stdin_file() {
            Ok(f) => Box::new(f),
            Err(_) => Box::new(io::stdin()),
        },
        Host::Sandbox(_) => Box::new(host.stdin()),
    }
}

#[cfg(test)]
mod tests;
