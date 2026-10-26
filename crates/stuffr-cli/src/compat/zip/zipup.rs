//! Writing a new archive: `zipup.c` (one entry: the method, the local
//! header, the data stored or deflated, `-l`/`-ll`'s line ends, the
//! descriptor or the rewritten header) and the part of `zip.c:main` that
//! drives it (the temporary archive, the loop over the names with its
//! progress and its unreadable inputs, the comments, the central directory,
//! the end record, the replacement of the archive, `finish()`'s `-o` and
//! `-m`).
//!
//! **Inputs are opened through `Host::track`**, so a sandboxed run counts
//! every byte it reads. Reads are zipup's: one `read` per request
//! (`zread`), so a pipe's short reads reach deflate as they reach the C's,
//! and `-l`/`-ll` translate each request as `file_read` does. A read error
//! is the end of the input, as there (`file_read` returns `EOF`): a stored
//! entry then warns "could not read input file", a deflated one does not
//! (zipup's `zerr()` looks at the stored loop's `k` only), and both warn
//! that the size changed.
//!
//! An archive that already exists is Task 7's (`readzipfile`); splits are
//! Task 8's, encryption Task 9's, `-T` Task 7's, bzip2 Task 11's: those
//! command lines still answer `NOT_BUILT`.

use std::fs::File;
use std::io::{self, BufRead, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use stuffr::infozip::{BlockVanished, ZipDeflater};

use super::cli::{Method, ZE_OK, ZE_OPEN, ZE_PARMS};
use super::flavour;
use super::messages::{self as m, printf};
use super::scan::Found;
use super::unix::{self, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use super::zipfile::{
    Bf, CENHEAD, GlobalDots, LOCHEAD, PutError, ZEntry, ZOut, ZWrite, putcentral, putend,
    putextended, putlocal, putlocal_rewrite,
};
use super::{Exit, Zr};
use crate::compat::host::{self, Host};

/// ziperr.h codes this file raises.
const ZE_LOGIC: i32 = 5;
const ZE_BIG: i32 = 6;
const ZE_TEMP: i32 = 10;
const ZE_WRITE: i32 = 14;
const ZE_CREAT: i32 = 15;

/// zip.h's methods.
const STORE: u16 = 0;
const DEFLATE: u16 = 8;
/// tailor.h:SBSZ, the stored entries' copy buffer.
const SBSZ: usize = 16384;
/// tailor.h:ZBSZ, the archive's stdio buffer.
const ZBSZ: usize = 16384;
/// deflate.c's window half, for `-dd`'s dots.
const WSIZE: i64 = 0x8000;
/// zip.h:MSDOS_DIR_ATTR
const MSDOS_DIR_ATTR: u32 = 0x10;
/// zip.c:MAXCOM, a `-c` line.
const MAXCOM: usize = 256;

/// Whether a ziperr code also prints `zip I/O error: <strerror>`
/// (`ZE_S_PERR` in ziperr.h).
fn perr(code: i32) -> bool {
    matches!(code, 10 | 11 | 14 | 15 | 18)
}

/// `ZIPERR(code, h)` with the system's answer `e` where the code prints one.
fn zerr(z: &mut Zr, code: i32, h: &[u8], e: Option<&io::Error>) -> Exit {
    match e {
        Some(e) if perr(code) => z.ziperr_os(code, h, e),
        _ => z.ziperr(code, h),
    }
}

// ---- the archive's sinks ----

/// A file the archive is written to: the temporary archive, or standard
/// output when it is a file. Buffered as zip's stdio stream is (`ZBSZ`), so
/// a failing write shows where zip's would.
struct FileSink {
    f: BufWriter<File>,
    pos: u64,
    /// A sandbox's output budget.
    budget: Option<Arc<AtomicU64>>,
}

impl Write for FileSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(b) = &self.budget {
            host::take(b, buf.len() as u64)?;
        }
        self.f.write_all(buf)?;
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.f.flush()
    }
}

impl ZWrite for FileSink {
    fn seekable(&self) -> bool {
        true
    }
    fn offset(&self) -> u64 {
        self.pos
    }
    fn rewrite(&mut self, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.f.flush()?;
        let f = self.f.get_mut();
        f.seek(SeekFrom::Start(at))?;
        f.write_all(bytes)?;
        f.seek(SeekFrom::Start(self.pos))?;
        Ok(())
    }
}

/// A stream the archive is written to that cannot be rewound (a pipe, a
/// sandbox's standard output).
struct StreamSink {
    w: BufWriter<Box<dyn Write + Send>>,
    pos: u64,
}

impl Write for StreamSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.w.write_all(buf)?;
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl ZWrite for StreamSink {
    fn seekable(&self) -> bool {
        false
    }
    fn offset(&self) -> u64 {
        self.pos
    }
    fn rewrite(&mut self, _at: u64, _bytes: &[u8]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Standard output as the archive: a file when `lseek` works on it
/// (`is_seekable`), else a stream.
fn stdout_sink(host: &Host) -> Box<dyn ZWrite> {
    #[cfg(unix)]
    if matches!(host, Host::Real) {
        use std::os::fd::AsFd;
        if let Ok(fd) = io::stdout().as_fd().try_clone_to_owned() {
            let mut f = File::from(fd);
            if let Ok(p) = f.stream_position()
                && f.seek(SeekFrom::Start(p)).is_ok()
            {
                return Box::new(FileSink {
                    f: BufWriter::with_capacity(ZBSZ, f),
                    pos: 0,
                    budget: None,
                });
            }
        }
    }
    Box::new(StreamSink {
        w: host.out_writer(None),
        pos: 0,
    })
}

// ---- the input ----

/// What an entry's data is read from: a file opened through `Host::track`,
/// or standard input.
enum Src {
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
struct FileRead<'a> {
    src: &'a mut dyn Read,
    /// 0, 1 `-l`, 2 `-ll`.
    translate_eol: u8,
    /// `file_binary`: -1 until the first read, then 1 when it was not text.
    file_binary: i8,
    /// The read error that ended the input, if one did.
    err: Option<io::Error>,
    scratch: Vec<u8>,
}

impl FileRead<'_> {
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
fn is_text_buf(b: &[u8]) -> bool {
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
    deflater: Option<ZipDeflater>,
    /// `use_descriptors`: `-fd`, or an archive that cannot be rewound.
    pub(crate) use_descriptors: bool,
    /// `tempzn`: bytes written so far, by zip's own count.
    pub(crate) tempzn: u64,
    files_total: u64,
    files_so_far: u64,
    bytes_total: u64,
    bytes_so_far: u64,
    good_bytes_so_far: u64,
    bad_files_so_far: u64,
    bad_bytes_so_far: u64,
}

/// What zipup made of one name.
pub(crate) enum Zipped {
    /// The entry, written.
    Entry(ZEntry),
    /// `ZE_OPEN`: it could not be stat'ed or opened (the system's answer).
    Open(io::Error),
    /// `ZE_MISS`: a directory in the scan is a file now, or the other way.
    Miss,
    /// Another failure: zip.c's `ZIPERR(r, "was zipping <name>")`.
    Fail(i32, Option<io::Error>),
}

/// Pass on the dots `bfwrite` printed for `-dg`.
fn drain_dots(z: &mut Zr, w: &mut Wr) {
    if !w.out.dots.is_empty() {
        let d = std::mem::take(&mut w.out.dots);
        z.mesg_write(&d);
        // the leading space does not start a line; a dot does
        if d.contains(&b'.') {
            z.mesg_line_started = true;
        }
    }
}

/// deflate.c:fill_window and zipup.c's stored loop: the per-file dots of
/// `-dd`/`-ds`, once per `unit` bytes handled.
fn file_dot(z: &mut Zr, unit: i64) {
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
        z.mesg_line_started = true;
    }
}

/// `perror(prefix)`: standard error, and the log's copy.
fn perror(z: &mut Zr, fmt: &str, e: &io::Error) {
    let mut line = Vec::new();
    printf(&mut line, fmt, &[&host::strerror(e)]);
    let _ = z.err.write_all(&line);
    let _ = z.err.flush();
    z.log_write(&line);
}

/// zip.c:zipmessage_nl("", 1): end a line a message began.
fn end_line(z: &mut Zr) {
    if z.o.noisy && z.mesg_line_started {
        z.mesg_write(b"\n");
        z.mesg_line_started = false;
    }
    if z.log.is_some() && z.log_line_started {
        z.log_write(b"\n");
        z.log_line_started = false;
    }
}

/// zip.c:DisplayRunningStats: `-dv`, `-dc` and `-db` before a name.
// port: zip.c:DisplayRunningStats
fn display_running_stats(z: &mut Zr, w: &Wr) {
    if z.mesg_line_started {
        z.mesg_write(b"\n");
        z.mesg_line_started = false;
    }
    if z.log_line_started {
        z.log_write(b"\n");
        z.log_line_started = false;
    }
    let mut parts: Vec<Vec<u8>> = Vec::new();
    if z.o.display_volume {
        let mut s = Vec::new();
        printf(&mut s, m::DV, &[b"1", b"1"]);
        parts.push(s);
    }
    if z.o.display_counts {
        let mut s = Vec::new();
        let a = format!("{:>3}", w.files_so_far);
        let b = format!("{:>3}", w.files_total as i64 - w.files_so_far as i64);
        printf(&mut s, m::DC, &[a.as_bytes(), b.as_bytes()]);
        parts.push(s);
    }
    if z.o.display_bytes {
        let mut s = Vec::new();
        let a = format!("{:>4}", write_num_string(w.bytes_so_far));
        printf(&mut s, m::DB_START, &[a.as_bytes()]);
        if w.bytes_total >= w.bytes_so_far {
            let b = format!("{:>4}", write_num_string(w.bytes_total - w.bytes_so_far));
            printf(&mut s, m::DB_LEFT, &[b.as_bytes()]);
        } else {
            let b = format!("{:>4}", write_num_string(w.bytes_so_far - w.bytes_total));
            printf(&mut s, m::DB_OVER, &[b.as_bytes()]);
        }
        parts.push(s);
    }
    for p in parts {
        if z.o.noisy {
            z.mesg_write(&p);
            z.mesg_line_started = true;
        }
        if z.o.logall {
            z.log_write(&p);
            z.log_line_started = true;
        }
    }
}

/// unix.c:filetime for zipup: the attributes (`st_mode << 16`, the
/// MS-DOS read-only and directory bits), the size (-1 for anything but a
/// regular file), the stat and its MS-DOS time.
struct FileTime {
    a: u32,
    q: i64,
    tim: u32,
}

// port: unix/unix.c:filetime
fn filetime(z: &Zr, name: &[u8]) -> Result<FileTime, io::Error> {
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
fn suffixes(a: &[u8], s: &[u8]) -> bool {
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
    let mut e = ZEntry {
        name: f.name.clone(),
        iname: f.zname.clone(),
        oname: f.oname.clone(),
        ..ZEntry::default()
    };
    let isdir = e.iname.last() == Some(&b'/');
    let ft = match filetime(z, &e.name) {
        Ok(t) => t,
        Err(err) => return Ok(Zipped::Open(err)),
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
            z.mesg_line_started = true;
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

    let mut src: Option<Src> = None;
    let mut symlink = false;
    let mut opened_path: Option<PathBuf> = None;
    if e.name == b"-" {
        src = Some(Src::Stdin(stdin_reader(&mut z.host)));
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
        symlink = (a >> 16) & S_IFMT == S_IFLNK;
        if symlink {
            m_ = STORE;
        } else if isdir {
            m_ = STORE;
            q = 0;
        } else {
            let p = f.disk.clone();
            match File::open(&p) {
                Ok(file) => {
                    src = Some(Src::File(z.host.track(&p, file)));
                    opened_path = Some(p);
                }
                Err(err) => return Ok(Zipped::Open(err)),
            }
        }
        e.tim = ft.tim;
    }
    #[cfg(test)]
    if let Some(p) = &opened_path {
        AFTER_OPEN.with(|h| {
            if let Some(h) = h.borrow_mut().as_mut() {
                h(p);
            }
        });
    }
    let _ = opened_path;

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

    if let Err(pe) = putlocal(&mut e, &mut w.out) {
        drain_dots(z, w);
        return put_failed(z, &e, pe);
    }
    drain_dots(z, w);
    e.off = w.out.current_local_offset;
    e.dsk = 0;
    w.tempzn += 4 + LOCHEAD + e.iname.len() as u64 + e.extra.len() as u64;

    // Write stored or deflated file to zip file
    let mut isize: u64 = 0;
    let s: u64;
    let mut stored_read_error = false;
    let mut crc = flate2::Crc::new();
    let mut file_binary: i8 = -1;
    let mut read_err: Option<io::Error> = None;
    if isdir {
        s = 0;
    } else if m_ != STORE {
        let level = z.o.level;
        if !(1..=9).contains(&level) {
            return Err(z.ziperr(ZE_LOGIC, m::BAD_PACK_LEVEL.as_bytes()));
        }
        let d = w.deflater.get_or_insert_with(|| {
            let mut d = ZipDeflater::new(level);
            d.set_one_read(true);
            d
        });
        d.set_store_fallback(!w.use_descriptors && w.out.w.seekable());
        let Some(src_r) = src.as_mut() else {
            return Err(z.ziperr(ZE_LOGIC, m::BLOCK_VANISHED.as_bytes()));
        };
        let mut fr = FileRead {
            src: src_r,
            translate_eol: z.o.translate_eol,
            file_binary: -1,
            err: None,
            scratch: Vec::new(),
        };
        let mut sink = DataSink { out: &mut w.out };
        let r = d.compress(&mut fr, &mut sink);
        file_binary = fr.file_binary;
        read_err = fr.err.take();
        let sum = match r {
            Ok(sum) => sum,
            Err(err) => {
                drain_dots(z, w);
                if err.get_ref().is_some_and(|i| i.is::<BlockVanished>()) {
                    return Err(z.ziperr(ZE_LOGIC, m::BLOCK_VANISHED.as_bytes()));
                }
                return Err(zerr(
                    z,
                    ZE_WRITE,
                    m::WRITE_ERROR_ON_ZIP.as_bytes(),
                    Some(&err),
                ));
            }
        };
        for _ in 0..sum.slides {
            file_dot(z, WSIZE);
        }
        drain_dots(z, w);
        e.flg |= sum.gp_flags;
        e.att = u16::from(sum.text);
        if sum.stored {
            m_ = STORE;
        }
        isize = sum.in_bytes;
        s = sum.out_bytes;
        e.crc = sum.crc32;
        if e.att == 0 && z.o.translate_eol != 0 {
            let text = if file_binary != 0 {
                if z.o.translate_eol == 1 {
                    m::L_BINARY_IGNORED
                } else {
                    m::LL_BINARY_IGNORED
                }
            } else if z.o.translate_eol == 1 {
                m::L_CORRUPTED
            } else {
                m::LL_CORRUPTED
            };
            z.zipwarn(text.as_bytes(), b"");
        }
    } else if symlink {
        let mut b = match std::fs::read_link(z.host.path(&e.name)) {
            Ok(t) => t.into_os_string().into_encoded_bytes(),
            Err(_) => Vec::new(),
        };
        b.truncate(SBSZ);
        crc.update(&b);
        let r = w.out.bfwrite(&b, Bf::Data);
        drain_dots(z, w);
        if let Err(err) = r {
            return Ok(Zipped::Fail(ZE_TEMP, Some(err)));
        }
        isize = b.len() as u64;
        s = isize;
        e.crc = crc.sum();
    } else {
        let Some(src_r) = src.as_mut() else {
            return Err(z.ziperr(ZE_LOGIC, m::BLOCK_VANISHED.as_bytes()));
        };
        let mut fr = FileRead {
            src: src_r,
            translate_eol: z.o.translate_eol,
            file_binary: -1,
            err: None,
            scratch: Vec::new(),
        };
        let mut b = vec![0u8; SBSZ];
        loop {
            let k = fr.file_read(&mut b);
            if k == 0 {
                break;
            }
            crc.update(&b[..k]);
            isize += k as u64;
            let r = w.out.bfwrite(&b[..k], Bf::Data);
            drain_dots(z, w);
            if let Err(err) = r {
                return Ok(Zipped::Fail(ZE_TEMP, Some(err)));
            }
            file_dot(z, SBSZ as i64);
        }
        if let Some(err) = fr.err.take() {
            stored_read_error = true;
            read_err = Some(err);
        }
        s = isize;
        e.crc = crc.sum();
    }
    let _ = file_binary;
    if stored_read_error && let Some(err) = &read_err {
        // zerr(ifile): the stored loop's k was EOF
        perror(z, m::PERROR_WARNING_NL, err);
        z.zipwarn(m::COULD_NOT_READ.as_bytes(), &e.oname.clone());
    }
    drop(src);

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
        if w.use_descriptors {
            if m_ == STORE && q < 0 {
                return Err(z.ziperr(ZE_PARMS, m::NO_STORE_ON_PIPES.as_bytes()));
            }
            if let Err(err) = putextended(&e, &mut w.out) {
                drain_dots(z, w);
                return Ok(Zipped::Fail(ZE_TEMP, Some(err)));
            }
            drain_dots(z, w);
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
            if let Err(pe) = putlocal_rewrite(&mut e, &mut w.out) {
                return put_failed(z, &e, pe);
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
        z.mesg_line_started = false;
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
fn stat_line(l: &mut Vec<u8>, method: u16, isize: u64, s: u64) {
    if method == DEFLATE {
        printf(l, m::DEFLATED, &[percent(isize, s).to_string().as_bytes()]);
    } else {
        printf(l, m::STORED, &[]);
    }
}

/// A header write that failed: `ZE_BIG` with putlocal's warning and
/// message (the run ends here), or `ZE_TEMP` back to the caller.
fn put_failed(z: &mut Zr, e: &ZEntry, pe: PutError) -> Result<Zipped, Exit> {
    match pe {
        PutError::Big { warn, why } => {
            if !warn.is_empty() {
                z.zipwarn(warn.as_bytes(), &e.oname);
            }
            Err(z.ziperr(ZE_BIG, why.as_bytes()))
        }
        PutError::Temp(err) => Ok(Zipped::Fail(ZE_TEMP, Some(err))),
    }
}

/// deflate's output, each piece one `zfwrite` (`bfwrite(..., BFWRITE_DATA)`).
struct DataSink<'a> {
    out: &'a mut ZOut,
}

impl Write for DataSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.out.bfwrite(buf, Bf::Data)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Standard input as an entry's data: descriptor 0 read directly (one
/// `read` per request, as `zread(zstdin, ...)`), or a sandbox's bytes.
fn stdin_reader(host: &mut Host) -> Box<dyn Read> {
    match host {
        Host::Real => match host::stdin_file() {
            Ok(f) => Box::new(f),
            Err(_) => Box::new(io::stdin()),
        },
        Host::Sandbox(_) => Box::new(host.stdin()),
    }
}

/// Where `-c` and `-z` read their lines: standard input, or (after `-@` or
/// as a filter, when standard input is the names or the data) standard
/// error opened for reading (`fdopen(fileno(stderr), "r")`). `None` is
/// that `fdopen` failing: standard error is not open for reading (a pipe,
/// a file opened to write; a sandbox's).
fn comment_stream(z: &mut Zr) -> Option<Box<dyn BufRead>> {
    let from_stderr = z.o.comment_from_stderr || z.o.filter_mode;
    match &mut z.host {
        Host::Real => {
            if from_stderr {
                #[cfg(unix)]
                {
                    use std::os::fd::AsFd;
                    // SAFETY: F_GETFL only reads descriptor 2's flags.
                    let fl = unsafe { libc::fcntl(2, libc::F_GETFL) };
                    if fl == -1 || fl & libc::O_ACCMODE == libc::O_WRONLY {
                        return None;
                    }
                    if let Ok(fd) = io::stderr().as_fd().try_clone_to_owned() {
                        return Some(Box::new(io::BufReader::new(File::from(fd))));
                    }
                }
                None
            } else {
                Some(Box::new(io::stdin().lock()))
            }
        }
        h @ Host::Sandbox(_) => {
            if from_stderr {
                None
            } else {
                Some(Box::new(h.stdin()))
            }
        }
    }
}

/// `fgets(e, MAXCOM + 1, stream)`: a line with its newline, at most
/// `MAXCOM` bytes; `None` at the end (or an error) with nothing read.
fn fgets(r: &mut dyn BufRead) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    while line.len() < MAXCOM {
        let buf = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if buf.is_empty() {
            break;
        }
        let room = MAXCOM - line.len();
        let take = buf.len().min(room);
        if let Some(i) = buf[..take].iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&buf[..=i]);
            r.consume(i + 1);
            return Some(line);
        }
        line.extend_from_slice(&buf[..take]);
        r.consume(take);
    }
    (!line.is_empty()).then_some(line)
}

/// A temporary archive (`mkstemp("ziXXXXXX")` in the archive's directory or
/// `-b`'s), removed unless it was published.
struct Temp {
    path: Option<PathBuf>,
}

impl Drop for Temp {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// `mkstemp(template)`: `dir` + `zi` + six random characters, created new,
/// mode 0600. The name tried last is returned with the error.
fn mkstemp(host: &Host, dir: &[u8]) -> (Vec<u8>, io::Result<File>) {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
        ^ (u64::from(std::process::id()) << 32);
    let mut name = Vec::new();
    for _ in 0..100 {
        name = dir.to_vec();
        name.extend_from_slice(b"zi");
        for _ in 0..6 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            name.push(CHARS[(seed % CHARS.len() as u64) as usize]);
        }
        let mut opts = File::options();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(host.path(&name)) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            r => return (name, r),
        }
    }
    (name, Err(io::Error::from(io::ErrorKind::AlreadyExists)))
}

/// fileio.c:replace for a new archive: `rename` the temporary onto it, or
/// copy it when the rename crosses devices. `Err` is the ziperr code and
/// the system's answer.
// port: fileio.c:replace
fn replace(d: &Path, s: &Path) -> Result<(), (i32, io::Error)> {
    // an existing destination is Task 7's (links respected, unlinked first)
    if let Ok(t) = std::fs::symlink_metadata(d) {
        #[cfg(unix)]
        let copy = {
            use std::os::unix::fs::MetadataExt;
            t.nlink() > 1 || t.file_type().is_symlink()
        };
        #[cfg(not(unix))]
        let copy = t.file_type().is_symlink();
        if !copy {
            std::fs::remove_file(d).map_err(|e| (ZE_CREAT, e))?;
        } else {
            return copy_over(d, s);
        }
    }
    match std::fs::rename(s, d) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) => copy_over(d, s),
        Err(e) => Err((ZE_CREAT, e)),
    }
}

/// fileio.c:replace's copy: `s` into `d`, then `s` removed.
fn copy_over(d: &Path, s: &Path) -> Result<(), (i32, io::Error)> {
    let mut f = File::open(s).map_err(|e| (ZE_TEMP, e))?;
    let mut g = File::create(d).map_err(|e| (ZE_CREAT, e))?;
    if let Err(e) = io::copy(&mut f, &mut g).and_then(|_| g.flush()) {
        let _ = std::fs::remove_file(d);
        return Err((ZE_WRITE, e));
    }
    let _ = std::fs::remove_file(s);
    Ok(())
}

/// zip.c:main, from "make sure the zip file is writeable" to the end: write
/// the archive of `found` (no archive exists at the path), replace, and
/// `finish()`.
// port: zip.c:main
pub(crate) fn write_new(z: &mut Zr, found: Vec<Found>) -> Exit {
    // Tasks 7 (-T), 8 (splits), 9 (encryption) and 11 (bzip2)
    if z.o.key.is_some()
        || z.o.key_needed
        || z.o.split_method > 0
        || z.o.method == Method::Bzip2
        || z.o.test
    {
        return z.not_built();
    }
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    let to_stdout = zipfile == b"-";
    let out_path = z.o.out_path.clone().unwrap_or_else(|| zipfile.clone());
    let mut zip_attributes: u32 = 0;
    // Make sure the zip file is writeable (the C leaves the check to the
    // end when -b names the temp's directory).
    if !to_stdout && !z.o.tempdir {
        let p = z.host.path(&out_path);
        match File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)
        {
            Err(e) => return z.ziperr_os(ZE_CREAT, &out_path, &e),
            Ok(f) => {
                drop(f);
                zip_attributes = std::fs::metadata(&p).map_or(0, |md| unix::meta_of(&md).mode);
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    if z.o.show_what_doing {
        z.mesg_write(m::SD_OPEN_ZIP.as_bytes());
    }
    let mut temp = Temp { path: None };
    let mut tempzip: Vec<u8> = b"-".to_vec();
    let sink: Box<dyn ZWrite> = if to_stdout {
        stdout_sink(&z.host)
    } else {
        if z.o.show_what_doing {
            z.mesg_write(m::SD_CREATING.as_bytes());
        }
        let dir: Vec<u8> = match &z.o.tempath {
            Some(t) => {
                let mut d = t.clone();
                if d.last() != Some(&b'/') {
                    d.push(b'/');
                }
                d
            }
            None => match zipfile.iter().rposition(|&b| b == b'/') {
                Some(i) => zipfile[..=i].to_vec(),
                None => Vec::new(),
            },
        };
        let (name, r) = mkstemp(&z.host, &dir);
        tempzip = name;
        match r {
            Err(e) => return z.ziperr_os(ZE_TEMP, &tempzip, &e),
            Ok(f) => {
                temp.path = Some(z.host.path(&tempzip));
                let budget = match &z.host {
                    Host::Sandbox(s) => Some(s.budget.clone()),
                    Host::Real => None,
                };
                Box::new(FileSink {
                    f: BufWriter::with_capacity(ZBSZ, f),
                    pos: 0,
                    budget,
                })
            }
        }
    };
    let use_descriptors = z.o.use_descriptors || !sink.seekable();
    let gdots = z.o.display_globaldots.then_some(GlobalDots {
        dot_size: z.o.dot_size,
        dot_count: z.o.dot_count,
    });
    let mut w = Wr {
        out: ZOut::new(sink, z.o.force_zip64, gdots),
        deflater: None,
        use_descriptors,
        tempzn: 0,
        files_total: found.len() as u64,
        files_so_far: 0,
        bytes_total: found.iter().map(|f| f.usize.unwrap_or(0)).sum(),
        bytes_so_far: 0,
        good_bytes_so_far: 0,
        bad_files_so_far: 0,
        bad_bytes_so_far: 0,
    };
    let mut o = false;
    if z.o.show_what_doing {
        z.mesg_write(m::SD_ZIPPING_NEW.as_bytes());
    }
    let mut entries: Vec<ZEntry> = Vec::new();
    for f in &found {
        display_running_stats(z, &w);
        let mut line = Vec::new();
        printf(&mut line, m::ADDING, &[&f.oname]);
        if z.o.noisy {
            z.mesg_write(&line);
            z.mesg_line_started = true;
        }
        if z.o.logall {
            z.log_write(&line);
            z.log_line_started = true;
        }
        let len = f.usize.unwrap_or(0);
        let r = match add(z, &mut w, f) {
            Ok(r) => r,
            Err(x) => return x,
        };
        match r {
            Zipped::Fail(code, err) => {
                end_line(z);
                let mut h = Vec::new();
                printf(&mut h, m::WAS_ZIPPING, &[&f.oname]);
                return zerr(z, code, &h, err.as_ref());
            }
            Zipped::Open(err) => {
                o = true;
                end_line(z);
                perror(z, m::PERROR_WARNING, &err);
                z.zipwarn(m::COULD_NOT_OPEN.as_bytes(), &f.oname);
                if z.o.bad_open_is_error {
                    let mut h = Vec::new();
                    printf(&mut h, m::WAS_ZIPPING, &[&f.name]);
                    // ubuntu: glibc's stdio leaves EINVAL in errno by the
                    // time ziperr prints it (measured)
                    let shown = if flavour::stale_errno_after_warning(z.flavour) {
                        io::Error::from_raw_os_error(22)
                    } else {
                        err
                    };
                    return z.ziperr_os(ZE_OPEN, &h, &shown);
                }
                w.files_so_far += 1;
                w.bytes_so_far += len;
                w.bad_files_so_far += 1;
                w.bad_bytes_so_far += len;
            }
            Zipped::Miss => {
                o = true;
                end_line(z);
                z.zipwarn(m::FILE_AND_DIR.as_bytes(), &f.oname);
                w.files_so_far += 1;
                w.bytes_so_far += len;
                w.bad_files_so_far += 1;
                w.bad_bytes_so_far += len;
            }
            Zipped::Entry(e) => {
                w.files_so_far += 1;
                w.good_bytes_so_far += e.len;
                w.bytes_so_far += len;
                entries.push(e);
            }
        }
    }
    // final status
    if w.bad_files_so_far > 0 {
        let mut s = Vec::new();
        s.extend_from_slice(m::NOT_ALL_READABLE.as_bytes());
        let read = (w.files_total - w.bad_files_so_far).to_string();
        printf(&mut s, m::FILES_READ, &[read.as_bytes()]);
        printf(
            &mut s,
            m::N_BYTES,
            &[write_num_string(w.good_bytes_so_far).as_bytes()],
        );
        printf(
            &mut s,
            m::SKIPPED,
            &[w.bad_files_so_far.to_string().as_bytes()],
        );
        printf(
            &mut s,
            m::N_BYTES,
            &[write_num_string(w.bad_bytes_so_far).as_bytes()],
        );
        if z.o.noisy {
            let mut l = s.clone();
            l.push(b'\n');
            z.mesg_write(&l);
        }
        z.log_write(&s);
    }
    // Get one line comment for each new entry
    if z.o.show_what_doing {
        z.mesg_write(m::SD_GET_COMMENT.as_bytes());
    }
    let mut zcomment: Vec<u8> = Vec::new();
    if z.o.comadd || z.o.zipedit {
        let mut cs = comment_stream(z);
        if z.o.comadd {
            for e in &mut entries {
                if z.o.noisy {
                    let mut l = Vec::new();
                    printf(&mut l, m::ENTER_COMMENT, &[&e.oname]);
                    z.mesg_write(&l);
                }
                // deviation 9: fgets(NULL) after a failed fdopen is SIGSEGV
                // in both references, which zip's handler answers
                let Some(r) = cs.as_mut() else {
                    return super::scan::crashed(z);
                };
                if let Some(mut p) = fgets(r.as_mut()) {
                    if p.last() == Some(&b'\n') {
                        p.pop();
                    }
                    e.comment = p;
                }
            }
        }
        if z.o.zipedit {
            if z.o.noisy {
                z.mesg_write(m::ENTER_ZIP_COMMENT.as_bytes());
            }
            let Some(r) = cs.as_mut() else {
                // deviation 9, as for -c
                return super::scan::crashed(z);
            };
            while let Some(mut e) = fgets(r.as_mut()) {
                if e == b".\n" {
                    break;
                }
                if e.last() == Some(&b'\n') {
                    e.pop();
                }
                if !zcomment.is_empty() {
                    zcomment.extend_from_slice(b"\r\n");
                    zcomment.extend_from_slice(&e);
                } else if e.is_empty() {
                    zcomment = b"\r\n".to_vec();
                } else {
                    zcomment = e;
                }
            }
        }
    }
    if z.o.display_globaldots {
        z.mesg_write(b"\n");
        z.mesg_line_started = false;
    }
    // Write central directory and end header to temporary zip
    if z.o.show_what_doing {
        z.mesg_write(m::SD_WRITING_CENTRAL.as_bytes());
    }
    let c = w.tempzn;
    let (mut n, mut t, mut k) = (0u64, 0u64, 0u64);
    for e in &mut entries {
        let r = putcentral(e, &mut w.out);
        drain_dots(z, &mut w);
        match r {
            Ok(()) => {}
            Err(PutError::Big { why, .. }) => {
                z.zipwarn(why.as_bytes(), b"");
                return z.ziperr(ZE_BIG, &tempzip);
            }
            Err(PutError::Temp(err)) => return z.ziperr_os(ZE_TEMP, &tempzip, &err),
        }
        w.tempzn +=
            4 + CENHEAD + e.iname.len() as u64 + e.cextra.len() as u64 + e.comment.len() as u64;
        n += e.len;
        t += e.siz;
        k += 1;
    }
    if k == 0 {
        z.zipwarn(m::ZIP_FILE_EMPTY.as_bytes(), b"");
    }
    let mut total = Vec::new();
    printf(
        &mut total,
        m::TOTAL_BYTES,
        &[
            n.to_string().as_bytes(),
            t.to_string().as_bytes(),
            percent(n, t).to_string().as_bytes(),
        ],
    );
    if z.o.verbose > 0 {
        z.mesg_write(&total);
    }
    if z.o.logall {
        z.log_write(&total);
    }
    let size = w.tempzn - c;
    if z.o.show_what_doing {
        z.mesg_write(m::SD_WRITING_END.as_bytes());
    }
    let r = putend(&mut w.out, k, size, c, &zcomment);
    drain_dots(z, &mut w);
    if let Err(err) = r {
        return z.ziperr_os(ZE_TEMP, &tempzip, &err);
    }
    // fclose(y)
    if let Err(err) = w.out.w.flush() {
        return z.ziperr_os(ZE_TEMP, &tempzip, &err);
    }
    drop(w);
    // Replace old zip file with new zip file, leaving only the new one
    if !to_stdout {
        if z.o.show_what_doing {
            z.mesg_write(m::SD_REPLACING.as_bytes());
        }
        let tmp = temp.path.take().unwrap_or_default();
        if let Err((code, err)) = replace(&z.host.path(&out_path), &tmp) {
            // the new archive stays, under the temporary name
            z.zipwarn(m::NEW_ZIP_LEFT_AS.as_bytes(), &tempzip);
            return zerr(z, code, m::WAS_REPLACING.as_bytes(), Some(&err));
        }
        if zip_attributes != 0 {
            set_mode(&z.host.path(&out_path), zip_attributes);
        }
        if z.o.show_what_doing {
            z.mesg_write(m::SD_SETTING_TYPE.as_bytes());
        }
    }
    // finish the log file
    if z.log.is_some() {
        let mut l = Vec::new();
        printf(&mut l, m::LOG_TOTAL, &[found.len().to_string().as_bytes()]);
        let total = found.iter().map(|f| f.usize.unwrap_or(0)).sum::<u64>();
        let good: u64 = entries.iter().map(|e| e.len).sum();
        if good != total {
            l.extend_from_slice(m::LOG_PLANNED.as_bytes());
            l.extend_from_slice(write_num_string(total).trim_start().as_bytes());
            l.extend_from_slice(m::LOG_ACTUAL.as_bytes());
            l.extend_from_slice(write_num_string(good).trim_start().as_bytes());
            l.extend_from_slice(m::LOG_BYTES.as_bytes());
        } else {
            l.extend_from_slice(write_num_string(total).trim_start().as_bytes());
            l.extend_from_slice(m::LOG_BYTES.as_bytes());
        }
        let now = super::asctime_now(z);
        printf(&mut l, m::LOG_DONE, &[now.as_bytes()]);
        z.log_write(&l);
    }
    finish(z, if o { ZE_OPEN } else { ZE_OK }, &mut entries)
}

/// `chmod(path, mode)` (`setfileattr`).
fn set_mode(p: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode & 0o7777));
    }
    #[cfg(not(unix))]
    {
        let _ = (p, mode);
    }
}

/// zip.c:finish with entries: `-o` (the archive's time is its newest
/// file's) and `-m` (the inputs deleted, after the archive is in place).
// port: zip.c:finish
fn finish(z: &mut Zr, code: i32, entries: &mut [ZEntry]) -> Exit {
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    if z.o.latest && !zipfile.is_empty() && zipfile != b"-" {
        if entries.is_empty() {
            z.zipwarn(m::ZIP_EMPTY_NO_LATEST.as_bytes(), b"");
        } else {
            let mut t: u32 = 0;
            for e in entries.iter() {
                if e.iname.last() == Some(&b'/') {
                    continue; // directories are ignored
                }
                let tim = ut_mtime(&e.cextra).map_or(e.tim, |mt| unix::unix2dostime(z, mt) as u32);
                t = t.max(tim);
            }
            if t != 0 {
                stamp(z, &zipfile, t);
            } else {
                z.zipwarn(m::ONLY_DIRS_NO_LATEST.as_bytes(), b"");
            }
        }
    }
    if z.o.dispose {
        trash(z, entries);
    }
    Exit { code }
}

/// The modification time of a `UT` block in `extra`
/// (zipfile.c:ef_scan_ut_time, as `get_ef_ut_ztime` reads it).
fn ut_mtime(extra: &[u8]) -> Option<i64> {
    let mut p = 0;
    let mut found = None;
    while p + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[p], extra[p + 1]]);
        let len = usize::from(u16::from_le_bytes([extra[p + 2], extra[p + 3]]));
        if len > extra.len() - p - 4 {
            break;
        }
        if id == 0x5455 && len >= 1 {
            let flags = extra[p + 4];
            found = if flags & 1 != 0 && len >= 5 {
                let b = &extra[p + 5..p + 9];
                Some(i64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
            } else {
                None
            };
        }
        p += 4 + len;
    }
    found
}

/// unix.c:stamp: the file's access and modification times set to the
/// MS-DOS time `d` read as local time (`dos2unixtime`).
fn stamp(z: &Zr, name: &[u8], d: u32) {
    let t = dos2unixtime(&z.host, d);
    let when = if t >= 0 {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(t as u64)
    } else {
        std::time::UNIX_EPOCH - std::time::Duration::from_secs(t.unsigned_abs())
    };
    if let Ok(f) = File::options().write(true).open(z.host.path(name)) {
        let _ = f.set_times(
            std::fs::FileTimes::new()
                .set_accessed(when)
                .set_modified(when),
        );
    }
}

/// fileio.c:dos2unixtime: `mktime` of the MS-DOS fields in the local zone
/// (a sandbox's is UTC).
#[allow(clippy::useless_conversion)] // `time_t` is 32 bits on some unixes
fn dos2unixtime(host: &Host, d: u32) -> i64 {
    let sec = ((d << 1) & 0x3e) as i64;
    let min = ((d >> 5) & 0x3f) as i64;
    let hour = ((d >> 11) & 0x1f) as i64;
    let mday = ((d >> 16) & 0x1f) as i64;
    let mon = ((d >> 21) & 0x0f) as i64 - 1;
    let year = ((d >> 25) & 0x7f) as i64 + 80;
    #[cfg(unix)]
    if matches!(host, Host::Real) {
        // SAFETY: `tm` is plain data filled before the call; mktime only
        // reads and normalises it.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_sec = sec as libc::c_int;
        tm.tm_min = min as libc::c_int;
        tm.tm_hour = hour as libc::c_int;
        tm.tm_mday = mday as libc::c_int;
        tm.tm_mon = mon as libc::c_int;
        tm.tm_year = year as libc::c_int;
        tm.tm_isdst = -1;
        return i64::from(unsafe { libc::mktime(&mut tm) });
    }
    let _ = host;
    // days from civil, UTC
    let (y, m0) = (year + 1900, mon + 1);
    let yy = if m0 <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (m0 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + mday - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86400 + hour * 3600 + min * 60 + sec
}

/// zipfile.c:trash for new entries: delete each added file, then the
/// added directories, deepest first, when empty. Failures to delete a
/// directory are ignored, as there.
// port: zipfile.c:trash
fn trash(z: &mut Zr, entries: &[ZEntry]) {
    for e in entries {
        if e.iname.last() != Some(&b'/') {
            if z.o.verbose > 0 {
                let mut l = Vec::new();
                printf(&mut l, m::DELETING_FILE, &[&e.name]);
                z.mesg_write(&l);
            }
            if std::fs::remove_file(z.host.path(&e.name)).is_err() {
                z.zipwarn(m::ERROR_DELETING.as_bytes(), &e.name);
            }
            // without directory names (-D) the C cuts the names to their
            // parents, but leaves them so that none counts as a directory
        }
    }
    let mut dirs: Vec<&ZEntry> = Vec::new();
    for e in entries {
        if e.iname.last() == Some(&b'/')
            && (dirs.is_empty() || dirs.last().is_some_and(|l| l.name != e.name))
        {
            dirs.push(e);
        }
    }
    // reverse order of the stored names: subdirectories first
    dirs.sort_by(|a, b| b.iname.cmp(&a.iname));
    let mut prev: Option<Vec<u8>> = None;
    for d in dirs {
        let mut p = d.name.clone();
        if p.is_empty() {
            continue;
        }
        if p.last() == Some(&b'/') {
            p.pop();
        }
        if prev.as_ref() != Some(&p) {
            if z.o.verbose > 0 {
                let mut l = Vec::new();
                printf(&mut l, m::DELETING_DIR, &[&p]);
                z.mesg_write(&l);
            }
            let _ = std::fs::remove_dir(z.host.path(&p));
        }
        prev = Some(p);
    }
}

#[cfg(test)]
mod tests;
