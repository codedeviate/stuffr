//! The reading half of `zipfile.c`: the archive already at the path
//! (`readzipfile`, `scanzipf_regnew`: the end record, the Zip64 end record
//! and locator, the central directory), the local header of an entry
//! (`readlocal`), the copy of an entry into the new archive (`zipcopy`,
//! fileio.c's `bfcopy`) and the `UT`/`UX` times of an entry
//! (`ef_scan_ut_time`).
//!
//! **Every read of the archive goes through `Host::track`** ([`CFile`]), so
//! a sandboxed run counts it. The C reads through stdio (`getc`, `ungetc`,
//! `fread`, `fseeko`, `feof`, `ferror`); [`CFile`] keeps those semantics,
//! the `errno` of the last failure included (the C's messages print it).
//!
//! Not here: `-F`/`-FF` (`scanzipf_fixnew`) and the reading of split
//! archives' other parts (Task 8): a run that needs another part answers
//! `messages::NOT_BUILT`. Ubuntu's `UNICODE_SUPPORT` reading of bit-11 and
//! Unicode Path names is Task 11's.
//!
//! Undefined behaviour in the C, not reproduced (deviation 13 in
//! `mod.rs`): a short read of the end record or the Zip64 records leaves
//! the C's stack buffer uninitialised (stuffr reads zeros); a Zip64 extra
//! field shorter than the fields it should hold is read past its end by
//! `adjust_zip_central_entry` (stuffr reads zeros); `copy_nondup_extra_fields`
//! copies a block that runs past its field (stuffr stops at the field's
//! end).

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};

use super::cli::{ZE_OPEN, ZE_PARMS};
use super::flavour;
use super::messages::{self as m, printf};
use super::zipfile::{Bf, LOCHEAD, ZEntry, ZOut};
use super::{Exit, Zr};
use crate::compat::host::InFile;

/// ziperr.h codes this file returns.
pub(crate) const ZE_EOF: i32 = 2;
pub(crate) const ZE_FORM: i32 = 3;
pub(crate) const ZE_READ: i32 = 11;
/// zip.h:ENDHEAD and friends.
const ENDHEAD: usize = 18;
const EC64LOC: usize = 16;
const EC64REC: usize = 52;
const CENHEAD: usize = 42;
/// zip.h's general-purpose bit 11.
const UTF8_BIT: u16 = 1 << 11;
/// tailor.h:NUM_HOSTS
const NUM_HOSTS: u16 = 31;
/// tailor.h:CBSZ, bfcopy's buffer.
const CBSZ: usize = 16384;
const ZIP_UWORD32_MAX: u64 = 0xffff_ffff;
const ZIP_UWORD16_MAX: u64 = 0xffff;

/// An archive entry read from the central directory (`struct zlist`).
#[derive(Debug, Clone, Default)]
pub(crate) struct ZFile {
    /// The headers' fields; `e.name` is `z->name` (the external name, or
    /// the name on disk once `newname` matched it), `e.oname` the shown
    /// one.
    pub(crate) e: ZEntry,
    /// `z->zname`: the external name of the stored one (`in2ex`, the same
    /// on unix up to its first NUL).
    pub(crate) zname: Vec<u8>,
    /// 0 keep, 1 operate on, 2 comment only (`-c` on an entry up to date).
    pub(crate) mark: u8,
    /// `-um`/`-fm`: delete the file although the entry was up to date.
    pub(crate) trash: bool,
    /// `-FS`: the entry matches the file on disk.
    pub(crate) current: bool,
    /// `-k` given when it was matched.
    pub(crate) dosflag: bool,
}

/// What `readzipfile` leaves in zip's globals.
#[derive(Debug, Default)]
pub(crate) struct Archive {
    /// `zipfile_exists`
    pub(crate) exists: bool,
    /// `zfiles`, in the central directory's order.
    pub(crate) zfiles: Vec<ZFile>,
    /// `zsort`: indices of `zfiles` sorted by stored name (the flavour's
    /// `qsort`), for `zsearch`.
    pub(crate) zsort: Vec<usize>,
    /// `zipbeg`: where the first entry starts (what is before it is copied).
    pub(crate) zipbeg: u64,
    /// `cenbeg`: where the central directory starts.
    pub(crate) cenbeg: u64,
    /// `zcomment`
    pub(crate) zcomment: Vec<u8>,
    /// `total_disks`
    pub(crate) total_disks: u64,
}

/// A name as the C's string functions see it: up to its first NUL.
pub(crate) fn cstr(b: &[u8]) -> &[u8] {
    match b.iter().position(|&c| c == 0) {
        Some(i) => &b[..i],
        None => b,
    }
}

// ---- stdio over a tracked file ----

/// A stdio stream reading the archive: `getc`/`ungetc`, `fread`, `fseeko`,
/// `ftello`, `feof`, `ferror`, and the `errno` the last failure left.
pub(crate) struct CFile {
    f: BufReader<InFile>,
    back: Option<u8>,
    eof: bool,
    err: bool,
    /// `errno` after the last failing call (0 before any).
    pub(crate) errno: i32,
}

impl CFile {
    /// `fopen(path, "rb")`, through `Host::track`.
    pub(crate) fn open(z: &Zr, name: &[u8]) -> io::Result<CFile> {
        let p = z.host.path(name);
        let f = File::open(&p)?;
        Ok(CFile {
            f: BufReader::with_capacity(8192, z.host.track(&p, f)),
            back: None,
            eof: false,
            err: false,
            errno: 0,
        })
    }

    fn failed(&mut self, e: &io::Error) {
        self.errno = e.raw_os_error().unwrap_or(5);
    }

    /// `getc`
    pub(crate) fn getc(&mut self) -> Option<u8> {
        if let Some(b) = self.back.take() {
            return Some(b);
        }
        loop {
            match self.f.fill_buf() {
                Ok([]) => {
                    self.eof = true;
                    return None;
                }
                Ok(b) => {
                    let c = b[0];
                    self.f.consume(1);
                    return Some(c);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.failed(&e);
                    self.err = true;
                    return None;
                }
            }
        }
    }

    /// `ungetc`, which also clears the end-of-file flag.
    fn ungetc(&mut self, c: u8) {
        self.back = Some(c);
        self.eof = false;
    }

    /// `fread(buf, 1, n, f)`: what could be read (short at the end or on an
    /// error, with the flags set).
    pub(crate) fn fread(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n.min(1 << 20));
        if n > 0
            && let Some(b) = self.back.take()
        {
            out.push(b);
        }
        while out.len() < n {
            let want = (n - out.len()).min(CBSZ);
            let mut chunk = vec![0u8; want];
            match self.f.read(&mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(k) => out.extend_from_slice(&chunk[..k]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.failed(&e);
                    self.err = true;
                    break;
                }
            }
        }
        out
    }

    /// `fseeko(f, at, SEEK_SET)`: a negative offset fails with `EINVAL`.
    pub(crate) fn seek(&mut self, at: i128) -> bool {
        self.back = None;
        if at < 0 || at > i128::from(i64::MAX) {
            self.errno = 22;
            return false;
        }
        match self.f.seek(SeekFrom::Start(at as u64)) {
            Ok(_) => {
                self.eof = false;
                true
            }
            Err(e) => {
                self.failed(&e);
                false
            }
        }
    }

    /// `fseeko(f, 0, SEEK_END)`'s position: the file's size.
    fn end(&mut self) -> Option<u64> {
        self.back = None;
        match self.f.seek(SeekFrom::End(0)) {
            Ok(p) => Some(p),
            Err(e) => {
                self.failed(&e);
                None
            }
        }
    }

    /// `ftello`
    pub(crate) fn tell(&mut self) -> u64 {
        let p = self.f.stream_position().unwrap_or(0);
        p - u64::from(self.back.is_some())
    }

    pub(crate) fn feof(&self) -> bool {
        self.eof
    }

    pub(crate) fn ferror(&self) -> bool {
        self.err
    }

    /// The error a `ZE_READ` prints (`strerror(errno)`).
    pub(crate) fn error(&self) -> io::Error {
        io::Error::from_raw_os_error(self.errno)
    }
}

/// zipfile.c:find_next_signature: the next `PK` followed by two bytes below
/// 16 (`sigbuf`), the stream left after it.
// port: zipfile.c:find_next_signature
fn find_next_signature(f: &mut CFile, sigbuf: &mut [u8; 4]) -> bool {
    let mut m = f.getc();
    while let Some(c) = m {
        if c == 0x50 {
            // found a P
            sigbuf[0] = c;
            let Some(c2) = f.getc() else { break };
            if c2 != 0x4b {
                // not a signature
                f.ungetc(c2);
            } else {
                // found P K
                sigbuf[1] = c2;
                let Some(c3) = f.getc() else { break };
                if c3 == 0x50 {
                    // not a signature but maybe the start of a new one
                    f.ungetc(c3);
                    m = Some(c3);
                    continue;
                } else if c3 >= 16 {
                    m = Some(c3);
                    continue;
                }
                sigbuf[2] = c3;
                let Some(c4) = f.getc() else { break };
                if c4 == 0x50 {
                    f.ungetc(c4);
                    m = Some(c4);
                    continue;
                } else if c4 >= 16 {
                    m = Some(c4);
                    continue;
                }
                sigbuf[3] = c4;
                return true;
            }
        }
        m = f.getc();
    }
    false
}

/// zipfile.c:find_signature: the next `sig`.
// port: zipfile.c:find_signature
fn find_signature(f: &mut CFile, sig: &[u8; 4], sigbuf: &mut [u8; 4]) -> bool {
    while !f.feof() {
        if !find_next_signature(f, sigbuf) {
            return false;
        }
        if sigbuf == sig {
            return true;
        }
    }
    false
}

/// zipfile.c:at_signature: the next four bytes are `sig`.
fn at_signature(f: &mut CFile, sig: &[u8; 4]) -> bool {
    let b = f.fread(4);
    b.len() == 4 && b == sig
}

fn sh(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn lg(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn llg(b: &[u8], at: usize) -> u64 {
    u64::from(lg(b, at)) | (u64::from(lg(b, at + 4)) << 32)
}

/// `buf` padded with zeros to `n` (a short read into the C's buffer).
fn padded(mut buf: Vec<u8>, n: usize) -> Vec<u8> {
    buf.resize(n.max(buf.len()), 0);
    buf
}

/// Why a scan stopped.
pub(crate) enum Fail {
    /// `return ZE_*` (the `errno` for the codes that print one).
    Code(i32, Option<io::Error>),
    /// Another split part is needed (Task 8).
    NotBuilt,
}

fn code(c: i32) -> Fail {
    Fail::Code(c, None)
}

fn read_fail(f: &CFile) -> Fail {
    if f.ferror() {
        Fail::Code(ZE_READ, Some(f.error()))
    } else {
        code(ZE_EOF)
    }
}

/// `strerror(errno)` as the C's messages print it.
fn strerror(errno: i32) -> Vec<u8> {
    crate::compat::host::strerror(&io::Error::from_raw_os_error(errno))
}

/// zipfile.c:readzipfile: read the archive at the path, if there is one.
/// A failure ends the run (`ZIPERR(r, zipfile)`).
// port: zipfile.c:readzipfile
pub(crate) fn read_archive(z: &mut Zr) -> Result<Archive, Exit> {
    let mut ar = Archive {
        total_disks: 1,
        ..Archive::default()
    };
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    let in_path = z.o.in_path.clone().unwrap_or_else(|| zipfile.clone());
    let out_path = z.o.out_path.clone().unwrap_or_else(|| zipfile.clone());
    let opened = if zipfile.is_empty() || zipfile == b"-" {
        None
    } else {
        Some(CFile::open(z, &zipfile))
    };
    match opened {
        None => return Ok(ar),
        Some(Err(e)) => {
            if !z.o.zip_to_stdout && z.o.fix != 2 && in_path != out_path {
                // if -O is used then in_path must exist
                return Err(z.ziperr_os(ZE_OPEN, &zipfile, &e));
            }
            return Ok(ar);
        }
        Some(Ok(_)) => ar.exists = true,
    }
    match scanzipf_regnew(z, &mut ar, &in_path, &out_path) {
        Ok(()) => {}
        Err(Fail::NotBuilt) => return Err(z.not_built()),
        Err(Fail::Code(c, e)) => {
            return Err(super::zipup::zerr(z, c, &zipfile, e.as_ref()));
        }
    }
    // sort by name
    let mut order: Vec<usize> = (0..ar.zfiles.len()).collect();
    let names: Vec<Vec<u8>> = ar
        .zfiles
        .iter()
        .map(|f| cstr(&f.e.iname).to_vec())
        .collect();
    super::scan::qsort(z.flavour, &mut order, &|a, b| names[a].cmp(&names[b]));
    ar.zsort = order;
    Ok(ar)
}

/// zipfile.c:zsearch: the entry whose external name is `n` (util.c's binary
/// `search` over `zsort`).
// port: zipfile.c:zsearch
pub(crate) fn zsearch(ar: &Archive, n: &[u8]) -> Option<usize> {
    let n = cstr(n);
    let a = &ar.zsort;
    if a.is_empty() {
        return None;
    }
    let (mut l, mut u) = (0i64, a.len() as i64 - 1);
    while u >= l {
        let i = l + ((u - l) >> 1);
        let idx = a[i as usize];
        match n.cmp(cstr(&ar.zfiles[idx].zname)) {
            std::cmp::Ordering::Less => u = i - 1,
            std::cmp::Ordering::Greater => l = i + 1,
            std::cmp::Ordering::Equal => return Some(idx),
        }
    }
    None
}

/// zipfile.c:scanzipf_regnew: the end record (and the Zip64 ones), then the
/// central directory into `ar.zfiles`.
// port: zipfile.c:scanzipf_regnew
fn scanzipf_regnew(
    z: &mut Zr,
    ar: &mut Archive,
    in_path: &[u8],
    out_path: &[u8],
) -> Result<(), Fail> {
    let mut sigbuf = [0u8; 4];
    let mut f = match CFile::open(z, in_path) {
        Ok(f) => f,
        Err(e) => {
            z.zipwarn(m::COULD_NOT_OPEN_INPUT_ARCHIVE.as_bytes(), in_path);
            return Err(Fail::Code(ZE_OPEN, Some(e)));
        }
    };
    // look for the End Of Central Directory Record in the last 128 KiB
    let back_ok = match f.end() {
        Some(len) if len >= 0x20000 => f.seek(i128::from(len - 0x20000)),
        Some(_) => {
            f.errno = 22;
            false
        }
        None => false,
    };
    if !back_ok && !f.seek(0) {
        z.zipwarn(m::UNABLE_TO_SEEK.as_bytes(), in_path);
        return Err(Fail::Code(ZE_READ, Some(f.error())));
    }
    if !find_signature(&mut f, b"PK\x05\x06", &mut sigbuf) {
        z.zipwarn(m::MISSING_END_1.as_bytes(), b"");
        z.zipwarn(m::MISSING_END_2.as_bytes(), b"");
        z.zipwarn(m::MISSING_END_3.as_bytes(), b"");
        return Err(code(ZE_FORM));
    }
    let mut eocdr_offset = f.tell();
    while find_signature(&mut f, b"PK\x05\x06", &mut sigbuf) {
        eocdr_offset = f.tell();
    }
    if !f.seek(i128::from(eocdr_offset)) {
        z.zipwarn(m::UNABLE_TO_SEEK.as_bytes(), in_path);
        return Err(Fail::Code(ZE_READ, Some(f.error())));
    }
    let scbuf = padded(f.fread(ENDHEAD), ENDHEAD);
    let eocdr_disk = u64::from(sh(&scbuf, 0));
    let mut total_disks = eocdr_disk + 1;
    let mut current_in_disk = total_disks.wrapping_sub(1);
    let mut in_cd_start_disk = u64::from(sh(&scbuf, 2));
    let mut in_cd_start_offset = u64::from(lg(&scbuf, 12));
    let mut cd_total_entries = u64::from(sh(&scbuf, 6));
    let cd_total_size = u64::from(lg(&scbuf, 8));
    ar.total_disks = total_disks;
    let zcomlen = usize::from(sh(&scbuf, 16));
    if zcomlen > 0 {
        let c = f.fread(zcomlen);
        if c.len() != zcomlen {
            return Err(read_fail(&f));
        }
        ar.zcomment = c;
    }
    if cd_total_entries == 0 {
        // empty archive
        return Ok(());
    }
    if total_disks != 1 {
        // the archive's name must end in .zip for split archives
        if z.o.adjust {
            z.zipwarn(m::ADJUST_SPLITS.as_bytes(), b"");
            return Err(code(ZE_FORM));
        }
        let ok = in_path.len() >= 4 && {
            let e = &in_path[in_path.len() - 4..];
            e[0] == b'.' && e[1..].eq_ignore_ascii_case(b"zip")
        };
        if !ok {
            z.zipwarn(m::SPLIT_NAME_ZIP.as_bytes(), b"");
            return Err(code(ZE_PARMS));
        }
    }
    // if input or output are split archives, they must be different
    if (total_disks != 1 || z.o.split_method != 0) && z.o.show_files == 0 && in_path == out_path {
        z.zipwarn(m::CANNOT_UPDATE_SPLIT.as_bytes(), b"");
        return Err(code(ZE_PARMS));
    }
    let mut adjust_offset: u64 = 0;
    if z.o.adjust {
        if in_cd_start_offset != ZIP_UWORD32_MAX && cd_total_size != ZIP_UWORD32_MAX {
            let cd_start = i128::from(eocdr_offset) - i128::from(cd_total_size) - 24 - 56;
            if !f.seek(cd_start) {
                z.zipwarn(m::READING_ARCHIVE_FSEEK.as_bytes(), &strerror(f.errno));
                return Err(code(ZE_FORM));
            }
            if find_signature(&mut f, b"PK\x01\x02", &mut sigbuf) {
                adjust_offset = f.tell().wrapping_sub(4).wrapping_sub(in_cd_start_offset);
            } else {
                z.zipwarn(m::CENTRAL_NOT_WHERE_EXPECTED.as_bytes(), b"");
                z.zipwarn(m::TRY_FF.as_bytes(), b"");
                return Err(code(ZE_FORM));
            }
        } else {
            if !f.seek(i128::from(eocdr_offset) - 24) {
                z.zipwarn(m::READING_ARCHIVE_FSEEK.as_bytes(), &strerror(f.errno));
                return Err(code(ZE_FORM));
            }
            if at_signature(&mut f, b"PK\x06\x07") {
                let z64eocdl_offset = f.tell().wrapping_sub(4);
                let loc = f.fread(EC64LOC);
                if loc.len() != EC64LOC {
                    z.zipwarn(m::READING_ARCHIVE.as_bytes(), &strerror(f.errno));
                    return Err(Fail::Code(ZE_READ, Some(f.error())));
                }
                if !at_signature(&mut f, b"PK\x05\x06") {
                    z.zipwarn(m::UNABLE_TO_READ_EOCD.as_bytes(), in_path);
                    return Err(Fail::Code(ZE_READ, Some(f.error())));
                }
                let z64eocdr_offset = llg(&loc, 4);
                if lg(&loc, 12) != 1 {
                    z.zipwarn(m::ADJUST_SPLITS_NOT_SUPPORTED.as_bytes(), in_path);
                    z.zipwarn(m::TRY_FF.as_bytes(), b"");
                    return Err(code(ZE_FORM));
                }
                if !f.seek(i128::from(z64eocdr_offset)) {
                    z.zipwarn(m::READING_ARCHIVE_FSEEK.as_bytes(), &strerror(f.errno));
                    return Err(code(ZE_FORM));
                }
                if !at_signature(&mut f, b"PK\x06\x06") {
                    let start = i128::from(z64eocdl_offset) - 24 - 56;
                    if !f.seek(start) {
                        z.zipwarn(m::READING_ARCHIVE_FSEEK.as_bytes(), &strerror(f.errno));
                        return Err(code(ZE_FORM));
                    }
                    if find_next_signature(&mut f, &mut sigbuf) && &sigbuf == b"PK\x06\x06" {
                        adjust_offset = f.tell().wrapping_sub(4).wrapping_sub(z64eocdr_offset);
                    } else {
                        z.zipwarn(m::COULD_NOT_DETERMINE_OFFSET.as_bytes(), b"");
                        z.zipwarn(m::TRY_FF.as_bytes(), b"");
                        return Err(code(ZE_FORM));
                    }
                }
            }
        }
        if z.o.noisy {
            let mut s = Vec::new();
            if adjust_offset != 0 {
                printf(
                    &mut s,
                    m::OFFSETS_OFF_BY,
                    &[(adjust_offset as i64).to_string().as_bytes()],
                );
            } else {
                s.extend_from_slice(m::OFFSETS_DO_NOT_NEED.as_bytes());
            }
            z.zipmessage(&s, b"");
        }
    }

    // a Zip64 end of central directory locator?
    if !f.seek(i128::from(eocdr_offset) - 24) {
        z.zipwarn(m::READING_ARCHIVE_FSEEK.as_bytes(), &strerror(f.errno));
        return Err(code(ZE_FORM));
    }
    if at_signature(&mut f, b"PK\x06\x07") {
        let z64eocdl_offset = f.tell().wrapping_sub(4);
        let loc = f.fread(EC64LOC);
        if loc.len() != EC64LOC {
            z.zipwarn(m::READING_ARCHIVE.as_bytes(), &strerror(f.errno));
            return Err(Fail::Code(ZE_READ, Some(f.error())));
        }
        if !at_signature(&mut f, b"PK\x05\x06") {
            z.zipwarn(m::UNABLE_TO_READ_EOCD.as_bytes(), in_path);
            return Err(Fail::Code(ZE_READ, Some(f.error())));
        }
        let z64eocdr_disk = u64::from(lg(&loc, 0));
        let z64eocdr_offset = llg(&loc, 4).wrapping_add(adjust_offset);
        total_disks = u64::from(lg(&loc, 12));
        ar.total_disks = total_disks;
        if z64eocdr_disk != total_disks.wrapping_sub(1) {
            // the Zip64 end record is on another part
            return Err(Fail::NotBuilt);
        }
        current_in_disk = z64eocdr_disk;
        if !f.seek(i128::from(z64eocdr_offset)) {
            z.zipwarn(m::READING_ARCHIVE_FSEEK.as_bytes(), &strerror(f.errno));
            return Err(code(ZE_FORM));
        }
        if !at_signature(&mut f, b"PK\x06\x06") {
            let start = i128::from(z64eocdl_offset) - 24 - 56;
            if !f.seek(start) {
                z.zipwarn(m::READING_ARCHIVE_FSEEK.as_bytes(), &strerror(f.errno));
                return Err(code(ZE_FORM));
            }
            if find_next_signature(&mut f, &mut sigbuf) && &sigbuf == b"PK\x06\x06" {
                adjust_offset = f.tell().wrapping_sub(4).wrapping_sub(z64eocdr_offset);
                z.zipwarn(m::Z64_COMPENSATING.as_bytes(), b"");
                z.zipwarn(m::TRY_A.as_bytes(), b"");
            } else {
                z.zipwarn(m::Z64_EOCDR_NOT_FOUND.as_bytes(), in_path);
                return Err(code(ZE_FORM));
            }
        }
        let rec = f.fread(EC64REC);
        if rec.len() < EC64REC {
            z.zipwarn(m::Z64_EOCDR_TRUNCATED.as_bytes(), b"");
            return Err(code(ZE_FORM));
        }
        let version_needed = sh(&rec, 10);
        in_cd_start_disk = u64::from(lg(&rec, 16));
        cd_total_entries = llg(&rec, 28);
        in_cd_start_offset = llg(&rec, 44).wrapping_add(adjust_offset);
        if version_needed > 46 {
            let major = version_needed / 10;
            let minor = version_needed - major * 10;
            let mut s = Vec::new();
            printf(
                &mut s,
                m::REQUIRES_VERSION,
                &[major.to_string().as_bytes(), minor.to_string().as_bytes()],
            );
            z.zipwarn(&s, b"");
            z.zipwarn(m::SUPPORTS_UP_TO_46.as_bytes(), b"");
            z.zipwarn(m::UP_TO_45.as_bytes(), b"");
            z.zipwarn(m::TRY_F_READ_ANYWAY.as_bytes(), b"");
            return Err(code(ZE_FORM));
        }
    }

    // now the central directory
    in_cd_start_offset = in_cd_start_offset.wrapping_add(adjust_offset);
    ar.cenbeg = in_cd_start_offset;
    let mut zipbegset = false;
    ar.zipbeg = 0;
    let mut first_cd = true;
    let mut in_file = Some(f);
    if current_in_disk != in_cd_start_disk {
        in_file = None;
    }
    let mut disk = in_cd_start_disk;
    while disk < total_disks {
        if disk != total_disks - 1 {
            // archive.z01, ...: another part
            return Err(Fail::NotBuilt);
        }
        let split_path = in_path;
        let mut f = match in_file.take() {
            Some(f) => f,
            None => match CFile::open(z, split_path) {
                Ok(f) => f,
                // the C asks where the part is (Task 8)
                Err(_) => return Err(Fail::NotBuilt),
            },
        };
        if first_cd {
            if !f.seek(i128::from(in_cd_start_offset)) {
                z.zipwarn(m::UNABLE_TO_SEEK.as_bytes(), split_path);
                return Err(Fail::Code(ZE_READ, Some(f.error())));
            }
            first_cd = false;
        }
        while find_next_signature(&mut f, &mut sigbuf) {
            let current_in_offset = f.tell();
            if &sigbuf == b"PK\x05\x06" || &sigbuf == b"PK\x06\x06" {
                break;
            } else if &sigbuf != b"PK\x01\x02" {
                let mut s = Vec::new();
                printf(
                    &mut s,
                    m::UNEXPECTED_SIGNATURE,
                    &[
                        disk.to_string().as_bytes(),
                        current_in_offset.wrapping_sub(4).to_string().as_bytes(),
                    ],
                );
                z.zipwarn(&s, b"");
                z.zipwarn(m::NOT_IN_CORRECT_FORMAT.as_bytes(), split_path);
                z.zipwarn(m::TRY_F.as_bytes(), b"");
                return Err(code(ZE_FORM));
            }
            let cen = f.fread(CENHEAD);
            if cen.len() != CENHEAD {
                z.zipwarn(m::READING_CENTRAL.as_bytes(), &strerror(f.errno));
                return Err(read_fail(&f));
            }
            let mut e = ZEntry {
                vem: sh(&cen, 0),
                ver: sh(&cen, 2),
                flg: sh(&cen, 4),
                how: sh(&cen, 6),
                tim: lg(&cen, 8),
                crc: lg(&cen, 12),
                siz: u64::from(lg(&cen, 16)),
                len: u64::from(lg(&cen, 20)),
                dsk: u64::from(sh(&cen, 30)),
                att: sh(&cen, 32),
                atx: lg(&cen, 34),
                off: u64::from(lg(&cen, 38)),
                ..ZEntry::default()
            };
            let nam = usize::from(sh(&cen, 24));
            let cext = usize::from(sh(&cen, 26));
            let com = usize::from(sh(&cen, 28));
            let dosflag = (e.vem & 0xff00) == 0;
            if nam == 0 {
                z.zipwarn(
                    m::ZERO_LENGTH_NAME.as_bytes(),
                    (ar.zfiles.len() + 1).to_string().as_bytes(),
                );
                return Err(code(ZE_FORM));
            }
            e.iname = f.fread(nam);
            if e.iname.len() != nam {
                return Err(read_fail(&f));
            }
            if cext > 0 {
                e.cextra = f.fread(cext);
                if e.cextra.len() != cext {
                    return Err(read_fail(&f));
                }
            }
            if com > 0 {
                e.comment = f.fread(com);
                if e.comment.len() != com {
                    return Err(read_fail(&f));
                }
            }
            // ubuntu: UNICODE_SUPPORT's bit-11 and Unicode Path names (Task 11)
            adjust_zip_central_entry(&mut e);
            if z.o.adjust {
                e.off = e.off.wrapping_add(adjust_offset);
            }
            if e.dsk == 0 && (!zipbegset || e.off < ar.zipbeg) {
                ar.zipbeg = e.off;
                zipbegset = true;
            }
            let zname = cstr(&e.iname).to_vec();
            e.name = zname.clone();
            e.oname = super::scan::display(z, &zname);
            if z.o.verbose > 0 && z.o.fix == 0 {
                zipoddities(z, &e);
            }
            ar.zfiles.push(ZFile {
                e,
                zname,
                mark: 0,
                trash: false,
                current: false,
                dosflag,
            });
        }
        if &sigbuf != b"PK\x01\x02" {
            break;
        }
        disk += 1;
    }
    if ar.zfiles.len() as u64 != cd_total_entries {
        let mut s = Vec::new();
        printf(
            &mut s,
            m::EXPECTED_ENTRIES,
            &[
                cd_total_entries.to_string().as_bytes(),
                ar.zfiles.len().to_string().as_bytes(),
            ],
        );
        z.zipwarn(&s, b"");
        return Err(code(ZE_FORM));
    }
    Ok(())
}

/// zipfile.c:adjust_zip_central_entry: the sizes, offset and disk a Zip64
/// extra field holds for the fields that say so. A field too short is read
/// as zeros past its end (deviation 13: the C reads past it).
// port: zipfile.c:adjust_zip_central_entry
fn adjust_zip_central_entry(e: &mut ZEntry) {
    let Some(at) = get_extra_field(0x0001, &e.cextra) else {
        return;
    };
    let size = usize::from(sh(&e.cextra, at + 2));
    let data_end = (at + 4 + size).min(e.cextra.len());
    let block = padded(e.cextra[(at + 4).min(data_end)..data_end].to_vec(), 28);
    let mut p = 0;
    if e.len == ZIP_UWORD32_MAX {
        e.len = llg(&block, p);
        p += 8;
    }
    if e.siz == ZIP_UWORD32_MAX {
        e.siz = llg(&block, p);
        p += 8;
    }
    if e.off == ZIP_UWORD32_MAX {
        e.off = llg(&block, p);
        p += 8;
    }
    if e.dsk == ZIP_UWORD16_MAX {
        e.dsk = u64::from(lg(&block, p));
    }
}

/// zipfile.c:get_extra_field: the offset of the block tagged `tag`.
fn get_extra_field(tag: u16, extra: &[u8]) -> Option<usize> {
    let mut p = 0usize;
    while p + 4 < extra.len() {
        if sh(extra, p) == tag {
            return Some(p);
        }
        p += usize::from(sh(extra, p + 2)) + 4;
    }
    None
}

/// zipfile.c:copy_nondup_extra_fields: the blocks of `old` whose tag `new`
/// has not, then `new` (`-X-` keeps old extra fields). A block that runs
/// past `old` ends the copy (deviation 13: the C copies past it).
// port: zipfile.c:copy_nondup_extra_fields
pub(crate) fn copy_nondup_extra_fields(old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < old.len() {
        if p + 4 > old.len() {
            break;
        }
        let tag = sh(old, p);
        let size = usize::from(sh(old, p + 2));
        let end = p + 4 + size;
        if end > old.len() {
            break;
        }
        if get_extra_field(tag, new).is_none() {
            out.extend_from_slice(&old[p..end]);
        }
        p = end;
    }
    out.extend_from_slice(new);
    out
}

/// zipfile.c:zipoddities: `-v`'s warnings about an entry read.
// port: zipfile.c:zipoddities
fn zipoddities(z: &mut Zr, e: &ZEntry) {
    let oname = e.oname.clone();
    let warn = |z: &mut Zr, fmt: &str, args: &[&[u8]]| {
        let mut s = Vec::new();
        printf(&mut s, fmt, args);
        z.zipwarn(&s, &oname);
    };
    if (e.vem >> 8) >= NUM_HOSTS {
        let v = e.vem & 0xff;
        warn(
            z,
            m::MADE_BY_VERSION,
            &[
                (v / 10).to_string().as_bytes(),
                (v % 10).to_string().as_bytes(),
                (e.vem >> 8).to_string().as_bytes(),
            ],
        );
    }
    if e.ver != 10 && e.ver != 11 && e.ver != 20 {
        let v = e.ver & 0xff;
        warn(
            z,
            m::NEEDS_UNZIP,
            &[
                (v / 10).to_string().as_bytes(),
                (v % 10).to_string().as_bytes(),
                (e.ver >> 8).to_string().as_bytes(),
            ],
        );
    }
    if e.flg & !0xf != 0 && (e.flg & !0xf0) != UTF8_BIT {
        warn(z, m::UNDEFINED_BITS, &[format!("{:04x}", e.flg).as_bytes()]);
    }
    if e.how > flavour::last_known_method(z.flavour) {
        warn(z, m::UNKNOWN_METHOD, &[e.how.to_string().as_bytes()]);
    }
    if e.dsk != 0 {
        warn(z, m::STARTS_ON_DISK, &[e.dsk.to_string().as_bytes()]);
    }
    if e.att != 1 && e.att != 0 && e.att != 2 {
        warn(
            z,
            m::UNKNOWN_INTERNAL,
            &[format!("{:04x}", e.att).as_bytes()],
        );
    }
}

// ---- entries ----

/// The archive being read for the entries copied or updated (`in_file`,
/// opened when first needed and kept).
pub(crate) struct InArchive {
    pub(crate) f: Option<CFile>,
    pub(crate) path: Vec<u8>,
}

impl InArchive {
    /// The stream, opened at the first use (`zfopen(split_path, FOPR)`).
    fn get(&mut self, z: &mut Zr) -> Result<&mut CFile, io::Error> {
        if self.f.is_none() {
            self.f = Some(CFile::open(z, &self.path)?);
        }
        Ok(self.f.as_mut().expect("opened above"))
    }
}

/// What `readlocal` read of a local header.
pub(crate) struct Local {
    pub(crate) lflg: u16,
    pub(crate) extra: Vec<u8>,
}

/// zipfile.c:readlocal: the flags and extra field of `zf`'s local header,
/// and its warnings when they differ from the central header's. `Err` is
/// the `ZE_*` code (the caller warns).
// port: zipfile.c:readlocal
pub(crate) fn readlocal(z: &mut Zr, ia: &mut InArchive, zf: &ZFile) -> Result<Local, i32> {
    let e = &zf.e;
    let f = match ia.get(z) {
        Ok(f) => f,
        // the C asks where the part is (Task 8); its answer at EOF aborts
        Err(_) => return Err(super::cli::ZE_ABORT),
    };
    if !f.seek(i128::from(e.off)) {
        let s = strerror(f.errno);
        ia.f = None;
        z.zipwarn(m::READING_ARCHIVE_FSEEK.as_bytes(), &s);
        return Err(ZE_READ);
    }
    if !at_signature(f, b"PK\x03\x04") {
        ia.f = None;
        z.zipwarn(m::DID_NOT_FIND_ENTRY.as_bytes(), cstr(&e.iname));
        return Err(ZE_FORM);
    }
    let buf = f.fread(LOCHEAD as usize);
    if buf.len() != LOCHEAD as usize {
        let (err, s) = (f.ferror(), strerror(f.errno));
        ia.f = None;
        z.zipwarn(m::READING_LOCAL_ENTRY.as_bytes(), &s);
        return Err(if err { ZE_READ } else { ZE_EOF });
    }
    let ver = sh(&buf, 0);
    let lflg = sh(&buf, 2);
    let crc = lg(&buf, 10);
    let nam = usize::from(sh(&buf, 22));
    let ext = usize::from(sh(&buf, 24));
    let name = f.fread(nam);
    if name.len() != nam {
        return Err(if f.ferror() { ZE_READ } else { ZE_EOF });
    }
    let extra = f.fread(ext);
    if extra.len() != ext {
        return Err(if f.ferror() { ZE_READ } else { ZE_EOF });
    }
    let iname = cstr(&e.iname).to_vec();
    if ver != e.ver {
        let mut s = Vec::new();
        printf(
            &mut s,
            m::LOCAL_VERSION_NEEDED,
            &[ver.to_string().as_bytes(), e.ver.to_string().as_bytes()],
        );
        z.zipwarn(&s, &iname);
    }
    if lflg != e.flg {
        z.zipwarn(m::LOCAL_FLAG_MISMATCH.as_bytes(), &iname);
    }
    if crc != e.crc {
        z.zipwarn(m::LOCAL_CRC_MISMATCH.as_bytes(), &iname);
    }
    Ok(Local { lflg, extra })
}

/// The dots of `-U`'s copies (bfcopy, `copy_only` without `-dg`).
fn copy_dot(z: &mut Zr, k: usize) {
    if z.o.dot_size > 0 {
        if z.o.noisy && z.o.dot_count == -1 {
            z.mesg_write(b" ");
            z.o.dot_count += 1;
        }
        z.o.dot_count += k as i64;
        if z.o.dot_size <= z.o.dot_count {
            z.o.dot_count = 0;
        }
    }
    if (z.o.verbose > 0 || z.o.noisy) && z.o.dot_size != 0 && z.o.dot_count == 0 {
        z.mesg_write(b".");
        z.set_line(true);
    }
}

/// How a copy failed: a `ZE_*` code (with the read's error for
/// `ZE_READ`), or a write the archive refused (`bfwrite`'s `ZE_WRITE`).
pub(crate) enum CopyFail {
    Code(i32, Option<io::Error>),
    Write(io::Error),
    Exit(Exit),
}

/// fileio.c:bfcopy: `n` bytes from the archive to the new one (fewer when
/// it ends first, as there).
// port: fileio.c:bfcopy
pub(crate) fn bfcopy(z: &mut Zr, f: &mut CFile, out: &mut ZOut, n: u64) -> Result<(), CopyFail> {
    let copy_dots = z.o.copy_only && !z.o.display_globaldots;
    if copy_dots {
        z.o.dot_count = -1;
    }
    let mut done: u64 = 0;
    while done < n {
        let brd = (n - done).min(CBSZ as u64) as usize;
        let b = f.fread(brd);
        if b.is_empty() {
            if f.ferror() {
                return Err(CopyFail::Code(ZE_READ, Some(f.error())));
            }
            break;
        }
        let r = out.bfwrite(&b, Bf::Data);
        super::zipup::drain_dots(z, out);
        r.map_err(CopyFail::Write)?;
        done += b.len() as u64;
        if copy_dots {
            copy_dot(z, b.len());
        }
        if f.feof() {
            // one disk: past its end the copy is done
            break;
        }
    }
    Ok(())
}

/// zipfile.c:zipcopy: copy `zf` from the archive into the new one at its
/// current end: a local header made again (from the old one's fields, the
/// sizes and CRC of the central header), the data, a descriptor only for
/// an encrypted entry that had one. `zf`'s disk and offset become the new
/// ones; `tempzn` grows by the entry's size.
// port: zipfile.c:zipcopy
pub(crate) fn zipcopy(
    z: &mut Zr,
    ia: &mut InArchive,
    out: &mut ZOut,
    tempzn: &mut u64,
    zf: &mut ZFile,
) -> Result<(), CopyFail> {
    let noisy = z.o.noisy;
    let f = match ia.get(z) {
        Ok(f) => f,
        Err(e) => {
            // ruling: the C asks where the part is when noisy (Task 8's
            // prompt); stuffr answers as quiet zip does
            let _ = noisy;
            let p = ia.path.clone();
            return Err(CopyFail::Exit(z.ziperr_os(ZE_OPEN, &p, &e)));
        }
    };
    if !f.seek(i128::from(zf.e.off)) {
        let (s, err) = (strerror(f.errno), f.error());
        ia.f = None;
        z.zipwarn(m::READING_ARCHIVE_FSEEK.as_bytes(), &s);
        return Err(CopyFail::Code(ZE_READ, Some(err)));
    }
    if !at_signature(f, b"PK\x03\x04") {
        ia.f = None;
        z.zipwarn(m::DID_NOT_FIND_ENTRY.as_bytes(), cstr(&zf.e.iname));
        return Err(CopyFail::Code(ZE_FORM, None));
    }
    let buf = f.fread(LOCHEAD as usize);
    if buf.len() != LOCHEAD as usize {
        let (err, s) = (f.ferror(), strerror(f.errno));
        ia.f = None;
        z.zipwarn(m::READING_LOCAL_ENTRY.as_bytes(), &s);
        return Err(CopyFail::Code(if err { ZE_READ } else { ZE_EOF }, None));
    }
    let mut lz = ZEntry {
        ver: sh(&buf, 0),
        lflg: sh(&buf, 2),
        how: sh(&buf, 4),
        tim: lg(&buf, 6),
        crc: lg(&buf, 10),
        ..ZEntry::default()
    };
    let nam = usize::from(sh(&buf, 22));
    let ext = usize::from(sh(&buf, 24));
    lz.iname = f.fread(nam);
    if lz.iname.len() != nam {
        return Err(read_or_eof(f));
    }
    lz.extra = f.fread(ext);
    if lz.extra.len() != ext {
        return Err(read_or_eof(f));
    }
    lz.name = cstr(&lz.iname).to_vec();
    // zip64_entry = adjust_zip_local_entry(localz)
    out.zip64_entry = get_extra_field(0x0001, &lz.extra).is_some();
    lz.vem = zf.e.vem;
    // ubuntu: UNICODE_SUPPORT's local names (Task 11)
    let ciname = cstr(&zf.e.iname).to_vec();
    if lz.ver != zf.e.ver {
        z.zipwarn(m::LOCAL_VERSION_MISMATCH.as_bytes(), &ciname);
    }
    if lz.lflg != zf.e.flg {
        z.zipwarn(m::LOCAL_FLAG_MISMATCH.as_bytes(), &ciname);
    }
    if zf.e.flg & 8 == 0 && lz.crc != zf.e.crc {
        z.zipwarn(m::LOCAL_CRC_MISMATCH.as_bytes(), &ciname);
    }
    if cstr(&lz.iname) != ciname.as_slice() {
        z.zipwarn(m::LOCAL_NAME_MISMATCH.as_bytes(), &ciname);
    }
    // the sizes from the central directory
    lz.len = zf.e.len;
    lz.siz = zf.e.siz;
    // the disk and offset in the new archive
    zf.e.dsk = 0;
    zf.e.off = out.w.offset();
    if zf.e.flg & 1 == 0 {
        // not encrypted: no data descriptor
        zf.e.flg &= !8;
        lz.lflg &= !8;
    }
    zf.e.lflg = lz.lflg;
    let e = if zf.e.lflg & 8 != 0 {
        if out.zip64_entry { 24 } else { 16 }
    } else {
        0
    };
    *tempzn += 4 + LOCHEAD + nam as u64 + ext as u64 + e + zf.e.siz;
    lz.crc = zf.e.crc;
    // the C's localz->oname is NULL: zipwarn prints `(null)`
    lz.oname = b"(null)".to_vec();
    let r = super::zipfile::putlocal(&mut lz, out);
    super::zipup::drain_dots(z, out);
    match r {
        Ok(()) => {}
        Err(super::zipfile::PutError::Write(err)) => return Err(CopyFail::Write(err)),
        Err(pe) => {
            return Err(CopyFail::Exit(super::zipup::put_failed(z, &lz, pe)));
        }
    }
    let f = ia.f.as_mut().expect("opened above");
    bfcopy(z, f, out, lz.siz)?;
    if zf.e.flg & 8 != 0 {
        let r = super::zipfile::putextended(&lz, out);
        super::zipup::drain_dots(z, out);
        r.map_err(CopyFail::Write)?;
    }
    Ok(())
}

fn read_or_eof(f: &CFile) -> CopyFail {
    CopyFail::Code(if f.ferror() { ZE_READ } else { ZE_EOF }, None)
}

/// zipfile.c:ef_scan_ut_time for the modification time: the flags of the
/// last `UT` block (or an old `UX` block when there is none) and its
/// modification time when it has one.
// port: zipfile.c:ef_scan_ut_time
fn ef_scan_ut_time(ef: &[u8], is_cent: bool) -> (u8, Option<i64>) {
    let mut flags: u8 = 0;
    let mut mtime: Option<i64> = None;
    let mut have_new_type_eb = false;
    let mut p = 0usize;
    while ef.len() - p >= 4 {
        let id = sh(ef, p);
        let len = usize::from(sh(ef, p + 2));
        if len > ef.len() - p - 4 {
            break;
        }
        let data = &ef[p + 4..p + 4 + len];
        match id {
            0x5455 => {
                flags = 0;
                have_new_type_eb = true;
                if len >= 1 {
                    flags |= data[0];
                    if flags & 1 != 0 {
                        if 4 < len {
                            mtime = Some(i64::from(lg(data, 1)));
                        } else {
                            flags &= !1;
                        }
                    }
                    if !is_cent {
                        // the access and creation times are not needed
                        let mut idx = 1 + if flags & 1 != 0 { 4 } else { 0 };
                        if flags & 2 != 0 {
                            if idx + 4 <= len {
                                idx += 4;
                            } else {
                                flags &= !2;
                            }
                        }
                        if flags & 4 != 0 && idx + 4 > len {
                            flags &= !4;
                        }
                    }
                }
            }
            0x7855 if !have_new_type_eb => {
                flags = 0;
                have_new_type_eb = true;
            }
            0x5855 if len >= 8 && !have_new_type_eb => {
                mtime = Some(i64::from(lg(data, 4)));
                flags |= 1 | 2;
            }
            _ => {}
        }
        p += len + 4;
    }
    (flags, mtime)
}

/// zipfile.c:get_ef_ut_ztime: the entry's modification time from its local
/// extra field, else its central one; `None` when neither has one.
// port: zipfile.c:get_ef_ut_ztime
pub(crate) fn ut_mtime(e: &ZEntry) -> Option<i64> {
    let (mut flags, mut t) = if e.extra.is_empty() {
        (0, None)
    } else {
        ef_scan_ut_time(&e.extra, false)
    };
    if flags == 0 && !e.cextra.is_empty() {
        (flags, t) = ef_scan_ut_time(&e.cextra, true);
    }
    if flags & 1 != 0 { t } else { None }
}

/// unix.c's filetime for an archive entry's name: its MS-DOS time (0 when
/// it is not on disk), size (-1 for anything but a regular file) and
/// modification time.
pub(crate) fn disk_time(z: &Zr, name: &[u8]) -> (u64, i64, i64) {
    let stripped = name.strip_suffix(b"/").unwrap_or(name);
    if stripped.is_empty() {
        return (0, -1, 0);
    }
    let p = z.host.path(stripped);
    let md = if z.o.linkput {
        std::fs::symlink_metadata(&p)
    } else {
        std::fs::metadata(&p)
    };
    let Ok(md) = md else {
        return (0, -1, 0);
    };
    let meta = super::unix::meta_of(&md);
    let usize = if meta.file_type() == super::unix::S_IFREG {
        meta.size as i64
    } else {
        -1
    };
    (super::unix::unix2dostime(z, meta.mtime), usize, meta.mtime)
}

#[cfg(test)]
mod tests;
