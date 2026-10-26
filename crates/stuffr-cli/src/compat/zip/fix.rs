//! `zip -FF` (zip.c:main's `fix == 2` block, zipfile.c:scanzipf_fixnew,
//! zipcopy and fileio.c:bfcopy as `-FF` runs them): the archive is read
//! from its first byte as a stream of signatures; each local header found
//! is copied to the new archive at once (its data up to the sizes the
//! local header gives, or up to the data descriptor whose sizes agree),
//! and a central header found later fills in what only the central
//! directory has (the comment, the attributes, the made-by version) and the
//! local header is written again. The new archive's central directory is
//! the entries copied, in the order met.
//!
//! **Bounded (ruling Z22), with the C's output:** the archive is read
//! going forward, once, but for two of the C's steps back, both kept as
//! the C makes them and both made cheap: the descriptor search goes back
//! over a signature whose sizes do not agree (4 bytes) or to the OUTPUT's
//! count (`bytes_this_split + kk`: where the input and the output counts
//! differ the C reads some bytes again, and each such pass writes at least
//! one byte). stuffr reads only the bytes the C looks at (4, then a
//! descriptor's 16 or 24, or a search reading on in doubling pieces up to
//! the C's 16 KiB) and its stream keeps its buffer over a seek within it,
//! so a run of fake descriptor signatures costs a few bytes each, not a
//! 16 KiB read. The sort of the entries at each central header met (the
//! C's `qsort` of all of them) is skipped when nothing was added and is an
//! insertion when a few entries with new names were, while every name met
//! is distinct; once two entries share a name the flavour's `qsort` runs
//! over all entries at each central header met after new entries, as in
//! the C (an unstable `qsort` orders equal names its own way): quadratic
//! then in the number of local headers alternating with central ones. In a sandbox every byte `-FF` reads is
//! charged to the output budget. The parts of a split archive are opened
//! through `Host::track`.
//!
//! Undefined behaviour in the C, not reproduced (deviation 19):
//! - zipcopy copies the local extra field into the central one with
//!   `strcpy`, which stops at the first NUL (the second byte of a block's
//!   size, nearly always) and leaves the rest of the `malloc`ed field as it
//!   was (zeros on Apple; heap garbage that changes run to run on Ubuntu).
//!   stuffr copies up to and with the first NUL and fills the rest with
//!   zeros: Apple's bytes.
//! - an entry's `lflg` is never set before zipcopy reads it for the size of
//!   a descriptor it adds to `tempzn`: only the central directory's offset
//!   in a Zip64 decision could see it; stuffr reads 0.
//! - a descriptor signature split across two 16 KiB reads makes bfcopy
//!   write `kk - 3` (wrapped) bytes from its buffer; stuffr does not take
//!   it for a signature (the search goes on).
//! - a Zip64 extra field shorter than the sizes it should hold is read as
//!   zeros past its end (as deviation 13).

use super::cli::ZE_ABORT;
use super::messages::{self as m, printf};
use super::readzip::{
    self, Archive, CENHEAD, CFile, CopyFail, ENDHEAD, InArchive, ZFile, cstr, find_next_signature,
    find_signature, get_extra_field, lg, llg, sh,
};
use super::sink::{FileSink, Temp, mkstemp, replace};
use super::zipfile::{self, Bf, LOCHEAD, ZEntry, ZOut};
use super::zipup::{drain_dots, write_failed, write_num_string, zerr};
use super::{Exit, Zr};
use crate::compat::host::Host;

/// ziperr.h codes this file raises or returns.
const ZE_EOF: i32 = 2;
const ZE_FORM: i32 = 3;
const ZE_BIG: i32 = 6;
const ZE_TEMP: i32 = 10;
const ZE_READ: i32 = 11;
const ZE_WRITE: i32 = 14;
const ZIP_UWORD32_MAX: u64 = 0xffff_ffff;

/// `errno` as the C's messages print it: the last failure of any call, kept
/// across files (a successful call leaves it).
#[derive(Default)]
struct Errno(i32);

impl Errno {
    /// The file's own last failure, if newer.
    fn from(&mut self, f: &CFile) {
        if f.errno != 0 {
            self.0 = f.errno;
        }
    }
    fn text(&self) -> Vec<u8> {
        readzip::strerror(self.0)
    }
}

/// What the descriptor search found (`des_good`, `des_crc`, ...).
#[derive(Default)]
struct Des {
    good: bool,
    crc: u32,
    csize: u64,
    usize: u64,
}

/// zip.c:main, `fix == 2`: the temporary archive, the scan, the central
/// directory, the replacement of `--out`'s file, `finish()`.
// port: zip.c:main (fix == 2)
pub(crate) fn run(z: &mut Zr) -> Exit {
    if z.o.show_what_doing {
        z.mesg_write(m::SD_OPEN_FF.as_bytes());
        z.mesg_write(m::SD_CREATING_FF.as_bytes());
    }
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    let out_path = z.o.out_path.clone().unwrap_or_else(|| zipfile.clone());
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
    let (tempzip, r) = mkstemp(&z.host, &dir);
    let (file, _armed) = match r {
        Ok(x) => x,
        Err(e) => return z.ziperr_os(ZE_TEMP, &tempzip, &e),
    };
    let mut temp = Temp {
        path: Some(z.host.path(&tempzip)),
    };
    let budget = match &z.host {
        Host::Sandbox(s) => Some(s.budget.clone()),
        Host::Real => None,
    };
    let mut out = ZOut::new(Box::new(FileSink::new(file, budget)), z.o.force_zip64, None);
    let mut tempzn: u64 = 0;
    // readzipfile: the archive is opened (and kept), then scanned
    if !zipfile.is_empty() && zipfile != b"-" {
        let _ = CFile::open(z, &zipfile);
    }
    let mut sc = Scan {
        ar: Archive::default(),
        zcomment: None,
        zcomlen: 0,
        files_total: 0,
        bytes_total: 0,
    };
    // readzipfile ignores scanzipf_fixnew's answer
    if let Err(x) = scanzipf_fixnew(z, &mut sc, &mut out, &mut tempzn) {
        return x;
    }
    // Write central directory and end header to temporary zip
    if z.o.show_what_doing {
        z.mesg_write(m::SD_WRITING_CENTRAL_FF.as_bytes());
    }
    let c = tempzn;
    let mut k: u64 = 0;
    for zf in sc.ar.zfiles.iter_mut() {
        let r = zipfile::putcentral(&mut zf.e, &mut out);
        drain_dots(z, &mut out);
        match r {
            Ok(()) => {}
            Err(zipfile::PutError::Big { why, .. }) => {
                z.zipwarn(why.as_bytes(), b"");
                return z.ziperr(ZE_BIG, &tempzip);
            }
            Err(zipfile::PutError::Write(err)) => return write_failed(z, &err),
        }
        let e = &zf.e;
        tempzn = tempzn.wrapping_add(
            4 + zipfile::CENHEAD
                + e.iname.len() as u64
                + e.cextra.len() as u64
                + e.comment.len() as u64,
        );
        k += 1;
    }
    if sc.ar.zfiles.is_empty() {
        z.zipwarn(m::ZIP_FILE_EMPTY.as_bytes(), b"");
    }
    let t = tempzn.wrapping_sub(c);
    let comment = sc.zcomment.unwrap_or_default();
    let r = zipfile::putend_with(&mut out, k, t, c, sc.zcomlen, &comment);
    drain_dots(z, &mut out);
    if let Err(err) = r {
        return write_failed(z, &err);
    }
    // fclose(y)
    if let Err(err) = out.w.flush() {
        return z.ziperr_os(ZE_TEMP, &tempzip, &err);
    }
    drop(out);
    // Replace old zip file with new zip file, leaving only the new one
    if zipfile != b"-" {
        let tmp = temp.path.take().unwrap_or_default();
        if let Err((code, err)) = replace(&z.host.path(&out_path), &tmp) {
            z.zipwarn(m::NEW_ZIP_LEFT_AS.as_bytes(), &tempzip);
            return zerr(z, code, m::WAS_REPLACING.as_bytes(), Some(&err));
        }
    }
    drop(_armed);
    // finish the log file
    if z.log.is_some() {
        let mut l = Vec::new();
        printf(
            &mut l,
            m::LOG_TOTAL,
            &[sc.files_total.to_string().as_bytes()],
        );
        l.extend_from_slice(write_num_string(sc.bytes_total).trim_start().as_bytes());
        l.extend_from_slice(m::LOG_BYTES.as_bytes());
        let now = super::asctime_now(z);
        printf(&mut l, m::LOG_DONE, &[now.as_bytes()]);
        z.log_write(&l);
    }
    super::write::finish(z, super::cli::ZE_OK, &mut sc.ar.zfiles)
}

/// What `scanzipf_fixnew` leaves in zip's globals.
struct Scan {
    /// `zfiles` (and `zsort`, made when the central directory is met).
    ar: Archive,
    /// `zcomment` (`None`: none, or one that could not be read).
    zcomment: Option<Vec<u8>>,
    /// `zcomlen`: the end record's comment length, kept when the comment
    /// could not be read.
    zcomlen: usize,
    files_total: u64,
    bytes_total: u64,
}

/// `(%2lu %6s)`: a disk (1-based) and an offset as the messages show them.
fn at(disk: u64, offset: u64) -> [Vec<u8>; 2] {
    [
        format!("{disk:2}").into_bytes(),
        format!("{offset:6}").into_bytes(),
    ]
}

/// `zipmessage_nl(sprintf(fmt, args), nl)`.
fn message(z: &mut Zr, fmt: &str, args: &[&[u8]], nl: bool) {
    let mut s = Vec::new();
    printf(&mut s, fmt, args);
    z.zipmessage_nl(&s, nl);
}

/// zipfile.c:scanzipf_fixnew: the archive from its first part on, as a
/// stream of signatures. `Err` is a `ZIPERR` inside (the run is over);
/// every other end of the scan (`ZE_ABORT` after `q`, `ZE_EOF` after `e`,
/// a failed seek in the output) is ignored, as readzipfile ignores it.
// port: zipfile.c:scanzipf_fixnew
fn scanzipf_fixnew(
    z: &mut Zr,
    sc: &mut Scan,
    out: &mut ZOut,
    tempzn: &mut u64,
) -> Result<i32, Exit> {
    let mut errno = Errno::default();
    let mut sigbuf = [0u8; 4];
    let mut in_central_directory = false;
    // how far `zsort` is made (ruling Z22)
    let mut sorted = SortState::default();
    let mut r: i32 = 0;
    z.total_disks = 1_000_000;
    let in_path = z.o.in_path.clone().unwrap_or_default();
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    // a name ending .z01, .z02, ...: not the last part (the C looks at
    // `zipfile` with in_path's length, and at the byte after the four,
    // which is the end of the name unless the name is those four bytes)
    let plen = in_path.len();
    if plen >= 4 && zipfile.len() >= plen {
        let ext = &zipfile[plen - 4..];
        let after = zipfile.get(plen).copied().unwrap_or(0);
        if ext[0] == b'.'
            && ext[1].eq_ignore_ascii_case(&b'z')
            && ext[2].is_ascii_digit()
            && ext[3].is_ascii_digit()
            && (plen == 4 || after.is_ascii_digit())
        {
            z.zipwarn(m::FF_NEED_ZIP.as_bytes(), b"");
            return Ok(ZE_FORM);
        }
    }
    let mut ia = InArchive { f: None };
    match CFile::open(z, &in_path) {
        Err(e) => {
            errno.0 = e.raw_os_error().unwrap_or(2);
            z.zipwarn(m::FF_COULD_NOT_OPEN.as_bytes(), &in_path);
        }
        Ok(mut f) => {
            // back up 256 KiB from the end for the end record
            let back = match f.end() {
                Some(len) if len >= 0x40000 => f.seek(i128::from(len - 0x40000)),
                Some(_) => {
                    f.errno = 22;
                    false
                }
                None => false,
            };
            if !back && !f.seek(0) {
                errno.from(&f);
                z.zipwarn(m::UNABLE_TO_SEEK.as_bytes(), &in_path);
                return Ok(ZE_READ);
            }
            if !find_signature(&mut f, b"PK\x05\x06", &mut sigbuf) {
                z.zipwarn(m::FF_MISSING_EOCDR.as_bytes(), b"");
            } else {
                let mut eocdr_offset = f.tell();
                while find_signature(&mut f, b"PK\x05\x06", &mut sigbuf) {
                    eocdr_offset = f.tell();
                }
                if !f.seek(i128::from(eocdr_offset)) {
                    errno.from(&f);
                    z.zipwarn(m::UNABLE_TO_SEEK.as_bytes(), &in_path);
                    return Ok(ZE_READ);
                }
                let scbuf = f.fread(ENDHEAD);
                if scbuf.len() < ENDHEAD {
                    let mut s = Vec::new();
                    printf(
                        &mut s,
                        m::FF_EOCDR_SHORT,
                        &[scbuf.len().to_string().as_bytes()],
                    );
                    z.zipwarn(&s, b"");
                } else {
                    let eocdr_disk = u64::from(sh(&scbuf, 0));
                    z.total_disks = eocdr_disk + 1;
                    z.current_in_disk = z.total_disks - 1;
                    let in_cd_start_disk = u64::from(sh(&scbuf, 2));
                    if z.total_disks < 0x10000 && in_cd_start_disk > z.total_disks {
                        z.zipwarn(m::FF_EOCDR_BAD_DISKS.as_bytes(), b"");
                        z.total_disks = 0;
                    } else {
                        let zcomlen = usize::from(sh(&scbuf, 16));
                        sc.zcomlen = zcomlen;
                        if zcomlen > 0 {
                            let c = f.fread(zcomlen);
                            if c.len() != zcomlen {
                                errno.from(&f);
                                z.zipwarn(m::FF_COMMENT_TRUNCATED.as_bytes(), b"");
                            } else {
                                sc.zcomment = Some(c);
                            }
                        }
                    }
                    let mut s = Vec::new();
                    if z.total_disks != 1 {
                        printf(
                            &mut s,
                            m::FF_EXPECT_SPLITS,
                            &[z.total_disks.to_string().as_bytes()],
                        );
                    } else {
                        s.extend_from_slice(m::FF_EXPECT_SINGLE.as_bytes());
                    }
                    z.zipmessage(&s, b"");
                    if sc.zcomment.is_some() {
                        z.zipmessage(m::FF_FOUND_COMMENT.as_bytes(), b"");
                    }
                }
            }
            // a bad end record: guess whether this is a single-disk archive
            // by whether it starts with a local header
            if z.total_disks == 0 {
                if !f.seek(0) {
                    errno.from(&f);
                    z.zipwarn(m::UNABLE_TO_SEEK.as_bytes(), &in_path);
                    return Ok(ZE_READ);
                }
                let mut issig = find_next_signature(&mut f, &mut sigbuf);
                if issig {
                    let off = f.tell();
                    if off == 4 && &sigbuf == b"PK\x03\x03" {
                        // could be a multi-disk aborted signature at the top
                        issig = find_next_signature(&mut f, &mut sigbuf);
                    } else if off <= 4 && &sigbuf == b"PK\x03\x03" {
                        // multi-disk spanning signature
                        z.total_disks = 99999;
                    }
                }
                if issig && z.total_disks == 0 && f.tell() == 8 && &sigbuf == b"PK\x03\x04" {
                    // a local header at the top
                    ask_single_disk(z);
                }
            }
            errno.from(&f);
            if !z.o.noisy {
                // quiet: assume a single-disk archive
                z.total_disks = 1;
            }
            if z.total_disks == 1_000_000 {
                // still not known: ask
                ask_single_disk(z);
            }
            if z.total_disks == 1_000_000 {
                // assume the most
                z.total_disks = 100_000;
            }
            ia.f = Some(f);
        }
    }
    // unless quiet, start again with the first disk (the end record said
    // how many there are, or the answer did)
    if z.o.noisy
        && let Some(f) = ia.f.take()
    {
        errno.from(&f);
    }
    z.zipmessage(m::FF_SCANNING.as_bytes(), b"");
    z.current_in_disk = 0;
    while z.current_in_disk < z.total_disks {
        let disk = z.current_in_disk;
        let ip = z.o.in_path.clone().unwrap_or_default();
        let mut split_path = super::split::get_in_split_path(z, &ip, disk)?;
        if ia.f.is_none() {
            let mut skip_disk = false;
            loop {
                match CFile::open(z, &split_path) {
                    Ok(f) => {
                        ia.f = Some(f);
                        break;
                    }
                    Err(e) => errno.0 = e.raw_os_error().unwrap_or(2),
                }
                // ask for the directory with the part (updates in_path)
                let result = super::split::ask_for_split_read_path(z, disk)?;
                if result == ZE_ABORT {
                    z.zipwarn(m::COULD_NOT_FIND_SPLIT.as_bytes(), &split_path);
                    return Ok(ZE_ABORT);
                } else if result == super::split::ANSWER_EOF {
                    z.zipmessage_nl(b"", true);
                    z.zipwarn(m::USER_ENDED_READING.as_bytes(), b"");
                    return Ok(ZE_EOF);
                } else if result == super::split::ANSWER_SKIP {
                    // the user asked to skip this disk
                    z.zipmessage_nl(b"", true);
                    let mut s = Vec::new();
                    printf(&mut s, m::SKIPPING_DISK, &[disk.to_string().as_bytes()]);
                    z.zipwarn(&s, b"");
                    skip_disk = true;
                    break;
                }
                let ip = z.o.in_path.clone().unwrap_or_default();
                split_path = super::split::get_in_split_path(z, &ip, disk)?;
            }
            if skip_disk {
                // (the C sets skipped_disk here and never reads it)
                z.current_in_disk += 1;
                continue;
            }
        }
        // the main loop: the next signature, and what it starts
        while let Some(f) = ia.f.as_mut() {
            if !find_next_signature(f, &mut sigbuf) {
                break;
            }
            let current_in_offset = f.tell();
            let cur = z.current_in_disk;
            let [d1, o1] = at(cur + 1, current_in_offset.wrapping_sub(4));
            if &sigbuf == b"PK\x05\x06" {
                message(z, m::FF_EOCDR_FOUND, &[&d1, &o1], true);
            } else if &sigbuf == b"PK\x06\x06" {
                message(z, m::FF_Z64_EOCDR_FOUND, &[&d1, &o1], true);
            } else if &sigbuf == b"PK\x06\x07" {
                message(z, m::FF_Z64_EOCDL_FOUND, &[&d1, &o1], true);
            } else if &sigbuf == b"PK\x03\x04" {
                // a local header
                if z.o.verbose > 0 {
                    message(z, m::FF_LOCAL, &[&d1, &o1], false);
                }
                let mut zf = ZFile::default();
                r = zipcopy_ff(z, &mut ia, out, tempzn, &mut zf, &mut errno)?;
                if in_central_directory {
                    message(z, m::FF_ENTRY_AFTER_CENTRAL, &[&d1, &o1], true);
                    in_central_directory = false;
                }
                if r == ZE_EOF {
                    // the user said no more splits
                    break;
                } else if r == 0 {
                    sc.files_total += 1;
                    sc.bytes_total = sc.bytes_total.wrapping_add(zf.e.siz);
                    sc.ar.zfiles.push(zf);
                }
            } else if &sigbuf == b"PK\x01\x02" {
                // a central header
                if !in_central_directory {
                    z.zipmessage(m::FF_CENTRAL_FOUND.as_bytes(), b"");
                    // sort what there is by name
                    resort(z, &mut sc.ar, &mut sorted);
                }
                if z.o.verbose > 0 {
                    message(z, m::FF_CEN, &[&d1, &o1], false);
                }
                in_central_directory = true;
                let f = ia.f.as_mut().expect("open");
                let scbuf = f.fread(CENHEAD);
                if scbuf.len() != CENHEAD {
                    errno.from(f);
                    z.zipwarn(m::READING_CENTRAL.as_bytes(), &errno.text());
                    z.zipwarn(m::F_ERROR_READING_CENTRAL.as_bytes(), b"");
                    z.zipwarn(m::SKIPPING_ENTRY.as_bytes(), b"");
                    continue;
                }
                let nam = usize::from(sh(&scbuf, 24));
                let cext = usize::from(sh(&scbuf, 26));
                let com = usize::from(sh(&scbuf, 28));
                if nam == 0 {
                    z.zipwarn(
                        m::ZERO_LENGTH_NAME.as_bytes(),
                        (sc.ar.zfiles.len() + 1).to_string().as_bytes(),
                    );
                    z.zipwarn(m::SKIPPING_ENTRY.as_bytes(), b"");
                    continue;
                }
                let iname = f.fread(nam);
                let mut ok = iname.len() == nam;
                let mut cextra = Vec::new();
                let mut comment = Vec::new();
                if ok && cext > 0 {
                    cextra = f.fread(cext);
                    ok = cextra.len() == cext;
                }
                if ok && com > 0 {
                    comment = f.fread(com);
                    ok = comment.len() == com;
                }
                if !ok {
                    errno.from(f);
                    z.zipwarn(m::ERROR_READING_ENTRY.as_bytes(), &errno.text());
                    z.zipwarn(m::SKIPPING_ENTRY.as_bytes(), b"");
                    continue;
                }
                let vem = sh(&scbuf, 0);
                let tim = lg(&scbuf, 8);
                let crc = lg(&scbuf, 12);
                let att = sh(&scbuf, 32);
                let atx = lg(&scbuf, 34);
                let found = readzip::zsearch(&sc.ar, &iname);
                match found {
                    Some(i) if sc.ar.zfiles[i].e.tim == tim => {
                        // name and time match: this central header goes
                        // with that entry
                        if z.o.verbose > 0 {
                            message(z, m::FF_CEN_UPDATING, &[cstr(&iname)], false);
                        }
                        let zcrc = sc.ar.zfiles[i].e.crc;
                        if zcrc != crc {
                            let mut s = Vec::new();
                            printf(
                                &mut s,
                                m::FF_CRC_MISMATCH,
                                &[zcrc.to_string().as_bytes(), crc.to_string().as_bytes()],
                            );
                            z.zipwarn(&s, b"");
                        }
                        let zf = &mut sc.ar.zfiles[i];
                        zf.e.vem = vem;
                        zf.e.cextra = cextra;
                        zf.e.comment = comment;
                        zf.e.att = att;
                        zf.e.atx = atx;
                        zf.dosflag = (vem & 0xff00) == 0;
                        if z.o.verbose > 0 {
                            let e = zf.e.clone();
                            readzip::zipoddities(z, &e);
                        }
                        let zf = &mut sc.ar.zfiles[i];
                        // the local header again, where it is in the output
                        let current_offset = match out.w.tell_raw() {
                            Ok(o) => o,
                            Err(e) => {
                                z.zipwarn(m::FF_WRITING_SEEK.as_bytes(), &host_err(&e));
                                return Ok(ZE_WRITE);
                            }
                        };
                        if let Err(e) = out.w.seek_to(zf.e.off) {
                            z.zipwarn(m::FF_WRITING_SEEK.as_bytes(), &host_err(&e));
                            return Ok(ZE_WRITE);
                        }
                        let rr = zipfile::putlocal_rewrite(&mut zf.e, out);
                        drain_dots(z, out);
                        if rr.is_err() {
                            z.zipwarn(m::FF_ERROR_REWRITING.as_bytes(), b"");
                        }
                        if let Err(e) = out.w.seek_raw(current_offset) {
                            z.zipwarn(m::FF_WRITE_SEEK.as_bytes(), &host_err(&e));
                            return Ok(ZE_WRITE);
                        }
                        match out.w.tell_raw() {
                            Ok(o) if o == current_offset => {}
                            Ok(_) => {
                                z.zipwarn(m::FF_SEEK_AFTER_LOCAL.as_bytes(), &errno.text());
                                return Ok(ZE_WRITE);
                            }
                            Err(e) => {
                                z.zipwarn(m::FF_SEEK_AFTER_LOCAL.as_bytes(), &host_err(&e));
                                return Ok(ZE_WRITE);
                            }
                        }
                        if z.o.verbose > 0 {
                            z.zipmessage_nl(b"", true);
                        }
                    }
                    _ => {
                        message(z, m::FF_NO_LOCAL_ENTRY, &[cstr(&iname)], true);
                    }
                }
            } else if sc.ar.zfiles.is_empty() && &sigbuf == b"PK\x07\x08" {
                // a spanning signature at the top of the archive
                let text = if z.total_disks == 1 {
                    m::FF_SPAN_NOT_EXPECTED
                } else if z.total_disks > 1 {
                    m::FF_SPAN_EXPECTED
                } else {
                    m::FF_SPAN_MAYBE
                };
                z.zipmessage(text.as_bytes(), b"");
            } else {
                // this signature should not be here
                let mut s = m::FF_UNEXPECTED_SIGNATURE.as_bytes().to_vec();
                for c in sigbuf {
                    s.extend_from_slice(format!("{c:02x} ").as_bytes());
                }
                printf(
                    &mut s,
                    m::SIG_ON_DISK,
                    &[
                        cur.to_string().as_bytes(),
                        current_in_offset.wrapping_sub(4).to_string().as_bytes(),
                    ],
                );
                z.zipwarn(&s, b"");
                z.zipwarn(m::SKIPPING_SIGNATURE.as_bytes(), b"");
            }
        }
        // close this disk and do the next
        if let Some(f) = ia.f.take() {
            errno.from(&f);
        }
        if r == ZE_EOF {
            // the user says no more splits
            break;
        }
        z.current_in_disk += 1;
    }
    Ok(0)
}

/// How far `zsort` is made, and whether two entries have ever had equal
/// names (sticky: from then on the flavour's `qsort` decides their order,
/// and an insertion could not reproduce it).
#[derive(Default)]
struct SortState {
    upto: usize,
    has_equal: bool,
}

/// zipfile.c:scanzipf_fixnew's sort of the entries met so far, at each
/// central directory met (`qsort(zsort, zcount, ..., zqcmp)`), with the
/// same `zsort` and less work (ruling Z22): nothing when no entry was
/// added since the last sort; while every name met is distinct, a few new
/// entries inserted where they go, or many sorted (with names all distinct
/// any sort gives the one order); once two names are equal, the flavour's
/// `qsort` over all entries in their order, every time, as in the C (an
/// unstable `qsort` orders equal names its own way).
fn resort(z: &Zr, ar: &mut Archive, st: &mut SortState) {
    let n = ar.zfiles.len();
    if n == st.upto {
        return;
    }
    if !st.has_equal {
        if n - st.upto <= 64 {
            let mut zsort = ar.zsort.clone();
            for i in st.upto..n {
                let k = cstr(&ar.zfiles[i].zname);
                match zsort.binary_search_by(|&j| cstr(&ar.zfiles[j].zname).cmp(k)) {
                    Ok(_) => {
                        st.has_equal = true;
                        break;
                    }
                    Err(pos) => zsort.insert(pos, i),
                }
            }
            if !st.has_equal {
                ar.zsort = zsort;
                st.upto = n;
                return;
            }
        } else {
            let mut order: Vec<usize> = (0..n).collect();
            order.sort_by(|&a, &b| cstr(&ar.zfiles[a].zname).cmp(cstr(&ar.zfiles[b].zname)));
            if order
                .windows(2)
                .all(|w| cstr(&ar.zfiles[w[0]].zname) != cstr(&ar.zfiles[w[1]].zname))
            {
                ar.zsort = order;
                st.upto = n;
                return;
            }
            st.has_equal = true;
        }
    }
    let names: Vec<&[u8]> = ar.zfiles.iter().map(|f| cstr(&f.zname)).collect();
    let mut order: Vec<usize> = (0..n).collect();
    super::scan::qsort(z.flavour, &mut order, &|a, b| names[a].cmp(names[b]));
    ar.zsort = order;
    st.upto = n;
}

/// `strerror` of an error the output stream met.
fn host_err(e: &std::io::Error) -> Vec<u8> {
    crate::compat::host::strerror(e)
}

/// `printf("Is this a single-disk archive?  (y/n): ")` and the answer
/// (`fgets(errbuf, 100, stdin)`): `y` or `Y` first makes it one disk. The
/// end of standard input is not `y`.
fn ask_single_disk(z: &mut Zr) {
    z.stdout_write(m::FF_SINGLE_DISK_Q.as_bytes());
    let p = super::split::prompt(z);
    if let Some(a) = super::split::fgets_n(&p, 100)
        && matches!(a.first(), Some(b'y' | b'Y'))
    {
        z.total_disks = 1;
        z.zipmessage(m::FF_ASSUMING_SINGLE.as_bytes(), b"");
    }
}

/// zipfile.c:zipcopy with `fix == 2`: the stream is just past a local
/// header's signature; the entry is made from the local header and copied
/// (its data up to the local header's size, or up to its data descriptor).
/// The `ZE_*` code: 0 for an entry to keep.
// port: zipfile.c:zipcopy (fix == 2)
fn zipcopy_ff(
    z: &mut Zr,
    ia: &mut InArchive,
    out: &mut ZOut,
    tempzn: &mut u64,
    zf: &mut ZFile,
    errno: &mut Errno,
) -> Result<i32, Exit> {
    let f = ia.f.as_mut().expect("open");
    let buf = f.fread(LOCHEAD as usize);
    if buf.len() != LOCHEAD as usize {
        errno.from(f);
        let err = f.ferror();
        z.zipwarn(m::READING_LOCAL_ENTRY.as_bytes(), &errno.text());
        return Ok(if err { ZE_READ } else { ZE_EOF });
    }
    let mut lz = ZEntry {
        ver: sh(&buf, 0),
        lflg: sh(&buf, 2),
        how: sh(&buf, 4),
        tim: lg(&buf, 6),
        crc: lg(&buf, 10),
        siz: u64::from(lg(&buf, 14)),
        len: u64::from(lg(&buf, 18)),
        ..ZEntry::default()
    };
    let nam = usize::from(sh(&buf, 22));
    let ext = usize::from(sh(&buf, 24));
    // some sanity checks that this is a local header
    let os = lz.ver >> 8;
    let pkver = lz.ver.wrapping_sub(os);
    let insane = if os > 40 {
        Some((m::FF_ILLEGAL_HOST, os))
    } else if pkver > 100 {
        Some((m::FF_ILLEGAL_PKVER, pkver))
    } else if lz.how > 200 {
        Some((m::FF_UNRECOGNIZED_METHOD, lz.how))
    } else {
        None
    };
    if let Some((fmt, v)) = insane {
        let mut s = Vec::new();
        printf(&mut s, fmt, &[v.to_string().as_bytes()]);
        z.zipwarn(&s, b"");
        // the entry's name is not known yet (the C prints a NULL)
        z.zipwarn(m::FF_SKIPPING.as_bytes(), b"(null)");
        return Ok(ZE_FORM);
    }
    lz.iname = f.fread(nam);
    if lz.iname.len() != nam {
        errno.from(f);
        return Ok(if f.ferror() { ZE_READ } else { ZE_EOF });
    }
    lz.extra = f.fread(ext);
    if lz.extra.len() != ext {
        errno.from(f);
        return Ok(if f.ferror() { ZE_READ } else { ZE_EOF });
    }
    lz.name = cstr(&lz.iname).to_vec();
    // zip64_entry = adjust_zip_local_entry(localz)
    out.zip64_entry = adjust_zip_local_entry(&mut lz);
    // set z from localz
    zf.e.flg = lz.lflg;
    zf.e.len = lz.len;
    zf.e.siz = lz.siz;
    zf.e.dsk = out.current_disk;
    zf.e.off = out.w.offset();
    // deviation 19: z->lflg is never set here (0)
    let e: u64 = if zf.e.lflg & 8 != 0 {
        if out.zip64_entry { 24 } else { 16 }
    } else {
        0
    };
    *tempzn = tempzn
        .wrapping_add(4 + LOCHEAD + nam as u64 + ext as u64 + e)
        .wrapping_add(zf.e.siz);
    let oname = cstr(&lz.iname).to_vec();
    zf.e.oname = oname.clone();
    let mut s = Vec::new();
    printf(&mut s, m::FF_COPYING, &[&oname]);
    z.zipmessage_nl(&s, false);
    zf.e.crc = lz.crc;
    let r = zipfile::putlocal(&mut lz, out);
    drain_dots(z, out);
    match r {
        Ok(()) => {}
        Err(zipfile::PutError::Write(err)) => return Err(write_failed(z, &err)),
        Err(pe) => return Err(super::zipup::put_failed(z, &lz, pe)),
    }
    // copy the data: up to the descriptor, or the local header's size
    let mut des = Des::default();
    let r = if lz.lflg & 8 != 0 {
        bfcopy_ff(z, ia, out, None, &mut des, errno)?
    } else {
        bfcopy_ff(z, ia, out, Some(lz.siz), &mut des, errno)?
    };
    if r == ZE_ABORT {
        return Err(z.ziperr(ZE_ABORT, m::COULD_NOT_FIND_SPLIT_ABORT.as_bytes()));
    }
    if r == ZE_EOF || z.skip_this_disk != 0 {
        // missing disk
        z.zipwarn(m::ABORTING_ENTRY.as_bytes(), &oname);
        let r = if r == 0 { ZE_FORM } else { r };
        // -FF goes on with the next disk: back over this entry
        z.skip_this_disk = 0;
        let at = out.current_local_offset;
        if out.w.seek_raw(at).is_err() {
            return Err(z.ziperr(ZE_WRITE, m::SEEK_FAILED_OUTPUT.as_bytes()));
        }
        out.w.set_offset(at);
        *tempzn = at;
        return Ok(r);
    }
    if zf.e.flg & 8 != 0 {
        // this entry should have a data descriptor
        if des.good {
            lz.crc = des.crc;
            lz.siz = des.csize;
            lz.len = des.usize;
        } else {
            z.zipwarn(m::FF_NO_END_OF_STREAM.as_bytes(), &oname);
            z.zipwarn(m::FF_REWINDING.as_bytes(), b"");
            // back in the output to overwrite this entry (the count stays)
            let _ = out.w.seek_raw(out.current_local_offset);
            return Ok(ZE_FORM);
        }
    }
    if zf.e.flg & 8 != 0 {
        let rr = zipfile::putextended(&lz, out);
        drain_dots(z, out);
        if let Err(err) = rr {
            return Err(write_failed(z, &err));
        }
    }
    zf.e.ver = lz.ver;
    zf.e.how = lz.how;
    zf.e.tim = lz.tim;
    zf.e.crc = lz.crc;
    zf.e.lflg = lz.lflg;
    zf.e.flg = lz.lflg;
    zf.e.len = lz.len;
    zf.e.siz = lz.siz;
    zf.e.extra = lz.extra.clone();
    // the local extra field as the central one, for now (deviation 19:
    // strcpy's copy, the rest zeros)
    let mut cextra = vec![0u8; lz.extra.len()];
    let upto = lz
        .extra
        .iter()
        .position(|&b| b == 0)
        .map_or(lz.extra.len(), |i| i + 1);
    cextra[..upto].copy_from_slice(&lz.extra[..upto]);
    zf.e.cextra = cextra;
    zf.e.comment = Vec::new();
    zf.e.att = 0;
    zf.e.atx = 0;
    zf.e.name = lz.name.clone();
    zf.e.iname = lz.iname.clone();
    zf.zname = cstr(&lz.iname).to_vec();
    let mut s = Vec::new();
    printf(&mut s, m::FF_BYTES, &[zf.e.siz.to_string().as_bytes()]);
    z.zipmessage_nl(&s, true);
    if r == ZE_READ {
        z.zipwarn(m::FF_ENTRY_TRUNCATED.as_bytes(), &oname);
        let mut s = Vec::new();
        printf(
            &mut s,
            m::FF_EXPECTED_SIZE,
            &[
                lz.siz.to_string().as_bytes(),
                out.bytes_this_entry.to_string().as_bytes(),
            ],
        );
        z.zipwarn(&s, b"");
    }
    Ok(r)
}

/// zipfile.c:adjust_zip_local_entry: the sizes a Zip64 extra field holds
/// for the ones that say so; true when there is one. A field too short is
/// read as zeros past its end (deviation 19).
// port: zipfile.c:adjust_zip_local_entry
fn adjust_zip_local_entry(e: &mut ZEntry) -> bool {
    let Some(at) = get_extra_field(0x0001, &e.extra) else {
        return false;
    };
    let mut block = e.extra[(at + 4).min(e.extra.len())..].to_vec();
    block.resize(block.len().max(16), 0);
    let mut p = 0;
    if e.len == ZIP_UWORD32_MAX {
        e.len = llg(&block, p);
        p += 8;
    }
    if e.siz == ZIP_UWORD32_MAX {
        e.siz = llg(&block, p);
    }
    true
}

/// fileio.c:bfcopy as `-FF` runs it: `n` bytes (`Some`), or (`None`, an
/// entry with a data descriptor) up to the descriptor whose compressed
/// size is the distance read. A read that gives nothing is `ZE_READ`. The
/// `ZE_*` code: 0, `ZE_READ`, `ZE_EOF`/`ZE_FORM` from a question, or
/// `ZE_ABORT`.
// port: fileio.c:bfcopy (fix == 2)
fn bfcopy_ff(
    z: &mut Zr,
    ia: &mut InArchive,
    out: &mut ZOut,
    n: Option<u64>,
    des: &mut Des,
    errno: &mut Errno,
) -> Result<i32, Exit> {
    let cbsz = readzip::CBSZ;
    let desc = n.is_none();
    let n = n.unwrap_or(u64::MAX - 1);
    let mut sbuf = [0u8; 4];
    let mut data_start = 0u64;
    if desc {
        data_start = ia.f.as_mut().map_or(0, CFile::tell);
    }
    let copy_dots = z.o.copy_only && !z.o.display_globaldots;
    if copy_dots {
        z.o.dot_count = -1;
    }
    des.good = false;
    let mut m: u64 = 0;
    while desc || m < n {
        let brd = if desc {
            cbsz
        } else {
            (n - m).min(cbsz as u64) as usize
        };
        let Some(f) = ia.f.as_mut() else {
            return Ok(ZE_READ);
        };
        let des_start = f.tell();
        // ruling Z22: the C reads 16 KiB and looks at it; stuffr reads what
        // it looks at (4 bytes, a descriptor's 16 or 24, or a search
        // reading on in doubling pieces up to the 16 KiB): the same bytes
        // written and the same position after
        let first = if desc { 4 } else { brd };
        let mut b = f.fread(first);
        if b.is_empty() {
            errno.from(f);
            return Ok(ZE_READ);
        }
        let mut k = b.len();
        if desc {
            des.crc = 0;
            des.csize = 0;
            des.usize = 0;
            let size = if out.zip64_entry { 24 } else { 16 };
            if !b.starts_with(b"PK\x07\x08") {
                // not at a descriptor: look for its signature, and stop
                // the buffer before it
                let mut scanned = 0;
                let mut found = None;
                loop {
                    for (kk, &c) in b.iter().enumerate().skip(scanned) {
                        sbuf.copy_within(1..4, 0);
                        sbuf[3] = c;
                        // deviation 19: only a signature wholly in this read
                        // (one begun in the previous read makes the C write
                        // `kk - 3`, wrapped, bytes)
                        if &sbuf == b"PK\x07\x08" && kk >= 3 {
                            found = Some(kk - 3);
                            break;
                        }
                    }
                    if found.is_some() || b.len() >= brd || f.feof() {
                        break;
                    }
                    scanned = b.len();
                    let more = scanned.max(64).min(brd - scanned);
                    let c = f.fread(more);
                    if c.is_empty() {
                        break;
                    }
                    b.extend_from_slice(&c);
                }
                k = b.len();
                if let Some(kk) = found {
                    // (the C seeks to the OUTPUT's count plus kk)
                    let to = out.w.offset().wrapping_add(kk as u64);
                    if !f.seek(i128::from(to)) {
                        return Err(z.ziperr(ZE_READ, m::SEEK_FAILED_DESCRIPTOR.as_bytes()));
                    }
                    k = kk;
                }
            } else {
                // the signature at the start of the buffer
                if b.len() == 4 {
                    b.extend_from_slice(&f.fread(size - 4));
                }
                k = b.len();
                des.good = false;
                if k >= size {
                    if out.zip64_entry {
                        des.crc = lg(&b, 4);
                        des.csize = llg(&b, 8);
                        des.usize = llg(&b, 16);
                    } else {
                        des.crc = lg(&b, 4);
                        des.csize = u64::from(lg(&b, 8));
                        des.usize = u64::from(lg(&b, 12));
                    }
                    if des_start.wrapping_sub(data_start) != des.csize {
                        // not this data's: the signature is data
                        k = 4;
                        if !f.seek(i128::from(des_start) + 4) {
                            return Err(z.ziperr(ZE_READ, m::SEEK_FAILED_DESCRIPTOR.as_bytes()));
                        }
                        let r = out.bfwrite(&b[..k], Bf::Data);
                        drain_dots(z, out);
                        if let Err(err) = r {
                            return Err(write_failed(z, &err));
                        }
                        m += k as u64;
                        continue;
                    }
                    // the right descriptor: skip it, it is written later
                    des.good = true;
                    k = size;
                    if !f.seek(i128::from(des_start) + size as i128) {
                        return Err(z.ziperr(ZE_READ, m::SEEK_FAILED_DESCRIPTOR.as_bytes()));
                    }
                    data_start = f.tell();
                } else {
                    // fewer than a descriptor's bytes are left: the C's
                    // 16 KiB read got these and no more
                    let rest = f.fread(brd - b.len());
                    b.extend_from_slice(&rest);
                    k = b.len();
                }
            }
        }
        if !des.good {
            // write out (what may be a wrong descriptor) as data
            let r = out.bfwrite(&b[..k], Bf::Data);
            drain_dots(z, out);
            if let Err(err) = r {
                return Err(write_failed(z, &err));
            }
            m += k as u64;
        }
        if copy_dots {
            readzip::copy_dot(z, k);
        }
        if des.good {
            break;
        }
        if desc {
            continue;
        }
        if m < n && ia.f.as_ref().is_some_and(CFile::feof) {
            match readzip::next_in_split(z, ia) {
                Ok(true) => {}
                Ok(false) => break,
                Err(CopyFail::Code(c, _)) => return Ok(c),
                Err(CopyFail::Exit(x)) => return Err(x),
                Err(CopyFail::Write(err)) => return Err(write_failed(z, &err)),
            }
        }
    }
    Ok(0)
}
