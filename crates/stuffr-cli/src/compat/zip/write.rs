//! zip.c:main from the temporary archive to the end, for a new archive:
//! the loop over the names (its progress counters, its unreadable inputs),
//! `-c` and `-z`, the central directory and end record
//! ([`zipfile::write_central`]), the replacement of the archive, and
//! `finish()`'s `-o` and `-m`.

use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::Path;

use super::cli::{Method, ZE_OK, ZE_OPEN};
use super::flavour;
use super::messages::{self as m, printf};
use super::scan::Found;
use super::sink::{FileSink, Temp, mkstemp, replace, stdout_sink};
use super::unix;
use super::zipfile::{self, GlobalDots, PutError, ZEntry, ZOut, ZWrite};
use super::zipup::{
    Wr, Zipped, add, drain_dots, percent, perror, write_failed, write_num_string, zerr,
};
use super::{Exit, Zr};
use crate::compat::host::Host;

/// ziperr.h codes this file raises.
const ZE_BIG: i32 = 6;
const ZE_TEMP: i32 = 10;
const ZE_CREAT: i32 = 15;
/// zip.c:MAXCOM, a `-c` line.
const MAXCOM: usize = 256;

/// zip.c:zipmessage_nl("", 1): end a line a message began.
pub(crate) fn end_line(z: &mut Zr) {
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
pub(crate) fn display_running_stats(z: &mut Zr, w: &Wr) {
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

/// Where `-c` and `-z` read their lines: standard input, or (after `-@` or
/// as a filter, when standard input is the names or the data) standard
/// error opened for reading (`fdopen(fileno(stderr), "r")`). `None` is
/// that `fdopen` failing: standard error is not open for reading (a pipe,
/// a file opened to write; a sandbox's).
pub(crate) fn comment_stream(z: &mut Zr) -> Option<Box<dyn BufRead>> {
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
/// A `fgets` line as the C's string functions see it: up to its first NUL.
pub(crate) fn cut_at_nul(mut l: Vec<u8>) -> Vec<u8> {
    if let Some(i) = l.iter().position(|&b| b == 0) {
        l.truncate(i);
    }
    l
}

/// A `-c` or `-z` line: cut at its first NUL (`strlen`, `strcpy`), its
/// newline dropped. Deviation 10: a line that begins with a NUL makes the C
/// read before its buffer (`p[k-1]`, `e[r-1]` with a length of 0); stuffr
/// takes it for an empty line.
pub(crate) fn comment_line(l: Vec<u8>) -> Vec<u8> {
    let mut l = cut_at_nul(l);
    if l.last() == Some(&b'\n') {
        l.pop();
    }
    l
}

pub(crate) fn fgets(r: &mut dyn BufRead) -> Option<Vec<u8>> {
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
                Box::new(FileSink::new(f, budget))
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
                if let Some(p) = fgets(r.as_mut()) {
                    e.comment = comment_line(p);
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
            while let Some(e) = fgets(r.as_mut()) {
                let e = cut_at_nul(e);
                if e == b".\n" {
                    break;
                }
                let e = comment_line(e);
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
    let verbose = z.o.verbose > 0;
    let r = {
        let mut before_end = |out: &mut ZOut, tot: zipfile::Totals| {
            drain_dots(z, out);
            if tot.k == 0 {
                z.zipwarn(m::ZIP_FILE_EMPTY.as_bytes(), b"");
            }
            let mut total = Vec::new();
            printf(
                &mut total,
                m::TOTAL_BYTES,
                &[
                    tot.n.to_string().as_bytes(),
                    tot.t.to_string().as_bytes(),
                    percent(tot.n, tot.t).to_string().as_bytes(),
                ],
            );
            if verbose {
                z.mesg_write(&total);
            }
            if z.o.logall {
                z.log_write(&total);
            }
            if z.o.show_what_doing {
                z.mesg_write(m::SD_WRITING_END.as_bytes());
            }
        };
        zipfile::write_central(
            &mut entries,
            &zcomment,
            &mut w.out,
            &mut w.tempzn,
            &mut before_end,
        )
    };
    drain_dots(z, &mut w.out);
    match r {
        Ok(_) => {}
        Err(PutError::Big { why, .. }) => {
            z.zipwarn(why.as_bytes(), b"");
            return z.ziperr(ZE_BIG, &tempzip);
        }
        Err(PutError::Write(err)) => return write_failed(z, &err),
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
pub(crate) fn set_mode(p: &Path, mode: u32) {
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
pub(crate) fn finish(z: &mut Zr, code: i32, entries: &mut [ZEntry]) -> Exit {
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
pub(crate) fn ut_mtime(extra: &[u8]) -> Option<i64> {
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
pub(crate) fn stamp(z: &Zr, name: &[u8], d: u32) {
    let t = dos2unixtime(&z.host, d);
    let when = if t >= 0 {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(t as u64)
    } else {
        std::time::UNIX_EPOCH - std::time::Duration::from_secs(t.unsigned_abs())
    };
    set_times_by_path(&z.host.path(name), t, when);
}

/// `utime(path, ...)`: by the path, as unix.c's `stamp` does, so the owner
/// of a read-only archive can stamp it.
fn set_times_by_path(p: &Path, t: i64, when: std::time::SystemTime) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let _ = when;
        let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
            return;
        };
        let tv = libc::timeval {
            tv_sec: t as libc::time_t,
            tv_usec: 0,
        };
        let times = [tv, tv];
        // SAFETY: a NUL-terminated path and two timevals, alive for the call.
        unsafe { libc::utimes(c.as_ptr(), times.as_ptr()) };
    }
    #[cfg(not(unix))]
    {
        let _ = t;
        if let Ok(f) = File::options().write(true).open(p) {
            let _ = f.set_times(
                std::fs::FileTimes::new()
                    .set_accessed(when)
                    .set_modified(when),
            );
        }
    }
}

/// fileio.c:dos2unixtime: `mktime` of the MS-DOS fields in the local zone
/// (a sandbox's is UTC).
#[allow(clippy::useless_conversion)] // `time_t` is 32 bits on some unixes
pub(crate) fn dos2unixtime(host: &Host, d: u32) -> i64 {
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
    // days from civil, UTC, the month normalised first as mktime does
    // (an MS-DOS month 0 is December before, 13 to 15 the next year's)
    let months = (year + 1900) * 12 + mon;
    let (y, m0) = (months.div_euclid(12), months.rem_euclid(12) + 1);
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
pub(crate) fn trash(z: &mut Zr, entries: &[ZEntry]) {
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
