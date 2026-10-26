//! What zip.c:main's writing needs around the entries (`update.rs` is the
//! driver): the progress counters, `-c` and `-z`'s comment stream and
//! lines, and `finish()`'s `-o` and `-m`.

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use super::messages::{self as m, printf};
use super::readzip::{ZFile, ut_mtime};
use super::unix;
use super::zipfile::ZEntry;
use super::zipup::{Wr, write_num_string};
use super::{Exit, Zr};
use crate::compat::host::Host;

/// zip.c:MAXCOM, a `-c` line.
const MAXCOM: usize = 256;

/// zip.c:zipmessage_nl("", 1): end a line a message began.
pub(crate) fn end_line(z: &mut Zr) {
    if z.o.noisy && z.mesg_line_started {
        z.mesg_write(b"\n");
        z.set_line(false);
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
        z.set_line(false);
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
            z.set_line(true);
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

/// zip.c:finish with the archive's entries: `-o` (the archive's time is
/// its newest file's) and `-m` (the inputs deleted, after the archive is
/// in place).
// port: zip.c:finish
pub(crate) fn finish(z: &mut Zr, code: i32, zfiles: &mut [ZFile]) -> Exit {
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    if z.o.latest && !zipfile.is_empty() && zipfile != b"-" {
        if zfiles.is_empty() {
            z.zipwarn(m::ZIP_EMPTY_NO_LATEST.as_bytes(), b"");
        } else {
            let mut t: u32 = 0;
            for zf in zfiles.iter() {
                let e = &zf.e;
                if e.iname.last() == Some(&b'/') {
                    continue; // directories are ignored
                }
                let tim = ut_mtime(e).map_or(e.tim, |mt| unix::unix2dostime(z, mt) as u32);
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
        trash(z, zfiles);
    }
    Exit { code }
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

/// zipfile.c:trash: delete the file of each entry marked (added or
/// updated) or up to date under `-um`/`-fm`, then their directories,
/// deepest first, when empty. Failures to delete a directory are ignored,
/// as there.
// port: zipfile.c:trash
pub(crate) fn trash(z: &mut Zr, zfiles: &mut [ZFile]) {
    for zf in zfiles.iter_mut() {
        if zf.mark == 1 || zf.trash {
            zf.mark = 1;
            if zf.e.iname.last() != Some(&b'/') {
                let name = zf.e.name.clone();
                if z.o.verbose > 0 {
                    let mut l = Vec::new();
                    printf(&mut l, m::DELETING_FILE, &[&name]);
                    z.mesg_write(&l);
                }
                if std::fs::remove_file(z.host.path(&name)).is_err() {
                    z.zipwarn(m::ERROR_DELETING.as_bytes(), &name);
                }
                // without directory names (-D) the C cuts the names to their
                // parents, but leaves them so that none counts as a directory
            }
        }
    }
    let mut dirs: Vec<&ZEntry> = Vec::new();
    for zf in zfiles.iter() {
        let e = &zf.e;
        if zf.mark != 0
            && e.iname.last() == Some(&b'/')
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
