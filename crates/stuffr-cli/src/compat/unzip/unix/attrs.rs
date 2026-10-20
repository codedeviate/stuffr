//! `unix/unix.c`'s attributes: `mapattr()` (an entry's mode), `filtattr()`,
//! `get_extattribs()`, `close_outfile()` (mode, owner and times of a file,
//! or a symlink deferred), `defer_dir_attribs()`/`set_direc_attribs()`,
//! `set_symlnk_attribs()`; and Apple's quarantine (`qtn_file_*`, R9/P7,
//! deviation 7).
//!
//! Every change goes through the beneath walk: a file by the descriptor it
//! was created with, a directory or symlink by its parent's.

use std::io;

use super::super::extract::{Ex, Info};
use super::super::fileio::{self, c_str};
use super::super::messages as m;
use super::super::process::{CentralEntry, EB_UT_FL_ATIME, EB_UT_FL_MTIME, IzTimes};
use super::super::{PK_COOL, PK_OK, PK_WARN, Uz, flavour};
use super::mapname::{self, filtattr, perror};
use crate::compat::host::Host;

/// unzpriv.h's host numbers `mapattr()` tells apart.
const AMIGA_: u8 = 1;
const VMS_: u8 = 2;
const UNIX_: u8 = 3;
const ATARI_: u8 = 5;
const QDOS_: u8 = 12;
const ACORN_: u8 = 13;
const BEOS_: u8 = 16;
const TANDEM_: u8 = 17;
const THEOS_: u8 = 18;
const ATHEOS_: u8 = 30;
const FS_FAT_: u8 = 0;

/// unzpriv.h's extra block ids `mapattr()` looks for.
const EF_ASIUNIX: u16 = 0x756e;
const EF_PKVMS: u16 = 0x000c;
/// unzpriv.h's `EB_ASI_MODE`.
const EB_ASI_MODE: usize = 4;

/// `S_ISLNK()` of a mode.
pub(crate) fn s_islnk(mode: u32) -> bool {
    mode & 0o170000 == 0o120000
}

/// unzpriv.h's `SYMLINK_HOST()`: the made-by hosts whose symlinks unzip
/// restores.
fn symlink_host(hn: u8) -> bool {
    matches!(hn, UNIX_ | ATARI_ | ATHEOS_ | BEOS_ | VMS_)
}

/// The process's file mode creation mask (`umask(tmp = umask(0))`); a
/// sandbox's is 022 (R7: nothing of the process is read).
// `mode_t` is 16 bits on macOS, 32 on Linux.
#[allow(clippy::useless_conversion)]
fn umask(host: &Host) -> u32 {
    match host {
        #[cfg(unix)]
        Host::Real => {
            // SAFETY: `umask` only swaps the process's mask; it is set back
            // at once (the run is single-threaded, as unzip is).
            unsafe {
                let m = libc::umask(0);
                libc::umask(m);
                u32::from(m)
            }
        }
        _ => 0o022,
    }
}

// port: unix.c:mapattr
/// `mapattr()`: the entry's mode (`G.pInfo->file_attr`) from its external
/// attributes (`e`, `G.crec`), by the host that made it: Unix-like hosts
/// keep their high 16 bits (unless 0 and an ASi or PKWARE VMS block says
/// otherwise), and hosts without Unix modes get `0444`, the write bits
/// unless MS-DOS's read-only bit, execute for a directory, less the umask.
/// It also decides `G.pInfo->symlink`.
pub(crate) fn mapattr(uz: &Uz, e: &CentralEntry, info: &mut Info) {
    let mut tmp = e.external_file_attributes as u32;
    info.file_attr = 0;
    let hostnum = info.pinfo.hostnum;
    let mut dos = false;
    match hostnum {
        AMIGA_ => {
            tmp = (tmp >> 17) & 7; // Amiga RWE bits
            info.file_attr = (tmp << 6) | (tmp << 3) | tmp;
        }
        THEOS_ | UNIX_ | VMS_ | ACORN_ | ATARI_ | ATHEOS_ | BEOS_ | QDOS_ | TANDEM_ => {
            if hostnum == THEOS_ {
                tmp &= 0xF1FF_FFFF;
                if tmp & 0xF000_0000 != 0x4000_0000 {
                    tmp &= 0x01FF_FFFF; // not a dir, mask all ftype bits
                } else {
                    tmp &= 0x41FF_FFFF; // leave directory bit as set
                }
            }
            let mut r = false;
            info.file_attr = tmp >> 16;
            if info.file_attr == 0
                && let Some(ef) = e.extra.as_deref()
            {
                // Some (non-Info-ZIP) implementations of Zip for Unix and
                // VMS leave 0 in the upper 16-bit part of the
                // external_file_attributes field; we look for the extra
                // fields that hold them instead.
                let mut ef = ef;
                while !r && ef.len() >= 4 {
                    let eb_id = fileio::makeword(ef);
                    let eb_len = usize::from(fileio::makeword(&ef[2..]));
                    if eb_len > ef.len() - 4 {
                        // discoverd some e.f. inconsistency!
                        break;
                    }
                    match eb_id {
                        EF_ASIUNIX if eb_len >= EB_ASI_MODE + 2 => {
                            info.file_attr = u32::from(fileio::makeword(&ef[4 + EB_ASI_MODE..]));
                            // force stop of loop:
                            ef = &ef[..eb_len + 4];
                        }
                        // "found nondecypherable e.f. with perm. attr"
                        EF_ASIUNIX | EF_PKVMS => r = true,
                        _ => {}
                    }
                    ef = &ef[eb_len + 4..];
                }
            }
            if !r {
                // Check if the file is a (POSIX-compatible) symbolic link.
                // We restrict symlink support to those "made-by" hosts that
                // are known to support symbolic links.
                info.symlink = s_islnk(info.file_attr) && symlink_host(hostnum);
                return;
            }
            // fall through!
            info.file_attr = tmp >> 16;
            dos = true;
        }
        FS_FAT_ => {
            // PKWARE's PKZip for Unix marks entries as FS_FAT_, but stores
            // the Unix attributes in the upper 16 bits of the external
            // attributes field, just like Info-ZIP's Zip for Unix.
            info.file_attr = tmp >> 16;
            dos = true;
        }
        _ => dos = true,
    }
    if dos {
        // Ensure that DOS subdir bit is set when the entry's name ends in a
        // '/'.  Some third-party Zip programs fail to set the subdir bit
        // for directory entries.
        if tmp & 0x10 == 0 && e.filename.last() == Some(&b'/') {
            tmp |= 0x10;
        }
        // read-only bit --> write perms; subdir bit --> dir exec bit
        tmp = (u32::from(tmp & 1 == 0) << 1) | ((tmp & 0x10) >> 4);
        if info.file_attr & 0o700 == (0o400 | (tmp << 6)) {
            // keep previous G.pInfo->file_attr setting, when its "owner"
            // part appears to be consistent with DOS attribute flags!
            // Entries "made by FS_FAT_" could have been zipped on a system
            // that supports POSIX-style symbolic links.
            info.symlink = s_islnk(info.file_attr) && hostnum == FS_FAT_;
            return;
        }
        info.file_attr = 0o444 | (tmp << 6) | (tmp << 3) | tmp;
    }
    // for originating systems with no concept of "group," "other,"
    // "system": apply mask to expanded r/w(/x) perms
    info.file_attr &= !umask(&uz.host);
}

// port: unix.c:get_extattribs
/// `get_extattribs()`: the access and modification times from the local
/// extra field (`G.extra_field`), else the DOS time for both; and the
/// owner `-X` restores, when the build reads one (`IZ_HAVE_UXUIDGID`).
pub(crate) fn get_extattribs(uz: &Uz, ex: &Ex) -> (IzTimes, Option<[u64; 2]>) {
    let mut z = IzTimes::default();
    let mut ug = [0u64; 2];
    let dos = uz.lrec.last_mod_dos_datetime;
    // ubuntu: -DIZ_HAVE_UXUIDGID (`flavour::iz_have_uxuidgid`, Task 13): the
    // scan reads the owner (and a `ux` block then drops earlier times),
    // whether or not `-X` asks for it, as the C passes `z_uidgid` always.
    let owner = flavour::iz_have_uxuidgid(uz.flavour).then_some((&mut ug, uz.flavour));
    let flags = match ex.extra_field.as_deref() {
        Some(ef) => {
            super::super::process::ef_scan_for_izux_owner(ef, false, dos, Some(&mut z), owner)
        }
        None => 0,
    };
    if flags & EB_UT_FL_MTIME == 0 {
        z.mtime = fileio::dos_to_unix_time(uz, dos);
    }
    if flags & EB_UT_FL_ATIME == 0 {
        z.atime = z.mtime;
    }
    // if -X option was specified and we have UID/GID info, restore it
    // (`RESTORE_UIDGID` is in both builds; the `chown` is tried for any
    // user, as the C tries it)
    let have = uz.o.x_flag != 0 && flags & super::super::process::EB_UX2_VALID != 0;
    (z, have.then_some(ug))
}

/// `(ulg)(uid_t)(v) == v`: the value fits `uid_t`/`gid_t` (32 bits).
fn fits(v: u64) -> bool {
    u32::try_from(v).is_ok()
}

/// `utime()`'s pair on an open file (`futimens`, whole seconds).
fn set_times(f: &std::fs::File, atime: i64, mtime: i64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let ts = [
            libc::timespec {
                tv_sec: atime as libc::time_t,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: mtime as libc::time_t,
                tv_nsec: 0,
            },
        ];
        // SAFETY: `ts` holds the two `timespec`s `futimens` reads; the
        // descriptor is open for the call.
        if unsafe { libc::futimens(f.as_raw_fd(), ts.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(unix))]
    {
        let t = |s: i64| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s.max(0) as u64);
        f.set_times(
            std::fs::FileTimes::new()
                .set_accessed(t(atime))
                .set_modified(t(mtime)),
        )
    }
}

/// `fchmod(fd, mode)`.
fn fchmod(f: &std::fs::File, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let mut p = f.metadata()?.permissions();
        p.set_readonly(mode & 0o200 == 0);
        f.set_permissions(p)
    }
}

/// `fchown(fd, uid, gid)`.
fn fchown(f: &std::fs::File, uid: u64, gid: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::fchown(f, Some(uid as u32), Some(gid as u32))
    }
    #[cfg(not(unix))]
    {
        let _ = (f, uid, gid);
        Ok(())
    }
}

/// The owner messages: `CannotSetItemUidGid` under `-q`, else
/// `CannotSetUidGid` after the "extracting:" line.
fn uidgid_failed(uz: &mut Uz, uidgid: [u64; 2], name: &[u8], e: &io::Error) {
    let (u, g) = (uidgid[0].to_string(), uidgid[1].to_string());
    let err = mapname::strerror(uz, e);
    if uz.o.qflag != 0 {
        let shown = fileio::fnfilter1(uz, name);
        uz.info_fmt(
            0x201,
            m::CANNOT_SET_ITEM_UID_GID,
            &[u.as_bytes(), g.as_bytes(), &shown, &err],
        );
    } else {
        uz.info_fmt(
            0x201,
            m::CANNOT_SET_UID_GID,
            &[u.as_bytes(), g.as_bytes(), &err],
        );
    }
}

/// A deferred symlink (`slinkentry`): its target, its path (`G.filename`
/// when it was extracted) and the attributes `set_symlnk_attribs()` sets.
pub(crate) struct SlinkEntry {
    pub(crate) target: Vec<u8>,
    pub(crate) fname: Vec<u8>,
    pub(crate) attr: u32,
    pub(crate) uidgid: Option<[u64; 2]>,
}

// port: unix.c:close_outfile
/// `close_outfile()`: for a symlink, its target read back from the
/// placeholder and the link deferred (`G.slink_head`); for a file, its
/// owner (`-X`), mode and times set, then closed. Returns the C's code
/// (T10-2 on its missing `return`: `PK_COOL`).
pub(crate) fn close_outfile(uz: &mut Uz, ex: &mut Ex) -> i32 {
    let (zt, uidgid) = get_extattribs(uz, ex);
    let Some(out) = ex.outfile.take() else {
        return PK_COOL;
    };
    let fname = c_str(&uz.filename).to_vec();

    // If symbolic links are supported, allocate storage for a symlink
    // control structure, put the uncompressed "data" and other required
    // info in it, and add the structure to the "deferred symlinks" chain.
    if ex.symlnk {
        let ucsize = uz.lrec.ucsize;
        let mut f = out.file;
        // move back to the start of the file to re-read the "link data"
        let mut target = Vec::new();
        let read = {
            use std::io::{Read, Seek, SeekFrom};
            f.seek(SeekFrom::Start(0))
                .and_then(|_| (&mut f).take(ucsize).read_to_end(&mut target))
        };
        if !matches!(read, Ok(n) if n as u64 == ucsize) {
            let shown = fileio::fnfilter1(uz, &fname);
            uz.info_fmt(0x201, m::SYMLINK_FAILED, &[&shown]);
            return PK_WARN;
        }
        drop(f); // close "link" file for good...
        // `slnk_entry->target[ucsize] = '\0'`: a C string from here on
        let target = c_str(&target).to_vec();
        if uz.o.qflag == 0 {
            let shown = fileio::fnfilter1(uz, &target);
            uz.info_fmt(0, m::SYMLINK_ARROW, &[&shown]);
        }
        // add this symlink record to the list of deferred symlinks
        ex.slinks.push(SlinkEntry {
            target,
            fname,
            attr: ex.pinfo.file_attr,
            uidgid,
        });
        return PK_COOL;
    }

    let f = out.file;
    // if -X option was specified and we have UID/GID info, restore it
    if let Some(ug) = uidgid.filter(|ug| fits(ug[0]) && fits(ug[1]))
        && let Err(e) = fchown(&f, ug[0], ug[1])
    {
        uidgid_failed(uz, ug, &fname, &e);
    }

    // Change the file permissions from default ones to those stored in the
    // zipfile.
    if let Err(e) = fchmod(&f, filtattr(uz, ex.pinfo.file_attr)) {
        perror(uz, m::PERROR_FCHMOD, &e);
    }

    // skip restoring time stamps on user's request
    if uz.o.d_flag <= 1 {
        // set the file's access and modification times
        if let Err(e) = set_times(&f, zt.atime, zt.mtime) {
            let err = mapname::strerror(uz, &e);
            if uz.o.qflag != 0 {
                let shown = fileio::fnfilter1(uz, &fname);
                uz.info_fmt(0x201, m::CANNOT_SET_ITEM_TIMESTAMPS, &[&shown, &err]);
            } else {
                uz.info_fmt(0x201, m::CANNOT_SET_TIMESTAMPS, &[&err]);
            }
        }
    }
    drop(f);
    PK_COOL
}

// port: unix.c:set_symlnk_attribs
/// `set_symlnk_attribs()`: a deferred symlink's owner (`-X`, `lchown()`) and
/// mode (`lchmod()`, unless the build has none).
pub(crate) fn set_symlnk_attribs(uz: &mut Uz, s: &SlinkEntry) -> i32 {
    let Ok((root, rel)) = mapname::target(uz, &s.fname) else {
        return PK_OK;
    };
    let Ok((dir, name)) = root.parent(rel) else {
        return PK_OK;
    };
    if let Some(ug) = s.uidgid.filter(|ug| fits(ug[0]) && fits(ug[1]))
        && let Err(e) = dir.lchown(&name, ug[0] as u32, ug[1] as u32)
    {
        let (u, g) = (ug[0].to_string(), ug[1].to_string());
        let shown = fileio::fnfilter1(uz, &s.fname);
        let err = mapname::strerror(uz, &e);
        uz.info_fmt(
            0x201,
            m::CANNOT_SET_ITEM_UID_GID,
            &[u.as_bytes(), g.as_bytes(), &shown, &err],
        );
    }
    // ubuntu: -DNO_LCHMOD (`flavour::no_lchmod`, Task 13)
    if !flavour::no_lchmod(uz.flavour)
        && let Err(e) = dir.lchmod(&name, filtattr(uz, s.attr))
    {
        perror(uz, m::PERROR_LCHMOD, &e);
    }
    // currently, no error propagation...
    PK_OK
}

/// A directory whose times and mode are set at the end (`uxdirattr`).
pub(crate) struct DirEntry {
    /// `fn`: its path, `G.filename` when it was made.
    pub(crate) fname: Vec<u8>,
    pub(crate) times: IzTimes,
    pub(crate) perms: u32,
    pub(crate) uidgid: Option<[u64; 2]>,
}

// port: unix.c:defer_dir_attribs
/// `defer_dir_attribs()`: the directory just made, its attributes kept for
/// the end.
pub(crate) fn defer_dir_attribs(uz: &Uz, ex: &Ex) -> DirEntry {
    let (times, uidgid) = get_extattribs(uz, ex);
    DirEntry {
        fname: c_str(&uz.filename).to_vec(),
        times,
        perms: ex.pinfo.file_attr,
        uidgid,
    }
}

// port: unix.c:set_direc_attribs
/// `set_direc_attribs()`: a made directory's owner (`-X`), times (unless
/// `-D`) and mode, each failure a warning.
pub(crate) fn set_direc_attribs(uz: &mut Uz, d: &DirEntry) -> i32 {
    let mut errval = PK_OK;
    let dir = mapname::target(uz, &d.fname)
        .and_then(|(root, rel)| root.dir(rel))
        .and_then(|dir| dir.attr_file());
    if let Some(ug) = d.uidgid.filter(|ug| fits(ug[0]) && fits(ug[1])) {
        let r = match &dir {
            Ok(f) => fchown(f, ug[0], ug[1]),
            Err(e) => Err(copy(e)),
        };
        if let Err(e) = r {
            let (u, g) = (ug[0].to_string(), ug[1].to_string());
            let shown = fileio::fnfilter1(uz, &d.fname);
            let err = mapname::strerror(uz, &e);
            uz.info_fmt(
                0x201,
                m::CANNOT_SET_ITEM_UID_GID,
                &[u.as_bytes(), g.as_bytes(), &shown, &err],
            );
            if errval == 0 {
                errval = PK_WARN;
            }
        }
    }
    // Skip restoring directory time stamps on user' request.
    if uz.o.d_flag <= 0 {
        // restore directory timestamps
        let r = match &dir {
            Ok(f) => set_times(f, d.times.atime, d.times.mtime),
            Err(e) => Err(copy(e)),
        };
        if let Err(e) = r {
            let shown = fileio::fnfilter1(uz, &d.fname);
            let err = mapname::strerror(uz, &e);
            uz.info_fmt(0x201, m::CANNOT_SET_ITEM_TIMESTAMPS, &[&shown, &err]);
            if errval == 0 {
                errval = PK_WARN;
            }
        }
    }
    let r = match &dir {
        Ok(f) => fchmod(f, d.perms),
        Err(e) => Err(copy(e)),
    };
    if let Err(e) = r {
        let shown = fileio::fnfilter1(uz, &d.fname);
        let err = mapname::strerror(uz, &e);
        uz.info_fmt(0x201, m::DIRLIST_CHMOD_FAILED, &[&shown, &err]);
        if errval == 0 {
            errval = PK_WARN;
        }
    }
    errval
}

/// The same error again (each call that would have failed reports it).
fn copy(e: &io::Error) -> io::Error {
    match e.raw_os_error() {
        Some(n) => io::Error::from_raw_os_error(n),
        None if super::beneath::is_escape(e) => super::beneath::escape(),
        None => io::Error::new(e.kind(), e.to_string()),
    }
}

/// `chmod(G.filename, mode)` of a directory just made (beneath the root).
pub(crate) fn chmod_dir(uz: &Uz, full: &[u8], mode: u32) -> io::Result<()> {
    let (root, rel) = mapname::target(uz, full)?;
    fchmod(&root.dir(rel)?.attr_file()?, mode)
}

// ---- quarantine (R9, P7) ----

/// The quarantine attribute's name.
#[cfg(target_os = "macos")]
const QUARANTINE: &std::ffi::CStr = c"com.apple.quarantine";

/// The longest quarantine value read from an archive (its fields are a
/// flags word, a time, an agent name and a UUID: far below this).
const QUARANTINE_MAX: usize = 1024;

/// What libquarantine writes for an archive whose quarantine value is
/// `raw` (`qtn_file_init_with_fd()` then `qtn_file_apply_to_fd()`), `None`
/// when it writes nothing. The flags (the first field, hex) are rewritten,
/// the time, agent and UUID copied; a value without its fourth field is
/// dropped.
/// probe: Task 1's sweep of flags 0000..ffff (`<flags>;00000000;;`) on this
/// Mac (P7): flags >= 0x4000 nothing; 0 becomes `0081`; g = flags & 0x3de7,
/// nothing when 0, else g when it has 0x40, g | 0x80 when it has 0x01 or
/// 0x02, else g. `0181;5f000000;Safari` (three fields) is dropped.
/// ruling: T10-6. Flags that are not hex (never seen, not swept) are
/// treated as a value libquarantine cannot parse: nothing is written.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn qtn_value(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.iter().filter(|&&b| b == b';').count() < 3 {
        return None;
    }
    let semi = raw.iter().position(|&b| b == b';')?;
    let flags = std::str::from_utf8(&raw[..semi]).ok()?;
    if flags.is_empty() || !flags.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let flags = u32::from_str_radix(flags, 16).ok()?;
    let out = if flags >= 0x4000 {
        return None;
    } else if flags == 0 {
        0x0081
    } else {
        let g = flags & 0x3de7;
        if g == 0 {
            return None;
        } else if g & 0x40 != 0 {
            g
        } else if g & 0x03 != 0 {
            g | 0x80
        } else {
            g
        }
    };
    let mut v = format!("{out:04x}").into_bytes();
    v.extend_from_slice(&raw[semi..]);
    Some(v)
}

/// apple: fileio.c:263 (`qtn_file_init_with_fd(G.qf, G.zipfd)`): the value
/// to give what is extracted from the open archive `f`, `None` when it has
/// none (or under a sandbox, R7, or off macOS).
pub(crate) fn archive_quarantine(host: &Host, f: &std::fs::File) -> Option<Vec<u8>> {
    if !matches!(host, Host::Real) {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut buf = vec![0u8; QUARANTINE_MAX];
        // SAFETY: the name is NUL-terminated; `buf` is valid for its
        // length; the descriptor is open.
        let n = unsafe {
            libc::fgetxattr(
                f.as_raw_fd(),
                QUARANTINE.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                0,
            )
        };
        if n < 0 {
            return None;
        }
        buf.truncate(n as usize);
        qtn_value(&buf)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (f, QUARANTINE_MAX);
        None
    }
}

/// `qtn_file_apply_to_fd(G.qf, fd)` on an open file or directory.
pub(crate) fn quarantine_fd(uz: &Uz, f: &std::fs::File) -> io::Result<()> {
    let Some(v) = uz.qf.as_deref() else {
        return Ok(());
    };
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the name is NUL-terminated; `v` is valid for its length;
        // the descriptor is open.
        let rc = unsafe {
            libc::fsetxattr(
                f.as_raw_fd(),
                QUARANTINE.as_ptr(),
                v.as_ptr().cast(),
                v.len(),
                0,
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (f, v);
        Ok(())
    }
}

/// The quarantine of a directory reached beneath the root.
pub(crate) fn quarantine_dir(uz: &Uz, d: &super::beneath::Dir) -> io::Result<()> {
    if uz.qf.is_none() {
        return Ok(());
    }
    quarantine_fd(uz, &d.attr_file()?)
}

/// apple: extract.c:2633, the quarantine of the symlink `name` in `dir`
/// (`O_SYMLINK`).
pub(crate) fn quarantine_symlink(
    uz: &Uz,
    dir: &super::beneath::Dir,
    name: &[u8],
) -> io::Result<()> {
    if uz.qf.is_none() {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        quarantine_fd(uz, &dir.open_symlink(name)?)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (dir, name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P7's rule, value by value (the Task 1 probe's cases).
    #[test]
    fn quarantine_values_are_rewritten_as_libquarantine_does() {
        let q = |s: &str| qtn_value(s.as_bytes()).map(|v| String::from_utf8(v).unwrap());
        assert_eq!(
            q("0001;5f000000;Safari;UUID").as_deref(),
            Some("0081;5f000000;Safari;UUID")
        );
        assert_eq!(
            q("0082;688909f7;Test;").as_deref(),
            Some("0082;688909f7;Test;")
        );
        assert_eq!(
            q("0181;5f000000;Safari;ABCDEF01-0000").as_deref(),
            Some("0181;5f000000;Safari;ABCDEF01-0000")
        );
        assert_eq!(q("0000;00000000;;").as_deref(), Some("0081;00000000;;"));
        assert_eq!(q("4000;00000000;;"), None);
        assert_eq!(q("ffff;00000000;;"), None);
        assert_eq!(q("0018;00000000;;"), None); // g = 0x0000
        assert_eq!(q("0040;00000000;;").as_deref(), Some("0040;00000000;;"));
        assert_eq!(q("0002;00000000;;").as_deref(), Some("0082;00000000;;"));
        assert_eq!(q("0004;00000000;;").as_deref(), Some("0004;00000000;;"));
        assert_eq!(q("0181;5f000000;Safari"), None); // three fields
        assert_eq!(q("zz;00000000;;"), None); // T10-6
    }
}
