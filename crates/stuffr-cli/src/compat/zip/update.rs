//! zip.c:main from "make sure the zip file is writeable" to the end, for a
//! new archive and an archive already at the path alike: the temporary
//! archive (armed for zip's interrupt handler), what is before the first
//! entry, the old entries (updated, copied, deleted, `-FS`'s, `-U`'s copy
//! mode), the new ones, `-c` and `-z`, the central directory and end
//! record, `-T` (`check_zipfile`), the replacement of the archive (a
//! rename) and `finish()`'s `-o` and `-m` (after the archive is in place).
//!
//! **No input is ever lost:** the archive is only ever replaced by a
//! rename of the finished temporary (or written through, `replace`'s copy,
//! when it has other links); every failure before that leaves it as it was
//! and removes the temporary.
//!
//! Deviations (`mod.rs`, 13-16): `-g` grows a copy (zip writes into the
//! archive itself), the output is not truncated before it is replaced,
//! `-T` never sees Ubuntu's double free (ruling Z3), and a sandboxed `-T`
//! spawns nothing.

use std::ffi::OsStr;
use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};

use super::cli::{Action, Method, ZE_OK, ZE_OPEN, ZE_PARMS};
use super::flavour;
use super::messages::{self as m, printf};
use super::readzip::{self, CopyFail, InArchive, ZFile, zipcopy};
use super::scan::Collected;
use super::sink::{FileSink, Temp, mkstemp, replace, stdout_sink};
use super::unix;
use super::write::{
    comment_line, comment_stream, cut_at_nul, display_running_stats, end_line, fgets, finish,
    set_mode,
};
use super::zipfile::{self, GlobalDots, PutError, ZEntry, ZOut, ZWrite};
use super::zipup::{
    Wr, Zipped, add, add_entry, drain_dots, percent, perror, write_failed, write_num_string, zerr,
};
use super::{Exit, Zr};
use crate::compat::host::Host;

/// ziperr.h codes this file raises.
const ZE_BIG: i32 = 6;
const ZE_TEST: i32 = 8;
const ZE_TEMP: i32 = 10;
const ZE_WRITE: i32 = 14;
const ZE_CREAT: i32 = 15;

/// `ZIPERR(r, "was copying <oname>")` for a failed `zipcopy` (a write
/// failure is `bfwrite`'s own `ZE_WRITE`).
fn copy_failed(z: &mut Zr, f: CopyFail, oname: &[u8]) -> Exit {
    match f {
        CopyFail::Code(code, err) => {
            let mut h = Vec::new();
            printf(&mut h, m::WAS_COPYING, &[oname]);
            zerr(z, code, &h, err.as_ref())
        }
        CopyFail::Write(err) => write_failed(z, &err),
        CopyFail::Exit(x) => x,
    }
}

/// A message to `mesg` that starts a line (`fprintf(mesg, ...)`, then
/// `mesg_line_started = 1`), and its log copy.
fn start_line(z: &mut Zr, text: &[u8], to_mesg: bool, to_log: bool) {
    if to_mesg {
        z.mesg_write(text);
        z.set_line(true);
    }
    if to_log {
        z.log_write(text);
        z.log_line_started = true;
    }
}

/// `" (" + DisplayNumString(len) + ")"` under `-du`.
fn usize_text(z: &Zr, len: u64) -> Vec<u8> {
    let mut s = Vec::new();
    if z.o.display_usize {
        printf(&mut s, m::USIZE, &[write_num_string(len).as_bytes()]);
    }
    s
}

/// zip.c:BlankRunningStats: `-FS`'s blank counters before a deletion.
// port: zip.c:BlankRunningStats
fn blank_running_stats(z: &mut Zr) {
    let mut parts: Vec<&[u8]> = Vec::new();
    if z.o.display_volume {
        parts.push(m::BLANK_DV.as_bytes());
    }
    if z.o.display_counts {
        parts.push(m::BLANK_DC.as_bytes());
    }
    if z.o.display_bytes {
        parts.push(m::BLANK_DB.as_bytes());
    }
    for p in parts {
        if z.o.noisy {
            z.mesg_write(p);
            z.set_line(true);
        }
        if z.o.logall {
            z.log_write(p);
            z.log_line_started = true;
        }
    }
}

/// zip.c:main, from "make sure the zip file is writeable" to `finish()`.
// port: zip.c:main
pub(crate) fn run(z: &mut Zr, c: Collected) -> Exit {
    let Collected {
        found,
        mut ar,
        k,
        files_total,
        bytes_total,
        ..
    } = c;
    // Tasks 9 (encryption) and 11 (bzip2)
    if z.o.key.is_some() || z.o.key_needed || z.o.method == Method::Bzip2 {
        return z.not_built();
    }
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    let to_stdout = zipfile == b"-";
    let in_path = z.o.in_path.clone().unwrap_or_else(|| zipfile.clone());
    let out_path = z.o.out_path.clone().unwrap_or_else(|| zipfile.clone());
    let has_files = !ar.zfiles.is_empty();
    // d is true if appending (-g)
    let d = z.o.grow && k == 0 && (ar.zipbeg != 0 || has_files);
    // just ignore the spanning signature of a multi-disk archive
    if has_files && z.total_disks != 1 && ar.zipbeg == 4 {
        ar.zipbeg = 0;
    }
    let mut zip_attributes: u32 = 0;
    // Make sure the zip file is writeable (the C leaves the check to the
    // end when -b names the temp's directory and there is no archive).
    let tempdir_check_later = z.o.tempdir && !has_files && ar.zipbeg == 0;
    if !to_stdout && !tempdir_check_later {
        let p = z.host.path(&out_path);
        let fresh = z.o.have_out || (!has_files && ar.zipbeg == 0);
        let existed = std::fs::symlink_metadata(&p).is_ok();
        // deviation 14: an existing output is opened, not truncated
        let opened = if fresh {
            std::fs::File::options()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&p)
        } else {
            std::fs::File::options().read(true).write(true).open(&p)
        };
        match opened {
            Err(e) => return z.ziperr_os(ZE_CREAT, &out_path, &e),
            Ok(f) => {
                drop(f);
                zip_attributes = std::fs::metadata(&p).map_or(0, |md| unix::meta_of(&md).mode);
                if !has_files && ar.zipbeg == 0 && !existed {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    // throw away the garbage in front of the zip file for -J
    if z.o.junk_sfx {
        ar.zipbeg = 0;
    }
    if z.o.show_what_doing {
        z.mesg_write(m::SD_OPEN_ZIP.as_bytes());
    }
    let mut ia = InArchive { f: None };
    let mut temp = Temp { path: None };
    let mut _armed = None;
    let mut tempzip: Vec<u8> = b"-".to_vec();
    let mut temp_dir: Vec<u8> = Vec::new();
    if d && !to_stdout && z.total_disks > 1 {
        return z.ziperr(ZE_PARMS, m::CANNOT_GROW_SPLIT.as_bytes());
    }
    // something at the beginning of disk 1 to copy: open that disk now
    if !to_stdout && !d && ar.zipbeg != 0 {
        let ip = z.o.in_path.clone().unwrap_or_default();
        let mut p = match super::split::get_in_split_path(z, &ip, 0) {
            Ok(p) => p,
            Err(x) => return x,
        };
        loop {
            if let Ok(f) = readzip::CFile::open(z, &p) {
                ia.f = Some(f);
                break;
            }
            // ask for the directory with the part (updates in_path)
            match super::split::ask_for_split_read_path(z, 0) {
                Err(x) => return x,
                Ok(super::split::ZE_OK) => {}
                Ok(_) => {
                    return z.ziperr(super::cli::ZE_ABORT, m::COULD_NOT_OPEN_TO_READ.as_bytes());
                }
            }
            // (the C tries disk 1's name next)
            let ip = z.o.in_path.clone().unwrap_or_default();
            p = match super::split::get_in_split_path(z, &ip, 1) {
                Ok(p) => p,
                Err(x) => return x,
            };
        }
    }
    let sink: Box<dyn ZWrite> = if to_stdout {
        stdout_sink(&z.host)
    } else {
        if !d && z.o.show_what_doing {
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
        temp_dir = dir.clone();
        let (name, r) = mkstemp(&z.host, &dir);
        tempzip = name;
        match r {
            Err(e) => return z.ziperr_os(ZE_TEMP, &tempzip, &e),
            Ok((f, guard)) => {
                temp.path = Some(z.host.path(&tempzip));
                _armed = Some(guard);
                let budget = match &z.host {
                    Host::Sandbox(s) => Some(s.budget.clone()),
                    Host::Real => None,
                };
                Box::new(FileSink::new(f, budget))
            }
        }
    };
    // the name zip's messages give the archive being written: under -g the
    // archive itself (deviation 13: stuffr grows a copy)
    let shown_temp = if d { zipfile.clone() } else { tempzip.clone() };
    if d && !to_stdout {
        // zip.c: tempzip = zipfile; ziperr now says it restores the archive
        let mut l = Vec::new();
        printf(&mut l, m::ATTEMPTING_RESTORE, &[&zipfile]);
        let l: &'static [u8] = Box::leak(l.into_boxed_slice());
        crate::compat::host::zip_abort_extra(&z.host, Some(l));
        z.restoring = Some(zipfile.clone());
    }
    let use_descriptors = z.o.use_descriptors || !sink.seekable();
    let gdots = z.o.display_globaldots.then_some(GlobalDots {
        dot_size: z.o.dot_size,
        dot_count: z.o.dot_count,
    });
    let mut out = ZOut::new(sink, z.o.force_zip64, gdots);
    out.split_size = z.o.split_size;
    if z.o.split_method > 0 && !to_stdout {
        // the splits own the temporary from here
        temp.path = None;
        let prompt = super::split::prompt(z);
        out.split = Some(Box::new(super::split::SplitW {
            method: z.o.split_method,
            bell: z.o.split_bell,
            noisy_splits: z.o.noisy_splits,
            out_path: out_path.clone(),
            temp_dir: temp_dir.clone(),
            env: super::split::SplitEnv::of(&z.host),
            tempzip: tempzip.clone(),
            guard: _armed.take(),
            published: false,
            local: None,
            lost: Vec::new(),
            zip_attributes,
            prompt,
            fnmax: flavour::fnmax(z.flavour),
            mesg: Some(z.host.out_writer(None)),
            noisy: z.o.noisy,
            line: z.line_cell.clone(),
        }));
    }
    let mut w = Wr {
        out,
        deflater: None,
        use_descriptors,
        tempzn: 0,
        files_total,
        files_so_far: 0,
        bytes_total,
        bytes_so_far: 0,
        good_bytes_so_far: 0,
        bad_files_so_far: 0,
        bad_bytes_so_far: 0,
    };
    // copy what is before the archive (or, growing, everything up to its
    // central directory)
    if !to_stdout {
        let upto = if d { ar.cenbeg } else { ar.zipbeg };
        if d && upto > 0 {
            let f = match readzip::CFile::open(z, &in_path) {
                Ok(f) => f,
                Err(e) => return z.ziperr_os(ZE_OPEN, &in_path, &e),
            };
            ia.f = Some(f);
        }
        if upto > 0
            && ia.f.is_some()
            && let Err(fail) = readzip::bfcopy(z, &mut ia, &mut w.out, upto)
        {
            return copy_failed_plain(z, fail, &zipfile);
        }
        ia.f = None;
        w.tempzn = upto;
        if z.o.split_method > 0 && !d {
            // the spanning signature at the top of the archive
            if z.o.show_what_doing {
                z.mesg_write(m::SD_SPANNING.as_bytes());
            }
            let r = w.out.bfwrite(b"PK\x07\x08", zipfile::Bf::Data);
            drain_dots(z, &mut w.out);
            if let Err(err) = r {
                return write_failed(z, &err);
            }
            w.tempzn += 4;
        }
    }
    let mut o = false;

    // Process the zip file, updating marked files
    if has_files && z.o.show_what_doing {
        z.mesg_write(m::SD_GOING_THROUGH.as_bytes());
    }
    let action = z.o.action;
    let filesync = z.o.filesync;
    let mut zfiles: Vec<ZFile> = Vec::new();
    for mut zf in std::mem::take(&mut ar.zfiles) {
        if zf.mark == 1 {
            let len = zf.e.len;
            match action {
                Action::Add | Action::Update | Action::Freshen => {
                    let current = filesync && zf.current;
                    if z.o.verbose > 0 || !current {
                        display_running_stats(z, &w);
                    }
                    let oname = zf.e.oname.clone();
                    let mut l = Vec::new();
                    let (text, log_text) = if action == Action::Freshen {
                        printf(&mut l, m::FRESHENING, &[&oname]);
                        (Some(l.clone()), Some(l))
                    } else if current {
                        let mut lg = Vec::new();
                        printf(&mut l, m::FS_OK, &[&oname]);
                        printf(&mut lg, m::FS_CURRENT_LOG, &[&oname]);
                        let v = z.o.verbose > 0;
                        (v.then_some(l), v.then_some(lg))
                    } else {
                        printf(&mut l, m::UPDATING, &[&oname]);
                        (Some(l.clone()), Some(l))
                    };
                    if let Some(t) = text {
                        start_line(z, &t, z.o.noisy, false);
                    }
                    if let Some(t) = log_text {
                        let logall = z.o.logall;
                        start_line(z, &t, false, logall);
                    }
                    // get the local header's flags and extra field
                    match readzip::readlocal(z, &mut ia, &zf) {
                        Err(_) => {
                            z.zipwarn(m::COULD_NOT_READ_LOCAL.as_bytes(), &oname);
                            zf.e.lflg = zf.e.flg;
                            zf.e.extra.clear();
                        }
                        Ok(local) => {
                            zf.e.lflg = local.lflg;
                            zf.e.extra = local.extra;
                        }
                    }
                    let mut r: Option<Zipped> = None;
                    if !current {
                        let stripped = zf.e.name.strip_suffix(b"/").unwrap_or(&zf.e.name);
                        let disk = z.host.path(stripped);
                        match add_entry(z, &mut w, zf.e.clone(), &disk) {
                            Err(x) => return x,
                            Ok(Zipped::Entry(e)) => zf.e = e,
                            Ok(other) => r = Some(other),
                        }
                    } else {
                        // -FS: the entry matches its file, so it is copied
                        if let Err(f) = zipcopy(z, &mut ia, &mut w.out, &mut w.tempzn, &mut zf) {
                            return copy_failed(z, f, &oname);
                        }
                        end_line(z);
                    }
                    if let Some(r) = r {
                        o = true;
                        end_line(z);
                        match r {
                            Zipped::Open(err, e) => {
                                zf.e = *e;
                                perror_named(z, &oname, &err);
                                z.zipwarn(m::COULD_NOT_OPEN.as_bytes(), &oname);
                                if z.o.bad_open_is_error {
                                    let mut h = Vec::new();
                                    printf(&mut h, m::WAS_ZIPPING, &[&zf.e.name]);
                                    // ubuntu: the stale errno, as for a new file
                                    let shown = if flavour::stale_errno_after_warning(z.flavour) {
                                        io::Error::from_raw_os_error(22)
                                    } else {
                                        err
                                    };
                                    return z.ziperr_os(ZE_OPEN, &h, &shown);
                                }
                            }
                            _ => z.zipwarn(m::FILE_AND_DIR.as_bytes(), &oname),
                        }
                        z.zipwarn(m::WILL_JUST_COPY.as_bytes(), &oname);
                        if let Err(f) = zipcopy(z, &mut ia, &mut w.out, &mut w.tempzn, &mut zf) {
                            return copy_failed(z, f, &oname);
                        }
                        zf.mark = 0;
                    }
                    w.files_so_far += 1;
                    w.good_bytes_so_far = w.good_bytes_so_far.wrapping_add(zf.e.len);
                    w.bytes_so_far = w.bytes_so_far.wrapping_add(len);
                    zfiles.push(zf);
                }
                Action::Archive => {
                    display_running_stats(z, &w);
                    let fix = z.o.fix;
                    // moved to another disk: copy again
                    if z.skip_this_disk.wrapping_sub(1) != zf.e.dsk {
                        z.skip_this_disk = 0;
                    }
                    let skipping = z.skip_this_disk.wrapping_sub(1) == zf.e.dsk;
                    let oname = zf.e.oname.clone();
                    let mut l = Vec::new();
                    if skipping {
                        printf(&mut l, m::SKIPPING_ENTRY_NAME, &[&oname]);
                    } else {
                        printf(&mut l, m::COPYING, &[&oname]);
                        l.extend_from_slice(&usize_text(z, zf.e.len));
                    }
                    let (noisy, logall) = (z.o.noisy, z.o.logall);
                    start_line(z, &l, noisy, logall);
                    let siz = zf.e.siz;
                    let mut ok = true;
                    if skipping {
                        // skip the entries on this disk
                        zf.mark = 0;
                    } else if let Err(f) = zipcopy(z, &mut ia, &mut w.out, &mut w.tempzn, &mut zf) {
                        match f {
                            // ZIPERR inside zipcopy or bfwrite: already ended
                            CopyFail::Exit(x) => return x,
                            CopyFail::Write(err) => return write_failed(z, &err),
                            CopyFail::Code(super::cli::ZE_ABORT, _) => {
                                return z.ziperr(
                                    super::cli::ZE_ABORT,
                                    m::USER_REQUESTED_ABORT.as_bytes(),
                                );
                            }
                            CopyFail::Code(code, _) if fix == 1 => {
                                // back over the entry in the output, to write
                                // the next over it
                                let at = w.out.current_local_offset;
                                if w.out.w.seek_raw(at).is_err() {
                                    return z.ziperr(code, m::COULD_NOT_SEEK_OUTPUT.as_bytes());
                                }
                                z.zipwarn(m::BAD_SKIPPING.as_bytes(), &oname);
                                w.tempzn = at;
                                w.out.w.set_offset(at);
                                ok = false;
                            }
                            f => {
                                z.zipwarn(m::TRY_F_TO_FIX.as_bytes(), b"");
                                return copy_failed(z, f, &oname);
                            }
                        }
                    }
                    if z.skip_this_disk != 0 || fix != 1 || ok {
                        if z.o.noisy && z.mesg_line_started {
                            z.mesg_write(b"\n");
                            z.set_line(false);
                        }
                        if z.o.logall && z.log_line_started {
                            z.log_write(b"\n");
                            z.log_line_started = false;
                        }
                    }
                    w.files_so_far += 1;
                    if ok {
                        w.good_bytes_so_far = w.good_bytes_so_far.wrapping_add(siz);
                    } else {
                        w.bad_bytes_so_far = w.bad_bytes_so_far.wrapping_add(siz);
                    }
                    w.bytes_so_far = w.bytes_so_far.wrapping_add(siz);
                    if ok || fix != 1 {
                        zfiles.push(zf);
                    }
                    // (-F: a bad entry is removed from the list)
                }
                Action::Delete => {
                    display_running_stats(z, &w);
                    let mut l = Vec::new();
                    printf(&mut l, m::DELETING, &[&zf.e.oname]);
                    l.extend_from_slice(&usize_text(z, zf.e.len));
                    l.push(b'\n');
                    if z.o.noisy {
                        z.mesg_write(&l);
                    }
                    if z.o.logall {
                        z.log_write(&l);
                    }
                    w.files_so_far += 1;
                    w.good_bytes_so_far = w.good_bytes_so_far.wrapping_add(zf.e.siz);
                    w.bytes_so_far = w.bytes_so_far.wrapping_add(zf.e.siz);
                    // deleted from the list
                }
            }
        } else if action == Action::Archive {
            // not copied
        } else if filesync {
            // delete the entries that match no file on disk
            blank_running_stats(z);
            let mut l = Vec::new();
            printf(&mut l, m::DELETING, &[&zf.e.oname]);
            l.extend_from_slice(&usize_text(z, zf.e.len));
            l.push(b'\n');
            if z.o.noisy {
                z.mesg_write(&l);
                z.set_line(false);
            }
            if z.o.logall {
                z.log_write(&l);
                z.log_line_started = false;
            }
            zfiles.push(zf);
        } else {
            // copy the original entry
            if !d && !z.o.diff_mode {
                let oname = zf.e.oname.clone();
                if let Err(f) = zipcopy(z, &mut ia, &mut w.out, &mut w.tempzn, &mut zf) {
                    return copy_failed(z, f, &oname);
                }
            }
            zfiles.push(zf);
        }
    }

    // Process the edited found list, adding them to the zip file
    if z.o.show_what_doing {
        z.mesg_write(m::SD_ZIPPING_NEW.as_bytes());
    }
    for f in &found {
        display_running_stats(z, &w);
        let mut line = Vec::new();
        printf(&mut line, m::ADDING, &[&f.oname]);
        let (noisy, logall) = (z.o.noisy, z.o.logall);
        start_line(z, &line, noisy, logall);
        let len = f.usize.unwrap_or(0);
        let r = match add(z, &mut w, f) {
            Ok(r) => r,
            Err(x) => return x,
        };
        match r {
            Zipped::Open(err, _) => {
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
                w.bytes_so_far = w.bytes_so_far.wrapping_add(len);
                w.bad_files_so_far += 1;
                w.bad_bytes_so_far = w.bad_bytes_so_far.wrapping_add(len);
            }
            Zipped::Miss => {
                o = true;
                end_line(z);
                z.zipwarn(m::FILE_AND_DIR.as_bytes(), &f.oname);
                w.files_so_far += 1;
                w.bytes_so_far = w.bytes_so_far.wrapping_add(len);
                w.bad_files_so_far += 1;
                w.bad_bytes_so_far = w.bad_bytes_so_far.wrapping_add(len);
            }
            Zipped::Entry(e) => {
                w.files_so_far += 1;
                w.good_bytes_so_far = w.good_bytes_so_far.wrapping_add(e.len);
                w.bytes_so_far = w.bytes_so_far.wrapping_add(len);
                zfiles.push(ZFile {
                    e,
                    zname: f.zname.clone(),
                    mark: 1,
                    trash: false,
                    current: false,
                    dosflag: f.dosflag,
                });
            }
        }
    }
    // final status
    if w.bad_files_so_far > 0 {
        let mut s = Vec::new();
        s.extend_from_slice(m::NOT_ALL_READABLE.as_bytes());
        let read = w.files_total.wrapping_sub(w.bad_files_so_far).to_string();
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
    let mut zcomment = std::mem::take(&mut ar.zcomment);
    if z.o.comadd || z.o.zipedit {
        let mut cs = comment_stream(z);
        if z.o.comadd {
            for zf in zfiles.iter_mut().filter(|zf| zf.mark != 0) {
                if z.o.noisy {
                    let mut l = Vec::new();
                    printf(&mut l, m::ENTER_COMMENT, &[&zf.e.oname]);
                    z.mesg_write(&l);
                }
                // deviation 9: fgets(NULL) after a failed fdopen is SIGSEGV
                // in both references, which zip's handler answers
                let Some(r) = cs.as_mut() else {
                    return super::scan::crashed(z);
                };
                if let Some(p) = fgets(r.as_mut()) {
                    zf.e.comment = comment_line(p);
                }
            }
        }
        if z.o.zipedit {
            if z.o.noisy && !zcomment.is_empty() {
                let mut l = m::CURRENT_COMMENT.as_bytes().to_vec();
                l.extend_from_slice(&zcomment);
                if zcomment.last() != Some(&b'\n') {
                    l.push(b'\n');
                }
                z.mesg_write(&l);
            }
            zcomment = Vec::new();
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
        z.set_line(false);
    }
    // Write central directory and end header to temporary zip
    if z.o.show_what_doing {
        z.mesg_write(m::SD_WRITING_CENTRAL.as_bytes());
    }
    let keep = |zf: &ZFile| zf.mark != 0 || !(z.o.diff_mode || filesync);
    let picked: Vec<usize> = (0..zfiles.len()).filter(|&i| keep(&zfiles[i])).collect();
    let mut central: Vec<ZEntry> = picked.iter().map(|&i| zfiles[i].e.clone()).collect();
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
            &mut central,
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
            return z.ziperr(ZE_BIG, &shown_temp);
        }
        Err(PutError::Write(err)) => return write_failed(z, &err),
    }
    for (i, e) in picked.into_iter().zip(central) {
        zfiles[i].e = e;
    }
    // the last split is the temporary published as the archive
    let split = w.out.split.take();
    if let Some(sp) = &split {
        tempzip = sp.tempzip.clone();
    }
    // fclose(y)
    if let Err(err) = w.out.w.flush() {
        let shown = if split.is_some() {
            tempzip.clone()
        } else {
            shown_temp.clone()
        };
        return z.ziperr_os(if d { ZE_WRITE } else { ZE_TEMP }, &shown, &err);
    }
    let zip64_archive = w.out.zip64_archive;
    let good = w.good_bytes_so_far;
    drop(w);
    ia.f = None;
    // -g: zip wrote into the archive and never truncates it, so the old
    // bytes past the new end stay; the copy gets them too (deviation 13)
    if d && let Err(x) = keep_old_tail(z, &in_path, &tempzip, &shown_temp) {
        return x;
    }
    // Test new zip file before overwriting old one or removing input files
    if z.o.test
        && let Err(x) = check_zipfile_64(z, &tempzip, zip64_archive)
    {
        return x;
    }
    // Replace old zip file with new zip file, leaving only the new one
    if !to_stdout {
        if !d && z.o.show_what_doing {
            z.mesg_write(m::SD_REPLACING.as_bytes());
        }
        let (tmp, out_path) = match &split {
            Some(sp) => (sp.env.path(&sp.tempzip), sp.out_path.clone()),
            None => (temp.path.take().unwrap_or_default(), out_path.clone()),
        };
        let r = replace(&z.host.path(&out_path), &tmp);
        if let Some(mut sp) = split {
            // published or left as the new archive: not removed
            sp.published = true;
        }
        if let Err((code, err)) = r {
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
    z.restoring = None;
    crate::compat::host::zip_abort_extra(&z.host, None);
    drop(_armed);
    // finish the log file
    if z.log.is_some() {
        let mut l = Vec::new();
        printf(&mut l, m::LOG_TOTAL, &[files_total.to_string().as_bytes()]);
        if good != bytes_total {
            l.extend_from_slice(m::LOG_PLANNED.as_bytes());
            l.extend_from_slice(write_num_string(bytes_total).trim_start().as_bytes());
            l.extend_from_slice(m::LOG_ACTUAL.as_bytes());
            l.extend_from_slice(write_num_string(good).trim_start().as_bytes());
            l.extend_from_slice(m::LOG_BYTES.as_bytes());
        } else {
            l.extend_from_slice(write_num_string(bytes_total).trim_start().as_bytes());
            l.extend_from_slice(m::LOG_BYTES.as_bytes());
        }
        let now = super::asctime_now(z);
        printf(&mut l, m::LOG_DONE, &[now.as_bytes()]);
        z.log_write(&l);
    }
    finish(z, if o { ZE_OPEN } else { ZE_OK }, &mut zfiles)
}

/// `perror(name)`: `name: <strerror>` on standard error, and the log's
/// copy.
fn perror_named(z: &mut Zr, name: &[u8], e: &io::Error) {
    let mut line = name.to_vec();
    line.extend_from_slice(b": ");
    line.extend_from_slice(&crate::compat::host::strerror(e));
    line.push(b'\n');
    let _ = z.err.write_all(&line);
    let _ = z.err.flush();
    z.log_write(&line);
}

/// `-g`'s in-place write leaves what the old archive had past the new
/// end: append `old[new_len..old_len]` to the copy at `tempzip`. A failure
/// is the C's `fclose` failing (`ZE_WRITE`, the archive's name).
fn keep_old_tail(z: &mut Zr, in_path: &[u8], tempzip: &[u8], shown: &[u8]) -> Result<(), Exit> {
    let tmp = z.host.path(tempzip);
    let new_len = std::fs::metadata(&tmp).map_or(0, |m| m.len());
    let mut f = match readzip::CFile::open(z, in_path) {
        Ok(f) => f,
        Err(e) => return Err(z.ziperr_os(ZE_WRITE, shown, &e)),
    };
    if !f.seek(i128::from(new_len)) {
        return Ok(());
    }
    let mut out = match std::fs::OpenOptions::new().append(true).open(&tmp) {
        Ok(o) => o,
        Err(e) => return Err(z.ziperr_os(ZE_WRITE, shown, &e)),
    };
    loop {
        let b = f.fread(16384);
        if b.is_empty() {
            break;
        }
        if let Host::Sandbox(s) = &z.host
            && let Err(e) = crate::compat::host::take(&s.budget, b.len() as u64)
        {
            return Err(z.ziperr_os(ZE_WRITE, shown, &e));
        }
        if let Err(e) = out.write_all(&b) {
            return Err(z.ziperr_os(ZE_WRITE, shown, &e));
        }
    }
    Ok(())
}

/// `ZIPERR(r, zipfile)` for a failed copy of what is before the archive
/// (`bfcopy(zipbeg)`).
fn copy_failed_plain(z: &mut Zr, f: CopyFail, zipfile: &[u8]) -> Exit {
    match f {
        CopyFail::Code(code, err) => zerr(z, code, zipfile, err.as_ref()),
        CopyFail::Write(err) => write_failed(z, &err),
        CopyFail::Exit(x) => x,
    }
}

// ---- -T ----

/// zip.c:check_zipfile for an archive already written: `name` tested.
pub(crate) fn check_zipfile(z: &mut Zr, name: &[u8]) -> Result<(), Exit> {
    check_zipfile_64(z, name, false)
}

/// zip.c:check_zipfile: test `name` with `unzip -t` (or `-TT`'s command):
/// Apple through `posix_spawnp` (no shell; `{}` refused), Ubuntu through
/// `system()` (`/bin/sh -c`, the name quoted). A failure is
/// `ZE_TEST`, "original files unmodified": ruling Z3 (deviation 15), as
/// Apple answers in both flavours, where Ubuntu's build frees the
/// temporary's stream twice and aborts.
// port: zip.c:check_zipfile
fn check_zipfile_64(z: &mut Zr, name: &[u8], zip64_archive: bool) -> Result<(), Exit> {
    let _ = z.out.flush();
    let zipfile = z.o.zipfile.clone().unwrap_or_default();
    let shell = flavour::test_through_shell(z.flavour);
    let verbose = z.o.verbose > 0;
    let ok = match z.o.unzip_path.take() {
        Some(up) => {
            if shell {
                // replace the first {} with the quoted name, or append it
                let mut cmd = Vec::new();
                match up.windows(2).position(|w| w == b"{}") {
                    Some(i) => {
                        cmd.extend_from_slice(&up[..i]);
                        cmd.extend_from_slice(b" '");
                        cmd.extend_from_slice(name);
                        cmd.extend_from_slice(b"' ");
                        cmd.extend_from_slice(&up[i + 2..]);
                    }
                    None => {
                        cmd.extend_from_slice(&up);
                        cmd.extend_from_slice(b" '");
                        cmd.extend_from_slice(name);
                        cmd.push(b'\'');
                    }
                }
                system(z, &cmd)
            } else {
                if up.windows(2).any(|w| w == b"{}") {
                    return Err(z.ziperr(ZE_PARMS, m::BRACES_NOT_SUPPORTED.as_bytes()));
                }
                spawn(z, &[up, name.to_vec()])
            }
        }
        None => {
            if !check_unzip_version(z, zip64_archive) {
                return Err(z.ziperr(ZE_TEST, &zipfile));
            }
            if shell {
                let mut cmd = m::UNZIP_T_CMD.as_bytes().to_vec();
                if !verbose {
                    cmd.extend_from_slice(m::QQ_CMD.as_bytes());
                }
                cmd.push(b'\'');
                cmd.extend_from_slice(name);
                cmd.push(b'\'');
                system(z, &cmd)
            } else {
                let mut argv = vec![m::UNZIP.as_bytes().to_vec(), m::UNZIP_T.as_bytes().to_vec()];
                if !verbose {
                    argv.push(m::UNZIP_QQ.as_bytes().to_vec());
                }
                argv.push(name.to_vec());
                spawn(z, &argv)
            }
        }
    };
    if !ok {
        let mut l = Vec::new();
        printf(&mut l, m::TEST_FAILED, &[&zipfile]);
        z.mesg_write(&l);
        // ruling Z3: Ubuntu's double free (exit 5) is not reproduced
        return Err(z.ziperr(ZE_TEST, m::ORIGINAL_UNMODIFIED.as_bytes()));
    }
    let mut l = Vec::new();
    printf(&mut l, m::TEST_OK, &[&zipfile]);
    if z.o.noisy {
        z.mesg_write(&l);
    }
    z.log_write(&l);
    Ok(())
}

fn os(b: &[u8]) -> &OsStr {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        OsStr::from_bytes(b)
    }
    #[cfg(not(unix))]
    {
        OsStr::new(std::str::from_utf8(b).unwrap_or(""))
    }
}

/// `posix_spawnp(argv[0], argv)` with a NULL environment (apple.diff) and
/// `waitpid`: true when the program ran and exited 0. The child gets an
/// empty environment; the program is looked up on zip's own `PATH`. A
/// program that cannot be run, or one killed by a signal, is a failure. A
/// sandbox spawns nothing (deviation 16): a failure.
fn spawn(z: &Zr, argv: &[Vec<u8>]) -> bool {
    if matches!(z.host, Host::Sandbox(_)) {
        return false;
    }
    let Some(prog) = spawnp_lookup(&argv[0]) else {
        return false;
    };
    let mut cmd = Command::new(prog);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.arg0(os(&argv[0]));
    }
    cmd.env_clear();
    for a in &argv[1..] {
        cmd.arg(os(a));
    }
    matches!(cmd.status(), Ok(s) if s.code() == Some(0))
}

/// `posix_spawnp`'s search: a name with a `/` as it is, else the first
/// executable regular file of that name in a `PATH` directory (an empty
/// entry is the current directory; no `PATH`: `/usr/bin:/bin`).
fn spawnp_lookup(name: &[u8]) -> Option<std::path::PathBuf> {
    let p = crate::compat::host::path(name);
    if name.contains(&b'/') {
        return Some(p);
    }
    if name.is_empty() {
        return None;
    }
    let path = std::env::var_os("PATH")
        .map_or_else(|| b"/usr/bin:/bin".to_vec(), |v| v.into_encoded_bytes());
    for dir in path.split(|&b| b == b':') {
        let mut full = if dir.is_empty() {
            b".".to_vec()
        } else {
            dir.to_vec()
        };
        full.push(b'/');
        full.extend_from_slice(name);
        let fp = crate::compat::host::path(&full);
        if let Ok(md) = std::fs::metadata(&fp)
            && md.is_file()
            && executable(&md)
        {
            return Some(fp);
        }
    }
    None
}

fn executable(md: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        true
    }
}

/// `/bin/sh -c cmd` as `sh` (popen's and system()'s shell, so its messages
/// say `sh:`).
fn sh(cmd: &[u8]) -> Command {
    let mut c = Command::new("/bin/sh");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.arg0("sh");
    }
    c.arg("-c").arg(os(cmd));
    c
}

/// `system(cmd)`: true when the shell exited 0. A sandbox spawns nothing.
fn system(z: &Zr, cmd: &[u8]) -> bool {
    if matches!(z.host, Host::Sandbox(_)) {
        return false;
    }
    matches!(sh(cmd).status(), Ok(s) if s.code() == Some(0))
}

/// zip.c:check_unzip_version: `popen("unzip -v")`, its first line read as
/// `UnZip %f`; a Zip64 archive needs UnZip 6. False when the test cannot
/// go on (the caller answers `ZE_TEST`).
// port: zip.c:check_unzip_version
fn check_unzip_version(z: &mut Zr, zip64_archive: bool) -> bool {
    let mut version: f32 = 0.0;
    let mut first: Option<Vec<u8>> = None;
    let mut cmd = m::UNZIP.as_bytes().to_vec();
    cmd.extend_from_slice(m::UNZIP_V_CMD.as_bytes());
    let child = if matches!(z.host, Host::Sandbox(_)) {
        None
    } else {
        match sh(&cmd).stdout(Stdio::piped()).spawn() {
            Ok(c) => Some(c),
            Err(e) => {
                perror(z, m::UNZIP_PIPE_ERROR, &e);
                return finish_version(z, version, zip64_archive);
            }
        }
    };
    let mut child = child;
    let mut parsed = false;
    if let Some(c) = child.as_mut()
        && let Some(out) = c.stdout.take()
    {
        let mut r = io::BufReader::new(out);
        let mut line = Vec::new();
        if matches!(r.read_until(b'\n', &mut line), Ok(n) if n > 0) {
            first = Some(line);
        }
        if let Some(l) = &first
            && let Some(v) = scan_unzip_version(l)
        {
            version = v;
            parsed = true;
            // read the rest
            let mut sink = Vec::new();
            while matches!(r.read_until(b'\n', &mut sink), Ok(n) if n > 0) {
                sink.clear();
            }
        }
        drop(r);
    }
    match &first {
        None => z.zipwarn(m::FAILED_UNZIP_INFO.as_bytes(), b""),
        Some(_) if !parsed => z.zipwarn(m::UNEXPECTED_UNZIP_V.as_bytes(), b""),
        _ => {}
    }
    if let Some(mut c) = child {
        let _ = c.wait();
    }
    finish_version(z, version, zip64_archive)
}

fn finish_version(z: &mut Zr, version: f32, zip64_archive: bool) -> bool {
    if version < 6.0 && zip64_archive {
        let v = format!("{version:4.2}");
        let mut s = Vec::new();
        printf(&mut s, m::FOUND_UNZIP_VERSION, &[v.as_bytes()]);
        z.zipwarn(&s, b"");
        z.zipwarn(m::NEED_UNZIP_6.as_bytes(), b"");
        return false;
    }
    true
}

/// `sscanf(buf, "UnZip %f ", &v)`: `UnZip`, any white space, a float.
fn scan_unzip_version(l: &[u8]) -> Option<f32> {
    let rest = l.strip_prefix(m::UNZIP_V_PREFIX.as_bytes())?;
    let rest = &rest[rest.iter().take_while(|b| b.is_ascii_whitespace()).count()..];
    // strtod's longest prefix of a decimal number
    let mut end = 0;
    if matches!(rest.first(), Some(b'+' | b'-')) {
        end = 1;
    }
    let digits_start = end;
    while rest.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    let mut ndig = end - digits_start;
    if rest.get(end) == Some(&b'.') {
        let mut e2 = end + 1;
        while rest.get(e2).is_some_and(u8::is_ascii_digit) {
            e2 += 1;
        }
        ndig += e2 - end - 1;
        end = e2;
    }
    if ndig == 0 {
        return None;
    }
    if matches!(rest.get(end), Some(b'e' | b'E')) {
        let mut e2 = end + 1;
        if matches!(rest.get(e2), Some(b'+' | b'-')) {
            e2 += 1;
        }
        let s = e2;
        while rest.get(e2).is_some_and(u8::is_ascii_digit) {
            e2 += 1;
        }
        if e2 > s {
            end = e2;
        }
    }
    std::str::from_utf8(&rest[..end]).ok()?.parse().ok()
}

#[cfg(test)]
mod tests;
