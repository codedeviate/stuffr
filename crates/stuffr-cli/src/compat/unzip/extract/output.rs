//! `fileio.c`'s output side: `open_outfile()` (with Apple's
//! `__open_outfile()` wrapper, `-B`'s backups and deviation 4's guard),
//! `flush()` (the CRC, the writes, `-a`'s line ends and VMS text),
//! `disk_error()`, `check_for_newer()`, the input side the decoders read
//! (`readbyte()`, `defer_leftover_input()`, `undefer_input()`), and
//! `fgets(..., stdin)` for the questions.
//!
//! Writes are `write(2)`s of exactly the C's buffers (`USE_FWRITE` is not in
//! either build): a full disk, or a sandbox's spent budget (R7), fails the
//! write the C's fails.

use std::fs::File;
use std::io::{self, Write};

use stuffr::infozip::ByteSource;
use stuffr::infozip::crypt::Keys;

use super::super::fileio::{self, INBUFSIZ, OUTBUFSIZ, ZipIn, c_str};
use super::super::messages as m;
use super::super::process::{self, EB_UT_FL_MTIME, IzTimes};
use super::super::unix::beneath::{self, Dir};
use super::super::unix::mapname::{self, strerror};
use super::super::{PK_OK, Uz, flavour};
use super::{DOES_NOT_EXIST, EXISTS_AND_NEWER, EXISTS_AND_OLDER, Ex, OVERWRT_ALWAYS, PK_DISK};
use crate::compat::host::{self, Host};

/// `G.outfile`: the file being extracted, and the descriptor it was made
/// with (every attribute change goes through it).
pub(crate) struct OutFile {
    pub(crate) file: File,
}

/// unzpriv.h's `CR`, `LF`, `CTRLZ`.
const CR: u8 = 13;
const LF: u8 = 10;
const CTRLZ: u8 = 26;

/// `G.answerbuf`'s size.
const ANSWERBUF: usize = 10;

/// `fgets(buf, size, stdin)`: the next line of standard input up to its
/// `\n` (kept) or `size - 1` bytes, `None` at the end with nothing read.
/// Standard input is one stdio stream for the whole run, as the C's.
fn fgets(uz: &mut Uz, size: usize) -> Option<Vec<u8>> {
    let input = uz.stdin();
    let mut line = Vec::new();
    while line.len() + 1 < size {
        let buf = match input.fill_buf() {
            Ok(b) => b,
            Err(_) => break,
        };
        if buf.is_empty() {
            break;
        }
        let want = size - 1 - line.len();
        let take = match buf.iter().take(want).position(|&b| b == b'\n') {
            Some(i) => i + 1,
            None => buf.len().min(want),
        };
        line.extend_from_slice(&buf[..take]);
        input.consume(take);
        if line.last() == Some(&b'\n') {
            break;
        }
    }
    (!line.is_empty()).then_some(line)
}

/// `fgets(G.answerbuf, sizeof(G.answerbuf), stdin)`: false (the buffer
/// unchanged) at the end of input.
pub(crate) fn fgets_answer(uz: &mut Uz) -> bool {
    match fgets(uz, ANSWERBUF) {
        Some(line) => {
            uz.answerbuf = [0; ANSWERBUF];
            uz.answerbuf[..line.len()].copy_from_slice(&line);
            true
        }
        None => false,
    }
}

/// `fgets(G.filename, FILNAMSIZ, stdin)`: the new name typed at
/// "new name: " (at the end of input `G.filename` is unchanged: false).
pub(crate) fn fgets_filename(uz: &mut Uz) -> bool {
    let size = uz.filename.len();
    match fgets(uz, size) {
        Some(line) => {
            uz.filename[..line.len()].copy_from_slice(&line);
            uz.filename[line.len()] = 0;
            true
        }
        None => false,
    }
}

// port: fileio.c:check_for_newer
/// `check_for_newer(filename)`: `DOES_NOT_EXIST`, `EXISTS_AND_OLDER` (also
/// for any symlink: "symlink dates are meaningless") or `EXISTS_AND_NEWER`
/// (or equal), comparing the existing file's modification time with the
/// entry's (its `UT` time when the local extra field has one, else its DOS
/// time with the existing time rounded up to an even second). The path is
/// `stat()`ed as the C does: read only, so it may look through a symlink
/// outside the root; nothing is changed here.
pub(crate) fn check_for_newer(uz: &mut Uz, ex: &Ex, filename: &[u8]) -> i32 {
    let p = uz.host.path(filename);
    let Ok(st) = std::fs::metadata(&p) else {
        if std::fs::symlink_metadata(&p).is_ok() {
            if uz.o.qflag == 0 && uz.overwrite_mode != OVERWRT_ALWAYS {
                let shown = fileio::fnfilter1(uz, filename);
                uz.info_fmt(0, m::FILE_IS_SYMLINK, &[&shown, m::WITH_NO_REAL_FILE]);
            }
            return EXISTS_AND_OLDER; // symlink dates are meaningless
        }
        return DOES_NOT_EXIST;
    };
    if std::fs::symlink_metadata(&p).is_ok_and(|md| md.file_type().is_symlink()) {
        if uz.o.qflag == 0 && uz.overwrite_mode != OVERWRT_ALWAYS {
            let shown = fileio::fnfilter1(uz, filename);
            uz.info_fmt(0, m::FILE_IS_SYMLINK, &[&shown, b""]);
        }
        return EXISTS_AND_OLDER; // symlink dates are meaningless
    }
    let st_mtime = mtime_of(&st);
    let mut z = IzTimes::default();
    let ut = ex.extra_field.as_deref().is_some_and(|ef| {
        process::ef_scan_for_izux(
            uz.flavour,
            ef,
            false,
            uz.lrec.last_mod_dos_datetime,
            Some(&mut z),
        ) & EB_UT_FL_MTIME
            != 0
    });
    let (existing, archive) = if ut {
        (st_mtime, z.mtime)
    } else {
        // round up existing filetime to nearest 2 seconds for comparison,
        // but saturate in case of arithmetic overflow
        let existing = if st_mtime & 1 != 0 && st_mtime.checked_add(1).is_some() {
            st_mtime + 1
        } else {
            st_mtime
        };
        (
            existing,
            fileio::dos_to_unix_time(uz, uz.lrec.last_mod_dos_datetime),
        )
    };
    if existing >= archive {
        EXISTS_AND_NEWER
    } else {
        EXISTS_AND_OLDER
    }
}

/// `st_mtime`, whole seconds.
fn mtime_of(md: &std::fs::Metadata) -> i64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.mtime()
    }
    #[cfg(not(unix))]
    {
        md.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as i64)
    }
}

/// The archive being read (`G.zipfd`) is the file `st` describes:
/// deviation 4's question (`host::same_file`). Off unix there is no
/// identity to compare, and the answer is no.
pub(crate) fn same_as_archive(uz: &Uz, st: &beneath::Stat) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        uz.zin
            .fd
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .is_some_and(|md| md.dev() == st.dev && md.ino() == st.ino)
    }
    #[cfg(not(unix))]
    {
        let _ = (uz, st);
        false
    }
}

/// The error deviation 4's refusal reports: `EBUSY`, the archive is in use.
fn archive_busy() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::EBUSY)
    }
    #[cfg(not(unix))]
    {
        io::Error::from(io::ErrorKind::ResourceBusy)
    }
}

// port: fileio.c:open_outfile
/// `open_outfile()`: the output file `G.filename` made (an existing one
/// removed, or with `-B` renamed to a backup first), its quarantine given
/// (R9). 0, or 1 after the failure's message. Apple's tree opens the
/// parent beneath the root first ("cannot enter" when it will not open:
/// apple: fileio.c:297); every operation here goes through the walk.
/// ruling: T10-7 (deviation 4). When the existing file is the archive being
/// read (same device and inode), it is not removed, renamed or truncated:
/// "cannot create", with `EBUSY`'s text, as any file the run cannot create.
pub(crate) fn open_outfile(uz: &mut Uz, ex: &mut Ex) -> i32 {
    let full = c_str(&uz.filename).to_vec();
    let apple = flavour::apple_root(uz.flavour);
    let parent = mapname::target(uz, &full).and_then(|(root, rel)| root.parent(rel));
    let (pd, fname) = match parent {
        Ok(p) => p,
        Err(e) => {
            if apple {
                // apple: fileio.c:314 (`ENOTCAPABLE` becomes `EACCES`)
                let e = if beneath::is_escape(&e) {
                    beneath::eacces()
                } else {
                    e
                };
                let dir = match full.iter().rposition(|&b| b == b'/') {
                    Some(i) => full[..i].to_vec(),
                    None => full.clone(),
                };
                let shown = mapname::shown(uz, &dir);
                let err = host::strerror(&e);
                uz.info_fmt(0x401, m::CANNOT_ENTER_DIR, &[&shown, &err]);
            } else {
                cannot_create(uz, &full, &e);
            }
            return 1;
        }
    };

    if let Ok(st) = pd.lstat(&fname) {
        // the file exists
        if same_as_archive(uz, &st) {
            cannot_create(uz, &full, &archive_busy());
            return 1;
        }
        if uz.o.b_flag {
            // do backup
            if backup(uz, &pd, &fname, &full) != 0 {
                return 1;
            }
        } else if let Err(e) = pd.unlink(&fname, false) {
            let shown = mapname::shown(uz, &full);
            let err = strerror(uz, &e);
            uz.info_fmt(0x401, m::CANNOT_DELETE_OLD_FILE, &[&shown, &err]);
            return 1;
        }
    }

    // ruling: T10-11. When the create fails, `G.outfile` is "none" here;
    // Apple's `__open_outfile()` leaves it at the previous entry's closed
    // stream and writes through that (a use after `fclose`), where this
    // gives upstream's "cannot create" and the run goes on.
    let file = pd.create_file(&fname).and_then(|f| {
        // apple: fileio.c:561
        match super::super::unix::attrs::quarantine_fd(uz, &f) {
            Ok(()) => Ok(f),
            Err(e) => {
                let _ = pd.unlink(&fname, false);
                Err(e)
            }
        }
    });
    match file {
        Ok(file) => {
            ex.outfile = Some(OutFile { file });
            0
        }
        Err(e) => {
            cannot_create(uz, &full, &e);
            1
        }
    }
}

/// fileio.c:CannotCreateFile for `full`.
fn cannot_create(uz: &mut Uz, full: &[u8], e: &io::Error) {
    let shown = mapname::shown(uz, full);
    let err = strerror(uz, e);
    uz.info_fmt(0x401, m::CANNOT_CREATE_FILE, &[&shown, &err]);
}

/// `open_outfile()`'s `UNIXBACKUP` branch: the existing file renamed to its
/// name and `~` (with `-o` an older backup removed first; otherwise the
/// first of `~1`, `~2`, ... that is free). Apple's tree builds the backup
/// from the name in its directory, upstream's from the whole path.
fn backup(uz: &mut Uz, pd: &Dir, fname: &[u8], full: &[u8]) -> i32 {
    let filnamsiz = uz.filename.len();
    let apple = flavour::apple_root(uz.flavour);
    let base: &[u8] = if apple { fname } else { full };
    let blen = m::BACKUP_SUFFIX.len();
    let mut flen = base.len();
    let mut tlen = flen + blen + 6; // includes space for 5 digits
    let mut tname: Vec<u8>;
    if tlen >= filnamsiz {
        // in case name is too long, truncate
        tlen = filnamsiz - 1 - blen;
        tname = base[..base.len().min(tlen)].to_vec();
        if flen > tlen {
            flen = tlen;
        }
        tlen = filnamsiz;
    } else {
        tname = base.to_vec();
    }
    tname.truncate(flen);
    tname.extend_from_slice(m::BACKUP_SUFFIX);

    // the backup's directory and name (upstream's is a whole path)
    let locate = |uz: &Uz, t: &[u8]| -> io::Result<(Dir, Vec<u8>)> {
        if apple {
            Ok((pd.reopen()?, t.to_vec()))
        } else {
            let (root, rel) = mapname::target(uz, t)?;
            root.parent(rel)
        }
    };
    let exists = |uz: &Uz, t: &[u8]| locate(uz, t).is_ok_and(|(d, n)| d.lstat(&n).is_ok());
    // ruling: T10-7 (deviation 4). The backup's name may be the archive
    // being read: it is neither removed (`-oB`) nor renamed over.
    let is_archive = |uz: &Uz, t: &[u8]| {
        locate(uz, t).is_ok_and(|(d, n)| d.lstat(&n).is_ok_and(|st| same_as_archive(uz, &st)))
    };

    if uz.overwrite_mode == OVERWRT_ALWAYS {
        // If there is a previous backup file, delete it, otherwise the
        // following rename operation may fail.
        if is_archive(uz, &tname) {
            cannot_create(uz, full, &archive_busy());
            return 1;
        }
        if let Ok((d, n)) = locate(uz, &tname)
            && d.lstat(&n).is_ok()
        {
            let _ = d.unlink(&n, false);
        }
    } else {
        // Check if backupname exists, and, if it's true, try appending
        // numbers of up to 5 digits to the BackupSuffix, until an unused
        // name is found.
        let maxtail: u32 = match tlen - flen - blen - 1 {
            4 => 9999,
            3 => 999,
            2 => 99,
            1 => 9,
            0 => 0,
            _ => 99999,
        };
        let numtail = flen + blen;
        let mut i = 0u32;
        while i < maxtail && exists(uz, &tname) {
            i += 1;
            tname.truncate(numtail);
            tname.extend_from_slice(i.to_string().as_bytes());
        }
    }

    // (the numbered search can stop at `maxtail` on an existing name)
    if is_archive(uz, &tname) {
        cannot_create(uz, full, &archive_busy());
        return 1;
    }
    let renamed = locate(uz, &tname).and_then(|(d, n)| pd.rename_to(fname, &d, &n));
    if let Err(e) = renamed {
        let shown = mapname::shown(uz, full);
        let err = strerror(uz, &e);
        uz.info_fmt(0x401, m::CANNOT_RENAME_OLD_FILE, &[&shown, &err]);
        return 1;
    }
    0
}

/// What a write of `buf` to the output did: `write(fileno(G.outfile))`,
/// charged to a sandbox's budget first (R7).
fn write_out(uz: &Uz, ex: &mut Ex, buf: &[u8]) -> io::Result<()> {
    uz.host.charge(buf.len() as u64)?;
    match ex.outfile.as_mut() {
        Some(o) => o.file.write_all(buf),
        None => Ok(()),
    }
}

/// `(*G.message)(buf, size, 0)` for `-c`/`-p` data: standard output, through
/// `UzpMessagePrnt`. A failed write is the C's `return PK_OK` (the rest of
/// the entry is not written), except under a sandbox, whose spent budget is
/// a full disk (R7).
fn message_out(uz: &mut Uz, ex: &mut Ex, buf: &[u8]) -> Result<(), i32> {
    match uz.print_data(buf) {
        Ok(()) => Ok(()),
        Err(_) if matches!(uz.host, Host::Sandbox(_)) => Err(disk_error(uz, ex)),
        Err(_) => Err(PK_OK),
    }
}

/// One piece of converted (or raw) output: to the file, or to standard
/// output under `-c`. `Err(code)` is what `flush()` returns at once.
fn emit(uz: &mut Uz, ex: &mut Ex, buf: &[u8]) -> Result<(), i32> {
    if buf.is_empty() {
        return Ok(());
    }
    if uz.o.cflag {
        message_out(uz, ex, buf)
    } else if write_out(uz, ex, buf).is_err() {
        Err(disk_error(uz, ex))
    } else {
        Ok(())
    }
}

// port: fileio.c:flush
/// `flush(rawbuf, size, unshrink)`: the CRC of `rawbuf` taken; unless
/// testing, the bytes written (or shown, `-c`), converted under `-a`/`-aa`:
/// CR LF, a lone CR and a lone LF each become one LF, `^Z` dropped (or, for a
/// VMS variable-length text record file, its records become lines).
/// Returns `PK_OK` or the PK code that stops the decoder (`PK_DISK`).
pub(crate) fn flush(uz: &mut Uz, ex: &mut Ex, rawbuf: &[u8], _unshrink: bool) -> i32 {
    // Compute the CRC first; if testing or if disk is full, that's it.
    ex.crc.update(rawbuf);
    if uz.o.tflag || rawbuf.is_empty() {
        // testing or nothing to write:  all done; a sandbox counts what a
        // test decodes (R7)
        if uz.o.tflag && uz.host.charge(rawbuf.len() as u64).is_err() {
            return disk_error(uz, ex);
        }
        return PK_OK;
    }
    if ex.disk_full != 0 {
        return PK_DISK; // disk already full:  ignore rest of file
    }

    // Write the bytes rawbuf[0..size-1] to the output device, first
    // converting end-of-lines and ASCII/EBCDIC as needed.
    if !ex.pinfo.textmode {
        // write raw binary data
        return match emit(uz, ex, rawbuf) {
            Ok(()) => PK_OK,
            Err(code) => code,
        };
    }

    // textmode:  aflag is true
    if ex.newfile {
        // VMS_TEXT_CONV
        ex.vms_line_state = if ex.pinfo.pinfo.hostnum == super::VMS_
            && ex
                .extra_field
                .as_deref()
                .is_some_and(|ef| super::extra::is_vms_varlen_txt(uz, ef))
        {
            0 // 0: ready to read line length
        } else {
            -1 // -1: don't treat as VMS text
        };
        ex.did_cr_last = false; // no previous buffers written
        ex.newfile = false;
    }

    let mut q: Vec<u8> = Vec::with_capacity(OUTBUFSIZ.min(rawbuf.len() + 1));
    if ex.vms_line_state >= 0 {
        if let Err(code) = vms_text(uz, ex, rawbuf, &mut q) {
            return code;
        }
    } else {
        // Algorithm:  CR/LF => native; lone CR => native; lone LF =>
        // native.
        let mut p = 0usize;
        if rawbuf[0] == LF && ex.did_cr_last {
            p += 1;
        }
        ex.did_cr_last = false;
        while p < rawbuf.len() {
            let c = rawbuf[p];
            if c == CR {
                // lone CR or CR/LF: treat as EOL
                q.push(LF);
                if p == rawbuf.len() - 1 {
                    // last char in buffer
                    ex.did_cr_last = true;
                } else if rawbuf[p + 1] == LF {
                    // get rid of accompanying LF
                    p += 1;
                }
            } else if c == LF {
                // lone LF
                q.push(LF);
            } else if c != CTRLZ {
                // lose all ^Z's
                q.push(c);
            }
            p += 1;
        }
    }
    // Done translating:  write whatever we've got to file (or screen).
    match emit(uz, ex, &q) {
        Ok(()) => PK_OK,
        Err(code) => code,
    }
}

/// flush()'s `VMS_TEXT_CONV` state machine: each record's 16-bit length,
/// its bytes, a newline, and the pad byte of an odd length; written as the
/// output buffer (`OUTBUFSIZ`) fills.
fn vms_text(uz: &mut Uz, ex: &mut Ex, rawbuf: &[u8], q: &mut Vec<u8>) -> Result<(), i32> {
    let size = rawbuf.len();
    let mut p = 0usize;
    while p < size {
        match ex.vms_line_state {
            // 0: ready to read line length
            0 => {
                ex.vms_line_length = 0;
                if p == size - 1 {
                    // last char
                    ex.vms_line_length = u32::from(rawbuf[p]);
                    p += 1;
                    ex.vms_line_state = 1;
                } else {
                    ex.vms_line_length = u32::from(fileio::makeword(&rawbuf[p..]));
                    p += 2;
                    ex.vms_line_state = 2;
                }
                ex.vms_line_pad = ex.vms_line_length & 1 != 0; // odd
            }
            // 1: read one byte of length, need second
            1 => {
                ex.vms_line_length += u32::from(rawbuf[p]) << 8;
                p += 1;
                ex.vms_line_state = 2;
            }
            // 2: ready to read VMS_line_length chars
            2 => {
                let mut remaining = size - p;
                if (ex.vms_line_length as usize) < remaining {
                    remaining = ex.vms_line_length as usize;
                    ex.vms_line_state = 3;
                }
                let outroom = OUTBUFSIZ - q.len();
                if remaining >= outroom {
                    remaining -= outroom;
                    q.extend_from_slice(&rawbuf[p..p + outroom]);
                    p += outroom;
                    emit(uz, ex, q)?;
                    q.clear();
                    // fall through to normal case
                }
                ex.vms_line_length -= remaining as u32;
                q.extend_from_slice(&rawbuf[p..p + remaining]);
                p += remaining;
            }
            // 3: ready to PutNativeEOL
            3 => {
                if q.len() > OUTBUFSIZ - 1 {
                    emit(uz, ex, q)?;
                    q.clear();
                }
                q.push(LF);
                ex.vms_line_state = if ex.vms_line_pad { 4 } else { 0 };
            }
            // 4: ready to read pad byte
            _ => {
                p += 1;
                ex.vms_line_state = 0;
            }
        }
    }
    Ok(())
}

// port: fileio.c:disk_error
/// `disk_error()`: "write error (disk full?).  Continue? (y/n/^C) " and
/// the answer from standard input (`y`: skip the rest of this file and go
/// on; anything else, or no answer to a first question: stop). Returns
/// `PK_DISK`.
pub(crate) fn disk_error(uz: &mut Uz, ex: &mut Ex) -> i32 {
    // OK to use slide[] here because this file is finished regardless
    let name = c_str(&uz.filename).to_vec();
    let shown = fileio::fnfilter1(uz, &name);
    uz.info_fmt(0x4a1, m::DISK_FULL_QUERY, &[&shown]);
    fgets_answer(uz);
    ex.disk_full = if uz.answerbuf[0] == b'y' {
        1 // stop writing to this file (outfile bad?), but new OK
    } else {
        2 // no:  exit program
    };
    PK_DISK
}

/// What `NEXTBYTE` reads: the archive's buffer (`G.inbuf`, `G.incnt`,
/// `G.inptr`) over `G.csize` more bytes of the entry, decrypted as each
/// buffer is read when the entry is encrypted (`readbyte()`).
pub(crate) struct EntrySrc {
    pub(crate) zin: ZipIn,
    /// `G.csize`.
    pub(crate) csize: i64,
    /// The keys, while `G.pInfo->encrypted` (cleared by `decrypt()` for the
    /// header it reads itself).
    pub(crate) keys: Option<Keys>,
    /// A `read()` failed: the C prints "zipfile read error" and exits
    /// (`PK_BADERR`); here the input ends and the caller does that.
    pub(crate) read_error: bool,
}

impl EntrySrc {
    // port: fileio.c:readbyte
    /// `readbyte()`: refill the buffer and return a byte, else `EOF`.
    fn readbyte(&mut self) -> Option<u8> {
        if self.read_error {
            return None;
        }
        if self.csize <= 0 {
            self.csize -= 1; // for tests done after exploding
            self.zin.incnt = 0;
            return None;
        }
        if self.zin.incnt <= 0 {
            let n = self.zin.read_at(0, INBUFSIZ);
            if n == 0 {
                self.zin.incnt = 0;
                return None;
            } else if n < 0 {
                // "fail" (abort, retry, ...) returns this
                self.read_error = true;
                self.zin.incnt = 0;
                return None;
            }
            self.zin.incnt = n;
            // always starts on block bndry
            self.zin.cur_zipfile_bufstart =
                self.zin.cur_zipfile_bufstart.wrapping_add(INBUFSIZ as i64);
            self.zin.inptr = 0;
            defer_leftover_input(&mut self.zin, &mut self.csize); // decrements G.csize
            if let Some(k) = self.keys.as_mut() {
                let (a, b) = (
                    self.zin.inptr,
                    self.zin.inptr + self.zin.incnt.max(0) as usize,
                );
                let b = b.min(self.zin.inbuf.len());
                k.decrypt(&mut self.zin.inbuf[a.min(b)..b]);
            }
        }
        self.zin.incnt -= 1;
        let b = self.zin.inbuf.get(self.zin.inptr).copied().unwrap_or(0);
        self.zin.inptr += 1;
        Some(b)
    }
}

impl EntrySrc {
    // port: fileio.c:fillinbuf
    /// `fillinbuf()` (ubuntu: -DUSE_BZIP2): the next block read into the
    /// buffer, the bytes past the entry hidden, the rest decrypted; the
    /// count left in it, 0 at the end of the file or after a failed
    /// `read()` (which stays in `G.incnt`, unreported: `UZbunzip2()` takes
    /// it as running out of data).
    pub(crate) fn fillinbuf(&mut self) -> i64 {
        let n = self.zin.read_at(0, INBUFSIZ);
        self.zin.incnt = n;
        if n <= 0 {
            return 0;
        }
        // always starts on a block boundary
        self.zin.cur_zipfile_bufstart = self.zin.cur_zipfile_bufstart.wrapping_add(INBUFSIZ as i64);
        self.zin.inptr = 0;
        defer_leftover_input(&mut self.zin, &mut self.csize); // decrements G.csize
        if let Some(k) = self.keys.as_mut() {
            let b = (self.zin.incnt.max(0) as usize).min(self.zin.inbuf.len());
            k.decrypt(&mut self.zin.inbuf[..b]);
        }
        self.zin.incnt
    }
}

impl ByteSource for EntrySrc {
    /// `NEXTBYTE`: `(G.incnt-- > 0 ? *G.inptr++ : readbyte())`.
    fn next_byte(&mut self) -> Option<u8> {
        if self.read_error {
            return None;
        }
        let had = self.zin.incnt;
        self.zin.incnt -= 1;
        if had > 0 {
            let b = self.zin.inbuf.get(self.zin.inptr).copied().unwrap_or(0);
            self.zin.inptr += 1;
            Some(b)
        } else {
            self.readbyte()
        }
    }

    fn remaining(&self) -> u64 {
        (self.csize.max(0) + self.zin.incnt.max(0)) as u64
    }
}

// port: fileio.c:defer_leftover_input
/// `defer_leftover_input()`: hide the buffer's bytes past the entry, so
/// `NEXTBYTE` stops at `G.csize`.
pub(crate) fn defer_leftover_input(zin: &mut ZipIn, csize: &mut i64) {
    if zin.incnt > *csize {
        // (G.csize < MAXINT), we can safely cast it to int !!
        if *csize < 0 {
            *csize = 0;
        }
        zin.inptr_leftover = zin.inptr + *csize as usize;
        zin.incnt_leftover = zin.incnt - *csize;
        zin.incnt = *csize;
    } else {
        zin.incnt_leftover = 0;
    }
    *csize -= zin.incnt;
}

// port: fileio.c:undefer_input
/// `undefer_input()`: give the hidden bytes back (and what the decoder left
/// of the entry).
/// ubuntu: 22-cve-2019-13232-fix-bug-in-undefer-input.patch clamps a
/// negative `G.csize` to 0 first (`flavour::cve_2019_13232_undefer_input`,
/// Task 14).
pub(crate) fn undefer_input(uz: &mut Uz, zin: &mut ZipIn, csize: &mut i64) {
    if flavour::cve_2019_13232_undefer_input(uz.flavour) && *csize < 0 {
        *csize = 0;
    }
    if zin.incnt > 0 {
        *csize += zin.incnt;
    }
    if zin.incnt_leftover > 0 {
        // We know that "(G.csize < MAXINT)" so we can cast G.csize to int
        zin.incnt = zin.incnt_leftover + *csize;
        zin.inptr = (zin.inptr_leftover as i64 - *csize).max(0) as usize;
        zin.incnt_leftover = 0;
    } else if zin.incnt < 0 {
        zin.incnt = 0;
    }
}

/// After a decoder or the header read: a `read()` that failed is the C's
/// `readbyte()` message and `EXIT(PK_BADERR)`, which ends the run here
/// (`uz.abort`).
pub(crate) fn finish_read(uz: &mut Uz, read_error: bool) {
    if read_error {
        uz.print_raw(0x401, m::READ_ERROR.as_bytes());
        uz.abort = Some(super::super::PK_BADERR);
    }
}
