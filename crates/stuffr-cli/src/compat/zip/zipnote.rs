//! `zipnote`: zipnote.c's `main()` after its arguments. The archive is read
//! as zip reads it (`readzip.rs`, every byte through `Host::track`); the
//! default action writes the entries' comments to standard output in
//! zipnote's format, `-w` reads that format from standard input and writes
//! the archive again with the new comments (and new names, `@=newname`).
//!
//! The new archive is written to a `ziXXXXXX` temporary beside the archive
//! (or in `-b`'s directory), armed for the interrupt handler (INT, TERM,
//! ABRT, BUS, ILL, SEGV: `zipnote error: Interrupted (aborting)`, the
//! temporary removed, exit 9), and renamed over the archive only when it is
//! whole: no input is ever lost. Messages go to standard error (`mesg`;
//! standard output is the listing).
//!
//! `-w` is Ubuntu's (patch 07): Apple's `zipnote -w` closes the input
//! stream `x` twice, the second time closing the temporary's stream, and
//! always ends in exit 10 (`Bad file descriptor`, `Temporary file failure`)
//! with the archive untouched. That is undefined behaviour in the C and is
//! not reproduced: both flavours work (deviation 26).
//!
//! The C's `zgetline()` returns NULL for a line that fills its buffer
//! (`WRBUFSIZ`, 2047 bytes): a longer line
//! reads as the end of the input; the rest of that line is read as the next
//! lines. Reproduced.

use super::cli::{NoteOptions, ZE_OK};
use super::messages::{self as m, printf};
use super::readzip::{self, CFile, InArchive, cstr};
use super::sink::{FileSink, Temp, mkstemp, replace};
use super::split::{self, Prompt};
use super::unix;
use super::write::set_mode;
use super::zipfile::{self, PutError, ZEntry, ZOut};
use super::zipup::{write_failed, zerr};
use super::{Exit, Zr};
use crate::compat::host::{self, Host};

/// ziperr.h codes zipnote raises.
const ZE_BIG: i32 = 6;
const ZE_NOTE: i32 = 7;
const ZE_TEMP: i32 = 10;
const ZE_NAME: i32 = 13;
const ZE_CREAT: i32 = 15;

/// The `MARK` of zipnote's format.
const MARK: u8 = b'@';

/// The size of zipnote.c's line buffer: `WRBUFSIZ` (2047, `FNMAX` being
/// 1024 in both builds; measured on Ubuntu's) plus one.
const LINE_SIZE: usize = 2048;

/// zipnote.c:putclean: `s` to standard output, without control characters
/// that are not a tab or a newline, a backslash before each `@` and
/// backslash, and a newline at the end if the last character written was
/// not one (nothing at all for no text).
// port: zipnote.c:putclean
fn putclean(out: &mut Vec<u8>, s: &[u8]) {
    // if empty, write nothing
    let mut e = b'\n';
    for &c in s {
        if c == MARK || c == b'\\' {
            out.push(b'\\');
        }
        if c >= b' ' || c == b'\t' || c == b'\n' {
            e = c;
            out.push(c);
        }
    }
    if e != b'\n' {
        out.push(b'\n');
    }
}

/// zipnote.c:zgetline: a line of standard input without its newline (and
/// cut at a NUL, as the C's string is); `None` at the end, or when the line
/// fills the buffer without ending.
// port: zipnote.c:zgetline
fn zgetline(p: &Prompt, size: usize) -> Option<Vec<u8>> {
    let mut line = split::fgets_n(p, size)?;
    let len = cstr(&line).len();
    if len > 0 {
        if len == size - 1 && line[len - 1] != b'\n' {
            // buffer is full and record delimiter not seen -> overflow
            return None;
        }
        line.truncate(len);
        // delete trailing record delimiter
        if line[len - 1] == b'\n' {
            line.pop();
        }
    } else {
        line.clear();
    }
    Some(line)
}

/// zipnote.c:catalloc: `s` after `comment`: its backslash escapes removed,
/// and a CR LF between them when `comment` is not empty.
// port: zipnote.c:catalloc
fn catalloc(comment: &mut Vec<u8>, s: &[u8]) {
    let mut t = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' && i + 1 < s.len() {
            i += 1;
        }
        t.push(s[i]);
        i += 1;
    }
    if !comment.is_empty() {
        comment.extend_from_slice(b"\r\n");
    }
    comment.extend_from_slice(&t);
}

/// zipnote.c:main, from the archive's name to the end.
// port: zipnote.c:main
pub(crate) fn run(z: &mut Zr, o: NoteOptions) -> Exit {
    // signal(SIGINT, handler) and the others
    host::install_zip_abort(&z.host, m::NOTE_INTERRUPTED);
    z.set_line(false);
    let zipfile = o.zipfile.clone();
    z.o.zipfile = Some(zipfile.clone());
    z.o.in_path = Some(zipfile.clone());
    z.o.out_path = Some(zipfile.clone());

    // Read zip file
    let mut ar = match readzip::read_archive(z) {
        Ok(ar) => ar,
        Err(x) => return x,
    };
    if ar.zfiles.is_empty() {
        return z.ziperr(ZE_NAME, &zipfile);
    }

    // Put comments to stdout, if not -w
    if !o.write {
        let mut out = Vec::new();
        for zf in &ar.zfiles {
            printf(&mut out, m::NOTE_NAME, &[cstr(&zf.zname)]);
            putclean(&mut out, &zf.e.comment);
            out.extend_from_slice(m::NOTE_END_OF_COMMENT.as_bytes());
        }
        out.extend_from_slice(m::NOTE_ZIP_COMMENT.as_bytes());
        putclean(&mut out, &ar.zcomment);
        z.stdout_write(&out);
        return Exit { code: ZE_OK };
    }

    // If updating comments, make sure zip file is writeable
    let zp = z.host.path(&zipfile);
    if let Err(e) = std::fs::File::options().append(true).create(true).open(&zp) {
        return z.ziperr_os(ZE_CREAT, &zipfile, &e);
    }
    let attr = std::fs::metadata(&zp).map_or(0, |md| unix::meta_of(&md).mode);

    // Process stdin, replacing comments
    let p = split::prompt(z);
    let size = LINE_SIZE;
    let markz = m::NOTE_MARKZ.as_bytes();
    let n = ar.zfiles.len();
    let mut zi = 0usize;
    let mut at_zip_comment = false;
    // while input and not file comment
    while let Some(a) = zgetline(&p, size) {
        if a.first() == Some(&MARK) && &a[1..] == markz {
            at_zip_comment = true;
            break;
        }
        // better be "@ name"
        if a.first() != Some(&MARK) || a.get(1) != Some(&b' ') {
            return z.helper_err(ZE_NOTE, m::UNEXPECTED_INPUT.as_bytes());
        }
        // allow missing entries in order
        while zi < n && a[2..] != *cstr(&ar.zfiles[zi].zname) {
            zi += 1;
        }
        if zi >= n {
            return z.helper_err(ZE_NOTE, m::UNKNOWN_ENTRY_NAME.as_bytes());
        }
        let zf = &mut ar.zfiles[zi];
        let mut a = zgetline(&p, size);
        if let Some(l) = &a
            && l.first() == Some(&MARK)
            && l.get(1) == Some(&b'=')
        {
            // the new name (zipcopy updates the lengths)
            zf.e.iname = l[2..].to_vec();
            a = zgetline(&p, size);
        }
        // change zip entry comment
        let mut comment = Vec::new();
        while let Some(l) = &a
            && l.first() != Some(&MARK)
        {
            catalloc(&mut comment, l);
            a = zgetline(&p, size);
        }
        // `com` is an `ush` in the C: the comment's length wraps at 65536
        // and the first that many bytes are written
        comment.truncate(comment.len() & 0xffff);
        zf.e.comment = comment;
        // point to next entry
        zi += 1;
    }
    if at_zip_comment {
        // change zip file comment
        let mut zcomment = Vec::new();
        while let Some(l) = zgetline(&p, size) {
            catalloc(&mut zcomment, &l);
        }
        // `zcomlen` is an `ush` too
        zcomment.truncate(zcomment.len() & 0xffff);
        ar.zcomment = zcomment;
    }

    // Open output zip file for writing: ziXXXXXX in -b's directory or the
    // archive's
    let dir: Vec<u8> = match &o.tempath {
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
    let (file, armed) = match r {
        Ok(x) => x,
        Err(e) => return z.ziperr_os(ZE_TEMP, &tempzip, &e),
    };
    let mut temp = Temp {
        path: Some(z.host.path(&tempzip)),
    };

    // Open input zip file again, copy preamble if any
    let mut ia = InArchive { f: None };
    match CFile::open(z, &zipfile) {
        Ok(f) => ia.f = Some(f),
        Err(_) => return z.ziperr(ZE_NAME, &zipfile),
    }
    // the archive is read as one disk
    z.current_in_disk = 0;
    let budget = match &z.host {
        Host::Sandbox(s) => Some(s.budget.clone()),
        Host::Real => None,
    };
    let mut out = ZOut::new(Box::new(FileSink::new(file, budget)), z.o.force_zip64, None);
    out.unicode = z.unicode_out();
    if ar.zipbeg != 0
        && let Err(f) = readzip::bfcopy(z, &mut ia, &mut out, ar.zipbeg)
    {
        let h = match &f {
            readzip::CopyFail::Code(ZE_TEMP, _) => tempzip.clone(),
            _ => zipfile.clone(),
        };
        return super::zipcloak::fail_exit(z, f, &h);
    }
    let mut tempzn = ar.zipbeg;

    // Go through local entries, copying them over as is
    // fix = 3: needed for zipcopy if name changed
    z.o.fix = 3;
    for zf in ar.zfiles.iter_mut() {
        if let Err(f) = readzip::zipcopy(z, &mut ia, &mut out, &mut tempzn, zf) {
            return super::zipcloak::fail_exit(z, f, m::WAS_COPYING_AN_ENTRY.as_bytes());
        }
    }
    ia.f = None;

    // Write central directory and end of central directory with new comments
    let mut central: Vec<ZEntry> = ar.zfiles.iter().map(|f| f.e.clone()).collect();
    let mut at = out.w.offset();
    let r = zipfile::write_central_as(
        &mut central,
        &ar.zcomment,
        &mut out,
        &mut at,
        &mut |_, _| {},
        true,
    );
    match r {
        Ok(_) => {}
        Err(PutError::Big { .. }) => return z.ziperr(ZE_BIG, &tempzip),
        Err(PutError::Write(err)) => return write_failed(z, &err),
    }
    // fclose(y)
    if let Err(err) = out.w.flush() {
        return z.ziperr_os(ZE_TEMP, &tempzip, &err);
    }
    drop(out);
    let tmp = temp.path.take().unwrap_or_default();
    if let Err((code, err)) = replace(&z.host.path(&zipfile), &tmp) {
        // the new archive stays, under the temporary name
        z.zipwarn(m::NEW_ZIP_LEFT_AS.as_bytes(), &tempzip);
        return zerr(z, code, m::WAS_REPLACING.as_bytes(), Some(&err));
    }
    drop(armed);
    if attr != 0 {
        set_mode(&zp, attr);
    }
    // Done!
    Exit { code: ZE_OK }
}

#[cfg(test)]
mod tests;
