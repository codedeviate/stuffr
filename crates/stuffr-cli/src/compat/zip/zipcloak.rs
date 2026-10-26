//! `zipcloak`: zipcloak.c's `main()` after its arguments, and crypt.c's
//! `zipcloak()` (encrypt an entry) and `zipbare()` (decrypt one), the UTIL
//! build's. The archive is read as zip reads it (`readzip.rs`, every byte
//! through `Host::track`), the new one written to a `ziXXXXXX` temporary
//! beside it (or in `-b`'s directory), armed for the interrupt handler
//! (INT, TERM, ABRT, BUS, ILL, SEGV: the terminal put back, `zipcloak
//! error: Interrupted (aborting)`, the temporary removed, exit 9), and
//! renamed over the archive (or `-O`'s) only when it is whole: no input is
//! ever lost. Messages go to standard output (`mesg` is stdout).
//!
//! The order is zipcloak's: the archive read (a missing one is `Missing or
//! empty zip file`, 13), "nothing to do" (12) before any prompt, the
//! archive opened to append (15), the temporary made (10), and only then
//! the password asked for on the terminal (`stderr is not a tty (you may
//! never see this message!)`, 16, without one), twice to encrypt.
//!
//! Encryption is compatible, not identical: the ten random bytes of each
//! header come from the system (`ttyio::random_header`), as the
//! references' come from `rand()`.
//!
//! Undefined behaviour of the C, not reproduced (deviation 24): crypt.c's
//! `zipcloak()` and `zipbare()` ignore `readlocal()`'s result and go on
//! with an uninitialised local header when it fails (a local header that
//! cannot be found or read); stuffr ends the run with that failure's code
//! (`was encrypting an entry`, `was decrypting an entry`), the temporary
//! removed. A central name longer than the local one makes `readlocal()`
//! write past the local name's buffer; stuffr keeps the local name.

use stuffr::infozip::crypt::{Keys, RAND_HEAD_LEN, crypt_header};

use super::cli::{CloakOptions, ZE_OK, ZE_PARMS};
use super::messages::{self as m, printf};
use super::readzip::{self, CFile, CopyFail, InArchive, ZFile, get_extra_field};
use super::sink::{FileSink, Temp, mkstemp, replace};
use super::unix;
use super::write::set_mode;
use super::zipfile::{self, Bf, LOCHEAD, PutError, ZEntry, ZOut};
use super::zipup::{put_failed, write_failed, zerr};
use super::{Exit, Zr};
use crate::compat::host::{self, Host};

/// ziperr.h codes zipcloak raises.
const ZE_EOF: i32 = 2;
const ZE_BIG: i32 = 6;
const ZE_TEMP: i32 = 10;
const ZE_READ: i32 = 11;
const ZE_NONE: i32 = 12;
const ZE_NAME: i32 = 13;
const ZE_CREAT: i32 = 15;
/// ziperr.h:ZE_MISS, zipbare's "wrong password, copied".
const ZE_MISS: i32 = -1;
/// crypt.c's write buffer.
const BUF: usize = 1024;

/// How an entry's encryption or decryption failed: a `ZE_*` code, a write
/// the archive refused, or a run already ended (its message printed).
type Fail = CopyFail;

/// `ziperr(res, h)` for a failure of the entry loop.
fn fail_exit(z: &mut Zr, f: Fail, h: &[u8]) -> Exit {
    match f {
        CopyFail::Code(code, err) => zerr(z, code, h, err.as_ref()),
        CopyFail::Write(err) => write_failed(z, &err),
        CopyFail::Exit(x) => x,
    }
}

/// `getc()` until `n` bytes or the end: the C's `ferror(in_file) ? ZE_READ
/// : ZE_EOF` when fewer come.
fn read_exact(f: &mut CFile, n: usize) -> Result<Vec<u8>, Fail> {
    let b = f.fread(n);
    if b.len() < n {
        return Err(CopyFail::Code(
            if f.ferror() { ZE_READ } else { ZE_EOF },
            None,
        ));
    }
    Ok(b)
}

/// zipcloak.c:main, from `in_path`/`out_path` to the end.
// port: zipcloak.c:main
pub(crate) fn run(z: &mut Zr, o: CloakOptions) -> Exit {
    // signal(SIGINT, handler) and the others: before the archive is read
    host::install_zip_abort(&z.host, m::CLOAK_INTERRUPTED);
    z.set_line(false);
    let zipfile = o.zipfile.clone();
    let out_path = o.out_path.clone().unwrap_or_else(|| zipfile.clone());
    z.o.zipfile = Some(zipfile.clone());
    z.o.in_path = Some(zipfile.clone());
    z.o.out_path = Some(out_path.clone());

    // Read zip file
    let mut ar = match readzip::read_archive(z) {
        Ok(ar) => ar,
        Err(x) => return x,
    };
    if ar.zfiles.is_empty() {
        return z.ziperr(ZE_NAME, &zipfile);
    }

    // Check for something to do
    let decrypt = o.decrypt;
    if !ar.zfiles.iter().any(|f| (f.e.flg & 1 != 0) == decrypt) {
        let h = if decrypt {
            m::NO_ENCRYPTED_FILES
        } else {
            m::ALL_ENCRYPTED_ALREADY
        };
        return z.ziperr(ZE_NONE, h.as_bytes());
    }

    // Before we get carried away, make sure zip file is writeable
    let zp = z.host.path(&zipfile);
    if let Err(e) = std::fs::File::options().append(true).create(true).open(&zp) {
        return z.ziperr_os(ZE_CREAT, &zipfile, &e);
    }
    let attr = std::fs::metadata(&zp).map_or(0, |md| unix::meta_of(&md).mode);

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
    let (file, _armed) = match r {
        Ok(x) => x,
        Err(e) => return z.ziperr_os(ZE_TEMP, &tempzip, &e),
    };
    let mut temp = Temp {
        path: Some(z.host.path(&tempzip)),
    };

    // Get password
    let Some(passwd) = super::ttyio::getp(z, m::ENTER_PASSWORD.as_bytes()) else {
        return z.ziperr(ZE_PARMS, m::CLOAK_STDERR_NOT_TTY.as_bytes());
    };
    if !decrypt {
        let Some(verify) = super::ttyio::getp(z, m::VERIFY_PASSWORD.as_bytes()) else {
            return z.ziperr(ZE_PARMS, m::CLOAK_STDERR_NOT_TTY.as_bytes());
        };
        if passwd.key() != verify.key() {
            return z.ziperr(ZE_PARMS, m::PASSWORD_VERIFICATION_FAILED.as_bytes());
        }
        if passwd.is_empty_answer() {
            return z.ziperr(ZE_PARMS, m::ZERO_LENGTH_PASSWORD.as_bytes());
        }
    }
    let pw = passwd.key().to_vec();

    // Open input zip file again, copy preamble if any
    let mut ia = InArchive { f: None };
    match CFile::open(z, &zipfile) {
        Ok(f) => ia.f = Some(f),
        Err(_) => return z.ziperr(ZE_NAME, &zipfile),
    }
    // the archive is read as one disk (the UTIL build's readlocal)
    z.current_in_disk = 0;
    let budget = match &z.host {
        Host::Sandbox(s) => Some(s.budget.clone()),
        Host::Real => None,
    };
    let mut out = ZOut::new(Box::new(FileSink::new(file, budget)), z.o.force_zip64, None);
    if ar.zipbeg != 0
        && let Err(f) = readzip::bfcopy(z, &mut ia, &mut out, ar.zipbeg)
    {
        let h = match &f {
            CopyFail::Code(ZE_TEMP, _) => tempzip.clone(),
            _ => zipfile.clone(),
        };
        return fail_exit(z, f, &h);
    }
    let mut tempzn = ar.zipbeg;

    // Go through local entries, copying, encrypting, or decrypting
    for zf in ar.zfiles.iter_mut() {
        if decrypt && zf.e.flg & 1 != 0 {
            let mut l = Vec::new();
            printf(&mut l, m::DECRYPTING, &[&zf.zname]);
            z.stdout_write(&l);
            match zipbare(z, &mut ia, &mut out, &mut tempzn, zf, &pw) {
                Ok(()) => {}
                Err(CopyFail::Code(ZE_MISS, _)) => {
                    z.stdout_write(m::WRONG_PASSWORD_JUST_COPYING.as_bytes());
                }
                Err(f) => return fail_exit(z, f, m::WAS_DECRYPTING.as_bytes()),
            }
            z.stdout_write(b"\n");
        } else if !decrypt && zf.e.flg & 1 == 0 {
            let mut l = Vec::new();
            printf(&mut l, m::ENCRYPTING, &[&zf.zname]);
            z.stdout_write(&l);
            if let Err(f) = zipcloak(z, &mut ia, &mut out, &mut tempzn, zf, &pw) {
                return fail_exit(z, f, m::WAS_ENCRYPTING.as_bytes());
            }
        } else {
            let mut l = Vec::new();
            printf(&mut l, m::CLOAK_COPYING, &[&zf.zname]);
            z.stdout_write(&l);
            if let Err(f) = readzip::zipcopy(z, &mut ia, &mut out, &mut tempzn, zf) {
                return fail_exit(z, f, m::WAS_COPYING_AN_ENTRY.as_bytes());
            }
        }
    }
    ia.f = None;

    // Write central directory and end of central directory
    let mut central: Vec<ZEntry> = ar.zfiles.iter().map(|f| f.e.clone()).collect();
    let mut at = out.w.offset();
    let r = zipfile::write_central(
        &mut central,
        &ar.zcomment,
        &mut out,
        &mut at,
        &mut |_, _| {},
    );
    match r {
        Ok(_) => {}
        Err(PutError::Big { .. }) => return z.ziperr(ZE_BIG, &tempzip),
        Err(PutError::Write(err)) => return write_failed(z, &err),
    }
    // fclose(outzip)
    if let Err(err) = out.w.flush() {
        return z.ziperr_os(ZE_TEMP, &tempzip, &err);
    }
    drop(out);
    let tmp = temp.path.take().unwrap_or_default();
    if let Err((code, err)) = replace(&z.host.path(&out_path), &tmp) {
        // the new archive stays, under the temporary name
        z.zipwarn(m::NEW_ZIP_LEFT_AS.as_bytes(), &tempzip);
        return zerr(z, code, m::WAS_REPLACING.as_bytes(), Some(&err));
    }
    drop(_armed);
    // setfileattr(zipfile, attr): the archive's own name, also under -O
    if attr != 0 {
        set_mode(&zp, attr);
    }
    Exit { code: ZE_OK }
}

/// What `readlocal()` gave crypt.c as `localz`, made a header to write: the
/// local header's own fields, the sizes from the central directory, the
/// local name cut where the central one ends (`iname[z->nam] = '\0'`).
fn local_entry(z: &mut Zr, ia: &mut InArchive, zf: &ZFile) -> Result<ZEntry, Fail> {
    let local = readzip::readlocal(z, ia, zf).map_err(|c| CopyFail::Code(c, None))?;
    let mut iname = local.iname;
    // ruling (deviation 24): only a shorter central name is honoured
    if let Some(b) = iname.get_mut(zf.e.iname.len()) {
        *b = 0;
    }
    let lz = ZEntry {
        name: readzip::cstr(&iname).to_vec(),
        iname,
        // the C's localz->oname is NULL: zipwarn prints `(null)`
        oname: b"(null)".to_vec(),
        vem: zf.e.vem,
        ver: local.ver,
        flg: local.lflg,
        lflg: local.lflg,
        how: local.how,
        tim: local.tim,
        crc: local.crc,
        siz: zf.e.siz,
        len: zf.e.len,
        extra: local.extra,
        ..ZEntry::default()
    };
    Ok(lz)
}

/// `putlocal(localz, PUTLOCAL_WRITE)` and its failure.
fn put(z: &mut Zr, lz: &mut ZEntry, out: &mut ZOut) -> Result<(), Fail> {
    // readlocal's adjust_zip_local_entry
    out.zip64_entry = get_extra_field(0x0001, &lz.extra).is_some();
    match zipfile::putlocal(lz, out) {
        Ok(()) => Ok(()),
        Err(PutError::Write(err)) => Err(CopyFail::Write(err)),
        Err(pe) => Err(CopyFail::Exit(put_failed(z, lz, pe))),
    }
}

/// crypt.c:zipcloak: encrypt entry `zf` from the archive into the new one
/// under `passwd`: its local header again (encrypted, no data descriptor,
/// 12 bytes larger), the header (`crypthead`, the check from the local
/// header's CRC), the data encrypted.
// port: crypt.c:zipcloak
fn zipcloak(
    z: &mut Zr,
    ia: &mut InArchive,
    out: &mut ZOut,
    tempzn: &mut u64,
    zf: &mut ZFile,
    passwd: &[u8],
) -> Result<(), Fail> {
    let n = out.w.offset();
    // read the local header
    let mut lz = local_entry(z, ia, zf)?;
    // update disk and offset
    zf.e.dsk = 0;
    zf.e.off = n;
    // set encryption and unset any extended local header
    zf.e.flg |= 1;
    zf.e.flg &= !8;
    lz.lflg |= 1;
    lz.lflg &= !8;
    // add size of encryption header
    lz.siz = lz.siz.wrapping_add(RAND_HEAD_LEN as u64);
    zf.e.siz = lz.siz;
    put(z, &mut lz, out)?;
    // initialize keys with password and write random header
    let mut keys = Keys::new(passwd);
    let h = crypt_header(
        &mut keys,
        super::ttyio::random_header(),
        (lz.crc >> 16) as u16,
    );
    out.bfwrite(&h, Bf::Data).map_err(CopyFail::Write)?;
    // encrypt data
    let mut left = lz.siz.wrapping_sub(RAND_HEAD_LEN as u64);
    while left > 0 {
        let k = left.min(BUF as u64) as usize;
        let f = ia.f.as_mut().ok_or(CopyFail::Code(ZE_EOF, None))?;
        let mut b = read_exact(f, k)?;
        keys.encrypt(&mut b);
        out.bfwrite(&b, Bf::Data).map_err(CopyFail::Write)?;
        left -= k as u64;
    }
    // since we seek to the start of each local header, any extended local
    // header is not read
    *tempzn = tempzn
        .wrapping_add(4 + LOCHEAD + lz.iname.len() as u64 + lz.extra.len() as u64)
        .wrapping_add(lz.siz);
    Ok(())
}

/// crypt.c:zipbare: decrypt entry `zf` under `passwd`: when the header's
/// last byte is not the check (the CRC's high byte, or the time's under a
/// data descriptor), the entry is copied as it is (`ZE_MISS`, "wrong
/// password--just copying"); else its local header again (not encrypted,
/// no descriptor, 12 bytes smaller) and the data decrypted.
// port: crypt.c:zipbare
fn zipbare(
    z: &mut Zr,
    ia: &mut InArchive,
    out: &mut ZOut,
    tempzn: &mut u64,
    zf: &mut ZFile,
    passwd: &[u8],
) -> Result<(), Fail> {
    // save position
    let n = out.w.offset();
    // read local header
    let mut lz = local_entry(z, ia, zf)?;
    // update disk and offset
    zf.e.dsk = 0;
    zf.e.off = n;
    // initialize keys with password, decrypt the encryption header
    let mut keys = Keys::new(passwd);
    let f = ia.f.as_mut().ok_or(CopyFail::Code(ZE_EOF, None))?;
    let head = read_exact(f, RAND_HEAD_LEN)?;
    let c1 = head.iter().fold(0u8, |_, &c| keys.decrypt_byte(c));
    // the last byte must match the CRC (or the file time under an extended
    // local header): one byte only, as pkzip 2.0
    let check = if zf.e.flg & 8 != 0 {
        ((zf.e.tim & 0xffff) >> 8) as u8
    } else {
        (zf.e.crc >> 24) as u8
    };
    if c1 != check {
        // back up (to the new archive's offset, as the C does) and copy
        if !f.seek(i128::from(n)) {
            return Err(CopyFail::Code(
                if f.ferror() { ZE_READ } else { ZE_EOF },
                None,
            ));
        }
        if let Err(e) = readzip::zipcopy(z, ia, out, tempzn, zf) {
            // ziperr(res, "was copying an entry"), there and then
            return Err(CopyFail::Exit(fail_exit(
                z,
                e,
                m::WAS_COPYING_AN_ENTRY.as_bytes(),
            )));
        }
        return Err(CopyFail::Code(ZE_MISS, None));
    }
    zf.e.siz = zf.e.siz.wrapping_sub(RAND_HEAD_LEN as u64);
    lz.siz = zf.e.siz;
    zf.e.flg &= !9;
    lz.flg = zf.e.flg;
    lz.lflg &= !9;
    zf.e.lflg = lz.lflg;
    put(z, &mut lz, out)?;
    // decrypt data
    let mut left = zf.e.siz;
    while left > 0 {
        let k = left.min(BUF as u64) as usize;
        let f = ia.f.as_mut().ok_or(CopyFail::Code(ZE_EOF, None))?;
        let mut b = read_exact(f, k)?;
        keys.decrypt(&mut b);
        out.bfwrite(&b, Bf::Data).map_err(CopyFail::Write)?;
        left -= k as u64;
    }
    *tempzn = tempzn
        .wrapping_add(4 + LOCHEAD + lz.iname.len() as u64 + lz.extra.len() as u64)
        .wrapping_add(lz.siz);
    Ok(())
}

#[cfg(test)]
mod tests;
