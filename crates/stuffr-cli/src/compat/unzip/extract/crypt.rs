//! crypt.c's `decrypt()` and `testkey()` for one entry: the 12-byte
//! encryption header read, the password tried, and the keys left for the
//! decoder (`stuffr::infozip::crypt`).
//!
//! Without `-P` the password comes from [`get_password`], crypt.c's
//! `G.decr_passwd` (fileio.c's `UzpPassword()`): with no terminal (a
//! sandbox, R7) that is `IZ_PW_ERROR`, the "unable to get password" path.
//! Task 11 gives it the terminal prompt.

use stuffr::infozip::ByteSource;
use stuffr::infozip::crypt::{self, RAND_HEAD_LEN};

use super::super::{PK_COOL, PK_WARN, Uz, flavour};
use super::output::{self, EntrySrc};
use super::{Ex, PK_ERR, PK_MEM2};

/// crypt.h's `IZ_PW_*`: what a password fetch answered.
#[allow(dead_code)]
pub(crate) enum Pw {
    /// `IZ_PW_ENTERED`: a password was typed.
    Entered(Vec<u8>),
    /// `IZ_PW_CANCEL`: skip this entry (the empty password is tried).
    Cancel,
    /// `IZ_PW_CANCELALL`: skip, and ask no more.
    CancelAll,
    /// `IZ_PW_ERROR`: no password can be had.
    Error,
}

/// `(*G.decr_passwd)(&G, rcnt, key, IZ_PWLEN+1, zipfn, filename)`:
/// fileio.c's `UzpPassword()`. `rcnt` is its retry counter.
/// Until Task 11 there is no terminal prompt: `IZ_PW_ERROR`, as `getp()`
/// answers when there is no terminal to read.
pub(crate) fn get_password(_uz: &mut Uz, _rcnt: &mut i32) -> Pw {
    Pw::Error
}

// port: crypt.c:testkey
/// `testkey(h, key)`: the header decrypted with `key` and its last byte
/// checked (P10's mix: the central bit 3 chooses the local DOS time's high
/// byte, else the local CRC's); on a match the entry's bytes already in the
/// buffer are decrypted in place and the keys kept for the rest.
fn testkey(uz: &mut Uz, ex: &mut Ex, h: &[u8; RAND_HEAD_LEN], key: &[u8]) -> bool {
    let check = crypt::check_byte(
        ex.pinfo.ext_loc_hdr,
        uz.lrec.crc32,
        uz.lrec.last_mod_dos_datetime,
    );
    let Some(mut keys) = crypt::test_key(key, h, check) else {
        return false; // bad
    };
    // password OK:  decrypt current buffer contents before leaving
    let n = uz.zin.incnt.min(uz.csize).max(0) as usize;
    let a = uz.zin.inptr.min(uz.zin.inbuf.len());
    let b = (a + n).min(uz.zin.inbuf.len());
    keys.decrypt(&mut uz.zin.inbuf[a..b]);
    ex.keys = Some(keys);
    true // OK
}

// port: crypt.c:decrypt
/// `decrypt(passwrd)`: the entry's encryption header read (`-P`'s password
/// taken once per archive, `G.key` kept across entries), then the password
/// tried; `PK_COOL` with the keys in `ex.keys`, `PK_WARN` for a wrong one,
/// `PK_MEM2` when none can be had.
pub(crate) fn decrypt_entry(uz: &mut Uz, ex: &mut Ex, passwrd: Option<&[u8]>) -> i32 {
    // get header once (turn off "encrypted" flag temporarily so we don't
    // try to decrypt the same data twice)
    let mut src = EntrySrc {
        zin: std::mem::take(&mut uz.zin),
        csize: uz.csize,
        keys: None,
        read_error: false,
    };
    output::defer_leftover_input(&mut src.zin, &mut src.csize);
    let mut h = [0u8; RAND_HEAD_LEN];
    let mut short = false;
    for b in h.iter_mut() {
        // `b = NEXTBYTE; h[n] = (uch)b`: EOF is 0xff
        *b = match src.next_byte() {
            Some(c) => c,
            None => {
                short = true;
                0xff
            }
        };
    }
    output::undefer_input(uz, &mut src.zin, &mut src.csize);
    uz.zin = std::mem::take(&mut src.zin);
    uz.csize = src.csize;
    output::finish_read(uz, src.read_error);
    if uz.abort.is_some() {
        return super::super::PK_BADERR;
    }
    // ubuntu: 14-cve-2015-7696.patch (`flavour::cve_2015_7696_short_header`,
    // Task 14): quit early if compressed size < HEAD_LEN.
    if short && flavour::cve_2015_7696_short_header(uz.flavour) {
        return PK_ERR;
    }

    if uz.newzip {
        // this is first encrypted member in this zipfile
        uz.newzip = false;
        if let Some(p) = passwrd {
            // user gave password on command line
            if uz.key.is_none() {
                uz.key = Some(p.to_vec());
                uz.nopwd = true; // inhibit password prompting!
            }
        } else if uz.key.is_some() {
            // get rid of previous zipfile's key
            uz.key = None;
        }
    }

    // if have key already, test it; else allocate memory for it
    if let Some(key) = uz.key.clone() {
        if testkey(uz, ex, &h, &key) {
            return PK_COOL; // existing password OK (else prompt for new)
        } else if uz.nopwd {
            return PK_WARN; // user indicated no more prompting
        }
    }

    // try a few keys
    let mut n = 0;
    loop {
        let key = match get_password(uz, &mut n) {
            Pw::Error => {
                // internal error in fetch of PW
                uz.key = None;
                return PK_MEM2;
            }
            Pw::Entered(k) => k,
            Pw::Cancel => {
                // user replied "skip": we try the NIL password, and cancel
                // fetch for this item
                n = 0;
                Vec::new()
            }
            Pw::CancelAll => {
                n = 0;
                uz.nopwd = true; // inhibit any further PW prompt!
                Vec::new()
            }
        };
        uz.key = Some(key.clone());
        if testkey(uz, ex, &h, &key) {
            return PK_COOL;
        }
        if n <= 0 {
            break;
        }
    }
    PK_WARN
}
