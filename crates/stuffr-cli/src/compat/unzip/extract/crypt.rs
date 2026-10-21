//! crypt.c's `decrypt()` and `testkey()` for one entry: the 12-byte
//! encryption header read, the password tried, and the keys left for the
//! decoder (`stuffr::infozip::crypt`).
//!
//! Without `-P` the password comes from `G.decr_passwd`, fileio.c's
//! `UzpPassword()` ([`fileio::uzp_password`]): the prompt on the
//! controlling terminal, or with none (a sandbox, cron: R7) `IZ_PW_ERROR`,
//! the "unable to get password" path.

use stuffr::infozip::ByteSource;
use stuffr::infozip::crypt::{self, RAND_HEAD_LEN};

use super::super::fileio::{self, Pw};
use super::super::ttyio::Password;
use super::super::{PK_COOL, PK_WARN, Uz, flavour};
use super::output::{self, EntrySrc};
use super::{Ex, PK_ERR, PK_MEM2};

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
    for b in h.iter_mut() {
        // `b = NEXTBYTE; h[n] = (uch)b`: EOF is 0xff
        *b = match src.next_byte() {
            Some(c) => c,
            // ubuntu: 14-cve-2015-7696.patch: quit early if compressed size
            // < HEAD_LEN, before `undefer_input()`: the input is left
            // deferred (`G.incnt` 0, the leftover hidden), as the C leaves
            // it for the next entry.
            None if flavour::cve_2015_7696_short_header(uz.flavour) => {
                uz.zin = std::mem::take(&mut src.zin);
                uz.csize = src.csize;
                output::finish_read(uz, src.read_error);
                if uz.abort.is_some() {
                    return super::super::PK_BADERR;
                }
                return PK_ERR;
            }
            None => 0xff,
        };
    }
    output::undefer_input(uz, &mut src.zin, &mut src.csize);
    uz.zin = std::mem::take(&mut src.zin);
    uz.csize = src.csize;
    output::finish_read(uz, src.read_error);
    if uz.abort.is_some() {
        return super::super::PK_BADERR;
    }

    if uz.newzip {
        // this is first encrypted member in this zipfile
        uz.newzip = false;
        if let Some(p) = passwrd {
            // user gave password on command line
            if uz.key.is_none() {
                uz.key = Some(Password::new(p));
                uz.nopwd = true; // inhibit password prompting!
            }
        } else if uz.key.is_some() {
            // get rid of previous zipfile's key
            uz.key = None;
        }
    }

    // if have key already, test it; else allocate memory for it
    if uz.key.is_some() {
        if testp(uz, ex, &h) {
            return PK_COOL; // existing password OK (else prompt for new)
        } else if uz.nopwd {
            return PK_WARN; // user indicated no more prompting
        }
    }

    // try a few keys
    let mut n = 0;
    loop {
        let r = fileio::uzp_password(uz, &mut n);
        let cancel_all = matches!(r, Pw::CancelAll);
        uz.key = match r {
            Pw::Error => {
                // internal error in fetch of PW
                uz.key = None;
                return PK_MEM2;
            }
            Pw::Entered(k) => Some(k),
            Pw::CancelAll => {
                // user replied "skip all": we try the NIL password, and
                // cancel fetch for this item
                n = 0;
                Some(Password::new(b""))
            }
        };
        if testp(uz, ex, &h) {
            return PK_COOL;
        }
        if cancel_all {
            // User replied "Skip all"
            uz.nopwd = true; // inhibit any further PW prompt!
        }
        if n <= 0 {
            break;
        }
    }
    PK_WARN
}

// port: crypt.c:testp
/// `testp(h)`: `G.key` tested (neither build translates it: no
/// `STR_TO_CP1`/`STR_TO_CP2` on unix).
fn testp(uz: &mut Uz, ex: &mut Ex, h: &[u8; RAND_HEAD_LEN]) -> bool {
    let Some(key) = uz.key.take() else {
        return false;
    };
    let ok = testkey(uz, ex, h, key.key());
    uz.key = Some(key);
    ok
}
