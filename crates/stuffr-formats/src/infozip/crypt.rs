//! Traditional PKWARE decryption (ZipCrypto), ported from Info-ZIP UnZip
//! 6.0's `crypt.c` (decryption 2.11, Info-ZIP licence; see the parent
//! module), plus the encryption side Zip 3.0's `crypt.c` shares
//! (`zencode`, `crypthead`); unzip itself only decrypts.
//!
//! The C keeps the three keys in unzip's global `G.keys`; here they are a
//! [`Keys`] value per entry. `decrypt()` and `testp()` in `crypt.c` (the
//! password fetch, re-prompt and `-P` handling) belong to the front end,
//! which calls [`test_key`] where they call `testkey()`.

/// crypt.h `RAND_HEAD_LEN`: the encryption header before an entry's data.
pub const RAND_HEAD_LEN: usize = 12;

/// The CRC-32 table `CRC32()` indexes (`CRY_CRC_TAB`, which is
/// `CRC_32_TAB` without `IZ_CRC_BE_OPTIMIZ`): the reflected polynomial
/// `0xedb88320`, one entry per byte value.
// port: crc32.c:make_crc_table
const CRC_32_TAB: [u32; 256] = {
    let mut tab = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 8;
        while k > 0 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k -= 1;
        }
        tab[n] = c;
        n += 1;
    }
    tab
};

/// crc32.h `CRC32(c, b, crctab)`, the little-endian form:
/// `crctab[((int)(c) ^ (b)) & 0xff] ^ ((c) >> 8)`.
pub(super) fn crc32(c: u32, b: u8) -> u32 {
    CRC_32_TAB[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8)
}

/// The three keys defining the pseudo-random sequence (`G.keys[0..3]`).
#[derive(Clone)]
pub struct Keys {
    k0: u32,
    k1: u32,
    k2: u32,
}

/// The keys are the password's whole state (anyone holding them decrypts
/// what it encrypted, and the first ones follow from the password alone), so
/// every copy is zeroed when dropped: volatile stores the optimiser cannot
/// drop as dead, then a fence (hardening, ruling T6 of the 2026-10-31
/// security audit). A copy a move left behind in an old stack slot is not
/// reached; nothing here can reach it.
impl Drop for Keys {
    fn drop(&mut self) {
        for k in [&mut self.k0, &mut self.k1, &mut self.k2] {
            // SAFETY: `k` is a valid, aligned, exclusive `&mut u32`.
            unsafe { std::ptr::write_volatile(k, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Keys {
    /// Keys initialised from `password`, as `init_keys()` does.
    ///
    /// The C takes a NUL-terminated string, so a NUL byte in `password`
    /// ends it there, exactly as it ends the C's loop.
    // port: crypt.c:init_keys
    pub fn new(password: &[u8]) -> Keys {
        let mut keys = Keys {
            k0: 305_419_896,
            k1: 591_751_049,
            k2: 878_082_192,
        };
        for &c in password.iter().take_while(|&&c| c != 0) {
            keys.update_keys(c);
        }
        keys
    }

    /// The next byte of the pseudo-random sequence. (crypt.c's own name for
    /// this is `decrypt_byte`; [`Keys::decrypt_byte`] is `zdecode`.)
    // port: crypt.c:decrypt_byte
    fn stream_byte(&self) -> u8 {
        // `temp * (temp ^ 1)` is at most 0xffff * 0xfffe, inside a u32: the
        // overflow crypt.c's "POTENTIAL BUG" comment names is 16-bit only.
        let temp = (self.k2 & 0xffff) | 2;
        ((temp * (temp ^ 1)) >> 8) as u8
    }

    /// Updates the keys with the next byte of plain text.
    // port: crypt.c:update_keys
    fn update_keys(&mut self, c: u8) {
        self.k0 = crc32(self.k0, c);
        self.k1 = self
            .k1
            .wrapping_add(self.k0 & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        let keyshift = (self.k1 >> 24) as u8;
        self.k2 = crc32(self.k2, keyshift);
    }

    /// Decrypts one byte and advances the keys over its plain text: crypt.h's
    /// `zdecode(c)`, `update_keys(c ^= decrypt_byte())`.
    // port: crypt.h:zdecode
    pub fn decrypt_byte(&mut self, c: u8) -> u8 {
        let plain = c ^ self.stream_byte();
        self.update_keys(plain);
        plain
    }

    /// Decrypts `buf` in place, `zdecode` over each byte in turn.
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        for c in buf {
            *c = self.decrypt_byte(*c);
        }
    }

    /// Encrypts one byte and advances the keys over its plain text:
    /// crypt.h's `zencode(c, t)`, `t = decrypt_byte(), update_keys(c), t ^ c`.
    // port: crypt.h:zencode
    pub fn encrypt_byte(&mut self, c: u8) -> u8 {
        let stream = self.stream_byte();
        self.update_keys(c);
        stream ^ c
    }

    /// Encrypts `buf` in place, `zencode` over each byte in turn (the loop
    /// in `zfwrite` and `zipcloak`).
    // port: crypt.c:zfwrite
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        for c in buf {
            *c = self.encrypt_byte(*c);
        }
    }

    /// The raw keys, for the tests that pin them against `crypt.c`.
    #[cfg(test)]
    pub(super) fn raw(&self) -> [u32; 3] {
        [self.k0, self.k1, self.k2]
    }
}

/// The 12 header bytes Zip 3.0's `crypthead` writes, and `keys` left
/// positioned after them, ready for the entry's data.
///
/// `keys` must be `Keys::new(password)`. `random` stands for the ten raw
/// draws `(rand() >> 7) & 0xff`, BEFORE `crypthead` touches them. The C
/// encrypts them twice: first under the fresh keys while drawing (so the
/// stored draws are `zencode(draw)`), then, after `init_keys` again, each of
/// those is passed through `zencode` a second time. Only that second
/// schedule's keys continue into the data, so `keys` ends after the
/// twelfth byte of the second pass. `check` is `crc >> 16` (low byte first
/// in the header, `crc >> 16 & 0xff` then `crc >> 24`), or the DOS time's
/// when general-purpose bit 3 is set. The caller supplies the draws, so the
/// header is deterministic here; the C's `rand()`/`srand()` seeding is the
/// caller's.
// port: crypt.c:crypthead
pub fn crypt_header(keys: &mut Keys, random: [u8; 10], check: u16) -> [u8; RAND_HEAD_LEN] {
    let password_keys = keys.clone();
    let mut header = [0u8; RAND_HEAD_LEN];
    for (h, &r) in header.iter_mut().zip(&random) {
        *h = keys.encrypt_byte(r);
    }
    *keys = password_keys;
    for h in &mut header[..RAND_HEAD_LEN - 2] {
        *h = keys.encrypt_byte(*h);
    }
    header[RAND_HEAD_LEN - 2] = keys.encrypt_byte((check & 0xff) as u8);
    header[RAND_HEAD_LEN - 1] = keys.encrypt_byte((check >> 8) as u8);
    header
}

/// crypt.c `testkey()`: decrypt the 12-byte header with `password` and
/// compare its last byte with `check` (the CRC's high byte, or the DOS
/// time's high byte when general-purpose bit 3 is set). `Some(keys
/// positioned after the header)` on a match.
///
/// Only the last byte is compared (unzip is built without `ZIP10`), so one
/// wrong password in 256 passes here; unzip finds out at the CRC check, and
/// so does its caller.
///
/// The C's tail, which decrypts the input buffer's remaining contents with
/// the new keys, is the caller's: it is what the returned keys are for.
// port: crypt.c:testkey
pub fn test_key(password: &[u8], header: &[u8; RAND_HEAD_LEN], check: u8) -> Option<Keys> {
    let mut keys = Keys::new(password);
    let mut hh = *header;
    keys.decrypt(&mut hh);
    (hh[RAND_HEAD_LEN - 1] == check).then_some(keys)
}

/// The byte [`test_key`] compares the header's last byte with, from unzip's
/// mixed sources (ruling P10): when the CENTRAL header has general-purpose
/// bit 3 (`G.pInfo->ExtLocHdr`, extract.c:895) the high byte of the local
/// header's DOS time (`G.lrec.last_mod_dos_datetime`'s low 16 bits,
/// process.c:1852), else the high byte of the local CRC (`G.lrec.crc32`,
/// which process.c:1859–1861 replaces with the central one when the LOCAL
/// header has bit 3).
// port: crypt.c:testkey (ternary)
pub fn check_byte(central_bit3: bool, lrec_crc32: u32, lrec_dos_datetime: u32) -> u8 {
    if central_bit3 {
        ((lrec_dos_datetime & 0xffff) >> 8) as u8
    } else {
        (lrec_crc32 >> 24) as u8
    }
}
