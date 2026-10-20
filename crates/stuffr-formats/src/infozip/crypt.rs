//! Traditional PKWARE decryption (ZipCrypto), ported from Info-ZIP UnZip
//! 6.0's `crypt.c` (decryption 2.11, Info-ZIP licence; see the parent
//! module). Decryption only: unzip never encrypts, so `zencode` and
//! `crypthead` are not ported.
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
fn crc32(c: u32, b: u8) -> u32 {
    CRC_32_TAB[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8)
}

/// The three keys defining the pseudo-random sequence (`G.keys[0..3]`).
#[derive(Clone)]
pub struct Keys {
    k0: u32,
    k1: u32,
    k2: u32,
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
    // port: crypt.c:zdecode
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

    /// The raw keys, for the tests that pin them against `crypt.c`.
    #[cfg(test)]
    pub(super) fn raw(&self) -> [u32; 3] {
        [self.k0, self.k1, self.k2]
    }
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
