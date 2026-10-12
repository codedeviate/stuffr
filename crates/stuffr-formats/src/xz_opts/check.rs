//! The `.xz` integrity checks the pure tier computes itself: CRC32
//! (IEEE), CRC64 (ECMA-182) and SHA-256 (FIPS 180-4). `lzma-rust2` keeps
//! its own private, and the workspace takes no new dependency for them.

use super::Check;

/// A table-driven reflected CRC over `POLY`.
const fn crc_table<const N: usize>(poly: u64, bits: u32) -> [u64; N] {
    let mut table = [0u64; N];
    let mut i = 0;
    while i < N {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ poly } else { c >> 1 };
            k += 1;
        }
        table[i] = if bits == 32 { c & 0xFFFF_FFFF } else { c };
        i += 1;
    }
    table
}

static CRC32_TABLE: [u64; 256] = crc_table(0xEDB8_8320, 32);
static CRC64_TABLE: [u64; 256] = crc_table(0xC96C_5795_D787_0F42, 64);

/// `lzma_crc32(buf, size, crc)`: continues `crc` over `data`.
pub(crate) fn crc32(data: &[u8], crc: u32) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = (CRC32_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] as u32) ^ (c >> 8);
    }
    !c
}

/// `lzma_crc64(buf, size, crc)`.
fn crc64(data: &[u8], crc: u64) -> u64 {
    let mut c = !crc;
    for &b in data {
        c = CRC64_TABLE[((c ^ u64::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// SHA-256, streaming.
#[derive(Clone)]
pub(crate) struct Sha256 {
    h: [u32; 8],
    block: [u8; 64],
    used: usize,
    len: u64,
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Sha256 {
    pub(crate) fn new() -> Sha256 {
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            used: 0,
            len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (64 - self.used).min(data.len());
            self.block[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used == 64 {
                let block = self.block;
                self.compress(&block);
                self.used = 0;
            }
        }
    }

    pub(crate) fn finish(mut self) -> [u8; 32] {
        let bits = self.len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.used != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (o, h) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.h) {
            o.copy_from_slice(&h.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in self.h.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *x = x.wrapping_add(y);
        }
    }
}

/// `lzma_check_size`: the bytes a check ID takes in a Block, supported or
/// not (IDs 0..=15; 0, then 4, 8, 16, 32, 64 bytes in threes).
pub(crate) fn check_size(id: u32) -> usize {
    if id == 0 { 0 } else { 4 << ((id - 1) / 3) }
}

/// A running check (`lzma_check_state`) over a Block's uncompressed data.
#[derive(Clone)]
pub(crate) enum Running {
    None,
    Crc32(u32),
    Crc64(u64),
    Sha256(Box<Sha256>),
}

impl Running {
    /// `lzma_check_init`; `None` also for an ID this build does not
    /// support (`lzma_check_is_supported`), which is not verified.
    pub(crate) fn new(id: u32) -> Running {
        match id {
            1 => Running::Crc32(0),
            4 => Running::Crc64(0),
            10 => Running::Sha256(Box::new(Sha256::new())),
            _ => Running::None,
        }
    }

    pub(crate) fn of(check: Check) -> Running {
        Running::new(check.id())
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Running::None => {}
            Running::Crc32(c) => *c = crc32(data, *c),
            Running::Crc64(c) => *c = crc64(data, *c),
            Running::Sha256(s) => s.update(data),
        }
    }

    /// `lzma_check_finish`: the field as a Block stores it (CRCs
    /// little-endian, SHA-256 as is); empty for no or an unknown check.
    pub(crate) fn finish(self) -> Vec<u8> {
        match self {
            Running::None => Vec::new(),
            Running::Crc32(c) => c.to_le_bytes().to_vec(),
            Running::Crc64(c) => c.to_le_bytes().to_vec(),
            Running::Sha256(s) => s.finish().to_vec(),
        }
    }
}

/// `lzma_check_is_supported`.
pub(crate) fn is_supported(id: u32) -> bool {
    matches!(id, 0 | 1 | 4 | 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_are_the_standard_ones() {
        // The CRC "check" values over "123456789".
        assert_eq!(crc32(b"123456789", 0), 0xCBF4_3926);
        assert_eq!(crc64(b"123456789", 0), 0x995D_C9BB_DF19_39FA);
        // Continuation equals one pass.
        assert_eq!(crc32(b"6789", crc32(b"12345", 0)), 0xCBF4_3926);
        let mut s = Sha256::new();
        s.update(b"ab");
        s.update(b"c");
        assert_eq!(
            s.finish(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        let mut long = Sha256::new();
        long.update(&[b'a'; 1_000]);
        let digest = long.finish();
        assert_eq!(&digest[..4], &[0x41, 0xed, 0xec, 0xe4]);
        assert_eq!(
            (0..16).map(check_size).collect::<Vec<_>>(),
            [0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64]
        );
    }
}
