//! A decoder for the old Unix `pack` format (`.z`, magic `1f 1e`).
//!
//! Not a registered codec: it exists so the `stuffr` binary's gzip
//! compatibility personalities can decode what both GNU and Apple `gzip -d`
//! decode. Reached through the doc-hidden `stuffr::pack_stream`.
//!
//! Ported from Apple's `file_cmds-479` `gzip/unpack.c` (originally NetBSD's
//! `unpack.c` 1.3, adapted for FreeBSD):
//!
//! ```text
//! SPDX-License-Identifier: BSD-2-Clause-FreeBSD
//! Copyright (c) 2009 Xin LI <delphij@FreeBSD.org>
//! ```
//!
//! The full BSD-2-Clause notice is in the `stuffr-cli` crate's
//! `LICENSE-gzip-bsd`. Where the C relies on undefined behaviour (an
//! out-of-range leaf index, a read one past the symbol table) this decoder
//! reports `Corrupt` instead of reproducing it.

use std::fmt;
use std::io::{self, Read};

/// Why a pack stream could not be decoded.
#[derive(Debug)]
pub enum PackError {
    /// The first two bytes are not `1f 1e`.
    BadMagic,
    /// Reserved: a header field that is impossible on its face.
    BadHeader(&'static str),
    /// The input ended inside the header, the tables or the bitstream.
    Truncated,
    /// The bytes contradict themselves; the reason names which check failed.
    Corrupt(&'static str),
    /// The underlying reader failed.
    Io(io::Error),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackError::BadMagic => f.write_str("not in pack format"),
            PackError::BadHeader(why) | PackError::Corrupt(why) => f.write_str(why),
            PackError::Truncated => f.write_str("File appears to be truncated"),
            PackError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PackError::Io(e) => Some(e),
            _ => None,
        }
    }
}

const MAX_LEVELS: usize = 24;
const IN_BUF: usize = 8192;

/// Decodes one pack (`.z`, magic 1f 1e) stream: 4-byte big-endian original
/// length, the Huffman level/leaf tables, then the bitstream.
pub struct PackReader<R: Read> {
    inner: R,
    original_len: u32,
    /// Leaf symbols per level (level `i` holds codes of length `i + 1`); the
    /// last level's count includes the EOB leaf.
    leaves: Vec<u32>,
    /// Internal nodes per level, derived from `leaves`.
    inodes: Vec<u32>,
    /// Index of each level's first leaf in `symbols`.
    first: Vec<usize>,
    /// Transmitted symbols; EOB is the virtual entry just past the end.
    symbols: Vec<u8>,
    buf: Box<[u8; IN_BUF]>,
    pos: usize,
    end: usize,
    /// Bits of `buf[pos - 1]` not yet consumed (0 = need a fresh byte).
    bits_left: u32,
    level: usize,
    code: u32,
    produced: u64,
    done: bool,
}

fn eof_is_truncated(e: io::Error) -> PackError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        PackError::Truncated
    } else {
        PackError::Io(e)
    }
}

impl<R: Read> PackReader<R> {
    /// Reads the header and builds the tree.
    pub fn new(mut inner: R) -> Result<Self, PackError> {
        let mut hdr = [0u8; 7];
        inner.read_exact(&mut hdr).map_err(eof_is_truncated)?;
        if hdr[0] != 0x1f || hdr[1] != 0x1e {
            return Err(PackError::BadMagic);
        }
        let original_len = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]);
        let levels = usize::from(hdr[6]);
        if !(1..=MAX_LEVELS).contains(&levels) {
            return Err(PackError::Corrupt("Huffman tree has insane levels"));
        }
        let mut counts = [0u8; MAX_LEVELS];
        inner
            .read_exact(&mut counts[..levels])
            .map_err(eof_is_truncated)?;
        let stored: u32 = counts[..levels].iter().map(|&c| u32::from(c)).sum();
        // `symbol_size` in the C counts EOB too.
        if stored + 1 > 256 {
            return Err(PackError::Corrupt("Bad symbol table"));
        }
        // The last level's stored count is two short of its leaves: one is
        // EOB (not transmitted) and one is the offset pack applies.
        let mut leaves: Vec<u32> = counts[..levels].iter().map(|&c| u32::from(c)).collect();
        leaves[levels - 1] += 2;
        let transmitted = (stored + 1) as usize;
        let mut symbols = vec![0u8; transmitted];
        inner.read_exact(&mut symbols).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                PackError::Corrupt("Symbol table truncated")
            } else {
                PackError::Io(e)
            }
        })?;
        let mut inodes = vec![0u32; levels];
        for l in (0..levels - 1).rev() {
            inodes[l] = (inodes[l + 1] + leaves[l + 1]) / 2;
        }
        let mut first = Vec::with_capacity(levels);
        let mut at = 0usize;
        for &c in &leaves {
            first.push(at);
            at += c as usize;
        }
        Ok(PackReader {
            inner,
            original_len,
            leaves,
            inodes,
            first,
            symbols,
            buf: Box::new([0; IN_BUF]),
            pos: 0,
            end: 0,
            bits_left: 0,
            level: 0,
            code: 0,
            produced: 0,
            done: false,
        })
    }

    /// The decoded length the header promises.
    pub fn original_len(&self) -> u32 {
        self.original_len
    }

    /// The next input bit, or `None` at end of input.
    fn next_bit(&mut self) -> io::Result<Option<u32>> {
        if self.bits_left == 0 {
            if self.pos == self.end {
                loop {
                    match self.inner.read(&mut self.buf[..]) {
                        Ok(0) => return Ok(None),
                        Ok(n) => {
                            self.pos = 0;
                            self.end = n;
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            self.pos += 1;
            self.bits_left = 8;
        }
        self.bits_left -= 1;
        Ok(Some(
            u32::from(self.buf[self.pos - 1] >> self.bits_left) & 1,
        ))
    }

    /// Decodes the next symbol: `Some(Some(byte))`, `Some(None)` for EOB, or
    /// `None` when the input ends between symbols' bits.
    fn next_symbol(&mut self) -> io::Result<Option<Option<u8>>> {
        let last = self.leaves.len() - 1;
        loop {
            let Some(bit) = self.next_bit()? else {
                return Ok(None);
            };
            self.code = (self.code << 1) | bit;
            let l = self.level;
            if self.code >= self.inodes[l] {
                let idx = self.code - self.inodes[l];
                // unpack.c rejects only `idx > leaves`. At `idx == leaves`
                // on a non-last level it reads the next level's first
                // symbol (defined, odd: reproduced, `symbols` is flat). On
                // the last level that is one past the symbol table, which
                // is undefined behaviour in the C, so it stays Corrupt
                // (the "never reproduce UB" rule).
                if idx > self.leaves[l] || (idx == self.leaves[l] && l == last) {
                    return Err(corrupt("File corrupt"));
                }
                let at = self.first[l] + idx as usize;
                self.level = 0;
                self.code = 0;
                return Ok(Some(self.symbols.get(at).copied()));
            }
            self.level += 1;
            if self.level > last {
                return Err(corrupt("File corrupt"));
            }
        }
    }
}

fn corrupt(why: &'static str) -> io::Error {
    io::Error::other(PackError::Corrupt(why))
}

impl<R: Read> Read for PackReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
            return Ok(0);
        }
        let want = u64::from(self.original_len);
        let mut n = 0;
        while n < out.len() {
            match self.next_symbol()? {
                // The bitstream ended. Between symbols with every byte
                // delivered is fine (the C accepts it); otherwise short.
                None => {
                    self.done = true;
                    if self.produced != want {
                        return Err(io::Error::other(PackError::Truncated));
                    }
                    break;
                }
                Some(None) => {
                    self.done = true;
                    if self.produced != want {
                        return Err(corrupt("Premature EOF"));
                    }
                    break;
                }
                Some(Some(b)) => {
                    if self.produced == want {
                        return Err(corrupt("File corrupt"));
                    }
                    out[n] = b;
                    n += 1;
                    self.produced += 1;
                }
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only canonical Huffman encoder writing pack's layout: level `i`
    /// holds codes of length `i + 1`, internal nodes take the smallest codes
    /// of a level and leaves the largest, and EOB is the last leaf.
    fn encode(data: &[u8]) -> Vec<u8> {
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let mut syms: Vec<usize> = (0..256).filter(|&b| freq[b] > 0).collect();
        if syms.is_empty() {
            syms.push(0); // pack needs two leaves; a dummy byte makes them
        }
        // Node weights: symbols then EOB (index syms.len()), weight 0.
        let n = syms.len() + 1;
        let mut weight: Vec<u64> = syms.iter().map(|&b| freq[b]).collect();
        weight.push(0);
        let mut parent = vec![usize::MAX; 2 * n];
        let mut w = weight.clone();
        let mut live: Vec<usize> = (0..n).collect();
        while live.len() > 1 {
            live.sort_by_key(|&i| std::cmp::Reverse((w[i], i)));
            let a = live.pop().unwrap();
            let b = live.pop().unwrap();
            let p = w.len();
            w.push(w[a] + w[b]);
            parent[a] = p;
            parent[b] = p;
            live.push(p);
        }
        let mut len = vec![0usize; n];
        for (i, slot) in len.iter_mut().enumerate() {
            let (mut d, mut c) = (0, i);
            while parent[c] != usize::MAX {
                c = parent[c];
                d += 1;
            }
            *slot = d;
        }
        let maxlen = *len.iter().max().unwrap();
        assert!(maxlen <= 24, "test data too skewed for pack");
        // Order: by length, EOB last within the deepest level, then by byte.
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| (len[i], i == n - 1, i));
        let mut count = vec![0usize; maxlen];
        for &i in &order {
            count[len[i] - 1] += 1;
        }
        // Codes: walk levels, internal nodes first.
        let mut code = vec![0u32; n];
        let mut levels_inodes = vec![0u32; maxlen];
        for l in (0..maxlen - 1).rev() {
            levels_inodes[l] = (levels_inodes[l + 1] + count[l + 1] as u32) / 2;
        }
        let mut idx_in_level = vec![0u32; maxlen];
        for &i in &order {
            let l = len[i] - 1;
            code[i] = levels_inodes[l] + idx_in_level[l];
            idx_in_level[l] += 1;
        }
        let mut out = vec![0x1f, 0x1e];
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.push(maxlen as u8);
        for (l, &c) in count.iter().enumerate() {
            out.push(if l + 1 == maxlen {
                (c - 2) as u8
            } else {
                c as u8
            });
        }
        for &i in &order {
            if i != n - 1 {
                out.push(syms[i] as u8);
            }
        }
        let mut pos = vec![usize::MAX; 256];
        for (k, &b) in syms.iter().enumerate() {
            pos[b] = k;
        }
        let (mut acc, mut nb) = (0u32, 0u32);
        let mut put = |c: u32, l: usize, out: &mut Vec<u8>| {
            for bit in (0..l).rev() {
                acc = (acc << 1) | ((c >> bit) & 1);
                nb += 1;
                if nb == 8 {
                    out.push(acc as u8);
                    acc = 0;
                    nb = 0;
                }
            }
        };
        for &b in data {
            let k = pos[b as usize];
            put(code[k], len[k], &mut out);
        }
        put(code[n - 1], len[n - 1], &mut out);
        if nb > 0 {
            out.push((acc << (8 - nb)) as u8);
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Vec<u8>, PackError> {
        let mut r = PackReader::new(bytes)?;
        let mut out = Vec::new();
        r.read_to_end(&mut out).map_err(|e| {
            match e.into_inner().and_then(|i| i.downcast::<PackError>().ok()) {
                Some(p) => *p,
                None => PackError::Corrupt("io"),
            }
        })?;
        Ok(out)
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn text() -> Vec<u8> {
        let words = [
            "the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog\n",
        ];
        let mut rng = Rng(0x9e3779b97f4a7c15);
        let mut v = Vec::new();
        while v.len() < 100_000 {
            v.extend_from_slice(words[(rng.next() % 8) as usize].as_bytes());
        }
        v
    }

    #[test]
    fn decodes_the_encoders_output() {
        let all: Vec<u8> = (0..=255u8).collect();
        let cases: Vec<Vec<u8>> = vec![vec![], vec![b'a'], all, text()];
        for c in cases {
            let packed = encode(&c);
            let r = PackReader::new(&packed[..]).unwrap();
            assert_eq!(r.original_len() as usize, c.len());
            assert_eq!(decode(&packed).unwrap(), c, "len {}", c.len());
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut p = encode(b"hello world");
        p[1] = 0x1d;
        assert!(matches!(PackReader::new(&p[..]), Err(PackError::BadMagic)));
    }

    #[test]
    fn truncated_header() {
        let p = encode(b"hello world");
        for cut in [0, 1, 5, 6, 7, 8] {
            assert!(
                matches!(PackReader::new(&p[..cut]), Err(PackError::Truncated)),
                "cut {cut}"
            );
        }
    }

    #[test]
    fn truncated_body() {
        let p = encode(&text());
        let cut = &p[..p.len() - 3];
        assert!(matches!(decode(cut), Err(PackError::Truncated)));
    }

    #[test]
    fn tree_deeper_than_24_is_corrupt() {
        let mut p = encode(b"hello world");
        p[6] = 25;
        assert!(matches!(
            PackReader::new(&p[..]),
            Err(PackError::Corrupt(_))
        ));
        p[6] = 0;
        assert!(matches!(
            PackReader::new(&p[..]),
            Err(PackError::Corrupt(_))
        ));
    }

    #[test]
    fn length_mismatch_is_corrupt() {
        let mut p = encode(b"hello world");
        p[5] += 1; // promises one more byte than the stream holds
        assert!(decode(&p).is_err());
        let mut p = encode(b"hello world");
        p[5] -= 1; // EOB arrives with a byte still owed to the length
        assert!(matches!(decode(&p), Err(PackError::Corrupt(_))));
    }

    #[test]
    fn an_index_one_past_a_non_last_level_reads_the_next_levels_symbol() {
        // Levels 3, leaves per level [1, 0, 2]: level 0 has no internal
        // node, so code 1 is index 1 == leaves[0], which unpack.c resolves
        // to the next level's first symbol ('B'). `/usr/bin/gzip -dc` on
        // these exact bytes prints BAAAAAAA.
        let p = b"\x1f\x1e\x00\x00\x00\x08\x03\x01\x00\x00AB\x80";
        assert_eq!(decode(p).unwrap(), b"BAAAAAAA");
    }

    #[test]
    fn fuzzish_bytes_never_panic() {
        let mut rng = Rng(42);
        for _ in 0..10_000 {
            let n = (rng.next() % 300) as usize;
            let mut b: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            if b.len() >= 2 && rng.next() & 3 != 0 {
                b[0] = 0x1f;
                b[1] = 0x1e;
            }
            if b.len() >= 7 && rng.next() & 1 == 0 {
                b[6] = 1 + (rng.next() % 24) as u8;
            }
            let _ = decode(&b);
        }
    }
}
