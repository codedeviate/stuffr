//! The old Unix `pack` format (`1f 1e`) as GNU gzip 1.15 decodes it,
//! written from observation of the binary only (GNU's source is never
//! read). It is stricter than the BSD-derived `stuffr::pack_stream`, which
//! the Apple personality uses: a table Apple accepts may be refused here.
//!
//! What the binary showed, each by `gzip -dc` on hand-built streams:
//!
//! - **Levels:** the level count must be 1 to 25 (0 and 26 are "Huffman
//!   code bit length out of range", before the counts are read).
//! - **The tree:** the last level's stored count is two short (the EOB leaf
//!   and pack's offset). More than 257 leaves in all, or code lengths that
//!   oversubscribe the tree, is "too many leaves"; lengths that leave codes
//!   unused is "too few leaves" (`[1, 0, 0]`, which Apple decodes as
//!   `BAAAAAAA`). Both are checked before the symbols are read.
//! - **The bitstream:** symbols are decoded to EOB whatever the header's
//!   length says, which is checked after ("length error"). A symbol is only
//!   decoded while at least `min(levels, 12)` bits remain from its start
//!   (and its own length, if longer): with one-bit codes and 25 levels,
//!   `n` bytes of bitstream gave `8n - 11` symbols before "unexpected end
//!   of file". The bits after EOB pad its byte; the next byte is the next
//!   member, if any.
//! - Every failure but a short input happens after the header stage (`-v`
//!   prints the name first), and every one ends the run.

use std::io::{self, BufRead, Write};

/// Why a pack stream failed.
#[derive(Debug)]
pub(super) enum PackFault {
    /// The input ended inside the header, the tables or the bitstream.
    Eof,
    /// A level count of 0 or more than 25.
    BitLength,
    /// The code lengths leave codes unused.
    Few,
    /// The code lengths oversubscribe the tree, or there are over 257
    /// leaves.
    Many,
    /// EOB came after a different number of bytes than the header says.
    Length,
    /// Reading the input failed.
    Read(io::Error),
    /// Writing the output failed.
    Write(io::Error),
}

const MAX_LEVELS: usize = 25;
/// The most bits a symbol needs available before it is decoded, whatever
/// its own length.
const PEEK: u32 = 12;
const OUT_CHUNK: usize = 64 * 1024;

/// A bit reader over a `BufRead` that takes whole bytes only when it needs
/// them, so EOB's byte is the last one consumed.
struct Bits<'r, R: BufRead> {
    r: &'r mut R,
    acc: u64,
    n: u32,
}

impl<R: BufRead> Bits<'_, R> {
    fn byte(&mut self) -> Result<Option<u8>, PackFault> {
        loop {
            match self.r.fill_buf() {
                Ok([]) => return Ok(None),
                Ok(b) => {
                    let x = b[0];
                    self.r.consume(1);
                    return Ok(Some(x));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(PackFault::Read(e)),
            }
        }
    }

    /// Make at least `k` bits available, or fail with `Eof`.
    fn need(&mut self, k: u32) -> Result<(), PackFault> {
        while self.n < k {
            match self.byte()? {
                Some(b) => {
                    self.acc = (self.acc << 8) | u64::from(b);
                    self.n += 8;
                }
                None => return Err(PackFault::Eof),
            }
        }
        Ok(())
    }

    fn bit(&mut self) -> Result<u32, PackFault> {
        self.need(1)?;
        self.n -= 1;
        let b = (self.acc >> self.n) & 1;
        self.acc &= (1u64 << self.n) - 1;
        Ok(b as u32)
    }
}

/// Read exactly `buf.len()` bytes, `Eof` if the input ends first.
fn read_exact<R: BufRead>(r: &mut R, buf: &mut [u8]) -> Result<(), PackFault> {
    let mut at = 0;
    while at < buf.len() {
        let avail = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(PackFault::Read(e)),
        };
        if avail.is_empty() {
            return Err(PackFault::Eof);
        }
        let k = avail.len().min(buf.len() - at);
        buf[at..at + k].copy_from_slice(&avail[..k]);
        r.consume(k);
        at += k;
    }
    Ok(())
}

/// Decode one pack member (magic included) from `r` to `out`, writing as
/// it goes; returns the bytes written. Output already written stays
/// written when it fails.
pub(super) fn unpack<R: BufRead>(r: &mut R, out: &mut dyn Write) -> Result<u64, PackFault> {
    let mut head = [0u8; 7];
    read_exact(r, &mut head)?;
    let length = u32::from_be_bytes([head[2], head[3], head[4], head[5]]);
    let levels = usize::from(head[6]);
    if !(1..=MAX_LEVELS).contains(&levels) {
        return Err(PackFault::BitLength);
    }
    let mut counts = [0u8; MAX_LEVELS];
    read_exact(r, &mut counts[..levels])?;
    let mut leaves: Vec<u64> = counts[..levels].iter().map(|&c| u64::from(c)).collect();
    leaves[levels - 1] += 2;
    let total: u64 = leaves.iter().sum();
    // Level `l` holds codes of length `l + 1`; a complete tree's leaves
    // weigh exactly `2^levels` in units of the deepest code.
    let weight: u64 = leaves
        .iter()
        .enumerate()
        .map(|(l, &c)| c << (levels - 1 - l))
        .sum();
    let full = 1u64 << levels;
    if total > 257 || weight > full {
        return Err(PackFault::Many);
    }
    if weight < full {
        return Err(PackFault::Few);
    }
    // EOB is the last leaf and is not transmitted.
    let mut symbols = vec![0u8; (total - 1) as usize];
    read_exact(r, &mut symbols)?;
    // Internal nodes take each level's smallest codes, leaves the rest.
    let mut inodes = vec![0u64; levels];
    for l in (0..levels - 1).rev() {
        inodes[l] = (inodes[l + 1] + leaves[l + 1]) / 2;
    }
    let mut first = Vec::with_capacity(levels);
    let mut at = 0u64;
    for &c in &leaves {
        first.push(at);
        at += c;
    }
    let peek = (levels as u32).min(PEEK);
    let mut bits = Bits { r, acc: 0, n: 0 };
    let mut buf: Vec<u8> = Vec::with_capacity(OUT_CHUNK);
    let mut written = 0u64;
    let flush = |buf: &mut Vec<u8>, out: &mut dyn Write| -> Result<(), PackFault> {
        out.write_all(buf).map_err(PackFault::Write)?;
        buf.clear();
        Ok(())
    };
    loop {
        let symbol = (|| -> Result<Option<u8>, PackFault> {
            bits.need(peek)?;
            let mut code = 0u64;
            for l in 0..levels {
                code = (code << 1) | u64::from(bits.bit()?);
                if code >= inodes[l] {
                    let idx = first[l] + (code - inodes[l]);
                    // A complete tree has no code past its leaves.
                    return Ok(symbols.get(idx as usize).copied());
                }
            }
            // Unreachable for a complete tree; refused as one too few.
            Err(PackFault::Few)
        })();
        match symbol {
            Ok(Some(b)) => {
                buf.push(b);
                written += 1;
                if buf.len() == OUT_CHUNK {
                    flush(&mut buf, out)?;
                }
            }
            Ok(None) => break,
            Err(e) => {
                flush(&mut buf, out)?;
                return Err(e);
            }
        }
    }
    flush(&mut buf, out)?;
    // Compared modulo 2^32, as gzip's ISIZE is.
    if written as u32 != length {
        return Err(PackFault::Length);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(length: u32, counts: &[u8], syms: &[u8], bits: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1f, 0x1e];
        v.extend_from_slice(&length.to_be_bytes());
        v.push(counts.len() as u8);
        v.extend_from_slice(counts);
        v.extend_from_slice(syms);
        v.extend_from_slice(bits);
        v
    }

    fn run(b: &[u8]) -> (Result<u64, PackFault>, Vec<u8>, usize) {
        let mut r = b;
        let mut out = Vec::new();
        let res = unpack(&mut r, &mut out);
        (res, out, r.len())
    }

    /// One level, two leaves: `A` is 0, EOB is 1 (observed: `gzip -dc` on
    /// these bytes with length 8 prints `AAAAAAAA`, exit 0).
    #[test]
    fn decodes_to_eob_and_stops_at_its_byte() {
        let mut b = pk(8, &[0], b"A", &[0x00, 0x80]);
        b.extend_from_slice(b"next");
        let (res, out, left) = run(&b);
        assert_eq!(res.unwrap(), 8);
        assert_eq!(out, b"AAAAAAAA");
        assert_eq!(left, 4);
    }

    /// Observed: the same bytes with length 3 print 8 `A`s, then "length
    /// error".
    #[test]
    fn the_length_is_checked_after_eob() {
        let (res, out, _) = run(&pk(3, &[0], b"A", &[0x00, 0x80]));
        assert!(matches!(res, Err(PackFault::Length)));
        assert_eq!(out.len(), 8);
    }

    /// Each expectation is GNU 1.15's message on the same table.
    #[test]
    fn tables_are_judged_as_the_binary_judges_them() {
        let cases: &[(&[u8], &str)] = &[
            (&[1, 0, 0], "few"), // Apple decodes this one
            (&[0, 0], "few"),
            (&[1, 1], "many"),
            (&[2], "many"),
            (&[0, 0, 0, 0, 0, 0, 0, 0, 255, 1], "many"), // 258 leaves
            (&[0, 0, 0, 0, 0, 0, 0, 254, 2], "many"),    // complete, 258
            (&[0, 0, 0, 0, 0, 0, 0, 255, 0], "eof"),     // complete, 257
        ];
        for (counts, want) in cases {
            let n: usize = counts.iter().map(|&c| usize::from(c)).sum::<usize>() + 1;
            let syms: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let (res, _, _) = run(&pk(1, counts, &syms, &[]));
            let got = match res {
                Err(PackFault::Few) => "few",
                Err(PackFault::Many) => "many",
                Err(PackFault::Eof) => "eof",
                other => panic!("{counts:?}: {other:?}"),
            };
            assert_eq!(got, *want, "{counts:?}");
        }
        for levels in [0usize, 26, 255] {
            let (res, _, _) = run(&pk(1, &vec![0; levels], b"A", &[0]));
            assert!(matches!(res, Err(PackFault::BitLength)), "{levels}");
        }
        // The level count is judged before the counts are read.
        let (res, _, _) = run(b"\x1f\x1e\0\0\0\x01\0");
        assert!(matches!(res, Err(PackFault::BitLength)));
    }

    /// A chain of `levels` levels where `A` is the one-bit code `1`: with
    /// `n` bytes of `ff`, GNU printed `8n - (min(levels, 12) - 1)` `A`s (or
    /// none) before "unexpected end of file".
    #[test]
    fn a_symbol_needs_the_peek_width_available() {
        for (levels, bytes, want) in [
            (25usize, 1usize, 0usize),
            (25, 2, 5),
            (25, 6, 37),
            (8, 1, 1),
            (8, 6, 41),
            (3, 1, 6),
        ] {
            let mut counts = vec![1u8; levels - 1];
            counts.push(0);
            let syms: Vec<u8> = (0..levels as u8).map(|i| b'A' + i).collect();
            let (res, out, _) = run(&pk(1000, &counts, &syms, &vec![0xff; bytes]));
            assert!(matches!(res, Err(PackFault::Eof)), "{levels} {bytes}");
            assert_eq!(out.len(), want, "{levels} {bytes}");
        }
    }

    /// A 13-bit code needs all 13 bits: GNU printed `floor(8n / 13)`.
    #[test]
    fn a_long_code_needs_its_own_length() {
        let levels = 25;
        let mut counts = vec![1u8; levels - 1];
        counts.push(0);
        let syms: Vec<u8> = (0..levels as u8).map(|i| b'A' + i).collect();
        let mut code = vec![0u8; 12];
        code.push(1);
        for bytes in 2..14usize {
            let bitv: Vec<u8> = code.iter().copied().cycle().take(8 * bytes).collect();
            let packed: Vec<u8> = bitv
                .chunks(8)
                .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b))
                .collect();
            let (res, out, _) = run(&pk(1000, &counts, &syms, &packed));
            assert!(matches!(res, Err(PackFault::Eof)));
            assert_eq!(out.len(), 8 * bytes / 13, "{bytes}");
            assert!(out.iter().all(|&b| b == b'M'));
        }
    }
}
