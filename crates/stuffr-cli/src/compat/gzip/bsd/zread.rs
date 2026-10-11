//! Apple gzip's `.Z` reader, ported from `file_cmds-479`
//! `gzip/zuncompress.c` (`zread` and `getcode`, NetBSD's `zopen.c`; the
//! Regents of the University of California's BSD-3-Clause notice is in
//! `LICENSE-gzip-bsd`).
//!
//! What `gunzip` shows of it, kept:
//!
//! - a header asking for fewer than 12 or more than 16 bits is refused
//!   (`EFTYPE`), so `compress -b9` output does not decode;
//! - codes are read in groups of `n_bits` bytes, the group rounded down to
//!   whole codes; the last, short group still yields a code from whatever
//!   its buffer held before (so `1f 9d 90 41` decodes to `A`);
//! - a code past the next free entry is `EFTYPE`, and so is the end of the
//!   input inside the header; the end of the input anywhere else is the
//!   end of the data, with no complaint.
//!
//! `gzip.c` reads it through stdio in 64 KiB `fread`s, each one call of
//! [`ZRead::zread`]: a failing call's output is lost (see the caller).

use std::io::{self, Read};

const BITS: u32 = 16;
const BIT_MASK: u8 = 0x1f;
const BLOCK_MASK: u8 = 0x80;
const INIT_BITS: u32 = 9;
const FIRST: i64 = 257;
const CLEAR: i64 = 256;
const RMASK: [u8; 9] = [0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];

fn maxcode(n_bits: u32) -> i64 {
    (1i64 << n_bits) - 1
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Middle,
    Eof,
}

/// `struct s_zstate` with the read parameters, over the input.
pub(super) struct ZRead<'r> {
    fp: &'r mut dyn Read,
    /// `compressed_pre`: the bytes `gzip` read before handing over.
    pre: Vec<u8>,
    pre_at: usize,
    state: State,
    n_bits: u32,
    maxbits: u32,
    maxcode: i64,
    maxmaxcode: i64,
    free_ent: i64,
    block_compress: bool,
    clear_flg: bool,
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    stack: Vec<u8>,
    finchar: u8,
    oldcode: i64,
    incode: i64,
    roffset: i64,
    size: i64,
    /// One past `BITS`: a code ending on the group's last bit reads the
    /// byte after it, masked to nothing (see `getcode`).
    gbuf: [u8; BITS as usize + 1],
    /// `total_compressed_bytes`.
    pub(super) total_compressed: u64,
}

/// `fread(buf, 1, n, fp)` on the input: as many bytes as there are, up to
/// `buf.len()`; an error ends it like the end of the input.
fn fread(fp: &mut dyn Read, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        match fp.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    got
}

impl<'r> ZRead<'r> {
    /// `zdopen`, with `pre` the bytes already read from the input.
    pub(super) fn new(fp: &'r mut dyn Read, pre: &[u8]) -> Self {
        ZRead {
            fp,
            pre: pre.to_vec(),
            pre_at: 0,
            state: State::Start,
            n_bits: 0,
            maxbits: 0,
            maxcode: 0,
            maxmaxcode: 0,
            free_ent: 0,
            block_compress: true,
            clear_flg: false,
            prefix: vec![0; 1 << BITS],
            suffix: vec![0; 1 << BITS],
            stack: Vec::with_capacity(1 << BITS),
            finchar: 0,
            oldcode: -1,
            incode: 0,
            roffset: 0,
            size: 0,
            gbuf: [0; BITS as usize + 1],
            total_compressed: 0,
        }
    }

    fn take_pre(&mut self) -> Option<u8> {
        let b = self.pre.get(self.pre_at).copied()?;
        self.pre_at += 1;
        Some(b)
    }

    /// `zread`: up to `out.len()` bytes; `Err(())` is `-1` with `errno`
    /// `EFTYPE`.
    pub(super) fn zread(&mut self, out: &mut [u8]) -> Result<usize, ()> {
        let num = out.len();
        if num == 0 {
            return Ok(0);
        }
        let mut count = num;
        let mut bp = 0;
        let mut resume = match self.state {
            State::Eof => return Ok(0),
            State::Middle => true,
            State::Start => {
                self.state = State::Middle;
                self.start()?;
                false
            }
        };
        loop {
            if !resume {
                let mut code = self.getcode();
                if code < 0 {
                    break;
                }
                if code == CLEAR && self.block_compress {
                    self.prefix[..256].fill(0);
                    self.clear_flg = true;
                    self.free_ent = FIRST;
                    self.oldcode = -1;
                    continue;
                }
                self.incode = code;
                // The KwKwK case.
                if code >= self.free_ent {
                    if code > self.free_ent || self.oldcode == -1 {
                        return Err(());
                    }
                    self.stack.push(self.finchar);
                    code = self.oldcode;
                }
                // Each step lowers the code (see the module doc of
                // zuncompress.c), so the stack stays under 64 KiB; the
                // check only keeps a broken table from looping.
                while code >= 256 {
                    if self.stack.len() >= 1 << BITS {
                        return Err(());
                    }
                    self.stack.push(self.suffix[code as usize]);
                    code = i64::from(self.prefix[code as usize]);
                }
                self.finchar = self.suffix[code as usize];
                self.stack.push(self.finchar);
            }
            resume = false;
            // Out in forward order; a full `out` keeps the rest for the
            // next call (`middle:`).
            loop {
                if count == 0 {
                    return Ok(num);
                }
                count -= 1;
                out[bp] = self.stack.pop().unwrap_or(0);
                bp += 1;
                if self.stack.is_empty() {
                    break;
                }
            }
            // The new entry.
            let code = self.free_ent;
            if code < self.maxmaxcode && self.oldcode != -1 {
                self.prefix[code as usize] = self.oldcode as u16;
                self.suffix[code as usize] = self.finchar;
                self.free_ent = code + 1;
            }
            self.oldcode = self.incode;
        }
        self.state = State::Eof;
        Ok(num - count)
    }

    /// `zread`'s `S_START` part: the magic, the bit count, the table.
    fn start(&mut self) -> Result<(), ()> {
        let mut header = [0u8; 3];
        let mut i = 0;
        while i < 3 {
            match self.take_pre() {
                Some(b) => header[i] = b,
                None => break,
            }
            i += 1;
        }
        if fread(self.fp, &mut header[i..]) != 3 - i || header[..2] != [0x1f, 0x9d] {
            return Err(());
        }
        self.total_compressed = 0;
        self.block_compress = header[2] & BLOCK_MASK != 0;
        self.maxbits = u32::from(header[2] & BIT_MASK);
        self.maxmaxcode = 1i64 << self.maxbits;
        if self.maxbits > BITS || self.maxbits < 12 {
            return Err(());
        }
        self.n_bits = INIT_BITS;
        self.maxcode = maxcode(INIT_BITS);
        for c in 0..256usize {
            self.prefix[c] = 0;
            self.suffix[c] = c as u8;
        }
        self.free_ent = if self.block_compress { FIRST } else { 256 };
        self.oldcode = -1;
        self.stack.clear();
        Ok(())
    }

    /// `getcode`: the next code, or -1 at the end of the input.
    fn getcode(&mut self) -> i64 {
        if self.clear_flg || self.roffset >= self.size || self.free_ent > self.maxcode {
            // The next entry needs more bits: a new group, read whole.
            if self.free_ent > self.maxcode {
                self.n_bits += 1;
                self.maxcode = if self.n_bits == self.maxbits {
                    self.maxmaxcode
                } else {
                    maxcode(self.n_bits)
                };
            }
            if self.clear_flg {
                self.n_bits = INIT_BITS;
                self.maxcode = maxcode(INIT_BITS);
                self.clear_flg = false;
            }
            let n = self.n_bits as usize;
            let mut i = 0;
            while i < n {
                match self.take_pre() {
                    Some(b) => self.gbuf[i] = b,
                    None => break,
                }
                i += 1;
            }
            let got = fread(self.fp, &mut self.gbuf[i..n]) + i;
            if got == 0 {
                return -1;
            }
            self.roffset = 0;
            self.total_compressed += got as u64;
            // Rounded down to a whole number of codes.
            self.size = ((got as i64) << 3) - (i64::from(self.n_bits) - 1);
        }
        let mut r_off = self.roffset as usize;
        let mut bits = self.n_bits as usize;
        let mut bp = r_off >> 3;
        r_off &= 7;
        let mut gcode = i64::from(self.gbuf[bp] >> r_off);
        bp += 1;
        bits -= 8 - r_off;
        r_off = 8 - r_off;
        if bits >= 8 {
            gcode |= i64::from(self.gbuf[bp]) << r_off;
            bp += 1;
            r_off += 8;
            bits -= 8;
        }
        gcode |= i64::from(self.gbuf[bp] & RMASK[bits]) << r_off;
        self.roffset += i64::from(self.n_bits);
        gcode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(bytes: &[u8]) -> (Vec<u8>, bool) {
        let mut src = bytes;
        let mut z = ZRead::new(&mut src, &[]);
        let mut out = Vec::new();
        loop {
            let mut buf = [0u8; 100];
            match z.zread(&mut buf) {
                Ok(0) => return (out, true),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(()) => return (out, false),
            }
        }
    }

    /// Observed: `/usr/bin/gzip -dc` prints `A` for these four bytes, and
    /// refuses a 9-bit header and a cut-short header.
    #[test]
    fn a_lone_short_group_still_yields_a_code() {
        assert_eq!(all(b"\x1f\x9d\x90\x41"), (b"A".to_vec(), true));
        assert_eq!(all(b"\x1f\x9d\x89\x41\x00"), (Vec::new(), false));
        assert_eq!(all(b"\x1f\x9d"), (Vec::new(), false));
    }

    #[test]
    fn a_code_past_the_next_entry_is_refused() {
        // 9-bit codes: 'a' (0x61), then 0x1ff, far past free_ent (257).
        let codes: [u16; 2] = [0x61, 0x1ff];
        let mut bits = 0u32;
        let mut acc = 0u64;
        let mut v = vec![0x1f, 0x9d, 0x90];
        for c in codes {
            acc |= u64::from(c) << bits;
            bits += 9;
        }
        while bits > 0 {
            v.push(acc as u8);
            acc >>= 8;
            bits = bits.saturating_sub(8);
        }
        // The failing call's `a` is lost with it, as `fread` loses it.
        assert_eq!(all(&v), (Vec::new(), false));
    }
}
