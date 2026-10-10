//! `bzip2recover.c`'s bit streams: `bsGetBit` over a buffered reader and
//! `bsPutBit`/`bsClose` over a buffered writer, most significant bit first.

use std::io::{self, BufWriter, ErrorKind, Read, Write};

/// Bytes fetched from the reader per refill.
const CHUNK: usize = 64 * 1024;

/// `BitStream` in read mode.
pub(super) struct BitIn {
    r: Box<dyn Read>,
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
    byte: u8,
    live: u8,
    eof: bool,
}

impl BitIn {
    pub(super) fn new(r: Box<dyn Read>) -> Self {
        BitIn {
            r,
            buf: vec![0; CHUNK].into_boxed_slice(),
            pos: 0,
            len: 0,
            byte: 0,
            live: 0,
            eof: false,
        }
    }

    /// `bsGetBit`: the next bit, or `None` at end of file. Like `getc`, an
    /// end of file is sticky and a read error is reported.
    pub(super) fn bit(&mut self) -> io::Result<Option<u32>> {
        if self.live == 0 {
            if self.pos == self.len && (self.eof || !self.refill()?) {
                return Ok(None);
            }
            self.byte = self.buf[self.pos];
            self.pos += 1;
            self.live = 8;
        }
        self.live -= 1;
        Ok(Some(u32::from(self.byte >> self.live) & 1))
    }

    fn refill(&mut self) -> io::Result<bool> {
        loop {
            match self.r.read(&mut self.buf) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(false);
                }
                Ok(n) => {
                    self.pos = 0;
                    self.len = n;
                    return Ok(true);
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// `BitStream` in write mode.
pub(super) struct BitOut {
    w: BufWriter<Box<dyn Write>>,
    buffer: u8,
    live: u8,
}

impl BitOut {
    pub(super) fn new(w: Box<dyn Write>) -> Self {
        BitOut {
            w: BufWriter::new(w),
            buffer: 0,
            live: 0,
        }
    }

    /// `bsPutBit`: a full byte is written only when the ninth bit arrives.
    pub(super) fn put_bit(&mut self, bit: u32) -> io::Result<()> {
        if self.live == 8 {
            self.w.write_all(&[self.buffer])?;
            self.live = 1;
            self.buffer = (bit & 1) as u8;
        } else {
            self.buffer = (self.buffer << 1) | (bit & 1) as u8;
            self.live += 1;
        }
        Ok(())
    }

    /// `bsPutUChar`.
    pub(super) fn put_u8(&mut self, c: u8) -> io::Result<()> {
        for i in (0..8).rev() {
            self.put_bit(u32::from(c >> i) & 1)?;
        }
        Ok(())
    }

    /// `bsPutUInt32`.
    pub(super) fn put_u32(&mut self, c: u32) -> io::Result<()> {
        for i in (0..32).rev() {
            self.put_bit((c >> i) & 1)?;
        }
        Ok(())
    }

    /// `bsClose` in write mode: pad the last byte with zero bits, write it,
    /// flush.
    pub(super) fn close(mut self) -> io::Result<()> {
        let pad = 8 - self.live;
        let last = if pad >= 8 { 0 } else { self.buffer << pad };
        self.w.write_all(&[last])?;
        self.w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Shared(Rc<RefCell<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn bits_read_most_significant_first_and_end_stays_ended() {
        let mut b = BitIn::new(Box::new(io::Cursor::new(vec![0b1010_0001])));
        let got: Vec<u32> = (0..8).map(|_| b.bit().unwrap().unwrap()).collect();
        assert_eq!(got, [1, 0, 1, 0, 0, 0, 0, 1]);
        assert_eq!(b.bit().unwrap(), None);
        assert_eq!(b.bit().unwrap(), None);
    }

    #[test]
    fn close_pads_with_zero_bits_and_always_writes_a_final_byte() {
        for (bits, want) in [
            (&[1u32, 1, 1][..], vec![0b1110_0000]),
            (&[1; 8][..], vec![0xff]),
            (&[1; 9][..], vec![0xff, 0x80]),
        ] {
            let v = Rc::new(RefCell::new(Vec::new()));
            let mut o = BitOut::new(Box::new(Shared(v.clone())));
            for &b in bits {
                o.put_bit(b).unwrap();
            }
            o.close().unwrap();
            assert_eq!(*v.borrow(), want);
        }
    }
}
