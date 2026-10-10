//! The gzip member layer: RFC 1952 headers, bodies and trailers as typed
//! facts. No messages and no exit codes live here; each personality words a
//! failure its own way.
//!
//! Every entry point that reads takes `&mut Lookahead<R>`, never a plain
//! `BufRead`: a member boundary is `1f 8b`, and only `Lookahead` guarantees
//! both bytes are visible at once whatever the source's read sizes. The
//! guarantee is the type, so forgetting to wrap does not compile. A flavour
//! builds one `Lookahead::new(source)` per input and passes it throughout.

use std::io::{self, BufRead, Read, Write};

/// Longest FNAME/FCOMMENT accepted. A longer one is reported as
/// `Truncated(Header)`; what each reference does with such names is pinned by
/// the differential suites, not decided here.
pub(crate) const MAX_FIELD: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    pub text: bool,
    pub mtime: u32,
    pub xfl: u8,
    pub os: u8,
    pub extra: Option<Vec<u8>>,
    pub name: Option<Vec<u8>>,
    pub comment: Option<Vec<u8>>,
    pub hcrc: bool,
    pub len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Where {
    Header,
    Body,
    Trailer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    BadMagic,
    BadMethod(u8),
    BadFlags(u8),
    BadHeaderCrc,
    Truncated(Where),
    Data,
    Crc { stored: u32, computed: u32 },
    Length { stored: u32, computed: u32 },
}

#[derive(Debug)]
pub(crate) enum MemberError {
    Fault(Fault),
    Io(io::Error),
}

#[derive(Debug, Clone)]
pub(crate) struct MemberInfo {
    pub header: Header,
    pub compressed: u64,
    pub uncompressed: u64,
    pub crc: u32,
    pub isize: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum After {
    End,
    NextMember,
    Trailing { offset: u64, all_zero: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Engine {
    /// flate2 over miniz_oxide: valid deflate, not zlib's bytes.
    Miniz,
    /// C zlib, `deflateInit2(level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY)`:
    /// byte-identical to stock zlib, which is what Apple's gzip links.
    #[cfg(feature = "zlib-c")]
    ZlibC,
}

const CHUNK: usize = 64 * 1024;

const FTEXT: u8 = 1;
const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;

/// Reads bytes, tracking the count and the CRC32 of everything read, and maps
/// EOF to `Truncated(Header)`.
struct HeaderReader<'a> {
    r: &'a mut dyn BufRead,
    crc: flate2::Crc,
    len: u64,
}

impl HeaderReader<'_> {
    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, MemberError> {
        let mut v = vec![0u8; n];
        let mut at = 0;
        while at < n {
            let got = loop {
                match self.r.read(&mut v[at..]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    other => break other.map_err(MemberError::Io)?,
                }
            };
            if got == 0 {
                return Err(MemberError::Fault(Fault::Truncated(Where::Header)));
            }
            at += got;
        }
        self.crc.update(&v);
        self.len += n as u64;
        Ok(v)
    }

    /// A NUL-terminated field, without the NUL. Capped at [`MAX_FIELD`].
    fn cstr(&mut self) -> Result<Vec<u8>, MemberError> {
        let mut out = Vec::new();
        loop {
            let b = self.bytes(1)?[0];
            if b == 0 {
                return Ok(out);
            }
            if out.len() >= MAX_FIELD {
                return Err(MemberError::Fault(Fault::Truncated(Where::Header)));
            }
            out.push(b);
        }
    }
}

/// Read one header from `r`; `Truncated(Header)` at EOF inside it.
pub(crate) fn read_header<R: Read>(r: &mut Lookahead<R>) -> Result<Header, MemberError> {
    let mut hr = HeaderReader {
        r,
        crc: flate2::Crc::new(),
        len: 0,
    };
    let fixed = hr.bytes(10)?;
    if fixed[0] != 0x1f || fixed[1] != 0x8b {
        return Err(MemberError::Fault(Fault::BadMagic));
    }
    if fixed[2] != 8 {
        return Err(MemberError::Fault(Fault::BadMethod(fixed[2])));
    }
    let flg = fixed[3];
    if flg & 0xe0 != 0 {
        return Err(MemberError::Fault(Fault::BadFlags(flg)));
    }
    let mtime = u32::from_le_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
    let extra = if flg & FEXTRA != 0 {
        let l = hr.bytes(2)?;
        let n = usize::from(u16::from_le_bytes([l[0], l[1]]));
        Some(hr.bytes(n)?)
    } else {
        None
    };
    let name = if flg & FNAME != 0 {
        Some(hr.cstr()?)
    } else {
        None
    };
    let comment = if flg & FCOMMENT != 0 {
        Some(hr.cstr()?)
    } else {
        None
    };
    let hcrc = flg & FHCRC != 0;
    if hcrc {
        let computed = (hr.crc.sum() & 0xffff) as u16;
        let stored = hr.bytes(2)?;
        if u16::from_le_bytes([stored[0], stored[1]]) != computed {
            return Err(MemberError::Fault(Fault::BadHeaderCrc));
        }
    }
    Ok(Header {
        text: flg & FTEXT != 0,
        mtime,
        xfl: fixed[8],
        os: fixed[9],
        extra,
        name,
        comment,
        hcrc,
        len: hr.len,
    })
}

/// Inflate one member's body and verify its trailer, writing plain bytes to
/// `out` as they are produced (so partial output exists before an error).
pub(crate) fn inflate_member<R: Read>(
    r: &mut Lookahead<R>,
    header: Header,
    out: &mut dyn Write,
) -> Result<MemberInfo, MemberError> {
    use flate2::{Decompress, FlushDecompress, Status};
    let io_err = MemberError::Io;
    let mut d = Decompress::new(false);
    let mut crc = flate2::Crc::new();
    let mut buf = vec![0u8; CHUNK];
    let mut written = 0u64;
    loop {
        let input = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(e)),
        };
        let eof = input.is_empty();
        let (in0, out0) = (d.total_in(), d.total_out());
        let flush = if eof {
            FlushDecompress::Finish
        } else {
            FlushDecompress::None
        };
        let res = d.decompress(input, &mut buf, flush);
        // Totals advance even when inflate reports an error, so what it
        // produced before failing is still flushed ahead of `Fault::Data`.
        let used = (d.total_in() - in0) as usize;
        let made = (d.total_out() - out0) as usize;
        r.consume(used);
        if made > 0 {
            crc.update(&buf[..made]);
            written += made as u64;
            out.write_all(&buf[..made]).map_err(io_err)?;
        }
        let status = res.map_err(|_| MemberError::Fault(Fault::Data))?;
        match status {
            Status::StreamEnd => break,
            _ if eof && made == 0 => {
                return Err(MemberError::Fault(Fault::Truncated(Where::Body)));
            }
            _ if used == 0 && made == 0 => return Err(MemberError::Fault(Fault::Data)),
            _ => {}
        }
    }
    let body = d.total_in();
    let mut trailer = [0u8; 8];
    let mut at = 0;
    while at < 8 {
        match r.read(&mut trailer[at..]) {
            Ok(0) => return Err(MemberError::Fault(Fault::Truncated(Where::Trailer))),
            Ok(n) => at += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_err(e)),
        }
    }
    let stored_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let stored_len = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    let computed = crc.sum();
    if stored_crc != computed {
        return Err(MemberError::Fault(Fault::Crc {
            stored: stored_crc,
            computed,
        }));
    }
    if stored_len != written as u32 {
        return Err(MemberError::Fault(Fault::Length {
            stored: stored_len,
            computed: written as u32,
        }));
    }
    Ok(MemberInfo {
        compressed: header.len + body + 8,
        header,
        uncompressed: written,
        crc: computed,
        isize: stored_len,
    })
}

/// A `BufRead` over any `Read` whose `fill_buf` yields at least two bytes
/// unless the stream is at EOF, so [`after_member`] can always see a possible
/// `1f 8b` whole whatever the source's read sizes. Callers walking
/// multi-member input wrap their source in this once and use it throughout.
pub(crate) struct Lookahead<R: Read> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    end: usize,
}

impl<R: Read> Lookahead<R> {
    pub(crate) fn new(inner: R) -> Self {
        Lookahead {
            inner,
            buf: vec![0; CHUNK],
            pos: 0,
            end: 0,
        }
    }
}

impl<R: Read> Read for Lookahead<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = {
            let avail = self.fill_buf()?;
            let n = avail.len().min(out.len());
            out[..n].copy_from_slice(&avail[..n]);
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl<R: Read> BufRead for Lookahead<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.end - self.pos < 2 {
            self.buf.copy_within(self.pos..self.end, 0);
            self.end -= self.pos;
            self.pos = 0;
            while self.end < 2 {
                match self.inner.read(&mut self.buf[self.end..]) {
                    Ok(0) => break,
                    Ok(n) => self.end += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(&self.buf[self.pos..self.end])
    }

    fn consume(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.end);
    }
}

/// What follows a member: EOF, another member (peeked `1f 8b`, not consumed),
/// or trailing bytes (consumed to EOF in bounded chunks; `all_zero` if every
/// one is NUL). `offset` is where the trailing bytes start.
///
/// Taking a [`Lookahead`] is what guarantees the two bytes of `1f 8b` are
/// visible together, so a member boundary is never taken for trailing data.
pub(crate) fn after_member<R: Read>(r: &mut Lookahead<R>, offset: u64) -> io::Result<After> {
    let first = loop {
        match r.fill_buf() {
            Ok(b) => break b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    };
    if first.is_empty() {
        return Ok(After::End);
    }
    if first.len() >= 2 && first[0] == 0x1f && first[1] == 0x8b {
        return Ok(After::NextMember);
    }
    let mut all_zero = true;
    loop {
        let b = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if b.is_empty() {
            return Ok(After::Trailing { offset, all_zero });
        }
        all_zero &= b.iter().all(|&x| x == 0);
        let n = b.len();
        r.consume(n);
    }
}

pub(crate) fn write_header(h: &Header, w: &mut dyn Write) -> io::Result<()> {
    let mut flg = 0u8;
    if h.text {
        flg |= FTEXT;
    }
    if h.hcrc {
        flg |= FHCRC;
    }
    if h.extra.is_some() {
        flg |= FEXTRA;
    }
    if h.name.is_some() {
        flg |= FNAME;
    }
    if h.comment.is_some() {
        flg |= FCOMMENT;
    }
    let mut b = vec![0x1f, 0x8b, 8, flg];
    b.extend_from_slice(&h.mtime.to_le_bytes());
    b.extend_from_slice(&[h.xfl, h.os]);
    if let Some(e) = &h.extra {
        let n = u16::try_from(e.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "FEXTRA over 65535 bytes"))?;
        b.extend_from_slice(&n.to_le_bytes());
        b.extend_from_slice(e);
    }
    for s in [&h.name, &h.comment].into_iter().flatten() {
        b.extend_from_slice(s);
        b.push(0);
    }
    if h.hcrc {
        let mut c = flate2::Crc::new();
        c.update(&b);
        b.extend_from_slice(&((c.sum() & 0xffff) as u16).to_le_bytes());
    }
    w.write_all(&b)
}

/// Compress `input` as one member: header `h`, raw deflate at `level` by
/// `engine`, then CRC32 and ISIZE. Returns (crc, uncompressed length).
pub(crate) fn compress_member(
    h: &Header,
    level: u32,
    engine: Engine,
    input: &mut dyn Read,
    out: &mut dyn Write,
) -> io::Result<(u32, u64)> {
    write_header(h, out)?;
    let (crc, total) = match engine {
        Engine::Miniz => deflate_miniz(level, input, out)?,
        #[cfg(feature = "zlib-c")]
        Engine::ZlibC => {
            let mut d = stuffr::zlib_c::RawDeflate::new(&mut *out, level)?;
            let sums = pump(input, &mut |chunk| d.write_all(chunk))?;
            d.finish()?;
            sums
        }
    };
    out.write_all(&crc.to_le_bytes())?;
    out.write_all(&(total as u32).to_le_bytes())?;
    Ok((crc, total))
}

/// Read `input` to EOF in chunks, handing each to `sink` and returning the
/// CRC32 and length of everything read.
fn pump(
    input: &mut dyn Read,
    sink: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<(u32, u64)> {
    let mut crc = flate2::Crc::new();
    let mut total = 0u64;
    let mut inbuf = vec![0u8; CHUNK];
    loop {
        let n = match input.read(&mut inbuf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok((crc.sum(), total));
        }
        crc.update(&inbuf[..n]);
        total += n as u64;
        sink(&inbuf[..n])?;
    }
}

/// Raw deflate through flate2 (miniz_oxide).
fn deflate_miniz(level: u32, input: &mut dyn Read, out: &mut dyn Write) -> io::Result<(u32, u64)> {
    use flate2::{Compress, Compression, FlushCompress, Status};
    let mut c = Compress::new(Compression::new(level), false);
    let mut outbuf = vec![0u8; CHUNK];
    let bad = |e: flate2::CompressError| io::Error::other(e.to_string());
    let sums = pump(input, &mut |mut rest| {
        while !rest.is_empty() {
            let (i0, o0) = (c.total_in(), c.total_out());
            c.compress(rest, &mut outbuf, FlushCompress::None)
                .map_err(bad)?;
            rest = &rest[(c.total_in() - i0) as usize..];
            out.write_all(&outbuf[..(c.total_out() - o0) as usize])?;
        }
        Ok(())
    })?;
    loop {
        let o0 = c.total_out();
        let st = c
            .compress(&[], &mut outbuf, FlushCompress::Finish)
            .map_err(bad)?;
        out.write_all(&outbuf[..(c.total_out() - o0) as usize])?;
        if st == Status::StreamEnd {
            return Ok(sums);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn la(b: &[u8]) -> Lookahead<&[u8]> {
        Lookahead::new(b)
    }

    fn plain(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    fn hdr() -> Header {
        Header {
            text: false,
            mtime: 0,
            xfl: 0,
            os: 3,
            extra: None,
            name: None,
            comment: None,
            hcrc: false,
            len: 0,
        }
    }

    fn member(h: &Header, level: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        compress_member(h, level, Engine::Miniz, &mut &data[..], &mut out).unwrap();
        out
    }

    fn fault(r: Result<MemberInfo, MemberError>) -> Fault {
        match r {
            Err(MemberError::Fault(f)) => f,
            Err(MemberError::Io(e)) => panic!("io error {e}"),
            Ok(_) => panic!("expected a fault"),
        }
    }

    fn inflate(bytes: &[u8]) -> (Result<MemberInfo, MemberError>, Vec<u8>) {
        let mut r = la(bytes);
        let h = read_header(&mut r).expect("header");
        let mut out = Vec::new();
        let res = inflate_member(&mut r, h, &mut out);
        (res, out)
    }

    #[test]
    fn round_trips_every_level() {
        let data = plain(200_000);
        for level in 1..=9 {
            let bytes = member(&hdr(), level, &data);
            let mut dec = Vec::new();
            flate2::read::MultiGzDecoder::new(&bytes[..])
                .read_to_end(&mut dec)
                .unwrap();
            assert_eq!(dec, data, "level {level}");
            let (res, out) = inflate(&bytes);
            let info = res.unwrap_or_else(|_| panic!("level {level}"));
            assert_eq!(out, data);
            assert_eq!(info.uncompressed, data.len() as u64);
            assert_eq!(info.compressed, bytes.len() as u64);
            assert_eq!(info.isize, data.len() as u32);
        }
    }

    #[test]
    fn header_fields_round_trip() {
        let mut cases = Vec::new();
        let mut t = hdr();
        t.text = true;
        cases.push(t);
        let mut e = hdr();
        e.extra = Some(vec![1, 2, 3, 4]);
        cases.push(e);
        let mut n = hdr();
        n.name = Some(b"file.txt".to_vec());
        cases.push(n);
        let mut c = hdr();
        c.comment = Some(b"hello".to_vec());
        cases.push(c);
        let mut f = hdr();
        f.hcrc = true;
        cases.push(f);
        cases.push(Header {
            text: true,
            mtime: 0x1234_5678,
            xfl: 2,
            os: 7,
            extra: Some(vec![9; 300]),
            name: Some(b"a/b.txt".to_vec()),
            comment: Some(b"c".to_vec()),
            hcrc: true,
            len: 0,
        });
        for h in cases {
            let mut buf = Vec::new();
            write_header(&h, &mut buf).unwrap();
            let mut r = la(&buf[..]);
            let got = read_header(&mut r).unwrap();
            assert_eq!(got.len, buf.len() as u64);
            assert!(r.fill_buf().unwrap().is_empty());
            assert_eq!(got, Header { len: got.len, ..h });
        }
    }

    #[test]
    fn bad_method() {
        let mut b = member(&hdr(), 6, b"x");
        b[2] = 7;
        let mut r = la(&b[..]);
        assert!(matches!(
            read_header(&mut r),
            Err(MemberError::Fault(Fault::BadMethod(7)))
        ));
    }

    #[test]
    fn reserved_flag_bits() {
        let mut b = member(&hdr(), 6, b"x");
        b[3] = 0x20;
        let mut r = la(&b[..]);
        assert!(matches!(
            read_header(&mut r),
            Err(MemberError::Fault(Fault::BadFlags(0x20)))
        ));
    }

    #[test]
    fn bad_header_crc() {
        let mut h = hdr();
        h.hcrc = true;
        let mut b = member(&h, 6, b"x");
        b[10] ^= 0xff;
        let mut r = la(&b[..]);
        assert!(matches!(
            read_header(&mut r),
            Err(MemberError::Fault(Fault::BadHeaderCrc))
        ));
    }

    #[test]
    fn truncated_in_header() {
        let mut h = hdr();
        h.name = Some(b"name".to_vec());
        let b = member(&h, 6, b"x");
        for cut in [0, 1, 5, 9, 11, 13] {
            let mut r = la(&b[..cut]);
            assert!(
                matches!(
                    read_header(&mut r),
                    Err(MemberError::Fault(Fault::Truncated(Where::Header)))
                ),
                "cut {cut}"
            );
        }
    }

    #[test]
    fn truncated_in_body() {
        let b = member(&hdr(), 6, &plain(5000));
        let (res, _) = inflate(&b[..b.len() / 2]);
        assert!(matches!(fault(res), Fault::Truncated(Where::Body)));
    }

    #[test]
    fn truncated_in_trailer() {
        let b = member(&hdr(), 6, &plain(5000));
        for cut in 1..=7 {
            let (res, _) = inflate(&b[..b.len() - cut]);
            assert!(
                matches!(fault(res), Fault::Truncated(Where::Trailer)),
                "cut {cut}"
            );
        }
    }

    #[test]
    fn corrupt_body_is_data() {
        let mut b = member(&hdr(), 6, b"hello hello hello");
        b[10] = 0xff; // BTYPE 11 is reserved
        b[11] = 0xff;
        let (res, _) = inflate(&b);
        assert!(matches!(fault(res), Fault::Data));
    }

    #[test]
    fn crc_mismatch_reports_both_values() {
        let data = b"some bytes to check";
        let mut b = member(&hdr(), 6, data);
        let n = b.len();
        let good = flate2::Crc::new();
        let mut c = good;
        c.update(data);
        b[n - 8] ^= 1;
        let (res, _) = inflate(&b);
        match fault(res) {
            Fault::Crc { stored, computed } => {
                assert_eq!(computed, c.sum());
                assert_eq!(stored, c.sum() ^ 1);
            }
            f => panic!("{f:?}"),
        }
    }

    #[test]
    fn length_mismatch_reports_both_values() {
        let data = b"some bytes to check";
        let mut b = member(&hdr(), 6, data);
        let n = b.len();
        b[n - 4] = 99;
        let (res, _) = inflate(&b);
        assert!(matches!(
            fault(res),
            Fault::Length {
                stored: 99,
                computed: 19
            }
        ));
    }

    #[test]
    fn after_member_classifies_eof_next_trailing_and_zeros() {
        assert!(matches!(after_member(&mut la(b""), 5).unwrap(), After::End));
        let mut r = la(&[0x1f, 0x8b, 8]);
        assert!(matches!(
            after_member(&mut r, 5).unwrap(),
            After::NextMember
        ));
        assert_eq!(r.fill_buf().unwrap().len(), 3, "not consumed");
        let mut r = la(&[0u8; 100]);
        match after_member(&mut r, 42).unwrap() {
            After::Trailing { offset, all_zero } => assert!(offset == 42 && all_zero),
            _ => panic!(),
        }
        assert!(r.fill_buf().unwrap().is_empty());
        let mut v = vec![0u8; 200_000];
        v[199_999] = 1;
        match after_member(&mut la(&v), 7).unwrap() {
            After::Trailing { offset, all_zero } => assert!(offset == 7 && !all_zero),
            _ => panic!(),
        }
        match after_member(&mut la(b"junk"), 0).unwrap() {
            After::Trailing { all_zero, .. } => assert!(!all_zero),
            _ => panic!(),
        }
    }

    #[test]
    fn partial_output_precedes_a_crc_error() {
        let data = plain(1000);
        let mut b = member(&hdr(), 6, &data);
        let n = b.len();
        b[n - 8] ^= 0x55;
        let (res, out) = inflate(&b);
        assert!(matches!(fault(res), Fault::Crc { .. }));
        assert_eq!(out, data);
    }

    #[test]
    fn fname_is_bounded() {
        let mut b = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3];
        b.extend(std::iter::repeat_n(b'a', MAX_FIELD + 10));
        let mut r = la(&b[..]);
        assert!(matches!(
            read_header(&mut r),
            Err(MemberError::Fault(Fault::Truncated(Where::Header)))
        ));
        // And a NUL-less name that simply ends is the same fact.
        let mut r = la(&b[..20]);
        assert!(matches!(
            read_header(&mut r),
            Err(MemberError::Fault(Fault::Truncated(Where::Header)))
        ));
    }

    #[test]
    fn multi_member_survives_every_buffer_boundary() {
        struct OneByte<'a>(&'a [u8]);
        impl io::Read for OneByte<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() || b.is_empty() {
                    return Ok(0);
                }
                b[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }
        fn walk<R: io::Read>(r: &mut Lookahead<R>) -> Vec<Vec<u8>> {
            let mut got = Vec::new();
            loop {
                let h = read_header(r).unwrap();
                let mut out = Vec::new();
                assert!(inflate_member(r, h, &mut out).is_ok());
                got.push(out);
                match after_member(r, 0).unwrap() {
                    After::NextMember => {}
                    After::End => return got,
                    After::Trailing { .. } => panic!("member boundary lost"),
                }
            }
        }
        let parts: Vec<Vec<u8>> = (1..=4).map(|i| plain(i * 37)).collect();
        let mut all = Vec::new();
        for p in &parts {
            all.extend(member(&hdr(), 6, p));
        }
        let mut r = Lookahead::new(io::BufReader::with_capacity(1, &all[..]));
        assert_eq!(walk(&mut r), parts);
        let mut r = Lookahead::new(OneByte(&all));
        assert_eq!(walk(&mut r), parts);
        // Split `1f | 8b` exactly at a source read edge, at every boundary:
        // the first read ends on `1f`, the next begins with `8b`.
        struct Split<'a>(&'a [u8], usize);
        impl io::Read for Split<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                let lim = if self.1 > 0 {
                    self.1.min(self.0.len())
                } else {
                    self.0.len()
                };
                let n = lim.min(b.len());
                b[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                self.1 = self.1.saturating_sub(n);
                Ok(n)
            }
        }
        let mut edge = 0;
        for p in &parts[..3] {
            edge += member(&hdr(), 6, p).len();
            let mut r = Lookahead::new(Split(&all, edge + 1));
            assert_eq!(walk(&mut r), parts);
        }
    }

    /// The C engine's member decodes through both the member layer and
    /// flate2, and its body is exactly what `RawDeflate` alone produces.
    #[cfg(feature = "zlib-c")]
    #[test]
    fn zlib_c_engine_round_trips() {
        let data = plain(200_000);
        let mut h = hdr();
        h.name = Some(b"plain.bin".to_vec());
        for level in 1..=9 {
            let mut bytes = Vec::new();
            let (crc, n) =
                compress_member(&h, level, Engine::ZlibC, &mut &data[..], &mut bytes).unwrap();
            assert_eq!(n, data.len() as u64);
            let mut dec = Vec::new();
            flate2::read::MultiGzDecoder::new(&bytes[..])
                .read_to_end(&mut dec)
                .unwrap();
            assert_eq!(dec, data, "level {level}");
            let mut r = la(&bytes);
            let got = read_header(&mut r).unwrap();
            let hlen = got.len as usize;
            let mut out = Vec::new();
            let info = inflate_member(&mut r, got, &mut out).unwrap();
            assert_eq!(out, data);
            assert_eq!(info.crc, crc);
            assert_eq!(info.compressed, bytes.len() as u64);
            let mut raw = stuffr::zlib_c::RawDeflate::new(Vec::new(), level).unwrap();
            raw.write_all(&data).unwrap();
            assert_eq!(
                &bytes[hlen..bytes.len() - 8],
                &raw.finish().unwrap()[..],
                "level {level}"
            );
        }
        // Empty input is a valid member too.
        let mut bytes = Vec::new();
        compress_member(&hdr(), 6, Engine::ZlibC, &mut &b""[..], &mut bytes).unwrap();
        let (res, out) = inflate(&bytes);
        assert!(res.is_ok() && out.is_empty());
    }

    #[test]
    fn partial_output_precedes_a_data_error() {
        use flate2::{Compress, Compression, FlushCompress};
        let data = plain(1000);
        let mut c = Compress::new(Compression::new(6), false);
        let mut body = vec![0u8; 4096];
        c.compress(&data, &mut body, FlushCompress::Sync).unwrap();
        body.truncate(c.total_out() as usize);
        body.push(0x07); // final block, reserved BTYPE 11
        let mut b = Vec::new();
        write_header(&hdr(), &mut b).unwrap();
        b.extend(body);
        let (res, out) = inflate(&b);
        assert!(matches!(fault(res), Fault::Data));
        assert_eq!(out, data);
    }
}
