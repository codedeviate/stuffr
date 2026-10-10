//! Format sniffing for the gzip family: which formats each flavour's
//! `gunzip` accepts, recognised by magic, and the decoders for the ones that
//! are not gzip.
//!
//! Each table is the reference's. Apple's comes from `gzip.c`'s
//! `file_gettype` (file_cmds-479, BSD-2-Clause): gzip (`1f 8b`, or the old
//! `1f 9e`), bzip2 (`BZh` and a digit), `.Z` (`1f 9d`), pack (`1f 1e`), xz
//! (`fd 37 7a 58`, four bytes only: the source says "we only have 4 bytes")
//! and lzip (`LZIP`). GNU's is its manual's list (gzip, zip, compress, pack,
//! LZH) checked by running `gzip -dc` on samples; see the ruling on LZH on
//! [`Detected::Lzh`].
//!
//! Every magic is at most four bytes, so [`detect`] takes the [`Lookahead`]
//! the callers already hold, whose `fill_buf` guarantees [`member::PEEK`]
//! bytes unless at EOF: a short peek is then a short input, never a short
//! read.

use std::io::{self, BufRead, Read};

use stuffr::FormatId;
use stuffr::pack_stream::PackReader;

use super::member::{Lookahead, PEEK};

/// Which reference the gzip family follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    /// GNU gzip 1.15, the default outside the BSDs and macOS.
    Gnu,
    /// Apple's gzip (FreeBSD/NetBSD lineage), the default on macOS and the
    /// BSDs.
    Bsd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detected {
    Gzip,
    /// `compress` (`.Z`, `1f 9d`).
    Compress,
    Bzip2,
    Xz,
    Lzip,
    /// The old Unix `pack` (`1f 1e`).
    Pack,
    /// A zip local header (`PK\x03\x04`), GNU only.
    Zip,
    /// GNU's LZH (`1f a0`, `compress -H`/SCO). Never returned: stuffr has no
    /// decoder for it, so it is a documented gap and a `1f a0` input is
    /// `Unknown` (see `foreign_reader`'s callers for the wording).
    Lzh,
    Unknown,
}

/// Classify by magic, peeking without consuming. A format the flavour does
/// not decode (or this build lacks) is `Unknown`.
pub(crate) fn detect<R: Read>(r: &mut Lookahead<R>, flavour: Flavour) -> io::Result<Detected> {
    let buf = r.fill_buf()?;
    let m = &buf[..buf.len().min(PEEK)];
    let d = match flavour {
        Flavour::Gnu => detect_gnu(m),
        Flavour::Bsd => detect_bsd(m),
    };
    Ok(if available(d) { d } else { Detected::Unknown })
}

fn detect_gnu(m: &[u8]) -> Detected {
    match m {
        [0x1f, 0x8b, ..] => Detected::Gzip,
        [b'P', b'K', 3, 4] => Detected::Zip,
        [0x1f, 0x9d, ..] => Detected::Compress,
        [0x1f, 0x1e, ..] => Detected::Pack,
        _ => Detected::Unknown,
    }
}

/// `file_gettype`, in its order.
fn detect_bsd(m: &[u8]) -> Detected {
    match m {
        [0x1f, 0x8b | 0x9e, ..] => Detected::Gzip,
        [b'B', b'Z', b'h', d, ..] if d.is_ascii_digit() => Detected::Bzip2,
        [0x1f, 0x9d, ..] => Detected::Compress,
        [0x1f, 0x1e, ..] => Detected::Pack,
        [0xfd, b'7', b'z', b'X'] => Detected::Xz,
        [b'L', b'Z', b'I', b'P'] => Detected::Lzip,
        _ => Detected::Unknown,
    }
}

/// Whether this build can decode `d`. A codec absent from the registry (the
/// `legacy` tier carries `compress`) makes its format unknown.
fn available(d: Detected) -> bool {
    match codec_id(d) {
        Some(id) => stuffr::registry().codec(FormatId::new(id)).is_some(),
        None => !matches!(d, Detected::Lzh),
    }
}

fn codec_id(d: Detected) -> Option<&'static str> {
    match d {
        Detected::Compress => Some("compress"),
        Detected::Bzip2 => Some("bzip2"),
        Detected::Xz => Some("xz"),
        Detected::Lzip => Some("lzip"),
        _ => None,
    }
}

/// A decoder for a non-gzip format, reading `r` to its end. Errors are
/// `io::Error`s carrying the codec's own error, for the flavour to word.
///
/// `r` is `Send + 'static` because stuffr's codecs own their source.
pub(crate) fn foreign_reader(
    d: Detected,
    r: Box<dyn BufRead + Send>,
) -> io::Result<Box<dyn Read + Send>> {
    if d == Detected::Pack {
        return match PackReader::new(r) {
            Ok(p) => Ok(Box::new(p)),
            Err(e) => Err(io::Error::other(e)),
        };
    }
    let Some(id) = codec_id(d) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a foreign format",
        ));
    };
    let Some(codec) = stuffr::registry().codec(FormatId::new(id)) else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "format not in this build",
        ));
    };
    let src = Box::new(stuffr::StreamOnly::new(r));
    match codec.decoder(src, &stuffr::DecodeOpts::default()) {
        Ok(s) => Ok(Box::new(s)),
        Err(stuffr::Error::Io(e)) => Err(e),
        Err(e) => Err(io::Error::other(e)),
    }
}

/// The first local entry of a zip: what GNU's `gunzip` reads. Method, flags
/// and sizes are exposed raw; which entries GNU accepts or refuses, and how
/// it words that, is decided by the personality.
pub(crate) struct ZipEntry<R> {
    pub method: u16,
    pub flags: u16,
    pub crc: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub name: Vec<u8>,
    reader: R,
}

/// Parse the first local header (signature included) and the name/extra
/// fields, leaving `r` at the start of the entry's data.
pub(crate) fn zip_first_entry<R: BufRead>(mut r: R) -> io::Result<ZipEntry<R>> {
    let mut h = [0u8; 30];
    r.read_exact(&mut h)?;
    if &h[..4] != b"PK\x03\x04" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a zip local header",
        ));
    }
    let u16_at = |i: usize| u16::from_le_bytes([h[i], h[i + 1]]);
    let u32_at = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
    let (flags, method) = (u16_at(6), u16_at(8));
    let (crc, compressed_size, uncompressed_size) = (u32_at(14), u32_at(18), u32_at(22));
    let (nlen, xlen) = (usize::from(u16_at(26)), u64::from(u16_at(28)));
    let mut name = vec![0u8; nlen];
    r.read_exact(&mut name)?;
    let skipped = io::copy(&mut (&mut r).take(xlen), &mut io::sink())?;
    if skipped < xlen {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(ZipEntry {
        method,
        flags,
        crc,
        compressed_size,
        uncompressed_size,
        name,
        reader: r,
    })
}

impl<R: BufRead> ZipEntry<R> {
    /// The entry's data: stored (needs the header's size, so not with a data
    /// descriptor, flag bit 3) or deflated, which stops where the deflate
    /// stream does. Any other method is `Unsupported`.
    pub(crate) fn data(self) -> io::Result<Box<dyn Read>>
    where
        R: 'static,
    {
        match self.method {
            0 if self.flags & 8 == 0 => Ok(Box::new(self.reader.take(self.compressed_size.into()))),
            0 => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "stored entry with a data descriptor",
            )),
            8 => Ok(Box::new(flate2::bufread::DeflateDecoder::new(self.reader))),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "zip method not stored or deflated",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn la(b: &[u8]) -> Lookahead<&[u8]> {
        Lookahead::new(b)
    }

    fn has(id: &'static str) -> bool {
        stuffr::registry().codec(FormatId::new(id)).is_some()
    }

    #[test]
    fn detect_every_magic_per_flavour() {
        use Detected::*;
        let compress = if has("compress") { Compress } else { Unknown };
        let bzip2 = if has("bzip2") { Bzip2 } else { Unknown };
        let xz = if has("xz") { Xz } else { Unknown };
        let lzip = if has("lzip") { Lzip } else { Unknown };
        let table: &[(&[u8], Flavour, Detected)] = &[
            (b"\x1f\x8b\x08\x00", Flavour::Gnu, Gzip),
            (b"PK\x03\x04", Flavour::Gnu, Zip),
            (b"\x1f\x9d\x90\x00", Flavour::Gnu, compress),
            (b"\x1f\x1e\x00\x00", Flavour::Gnu, Pack),
            (b"\x1f\xa0\x00\x00", Flavour::Gnu, Unknown), // LZH gap
            (b"\x1f\x8b\x08\x00", Flavour::Bsd, Gzip),
            (b"\x1f\x9e\x08\x00", Flavour::Bsd, Gzip),
            (b"\x1f\x9d\x90\x00", Flavour::Bsd, compress),
            (b"BZh9", Flavour::Bsd, bzip2),
            (b"\xfd7zXZ\x00", Flavour::Bsd, xz),
            (b"\xfd7zX", Flavour::Bsd, xz),
            (b"\x1f\x1e\x00\x00", Flavour::Bsd, Pack),
            (b"LZIP\x01", Flavour::Bsd, lzip),
        ];
        for (bytes, fl, want) in table {
            assert_eq!(
                detect(&mut la(bytes), *fl).unwrap(),
                *want,
                "{bytes:02x?} {fl:?}"
            );
        }
    }

    #[test]
    fn a_magic_the_flavour_lacks_is_unknown() {
        let cases: &[(&[u8], Flavour)] = &[
            (b"BZh9", Flavour::Gnu),
            (b"\xfd7zXZ\x00", Flavour::Gnu),
            (b"LZIP\x01", Flavour::Gnu),
            (b"PK\x03\x04", Flavour::Bsd),
            (b"\x1f\xa0\x00\x00", Flavour::Bsd),
            (b"BZhx", Flavour::Bsd), // Apple wants a digit after BZh
        ];
        for (bytes, fl) in cases {
            assert_eq!(
                detect(&mut la(bytes), *fl).unwrap(),
                Detected::Unknown,
                "{bytes:02x?} {fl:?}"
            );
        }
    }

    #[test]
    fn detect_does_not_consume() {
        let mut r = la(b"\x1f\x8b\x08\x00rest");
        detect(&mut r, Flavour::Gnu).unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"\x1f\x8b\x08\x00rest");
    }

    #[test]
    fn detect_sees_a_whole_magic_through_tiny_reads() {
        struct OneByte<'a>(&'a [u8]);
        impl Read for OneByte<'_> {
            fn read(&mut self, o: &mut [u8]) -> io::Result<usize> {
                let n = self.0.len().min(1).min(o.len());
                o[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let mut r = Lookahead::new(OneByte(b"PK\x03\x04xxxx"));
        assert_eq!(detect(&mut r, Flavour::Gnu).unwrap(), Detected::Zip);
        let mut r = Lookahead::new(OneByte(b"LZIP\x01"));
        let want = if has("lzip") {
            Detected::Lzip
        } else {
            Detected::Unknown
        };
        assert_eq!(detect(&mut r, Flavour::Bsd).unwrap(), want);
    }

    #[test]
    fn two_byte_and_empty_inputs() {
        for fl in [Flavour::Gnu, Flavour::Bsd] {
            assert_eq!(detect(&mut la(b""), fl).unwrap(), Detected::Unknown);
            assert_eq!(detect(&mut la(b"\x1f"), fl).unwrap(), Detected::Unknown);
            assert_eq!(detect(&mut la(b"\x1f\x8b"), fl).unwrap(), Detected::Gzip);
            assert_eq!(detect(&mut la(b"\x1f\x1e"), fl).unwrap(), Detected::Pack);
            assert_eq!(detect(&mut la(b"PK"), fl).unwrap(), Detected::Unknown);
        }
    }

    fn encode(id: &'static str, data: &[u8]) -> Vec<u8> {
        use std::sync::{Arc, Mutex};
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let out = Arc::new(Mutex::new(Vec::new()));
        let codec = stuffr::registry().codec(FormatId::new(id)).unwrap();
        let mut enc = codec
            .encoder(
                Box::new(Shared(out.clone())),
                &stuffr::EncodeOpts::default(),
            )
            .unwrap();
        enc.write_all(data).unwrap();
        enc.finish().unwrap();
        out.lock().unwrap().clone()
    }

    fn sample() -> Vec<u8> {
        (0..5000u32)
            .flat_map(|i| format!("line {i} of the sample\n").into_bytes())
            .collect()
    }

    #[test]
    fn foreign_reader_round_trips() {
        let data = sample();
        let mut cases: Vec<(Detected, Flavour, &str)> = vec![
            (Detected::Bzip2, Flavour::Bsd, "bzip2"),
            (Detected::Xz, Flavour::Bsd, "xz"),
            (Detected::Lzip, Flavour::Bsd, "lzip"),
        ];
        // `.Z` is decode-only in some builds; encode it when we can.
        if has("compress")
            && stuffr::registry()
                .codec(FormatId::new("compress"))
                .unwrap()
                .caps()
                .encode
        {
            cases.push((Detected::Compress, Flavour::Gnu, "compress"));
        }
        for (d, fl, id) in cases {
            if !has(id) {
                continue;
            }
            let packed = encode(id, &data);
            let mut r = Lookahead::new(io::Cursor::new(packed));
            assert_eq!(detect(&mut r, fl).unwrap(), d, "{id}");
            let mut out = Vec::new();
            foreign_reader(d, Box::new(r))
                .unwrap()
                .read_to_end(&mut out)
                .unwrap();
            assert_eq!(out, data, "{id}");
        }
    }

    #[test]
    fn foreign_reader_decodes_pack() {
        // `/usr/bin/gzip -dc` prints BAAAAAAA for these exact bytes.
        let p = b"\x1f\x1e\x00\x00\x00\x08\x03\x01\x00\x00AB\x80".to_vec();
        let mut r = Lookahead::new(io::Cursor::new(p));
        assert_eq!(detect(&mut r, Flavour::Gnu).unwrap(), Detected::Pack);
        let mut out = Vec::new();
        foreign_reader(Detected::Pack, Box::new(r))
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"BAAAAAAA");
    }

    #[test]
    fn foreign_reader_refuses_what_is_not_foreign() {
        for d in [
            Detected::Gzip,
            Detected::Zip,
            Detected::Lzh,
            Detected::Unknown,
        ] {
            assert!(foreign_reader(d, Box::new(io::Cursor::new(Vec::new()))).is_err());
        }
    }

    fn zip_entry(method: u16, flags: u16, data: &[u8], csize: u32, name: &[u8]) -> Vec<u8> {
        let mut z = b"PK\x03\x04".to_vec();
        z.extend(20u16.to_le_bytes());
        z.extend(flags.to_le_bytes());
        z.extend(method.to_le_bytes());
        z.extend([0u8; 4]); // time, date
        z.extend(0xdeadbeefu32.to_le_bytes());
        z.extend(csize.to_le_bytes());
        z.extend(7u32.to_le_bytes());
        z.extend((name.len() as u16).to_le_bytes());
        z.extend(2u16.to_le_bytes());
        z.extend(name);
        z.extend([0xaa, 0xbb]); // extra
        z.extend(data);
        z.extend(b"PK\x01\x02trailing central directory");
        z
    }

    #[test]
    fn zip_first_entry_stored_and_deflated() {
        let z = zip_entry(0, 0, b"payload", 7, b"a.txt");
        let e = zip_first_entry(io::Cursor::new(z)).unwrap();
        assert_eq!(
            (e.method, e.flags, e.crc, e.compressed_size),
            (0, 0, 0xdeadbeef, 7)
        );
        assert_eq!(e.name, b"a.txt");
        let mut out = Vec::new();
        e.data().unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out, b"payload");

        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"deflated payload").unwrap();
        let d = enc.finish().unwrap();
        let z = zip_entry(8, 0, &d, d.len() as u32, b"b");
        let e = zip_first_entry(io::Cursor::new(z)).unwrap();
        assert_eq!(e.method, 8);
        let mut out = Vec::new();
        e.data().unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out, b"deflated payload");
    }

    #[test]
    fn zip_first_entry_reports_other_methods_and_truncation() {
        let z = zip_entry(12, 1, b"x", 1, b"c");
        let e = zip_first_entry(io::Cursor::new(z)).unwrap();
        assert_eq!((e.method, e.flags), (12, 1));
        assert_eq!(e.data().err().unwrap().kind(), io::ErrorKind::Unsupported);
        let z = zip_entry(0, 0, b"", 0, b"name");
        let err = zip_first_entry(io::Cursor::new(&z[..20])).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
