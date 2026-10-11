//! One input through GNU gzip 1.15's decoders, as the binary was observed
//! to treat it (GNU's source is never read; `messages.rs` names the
//! command behind each outcome).
//!
//! GNU reads an input in two stages, and `-v` prints the name between
//! them:
//!
//! 1. **[`open`]**: the first magic, and for gzip and zip the whole first
//!    header. A refusal here (not gzip, an unknown method or flag, a zip
//!    entry it will not read) leaves no output file behind.
//! 2. **[`finish`]**: the members, in order. After a gzip or pack member
//!    any of `1f 8b`, `1f 9e`, `1f 9d` and `1f 1e` starts another member,
//!    of that format (`gzip -dc` on gzip-then-`.Z`, gzip-then-pack and
//!    pack-then-gzip decodes both); a `.Z` member runs to the end of the
//!    input; a zip is its first entry only. Anything else after a member is
//!    trailing data.
//!
//! With `-f`, when the output is standard output (or nothing, under `-t`),
//! input that is not compressed is copied as it is, and so is trailing
//! data (`gzip -dcf` on text prints the text; on a member then `junk`
//! prints both, exit 0).
//!
//! LZH (`1f a0`, which GNU also decodes) has no decoder in stuffr: a first
//! member is "not in gzip format", a later one trailing garbage. A
//! documented gap (Ruling T5).

use std::io::{self, BufRead, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::unpack::{PackFault, unpack};
use crate::compat::gzip::member::{
    Fault, Header, Lookahead, MemberError, inflate_member, read_header_with,
};
use crate::compat::gzip::sniff::{self, Detected, Flavour};

/// A source that counts the bytes read from it.
pub(super) struct Counted<R> {
    inner: R,
    n: Arc<AtomicU64>,
}

impl<R> Counted<R> {
    pub(super) fn new(inner: R) -> (Self, Arc<AtomicU64>) {
        let n = Arc::new(AtomicU64::new(0));
        (
            Counted {
                inner,
                n: n.clone(),
            },
            n,
        )
    }
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n.fetch_add(k as u64, Ordering::Relaxed);
        Ok(k)
    }
}

/// The input as every stage reads it: one [`Lookahead`] for its whole
/// life, so no peeked byte is ever lost.
pub(super) type Stream<R> = Lookahead<Counted<R>>;

/// The last member's format, for `-lv`'s method column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Method {
    Deflate,
    Stored,
    Compress,
    Pack,
    /// `-f` copied input that was not compressed.
    Copy,
}

/// Something to say that does not stop the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Note {
    /// A member's FEXTRA length (said under `-v`).
    Extra(usize),
    /// A `.Z` header's unknown flag bits (a warning).
    ZFlags(u8),
    /// Bytes after the last member, not all zero.
    TrailingGarbage,
    /// Zero bytes after the last member.
    TrailingZeros,
    /// A zip with a second local header.
    ZipMore,
}

/// Why an input failed.
#[derive(Debug)]
pub(super) enum Fail {
    Eof,
    FormatViolated,
    Crc,
    Length,
    /// A pack stream's length field (which, unlike gzip's, ends the run
    /// even under `-t` and `-l`).
    PackLength,
    /// A zip entry's data descriptor.
    CrcLength,
    NotGzip,
    UnknownMethod(u8),
    Encrypted,
    Flags(u8),
    /// FHCRC as stored, and as computed.
    HeaderCrc(u16, u16),
    ZipEncrypted,
    ZipMethod,
    Zip64,
    ZipInvalid,
    ZBits(u8),
    /// A corrupt `.Z`, after this many bytes of output.
    ZCorrupt(u64),
    PackFew,
    PackMany,
    PackBitLength,
    /// Under `-N`, a stored name too long to restore (judged by the
    /// caller, which knows the operand's directory).
    NameTooLarge,
    Read(io::Error),
    Write(io::Error),
}

impl Fail {
    /// Whether this failure ends the whole run (later operands untouched).
    /// Observed with a good file after each: truncation, a corrupt body or
    /// header CRC, a corrupt `.Z` and every pack failure always stop; a
    /// CRC or length error stops `-d` (and `-dc`) but not `-t` or `-l`;
    /// header-stage refusals never do, except a stored name too long for
    /// `-N` (observed: `gzip -dN n.gz g.gz` and `gzip -lN g.gz n.gz`, with
    /// a 1024-byte name in `n.gz`, leave `g.gz` alone and print no
    /// totals).
    pub(super) fn fatal(&self, decompressing: bool) -> bool {
        match self {
            Fail::Eof
            | Fail::FormatViolated
            | Fail::ZCorrupt(_)
            | Fail::PackFew
            | Fail::PackMany
            | Fail::PackBitLength
            | Fail::PackLength
            | Fail::NameTooLarge
            | Fail::Read(_)
            | Fail::Write(_) => true,
            Fail::Crc | Fail::Length | Fail::CrcLength => decompressing,
            Fail::NotGzip
            | Fail::UnknownMethod(_)
            | Fail::Encrypted
            | Fail::Flags(_)
            | Fail::HeaderCrc(..)
            | Fail::ZipEncrypted
            | Fail::ZipMethod
            | Fail::Zip64
            | Fail::ZipInvalid
            | Fail::ZBits(_) => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Gzip,
    Zip,
    Compress,
    Pack,
    Copy,
}

/// A zip's first local header, as far as GNU reads it.
#[derive(Debug, Clone, Copy)]
struct ZipLocal {
    method: u16,
    flags: u16,
    crc: u32,
    csize: u32,
    usize: u32,
}

/// What the header stage found.
pub(super) struct Opened {
    kind: Kind,
    /// The first gzip member's header.
    pub(super) header: Option<Header>,
    zip: Option<ZipLocal>,
}

/// What a whole input decoded to.
pub(super) struct Done {
    pub(super) method: Method,
    /// The last member's CRC, when it was gzip.
    pub(super) crc: Option<u32>,
    pub(super) out: u64,
    /// What `-v` and `-l` subtract from the compressed size: the first
    /// header and the trailer when the input was exactly one gzip member,
    /// else 0 (observed: a two-member file's ratio counts every byte, and
    /// so does a member followed by zeros).
    pub(super) header_bytes: u64,
}

/// GNU's input buffer: what `-v` and `-l` count of a header longer than it.
const INBUF: u64 = 256 * 1024;

/// The part of a `len`-byte first header that `-v` and `-l` subtract: all
/// of it up to [`INBUF`] bytes, then only what lies in the last buffer's
/// worth, `(len - 1) % INBUF + 1` (observed with GNU 1.15's `-l` ratios
/// over stored names of up to 1.5 MiB: a 262,144-byte header counts
/// 262,144, a 262,145-byte one 1, a 600,011-byte one 75,723; the same from
/// a file and from a pipe written 1,000 or 65,536 bytes at a time).
fn counted_header(len: u64) -> u64 {
    if len == 0 { 0 } else { (len - 1) % INBUF + 1 }
}

fn read_fail(e: io::Error) -> Fail {
    Fail::Read(e)
}

/// The header stage. `copy_ok`: `-f` and the output is standard output or
/// nothing, so input that is not compressed is copied.
pub(super) fn open<R: Read>(
    s: &mut Stream<R>,
    copy_ok: bool,
    note: &mut dyn FnMut(Note),
) -> Result<Opened, Fail> {
    let opened = |kind| Opened {
        kind,
        header: None,
        zip: None,
    };
    let peek_len = loop {
        match s.fill_buf() {
            Ok(b) => break b.len(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(read_fail(e)),
        }
    };
    if peek_len < 2 {
        return if copy_ok {
            Ok(opened(Kind::Copy))
        } else {
            Err(Fail::Eof)
        };
    }
    let detected = sniff::detect(s, Flavour::Gnu).map_err(read_fail)?;
    match detected {
        Detected::Gzip => Ok(Opened {
            header: Some(gzip_header(s, note)?),
            ..opened(Kind::Gzip)
        }),
        Detected::Zip => {
            let z = zip_header(s)?;
            Ok(Opened {
                zip: Some(z),
                ..opened(Kind::Zip)
            })
        }
        Detected::Compress => Ok(opened(Kind::Compress)),
        Detected::Pack => Ok(opened(Kind::Pack)),
        _ if copy_ok => Ok(opened(Kind::Copy)),
        _ => Err(Fail::NotGzip),
    }
}

/// One gzip header, its failures as GNU words them (a wrong FHCRC with
/// both values, observed: `header checksum 0x0012 != computed checksum
/// 0x003f`).
fn gzip_header<R: Read>(s: &mut Stream<R>, note: &mut dyn FnMut(Note)) -> Result<Header, Fail> {
    match read_header_with(s, &mut |n| note(Note::Extra(n))) {
        Ok(h) => Ok(h),
        Err(MemberError::Io(e)) => Err(read_fail(e)),
        Err(MemberError::Fault(f)) => Err(match f {
            Fault::BadMethod(m) => Fail::UnknownMethod(m),
            Fault::BadFlags(f) if f & 0x20 != 0 => Fail::Encrypted,
            Fault::BadFlags(f) => Fail::Flags(f),
            Fault::BadHeaderCrc { stored, computed } => Fail::HeaderCrc(stored, computed),
            // `read_header` reports nothing else; a short header is EOF.
            _ => Fail::Eof,
        }),
    }
}

/// A zip's first local header and GNU's refusals of it, in the order the
/// binary showed: the method, encryption, a Zip64 size, then a stored
/// entry it cannot size. A header cut short is "not a valid zip file".
fn zip_header<R: Read>(s: &mut Stream<R>) -> Result<ZipLocal, Fail> {
    let e = sniff::zip_first_entry(&mut *s).map_err(|_| Fail::ZipInvalid)?;
    let z = ZipLocal {
        method: e.method,
        flags: e.flags,
        crc: e.crc,
        csize: e.compressed_size,
        usize: e.uncompressed_size,
    };
    if z.method != 0 && z.method != 8 {
        return Err(Fail::ZipMethod);
    }
    if z.flags & 1 != 0 {
        return Err(Fail::ZipEncrypted);
    }
    if z.usize == u32::MAX {
        return Err(Fail::Zip64);
    }
    if z.method == 0 && (z.flags & 8 != 0 || z.csize != z.usize) {
        return Err(Fail::ZipInvalid);
    }
    Ok(z)
}

/// The output: counts and checksums what is written, and remembers whether
/// a failure came from writing, so an I/O error is attributed to the right
/// side.
struct Sink<'w> {
    inner: &'w mut dyn Write,
    n: u64,
    crc: flate2::Crc,
    failed: bool,
}

impl Write for Sink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.write(buf) {
            Ok(k) => {
                self.crc.update(&buf[..k]);
                self.n += k as u64;
                Ok(k)
            }
            Err(e) => {
                self.failed = true;
                Err(e)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().inspect_err(|_| self.failed = true)
    }
}

impl Sink<'_> {
    fn io(&self, e: io::Error) -> Fail {
        if self.failed {
            Fail::Write(e)
        } else {
            Fail::Read(e)
        }
    }
}

/// What the member stage learned, kept even when it fails.
#[derive(Debug, Default)]
pub(super) struct Progress {
    /// Each gzip member's stored time that is not 0, so it ends as the last
    /// such one, which is what `-N` restores (observed: `gzip -dN` on two
    /// members stamped T1 and T2 gives T2; on T1 and 0, T1; on 0 and T2,
    /// T2).
    pub(super) stamp: Option<u32>,
    /// [`Done::header_bytes`] as far as known: what `-l`'s totals subtract
    /// for an input that failed too.
    pub(super) header_bytes: u64,
}

/// The member stage: decode everything `open` found to `out`. `copy_ok` as
/// for [`open`]. Each note goes to `note` as it arises, never kept, so
/// memory is bounded whatever the member count; output already written
/// stays written when it fails.
pub(super) fn finish<R: Read + Send + 'static>(
    mut s: Stream<R>,
    o: Opened,
    copy_ok: bool,
    out: &mut dyn Write,
    note: &mut dyn FnMut(Note),
    progress: &mut Progress,
) -> Result<Done, Fail> {
    let mut sink = Sink {
        inner: out,
        n: 0,
        crc: flate2::Crc::new(),
        failed: false,
    };
    let first_kind = o.kind;
    let first_len = o.header.as_ref().map_or(0, |h| counted_header(h.len));
    progress.header_bytes = if first_kind == Kind::Gzip {
        first_len + 8
    } else {
        0
    };
    let mut header = o.header;
    let mut kind = o.kind;
    // Whether a second member followed the first.
    let mut several = false;
    let mut method;
    let mut crc;
    let mut trailing = false;
    loop {
        match kind {
            Kind::Gzip => {
                let h = match header.take() {
                    Some(h) => h,
                    None => gzip_header(&mut s, note)?,
                };
                if h.mtime != 0 {
                    progress.stamp = Some(h.mtime);
                }
                let info = inflate_member(&mut s, h, &mut sink).map_err(|e| match e {
                    MemberError::Io(e) => sink.io(e),
                    MemberError::Fault(f) => match f {
                        Fault::Truncated(_) => Fail::Eof,
                        Fault::Crc { .. } => Fail::Crc,
                        Fault::Length { .. } => Fail::Length,
                        _ => Fail::FormatViolated,
                    },
                })?;
                method = Method::Deflate;
                crc = Some(info.crc);
            }
            Kind::Pack => {
                unpack(&mut s, &mut sink).map_err(|e| match e {
                    PackFault::Eof => Fail::Eof,
                    PackFault::BitLength => Fail::PackBitLength,
                    PackFault::Few => Fail::PackFew,
                    PackFault::Many => Fail::PackMany,
                    PackFault::Length => Fail::PackLength,
                    PackFault::Read(e) => Fail::Read(e),
                    PackFault::Write(e) => Fail::Write(e),
                })?;
                method = Method::Pack;
                crc = None;
            }
            Kind::Compress => {
                lzw(s, &mut sink, note)?;
                return Ok(Done {
                    method: Method::Compress,
                    crc: None,
                    out: sink.n,
                    header_bytes: 0,
                });
            }
            Kind::Zip => {
                let z = o.zip.expect("a zip was opened");
                zip_entry(&mut s, z, &mut sink)?;
                if s.fill_buf().map_err(read_fail)?.starts_with(b"PK\x03\x04") {
                    note(Note::ZipMore);
                }
                return Ok(Done {
                    method: if z.method == 0 {
                        Method::Stored
                    } else {
                        Method::Deflate
                    },
                    crc: None,
                    out: sink.n,
                    header_bytes: 0,
                });
            }
            Kind::Copy => {
                io::copy(&mut s, &mut sink).map_err(|e| sink.io(e))?;
                return Ok(Done {
                    method: Method::Copy,
                    crc: None,
                    out: sink.n,
                    header_bytes: 0,
                });
            }
        }
        // What follows a gzip or pack member.
        let at_end = s.fill_buf().map_err(read_fail)?.is_empty();
        if at_end {
            break;
        }
        // Another member or trailing data: every byte counts.
        progress.header_bytes = 0;
        let next = match sniff::detect(&mut s, Flavour::Gnu).map_err(read_fail)? {
            Detected::Gzip => Kind::Gzip,
            Detected::Pack => Kind::Pack,
            Detected::Compress => Kind::Compress,
            // A zip, LZH or anything else is trailing data here.
            _ => {
                trailing = true;
                if copy_ok {
                    io::copy(&mut s, &mut sink).map_err(|e| sink.io(e))?;
                } else {
                    let mut all_zero = true;
                    loop {
                        let b = s.fill_buf().map_err(read_fail)?;
                        if b.is_empty() {
                            break;
                        }
                        all_zero &= b.iter().all(|&x| x == 0);
                        let n = b.len();
                        s.consume(n);
                    }
                    note(if all_zero {
                        Note::TrailingZeros
                    } else {
                        Note::TrailingGarbage
                    });
                }
                break;
            }
        };
        kind = next;
        several = true;
    }
    let single = !several && !trailing && first_kind == Kind::Gzip;
    Ok(Done {
        method,
        crc,
        out: sink.n,
        header_bytes: if single { first_len + 8 } else { 0 },
    })
}

/// A `.Z` member, which runs to the end of the input: its header byte as
/// GNU judges it, then stuffr's LZW decoder (whose output on cut-short and
/// corrupt input matched the binary's on every probe). A maximum below 9
/// bits is refused by that decoder before any output, where GNU writes a
/// few bytes first: a documented difference.
fn lzw<R: Read + Send + 'static>(
    mut s: Stream<R>,
    sink: &mut Sink<'_>,
    note: &mut dyn FnMut(Note),
) -> Result<(), Fail> {
    let b = s.fill_buf().map_err(read_fail)?;
    if b.len() < 3 {
        return Err(Fail::Eof);
    }
    let flags = b[2];
    let bits = flags & 0x1f;
    if bits > 16 {
        return Err(Fail::ZBits(bits));
    }
    if flags & 0x60 != 0 {
        note(Note::ZFlags(flags & 0x60));
    }
    let start = sink.n;
    // The decoder words its own findings as `InvalidData` ("corrupt
    // input."); any other kind is the source's, a read error.
    let fail = |e: io::Error, written: u64| {
        if e.kind() == io::ErrorKind::InvalidData {
            Fail::ZCorrupt(written)
        } else {
            Fail::Read(e)
        }
    };
    let mut r = sniff::foreign_reader(Detected::Compress, Box::new(s)).map_err(|e| fail(e, 0))?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(fail(e, sink.n - start)),
        };
        sink.write_all(&buf[..n]).map_err(Fail::Write)?;
    }
}

/// A zip's first entry's data, checked against its header, or against its
/// data descriptor (flag 8: an optional `PK\7\10`, then CRC, compressed and
/// uncompressed sizes) where any mismatch or shortfall is one "crc/length
/// error".
fn zip_entry<R: Read>(s: &mut Stream<R>, z: ZipLocal, sink: &mut Sink<'_>) -> Result<(), Fail> {
    sink.crc = flate2::Crc::new();
    let start = sink.n;
    if z.method == 0 {
        let mut left = u64::from(z.csize);
        while left > 0 {
            let b = s.fill_buf().map_err(read_fail)?;
            if b.is_empty() {
                return Err(Fail::Eof);
            }
            let k = b.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            let chunk = b[..k].to_vec();
            s.consume(k);
            sink.write_all(&chunk).map_err(Fail::Write)?;
            left -= k as u64;
        }
    } else {
        inflate_raw(s, sink)?;
    }
    let crc = sink.crc.sum();
    let len = (sink.n - start) as u32;
    if z.flags & 8 != 0 {
        let mut d = [0u8; 16];
        let short = |s: &mut Stream<R>, buf: &mut [u8]| -> Result<bool, Fail> {
            let mut at = 0;
            while at < buf.len() {
                match s.read(&mut buf[at..]) {
                    Ok(0) => return Ok(true),
                    Ok(n) => at += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(read_fail(e)),
                }
            }
            Ok(false)
        };
        if short(s, &mut d[..4])? {
            return Err(Fail::CrcLength);
        }
        let body = if d[..4] == *b"PK\x07\x08" {
            if short(s, &mut d[4..16])? {
                return Err(Fail::CrcLength);
            }
            &d[4..16]
        } else {
            if short(s, &mut d[4..12])? {
                return Err(Fail::CrcLength);
            }
            &d[..12]
        };
        let dcrc = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let dlen = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
        if dcrc != crc || dlen != len {
            return Err(Fail::CrcLength);
        }
        return Ok(());
    }
    if z.crc != crc {
        return Err(Fail::Crc);
    }
    if z.usize != len {
        return Err(Fail::Length);
    }
    Ok(())
}

/// A raw deflate stream from `s` to `sink`, stopping where it ends.
fn inflate_raw<R: Read>(s: &mut Stream<R>, sink: &mut Sink<'_>) -> Result<(), Fail> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut d = Decompress::new(false);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let input = match s.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(read_fail(e)),
        };
        let eof = input.is_empty();
        let (in0, out0) = (d.total_in(), d.total_out());
        let flush = if eof {
            FlushDecompress::Finish
        } else {
            FlushDecompress::None
        };
        let res = d.decompress(input, &mut buf, flush);
        let used = (d.total_in() - in0) as usize;
        let made = (d.total_out() - out0) as usize;
        s.consume(used);
        if made > 0 {
            sink.write_all(&buf[..made]).map_err(Fail::Write)?;
        }
        match res.map_err(|_| Fail::FormatViolated)? {
            Status::StreamEnd => return Ok(()),
            _ if eof && made == 0 => return Err(Fail::Eof),
            _ if used == 0 && made == 0 => return Err(Fail::FormatViolated),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `.Z` source that gives its header and a few bytes, then fails with
    /// `kind`.
    struct Failing {
        head: Vec<u8>,
        kind: io::ErrorKind,
    }

    impl Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.head.is_empty() {
                return Err(io::Error::from(self.kind));
            }
            let n = buf.len().min(self.head.len());
            buf[..n].copy_from_slice(&self.head[..n]);
            self.head.drain(..n);
            Ok(n)
        }
    }

    fn lzw_over(head: &[u8], kind: io::ErrorKind) -> Result<(), Fail> {
        let (counted, _) = Counted::new(Failing {
            head: head.to_vec(),
            kind,
        });
        let s = Lookahead::new(counted);
        let mut out = Vec::new();
        let mut sink = Sink {
            inner: &mut out,
            n: 0,
            crc: flate2::Crc::new(),
            failed: false,
        };
        lzw(s, &mut sink, &mut |_| {})
    }

    /// Fix round 1: a read error under a `.Z` is a read error (GNU's
    /// `gzip: NAME: strerror` shape), and only the decoder's own
    /// `InvalidData` is "corrupt input.".
    ///
    /// Fix round 2: never skipped. `stuffr-cli` always takes `stuffr`'s
    /// default features, `legacy` (and so `compress`) among them, whatever
    /// this crate's own feature flags (see its `Cargo.toml`), so the codec
    /// is in every build of this test; a `cfg(feature = ...)` on this
    /// crate's flags would drop the test from the plain leg, where the code
    /// under test is present. The assertion makes a build without it fail
    /// loudly instead of passing having checked nothing.
    #[test]
    fn a_read_error_under_lzw_is_not_corruption() {
        assert_eq!(
            sniff::detect(&mut Lookahead::new(&b"\x1f\x9d\x90\x00"[..]), Flavour::Gnu).unwrap(),
            Detected::Compress,
            "the compress codec is in every stuffr-cli build"
        );
        let head = b"\x1f\x9d\x90\x61\x00";
        assert!(matches!(
            lzw_over(head, io::ErrorKind::PermissionDenied),
            Err(Fail::Read(e)) if e.kind() == io::ErrorKind::PermissionDenied
        ));
        assert!(matches!(
            lzw_over(head, io::ErrorKind::InvalidData),
            Err(Fail::ZCorrupt(_))
        ));
    }
}
