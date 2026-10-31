//! bzip2, via the `bzip2` crate's pure-Rust `libbz2-rs-sys` backend.
//!
//! Despite the `-sys` name, `libbz2-rs-sys` is pure Rust — it is what plain
//! `bzip2 = "0.6"` (default features, no `default-features = false`, no
//! nonexistent `libbz2-rs-sys` feature flag) actually pulls in. No C
//! toolchain is required to build this codec.

use std::io::{BufRead, Write};

use bzip2::Compression;
use bzip2::bufread::BzDecoder as BzMemberDecoder;
use bzip2::write::BzEncoder;
use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FidelitySink, FormatId,
    FormatMeta, MagicRule, Result, Sink, Source, StreamOnly,
};

use crate::member_tail::{self, Header, PeekBuf, Rule};
use crate::normalize::{MALFORMED_AS_INVALID_INPUT_EOF, NormalizeDecodeErrors};

pub const BZIP2: FormatId = FormatId::new("bzip2");

const BZIP2_MAGIC_BYTES: &[u8] = &[0x42, 0x5a, 0x68];

const BZIP2_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: BZIP2_MAGIC_BYTES,
    format: BZIP2,
}];

/// Chains single-member `BzDecoder`s across a concatenated `.bz2` file
/// instead of `bzip2::read::MultiBzDecoder` — the same fix as gzip's
/// [`crate::gzip`] module for the same reason (Finding 7 of the Phase 1e
/// final review): reference `bzip2 -dc` and Python's `bz2` module both
/// recover the real data whole when trailing NUL/`'X'` bytes follow a
/// complete, valid stream (measured at 1, 2, 5, 9, 10, 16, 40 and 512
/// trailing bytes of each), while `MultiBzDecoder` rejected the file
/// outright.
///
/// `bzip2::bufread::BzDecoder(multi: false)` stops the instant its stream
/// footer (the combined CRC) verifies, and never attempts a next one — so
/// its `Ok(0)` is unambiguous proof of a complete, valid stream, never a
/// probe result, and truncation anywhere up through that footer still
/// errors straight out of `BzMemberDecoder` itself before this type's own
/// peek ever runs. From there [`crate::member_tail::after_member`] decides
/// what the remaining bytes are, exactly as for `MultiMemberGzip`: a stream
/// header chains into a fresh `BzMemberDecoder` (the legitimate
/// multi-stream case, e.g. `pbzip2` output); NUL/`'X'` padding stops
/// silently; a damaged header (`BZh` and a level outside `1`..`9`, or
/// `BZh1`..`BZh9` followed by neither the block magic nor the end-of-stream
/// magic, or the input ending inside `BZh`) is corrupt; any other tail is
/// ignored with [`stuffr_core::Fidelity::TrailingDataIgnored`] recorded in
/// [`DecodeOpts::fidelity`] (PARSE-1, security audit 2026-10-31: it used to
/// stop silently, so one flipped byte at a stream boundary dropped every
/// later stream at exit 0).
struct MultiMemberBzip2<'a> {
    /// `None` once the stream has ended (or failed); see `failed`.
    cur: Option<BzMemberDecoder<PeekBuf<Box<dyn Source + 'a>>>>,
    /// Set when the tail check refused: later reads repeat the refusal
    /// instead of reporting a clean end.
    failed: bool,
    sink: FidelitySink,
}

impl<'a> MultiMemberBzip2<'a> {
    fn new(src: Box<dyn Source + 'a>, sink: FidelitySink) -> Self {
        Self {
            cur: Some(BzMemberDecoder::new(PeekBuf::new(src))),
            failed: false,
            sink,
        }
    }
}

/// bzip2's half of [`crate::member_tail`]'s rule: `BZh`, a level digit, then
/// the first block's magic or (for an empty stream) the end-of-stream magic
/// — the same fields [`confirm`] checks.
const TAIL_RULE: Rule = Rule {
    format: BZIP2,
    magic: BZIP2_MAGIC_BYTES,
    header_len: 10,
    judge: |head| {
        if !head.starts_with(BZIP2_MAGIC_BYTES) {
            return Header::Junk;
        }
        if head.get(3).is_some_and(|d| !(b'1'..=b'9').contains(d)) {
            return Header::Corrupt(
                "a later bzip2 stream's header names a block size outside 1-9: a corrupt header \
                 in a multi-stream file",
            );
        }
        if let Some(next) = head.get(4..10)
            && next != BLOCK_MAGIC
            && next != END_MAGIC
        {
            return Header::Corrupt(
                "a later bzip2 stream's header is followed by neither a block nor the \
                 end-of-stream magic: a corrupt header in a multi-stream file",
            );
        }
        Header::Next
    },
};

impl std::io::Read for MultiMemberBzip2<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let Some(dec) = self.cur.as_mut() else {
                if self.failed {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bzip2 stream previously failed to decode",
                    ));
                }
                return Ok(0);
            };
            match dec.read(buf)? {
                0 => {
                    let mut rest = self.cur.take().unwrap().into_inner();
                    match member_tail::after_member(&mut rest, &TAIL_RULE, &self.sink) {
                        Ok(true) => {
                            self.cur = Some(BzMemberDecoder::new(rest));
                            continue;
                        }
                        Ok(false) => return Ok(0),
                        Err(e) => {
                            self.failed = true;
                            return Err(e);
                        }
                    }
                }
                n => return Ok(n),
            }
        }
    }
}

/// Registration metadata for bzip2.
pub fn meta() -> FormatMeta {
    FormatMeta::codec(BZIP2, &["bz2"], BZIP2_MAGIC).with_confirm(confirm)
}

/// The first block's magic (π) or, for an empty stream, the end-of-stream
/// magic (√π), both 48 bits.
const BLOCK_MAGIC: [u8; 6] = [0x31, 0x41, 0x59, 0x26, 0x53, 0x59];
const END_MAGIC: [u8; 6] = [0x17, 0x72, 0x45, 0x38, 0x50, 0x90];

/// `BZh`, a block-size digit `1`..=`9`, then the block magic or the
/// end-of-stream magic — as much of either as `prefix` holds.
///
/// A whole stream must reach the end of that first block or end magic.
fn confirm(prefix: &[u8], whole: bool) -> bool {
    if whole && prefix.len() < 10 {
        return false;
    }
    if !prefix.get(3).is_none_or(|d| (b'1'..=b'9').contains(d)) {
        return false;
    }
    let next = prefix.get(4..).unwrap_or(&[]);
    let next = &next[..next.len().min(6)];
    BLOCK_MAGIC.starts_with(next) || END_MAGIC.starts_with(next)
}

#[derive(Debug)]
pub struct Bzip2;

impl Codec for Bzip2 {
    fn id(&self) -> FormatId {
        BZIP2
    }

    fn caps(&self) -> CodecCaps {
        CodecCaps {
            // bzip2 carries a per-block CRC32 plus a whole-stream combined
            // CRC32, so both a flipped byte and a truncated stream are
            // detected rather than silently decoded into different bytes.
            detects_corruption: CorruptionDetection::Always,
            // Not measured: derived from the level-9 block size. bzip2's
            // block is 100 KiB * level, so 900 KiB at level 9; the encoder's
            // working set is several multiples of that for its Burrows-
            // Wheeler transform buffers. 4 MiB is a defensible round figure
            // for "several times 900 KiB", not a profiled number.
            memory_per_worker: Some(4 * 1024 * 1024),
            // What follows the last verified member is judged at the end of
            // the stream (`member_tail`), and junk there is a warning.
            reports_trailing_data: true,
            ..CodecCaps::round_trip()
        }
    }

    /// Decodes with `MultiMemberBzip2`, never a bare single-stream
    /// `BzDecoder` and never `bzip2::read::MultiBzDecoder` — concatenated
    /// bzip2 streams are valid bzip2, `pbzip2` produces them, and a bare
    /// single-stream decoder stops after the first without erroring,
    /// silently truncating exactly the files a parallel bzip2 encoder
    /// produces. `MultiMemberBzip2`'s own doc explains why its own
    /// chaining — not `MultiBzDecoder` — is what closes this without
    /// reopening Finding 7 (trailing NUL/`'X'` padding wrongly rejected).
    ///
    /// Wrapped in `StreamOnly` (a bzip2 stream carries no seek table) and in
    /// `NormalizeDecodeErrors` — see `crate::normalize` for why, and for the
    /// measurement backing the kinds reused here from flate2's list: bzip2's
    /// own vocabulary for malformed input turned out to be the same pair,
    /// `InvalidInput` and `UnexpectedEof`, independently measured against
    /// this crate rather than assumed from gzip's.
    fn decoder<'a>(
        &self,
        src: Box<dyn Source + 'a>,
        o: &DecodeOpts,
    ) -> Result<Box<dyn Source + 'a>> {
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            MultiMemberBzip2::new(src, o.fidelity.clone()),
            MALFORMED_AS_INVALID_INPUT_EOF,
        ))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        // Unlike gzip and zlib, bzip2 has no level 0: 1-9 is the whole valid
        // range, so this range is NOT the 0..=9 those codecs use. Rejecting
        // here, before any destination is opened, is what check_encode_opts
        // exists for.
        match o.level {
            Some(n) if !(1..=9).contains(&n) => Err(Error::Usage(format!(
                "bzip2 compression level must be 1-9, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        let level = Compression::new(o.level.unwrap_or(6) as u32);
        Ok(Box::new(Bzip2Sink(BzEncoder::new(dst, level))))
    }
}

struct Bzip2Sink(BzEncoder<Box<dyn Write + Send>>);

impl Write for Bzip2Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for Bzip2Sink {
    /// Writes the closing block and stream trailer.
    ///
    /// Without this the output is a truncated bzip2 stream, which is why
    /// `Sink` has a fallible completion step rather than relying on `Drop`.
    fn finish(self: Box<Self>) -> Result<()> {
        let Bzip2Sink(encoder) = *self;
        let mut w = encoder.finish()?;
        w.flush()?;
        Ok(())
    }
}

/// Why a [`StreamReader::read`] stopped short, in libbzip2's own classes.
///
/// [`Codec::decoder`] folds all of these into one "corrupt" error and chains
/// streams on its own, which is right for `stuffr` but loses what `bzip2(1)`
/// reports: a bad magic on the first stream ("not a bzip2 file") is not a bad
/// magic on a later one ("trailing garbage"), and neither is a CRC failure or
/// a cut-short file. The `bzip2` compatibility mode of the `stuffr` binary
/// needs those distinctions to reproduce bzip2's messages and exit codes.
#[derive(Debug)]
#[non_exhaustive]
#[doc(hidden)]
pub enum StreamError {
    /// `BZ_DATA_ERROR_MAGIC`: the stream does not start with `BZh1`..`BZh9`.
    Magic,
    /// `BZ_DATA_ERROR`: a malformed block or a CRC mismatch.
    Data,
    /// `BZ_UNEXPECTED_EOF`: the source ended inside the stream.
    UnexpectedEof,
    /// `BZ_MEM_ERROR`.
    Memory,
    /// Reading the source failed.
    Io(std::io::Error),
    /// A result libbzip2 never gives for a well-formed call sequence.
    Unexpected,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Magic => f.write_str("bzip2: bad magic number"),
            Self::Data => f.write_str("bzip2: data integrity error"),
            Self::UnexpectedEof => f.write_str("bzip2: stream ends unexpectedly"),
            Self::Memory => f.write_str("bzip2: out of memory"),
            Self::Io(e) => write!(f, "bzip2: {e}"),
            Self::Unexpected => f.write_str("bzip2: unexpected decoder state"),
        }
    }
}

impl std::error::Error for StreamError {}

/// One bzip2 stream, decoded with libbzip2's `BZ2_bzRead` contract.
///
/// Each [`read`](Self::read) fills its buffer completely, or up to the end of
/// the stream, or fails; on failure the partly filled buffer is lost, exactly
/// as `BZ2_bzRead` returns 0 on an error. The source is consumed only as far
/// as the decoder used it, so after the stream ends the bytes left in the
/// `BufRead` are libbzip2's "unused" bytes: the start of the next stream, or
/// trailing garbage.
#[doc(hidden)]
pub struct StreamReader {
    d: bzip2::Decompress,
    ended: bool,
}

impl std::fmt::Debug for StreamReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamReader")
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl StreamReader {
    /// A reader for one stream. `small` selects libbzip2's low-memory
    /// decoder; the output is the same either way.
    pub fn new(small: bool) -> Self {
        Self {
            d: bzip2::Decompress::new(small),
            ended: false,
        }
    }

    /// Fill `out` from `src`. `Ok((n, true))` means the stream ended after
    /// `n` bytes; `Ok((n, false))` means `n == out.len()` and more follows.
    pub fn read<R: BufRead + ?Sized>(
        &mut self,
        src: &mut R,
        out: &mut [u8],
    ) -> std::result::Result<(usize, bool), StreamError> {
        use bzip2::Status;
        if self.ended {
            return Ok((0, true));
        }
        let mut filled = 0;
        loop {
            let input = src.fill_buf().map_err(StreamError::Io)?;
            let (in0, out0) = (self.d.total_in(), self.d.total_out());
            let ret = self.d.decompress(input, &mut out[filled..]);
            let consumed = (self.d.total_in() - in0) as usize;
            let all_used = consumed == input.len();
            filled += (self.d.total_out() - out0) as usize;
            src.consume(consumed);
            match ret {
                Err(bzip2::Error::DataMagic) => return Err(StreamError::Magic),
                Err(bzip2::Error::Data) => return Err(StreamError::Data),
                Err(_) => return Err(StreamError::Unexpected),
                Ok(Status::MemNeeded) => return Err(StreamError::Memory),
                Ok(Status::StreamEnd) => {
                    self.ended = true;
                    return Ok((filled, true));
                }
                Ok(_) => {}
            }
            if filled == out.len() {
                return Ok((filled, false));
            }
            // `BZ2_bzRead`: OK, the input used up and the file at its end,
            // with room left in the output, is a stream cut short.
            if all_used && src.fill_buf().map_err(StreamError::Io)?.is_empty() {
                return Err(StreamError::UnexpectedEof);
            }
        }
    }
}

/// One bzip2 stream driven a `BZ2_bzDecompress` call at a time, with the
/// caller's buffers.
///
/// [`StreamReader`] keeps `BZ2_bzRead`'s contract, which fills a whole
/// buffer across calls and loses all of it on an error. Apple gzip's
/// `unbzip2` loop instead hands each call a fresh output buffer, writes
/// what that one call produced, and loses only a failing call's output; the
/// `stuffr` binary's Apple gzip personality reproduces that loop with this.
#[doc(hidden)]
pub struct RawStream {
    d: bzip2::Decompress,
}

impl std::fmt::Debug for RawStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawStream").finish_non_exhaustive()
    }
}

impl Default for RawStream {
    fn default() -> Self {
        Self::new()
    }
}

impl RawStream {
    /// A fresh decoder (`BZ2_bzDecompressInit(&s, 0, 0)`).
    pub fn new() -> Self {
        Self {
            d: bzip2::Decompress::new(false),
        }
    }

    /// One `BZ2_bzDecompress` call over `input` into `out`:
    /// `Ok((consumed, produced, stream_ended))`. On an error what the call
    /// produced is not reported, as libbzip2's caller cannot know it.
    pub fn decompress(
        &mut self,
        input: &[u8],
        out: &mut [u8],
    ) -> std::result::Result<(usize, usize, bool), StreamError> {
        let (consumed, produced, ret) = self.decompress_counted(input, out);
        ret.map(|ended| (consumed, produced, ended))
    }

    /// One `BZ2_bzDecompress` call as [`decompress`](Self::decompress), with
    /// what it consumed and produced reported whatever it returned:
    /// `(consumed, produced, Ok(stream_ended) or the error)`. libbzip2
    /// moves `next_in` and `next_out` on an error too, and a caller that
    /// goes on after one (Info-ZIP unzip's `UZbunzip2()` does after a bad
    /// magic) reads on from there.
    pub fn decompress_counted(
        &mut self,
        input: &[u8],
        out: &mut [u8],
    ) -> (usize, usize, std::result::Result<bool, StreamError>) {
        use bzip2::Status;
        let (in0, out0) = (self.d.total_in(), self.d.total_out());
        let ret = self.d.decompress(input, out);
        let consumed = (self.d.total_in() - in0) as usize;
        let produced = (self.d.total_out() - out0) as usize;
        let ret = match ret {
            Err(bzip2::Error::DataMagic) => Err(StreamError::Magic),
            Err(bzip2::Error::Data) => Err(StreamError::Data),
            Err(_) => Err(StreamError::Unexpected),
            Ok(Status::MemNeeded) => Err(StreamError::Memory),
            Ok(Status::StreamEnd) => Ok(true),
            Ok(_) => Ok(false),
        };
        (consumed, produced, ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use stuffr_core::ReaderSource;
    use stuffr_core::testing::SharedBuf;

    fn compress(plain: &[u8]) -> Vec<u8> {
        let buf = SharedBuf::new();
        let mut sink = Bzip2
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Bzip2.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    /// `RawStream` call by call: a stream decodes to its bytes and ends;
    /// a broken block is `Data`, a wrong magic `Magic`.
    #[test]
    fn raw_stream_decodes_call_by_call_and_names_its_errors() {
        let plain = b"raw stream, one call at a time\n".repeat(500);
        let packed = compress(&plain);
        let mut raw = RawStream::new();
        let (mut at, mut got, mut ended) = (0, Vec::new(), false);
        while !ended {
            let mut out = [0u8; 1000];
            let (c, p, e) = raw
                .decompress(&packed[at..(at + 64).min(packed.len())], &mut out)
                .unwrap();
            at += c;
            got.extend_from_slice(&out[..p]);
            ended = e;
        }
        assert_eq!(got, plain);
        assert_eq!(at, packed.len());
        let mut bad = packed.clone();
        bad[10] ^= 0xff; // the block CRC
        let mut raw = RawStream::new();
        let mut out = vec![0u8; 1 << 20];
        assert!(matches!(
            raw.decompress(&bad, &mut out),
            Err(StreamError::Data)
        ));
        let mut raw = RawStream::new();
        assert!(matches!(
            raw.decompress(b"BZx9junk", &mut out),
            Err(StreamError::Magic)
        ));
    }

    /// `decompress_counted` reports what an erroring call consumed: a bad
    /// magic is found at its third byte, which has been read (libbz2-rs-sys
    /// reads up to 7 bytes ahead into its 64-bit bit buffer where C
    /// libbzip2 reads a byte at a time, so the count is at least 3), and
    /// nothing comes out.
    #[test]
    fn raw_stream_counts_what_an_erroring_call_consumed() {
        let mut raw = RawStream::new();
        let mut out = [0u8; 64];
        let (c, p, r) = raw.decompress_counted(b"BZx9junk", &mut out);
        assert!((3..=8).contains(&c), "consumed {c}");
        assert_eq!(p, 0);
        assert!(matches!(r, Err(StreamError::Magic)));
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = compress(&plain);
        assert!(
            packed.len() < plain.len(),
            "bzip2 must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_bzip2_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..3], &[0x42, 0x5a, 0x68]);
    }

    #[test]
    fn decodes_concatenated_members_not_just_the_first() {
        // Concatenated bzip2 streams are valid bzip2 — pbzip2 produces them —
        // and BzDecoder stops after the first stream without erroring, so a
        // regression here truncates silently.
        let mut two = compress(b"first-");
        two.extend_from_slice(&compress(b"second"));
        assert_eq!(decompress(two), b"first-second");
    }

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path).find_map(|dir| {
            let candidate = dir.join(bin);
            candidate.is_file().then_some(candidate)
        })
    }

    /// Reproduces Finding 7 of the Phase 1e final review: trailing NUL or
    /// `'X'` padding after a complete, valid stream used to be rejected
    /// outright (exit 5, no file from `unpack`), where reference
    /// `bzip2 -dc` and Python's `bz2` module both recover the data whole
    /// (reference `bzip2 -dc` even exits 0, no warning at all). Swept at
    /// every length the review measured, plus the sub-magic lengths (1, 2)
    /// it didn't spell out but which the reference tool treats identically.
    #[test]
    fn trailing_padding_after_a_valid_stream_is_ignored_like_the_reference() {
        let plain = b"trailing-padding regression payload, repeated a bit. ".repeat(40);
        let packed = compress(&plain);

        for pad_byte in [0x00u8, b'X'] {
            for pad_len in [1, 2, 5, 9, 10, 16, 40, 512] {
                let mut padded = packed.clone();
                padded.extend(std::iter::repeat_n(pad_byte, pad_len));
                let (out, warnings) = decode_tail(padded);
                assert_eq!(
                    out.unwrap(),
                    plain,
                    "pad_byte={pad_byte:#04x} pad_len={pad_len}: trailing padding after a \
                     valid stream must not lose or corrupt the real data"
                );
                assert!(
                    warnings.is_empty(),
                    "pad_byte={pad_byte:#04x} pad_len={pad_len}: padding stays silent"
                );
            }
        }
    }

    fn decode_tail(bytes: Vec<u8>) -> (std::io::Result<Vec<u8>>, Vec<stuffr_core::Fidelity>) {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let opts = DecodeOpts::default();
        let mut dec = Bzip2.decoder(src, &opts).unwrap();
        let mut out = Vec::new();
        let r = dec.read_to_end(&mut out).map(|_| out);
        (r, opts.fidelity.warnings())
    }

    fn ignored(bytes: u64) -> Vec<stuffr_core::Fidelity> {
        vec![stuffr_core::Fidelity::TrailingDataIgnored {
            format: BZIP2,
            bytes,
        }]
    }

    /// PARSE-1: a flipped first magic byte of the second stream used to end
    /// the decode silently after the first, dropping the second at exit 0.
    #[test]
    fn a_later_stream_with_a_flipped_magic_byte_is_reported_not_dropped_silently() {
        let a = compress(&b"first member\n".repeat(100));
        let b = compress(&b"SECOND MEMBER\n".repeat(1000));
        let mut x = [a.clone(), b.clone()].concat();
        x[a.len()] = 0x41;
        let (out, warnings) = decode_tail(x);
        assert_eq!(out.unwrap(), b"first member\n".repeat(100));
        assert_eq!(warnings, ignored(b.len() as u64));
    }

    #[test]
    fn trailing_junk_that_is_not_padding_is_reported_with_its_length() {
        let plain = b"payload".repeat(10);
        for tail in [&b"BZx"[..], b"hello", b"\0\0X", b"ZZh9"] {
            let (out, warnings) = decode_tail([compress(&plain), tail.to_vec()].concat());
            assert_eq!(out.unwrap(), plain, "{tail:?}");
            assert_eq!(warnings, ignored(tail.len() as u64), "{tail:?}");
        }
    }

    /// A tail that starts like a stream header and then cannot be one is
    /// corrupt (exit 5), as reference lzip's "Corrupt header in multimember
    /// file" — never a warning and never silence.
    #[test]
    fn a_damaged_later_stream_header_is_corrupt() {
        let a = compress(b"first");
        let b = compress(b"second");
        let mut bad_level = [a.clone(), b.clone()].concat();
        bad_level[a.len() + 3] = b'0';
        let mut bad_block = [a.clone(), b.clone()].concat();
        bad_block[a.len() + 4] ^= 0xff;
        let mut cases = vec![("level 0", bad_level), ("block magic", bad_block)];
        for cut in [b"B".as_slice(), b"BZ", b"BZh", b"BZh9", b"BZh91AY"] {
            cases.push(("cut header", [a.clone(), cut.to_vec()].concat()));
        }
        for (what, x) in cases {
            let (out, warnings) = decode_tail(x);
            let err = out.expect_err(what);
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{what}: {err}");
            assert!(warnings.is_empty(), "{what}");
        }
    }

    /// The regression this fix must not reopen: a stream cut short — mid
    /// block, or anywhere inside its own trailer — is genuine truncation
    /// and must still error, even though the fix above now tolerates
    /// trailing bytes that follow a stream which completed and verified in
    /// full.
    #[test]
    fn a_truncated_stream_is_still_rejected_even_though_trailing_padding_is_now_tolerated() {
        let packed = compress(b"truncation must still be caught after this fix");
        for cut in 1..packed.len() {
            let truncated = &packed[..cut];
            let src: Box<dyn Source> =
                Box::new(ReaderSource::new(std::io::Cursor::new(truncated.to_vec())));
            let mut dec = Bzip2.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            assert!(
                dec.read_to_end(&mut out).is_err(),
                "cut at byte {cut} of {} decoded without error",
                packed.len()
            );
        }
    }

    /// Reference arbiter for the case above: the reference `bzip2` CLI (or,
    /// if absent, Python's `bz2` module) must independently agree that
    /// trailing NUL/`'X'` padding is recoverable, or the case above proves
    /// nothing about matching the reference.
    #[test]
    fn trailing_padding_matches_the_reference_tool() {
        let plain = b"reference-tool trailing-padding payload, repeated. ".repeat(40);
        let packed = compress(&plain);

        let bzip2_bin = which("bzip2");
        let python_bin = which("python3");
        if bzip2_bin.is_none() && python_bin.is_none() {
            return;
        }

        for pad_len in [1, 16, 40, 512] {
            let mut padded = packed.clone();
            padded.extend(std::iter::repeat_n(0u8, pad_len));

            let path_tmp =
                crate::test_tmp::Tmp::new("bzip2", &format!("trailing-pad-{pad_len}.bz2"));
            let path = path_tmp.path().to_path_buf();
            std::fs::write(&path, &padded).unwrap();

            if let Some(bzip2_bin) = &bzip2_bin {
                let out = std::process::Command::new(bzip2_bin)
                    .arg("-dc")
                    .arg(&path)
                    .output()
                    .unwrap();
                assert_eq!(
                    out.stdout, plain,
                    "pad_len={pad_len}: reference bzip2 must recover the real data"
                );
            }
            if let Some(python_bin) = &python_bin {
                let out = std::process::Command::new(python_bin)
                    .arg("-c")
                    .arg(format!(
                        "import bz2,sys; sys.stdout.buffer.write(bz2.open({:?},'rb').read())",
                        path.to_str().unwrap()
                    ))
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "python bz2 module rejected pad_len={pad_len}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                assert_eq!(
                    out.stdout, plain,
                    "pad_len={pad_len}: python bz2 module must recover the real data"
                );
            }
        }
    }

    #[test]
    fn level_zero_is_rejected_because_bzip2_starts_at_one() {
        // Unlike gzip, bzip2 has no level 0 — it is invalid, not "store".
        // A range copied from gzip would accept this and fail later, at encode
        // time, with the destination already open.
        let opts = EncodeOpts {
            level: Some(0),
            ..Default::default()
        };
        let Err(err) = Bzip2.check_encode_opts(&opts) else {
            panic!("level 0 must be rejected");
        };
        assert!(matches!(err, stuffr_core::Error::Usage(_)), "got {err:?}");
        assert!(
            err.to_string().contains("1-9"),
            "the error must name the real range: {err}"
        );

        // And the valid extremes are accepted.
        for n in [1, 9] {
            let opts = EncodeOpts {
                level: Some(n),
                ..Default::default()
            };
            assert!(
                Bzip2.check_encode_opts(&opts).is_ok(),
                "level {n} must be accepted"
            );
        }
    }

    #[test]
    fn an_out_of_range_level_is_a_usage_error_not_a_silent_clamp() {
        let opts = EncodeOpts {
            level: Some(12),
            ..Default::default()
        };
        match Bzip2.encoder(Box::new(SharedBuf::new()), &opts) {
            Err(err) => {
                assert!(matches!(err, stuffr_core::Error::Usage(_)));
                assert_eq!(err.exit_code(), 2);
                assert!(err.to_string().contains("1-9"));
            }
            Ok(_) => panic!("encoder should reject out-of-range level"),
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        // bzip2 carries no frame index, so its output must not claim random
        // access. A container above it would otherwise read wrong bytes.
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Bzip2.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Bzip2.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        let m = meta();
        assert_eq!(m.id, BZIP2);
        assert_eq!(m.extensions, &["bz2"]);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn bzip2_declares_an_integrity_check_and_a_memory_figure() {
        let c = Bzip2.caps();
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::Always,
            "bzip2 carries per-block and stream CRCs, so corrupt input is detectable"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    #[test]
    fn bzip2_conforms() {
        stuffr_core::testing::assert_codec_conforms(&Bzip2, &meta());
    }

    /// Drain one stream through `StreamReader` in 5000-byte reads, as
    /// `bzip2(1)` does: the decoded bytes, and what stopped it.
    fn one_stream(src: &mut &[u8]) -> (Vec<u8>, Option<StreamError>) {
        let mut sr = StreamReader::new(false);
        let mut out = Vec::new();
        let mut buf = [0u8; 5000];
        loop {
            match sr.read(src, &mut buf) {
                Ok((n, end)) => {
                    out.extend_from_slice(&buf[..n]);
                    if end {
                        return (out, None);
                    }
                }
                Err(e) => return (out, Some(e)),
            }
        }
    }

    #[test]
    fn stream_reader_stops_at_the_end_of_one_stream_and_leaves_the_rest() {
        let mut two = compress(b"first-");
        let second = compress(b"second");
        two.extend_from_slice(&second);
        two.extend_from_slice(b"tail");
        let mut src = &two[..];
        let (a, e) = one_stream(&mut src);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(a, b"first-");
        let (b, e) = one_stream(&mut src);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(b, b"second");
        assert_eq!(src, b"tail");
        assert!(matches!(one_stream(&mut src).1, Some(StreamError::Magic)));
    }

    #[test]
    fn stream_reader_classifies_like_libbzip2() {
        let good = compress(&b"classify me ".repeat(500));
        type Want = fn(&StreamError) -> bool;
        let cases: Vec<(&str, Vec<u8>, Want)> = vec![
            ("empty", vec![], |e| matches!(e, StreamError::UnexpectedEof)),
            ("one byte B", b"B".to_vec(), |e| {
                matches!(e, StreamError::UnexpectedEof)
            }),
            ("BZh", b"BZh".to_vec(), |e| {
                matches!(e, StreamError::UnexpectedEof)
            }),
            ("bad digit", b"BZhX....".to_vec(), |e| {
                matches!(e, StreamError::Magic)
            }),
            ("garbage", b"garbage".to_vec(), |e| {
                matches!(e, StreamError::Magic)
            }),
            ("block magic", b"BZh9xxxxxxxxxx".to_vec(), |e| {
                matches!(e, StreamError::Data)
            }),
            ("truncated", good[..good.len() / 2].to_vec(), |e| {
                matches!(e, StreamError::UnexpectedEof)
            }),
        ];
        for (what, bytes, want) in cases {
            let (_, e) = one_stream(&mut &bytes[..]);
            let e = e.unwrap_or_else(|| panic!("{what}: decoded without error"));
            assert!(want(&e), "{what}: got {e:?}");
        }
        // A flipped bit in the stored stream CRC (the last bytes before the
        // padding) is a data error, found only after all output is produced.
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 2] ^= 0x01;
        assert!(matches!(
            one_stream(&mut &bad[..]).1,
            Some(StreamError::Data)
        ));
    }

    #[test]
    fn stream_reader_fills_the_buffer_before_returning() {
        let plain: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let packed = compress(&plain);
        let mut sr = StreamReader::new(true);
        let mut src = &packed[..];
        let mut buf = [0u8; 5000];
        for _ in 0..4 {
            assert_eq!(sr.read(&mut src, &mut buf).unwrap().0, 5000);
        }
        assert_eq!(sr.read(&mut src, &mut buf).unwrap(), (0, true));
    }
}

#[cfg(test)]
mod confirm_tests {
    use super::*;
    use crate::confirm_test::{assert_every_cut_confirms, assert_never_panics, encode, inputs};
    use stuffr_core::ConfirmFn;

    fn confirm_fn() -> ConfirmFn {
        meta().confirm.expect("bzip2 registers a confirm function")
    }

    /// The registered function judging a window (`whole` false): what
    /// every test below that cuts a stream short means.
    fn confirm() -> impl Fn(&[u8]) -> bool {
        |p| confirm_fn()(p, false)
    }

    /// A whole stream that stops inside the header the check reads is
    /// refused; the same bytes as a window onto a longer stream are not.
    #[test]
    fn confirm_refuses_a_whole_stream_cut_inside_its_header() {
        use crate::confirm_test::assert_whole_cuts_refused as refused;
        let s = encode(&Bzip2, b"hello", None);
        refused("bzip2", confirm_fn(), &s[..10], 0);
        assert!(confirm_fn()(&s[..4], false));
    }

    #[test]
    fn confirm_accepts_own_output() {
        for plain in inputs() {
            for level in [Some(1), None, Some(9)] {
                let stream = encode(&Bzip2, &plain, level);
                let what = format!("bzip2 level {level:?}, {} bytes in", plain.len());
                assert_every_cut_confirms(&what, confirm_fn(), &stream, 3);
            }
        }
    }

    #[test]
    fn confirm_rejects_magic_plus_noise() {
        let good = encode(&Bzip2, b"hello", None);
        assert!(confirm()(&good));
        for size in [b'0', b'A', 0] {
            let mut bad = good.clone();
            bad[3] = size;
            assert!(!confirm()(&bad), "block size byte {size:#04x}");
        }
        // Neither a block magic nor the end-of-stream magic.
        let mut bad = good.clone();
        bad[9] ^= 1;
        assert!(!confirm()(&bad));
        assert!(!confirm()(b"BZh9\x17\x72\x45\x38\x50\x91"));
        assert!(!confirm()(b"BZh9ordinary text"));
    }

    #[test]
    fn confirm_never_panics_on_short_input() {
        assert_never_panics(confirm_fn(), &encode(&Bzip2, b"hello", None));
    }
}
