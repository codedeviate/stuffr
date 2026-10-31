//! gzip, via `flate2`'s pure-Rust backend.

use std::io::Write;

use flate2::Compression;
use flate2::bufread::GzDecoder as GzMemberDecoder;
use flate2::write::GzEncoder;
use stuffr_core::{
    Codec, CodecCaps, CorruptionDetection, DecodeOpts, EncodeOpts, Error, FidelitySink, FormatId,
    FormatMeta, MagicRule, Result, Sink, Source, StreamOnly,
};

use crate::member_tail::{self, Header, PeekBuf, Rule};
use crate::normalize::{MALFORMED_AS_INVALID_INPUT_EOF, NormalizeDecodeErrors};

pub const GZIP: FormatId = FormatId::new("gzip");

const GZIP_MAGIC_BYTES: &[u8] = &[0x1f, 0x8b];

const GZIP_MAGIC: &[MagicRule] = &[MagicRule {
    offset: 0,
    bytes: GZIP_MAGIC_BYTES,
    format: GZIP,
}];

/// Chains single-member `GzDecoder`s across a concatenated `.gz` file
/// instead of using `flate2::read::MultiGzDecoder` directly — see Finding 7
/// of the Phase 1e final review.
///
/// `MultiGzDecoder` conflates two states that must be told apart: "the
/// CURRENT member's own footer was cut short" (genuine truncation, must
/// still error) and "the CURRENT member completed and its CRC verified in
/// full, and what follows merely does not look like a gzip header" (both
/// reference `gzip -dc` and Python's own `gzip` module treat the second as
/// harmless padding and recover the data whole — measured at 1, 2, 5, 9,
/// 10, 16, 40 and 512 trailing NUL/`'X'` bytes, every one "trailing garbage
/// ignored", exit 2, full data). Both surface through the same
/// `io::ErrorKind` from the same helper inside flate2's own header parser,
/// with no reliable way to tell them apart once `MultiGzDecoder` has
/// already committed to one path — a naive "swallow this error kind" fix
/// risks quietly amnesty-ing real mid-member truncation instead, which is
/// this project's least acceptable failure mode.
///
/// This sidesteps the ambiguity by never letting flate2 attempt that probe
/// at all: `GzMemberDecoder` (`flate2::bufread::GzDecoder`, `multi: false`)
/// stops the instant one member's footer CRC verifies, and never looks for
/// a next one — reaching its `Ok(0)` is therefore unambiguous proof the
/// member is complete and valid, never a probe result. From there this
/// type does its OWN, unambiguous next-member check by peeking without
/// consuming (as `lzip.rs`'s `GuardedLzipReader` does): if what remains is
/// a gzip member header, chain into a fresh `GzMemberDecoder` over the same
/// buffer (the legitimate multi-member case); otherwise the tail rule
/// described below decides. Genuine truncation anywhere up through and
/// including the CURRENT member's own footer is untouched:
/// that error still comes straight from `GzMemberDecoder` itself, before
/// this type's peek ever runs.
///
/// `flate2::read::GzDecoder` (built on `std::io::BufReader` internally)
/// was considered and rejected: its own doc warns it "may have read past
/// the end of the gzip data" and that `into_inner` then loses whatever was
/// buffered past that point — exactly the bytes this peek needs. The
/// `bufread` variant, operating directly on a caller-owned buffer,
/// consumes precisely what the deflate stream needs and leaves the rest
/// sitting in that buffer for the peek to see.
///
/// **What follows a verified member** is decided by
/// [`crate::member_tail::after_member`] since PARSE-1 (security audit,
/// 2026-10-31): the "anything else stops cleanly" above dropped every later
/// member at exit 0 when one byte at a member boundary was flipped. NUL/`'X'`
/// padding still stops silently; a damaged header (`1f 8b` and a method other
/// than 8 or a reserved flag bit, or the input ending after `1f`) is corrupt;
/// any other tail is ignored with [`stuffr_core::Fidelity::TrailingDataIgnored`]
/// recorded in [`DecodeOpts::fidelity`]. The buffer is a
/// [`PeekBuf`](crate::member_tail::PeekBuf), not a `BufReader`, because a
/// `BufReader` shows a member boundary one byte before the end of its buffer
/// as a one-byte tail.
struct MultiMemberGzip<'a> {
    /// `None` once the stream has ended (or failed); see `failed`.
    cur: Option<GzMemberDecoder<PeekBuf<Box<dyn Source + 'a>>>>,
    /// Set when the tail check refused: later reads repeat the refusal
    /// instead of reporting a clean end.
    failed: bool,
    sink: FidelitySink,
}

impl<'a> MultiMemberGzip<'a> {
    fn new(src: Box<dyn Source + 'a>, sink: FidelitySink) -> Self {
        Self {
            cur: Some(GzMemberDecoder::new(PeekBuf::new(src))),
            failed: false,
            sink,
        }
    }
}

/// gzip's half of [`crate::member_tail`]'s rule: the magic, then RFC 1952's
/// compression method (8, the only one defined) and flag byte (bits 5-7
/// reserved) — the same two fields [`confirm`] checks.
const TAIL_RULE: Rule = Rule {
    format: GZIP,
    magic: GZIP_MAGIC_BYTES,
    header_len: 4,
    judge: |head| {
        if !head.starts_with(GZIP_MAGIC_BYTES) {
            return Header::Junk;
        }
        if head.get(2).is_some_and(|&cm| cm != 8) {
            return Header::Corrupt(
                "a later gzip member's header names a compression method other than deflate (8): \
                 a corrupt header in a multi-member file",
            );
        }
        if head.get(3).is_some_and(|&flg| flg & 0xe0 != 0) {
            return Header::Corrupt(
                "a later gzip member's header sets reserved flag bits: a corrupt header in a \
                 multi-member file",
            );
        }
        Header::Next
    },
};

impl std::io::Read for MultiMemberGzip<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let Some(dec) = self.cur.as_mut() else {
                if self.failed {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "gzip stream previously failed to decode",
                    ));
                }
                return Ok(0);
            };
            match dec.read(buf)? {
                0 => {
                    let mut rest = self.cur.take().unwrap().into_inner();
                    match member_tail::after_member(&mut rest, &TAIL_RULE, &self.sink) {
                        Ok(true) => {
                            self.cur = Some(GzMemberDecoder::new(rest));
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

/// Registration metadata for gzip.
pub fn meta() -> FormatMeta {
    FormatMeta::codec(GZIP, &["gz"], GZIP_MAGIC).with_confirm(confirm)
}

/// RFC 1952's header behind the magic: compression method 8 (deflate, the
/// only one defined) and none of the three reserved flag bits (`0xE0`),
/// which every decoder must refuse.
///
/// A whole stream must hold the ten-byte fixed header at least.
fn confirm(prefix: &[u8], whole: bool) -> bool {
    if whole && prefix.len() < 10 {
        return false;
    }
    prefix.get(2).is_none_or(|&cm| cm == 8) && prefix.get(3).is_none_or(|&flg| flg & 0xe0 == 0)
}

#[derive(Debug)]
pub struct Gzip;

impl Codec for Gzip {
    fn id(&self) -> FormatId {
        GZIP
    }

    fn caps(&self) -> CodecCaps {
        // Parallel encode and a frame index arrive in 1f.
        CodecCaps {
            // gzip's trailer carries a CRC32 over the uncompressed data, so a
            // flipped byte anywhere in the stream is detected rather than
            // silently decoded into different bytes.
            detects_corruption: CorruptionDetection::Always,
            // deflate's window is 32 KiB; miniz_oxide's encoder state plus our
            // 64 KiB copy buffer puts one worker comfortably under 256 KiB.
            memory_per_worker: Some(256 * 1024),
            // What follows the last verified member is judged at the end of
            // the stream (`member_tail`), and junk there is a warning.
            reports_trailing_data: true,
            ..CodecCaps::round_trip()
        }
    }

    /// Decodes with `MultiMemberGzip`, never a bare single-member
    /// `GzDecoder`.
    ///
    /// Concatenated gzip members are valid gzip, and every parallel encoder
    /// produces them. A bare `GzDecoder` stops after the first member and
    /// returns a short read *without an error*, silently truncating exactly
    /// the files this project will generate itself once 1c lands
    /// multi-member encode. `MultiMemberGzip`'s own doc explains why that
    /// type — not `flate2::read::MultiGzDecoder` — is what closes this: it
    /// ALSO fixes Finding 7 (trailing NUL/`'X'` padding wrongly rejected)
    /// without reopening this truncation gap.
    ///
    /// The result is wrapped in `StreamOnly`: a gzip stream carries no seek
    /// table, so its decoded output must not claim random access.
    ///
    /// `MultiMemberGzip` is wrapped again in `NormalizeDecodeErrors` first:
    /// see `crate::normalize` for why.
    fn decoder<'a>(
        &self,
        src: Box<dyn Source + 'a>,
        o: &DecodeOpts,
    ) -> Result<Box<dyn Source + 'a>> {
        Ok(Box::new(StreamOnly::new(NormalizeDecodeErrors::new(
            MultiMemberGzip::new(src, o.fidelity.clone()),
            MALFORMED_AS_INVALID_INPUT_EOF,
        ))))
    }

    fn check_encode_opts(&self, o: &EncodeOpts) -> Result<()> {
        match o.level {
            Some(n) if !(0..=9).contains(&n) => Err(Error::Usage(format!(
                "gzip compression level must be 0-9, got {n}"
            ))),
            _ => Ok(()),
        }
    }

    fn encoder(&self, dst: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
        self.check_encode_opts(o)?;
        let level = match o.level {
            Some(n) => Compression::new(n as u32),
            None => Compression::default(),
        };
        Ok(Box::new(GzSink(GzEncoder::new(dst, level))))
    }
}

struct GzSink(GzEncoder<Box<dyn Write + Send>>);

impl Write for GzSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Sink for GzSink {
    /// Writes the CRC32 and length trailer.
    ///
    /// Without this the output is a truncated gzip stream that most decoders
    /// reject and some accept with garbage — which is why `Sink` has a fallible
    /// completion step rather than relying on `Drop`.
    fn finish(self: Box<Self>) -> Result<()> {
        let GzSink(encoder) = *self;
        // `GzEncoder::finish` hands the wrapped writer back; the caller gave
        // it to us by value at `Codec::encoder` and has no other handle left
        // to flush it, so that is done here — see the contract on `Sink`.
        let mut w = encoder.finish()?;
        w.flush()?;
        Ok(())
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
        let mut sink = Gzip
            .encoder(Box::new(buf.clone()), &EncodeOpts::default())
            .unwrap();
        sink.write_all(plain).unwrap();
        sink.finish().unwrap();
        buf.contents()
    }

    fn decompress(bytes: Vec<u8>) -> Vec<u8> {
        let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
        let mut dec = Gzip.decoder(src, &DecodeOpts::default()).unwrap();
        let mut out = Vec::new();
        dec.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn round_trips_real_data() {
        let plain = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let packed = compress(&plain);
        assert!(
            packed.len() < plain.len(),
            "gzip must actually compress this"
        );
        assert_eq!(decompress(packed), plain);
    }

    #[test]
    fn output_begins_with_the_gzip_magic() {
        let packed = compress(b"payload");
        assert_eq!(&packed[..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn decodes_concatenated_members_not_just_the_first() {
        // Concatenated gzip members are valid gzip, and every parallel encoder
        // produces them — including the multi-member encode this project adds
        // in 1f. A single-member decoder stops after the first member and
        // returns a short read WITHOUT an error, so a regression here
        // truncates silently.
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
    /// `'X'` padding after a complete, valid member used to be rejected
    /// outright (exit 5, no file from `unpack`), where reference `gzip -dc`
    /// recovers the data whole (exit 2, "trailing garbage ignored") and so
    /// does Python's `gzip` module. Swept at every length the review
    /// measured, plus the sub-header lengths (1-9 bytes) it didn't spell
    /// out but which the reference tool treats identically.
    #[test]
    fn trailing_padding_after_a_valid_member_is_ignored_like_the_reference() {
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
                     valid member must not lose or corrupt the real data"
                );
                assert!(
                    warnings.is_empty(),
                    "pad_byte={pad_byte:#04x} pad_len={pad_len}: padding stays silent"
                );
            }
        }
    }

    /// The regression this fix must not reopen: a member cut short — mid
    /// body, or anywhere inside its own footer — is genuine truncation and
    /// must still error, even though the fix above now tolerates trailing
    /// bytes that follow a member which completed and verified in full.
    #[test]
    fn a_truncated_member_is_still_rejected_even_though_trailing_padding_is_now_tolerated() {
        let packed = compress(b"truncation must still be caught after this fix");
        for cut in 1..packed.len() {
            let truncated = &packed[..cut];
            let src: Box<dyn Source> =
                Box::new(ReaderSource::new(std::io::Cursor::new(truncated.to_vec())));
            let mut dec = Gzip.decoder(src, &DecodeOpts::default()).unwrap();
            let mut out = Vec::new();
            assert!(
                dec.read_to_end(&mut out).is_err(),
                "cut at byte {cut} of {} decoded without error",
                packed.len()
            );
        }
    }

    /// Reference arbiter for the case above: the reference `gzip` CLI (or,
    /// if absent, Python's `gzip` module) must independently agree that
    /// trailing NUL/`'X'` padding is recoverable, or the case above proves
    /// nothing about matching the reference.
    #[test]
    fn trailing_padding_matches_the_reference_tool() {
        let plain = b"reference-tool trailing-padding payload, repeated. ".repeat(40);
        let packed = compress(&plain);

        let gzip_bin = which("gzip");
        let python_bin = which("python3");
        if gzip_bin.is_none() && python_bin.is_none() {
            return;
        }

        for pad_len in [1, 16, 40, 512] {
            let mut padded = packed.clone();
            padded.extend(std::iter::repeat_n(0u8, pad_len));

            let path_tmp = crate::test_tmp::Tmp::new("gzip", &format!("trailing-pad-{pad_len}.gz"));
            let path = path_tmp.path().to_path_buf();
            std::fs::write(&path, &padded).unwrap();

            if let Some(gzip_bin) = &gzip_bin {
                let out = std::process::Command::new(gzip_bin)
                    .arg("-dc")
                    .arg(&path)
                    .output()
                    .unwrap();
                assert_eq!(
                    out.stdout, plain,
                    "pad_len={pad_len}: reference gzip must recover the real data"
                );
            }
            if let Some(python_bin) = &python_bin {
                let out = std::process::Command::new(python_bin)
                    .arg("-c")
                    .arg(format!(
                        "import gzip,sys; sys.stdout.buffer.write(gzip.open({:?},'rb').read())",
                        path.to_str().unwrap()
                    ))
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "python gzip module rejected pad_len={pad_len}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                assert_eq!(
                    out.stdout, plain,
                    "pad_len={pad_len}: python gzip module must recover the real data"
                );
            }
        }
    }

    /// Decodes `bytes` through `src`, returning the result and what the
    /// decoder recorded in its fidelity sink.
    fn decode_with(src: Box<dyn Source>) -> (std::io::Result<Vec<u8>>, Vec<stuffr_core::Fidelity>) {
        let opts = DecodeOpts::default();
        let mut dec = Gzip.decoder(src, &opts).unwrap();
        let mut out = Vec::new();
        let r = dec.read_to_end(&mut out).map(|_| out);
        (r, opts.fidelity.warnings())
    }

    fn decode_tail(bytes: Vec<u8>) -> (std::io::Result<Vec<u8>>, Vec<stuffr_core::Fidelity>) {
        decode_with(Box::new(ReaderSource::new(std::io::Cursor::new(bytes))))
    }

    fn ignored(bytes: u64) -> Vec<stuffr_core::Fidelity> {
        vec![stuffr_core::Fidelity::TrailingDataIgnored {
            format: GZIP,
            bytes,
        }]
    }

    /// PARSE-1: a flipped first magic byte of the second member used to end
    /// the stream silently after the first, dropping the second at exit 0.
    #[test]
    fn a_later_member_with_a_flipped_magic_byte_is_reported_not_dropped_silently() {
        let a = compress(&b"first member\n".repeat(100));
        let b = compress(&b"SECOND MEMBER\n".repeat(1000));
        let mut x = [a.clone(), b.clone()].concat();
        x[a.len()] = 0x1e;
        let (out, warnings) = decode_tail(x);
        assert_eq!(out.unwrap(), b"first member\n".repeat(100));
        assert_eq!(warnings, ignored(b.len() as u64));
    }

    #[test]
    fn trailing_junk_that_is_not_padding_is_reported_with_its_length() {
        let plain = b"payload".repeat(10);
        for tail in [&b"\x1f\x00junk"[..], b"hello", b"\0\0X", b"XXXX\0", b"\x8b"] {
            let (out, warnings) = decode_tail([compress(&plain), tail.to_vec()].concat());
            assert_eq!(out.unwrap(), plain, "{tail:?}");
            assert_eq!(warnings, ignored(tail.len() as u64), "{tail:?}");
        }
    }

    /// A tail that starts like a member header and then cannot be one is
    /// corrupt (exit 5), as reference lzip's "Corrupt header in multimember
    /// file" — never a warning and never silence.
    #[test]
    fn a_damaged_later_member_header_is_corrupt() {
        let a = compress(b"first");
        let b = compress(b"second");
        let mut bad_method = [a.clone(), b.clone()].concat();
        bad_method[a.len() + 2] = 7;
        let mut reserved = [a.clone(), b.clone()].concat();
        reserved[a.len() + 3] |= 0x40;
        let magic_cut = [a.clone(), vec![0x1f]].concat();
        let header_cut = [a.clone(), vec![0x1f, 0x8b, 8]].concat();
        for (what, x) in [
            ("method 7", bad_method),
            ("reserved flag", reserved),
            ("1f then EOF", magic_cut),
            ("header cut short", header_cut),
        ] {
            let (out, warnings) = decode_tail(x);
            let err = out.expect_err(what);
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{what}: {err}");
            assert!(warnings.is_empty(), "{what}");
        }
    }

    /// A member boundary is found whatever the source's read sizes — a
    /// `BufReader` showed a boundary one byte before its buffer's end as a
    /// one-byte tail.
    #[test]
    fn members_chain_through_a_source_that_reads_one_byte_at_a_time() {
        struct Trickle(std::io::Cursor<Vec<u8>>);
        impl std::io::Read for Trickle {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let n = out.len().min(1);
                self.0.read(&mut out[..n])
            }
        }
        let x = [compress(b"one-"), compress(b"two-"), compress(b"three")].concat();
        let (out, warnings) = decode_with(Box::new(ReaderSource::new(Trickle(
            std::io::Cursor::new(x),
        ))));
        assert_eq!(out.unwrap(), b"one-two-three");
        assert!(warnings.is_empty());
    }

    #[test]
    fn an_out_of_range_level_is_a_usage_error_not_a_silent_clamp() {
        let opts = EncodeOpts {
            level: Some(12),
            ..Default::default()
        };
        match Gzip.encoder(Box::new(SharedBuf::new()), &opts) {
            Err(err) => {
                assert!(matches!(err, stuffr_core::Error::Usage(_)));
                assert_eq!(err.exit_code(), 2);
                assert!(err.to_string().contains("0-9"));
            }
            Ok(_) => panic!("encoder should reject out-of-range level"),
        }
    }

    #[test]
    fn the_decoded_stream_reports_no_seek() {
        // gzip carries no frame index, so its output must not claim random
        // access. A container above it would otherwise read wrong bytes.
        let src: Box<dyn Source> =
            Box::new(ReaderSource::new(std::io::Cursor::new(compress(b"x"))));
        let dec = Gzip.decoder(src, &DecodeOpts::default()).unwrap();
        assert!(!dec.caps().seekable);
    }

    #[test]
    fn capabilities_and_metadata_match_the_format() {
        let c = Gzip.caps();
        assert!(c.encode && c.decode);
        assert!(!c.parallel_encode && !c.frame_index, "not until 1f");
        let m = meta();
        assert_eq!(m.id, GZIP);
        assert_eq!(m.extensions, &["gz"]);
        assert_eq!(m.priority, 0);
    }

    #[test]
    fn gzip_declares_an_integrity_check_and_a_memory_figure() {
        let c = Gzip.caps();
        assert_eq!(
            c.detects_corruption,
            CorruptionDetection::Always,
            "gzip carries a CRC32, so corrupt input is detectable and Error::Corrupt is reachable"
        );
        assert!(
            c.memory_per_worker.is_some(),
            "a codec that knows its working set should say so; the governor has no other source"
        );
    }

    #[test]
    fn gzip_conforms() {
        // Includes the incrementality check (harness property 8) against a
        // relative threshold, and the truncation check (property 10) against
        // gzip's real CRC32 trailer — this used to be duplicated in a private
        // ~80-line, 16 MiB test here; the harness now covers it for every
        // codec that adopts it, gzip included.
        stuffr_core::testing::assert_codec_conforms(&Gzip, &meta());
    }
}

#[cfg(test)]
mod confirm_tests {
    use super::*;
    use crate::confirm_test::{assert_every_cut_confirms, assert_never_panics, encode, inputs};
    use stuffr_core::ConfirmFn;

    fn confirm_fn() -> ConfirmFn {
        meta().confirm.expect("gzip registers a confirm function")
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
        let s = encode(&Gzip, b"hello", None);
        refused("gzip", confirm_fn(), &s[..10], 0);
        assert!(!confirm_fn()(&[0x1f, 0x8b], true), "the magic alone");
        assert!(confirm_fn()(&[0x1f, 0x8b], false), "a window may end there");
    }

    #[test]
    fn confirm_accepts_own_output() {
        for plain in inputs() {
            for level in [Some(0), None, Some(9)] {
                let stream = encode(&Gzip, &plain, level);
                let what = format!("gzip level {level:?}, {} bytes in", plain.len());
                assert_every_cut_confirms(&what, confirm_fn(), &stream, 2);
            }
        }
        // A header carrying every optional field (FTEXT, FHCRC, FEXTRA,
        // FNAME, FCOMMENT): bits 0-4 are the format's, only 5-7 reserved.
        let mut all_flags = vec![0x1f, 0x8b, 8, 0x1f, 0, 0, 0, 0, 0, 3];
        all_flags.extend_from_slice(b"\x02\x00ab");
        assert!(confirm()(&all_flags));
    }

    #[test]
    fn confirm_rejects_magic_plus_noise() {
        let good = encode(&Gzip, b"hello", None);
        assert!(confirm()(&good));
        for method in [0u8, 7, 9, 0xff] {
            let mut bad = good.clone();
            bad[2] = method;
            assert!(!confirm()(&bad), "compression method {method}");
        }
        for reserved in [0x20u8, 0x40, 0x80] {
            let mut bad = good.clone();
            bad[3] |= reserved;
            assert!(!confirm()(&bad), "reserved flag {reserved:#04x}");
        }
    }

    #[test]
    fn confirm_never_panics_on_short_input() {
        assert_never_panics(confirm_fn(), &encode(&Gzip, b"hello", None));
    }
}
