//! A conformance harness every codec adopts in one line.
//!
//! Phase 1b proved a property about gzip using a test double that lived in
//! gzip's own private test module. That does not survive contact with nine
//! codecs: the double gets copy-pasted, or quietly skipped for exactly the
//! codec where the property is hardest to satisfy. Here, adopting the whole
//! set costs one line and skipping a property is impossible without editing
//! shared code a reviewer reads.
//!
//! Properties that do not apply to a given codec are skipped on evidence
//! rather than on trust: magic from the registered rules, trailer presence by
//! measurement, corruption detection from a declared capability.
//!
//! A codec that cannot encode its own test input — the pure-Rust decode-only
//! fallbacks `Registry::require_decoder` is written for — cannot exercise
//! properties 7 through 10 by itself. [`assert_codec_conforms_with`] accepts a
//! `fixture`: a known-good encoded stream, supplied by the caller, that stands
//! in for the codec's own encode step. A decode-capable codec given neither an
//! `encode` capability nor a fixture skips those properties with a message
//! naming what is missing, rather than silently passing having exercised
//! nothing.
//!
//! Every codec is also checked for identity: `FormatMeta::id` must agree with
//! `Codec::id`, or a mismatched registration is silent. That check is not part
//! of the numbered list below — it is a registration sanity check, not a
//! property of encode/decode behavior — but its panic still says "property 1"
//! for the same reason every other panic is numbered: so a failure names
//! exactly which property broke.
//!
//! The behavioral properties, numbered to match each assertion's panic
//! message:
//!
//! 2. Round trip: encode then decode returns the original bytes, checked
//!    empty, one byte, and with a large incompressible payload.
//! 3. Magic agreement: encoded output matches AT LEAST ONE magic rule the
//!    format registers, so a file this build wrote is a file it can identify.
//!    A format with alternative signatures (lz4's frame and legacy-frame
//!    magics, zstd's legacy magic) registers more than one rule and only one
//!    need match.
//! 4. `finish()` flushes the underlying writer, since `Codec::encoder` takes
//!    the destination by value and leaves the caller no handle to do it.
//! 5. `finish()` surfaces a write error that `Drop` would otherwise swallow.
//!    The failure threshold is measured per codec by counting bytes written
//!    by a real encode, not assumed — a wrong threshold tests `Write` instead
//!    of `finish`, or never fails at all.
//! 6. An out-of-range level — probed at both ends, `i32::MIN` and `i32::MAX`,
//!    not just the upper bound — is either accepted or a `Usage` error, never
//!    a panic or another error variant, and `encoder()` agrees with
//!    `check_encode_opts()` on the same options.
//! 7. The decoder claims random access only if the format declares a frame
//!    index, or a container above it would seek and read the wrong bytes.
//! 8. Decoding is incremental, not read-to-end: output must begin long before
//!    the input is exhausted. The threshold is relative to the stream's own
//!    length, not an absolute figure tuned to one codec's window.
//! 9. Corrupted input is reported as `InvalidData`, gated on the codec's own
//!    declared `detects_corruption` — a format with no integrity check
//!    genuinely cannot detect corruption, and demanding it would force a fake.
//! 10. Truncated input is rejected. Unlike property 9, nothing can switch
//!     this off: every framed format detects premature EOF regardless of
//!     checksum, so a codec failing this should either detect truncation or
//!     be reconsidered — a raw, unframed stream that fails here honestly has
//!     no `detects_corruption: true` to claim anyway.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::archive::{Codec, DecodeOpts, EncodeOpts};
use crate::format::{CodecCaps, FormatMeta};
use crate::source::{ReaderSource, Source};
use crate::testing::SharedBuf;

/// A pseudo-random, incompressible payload.
///
/// Deliberately NOT a repeating pattern. Phase 1b's incrementality test used
/// `i % 251`, which gzip took from 16 MiB down to 65 KB — small enough that a
/// read-to-end decoder passed the test anyway. Incompressibility is what makes
/// the input large after encoding, and that is what the property depends on.
pub fn incompressible(len: usize) -> Vec<u8> {
    let mut s: u32 = 1;
    (0..len)
        .map(|_| {
            s = s.wrapping_mul(1103515245).wrapping_add(12345);
            (s >> 16) as u8
        })
        .collect()
}

/// The plaintext size property 8 encodes when the codec can encode its own
/// input.
///
/// Shrunk from Phase 1b's 8 MiB: the relative threshold (see property 8)
/// discriminates against a read-to-end decoder regardless of absolute size,
/// so the payload only needs to stay comfortably incompressible, not huge.
/// Smaller keeps every codec's suite fast, including the slow ones (bzip2 -9,
/// xz -6, brotli q11) arriving in Phase 1d.
const PROPERTY_8_PLAIN_LEN: usize = 2 * 1024 * 1024;

fn encode(codec: &dyn Codec, plain: &[u8]) -> Vec<u8> {
    let id = codec.id();
    let buf = SharedBuf::new();
    let mut sink = codec
        .encoder(Box::new(buf.clone()), &EncodeOpts::default())
        .unwrap_or_else(|e| panic!("conformance[{id}] encoder: {e}"));
    sink.write_all(plain)
        .unwrap_or_else(|e| panic!("conformance[{id}] write: {e}"));
    sink.finish()
        .unwrap_or_else(|e| panic!("conformance[{id}] finish: {e}"));
    buf.contents()
}

fn decode(codec: &dyn Codec, packed: Vec<u8>) -> Vec<u8> {
    let id = codec.id();
    let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
    let mut dec = codec
        .decoder(src, &DecodeOpts::default())
        .unwrap_or_else(|e| panic!("conformance[{id}] decoder: {e}"));
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .unwrap_or_else(|e| panic!("conformance[{id}] read_to_end: {e}"));
    out
}

/// Supplies the encoded stream properties 7-10 need: the codec's own encode
/// when it can, otherwise the caller-supplied fixture.
///
/// `None` means neither is available — a decode-only codec was handed no
/// fixture — and the caller must skip with a message naming what to pass.
fn test_input(
    caps: CodecCaps,
    fixture: Option<&[u8]>,
    make: impl FnOnce() -> Vec<u8>,
) -> Option<Vec<u8>> {
    if caps.encode {
        Some(make())
    } else {
        fixture.map(<[u8]>::to_vec)
    }
}

fn skip_no_fixture(id: crate::format::FormatId, property: u32) {
    eprintln!(
        "conformance[{id}] property {property}: skipped — this codec cannot encode its own \
         test input and no fixture was supplied; pass one via assert_codec_conforms_with"
    );
}

/// Asserts every conformance property that applies to `codec`, using `fixture`
/// as the encoded test input for a codec that cannot encode its own — see the
/// module docs.
pub fn assert_codec_conforms_with(codec: &dyn Codec, meta: &FormatMeta, fixture: Option<&[u8]>) {
    let id = codec.id();
    let caps = codec.caps();

    // 1. Identity: a mismatched registration is otherwise silent.
    assert_eq!(
        meta.id, id,
        "conformance[{id}] property 1: FormatMeta::id ({}) disagrees with Codec::id ({id})",
        meta.id
    );

    if caps.encode && caps.decode {
        // 2. Round trip. Empty first: it is where codecs most often break,
        //    because a zero-length body still needs a header and trailer.
        for (label, plain) in [
            ("empty", Vec::new()),
            ("one byte", vec![0x42]),
            ("1 MiB incompressible", incompressible(1024 * 1024)),
        ] {
            let packed = encode(codec, &plain);
            let back = decode(codec, packed);
            assert_eq!(
                back, plain,
                "conformance[{id}] property 2: {label} did not round-trip"
            );
        }
    }

    if caps.encode && !meta.magics.is_empty() {
        // 3. Magic agreement: AT LEAST ONE registered rule must match, not
        //    every one. A format with alternative signatures — lz4 registers
        //    a frame magic and a legacy-frame magic, zstd has a legacy magic
        //    — would otherwise fail outright on its second or third rule.
        let packed = encode(codec, b"conformance");
        let matched = meta.magics.iter().any(|rule| {
            let start = rule.offset;
            let end = start + rule.bytes.len();
            packed.len() >= end && &packed[start..end] == rule.bytes
        });
        if !matched {
            let tried: Vec<String> = meta
                .magics
                .iter()
                .map(|r| format!("offset {} expects {:02x?}", r.offset, r.bytes))
                .collect();
            let seen = &packed[..packed.len().min(16)];
            panic!(
                "conformance[{id}] property 3: encoded output matched none of its registered \
                 magic rules (tried: {}); output began with {seen:02x?}",
                tried.join(", ")
            );
        }
    }

    if caps.encode {
        // 6. An absurd level — probed at both ends, since a codec validating
        //    only `n > max` while indexing an array by `level` panics on a
        //    negative one just as readily — is either accepted (the codec has
        //    no levels) or a Usage error. Never a panic, never another
        //    variant: a level is a user-supplied number and it must not be
        //    able to produce a misleading error class. `encoder()` must agree
        //    with `check_encode_opts()` on the very same options in both
        //    directions: a codec whose `encoder()` does not re-validate would
        //    otherwise pass this property while still mishandling an absurd
        //    level on the real encode path, and `check_encode_opts` is a
        //    pre-flight call a codec could easily forget to also apply where
        //    it matters.
        for level in [i32::MIN, -1, i32::MAX] {
            let opts = EncodeOpts {
                level: Some(level),
                ..Default::default()
            };
            match codec.check_encode_opts(&opts) {
                Ok(()) => {
                    let encoder_result = codec.encoder(Box::new(SharedBuf::new()), &opts);
                    assert!(
                        !matches!(encoder_result, Err(crate::Error::Usage(_))),
                        "conformance[{id}] property 6: level {level} passed check_encode_opts \
                         but encoder() rejected it as Error::Usage — the two must agree"
                    );
                }
                Err(crate::Error::Usage(_)) => {
                    let encoder_result = codec.encoder(Box::new(SharedBuf::new()), &opts);
                    assert!(
                        matches!(encoder_result, Err(crate::Error::Usage(_))),
                        "conformance[{id}] property 6: level {level} was rejected by \
                         check_encode_opts as Error::Usage, but encoder() did not also reject \
                         it as Error::Usage — encoder() must re-validate, not rely on a \
                         pre-flight caller checked separately"
                    );
                }
                Err(other) => panic!(
                    "conformance[{id}] property 6: level {level} produced {other:?} from \
                     check_encode_opts, expected Ok or Error::Usage"
                ),
            }
        }
    }

    if caps.encode {
        // 4. finish() flushes the underlying writer.
        //
        // `Codec::encoder` takes the destination by value, so after handing it
        // over the caller holds no handle to flush. Forgetting is silent on an
        // unbuffered File and loses the tail on a buffered destination —
        // stdout's LineWriter auto-flushes only on '\n', which a run of binary
        // output may not contain.
        #[derive(Clone)]
        struct FlushSpy(Arc<std::sync::atomic::AtomicBool>);
        impl Write for FlushSpy {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.store(true, Ordering::Relaxed);
                Ok(())
            }
        }
        let flushed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut sink = codec
            .encoder(
                Box::new(FlushSpy(Arc::clone(&flushed))),
                &EncodeOpts::default(),
            )
            .unwrap_or_else(|e| panic!("conformance[{id}] property 4 encoder: {e}"));
        sink.write_all(b"conformance")
            .unwrap_or_else(|e| panic!("conformance[{id}] property 4 write: {e}"));
        sink.finish()
            .unwrap_or_else(|e| panic!("conformance[{id}] property 4 finish: {e}"));
        assert!(
            flushed.load(Ordering::Relaxed),
            "conformance[{id}] property 4: finish() did not flush the underlying writer"
        );

        // 5. finish() surfaces a write error that Drop would swallow.
        //
        // The threshold is MEASURED, not assumed: encode through a counter and
        // see how many bytes land before finish. A writer that fails earlier
        // would fail inside write_all, testing Write rather than finish; one
        // that fails later never fails at all. gzip's figure is its 10-byte
        // header; every codec's differs, which is why this is computed.
        struct Counting(Arc<AtomicU64>);
        impl Write for Counting {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.fetch_add(b.len() as u64, Ordering::Relaxed);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let count = Arc::new(AtomicU64::new(0));
        let mut sink = codec
            .encoder(
                Box::new(Counting(Arc::clone(&count))),
                &EncodeOpts::default(),
            )
            .unwrap_or_else(|e| panic!("conformance[{id}] property 5 encoder: {e}"));
        sink.write_all(b"conformance")
            .unwrap_or_else(|e| panic!("conformance[{id}] property 5 write: {e}"));
        let before_finish = count.load(Ordering::Relaxed);
        sink.finish()
            .unwrap_or_else(|e| panic!("conformance[{id}] property 5 finish: {e}"));
        let after_finish = count.load(Ordering::Relaxed);

        if after_finish > before_finish {
            // finish emits bytes, so there is something for a failing writer to
            // reject. A codec whose finish emits nothing (a raw stream with no
            // trailer) is skipped: the property is vacuous, not violated.
            struct FailAfter {
                budget: u64,
                written: u64,
            }
            impl Write for FailAfter {
                fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                    if self.written >= self.budget {
                        return Err(std::io::Error::other("conformance: writer failed"));
                    }
                    let n = std::cmp::min(b.len() as u64, self.budget - self.written);
                    self.written += n;
                    Ok(n as usize)
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut sink = codec
                .encoder(
                    Box::new(FailAfter {
                        budget: before_finish,
                        written: 0,
                    }),
                    &EncodeOpts::default(),
                )
                .unwrap_or_else(|e| panic!("conformance[{id}] property 5 encoder: {e}"));
            sink.write_all(b"conformance").unwrap_or_else(|e| {
                panic!("conformance[{id}] property 5: pre-finish writes must succeed: {e}")
            });
            assert!(
                sink.finish().is_err(),
                "conformance[{id}] property 5: finish() swallowed a write error \
                 that Drop would also have swallowed"
            );
        }
    }

    if caps.decode {
        // 7. The decoder claims random access only if the format has an index.
        //    A container above would otherwise seek and read wrong bytes.
        match test_input(caps, fixture, || encode(codec, b"conformance")) {
            Some(packed) => {
                let src: Box<dyn Source> =
                    Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
                let dec = codec
                    .decoder(src, &DecodeOpts::default())
                    .unwrap_or_else(|e| panic!("conformance[{id}] property 7 decoder: {e}"));
                assert!(
                    !dec.caps().seekable || caps.frame_index,
                    "conformance[{id}] property 7: decoder claims seekable without frame_index"
                );
            }
            None => skip_no_fixture(id, 7),
        }

        // 8. Decoding is incremental, not read-to-end. Peak heap is not
        //    observable from a test without a custom allocator, so the
        //    measurable property is that output begins long before the input
        //    is exhausted. The threshold is relative to the stream's own
        //    length — `consumed < len / 4` — rather than an absolute figure:
        //    an absolute 1 MiB threshold is tuned to gzip's 32 KiB window and
        //    wrongly fails a codec whose block or window is merely a few
        //    hundred KiB to a few MiB (bzip2's 900 KiB block, brotli's and
        //    lz4's multi-MiB window/block options), while a relative
        //    threshold still discriminates decisively against a read-to-end
        //    implementation, which always consumes the input exactly.
        match test_input(caps, fixture, || {
            encode(codec, &incompressible(PROPERTY_8_PLAIN_LEN))
        }) {
            Some(big) => {
                if caps.encode {
                    assert!(
                        big.len() > PROPERTY_8_PLAIN_LEN / 2,
                        "conformance[{id}] property 8: incompressible input did not stay large \
                         once encoded, so this property cannot discriminate"
                    );
                }
                let big_len = big.len() as u64;

                struct Metered {
                    inner: std::io::Cursor<Vec<u8>>,
                    served: Arc<AtomicU64>,
                }
                impl Read for Metered {
                    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                        let n = self.inner.read(buf)?;
                        self.served.fetch_add(n as u64, Ordering::Relaxed);
                        Ok(n)
                    }
                }
                impl Source for Metered {
                    fn caps(&self) -> crate::source::SourceCaps {
                        crate::source::SourceCaps {
                            seekable: false,
                            len: None,
                        }
                    }
                    fn as_seek(&mut self) -> Option<&mut dyn crate::source::SeekRead> {
                        None
                    }
                }

                let served = Arc::new(AtomicU64::new(0));
                let src: Box<dyn Source> = Box::new(Metered {
                    inner: std::io::Cursor::new(big),
                    served: Arc::clone(&served),
                });
                let mut dec = codec
                    .decoder(src, &DecodeOpts::default())
                    .unwrap_or_else(|e| panic!("conformance[{id}] property 8 decoder: {e}"));
                let mut first = [0u8; 1024];
                let n = dec
                    .read(&mut first)
                    .unwrap_or_else(|e| panic!("conformance[{id}] property 8 first read: {e}"));
                assert!(
                    n > 0,
                    "conformance[{id}] property 8: decoder produced no output"
                );
                let consumed = served.load(Ordering::Relaxed);
                let threshold = big_len / 4;
                assert!(
                    consumed < threshold,
                    "conformance[{id}] property 8: first output arrived only after reading \
                     {consumed} of {big_len} bytes (threshold {threshold}); a read-to-end \
                     implementation looks exactly like this"
                );
            }
            None => skip_no_fixture(id, 8),
        }

        // Shared base for properties 9 and 10: a modest incompressible
        // payload, encoded (or drawn from the fixture) once.
        let corruption_input =
            test_input(caps, fixture, || encode(codec, &incompressible(64 * 1024)));

        // 9. Corrupted input is reported as InvalidData — declared, because a
        //    format with no integrity check genuinely cannot detect it and a
        //    harness that demanded it would force a fake.
        if caps.detects_corruption {
            match &corruption_input {
                Some(base) => {
                    let mut bytes = base.clone();
                    let mid = bytes.len() / 2;
                    bytes[mid] ^= 0xFF;
                    let src: Box<dyn Source> =
                        Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
                    let mut dec = codec
                        .decoder(src, &DecodeOpts::default())
                        .unwrap_or_else(|e| panic!("conformance[{id}] property 9 decoder: {e}"));
                    let mut out = Vec::new();
                    match dec.read_to_end(&mut out) {
                        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {}
                        Err(e) => panic!(
                            "conformance[{id}] property 9: corrupted input gave {:?}, expected \
                             InvalidData — Error::from_decode_io keys exit 5 off that kind",
                            e.kind()
                        ),
                        Ok(_) => panic!(
                            "conformance[{id}] property 9: corrupted input decoded without \
                             error, but this codec declares detects_corruption = true"
                        ),
                    }
                }
                None => skip_no_fixture(id, 9),
            }
        }

        // 10. Truncated input is rejected. Gated on caps.decode alone, not on
        //     detects_corruption: no declaration can switch this one off. The
        //     incentive on a red property 9 at 11pm is to flip
        //     detects_corruption to false, and the only consequence used to
        //     be that property 9 disappeared. A framed format detects
        //     premature EOF regardless of checksum — gzip, zstd, bzip2, xz,
        //     brotli, lz4 frame and framed snappy all do. A raw, unframed
        //     stream honestly does not, and honestly fails here — the right
        //     outcome for a format that would have declared
        //     detects_corruption: false anyway.
        match &corruption_input {
            Some(base) if !base.is_empty() => {
                let mid = base.len() / 2;
                let truncated = base[..mid].to_vec();
                let src: Box<dyn Source> =
                    Box::new(ReaderSource::new(std::io::Cursor::new(truncated)));
                let mut dec = codec
                    .decoder(src, &DecodeOpts::default())
                    .unwrap_or_else(|e| panic!("conformance[{id}] property 10 decoder: {e}"));
                let mut out = Vec::new();
                assert!(
                    dec.read_to_end(&mut out).is_err(),
                    "conformance[{id}] property 10: truncated input decoded without error; a \
                     codec failing this should either detect truncation or be reconsidered"
                );
            }
            Some(_) => {}
            None => skip_no_fixture(id, 10),
        }
    }
}

/// Asserts every conformance property that applies to `codec`.
///
/// Equivalent to `assert_codec_conforms_with(codec, meta, None)` — for a codec
/// that can encode its own test input. See [`assert_codec_conforms_with`] for
/// a codec that cannot.
pub fn assert_codec_conforms(codec: &dyn Codec, meta: &FormatMeta) {
    assert_codec_conforms_with(codec, meta, None)
}

/// A minimally FRAMED double, built only to prove the harness's full property
/// set — including 9 and 10, which need an actual integrity check — can be
/// satisfied by a well-behaved codec.
///
/// `testing::MockCodec` stays a bare XOR pass-through: dozens of unrelated
/// tests (governor, ladder, container) rely on it being exactly that, with no
/// framing to get in the way. Property 10 is unconditional on any
/// decode-capable codec (see its module docs), and a bare XOR stream — like
/// the raw deflate the module docs describe — has no way to notice its input
/// was cut short, so `MockCodec` itself can no longer be the "conforms to
/// everything" fixture once property 10 exists. `FramedMock` is that fixture
/// instead, kept local to this test module so the change carries no weight
/// anywhere else.
///
/// Wire format: XOR(payload) followed by a 4-byte big-endian checksum of the
/// XORed bytes — the same shape a real codec's CRC trailer takes, just with a
/// byte-sum instead of a CRC32. That single trailer is what lets one double
/// stand in for both properties: missing or short means truncated (10),
/// present but wrong means corrupted (9).
#[cfg(test)]
mod framed_mock {
    use super::*;
    use crate::archive::Sink;

    const TRAILER_LEN: usize = 4;

    fn fold(sum: u32, byte: u8) -> u32 {
        sum.wrapping_mul(31).wrapping_add(byte as u32)
    }

    pub struct FramedMock;

    impl Codec for FramedMock {
        fn id(&self) -> crate::format::FormatId {
            crate::testing::MOCK_CODEC
        }

        fn caps(&self) -> CodecCaps {
            CodecCaps {
                encode: true,
                decode: true,
                detects_corruption: true,
                ..Default::default()
            }
        }

        fn decoder(&self, src: Box<dyn Source>, _o: &DecodeOpts) -> crate::Result<Box<dyn Source>> {
            Ok(Box::new(crate::source::StreamOnly::new(FramedReader {
                inner: src,
                pending: std::collections::VecDeque::new(),
                sum: 0,
                inner_eof: false,
                trailer_ok: None,
            })))
        }

        fn encoder(
            &self,
            dst: Box<dyn Write + Send>,
            _o: &EncodeOpts,
        ) -> crate::Result<Box<dyn Sink>> {
            Ok(Box::new(FramedSink { dst, sum: 0 }))
        }
    }

    struct FramedSink {
        dst: Box<dyn Write + Send>,
        sum: u32,
    }

    impl Write for FramedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let flipped: Vec<u8> = buf.iter().map(|b| b ^ 0xFF).collect();
            self.dst.write_all(&flipped)?;
            self.sum = flipped.iter().fold(self.sum, |acc, &b| fold(acc, b));
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.dst.flush()
        }
    }

    impl Sink for FramedSink {
        fn finish(mut self: Box<Self>) -> crate::Result<()> {
            self.dst.write_all(&self.sum.to_be_bytes())?;
            self.dst.flush()?;
            Ok(())
        }
    }

    /// Un-XORs the wire bytes it is handed, holding back the last
    /// `TRAILER_LEN` bytes at all times (they might still turn out to be the
    /// trailer, not payload) until the inner reader reports EOF, at which
    /// point the held-back bytes must equal the checksum of everything
    /// emitted plus everything still queued — computed as a read-only preview
    /// so the real running `sum` is only ever advanced by bytes actually
    /// handed to the caller, exactly once each.
    struct FramedReader<R> {
        inner: R,
        pending: std::collections::VecDeque<u8>,
        sum: u32,
        inner_eof: bool,
        trailer_ok: Option<bool>,
    }

    impl<R: Read> Read for FramedReader<R> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.trailer_ok == Some(false) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "framed mock: truncated or corrupted stream",
                ));
            }
            if self.trailer_ok == Some(true) && self.pending.is_empty() {
                return Ok(0);
            }

            while !self.inner_eof && self.pending.len() <= TRAILER_LEN {
                let mut chunk = [0u8; 4096];
                let n = self.inner.read(&mut chunk)?;
                if n == 0 {
                    self.inner_eof = true;
                } else {
                    self.pending.extend(chunk[..n].iter().copied());
                }
            }

            if self.inner_eof && self.trailer_ok.is_none() {
                if self.pending.len() >= TRAILER_LEN {
                    let split_at = self.pending.len() - TRAILER_LEN;
                    let projected = self
                        .pending
                        .iter()
                        .take(split_at)
                        .fold(self.sum, |acc, &b| fold(acc, b));
                    let trailer_bytes: Vec<u8> =
                        self.pending.iter().skip(split_at).copied().collect();
                    let got = u32::from_be_bytes(trailer_bytes.try_into().unwrap());
                    self.trailer_ok = Some(got == projected);
                    if self.trailer_ok == Some(true) {
                        self.pending.truncate(split_at);
                    }
                } else {
                    self.trailer_ok = Some(false);
                }
                if self.trailer_ok == Some(false) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "framed mock: truncated or corrupted stream",
                    ));
                }
            }

            let safe = if self.trailer_ok == Some(true) {
                self.pending.len()
            } else {
                self.pending.len().saturating_sub(TRAILER_LEN)
            };
            let n = safe.min(out.len());
            for slot in out.iter_mut().take(n) {
                let b = self.pending.pop_front().expect("counted as safe above");
                self.sum = fold(self.sum, b);
                *slot = b ^ 0xFF;
            }
            Ok(n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{FormatId, FormatMeta, MagicRule};
    use crate::testing::{MOCK_CODEC, MockCodec};
    use framed_mock::FramedMock;

    #[test]
    fn the_mock_codec_conforms() {
        // MockCodec registers no magic, so property 3 is skipped on evidence
        // rather than waived. That is the point of running the harness against
        // two shapes: one that satisfies every property and one that honestly
        // does not. MockCodec's own bare XOR stream has no framing, so it
        // cannot pass property 10 (truncation, unconditional — see the module
        // docs); FramedMock stands in as the fully-conforming shape.
        assert_codec_conforms(&FramedMock, &FormatMeta::codec(MOCK_CODEC, &["mock"], &[]));
    }

    #[test]
    fn a_codec_conforms_when_only_one_of_several_registered_magics_matches() {
        // The direct regression test for A1: lz4 registers a frame magic AND
        // a legacy-frame magic; zstd has a legacy magic. Property 3 must
        // accept a codec whose output matches at least one registered rule,
        // not demand every one. FramedMock XORs "conformance" with 0xFF, so
        // its output begins with 0x63^0xFF, 0x6F^0xFF = 0x9C, 0x90.
        const MAGICS: &[MagicRule] = &[
            MagicRule {
                offset: 0,
                bytes: &[0x9C, 0x90],
                format: MOCK_CODEC,
            },
            MagicRule {
                offset: 0,
                bytes: &[0x00, 0x00],
                format: MOCK_CODEC,
            },
        ];
        assert_codec_conforms(
            &FramedMock,
            &FormatMeta::codec(MOCK_CODEC, &["mock"], MAGICS),
        );
    }

    #[test]
    fn a_decode_only_codec_is_tested_from_a_fixture() {
        // The motivating shape: the pure-Rust zstd/xz fallbacks from spec
        // §1.3, which can decode but not encode. Build a fixture the normal
        // way (through the real encoder), then hand the harness only the
        // decode half plus that fixture — properties 7-10 must still run.
        struct DecodeOnlyMock;
        impl Codec for DecodeOnlyMock {
            fn id(&self) -> FormatId {
                MOCK_CODEC
            }
            fn caps(&self) -> CodecCaps {
                CodecCaps {
                    decode: true,
                    detects_corruption: true,
                    ..Default::default()
                }
            }
            fn decoder(
                &self,
                src: Box<dyn Source>,
                o: &DecodeOpts,
            ) -> crate::Result<Box<dyn Source>> {
                FramedMock.decoder(src, o)
            }
            fn encoder(
                &self,
                _dst: Box<dyn Write + Send>,
                _o: &EncodeOpts,
            ) -> crate::Result<Box<dyn crate::archive::Sink>> {
                panic!("DecodeOnlyMock cannot encode — the harness must never call this")
            }
        }

        let fixture = encode(&FramedMock, &incompressible(256 * 1024));
        assert_codec_conforms_with(
            &DecodeOnlyMock,
            &FormatMeta::codec(MOCK_CODEC, &["mock"], &[]),
            Some(&fixture),
        );
    }

    #[test]
    fn a_decode_only_codec_with_no_fixture_skips_rather_than_panics() {
        // No fixture, no encode capability: properties 7-10 have nothing to
        // run against. The harness must skip visibly, not silently pass by
        // doing nothing, and it must not panic for lack of a fixture either.
        struct DecodeOnlyNoFixture;
        impl Codec for DecodeOnlyNoFixture {
            fn id(&self) -> FormatId {
                MOCK_CODEC
            }
            fn caps(&self) -> CodecCaps {
                CodecCaps {
                    decode: true,
                    ..Default::default()
                }
            }
            fn decoder(
                &self,
                src: Box<dyn Source>,
                o: &DecodeOpts,
            ) -> crate::Result<Box<dyn Source>> {
                MockCodec.decoder(src, o)
            }
            fn encoder(
                &self,
                _dst: Box<dyn Write + Send>,
                _o: &EncodeOpts,
            ) -> crate::Result<Box<dyn crate::archive::Sink>> {
                panic!("DecodeOnlyNoFixture cannot encode — the harness must never call this")
            }
        }

        assert_codec_conforms(
            &DecodeOnlyNoFixture,
            &FormatMeta::codec(MOCK_CODEC, &["mock"], &[]),
        );
    }
}

/// Proof that the harness can actually fail.
///
/// A conformance suite nobody has watched fail is exactly the defect class
/// this project has spent two phases hunting — A1 (property 3's ANY-vs-EVERY
/// bug) shipped because nothing exercised property 3's loop semantics. Each
/// test here builds a codec that breaks exactly one property and asserts,
/// via `catch_unwind`, that `assert_codec_conforms` panics on it. Every
/// broken codec delegates to `MockCodec` for everything except the one thing
/// it deliberately gets wrong.
#[cfg(test)]
mod broken_codecs {
    use super::*;
    use crate::archive::Sink;
    use crate::format::{FormatId, MagicRule};
    use crate::testing::{MOCK_CODEC, MockCodec};
    use std::panic::catch_unwind;

    fn conforms_panics(codec: &dyn Codec, meta: &FormatMeta) {
        let id = codec.id();
        let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_codec_conforms(codec, meta);
        }));
        assert!(
            result.is_err(),
            "conformance[{id}]: expected assert_codec_conforms to panic on a broken codec, \
             but it passed"
        );
    }

    fn mock_meta(magics: &'static [MagicRule]) -> FormatMeta {
        FormatMeta::codec(MOCK_CODEC, &["mock"], magics)
    }

    /// Breaks property 2: encodes as a pass-through (no XOR) but decodes with
    /// the real un-XOR, so encode/decode no longer invert each other.
    struct BrokenRoundTrip;

    struct PassthroughSink(Box<dyn Write + Send>);
    impl Write for PassthroughSink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
    impl Sink for PassthroughSink {
        fn finish(mut self: Box<Self>) -> crate::Result<()> {
            self.0.flush()?;
            Ok(())
        }
    }

    impl Codec for BrokenRoundTrip {
        fn id(&self) -> FormatId {
            MOCK_CODEC
        }
        fn caps(&self) -> CodecCaps {
            MockCodec.caps()
        }
        fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> crate::Result<Box<dyn Source>> {
            MockCodec.decoder(src, o)
        }
        fn encoder(
            &self,
            dst: Box<dyn Write + Send>,
            _o: &EncodeOpts,
        ) -> crate::Result<Box<dyn Sink>> {
            Ok(Box::new(PassthroughSink(dst)))
        }
    }

    #[test]
    fn broken_round_trip_is_caught() {
        conforms_panics(&BrokenRoundTrip, &mock_meta(&[]));
    }

    #[test]
    fn broken_magic_with_no_match_is_caught() {
        // Two candidate rules, neither matching MockCodec's actual output —
        // the multi-magic case A1 introduced ANY-semantics for. The loop
        // must still correctly detect that NEITHER matched, with more than
        // one candidate to check.
        const MAGICS: &[MagicRule] = &[
            MagicRule {
                offset: 0,
                bytes: &[0x00, 0x00],
                format: MOCK_CODEC,
            },
            MagicRule {
                offset: 0,
                bytes: &[0x11, 0x11],
                format: MOCK_CODEC,
            },
        ];
        conforms_panics(&MockCodec, &mock_meta(MAGICS));
    }

    /// Breaks property 4: finish() never flushes the underlying writer.
    struct BrokenFlush;

    struct NoFlushSink(Box<dyn Write + Send>);
    impl Write for NoFlushSink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Sink for NoFlushSink {
        fn finish(self: Box<Self>) -> crate::Result<()> {
            // BUG: never calls self.0.flush().
            Ok(())
        }
    }

    impl Codec for BrokenFlush {
        fn id(&self) -> FormatId {
            MOCK_CODEC
        }
        fn caps(&self) -> CodecCaps {
            MockCodec.caps()
        }
        fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> crate::Result<Box<dyn Source>> {
            MockCodec.decoder(src, o)
        }
        fn encoder(
            &self,
            dst: Box<dyn Write + Send>,
            _o: &EncodeOpts,
        ) -> crate::Result<Box<dyn Sink>> {
            Ok(Box::new(NoFlushSink(dst)))
        }
    }

    #[test]
    fn broken_flush_is_caught() {
        conforms_panics(&BrokenFlush, &mock_meta(&[]));
    }

    /// Breaks property 5: finish() writes a trailer but swallows the error
    /// if writing it fails, exactly what `Drop` would also have swallowed.
    struct BrokenFinishSwallowsError;

    struct SwallowingSink(Box<dyn Write + Send>);
    impl Write for SwallowingSink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
    impl Sink for SwallowingSink {
        fn finish(mut self: Box<Self>) -> crate::Result<()> {
            // BUG: a real trailer write whose error is ignored.
            let _ = self.0.write_all(b"TRAILER");
            let _ = self.0.flush();
            Ok(())
        }
    }

    impl Codec for BrokenFinishSwallowsError {
        fn id(&self) -> FormatId {
            MOCK_CODEC
        }
        fn caps(&self) -> CodecCaps {
            MockCodec.caps()
        }
        fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> crate::Result<Box<dyn Source>> {
            MockCodec.decoder(src, o)
        }
        fn encoder(
            &self,
            dst: Box<dyn Write + Send>,
            _o: &EncodeOpts,
        ) -> crate::Result<Box<dyn Sink>> {
            Ok(Box::new(SwallowingSink(dst)))
        }
    }

    #[test]
    fn broken_finish_swallowing_a_write_error_is_caught() {
        conforms_panics(&BrokenFinishSwallowsError, &mock_meta(&[]));
    }

    /// Breaks property 6: `check_encode_opts` accepts every level (the
    /// default impl), but `encoder()` indexes an array by the raw level —
    /// the classic lower-bound panic a validator that only checks `n > max`
    /// leaves open.
    struct BrokenLevelPanics;

    impl Codec for BrokenLevelPanics {
        fn id(&self) -> FormatId {
            MOCK_CODEC
        }
        fn caps(&self) -> CodecCaps {
            MockCodec.caps()
        }
        fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> crate::Result<Box<dyn Source>> {
            MockCodec.decoder(src, o)
        }
        fn encoder(
            &self,
            dst: Box<dyn Write + Send>,
            o: &EncodeOpts,
        ) -> crate::Result<Box<dyn Sink>> {
            let level = o.level.unwrap_or(0);
            if level > 22 {
                return Err(crate::Error::Usage("level too high".into()));
            }
            let table = [1u8, 2, 3];
            let _ = table[level as usize]; // BUG: panics for level < 0 or level > 2.
            MockCodec.encoder(dst, o)
        }
    }

    #[test]
    fn broken_level_validation_is_caught() {
        conforms_panics(&BrokenLevelPanics, &mock_meta(&[]));
    }

    /// Breaks property 8: decodes by reading the whole input up front, then
    /// serving it from a buffer — indistinguishable from read-to-end.
    struct BrokenIncremental;

    impl Codec for BrokenIncremental {
        fn id(&self) -> FormatId {
            MOCK_CODEC
        }
        fn caps(&self) -> CodecCaps {
            MockCodec.caps()
        }
        fn decoder(
            &self,
            mut src: Box<dyn Source>,
            _o: &DecodeOpts,
        ) -> crate::Result<Box<dyn Source>> {
            let mut all = Vec::new();
            src.read_to_end(&mut all)?; // BUG: eager, whole-stream read.
            for b in &mut all {
                *b ^= 0xFF;
            }
            Ok(Box::new(crate::source::StreamOnly::new(
                std::io::Cursor::new(all),
            )))
        }
        fn encoder(
            &self,
            dst: Box<dyn Write + Send>,
            o: &EncodeOpts,
        ) -> crate::Result<Box<dyn Sink>> {
            MockCodec.encoder(dst, o)
        }
    }

    #[test]
    fn broken_incremental_decode_is_caught() {
        conforms_panics(&BrokenIncremental, &mock_meta(&[]));
    }

    /// Breaks property 9: declares `detects_corruption: true` but the
    /// decoder cannot actually fail on corrupted input (XOR never errors).
    struct LyingAboutCorruption;

    impl Codec for LyingAboutCorruption {
        fn id(&self) -> FormatId {
            MOCK_CODEC
        }
        fn caps(&self) -> CodecCaps {
            CodecCaps {
                detects_corruption: true, // BUG: nothing backs this claim.
                ..MockCodec.caps()
            }
        }
        fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> crate::Result<Box<dyn Source>> {
            MockCodec.decoder(src, o)
        }
        fn encoder(
            &self,
            dst: Box<dyn Write + Send>,
            o: &EncodeOpts,
        ) -> crate::Result<Box<dyn Sink>> {
            MockCodec.encoder(dst, o)
        }
    }

    #[test]
    fn lying_about_corruption_detection_is_caught() {
        conforms_panics(&LyingAboutCorruption, &mock_meta(&[]));
    }
}
