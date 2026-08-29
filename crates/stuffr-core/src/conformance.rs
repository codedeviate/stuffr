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
//! Every codec is also checked for identity: `FormatMeta::id` must agree with
//! `Codec::id`, or a mismatched registration is silent. That check is not part
//! of the numbered list below — it is a registration sanity check, not a
//! property of encode/decode behavior — but its panic still says "property 1"
//! for the same reason every other panic is numbered: so a failure names
//! exactly which property broke.
//!
//! The eight behavioral properties, numbered to match each assertion's panic
//! message:
//!
//! 2. Round trip: encode then decode returns the original bytes, checked
//!    empty, one byte, and with a large incompressible payload.
//! 3. Magic agreement: encoded output matches every magic rule the format
//!    registers, so a file this build wrote is a file it can identify.
//! 4. `finish()` flushes the underlying writer, since `Codec::encoder` takes
//!    the destination by value and leaves the caller no handle to do it.
//! 5. `finish()` surfaces a write error that `Drop` would otherwise swallow.
//!    The failure threshold is measured per codec by counting bytes written
//!    by a real encode, not assumed — a wrong threshold tests `Write` instead
//!    of `finish`, or never fails at all.
//! 6. An out-of-range level is either accepted or a `Usage` error, never a
//!    panic or another error variant, and `encoder()` agrees with
//!    `check_encode_opts()` on the same options.
//! 7. The decoder claims random access only if the format declares a frame
//!    index, or a container above it would seek and read the wrong bytes.
//! 8. Decoding is incremental, not read-to-end: output must begin long before
//!    the input is exhausted.
//! 9. Corrupted input is reported as `InvalidData`, gated on the codec's own
//!    declared `detects_corruption` — a format with no integrity check
//!    genuinely cannot detect corruption, and demanding it would force a fake.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::archive::{Codec, DecodeOpts, EncodeOpts};
use crate::format::FormatMeta;
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

/// Asserts every conformance property that applies to `codec`.
///
/// Panics naming the property and the format. Properties that do not apply are
/// skipped — see the module docs for how each is decided.
pub fn assert_codec_conforms(codec: &dyn Codec, meta: &FormatMeta) {
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
        // 3. Magic agreement: detection and encoding must not disagree, or a
        //    file this build wrote is a file it cannot identify.
        let packed = encode(codec, b"conformance");
        for rule in meta.magics {
            let start = rule.offset;
            let end = start + rule.bytes.len();
            assert!(
                packed.len() >= end,
                "conformance[{id}] property 3: encoded output is shorter than its own magic rule"
            );
            assert_eq!(
                &packed[start..end],
                rule.bytes,
                "conformance[{id}] property 3: encoded output does not match the registered magic"
            );
        }
    }

    if caps.encode {
        // 6. An absurd level is either accepted (the codec has no levels) or a
        //    Usage error. Never a panic, never another variant — a level is a
        //    user-supplied number and it must not be able to produce a
        //    misleading error class. And `encoder()` must agree with
        //    `check_encode_opts()` on the very same options: a codec whose
        //    `encoder()` does not re-validate would otherwise pass this
        //    property while still mishandling an absurd level on the real
        //    encode path — `check_encode_opts` is a pre-flight call a codec
        //    could easily forget to also apply where it matters.
        let opts = EncodeOpts {
            level: Some(i32::MAX),
            ..Default::default()
        };
        let check_result = match codec.check_encode_opts(&opts) {
            Ok(()) => Ok(()),
            Err(crate::Error::Usage(_)) => Err(()),
            Err(other) => panic!(
                "conformance[{id}] property 6: an out-of-range level produced {other:?}, \
                 expected Ok or Error::Usage"
            ),
        };
        let encoder_result = codec.encoder(Box::new(SharedBuf::new()), &opts);
        match check_result {
            Err(()) => assert!(
                encoder_result.is_err(),
                "conformance[{id}] property 6: check_encode_opts rejected the level but \
                 encoder() accepted it — encoder() must re-validate, not rely on a \
                 pre-flight caller checked separately"
            ),
            Ok(()) => assert!(
                !matches!(encoder_result, Err(crate::Error::Usage(_))),
                "conformance[{id}] property 6: check_encode_opts accepted the level but \
                 encoder() rejected it on level grounds — the two must agree"
            ),
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
        let packed = if caps.encode {
            encode(codec, b"conformance")
        } else {
            Vec::new()
        };
        if caps.encode {
            let src: Box<dyn Source> =
                Box::new(ReaderSource::new(std::io::Cursor::new(packed.clone())));
            let dec = codec
                .decoder(src, &DecodeOpts::default())
                .unwrap_or_else(|e| panic!("conformance[{id}] property 7 decoder: {e}"));
            assert!(
                !dec.caps().seekable || caps.frame_index,
                "conformance[{id}] property 7: decoder claims seekable without frame_index"
            );
        }

        // 8. Decoding is incremental, not read-to-end. Peak heap is not
        //    observable from a test without a custom allocator, so the
        //    measurable property is that output begins long before the input is
        //    exhausted. The payload must be incompressible or the whole stream
        //    is small enough that a read-to-end implementation passes anyway.
        if caps.encode {
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

            let big = encode(codec, &incompressible(8 * 1024 * 1024));
            assert!(
                big.len() > 1024 * 1024,
                "conformance[{id}] property 8: incompressible input did not stay large \
                 once encoded, so this property cannot discriminate"
            );
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
            assert!(
                consumed < 1024 * 1024,
                "conformance[{id}] property 8: first output arrived only after reading \
                 {consumed} bytes; a read-to-end implementation looks exactly like this"
            );
        }

        // 9. Corrupted input is reported as InvalidData — declared, because a
        //    format with no integrity check genuinely cannot detect it and a
        //    harness that demanded it would force a fake.
        if caps.encode && caps.detects_corruption {
            let mut bytes = encode(codec, &incompressible(64 * 1024));
            let mid = bytes.len() / 2;
            bytes[mid] ^= 0xFF;
            let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(bytes)));
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
                    "conformance[{id}] property 9: corrupted input decoded without error, \
                     but this codec declares detects_corruption = true"
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::FormatMeta;
    use crate::testing::{MOCK_CODEC, MockCodec};

    #[test]
    fn the_mock_codec_conforms() {
        // MockCodec registers no magic, so property 3 is skipped on evidence
        // rather than waived. That is the point of running the harness against
        // two shapes: one that satisfies every property and one that honestly
        // does not.
        assert_codec_conforms(&MockCodec, &FormatMeta::codec(MOCK_CODEC, &["mock"], &[]));
    }
}
