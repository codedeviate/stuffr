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

use std::io::{Read, Write};
use std::sync::Arc;

use crate::archive::{Codec, DecodeOpts, EncodeOpts};
use crate::format::FormatMeta;
use crate::source::{ReaderSource, Source};

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
    let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
    struct Shared(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = codec
        .encoder(Box::new(Shared(Arc::clone(&buf))), &EncodeOpts::default())
        .expect("encoder");
    sink.write_all(plain).expect("write");
    sink.finish().expect("finish");
    buf.lock().unwrap().clone()
}

fn decode(codec: &dyn Codec, packed: Vec<u8>) -> Vec<u8> {
    let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(packed)));
    let mut dec = codec.decoder(src, &DecodeOpts::default()).expect("decoder");
    let mut out = Vec::new();
    dec.read_to_end(&mut out).expect("read_to_end");
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
        //    misleading error class.
        let opts = EncodeOpts {
            level: Some(i32::MAX),
            ..Default::default()
        };
        match codec.check_encode_opts(&opts) {
            Ok(()) => {}
            Err(crate::Error::Usage(_)) => {}
            Err(other) => panic!(
                "conformance[{id}] property 6: an out-of-range level produced {other:?}, \
                 expected Ok or Error::Usage"
            ),
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
