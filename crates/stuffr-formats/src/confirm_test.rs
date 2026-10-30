//! Test helpers for the codecs' confirm functions
//! ([`stuffr_core::ConfirmFn`]): what every codec's own
//! `confirm_accepts_own_output` and `confirm_never_panics_on_short_input`
//! share.
// Each codec's tests use whichever helpers they need, and a build enabling
// only some codecs leaves the others unused.
#![allow(dead_code)]

use std::io::Write;

use stuffr_core::probe::PROBE_LEN;
use stuffr_core::testing::SharedBuf;
use stuffr_core::{Codec, ConfirmFn, EncodeOpts};

/// A few inputs of different shapes: empty, one byte, compressible text,
/// and 256 KiB of incompressible bytes (several blocks for every codec).
pub(crate) fn inputs() -> Vec<Vec<u8>> {
    let mut noise = Vec::with_capacity(256 << 10);
    let mut x: u32 = 0x9e37_79b9;
    while noise.len() < 256 << 10 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        noise.extend_from_slice(&x.to_le_bytes());
    }
    vec![
        Vec::new(),
        b"a".to_vec(),
        b"the quick brown fox jumps over the lazy dog\n".repeat(200),
        noise,
    ]
}

/// `plain` through `codec`'s encoder at `level`.
pub(crate) fn encode(codec: &dyn Codec, plain: &[u8], level: Option<i32>) -> Vec<u8> {
    let buf = SharedBuf::new();
    let opts = EncodeOpts {
        level,
        ..Default::default()
    };
    let mut sink = codec.encoder(Box::new(buf.clone()), &opts).unwrap();
    sink.write_all(plain).unwrap();
    sink.finish().unwrap();
    buf.contents()
}

/// Every cut of `stream` from `from` bytes up to the probe window (or the
/// whole stream) confirms: a stream cut short inside the prefix is still the
/// format's, so a confirm function may only refuse what it can see is wrong.
pub(crate) fn assert_every_cut_confirms(
    what: &str,
    confirm: ConfirmFn,
    stream: &[u8],
    from: usize,
) {
    let end = stream.len().min(PROBE_LEN);
    for cut in from.min(end)..=end {
        assert!(
            confirm(&stream[..cut]),
            "{what}: the first {cut} of {} bytes were refused: {:02x?}",
            stream.len(),
            &stream[..cut.min(24)]
        );
    }
}

/// Every prefix length 0..=64 of `stream` returns a verdict without
/// panicking, and so does each with its last byte replaced by every value.
pub(crate) fn assert_never_panics(confirm: ConfirmFn, stream: &[u8]) {
    for cut in 0..=stream.len().min(64) {
        let _ = confirm(&stream[..cut]);
        if cut > 0 {
            let mut bent = stream[..cut].to_vec();
            for b in 0..=255u8 {
                bent[cut - 1] = b;
                let _ = confirm(&bent);
            }
        }
    }
}
