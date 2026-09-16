#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Read;
use stuffr_core::testing::{CODEC_SLOTS, check_error_is_classified};
use stuffr_core::{DecodeOpts, FormatId};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let name = CODEC_SLOTS[selector as usize % CODEC_SLOTS.len()];

    let registry = stuffr::registry();
    // A slot this build did not register is skipped, not an error: `zstd-c`
    // exists in one tier and not the other. Erroring would make the target
    // unusable on the default tier.
    let Some(codec) = registry.codec(FormatId::new(name)) else {
        return;
    };

    let opts = DecodeOpts {
        // Bounded, or the fuzzer finds xz's declared-dictionary allocation in
        // seconds (69.35 MB from a 60-byte file, measured in Phase 1f) and
        // every run afterwards is an OOM rather than a finding. Bounded, a
        // genuinely unbounded allocation still surfaces.
        memory_limit: Some(64 * 1024 * 1024),
        ..Default::default()
    };

    // `ReaderSource::new(Cursor::new(..))` is how `conformance.rs` builds a
    // Source from bytes (four call sites). There is no `MemorySource`.
    let src = stuffr_core::ReaderSource::new(std::io::Cursor::new(payload.to_vec()));
    match codec.decoder(Box::new(src), &opts) {
        Err(e) => check_error_is_classified(&e).expect("decoder error classification"),
        Ok(mut decoded) => {
            // Bounded output, not just the bounded pre-flight allocation
            // above: an unconditional `read_to_end` on a small, well-formed,
            // highly compressible input (a decompression bomb) would trip
            // libFuzzer's own `-rss_limit_mb` and report a "crash" that is
            // not a finding about `stuffr` at all — the exact false-positive
            // `memory_limit` above exists to avoid, one layer further out.
            // Hitting the cap is a normal return, not a failure: the point
            // is only to stop reading, never to assert anything about a
            // ratio (that is `--max-ratio`'s job at the `ops` layer, not
            // this target's).
            const MAX_OUTPUT: usize = 64 * 1024 * 1024;
            let mut buf = [0u8; 64 * 1024];
            let mut total = 0usize;
            loop {
                if total >= MAX_OUTPUT {
                    break;
                }
                match decoded.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(e) => {
                        // `from_decode_io`, not the bare `Error::from`: an
                        // `io::Error` here is EXPECTED to be malformed-input
                        // `InvalidData` for hostile bytes, which this
                        // boundary reclassifies to `Error::Corrupt` (exit
                        // 5) — see `error.rs`'s doc on `from_decode_io` and
                        // its other callers (`ops.rs:823`,
                        // `entries.rs:2031`, `conformance.rs:722/788`). The
                        // bare `From` impl always yields `Error::Io`, always
                        // exit 1, which `check_error_is_classified` always
                        // refuses — an unconditional panic, not an
                        // invariant.
                        let e = stuffr_core::Error::from_decode_io(e);
                        check_error_is_classified(&e).expect("decode-read error classification");
                        break;
                    }
                }
            }
        }
    }
});
