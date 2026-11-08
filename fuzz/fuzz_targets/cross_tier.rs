//! The C tier against the pure one (0.26.0 Task 7; the 0.20.0 spec's
//! ruling F-a, for brotli and lz4), shared by `compat.rs` and
//! `roundtrip.rs` and compiled only under this crate's `c-backed` feature.
//!
//! **Where both tiers are built.** The compatibility seams register one
//! backend per build: under `c-backed`, `stuffr::brotli_opts` is libbrotli
//! 1.2.1 and `stuffr::lz4_opts` is liblz4 1.11.0 (both vendored, every
//! symbol prefixed `stuffr_`), and their pure halves are not compiled. The
//! registry's `brotli` and `lz4` codecs, though, are pure in every build
//! (the `brotli` crate's `BrotliDecompressStream`, `lz4_flex`'s frame
//! decoder), so a `c-backed` build holds a C and a pure decoder for each
//! format. The pure side compared here is that registry codec, not the
//! seam's own pure tier (the pure-tier legs fuzz that one, with no
//! counterpart).
//!
//! **What is compared, on hostile bytes** ([`check_decoders_agree`]): each
//! decoder's output up to its first refusal, capped at [`OUTPUT_CAP`]. The
//! two must agree on every byte both produced (one may stop earlier: they
//! check different things at different times, and a buffered decoder holds
//! back what an unbuffered one has already written), and when both accept
//! the whole input they must produce the same bytes. On the encoder side
//! (`roundtrip.rs`) each tier must decode the other's output exactly.
//!
//! **The C tier is asserted, not assumed** (the 0.26.0 spec's anti-goal: a
//! C-tier leg that silently builds the pure tier). [`stuffr::lz4_opts::c`]
//! exists only under `lz4-c`, so the `use` below does not compile without
//! it; the two `extern` functions resolve only against the vendored,
//! prefixed libraries, so the link fails without `brotli-c`/`lz4-c`; and
//! [`assert_c_tier`] checks their versions at the first input.

// Each target uses one half (decoders on hostile bytes, or the encoders).
#![allow(dead_code)]

use std::io::Read;
use std::sync::Once;

use stuffr::brotli_opts::{self, EncoderParams, Operation, StreamResult};
use stuffr::lz4_opts::{self, BlockSizeId, DecodeOptions, EncodeOptions};
use stuffr_core::{DecodeOpts, FormatId, ReaderSource, Source};

// Compile-time half of the C-tier assert: this module is liblz4's, present
// only under `stuffr/lz4-c`.
#[allow(unused_imports)]
use stuffr::lz4_opts::c as _the_lz4_c_tier_is_in;

// Link-time half: the vendored libraries' own version functions, under the
// `stuffr_` prefix (`c/*/stuffr-prefix.h`). No other library defines them.
unsafe extern "C" {
    fn stuffr_BrotliDecoderVersion() -> u32;
    fn stuffr_LZ4_versionNumber() -> std::ffi::c_int;
}

/// What each decoder may produce before it is stopped: the sandbox's 8 MiB
/// output budget, the bound the compat runs have.
pub const OUTPUT_CAP: usize = 8 * 1024 * 1024;

/// libbrotli 1.2.1 (`BROTLI_MAKE_HEX_VERSION`: major << 24 | minor << 12 |
/// patch) and liblz4 1.11.0 (`LZ4_VERSION_NUMBER`: major * 10000 + minor *
/// 100 + release), the vendored versions.
const BROTLI_VERSION: u32 = (1 << 24) | (2 << 12) | 1;
const LZ4_VERSION: i32 = 11_100;

/// Fails the run at its first input unless the vendored libraries are the
/// ones linked.
pub fn assert_c_tier() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: both are argument-less getters of a constant.
        let (br, lz) = unsafe { (stuffr_BrotliDecoderVersion(), stuffr_LZ4_versionNumber()) };
        assert_eq!(
            br, BROTLI_VERSION,
            "c-backed: libbrotli is not the vendored 1.2.1"
        );
        assert_eq!(
            lz, LZ4_VERSION,
            "c-backed: liblz4 is not the vendored 1.11.0"
        );
        assert_eq!(
            lz4_opts::liblz4_version(),
            "1.11.0",
            "c-backed: lz4_opts is not on liblz4"
        );
    });
}

/// A decode: what came out, and whether the decoder accepted the whole
/// input (and stopped below the cap).
pub struct Decoded {
    pub bytes: Vec<u8>,
    pub whole: bool,
}

/// The two formats compared, by registry name.
#[derive(Clone, Copy, Debug)]
pub enum Format {
    Brotli,
    Lz4,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Brotli => "brotli",
            Format::Lz4 => "lz4",
        }
    }
}

/// libbrotli over `input`: one stream, no large window, no dictionary (the
/// registry codec's own reading). Whole only at `Success` with no input
/// left (the registry refuses trailing data too).
pub fn c_brotli_decode(input: &[u8]) -> Decoded {
    let mut out = Vec::new();
    let Ok(mut d) = brotli_opts::Decoder::new(false, None) else {
        return Decoded {
            bytes: out,
            whole: false,
        };
    };
    let mut rest = input;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let mut space: &mut [u8] = &mut buf;
        let before = space.len();
        let r = d.decompress_stream(&mut rest, &mut space);
        let made = before - space.len();
        out.extend_from_slice(&buf[..made]);
        if out.len() > OUTPUT_CAP {
            out.truncate(OUTPUT_CAP);
            return Decoded {
                bytes: out,
                whole: false,
            };
        }
        match r {
            StreamResult::NeedsMoreOutput => continue,
            StreamResult::Success => {
                return Decoded {
                    bytes: out,
                    whole: rest.is_empty(),
                };
            }
            StreamResult::NeedsMoreInput | StreamResult::Error => {
                return Decoded {
                    bytes: out,
                    whole: false,
                };
            }
        }
    }
}

/// liblz4's frame decoder over `input`, frame after frame (skippable ones
/// consumed whole), as the lz4 tool walks a stream. A legacy frame stops it
/// (the seam leaves those to its `LegacyDecoder`), as does a magic cut
/// short. Whole only when the input ends exactly at a frame's end.
pub fn c_lz4_decode(input: &[u8]) -> Decoded {
    let mut out = Vec::new();
    let Ok(mut d) = lz4_opts::Decoder::new(&DecodeOptions::default()) else {
        return Decoded {
            bytes: out,
            whole: false,
        };
    };
    let mut pos = 0;
    while pos < input.len() {
        let rest = &input[pos..];
        if rest.len() < 4
            || u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) == lz4_opts::LEGACY_MAGIC
        {
            return Decoded {
                bytes: out,
                whole: false,
            };
        }
        // Fed in 1 KiB pieces, so one call's output (at most ~255 times its
        // input) stays far below the cap before it is checked.
        let mut ended = false;
        for piece in rest.chunks(1024) {
            match d.decompress(piece, &mut out) {
                Ok((used, 0)) => {
                    pos += used;
                    ended = true;
                    break;
                }
                Ok((used, _)) => pos += used,
                Err(_) => {
                    return Decoded {
                        bytes: out,
                        whole: false,
                    };
                }
            }
            if out.len() > OUTPUT_CAP {
                out.truncate(OUTPUT_CAP);
                return Decoded {
                    bytes: out,
                    whole: false,
                };
            }
        }
        if !ended {
            // The input ran out inside a frame.
            return Decoded {
                bytes: out,
                whole: false,
            };
        }
    }
    Decoded {
        bytes: out,
        whole: !input.is_empty(),
    }
}

/// The C decoder of `format`.
pub fn c_decode(format: Format, input: &[u8]) -> Decoded {
    match format {
        Format::Brotli => c_brotli_decode(input),
        Format::Lz4 => c_lz4_decode(input),
    }
}

/// The registry's (pure) codec of `format` over `input`, read to its first
/// error or the cap.
pub fn pure_decode(format: Format, input: &[u8]) -> Decoded {
    let codec = stuffr::registry()
        .codec(FormatId::new(format.name()))
        .expect("brotli and lz4 are registered in every build");
    let src: Box<dyn Source> = Box::new(ReaderSource::new(std::io::Cursor::new(input.to_vec())));
    let opts = DecodeOpts {
        // `roundtrip.rs`'s and `codec.rs`'s bound, for the same reason.
        memory_limit: Some(64 * 1024 * 1024),
        ..Default::default()
    };
    let mut out = Vec::new();
    let Ok(mut dec) = codec.decoder(src, &opts) else {
        return Decoded {
            bytes: out,
            whole: false,
        };
    };
    // `read_to_end` keeps what it read before an error.
    let ok = (&mut dec)
        .take(OUTPUT_CAP as u64 + 1)
        .read_to_end(&mut out)
        .is_ok();
    let whole = ok && out.len() <= OUTPUT_CAP;
    out.truncate(OUTPUT_CAP);
    Decoded { bytes: out, whole }
}

/// Hostile `input` through both tiers' decoders of `format`: no byte both
/// produced may differ, and when both accept the whole input, the outputs
/// are equal. See the module doc for why one may stop earlier.
pub fn check_decoders_agree(format: Format, input: &[u8]) {
    assert_c_tier();
    if input.is_empty() {
        return;
    }
    let c = c_decode(format, input);
    let pure = pure_decode(format, input);
    let common = c.bytes.len().min(pure.bytes.len());
    if let Some(at) = (0..common).find(|&i| c.bytes[i] != pure.bytes[i]) {
        panic!(
            "{}: the C and pure decoders disagree at output byte {at} of a {}-byte input \
             (C produced {} byte(s), whole: {}; pure {} byte(s), whole: {})",
            format.name(),
            input.len(),
            c.bytes.len(),
            c.whole,
            pure.bytes.len(),
            pure.whole
        );
    }
    if c.whole && pure.whole {
        assert_eq!(
            c.bytes.len(),
            pure.bytes.len(),
            "{}: both tiers accepted the whole {}-byte input but decoded different lengths",
            format.name(),
            input.len()
        );
    }
}

/// A small deterministic hash of `content`, picking the C encoder's
/// options (the roundtrip wire format has no byte for them).
pub fn knob(content: &[u8]) -> u32 {
    content.iter().fold(content.len() as u32, |a, &b| {
        a.wrapping_mul(31).wrapping_add(u32::from(b))
    })
}

/// libbrotli compresses `content`: quality `k % 12`, window 10..=24, a size
/// hint on odd `k`. `None` only if libbrotli refuses (out of memory).
pub fn c_brotli_encode(content: &[u8], k: u32) -> Option<Vec<u8>> {
    let params = EncoderParams {
        quality: k % 12,
        lgwin: brotli_opts::MIN_WINDOW_BITS + (k >> 4) % 15,
        large_window: false,
        size_hint: (k & 1 == 1).then_some(content.len() as u32),
    };
    let mut e = brotli_opts::Encoder::new(&params, None).ok()?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut rest = content;
    loop {
        let mut space: &mut [u8] = &mut buf;
        let before = space.len();
        assert!(
            e.compress_stream(Operation::Finish, &mut rest, &mut space),
            "brotli-c: BrotliEncoderCompressStream failed on {params:?}"
        );
        let made = before - space.len();
        out.extend_from_slice(&buf[..made]);
        if e.is_finished() {
            return Some(out);
        }
    }
}

/// liblz4 compresses `content` as one frame, its options from `k`: level
/// -3..=12, block size 64 KiB..4 MiB, linked blocks, block and content
/// checksums, the content size, single-threaded or threaded.
pub fn c_lz4_encode(content: &[u8], k: u32) -> Vec<u8> {
    let o = EncodeOptions {
        level: (k % 16) as i32 - 3,
        block_size: BlockSizeId::from_id(4 + ((k >> 4) % 4) as u8).expect("4..=7"),
        block_linked: k & (1 << 6) != 0,
        block_checksum: k & (1 << 7) != 0,
        content_checksum: k & (1 << 8) != 0,
        content_size: (k & (1 << 9) != 0).then_some(content.len() as u64),
        workers: (k >> 10) & 1,
        ..EncodeOptions::default()
    };
    let mut e = lz4_opts::Encoder::new(&o).unwrap_or_else(|err| panic!("lz4-c: {o:?}: {err:?}"));
    let mut out = Vec::new();
    e.update(content, &mut out)
        .unwrap_or_else(|err| panic!("lz4-c update: {o:?}: {err:?}"));
    e.finish(&mut out)
        .unwrap_or_else(|err| panic!("lz4-c finish: {o:?}: {err:?}"));
    out
}

/// The encoder half of the cross-tier check, for `roundtrip.rs`: the pure
/// (registry) encoder's `pure_encoded` must decode to `content` through
/// the C decoder, and the C encoder's output through the pure decoder (and
/// the C decoder, its own).
pub fn check_encoders_cross(format: Format, content: &[u8], pure_encoded: &[u8]) {
    assert_c_tier();
    let c = c_decode(format, pure_encoded);
    assert!(
        c.whole && c.bytes == content,
        "{}: the C decoder did not read back the pure encoder's {} byte(s) of a {}-byte input \
         (whole: {}, {} byte(s) out)",
        format.name(),
        pure_encoded.len(),
        content.len(),
        c.whole,
        c.bytes.len()
    );
    let k = knob(content);
    let encoded = match format {
        Format::Brotli => match c_brotli_encode(content, k) {
            Some(b) => b,
            None => return,
        },
        Format::Lz4 => c_lz4_encode(content, k),
    };
    for (side, got) in [
        ("pure", pure_decode(format, &encoded)),
        ("C", c_decode(format, &encoded)),
    ] {
        assert!(
            got.whole && got.bytes == content,
            "{}: the {side} decoder did not read back the C encoder's {} byte(s) (knob {k:#x}) \
             of a {}-byte input (whole: {}, {} byte(s) out)",
            format.name(),
            encoded.len(),
            content.len(),
            got.whole,
            got.bytes.len()
        );
    }
}
