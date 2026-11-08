//! The vendored liblz4 1.11.0 (`lz4-c`, every export prefixed `stuffr_`)
//! linked into one binary beside another, unprefixed liblz4: `lz4-sys`
//! (1.10.0, a dev-dependency only). Both must link, and each call must
//! reach its own library — the situation of a downstream graph that holds
//! `stuffr` and the `lz4` crate.
#![cfg(feature = "lz4-c")]

use stuffr_formats::lz4_opts::{EncodeOptions, LEGACY_MAGIC, LegacyDecoder, liblz4_version};

/// `n` bytes of word text (a fixed LCG), compressible enough that liblz4
/// 1.10.0's and 1.11.0's level-1 compressors part ways (probe §2).
fn text(n: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "frame", "block", "the", "of", "linked", "lz4", "a", "checksum",
    ];
    let mut x: u64 = 0x1_1100;
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.extend_from_slice(WORDS[(x >> 33) as usize % WORDS.len()].as_bytes());
        out.push(if (x >> 20).is_multiple_of(13) {
            b'\n'
        } else {
            b' '
        });
    }
    out.truncate(n);
    out
}

#[test]
fn both_libraries_link_and_answer_for_themselves() {
    // SAFETY: LZ4_versionNumber takes no arguments and returns a constant.
    assert_eq!(unsafe { lz4_sys::LZ4_versionNumber() }, 11000);
    assert_eq!(liblz4_version(), "1.11.0");
}

#[test]
fn each_compresses_with_its_own_version_and_reads_the_other() {
    let data = text(300_000);
    // stuffr's legacy frame at level 1: one `LZ4_compress_fast` block
    // (acceleration 1) from the vendored 1.11.0.
    let mut ours = Vec::new();
    let mut e = stuffr_formats::lz4_opts::Encoder::new(&EncodeOptions {
        legacy: true,
        ..EncodeOptions::default()
    })
    .unwrap();
    e.update(&data, &mut ours).unwrap();
    e.finish(&mut ours).unwrap();
    let ours_block = &ours[8..];

    // The same block from lz4-sys's 1.10.0.
    let cap = data.len() + data.len() / 255 + 16;
    let mut theirs = vec![0u8; cap];
    // SAFETY: data and theirs are live for the lengths passed; cap is
    // LZ4_COMPRESSBOUND(data.len()).
    let n = unsafe {
        lz4_sys::LZ4_compress_default(
            data.as_ptr().cast(),
            theirs.as_mut_ptr().cast(),
            data.len() as i32,
            cap as i32,
        )
    };
    assert!(n > 0);
    theirs.truncate(n as usize);
    assert_ne!(ours_block, &theirs[..], "the two calls reached one library");

    // 1.10.0 reads 1.11.0's block...
    let mut back = vec![0u8; data.len()];
    // SAFETY: ours_block and back are live for the lengths passed.
    let m = unsafe {
        lz4_sys::LZ4_decompress_safe(
            ours_block.as_ptr().cast(),
            back.as_mut_ptr().cast(),
            ours_block.len() as i32,
            back.len() as i32,
        )
    };
    assert_eq!(m as usize, data.len());
    assert!(back == data);

    // ...and 1.11.0 (stuffr's legacy reader) reads 1.10.0's.
    let mut frame = LEGACY_MAGIC.to_le_bytes().to_vec();
    frame.extend_from_slice(&(theirs.len() as u32).to_le_bytes());
    frame.extend_from_slice(&theirs);
    let mut d = LegacyDecoder::new();
    let mut out = Vec::new();
    let (used, _) = d.decompress(&frame, &mut out).unwrap();
    assert_eq!(used, frame.len());
    assert!(out == data);
}
