//! `ops::recompress` — codec-only conversion: every codec layer of the source
//! peeled, at most one written, the inner bytes untouched.
//!
//! Every fixture is built with the library's own `compress` (and
//! `entries::create_archive` for the tar), never with `recompress`, so each
//! expectation comes from the input bytes rather than from the code under
//! test.
#![cfg(all(feature = "gzip", feature = "tar"))]

use std::path::{Path, PathBuf};

use stuffr::FormatId;
use stuffr::entries;
use stuffr::ops::{
    CompressOpts, DecompressOpts, Input, Output, RecompressOpts, compress, decompress, recompress,
};

/// Looks the id up in the real registry, so a test cannot pass against a
/// format this build never registered.
fn fmt(name: &str) -> FormatId {
    stuffr::registry()
        .matrix()
        .into_iter()
        .find(|row| row.id.as_str() == name)
        .unwrap_or_else(|| panic!("format `{name}` is not registered in this build"))
        .id
}

fn opts(codec: Option<FormatId>) -> RecompressOpts {
    RecompressOpts {
        codec,
        level: None,
        force: false,
        sync: false,
        allow_weak_encoder: false,
        threads: None,
        turbo: false,
        max_ratio: stuffr::DEFAULT_MAX_RATIO,
        memory_limit: None,
    }
}

/// zstd as the target. The pure tier's zstd encoder is weak
/// (`CodecCaps::weak_encoder`), so consent is given — these tests are about
/// the conversion, and `a_weak_target_encoder_needs_consent` covers the
/// refusal.
#[cfg(feature = "zstd-pure")]
fn zstd_opts() -> RecompressOpts {
    RecompressOpts {
        allow_weak_encoder: true,
        ..opts(Some(fmt("zstd")))
    }
}

/// `plain` compressed with `format` into `dir/name`, by the library's own
/// `compress`.
fn compress_bytes(dir: &Path, plain: &[u8], format: &str, name: &str) -> PathBuf {
    let src = dir.join(format!("{name}.src"));
    std::fs::write(&src, plain).unwrap();
    let dst = dir.join(name);
    compress(
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &CompressOpts {
            format: Some(fmt(format)),
            sync: false,
            ..CompressOpts::default()
        },
    )
    .unwrap();
    std::fs::remove_file(&src).unwrap();
    dst
}

fn decompress_to_vec(dir: &Path, compressed: &Path) -> Vec<u8> {
    let out = dir.join("decompressed.out");
    let _ = std::fs::remove_file(&out);
    decompress(
        Input::Path(compressed.to_path_buf()),
        Output::Path(out.clone()),
        &DecompressOpts {
            sync: false,
            ..DecompressOpts::default()
        },
    )
    .unwrap();
    std::fs::read(&out).unwrap()
}

/// 1 MiB of a repeating, non-trivial pattern: compressible, but not a run of
/// one byte.
fn payload() -> Vec<u8> {
    (0..1024 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8 ^ (i % 251) as u8)
        .collect()
}

/// A two-file tar built by `entries::create_archive`; returns its path and
/// its bytes.
fn make_tar(dir: &Path) -> (PathBuf, Vec<u8>) {
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"alpha ".repeat(300)).unwrap();
    std::fs::write(tree.join("b.bin"), payload()).unwrap();
    let tar = dir.join("bundle.tar");
    entries::create_archive(
        &[tree],
        Output::Path(tar.clone()),
        fmt("tar"),
        None,
        &CompressOpts {
            sync: false,
            ..CompressOpts::default()
        },
    )
    .unwrap();
    let bytes = std::fs::read(&tar).unwrap();
    (tar, bytes)
}

#[cfg(feature = "xz-pure")]
#[test]
fn gz_to_xz_round_trips_the_payload() {
    let dir = tempfile::tempdir().unwrap();
    let plain = payload();
    let gz = compress_bytes(dir.path(), &plain, "gzip", "p.gz");
    let xz = dir.path().join("p.xz");

    let o = recompress(
        Input::Path(gz),
        Output::Path(xz.clone()),
        &opts(Some(fmt("xz"))),
    )
    .unwrap();

    let written = std::fs::read(&xz).unwrap();
    // The magic comes from the xz codec's own registered probe (Ruling F),
    // not from a constant copied into this test.
    assert_eq!(
        stuffr::registry().match_magic(&written),
        vec![fmt("xz")],
        "the output must be an xz stream by xz's own magic"
    );
    assert_eq!(decompress_to_vec(dir.path(), &xz), plain);
    assert_eq!(o.format, fmt("xz"));
    assert_eq!(o.bytes_out, written.len() as u64);
    assert!(o.fidelity.warnings.is_empty());
}

#[cfg(feature = "zstd-pure")]
#[test]
fn tar_gz_to_tar_zst_keeps_the_tar_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let (_, tar_bytes) = make_tar(dir.path());
    let tgz = compress_bytes(dir.path(), &tar_bytes, "gzip", "bundle.tar.gz");
    let zst = dir.path().join("bundle.tar.zst");

    recompress(Input::Path(tgz), Output::Path(zst.clone()), &zstd_opts()).unwrap();

    assert_eq!(
        stuffr::registry().match_magic(&std::fs::read(&zst).unwrap()),
        vec![fmt("zstd")]
    );
    assert_eq!(decompress_to_vec(dir.path(), &zst), tar_bytes);
}

#[cfg(all(feature = "xz-pure", feature = "zstd-pure"))]
#[test]
fn two_codec_layers_are_both_peeled() {
    let dir = tempfile::tempdir().unwrap();
    let plain = payload();
    let gz = compress_bytes(dir.path(), &plain, "gzip", "p.gz");
    let gz_bytes = std::fs::read(&gz).unwrap();
    let gz_xz = compress_bytes(dir.path(), &gz_bytes, "xz", "p.gz.xz");
    let zst = dir.path().join("p.zst");

    recompress(Input::Path(gz_xz), Output::Path(zst.clone()), &zstd_opts()).unwrap();

    // ONE decompress gives the payload: both source layers were peeled, and
    // exactly one was written.
    assert_eq!(decompress_to_vec(dir.path(), &zst), plain);
}

#[test]
fn to_no_codec_writes_the_decoded_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (_, tar_bytes) = make_tar(dir.path());
    let tgz = compress_bytes(dir.path(), &tar_bytes, "gzip", "bundle.tar.gz");
    let out = dir.path().join("plain.tar");

    let o = recompress(Input::Path(tgz), Output::Path(out.clone()), &opts(None)).unwrap();

    assert_eq!(std::fs::read(&out).unwrap(), tar_bytes);
    assert_eq!(
        o.format,
        fmt("tar"),
        "no target codec reports the inner format"
    );
    assert_eq!(o.bytes_out, tar_bytes.len() as u64);
}

/// Review Focus 1: an inner stream that decodes cleanly under a trailer that
/// fails its CRC must not be published as a freshly re-encoded file.
#[cfg(feature = "xz-pure")]
#[test]
fn a_corrupt_trailer_is_exit_5_and_leaves_no_output() {
    let dir = tempfile::tempdir().unwrap();
    let gz = compress_bytes(dir.path(), &payload(), "gzip", "p.gz");
    let mut bytes = std::fs::read(&gz).unwrap();
    // gzip's trailer is CRC32 then ISIZE, 4 bytes each: flip a CRC byte.
    let crc = bytes.len() - 8;
    bytes[crc] ^= 0xff;
    std::fs::write(&gz, &bytes).unwrap();
    let xz = dir.path().join("p.xz");

    let e = recompress(
        Input::Path(gz),
        Output::Path(xz.clone()),
        &opts(Some(fmt("xz"))),
    )
    .expect_err("a CRC mismatch must fail the conversion");

    assert_eq!(e.exit_code(), 5, "{e}");
    assert!(!xz.exists(), "a failed conversion must leave no output");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "no temp file may be left beside the destination either"
    );
}

#[test]
fn a_ratio_bomb_is_exit_6() {
    let dir = tempfile::tempdir().unwrap();
    let gz = compress_bytes(dir.path(), &vec![0u8; 64 * 1024 * 1024], "gzip", "z.gz");
    let out = dir.path().join("z.out");

    let e = recompress(
        Input::Path(gz),
        Output::Path(out.clone()),
        &RecompressOpts {
            max_ratio: 10,
            ..opts(None)
        },
    )
    .expect_err("a 1000:1 stream must trip a 10:1 limit");

    assert_eq!(e.exit_code(), 6, "{e}");
    assert!(!out.exists(), "a refused conversion must leave no output");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "no temp file may be left beside the destination either"
    );
}

#[test]
fn nothing_to_convert_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let (tar, _) = make_tar(dir.path());
    let out = dir.path().join("again.tar");

    let e = recompress(Input::Path(tar), Output::Path(out.clone()), &opts(None))
        .expect_err("a bare tar with no target codec has nothing to convert");

    assert!(matches!(e, stuffr::Error::Usage(_)), "{e:?}");
    assert_eq!(e.exit_code(), 2);
    assert!(!out.exists(), "a refused conversion must create nothing");

    // Bytes no probe recognises are not a stream with a codec layer either.
    let unknown = dir.path().join("notes.bin");
    std::fs::write(&unknown, b"just some plain words, nothing compressed").unwrap();
    let e = recompress(Input::Path(unknown), Output::Path(out.clone()), &opts(None))
        .expect_err("plain bytes have nothing to convert");
    assert_eq!(e.exit_code(), 2, "{e}");
    assert!(!out.exists());
}

/// The write side's consent rule reaches `recompress` too: it builds its
/// encoder through the same owner as `compress`. Only meaningful in a build
/// whose zstd encoder is the weak one; the c-backed leg has nothing to refuse.
#[cfg(feature = "zstd-pure")]
#[test]
fn a_weak_target_encoder_needs_consent() {
    let zstd = fmt("zstd");
    let weak = stuffr::registry()
        .codec(zstd)
        .is_some_and(|c| c.caps().weak_encoder);
    if !weak {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let gz = compress_bytes(dir.path(), b"some bytes to move", "gzip", "w.gz");
    let out = dir.path().join("w.zst");

    let e = recompress(
        Input::Path(gz),
        Output::Path(out.clone()),
        &opts(Some(zstd)),
    )
    .expect_err("a weak encoder without consent must be refused");

    assert!(matches!(e, stuffr::Error::Usage(_)), "{e:?}");
    assert_eq!(e.exit_code(), 2, "{e}");
    assert!(!out.exists(), "a refusal must create nothing");
}

/// Detection is by content: a name that claims `.tar.gz` must not stop the
/// xz layer hiding under the gzip from being peeled.
#[cfg(feature = "xz-pure")]
#[test]
fn a_misnamed_tar_gz_hiding_an_xz_layer_is_fully_peeled() {
    let dir = tempfile::tempdir().unwrap();
    let plain = payload();
    let xz = compress_bytes(dir.path(), &plain, "xz", "p.xz");
    let xz_bytes = std::fs::read(&xz).unwrap();
    let gz = compress_bytes(dir.path(), &xz_bytes, "gzip", "p.tar.gz");
    let out = dir.path().join("p.out");

    recompress(Input::Path(gz), Output::Path(out.clone()), &opts(None)).unwrap();

    assert!(
        std::fs::read(&out).unwrap() == plain,
        "the output must be the payload, not a still-compressed layer"
    );
}

/// Brotli has no magic: content cannot name it, so the path's `.br` must
/// still be honoured as the fallback.
#[cfg(all(feature = "brotli", feature = "xz-pure"))]
#[test]
fn a_brotli_source_with_a_correct_name_still_converts() {
    let dir = tempfile::tempdir().unwrap();
    let plain = payload();
    let br = compress_bytes(dir.path(), &plain, "brotli", "p.br");
    let xz = dir.path().join("p.xz");

    recompress(
        Input::Path(br),
        Output::Path(xz.clone()),
        &opts(Some(fmt("xz"))),
    )
    .unwrap();

    assert_eq!(decompress_to_vec(dir.path(), &xz), plain);
}

/// The corrupt trailer is on the INNER layer: gzip is intact, the xz stream
/// under it fails its own check.
#[cfg(feature = "xz-pure")]
#[test]
fn a_corrupt_inner_layer_trailer_is_exit_5_and_leaves_no_output() {
    let dir = tempfile::tempdir().unwrap();
    let xz = compress_bytes(dir.path(), &payload(), "xz", "p.xz");
    let mut bytes = std::fs::read(&xz).unwrap();
    // The xz footer is 12 bytes (CRC32, backward size, flags, magic) and the
    // index sits before it; flipping a byte of the footer's CRC32 field
    // breaks the stream's own integrity check.
    let crc = bytes.len() - 12;
    bytes[crc] ^= 0xff;
    // Re-wrap the damaged xz in a perfectly valid gzip.
    let damaged = dir.path().join("damaged.bin");
    std::fs::write(&damaged, &bytes).unwrap();
    let gz = dir.path().join("p.xz.gz");
    compress(
        Input::Path(damaged),
        Output::Path(gz.clone()),
        &CompressOpts {
            format: Some(fmt("gzip")),
            sync: false,
            ..CompressOpts::default()
        },
    )
    .unwrap();
    let before = std::fs::read_dir(dir.path()).unwrap().count();
    let out = dir.path().join("p.out");

    let e = recompress(Input::Path(gz), Output::Path(out.clone()), &opts(None))
        .expect_err("a damaged inner xz must fail the conversion");

    assert_eq!(e.exit_code(), 5, "{e}");
    assert!(!out.exists(), "a failed conversion must leave no output");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        before,
        "no temp file may be left beside the destination either"
    );
}

/// `memory_limit` is the cap on EVERY layer's decoder, the inner one
/// included: an xz stream made at the top preset needs a 64 MiB dictionary,
/// which a 1 MiB limit must refuse (exit 6) even under a small gzip. Gated
/// to the pure backend: the C xz decoder takes no memory limit, so under
/// `--all-features` (where `xz-c` wins registration) there is nothing to test
/// — the same split `ops_decompress.rs` documents for lzma.
#[cfg(all(feature = "xz-pure", not(feature = "xz-c")))]
#[test]
fn the_memory_limit_reaches_an_inner_layer() {
    let dir = tempfile::tempdir().unwrap();
    let xz = dir.path().join("big.xz");
    let src = dir.path().join("big.src");
    std::fs::write(&src, payload()).unwrap();
    compress(
        Input::Path(src),
        Output::Path(xz.clone()),
        &CompressOpts {
            format: Some(fmt("xz")),
            level: Some(9),
            sync: false,
            ..CompressOpts::default()
        },
    )
    .unwrap();
    let xz_bytes = std::fs::read(&xz).unwrap();
    let gz = compress_bytes(dir.path(), &xz_bytes, "gzip", "big.xz.gz");
    let out = dir.path().join("big.out");

    let e = recompress(
        Input::Path(gz),
        Output::Path(out.clone()),
        &RecompressOpts {
            memory_limit: Some(1024 * 1024),
            ..opts(None)
        },
    )
    .expect_err("a 64 MiB-dictionary inner layer must trip a 1 MiB limit");

    assert_eq!(e.exit_code(), 6, "{e}");
    assert!(!out.exists());
}
