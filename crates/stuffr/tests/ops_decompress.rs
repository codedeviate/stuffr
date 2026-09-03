use stuffr::FormatId;
use stuffr::ops::{
    CompressOpts, DecompressOpts, Detection, Input, Output, compress, decompress, inspect,
};

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-1b-dec-{}-{}", std::process::id(), name));
    p
}

/// Looks the id up in the real registry rather than constructing a
/// `FormatId` directly — `FormatId::new` would happily mint an id for a
/// format that was never registered, and the tests below would then pass
/// for the wrong reason (they'd never actually exercise the codec).
fn fmt(name: &str) -> FormatId {
    stuffr::registry()
        .matrix()
        .into_iter()
        .find(|row| row.id.as_str() == name)
        .unwrap_or_else(|| panic!("format `{name}` is not registered in this build"))
        .id
}

fn make_gz(plain: &[u8], name: &str) -> std::path::PathBuf {
    let src = tmp(&format!("{name}.txt"));
    let dst = tmp(&format!("{name}.txt.gz"));
    let _ = std::fs::remove_file(&dst);
    std::fs::write(&src, plain).unwrap();
    compress(
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &CompressOpts::default(),
    )
    .unwrap();
    let _ = std::fs::remove_file(&src);
    dst
}

#[test]
fn round_trips_byte_identically() {
    let plain = b"the quick brown fox ".repeat(500);
    let gz = make_gz(&plain, "round");
    let out = tmp("round-out.txt");
    let _ = std::fs::remove_file(&out);

    let o = decompress(
        Input::Path(gz.clone()),
        Output::Path(out.clone()),
        &DecompressOpts::default(),
    )
    .unwrap();

    assert_eq!(std::fs::read(&out).unwrap(), plain);
    assert_eq!(o.bytes_out, plain.len() as u64);
    assert_eq!(o.format.as_str(), "gzip");
    assert!(gz.exists(), "decompressing must not destroy the archive");

    let _ = std::fs::remove_file(&gz);
    let _ = std::fs::remove_file(&out);
}

// NOTE on what this file does NOT cover: `inspect` is supposed to compute its
// `Rung` from the source's actual seekability rather than assume one, and the
// test below only ever exercises the seekable (`Input::Path`) side — it would
// pass just as well if `inspect` hardcoded `Rung::Exact`. A genuine
// non-seekable case would need an `Input` backed by something other than a
// file, but `Input` (see `stuffr::ops::Input`) has exactly two public
// variants: `Path`, which always opens a `FileSource` (unconditionally
// seekable), and `Stdin`, which always wraps the process's real
// `std::io::stdin()` — there is no public constructor that accepts arbitrary
// bytes as a non-seekable source. Faking that here would mean redirecting
// this test binary's actual stdin (fd 0) out from under a test harness that
// runs every `#[test]` in this file as a thread of one shared process, which
// would be racy against any other test reading stdin concurrently. Spawning
// the real `stuffr` binary with a piped stdin — a separate OS process, safe to
// redirect — is the honest way to exercise that path, and
// `info_over_a_pipe_reports_forward_only_not_exact` in
// `crates/stuffr-cli/tests/cli.rs` already does exactly that for `inspect`
// (and `pack_over_a_pipe_reports_forward_only_not_exact` does the same for
// `compress`). So: renamed to describe only what it actually checks, rather
// than implying pipe coverage that belongs — and lives — one layer up.
#[test]
fn inspect_of_a_seekable_file_reports_exact() {
    // No container, so no entry-level ladder — but the rung is still real, and
    // reporting it honestly is what makes `stuffr info` meaningful before Phase 2.
    let gz = make_gz(b"payload", "rung");
    let from_file = inspect(Input::Path(gz.clone())).unwrap();
    assert_eq!(from_file.fidelity.rung, stuffr::Rung::Exact);
    assert!(
        !from_file.fidelity.has_warnings(),
        "gzip has no index; nothing is lost"
    );
    assert_eq!(from_file.format.as_str(), "gzip");
    assert_eq!(from_file.chain, "gzip");
    assert_eq!(
        from_file.bytes_in,
        Some(std::fs::metadata(&gz).unwrap().len())
    );
    let _ = std::fs::remove_file(&gz);
}

/// Every other test that touches `detected_by` uses a real gzip file, which
/// magic always wins on — so a build that hardcoded `Detection::Magic` and
/// never consulted the registry would pass all of them. This is the one case
/// that can only pass if `inspect` actually falls back to the extension:
/// content that is not gzip at all, named as if it were.
///
/// The fallback is real and reachable, not a hypothetical: `stuffr info` still
/// identifies such a file (by name) even though `unpack` would then fail on
/// it when the bytes turn out not to be gzip after all.
#[test]
fn a_non_gzip_file_named_dot_gz_is_detected_by_extension_not_magic() {
    let path = tmp("not-actually-gzip.gz");
    std::fs::write(&path, b"just plain text, no gzip magic here").unwrap();

    let inspection = inspect(Input::Path(path.clone())).unwrap();
    assert_eq!(
        inspection.format.as_str(),
        "gzip",
        "the extension still names a real format"
    );
    assert_eq!(
        inspection.detected_by,
        Detection::Extension,
        "no magic matched; only the name decided"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_bomb_trips_the_ratio_limit_with_exit_code_six() {
    // Two megabytes of zeroes compress to almost nothing — a ratio far past
    // 100:1, and past the 1 MiB enforcement floor. `DecompressOpts::default`'s
    // max_ratio (DEFAULT_MAX_RATIO = 10_000) can never be tripped by a single
    // gzip member: deflate's structural ceiling is ~1032:1, so this test
    // passes an explicit, much lower max_ratio to prove the mechanism.
    let src = tmp("bomb.bin");
    let gz = tmp("bomb.bin.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, vec![0u8; 2 * 1024 * 1024]).unwrap();
    compress(
        Input::Path(src.clone()),
        Output::Path(gz.clone()),
        &CompressOpts::default(),
    )
    .unwrap();

    let out = tmp("bomb-out.bin");
    let _ = std::fs::remove_file(&out);
    let o = DecompressOpts {
        max_ratio: 100,
        ..Default::default()
    };
    let err = decompress(Input::Path(gz.clone()), Output::Path(out.clone()), &o).unwrap_err();

    assert_eq!(err.exit_code(), 6);
    assert!(
        err.to_string().contains("ratio"),
        "the error must say what tripped"
    );
    assert!(!out.exists(), "a refused decode must leave no partial file");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn a_generous_max_ratio_lets_the_same_stream_through() {
    // Proves the limit is the thing refusing it, not some other failure.
    let src = tmp("ok.bin");
    let gz = tmp("ok.bin.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, vec![0u8; 2 * 1024 * 1024]).unwrap();
    compress(
        Input::Path(src.clone()),
        Output::Path(gz.clone()),
        &CompressOpts::default(),
    )
    .unwrap();

    let out = tmp("ok-out.bin");
    let _ = std::fs::remove_file(&out);
    let o = DecompressOpts {
        max_ratio: u64::MAX,
        ..Default::default()
    };
    decompress(Input::Path(gz.clone()), Output::Path(out.clone()), &o).unwrap();
    assert_eq!(std::fs::metadata(&out).unwrap().len(), 2 * 1024 * 1024);

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
    let _ = std::fs::remove_file(&out);
}

#[test]
fn the_default_max_ratio_is_ten_thousand() {
    assert_eq!(DecompressOpts::default().max_ratio, 10_000);
}

#[test]
fn the_default_sync_is_on() {
    // Mirrors CompressOpts::default().sync — durability must be the default
    // on the decompress side too, not just the compress side.
    assert!(DecompressOpts::default().sync);
}

#[test]
fn a_corrupted_stream_is_corrupt_not_an_io_error() {
    let plain = b"the quick brown fox ".repeat(200);
    let gz = make_gz(&plain, "corrupt");
    let mut bytes = std::fs::read(&gz).unwrap();

    // Flip a bit in the middle of the compressed body, past the 10-byte header
    // and well before the 8-byte trailer, so this is malformed deflate data
    // rather than a mismatched CRC. Both should classify the same way; the
    // middle is the case a naive implementation gets wrong.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&gz, &bytes).unwrap();

    let out = tmp("corrupt-out.txt");
    let _ = std::fs::remove_file(&out);
    let err = decompress(
        Input::Path(gz.clone()),
        Output::Path(out.clone()),
        &DecompressOpts::default(),
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), 5, "corruption is exit 5, not 1: {err}");
    assert!(matches!(err, stuffr::Error::Corrupt(_)), "got {err:?}");
    assert!(!out.exists(), "a refused decode must leave no partial file");

    let _ = std::fs::remove_file(&gz);
}

#[test]
fn each_magic_bearing_format_is_detected_from_its_own_bytes() {
    // Seven formats now share one registry. This is the test that would catch
    // one format's magic shadowing another's — for instance a rule registered
    // at the wrong offset, or a prefix collision nobody noticed.
    for (id, ext) in [
        ("gzip", "gz"),
        ("zlib", "zz"),
        ("bzip2", "bz2"),
        ("lz4", "lz4"),
        ("snappy", "sz"),
    ] {
        let src = tmp(&format!("detect-{id}.bin"));
        let packed = tmp(&format!("detect-{id}.bin.{ext}"));
        let _ = std::fs::remove_file(&packed);
        std::fs::write(&src, b"the quick brown fox ".repeat(50)).unwrap();

        let o = CompressOpts {
            format: Some(fmt(id)),
            ..Default::default()
        };
        compress(Input::Path(src.clone()), Output::Path(packed.clone()), &o).unwrap();

        // Inspect WITHOUT the extension hint, so only the magic can decide.
        let bare = tmp(&format!("detect-{id}-bare"));
        std::fs::rename(&packed, &bare).unwrap();
        let got = inspect(Input::Path(bare.clone())).unwrap();
        assert_eq!(
            got.format.as_str(),
            id,
            "magic detection picked the wrong format"
        );
        assert_eq!(got.detected_by, Detection::Magic);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&bare);
    }
}

#[test]
fn a_magic_less_format_is_unreachable_without_an_explicit_format() {
    // deflate has neither magic nor extension. Detection must fail cleanly
    // rather than guessing, and --format must be the way in. If this ever
    // starts succeeding, detection has begun guessing at streams it cannot
    // identify.
    let src = tmp("noformat.bin");
    let packed = tmp("noformat.deflate");
    let _ = std::fs::remove_file(&packed);
    std::fs::write(&src, b"payload").unwrap();

    let o = CompressOpts {
        format: Some(fmt("deflate")),
        ..Default::default()
    };
    compress(Input::Path(src.clone()), Output::Path(packed.clone()), &o).unwrap();

    let err = inspect(Input::Path(packed.clone())).unwrap_err();
    assert!(
        matches!(err, stuffr::Error::UnknownFormat { .. }),
        "detection must fail rather than guess: {err:?}"
    );

    // But it round-trips when named explicitly.
    let out = tmp("noformat-out.bin");
    let _ = std::fs::remove_file(&out);
    let d = DecompressOpts {
        format: Some(fmt("deflate")),
        ..Default::default()
    };
    decompress(Input::Path(packed.clone()), Output::Path(out.clone()), &d).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"payload");

    for p in [&src, &packed, &out] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn the_default_memory_limit_is_none() {
    // The library default is unbounded; the CLI is what resolves this to
    // `governor::default_memory_limit()` when `--memory-limit` is absent —
    // see `stuffr_core::DecodeOpts::memory_limit`'s doc.
    assert_eq!(DecompressOpts::default().memory_limit, None);
}

/// End-to-end: `DecompressOpts::memory_limit` reaches the decoder and
/// refuses a hostile declaration before allocating, through the same path
/// `stuffr unpack --memory-limit` uses. Gated to the pure backend actually
/// selected here — under `--all-features` `lzma-c` wins registration for
/// `lzma` (see `stuffr-formats/src/lzma_shared.rs`), and `lzma-c` is not
/// part of this defect or this task's fix, so `Makefile`'s `test` (all
/// features) never runs this and `test-pure` (default features) does —
/// the same split the Makefile documents for `lzma-pure` generally.
#[test]
#[cfg(all(feature = "lzma-pure", not(feature = "lzma-c")))]
fn a_declared_lzma_dictionary_over_the_memory_limit_is_refused_end_to_end() {
    let src = tmp("lzma-mem.bin");
    let packed = tmp("lzma-mem.bin.lzma");
    let _ = std::fs::remove_file(&packed);
    std::fs::write(&src, b"payload".repeat(200)).unwrap();
    compress(
        Input::Path(src.clone()),
        Output::Path(packed.clone()),
        &CompressOpts {
            format: Some(fmt("lzma")),
            ..Default::default()
        },
    )
    .unwrap();

    // A `.lzma` header declares its dictionary in bytes 1-4, little-endian —
    // patch it to claim 512 MiB, mirroring `lzma_pure.rs`'s own unit test.
    let mut bytes = std::fs::read(&packed).unwrap();
    bytes[1..5].copy_from_slice(&(512u32 * 1024 * 1024).to_le_bytes());
    std::fs::write(&packed, &bytes).unwrap();

    let out = tmp("lzma-mem-out.bin");
    let _ = std::fs::remove_file(&out);
    let o = DecompressOpts {
        memory_limit: Some(1024 * 1024),
        ..Default::default()
    };
    let err = decompress(Input::Path(packed.clone()), Output::Path(out.clone()), &o).unwrap_err();

    assert_eq!(
        err.exit_code(),
        6,
        "a memory refusal is ResourceLimit, not Corrupt: {err}"
    );
    assert!(
        err.to_string().contains("--memory-limit"),
        "the message must name the flag so the user can raise it: {err}"
    );
    assert!(!out.exists(), "a refused decode must leave no partial file");

    for p in [&src, &packed, &out] {
        let _ = std::fs::remove_file(p);
    }
}

/// The acceptance counterpart: a legitimate file decodes when its declared
/// dictionary fits under the limit, proving the bound is not merely strict.
#[test]
#[cfg(all(feature = "lzma-pure", not(feature = "lzma-c")))]
fn a_legitimate_lzma_dictionary_under_the_memory_limit_still_decodes_end_to_end() {
    let src = tmp("lzma-mem-ok.bin");
    let packed = tmp("lzma-mem-ok.bin.lzma");
    let _ = std::fs::remove_file(&packed);
    std::fs::write(&src, b"ordinary payload ".repeat(2000)).unwrap();
    compress(
        Input::Path(src.clone()),
        Output::Path(packed.clone()),
        &CompressOpts {
            format: Some(fmt("lzma")),
            ..Default::default()
        },
    )
    .unwrap();

    let out = tmp("lzma-mem-ok-out.bin");
    let _ = std::fs::remove_file(&out);
    let o = DecompressOpts {
        memory_limit: Some(64 * 1024 * 1024),
        ..Default::default()
    };
    decompress(Input::Path(packed.clone()), Output::Path(out.clone()), &o).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&src).unwrap());

    for p in [&src, &packed, &out] {
        let _ = std::fs::remove_file(p);
    }
}
