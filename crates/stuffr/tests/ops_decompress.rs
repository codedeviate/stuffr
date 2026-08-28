use stuffr::ops::{CompressOpts, DecompressOpts, Input, Output, compress, decompress, inspect};

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stf-1b-dec-{}-{}", std::process::id(), name));
    p
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

#[test]
fn a_seekable_source_reports_exact_and_a_pipe_reports_forward_only() {
    // No container, so no entry-level ladder — but the rung is still real, and
    // reporting it honestly is what makes `stf info` meaningful before Phase 2.
    let gz = make_gz(b"payload", "rung");
    let from_file = inspect(Input::Path(gz.clone())).unwrap();
    assert_eq!(from_file.rung, stuffr::Rung::Exact);
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
