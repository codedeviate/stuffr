use stuffr::ops::{CompressOpts, Input, Output, compress};

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stf-1b-{}-{}", std::process::id(), name));
    p
}

#[test]
fn compress_writes_a_gzip_file_and_reports_both_sizes() {
    let src = tmp("in.txt");
    let dst = tmp("in.txt.gz");
    let _ = std::fs::remove_file(&dst);
    let plain = b"the quick brown fox ".repeat(500);
    std::fs::write(&src, &plain).unwrap();

    let out = compress(
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &CompressOpts::default(),
    )
    .unwrap();

    assert_eq!(out.bytes_in, plain.len() as u64);
    assert!(
        out.bytes_out > 0 && out.bytes_out < out.bytes_in,
        "must actually compress"
    );
    assert_eq!(out.format.as_str(), "gzip");

    let written = std::fs::read(&dst).unwrap();
    assert_eq!(&written[..2], &[0x1f, 0x8b], "must be a real gzip stream");
    assert_eq!(
        written.len() as u64,
        out.bytes_out,
        "reported size must match the file"
    );

    // The source is kept, not consumed — this follows zstd, not gzip/xz.
    assert!(src.exists(), "compressing must not destroy the input");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[test]
fn an_existing_output_is_refused_without_force_and_is_left_untouched() {
    let src = tmp("guard-in.txt");
    let dst = tmp("guard-out.gz");
    std::fs::write(&src, b"payload").unwrap();
    std::fs::write(&dst, b"PRE-EXISTING").unwrap();

    let err = compress(
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &CompressOpts::default(),
    )
    .unwrap_err();

    assert!(matches!(err, stuffr::Error::Usage(_)));
    assert_eq!(err.exit_code(), 2);
    assert!(
        err.to_string().contains("--force"),
        "the error must say how to proceed"
    );
    // Checked BEFORE any work: the refused command must not have truncated it.
    assert_eq!(std::fs::read(&dst).unwrap(), b"PRE-EXISTING");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[test]
fn force_overwrites() {
    let src = tmp("force-in.txt");
    let dst = tmp("force-out.gz");
    std::fs::write(&src, b"payload").unwrap();
    std::fs::write(&dst, b"PRE-EXISTING").unwrap();

    let o = CompressOpts {
        force: true,
        ..Default::default()
    };
    compress(Input::Path(src.clone()), Output::Path(dst.clone()), &o).unwrap();
    assert_eq!(&std::fs::read(&dst).unwrap()[..2], &[0x1f, 0x8b]);

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[test]
fn an_out_of_range_level_surfaces_as_a_usage_error() {
    let src = tmp("level-in.txt");
    let dst = tmp("level-out.gz");
    let _ = std::fs::remove_file(&dst);
    std::fs::write(&src, b"payload").unwrap();

    let o = CompressOpts {
        level: Some(12),
        ..Default::default()
    };
    let err = compress(Input::Path(src.clone()), Output::Path(dst.clone()), &o).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    // And it must not have left a partial file behind.
    assert!(
        !dst.exists(),
        "a failed compress must clean up after itself"
    );

    let _ = std::fs::remove_file(&src);
}
