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

#[test]
fn a_rejected_level_leaves_a_forced_destination_byte_for_byte_intact() {
    let src = tmp("keep-in.txt");
    let dst = tmp("keep-out.gz");
    std::fs::write(&src, b"payload").unwrap();
    std::fs::write(&dst, b"PRE-EXISTING-AND-PRECIOUS").unwrap();

    // --force means "you may replace it", not "you may destroy it and produce
    // nothing". A usage error must leave the original exactly as it was.
    let o = CompressOpts {
        force: true,
        level: Some(12),
        ..Default::default()
    };
    let err = compress(Input::Path(src.clone()), Output::Path(dst.clone()), &o).unwrap_err();
    assert_eq!(err.exit_code(), 2);

    assert!(
        dst.exists(),
        "a usage error must not delete the destination"
    );
    assert_eq!(std::fs::read(&dst).unwrap(), b"PRE-EXISTING-AND-PRECIOUS");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[test]
fn a_rejected_level_leaves_no_temp_file_behind() {
    let src = tmp("notemp-in.txt");
    let dst = tmp("notemp-out.gz");
    std::fs::write(&src, b"payload").unwrap();
    std::fs::write(&dst, b"PRE-EXISTING").unwrap();

    let o = CompressOpts {
        force: true,
        level: Some(12),
        ..Default::default()
    };
    let _ = compress(Input::Path(src.clone()), Output::Path(dst.clone()), &o).unwrap_err();

    let dst_name = dst.file_name().unwrap().to_owned();
    let parent = dst.parent().unwrap().to_path_buf();
    let pid_marker = format!(".{}.", std::process::id());
    for entry in std::fs::read_dir(&parent).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == dst_name || name == src.file_name().unwrap() {
            continue;
        }
        let name_str = name.to_string_lossy();
        assert!(
            !name_str.contains(&pid_marker) || !name_str.contains("notemp-out"),
            "a leftover temp file was found: {name_str}"
        );
    }

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[cfg(unix)]
#[test]
fn a_forced_overwrite_preserves_the_destinations_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let src = tmp("perm-in.txt");
    let dst = tmp("perm-out.gz");
    std::fs::write(&src, b"payload").unwrap();
    std::fs::write(&dst, b"PRE-EXISTING").unwrap();
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600)).unwrap();

    let o = CompressOpts {
        force: true,
        ..Default::default()
    };
    compress(Input::Path(src.clone()), Output::Path(dst.clone()), &o).unwrap();

    let mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "a rename onto the destination must not widen its permissions"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[test]
fn suggested_names_add_and_strip_the_extension() {
    use std::path::Path;
    use stuffr::ops::{suggest_packed, suggest_unpacked};

    let gzip = stuffr::registry()
        .by_extension("gz")
        .expect("gzip must be registered");
    assert_eq!(
        suggest_packed(Path::new("/tmp/notes.txt"), gzip).unwrap(),
        Path::new("/tmp/notes.txt.gz"),
        "packing appends rather than replacing, so notes.txt.gz unpacks back to notes.txt"
    );
    assert_eq!(
        suggest_unpacked(Path::new("/tmp/notes.txt.gz")).unwrap(),
        Path::new("/tmp/notes.txt")
    );
}

#[test]
fn an_unrecognised_extension_asks_for_an_explicit_output() {
    use std::path::Path;
    use stuffr::ops::suggest_unpacked;

    let err = suggest_unpacked(Path::new("/tmp/mystery.bin")).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert!(
        err.to_string().contains("-o"),
        "the error must say how to proceed"
    );
}
