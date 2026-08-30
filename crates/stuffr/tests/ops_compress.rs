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
fn an_invalid_level_is_rejected_before_the_destination_is_touched() {
    // The destination sits in a directory that does not exist. If the level is
    // validated first we get a Usage error naming the level; if the destination
    // is opened first we get an i/o error about the missing directory. The two
    // are distinguishable, which is what makes this test able to fail.
    let src = tmp("order-in.txt");
    std::fs::write(&src, b"payload").unwrap();

    let mut dst = tmp("no-such-dir-order");
    dst.push("out.gz");

    let o = CompressOpts {
        level: Some(12),
        ..Default::default()
    };
    let err = compress(Input::Path(src.clone()), Output::Path(dst), &o).unwrap_err();

    assert_eq!(
        err.exit_code(),
        2,
        "an invalid level is a usage error, not i/o: {err}"
    );
    assert!(
        err.to_string().contains("0-9"),
        "the error must name the valid range, not the missing directory: {err}"
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

// The test formerly here (asserting the DESTINATION's final mode after a
// restrictive-permissions carry-over) was a byte-for-byte duplicate of
// `a_forced_overwrite_preserves_the_destinations_permissions` above: both
// check exactly the same thing, which the carry-over `set_permissions` call
// guarantees on its own regardless of what mode the temp file started at.
// Mutation-verified: removing `create_temp_file`'s `opts.mode(0o600)` left
// this test green, because the widening step that always immediately
// follows overwrites the temp file's mode before `Output::create` ever
// returns — the race the 0600-at-creation exists to close cannot be
// observed from the destination's final state at all. The test that
// actually pins it, `carrying_over_a_destination_creates_the_temp_file_at_
// 0600_before_any_widening` in `ops.rs`, calls `create_temp_file` directly,
// without letting the widening step run.

#[cfg(unix)]
#[test]
fn setuid_and_setgid_never_carry_over_onto_the_output() {
    // A destination that happens to carry setuid or setgid must never
    // propagate either bit onto a freshly compressed or decompressed
    // artefact — that is never what a user wants, regardless of how the
    // pre-existing file came to have it.
    use std::os::unix::fs::PermissionsExt;

    let src = tmp("setuid-in.txt");
    let dst = tmp("setuid-out.gz");
    std::fs::write(&src, b"payload").unwrap();
    std::fs::write(&dst, b"PRE-EXISTING").unwrap();
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o6644)).unwrap();

    compress(
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &CompressOpts {
            force: true,
            ..Default::default()
        },
    )
    .unwrap();

    let mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        mode, 0o644,
        "setuid/setgid must be masked off, not carried over onto the output: got {mode:o}"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

#[cfg(unix)]
#[test]
fn compressing_to_dev_null_succeeds_instead_of_failing_to_rename() {
    // F8: `/dev/null` already exists and is not a regular file, so renaming a
    // temp file onto it fails outright ("Operation not permitted"). The fix
    // writes straight through it instead of going via a temp file.
    let src = tmp("devnull-in.txt");
    std::fs::write(&src, b"payload").unwrap();

    let out = compress(
        Input::Path(src.clone()),
        Output::Path(std::path::PathBuf::from("/dev/null")),
        &CompressOpts {
            force: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(out.bytes_out > 0);

    let _ = std::fs::remove_file(&src);
}

#[cfg(unix)]
#[test]
fn compressing_to_a_symlink_destination_writes_through_it() {
    // F8: temp-then-rename would replace the symlink itself with a plain
    // file, silently turning `latest.gz -> archives/….gz` into a regular
    // file named `latest.gz` and leaving `archives/….gz` untouched. Writing
    // through the symlink instead must update the TARGET and leave the
    // symlink itself in place.
    let src = tmp("symlink-in.txt");
    let target = tmp("symlink-target.gz");
    let link = tmp("symlink-dest.gz");
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(&link);
    std::fs::write(&src, b"the quick brown fox ".repeat(200)).unwrap();
    std::fs::write(&target, b"PRE-EXISTING-TARGET-CONTENT").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    compress(
        Input::Path(src.clone()),
        Output::Path(link.clone()),
        &CompressOpts {
            force: true,
            ..Default::default()
        },
    )
    .unwrap();

    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the destination must still be a symlink after compressing to it"
    );
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        target,
        "the symlink must still point at the same target"
    );
    let written = std::fs::read(&target).unwrap();
    assert_eq!(
        &written[..2],
        &[0x1f, 0x8b],
        "the TARGET must have received the new gzip content"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(&link);
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

#[test]
fn sync_defaults_on_and_can_be_turned_off() {
    // The durability itself is not observable without crashing the machine, so
    // this pins the two things that are: the default, and that the flag reaches
    // the code path. A round trip under --no-sync must still produce a correct
    // file — the flag may cost durability, never correctness.
    assert!(
        CompressOpts::default().sync,
        "durability must be the default, not the opt-in"
    );

    let src = tmp("nosync-in.txt");
    let dst = tmp("nosync-out.gz");
    let _ = std::fs::remove_file(&dst);
    let plain = b"the quick brown fox ".repeat(100);
    std::fs::write(&src, &plain).unwrap();

    let o = CompressOpts {
        sync: false,
        ..Default::default()
    };
    let out = compress(Input::Path(src.clone()), Output::Path(dst.clone()), &o).unwrap();
    assert_eq!(out.bytes_in, plain.len() as u64);
    assert_eq!(&std::fs::read(&dst).unwrap()[..2], &[0x1f, 0x8b]);

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

/// The property `json_escape` used to guarantee by hand-rolled escaping:
/// warning variants embed archive-supplied entry names, so a quote,
/// backslash or newline in one must not break or forge the surrounding JSON.
/// serde guarantees it by construction now, but the property itself must
/// stay pinned through the real serializer, not just asserted away.
#[test]
fn a_hostile_entry_name_survives_serialization_as_data() {
    use stuffr::{Fidelity, FidelityReport, Rung};

    let mut report = FidelityReport::new(Rung::ForwardOnly);
    report.warn(Fidelity::EncryptedEntrySkipped {
        entry: "evil\", \"format\": \"pwned\n\\".into(),
    });

    let text = serde_json::to_string(&report).unwrap();
    let back: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        back["warnings"][0]["entry"], "evil\", \"format\": \"pwned\n\\",
        "the entry name must come back as data, not as structure"
    );
}

#[test]
fn a_caller_supplied_registry_is_the_one_that_is_used() {
    // A registry containing no codecs at all. If compress_with consults the
    // caller's registry the operation fails; if it quietly falls back to the
    // default it succeeds, and this test catches that.
    let empty = stuffr::core::Registry::new();

    let src = tmp("regsel-in.txt");
    let dst = tmp("regsel-out.gz");
    let _ = std::fs::remove_file(&dst);
    std::fs::write(&src, b"payload").unwrap();

    let err = stuffr::ops::compress_with(
        &empty,
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &CompressOpts::default(),
    )
    .unwrap_err();

    assert_eq!(
        err.exit_code(),
        2,
        "an empty registry offers no codec: {err}"
    );
    assert!(!dst.exists(), "nothing should have been written");

    let _ = std::fs::remove_file(&src);
}
