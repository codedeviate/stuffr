use stuffr::FormatId;
use stuffr::ops::{CompressOpts, Input, Output, compress};

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stf-1b-{}-{}", std::process::id(), name));
    p
}

/// Looks the id up in the real registry rather than constructing a
/// `FormatId` directly — see `ops_decompress.rs`'s identical helper for why.
///
/// Consumed by `a_pure_build_reads_zstd_and_writes_it_only_on_request`
/// (gated on `zstd-pure` without `zstd-c`) and
/// `the_c_backend_wins_when_both_zstd_features_are_compiled` (gated on
/// both) — mutually exclusive cfgs, so under any single feature
/// combination at most one of them compiles in and this helper would
/// otherwise be flagged dead code.
#[allow(dead_code)]
fn fmt(name: &str) -> FormatId {
    stuffr::registry()
        .matrix()
        .into_iter()
        .find(|row| row.id.as_str() == name)
        .unwrap_or_else(|| panic!("format `{name}` is not registered in this build"))
        .id
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
            // `/dev/null` has no extension to infer a format from, and this
            // build now registers more than one codec (Phase 1d), so an
            // explicit format is required — see `default_format_in`'s doc
            // comment. This test is about the dev/null write-through, not
            // format inference, so name one directly.
            format: Some(stuffr::FormatId::new("gzip")),
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
fn a_weak_encoder_is_refused_without_explicit_consent() {
    // A codec that admits its encoder is much worse than the format's usual one
    // must not be reachable by accident: a user who asked for `.xz` expects xz
    // ratios, and two builds of stf would otherwise produce very different files
    // from an identical command with no way to tell which they got.
    use std::io::Write;
    use stuffr_core::{
        Codec, CodecCaps, DecodeOpts, EncodeOpts, FormatId, FormatMeta, Result, Sink, Source,
    };

    const WEAK: FormatId = FormatId::new("weak-mock");

    #[derive(Debug)]
    struct WeakCodec;
    impl Codec for WeakCodec {
        fn id(&self) -> FormatId {
            WEAK
        }
        fn caps(&self) -> CodecCaps {
            CodecCaps {
                weak_encoder: true,
                ..CodecCaps::round_trip()
            }
        }
        fn decoder(&self, src: Box<dyn Source>, o: &DecodeOpts) -> Result<Box<dyn Source>> {
            stuffr_core::testing::MockCodec.decoder(src, o)
        }
        fn encoder(&self, d: Box<dyn Write + Send>, o: &EncodeOpts) -> Result<Box<dyn Sink>> {
            stuffr_core::testing::MockCodec.encoder(d, o)
        }
    }

    let mut reg = stuffr::core::Registry::new();
    reg.register_codec(
        std::sync::Arc::new(WeakCodec),
        FormatMeta::codec(WEAK, &["weak"], &[]),
    );

    let src = tmp("weak-in.txt");
    let dst = tmp("weak-out.weak");
    let _ = std::fs::remove_file(&dst);
    std::fs::write(&src, b"payload").unwrap();

    // Refused by default.
    let o = CompressOpts {
        format: Some(WEAK),
        ..Default::default()
    };
    let err = stuffr::ops::compress_with(
        &reg,
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &o,
    )
    .unwrap_err();
    assert_eq!(
        err.exit_code(),
        2,
        "consent is a usage matter, not a capability one: {err}"
    );
    assert!(
        err.to_string().contains("--allow-weak-encoder"),
        "must name the flag: {err}"
    );
    assert!(
        !dst.exists(),
        "a refused compress must not have touched the destination"
    );

    // Allowed with consent.
    let o = CompressOpts {
        format: Some(WEAK),
        allow_weak_encoder: true,
        ..Default::default()
    };
    stuffr::ops::compress_with(
        &reg,
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &o,
    )
    .unwrap();
    assert!(dst.exists());

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
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

#[test]
fn a_registry_with_two_non_gzip_codecs_reports_ambiguity_rather_than_guessing() {
    // Closes a Phase 1d deferred item: `default_format_in`'s ambiguity branch
    // (more than one codec, none of them gzip) was unreachable, because every
    // buildable configuration at the time always registered gzip alongside
    // whatever else was enabled. A hand-built registry with two non-gzip
    // codecs reaches it deterministically — this does not depend on finding a
    // real Cargo feature combination that excludes gzip, which turns out not
    // to be `--no-default-features --features zstd-pure` on this crate: that
    // invocation is a single-codec build (the "1 =>" branch below it, not
    // this one), and is covered separately by
    // `a_pure_build_reads_zstd_and_writes_it_only_on_request`.
    use std::sync::Arc;
    use stuffr::core::format::{FormatKind, FormatMeta};
    use stuffr::core::testing::MockCodec;

    let mut reg = stuffr::core::Registry::new();
    for name in ["mock-a", "mock-b"] {
        reg.register_codec(
            Arc::new(MockCodec),
            FormatMeta {
                id: FormatId::new(name),
                kind: FormatKind::Codec,
                extensions: &[],
                magics: &[],
                priority: 0,
            },
        );
    }

    let src = tmp("ambig-in.txt");
    std::fs::write(&src, b"payload").unwrap();
    let dst = tmp("ambig-out"); // no extension to infer from
    let _ = std::fs::remove_file(&dst);

    let err = stuffr::ops::compress_with(
        &reg,
        Input::Path(src.clone()),
        Output::Path(dst.clone()),
        &CompressOpts::default(),
    )
    .unwrap_err();

    assert_eq!(err.exit_code(), 2, "ambiguity is a usage matter: {err}");
    assert!(
        err.to_string().contains("cannot infer"),
        "must name the actual problem, not a generic usage error: {err}"
    );
    assert!(!dst.exists(), "nothing should have been written");

    let _ = std::fs::remove_file(&src);
}

#[test]
fn this_build_registers_exactly_one_backend_per_format() {
    // zstd_c and zstd_pure share a FormatId, so a registry with both would
    // silently keep whichever registered last. This asserts the cfg arms in
    // `stuffr_formats::register_all` are genuinely exclusive rather than
    // accidentally both-or-neither.
    //
    // This assertion alone is structurally UNABLE to catch a misselection,
    // though, and used to be the only one here: `Registry` is a
    // `HashMap<FormatId, _>` (`registry.rs`'s `codecs` field), so
    // `register_codec` on a duplicate id silently overwrites rather than
    // duplicating — `zstd_rows.len() <= 1` is true in EVERY possible build,
    // including one where `register_all`'s `not(feature = "zstd-c")` guard
    // was deleted and the wrong backend won. Proven by mutation during the
    // Phase 1e final review: deleting all three mutual-exclusion guards left
    // 396/396 tests and clippy green while a `c-backed` release binary
    // silently reported the PURE zstd backend active. See
    // `the_c_backend_wins_when_both_zstd_features_are_compiled` below for
    // the test that actually detects that failure mode — this one only
    // documents the row-count invariant that mutation left untouched.
    let reg = stuffr::registry();
    let zstd_rows: Vec<_> = reg
        .matrix()
        .into_iter()
        .filter(|r| r.id.as_str() == "zstd")
        .collect();
    assert!(
        zstd_rows.len() <= 1,
        "zstd registered {} times",
        zstd_rows.len()
    );
}

/// The test the finding above names: a genuine selection check, not a count.
///
/// `zstd_pure`'s `caps().weak_encoder` is `true` (a real, admitted
/// limitation — see `zstd_pure.rs`'s module doc) and `zstd_c`'s is `false`.
/// That is an observable difference between the two backends that survives
/// even after `register_all`'s `not(feature = "zstd-c")` guard makes the C
/// backend win, unlike a corrupted-stream exit code (xz's two backends are
/// DELIBERATELY made to agree on that — see the Phase 1e final review's
/// Finding 2 — so exit code cannot be the discriminator for every pair).
/// `Registry`'s `HashMap`-keyed storage means a duplicate registration
/// always collapses to one row (see the test above), so the only way to
/// prove WHICH one survived is to inspect a capability the two backends
/// actually disagree on.
///
/// Verified by mutation, the same way the review proved the old test
/// vacuous: deleting `register_all`'s `not(feature = "zstd-c")` guard from
/// the `zstd-pure` arm (`stuffr-formats/src/lib.rs`) makes this test FAIL —
/// `weak_encoder` flips to `true` because the pure arm, registered after the
/// C arm in `register_all`, silently overwrites it. The guard was restored
/// immediately afterward; the tree is clean.
#[test]
#[cfg(all(feature = "zstd-c", feature = "zstd-pure"))]
fn the_c_backend_wins_when_both_zstd_features_are_compiled() {
    let reg = stuffr::registry();
    let id = fmt("zstd");
    let caps = reg.codec(id).expect("zstd must be registered").caps();
    assert!(
        !caps.weak_encoder,
        "zstd's C backend must win when both zstd-c and zstd-pure are compiled — \
         weak_encoder=true means the pure backend silently took over, exactly the \
         regression register_all's `not(feature = \"zstd-c\")` guard exists to prevent"
    );
}

#[test]
#[cfg(all(feature = "zstd-pure", not(feature = "zstd-c")))]
fn a_pure_build_reads_zstd_and_writes_it_only_on_request() {
    // Reading is unconditional: opening a .zst must never need a flag.
    let reg = stuffr::registry();
    let id = fmt("zstd");
    assert!(reg.require_decoder(id).is_ok());
    assert!(
        reg.require_encoder(id).is_ok(),
        "ruzstd can encode, so the codec is not decode-only"
    );

    let src = tmp("zpure-in.txt");
    std::fs::write(&src, b"payload".repeat(500)).unwrap();
    let dst = tmp("zpure-out.zst");
    let _ = std::fs::remove_file(&dst);

    // Refused by default, naming the flag and the rebuild.
    let o = CompressOpts {
        format: Some(id),
        ..Default::default()
    };
    let err = compress(Input::Path(src.clone()), Output::Path(dst.clone()), &o).unwrap_err();
    assert_eq!(err.exit_code(), 2, "consent is a usage matter: {err}");
    assert!(
        err.to_string().contains("--allow-weak-encoder"),
        "must name the flag: {err}"
    );
    assert!(
        !dst.exists(),
        "a refused compress must not have touched the destination"
    );

    // Written on request, and the result is real zstd this build can read back.
    let o = CompressOpts {
        format: Some(id),
        allow_weak_encoder: true,
        ..Default::default()
    };
    compress(Input::Path(src.clone()), Output::Path(dst.clone()), &o).unwrap();
    assert!(dst.exists());

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}
