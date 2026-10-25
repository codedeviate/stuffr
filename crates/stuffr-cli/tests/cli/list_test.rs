use crate::common::*;
use std::process::Command;

// ---------------------------------------------------------------------
// `list` and `test` (Task 8): fixtures and helpers.
//
// Fixtures are built with the `tar` and `flate2` crates directly rather
// than through `stuffr pack`/a `stuffr-formats` writer — this build has no
// way to CREATE a tar archive yet (that's a later task), and using an
// independent generator means a read-side bug in `stuffr-formats::Tar`
// cannot also be hiding in the fixture that exercises it.
// ---------------------------------------------------------------------

#[test]
fn list_names_every_entry_and_extracts_nothing() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b/c.bin", b"\x00\xff")]);
    let out = run_output(&["list", archive.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("a.txt") && text.contains("b/c.bin"), "{text}");
    // Nothing was written to the filesystem.
    assert!(!dir.join("a.txt").exists(), "list must not extract");
    assert!(!dir.join("b").exists(), "list must not extract");
}

#[test]
fn ls_is_an_alias_for_list() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let out = run_output(&["ls", archive.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8(out.stdout).unwrap().contains("a.txt"));
}

#[test]
fn list_json_reports_name_kind_and_size() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let out = run_output(&["list", "--json", archive.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("not JSON: {e}\n{text}"));
    let rows = v.as_array().expect("a JSON array of entries");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "a.txt");
    assert_eq!(rows[0]["kind"], "file");
    assert_eq!(rows[0]["size"], 5);
}

#[test]
fn test_verb_exits_five_on_a_corrupt_archive_and_zero_on_a_good_one() {
    let dir = tmp_dir();
    let good = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    assert_eq!(run(&["test", good.to_str().unwrap()]).code(), Some(0));
    let bad = corrupt_midway(&good);
    assert_eq!(run(&["test", bad.to_str().unwrap()]).code(), Some(5));
}

#[test]
fn list_works_on_a_pipe() {
    // The streaming premise applied to the new verb.
    let dir = tmp_dir();
    let bytes = std::fs::read(write_fixture_tar(&dir, &[("a.txt", b"alpha")])).unwrap();
    let text = run_with_stdin(&["list", "-"], &bytes);
    assert!(text.contains("a.txt"), "{text}");
}

/// The forward risk flagged for this task: `open_archive` must not decode a
/// `.tar.gz`/`.tgz` layer twice, and `probe`'s peeking must not consume
/// bytes it doesn't replay — either bug reports every real `.tar.gz` as
/// "not a whole number of 512-byte blocks; the archive is truncated", which
/// looks exactly like corruption and is not. Verified here with a REAL
/// gzip (`flate2`) wrapping a REAL tar (`tar`), independent of
/// `stuffr-formats`' own writers, on a file AND on a pipe, for both
/// `.tar.gz` and `.tgz`.
#[test]
fn list_and_test_succeed_on_a_real_tar_gz_from_a_file() {
    let dir = tmp_dir();
    let archive = write_fixture_tar_gz(
        &dir,
        "fixture.tar.gz",
        &[("a.txt", b"alpha"), ("b/c.bin", b"\x00\xff")],
    );

    let list_out = run_output(&["list", archive.to_str().unwrap()]);
    assert!(
        list_out.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let text = String::from_utf8(list_out.stdout).unwrap();
    assert!(text.contains("a.txt") && text.contains("b/c.bin"), "{text}");

    let test_out = run_output(&["test", archive.to_str().unwrap()]);
    assert!(
        test_out.status.success(),
        "test stderr: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
}

#[test]
fn list_and_test_succeed_on_a_real_tar_gz_over_a_pipe() {
    let dir = tmp_dir();
    let archive = write_fixture_tar_gz(&dir, "fixture.tar.gz", &[("a.txt", b"alpha")]);
    let bytes = std::fs::read(&archive).unwrap();

    let list_out = run_with_stdin_output(&["list", "-"], &bytes);
    assert!(
        list_out.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    assert!(
        String::from_utf8(list_out.stdout)
            .unwrap()
            .contains("a.txt")
    );

    let test_out = run_with_stdin_output(&["test", "-"], &bytes);
    assert!(
        test_out.status.success(),
        "test stderr: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
}

#[test]
fn list_and_test_succeed_on_a_real_tgz_from_a_file() {
    let dir = tmp_dir();
    let archive = write_fixture_tar_gz(&dir, "fixture.tgz", &[("a.txt", b"alpha")]);

    let list_out = run_output(&["list", archive.to_str().unwrap()]);
    assert!(
        list_out.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    assert!(
        String::from_utf8(list_out.stdout)
            .unwrap()
            .contains("a.txt")
    );

    let test_out = run_output(&["test", archive.to_str().unwrap()]);
    assert!(
        test_out.status.success(),
        "test stderr: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
}

#[test]
fn list_and_test_succeed_on_a_real_tgz_over_a_pipe() {
    let dir = tmp_dir();
    let archive = write_fixture_tar_gz(&dir, "fixture.tgz", &[("a.txt", b"alpha")]);
    let bytes = std::fs::read(&archive).unwrap();

    let list_out = run_with_stdin_output(&["list", "-"], &bytes);
    assert!(
        list_out.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    assert!(
        String::from_utf8(list_out.stdout)
            .unwrap()
            .contains("a.txt")
    );

    let test_out = run_with_stdin_output(&["test", "-"], &bytes);
    assert!(
        test_out.status.success(),
        "test stderr: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
}

/// A truncation strictly INSIDE a single entry's declared payload, well
/// short of where any end-of-archive marker begins — the case `test`'s own
/// explicit payload read (`entries.rs::test`) is designed to catch, via
/// `Error::from_decode_io` reclassifying the raw `io::ErrorKind::InvalidData`
/// tar's `EntryPayload::read` raises when delivered bytes fall short of the
/// header's declared size (see that message below) — a bare `?` there would
/// have surfaced as exit 1, not exit 5.
///
/// `list` (which never reads a payload) turns out to ALSO exit 5 here, but
/// via a wholly different path and message: walking headers to completion
/// forces the underlying `tar` crate to skip past this entry's unread
/// payload before it can look for the next header, and that skip itself
/// reports "unexpected EOF during skip". So the two verbs converge on the
/// same outcome for tar's length-based corruption specifically — this test
/// pins BOTH messages so a future change that silently drops either
/// detection path is caught, without claiming `list` succeeds where it does
/// not.
#[test]
fn test_catches_a_payload_truncation() {
    let dir = tmp_dir();
    let payload = vec![b'x'; 8192];
    let full = write_fixture_tar(&dir, &[("big.bin", &payload)]);
    let bytes = std::fs::read(&full).unwrap();
    // One 512-byte header block, then a third of the way into the payload.
    let cut = 512 + payload.len() / 3;
    let truncated = dir.join("truncated.tar");
    std::fs::write(&truncated, &bytes[..cut]).unwrap();

    let test_out = run_output(&["test", truncated.to_str().unwrap()]);
    assert_eq!(
        test_out.status.code(),
        Some(5),
        "test reads the payload and must catch the truncation: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
    let test_err = String::from_utf8_lossy(&test_out.stderr);
    assert!(
        test_err.contains("big.bin") && test_err.contains("short of the size"),
        "must be tar's own per-entry short-read diagnosis, reclassified from a raw \
         io::ErrorKind::InvalidData via Error::from_decode_io: {test_err}"
    );

    let list_out = run_output(&["list", truncated.to_str().unwrap()]);
    assert_eq!(
        list_out.status.code(),
        Some(5),
        "list also exits 5 here, via the tar crate's own header-skip detection, not via a \
         payload read: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
}

/// The `container` fuzz target's own reproducer, minimised by `cargo fuzz
/// tmin` from the 6,779-byte artefact to the 540 bytes below, asserted at
/// the CLI because that is where the defect was user-visible.
///
/// **What it was:** `stuffr list`, `stuffr test` and `stuffr unpack` all
/// exited **1** — `stuffr: i/o error: Invalid argument (os error 22)` —
/// which in this project means *stuffr itself failed*. The oracle's own
/// words were `next_entry error classification: "a decoder raised Io(Os {
/// code: 22, kind: InvalidInput, message: \"Invalid argument\" }), which
/// maps to exit code 1"`.
///
/// **Why:** a zip64 extended-information extra field (tag `0x0001`) in the
/// central directory supplies an 8-byte relative local-header offset, and
/// `zip-8.6.0` hands it straight to `Seek::seek(SeekFrom::Start(..))`. On
/// unix `std` casts that `u64` to `off_t`, an `i64`, so anything above
/// `i64::MAX` reaches `lseek(2)` NEGATIVE and the kernel answers `EINVAL` —
/// a genuine errno that `Error::from_decode_io` does not fold.
///
/// The refusal now comes from `stuffr_core::source::GuardedSeek`, one layer
/// below every container, so this is a class fix and not a zip patch. Exit 5
/// rather than 6 by `error.rs`'s `exit_code` rule: nothing was allocated
/// from the offset, and what is wrong is the file's agreement with itself.
///
/// The assertion is on the CLASSIFIED outcome, not merely on "not 1": a
/// guard that turned one wrong answer into another would pass that.
#[test]
fn a_zip_declaring_an_unreachable_local_header_offset_exits_5_not_1() {
    // Hex rather than a checked-in binary: 540 bytes of fuzzer output has no
    // provenance a `fixtures/MANIFEST.md` entry could usefully describe, and
    // inline bytes cannot drift away from the test that stands on them.
    const MINIMISED_REPRODUCER: &str = concat!(
        "4b4d4d00504b010214031400000000000a3b375d0000000000000000000001010101e900000000000000237718c33a17",
        "fbe047df010101010101010166722066757a7a7403034b50ffff1304504b05060000000001000008f500040000000000",
        "000000000000005da481a9000007054b5000000a3b375dbc6ab89d2a00000000000000000b00000000000000000000a4",
        "81250000bf5907054b5047bbd19819f9938fb5527f0414d3000000000a3b375d000000000010000000004f0102141403",
        "1400000008000a3b375d06ff880a7374756666722066757a7a7403034b50ffff1304504b05060000000001000008f500",
        "0000ed000000000000000000005da481a900000081a90000001400000008000a3b375d06ff880a737475666672206675",
        "7a7a7403034b50ffff1304504b05060000000001000008f5000000ed000000000000000000005da481a900000081a900",
        "0000000000ed000000000000000000005da481a900000081a9000000a481a900000081a900000008000a3b375d06ff88",
        "0a7374756666722066757a7a7403034b50ffff1304504b05060000000001000008005da481a900000081000000000000",
        "5da481a900000081a9000000000000ed000000000000000000005da481a900000081a9000000a481a900000081a90000",
        "00000000000000000000005da481a900000081a9000000000000ed000000000000000000005da481a900000081a90000",
        "00a481a900000081a9000000",
    );

    let bytes: Vec<u8> = (0..MINIMISED_REPRODUCER.len() / 2)
        .map(|i| u8::from_str_radix(&MINIMISED_REPRODUCER[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    assert_eq!(bytes.len(), 540, "the reproducer must be carried verbatim");

    let dir = tmp_dir();
    let archive = dir.join("unreachable-offset.zip");
    std::fs::write(&archive, &bytes).unwrap();

    for verb in ["list", "test"] {
        let out = run_output(&[verb, archive.to_str().unwrap()]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(5),
            "`{verb}` must report the ARCHIVE as corrupt, never exit 1: {err}"
        );
        assert!(
            err.contains("archive is corrupt")
                && err.contains("largest position any file can hold"),
            "the refusal must name what the archive declared, not an errno: {err}"
        );
        assert!(
            !err.contains("os error 22"),
            "a bare errno reaching the user is the defect itself: {err}"
        );
    }

    let out = run_output(&[
        "unpack",
        "-C",
        dir.join("out").to_str().unwrap(),
        archive.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(5),
        "`unpack` too: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A zip symlink target declared over 64 KiB is a resource limit (exit 6),
/// the same answer cpio gives for the same predicate against the same
/// constant. It was exit 5 (corrupt) until 0.10.4. The control at exactly the
/// ceiling proves the fixture is a readable zip and the refusal is the
/// target's length, not the fixture's shape.
#[test]
fn a_zip_symlink_target_over_64_kib_exits_6_and_one_at_the_ceiling_does_not() {
    let dir = tmp_dir();

    let ok = dir.join("at-ceiling.zip");
    std::fs::write(&ok, zip_with_one_symlink("link", 65_536)).unwrap();
    let out = run_output(&["list", ok.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a 65,536-byte target is at the ceiling, not over it: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let big = dir.join("over-ceiling.zip");
    std::fs::write(&big, zip_with_one_symlink("link", 65_537)).unwrap();
    for verb_args in [
        vec!["list", big.to_str().unwrap()],
        vec!["test", big.to_str().unwrap()],
    ] {
        let out = run_output(&verb_args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(6),
            "`{}` must refuse the target as a resource limit: {err}",
            verb_args[0]
        );
        assert!(
            err.contains("65537") && err.contains("65536"),
            "the refusal names the declared length and the ceiling: {err}"
        );
    }

    let out = run_output(&[
        "unpack",
        "-C",
        dir.join("out").to_str().unwrap(),
        big.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(6),
        "`unpack` too: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run_output(&["cat", big.to_str().unwrap(), "link"]);
    assert_eq!(
        out.status.code(),
        Some(6),
        "`cat` too: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run_output(&[
        "convert",
        big.to_str().unwrap(),
        dir.join("converted.tar").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(6),
        "`convert` too: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn list_refuses_a_plain_codec_stream_as_not_an_archive() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    let gz = dir.join("notes.txt.gz");
    std::fs::write(&src, b"just plain text, not an archive").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let out = run_output(&["list", gz.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not an archive"), "{err}");
    assert!(
        err.contains("gzip"),
        "must name what the input actually resolved to: {err}"
    );
}

#[test]
fn list_refuses_nesting_past_the_depth_bound() {
    let mut bytes = b"payload too shallow to be an archive".to_vec();
    // MAX_CHAIN_DEPTH is 4; six gzip layers is comfortably past it.
    for _ in 0..6 {
        bytes = gzip_wrap(&bytes);
    }
    let out = run_with_stdin_output(&["list", "-"], &bytes);
    assert_eq!(
        out.status.code(),
        Some(6),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("nesting"), "{err}");
}

/// Task 4b (Phase 3a's fuzzing harness found this within seconds of the
/// `chain` target running). A truncated zlib stream with no container atop
/// it: `resolve_chain_deep_with` cannot resolve a container from the path
/// (`.zz` names nothing) or from the decoded bytes (there aren't enough of
/// them), so it falls into the peek-the-decoded-stream loop in
/// `probe.rs::resolve_chain_deep_with`, which used to hand the raw
/// `io::ErrorKind::InvalidData` `probe(decoded)` raised straight through a
/// bare `?` — `Error::Io`, exit 1, "stuffr failed" — for bytes that are
/// simply corrupt. `cat` (via `ops::decompress`, which already routes its
/// decode read through `Error::from_decode_io`) always got this right; the
/// two verbs disagreeing on the exit code for the identical bytes is the
/// bug.
#[test]
fn list_reports_a_truncated_codec_stream_as_corrupt_not_as_an_io_failure() {
    let dir = tmp_dir();
    let trunc = dir.join("trunc.zz");
    // A valid zlib header (`78 da`) plus one more byte, then nothing —
    // enough to identify the format, not enough to decode a single byte of
    // payload.
    std::fs::write(&trunc, [0x78, 0xda, 0x0a]).unwrap();

    let cat_out = run_output(&["cat", trunc.to_str().unwrap()]);
    assert_eq!(
        cat_out.status.code(),
        Some(5),
        "cat (unaffected by this bug) must still exit 5: {}",
        String::from_utf8_lossy(&cat_out.stderr)
    );

    let list_out = run_output(&["list", trunc.to_str().unwrap()]);
    assert_eq!(
        list_out.status.code(),
        Some(5),
        "list must agree with cat on the SAME bytes — exit 1 here means stuffr claimed it \
         failed, when the truth is the input is corrupt: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_err = String::from_utf8_lossy(&list_out.stderr);
    assert!(
        list_err.contains("archive is corrupt"),
        "must be Error::Corrupt's own wording, not Error::Io's: {list_err}"
    );
}

/// The second shape Task 4b's fuzzing found: an EMPTY file named `.lz`.
/// `lzip`'s decoder does not check the magic until its first `read`, so this
/// hits the identical `probe(decoded)` site as the truncated-zlib case
/// above, by a different route — an empty stream rather than a short one.
#[test]
fn list_reports_an_empty_lzip_stream_as_corrupt_not_as_an_io_failure() {
    let dir = tmp_dir();
    let empty = dir.join("empty.lz");
    std::fs::write(&empty, []).unwrap();

    let cat_out = run_output(&["cat", empty.to_str().unwrap()]);
    assert_eq!(
        cat_out.status.code(),
        Some(5),
        "cat (unaffected by this bug) must still exit 5: {}",
        String::from_utf8_lossy(&cat_out.stderr)
    );

    let list_out = run_output(&["list", empty.to_str().unwrap()]);
    assert_eq!(
        list_out.status.code(),
        Some(5),
        "list must agree with cat on the SAME bytes: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_err = String::from_utf8_lossy(&list_out.stderr);
    assert!(
        list_err.contains("archive is corrupt") && list_err.contains("LZIP"),
        "must be Error::Corrupt's own wording, naming what lzip's decoder actually \
         complained about: {list_err}"
    );
}

/// A directory handed to a read verb is a usage error (exit 2), never
/// `i/o error: Is a directory` at exit 1: `File::open` succeeds on a directory
/// and only the first `read` fails, so the refusal has to come first. Every
/// verb that reads one stream owes it, and none may touch its destination.
///
/// This replaces `list_reports_a_directory_as_an_io_failure_not_as_corrupt`,
/// whose directory-as-i/o-failure premise no longer holds. Its real guard —
/// that a raw-source `InvalidData` read error stays `Error::Io` rather than
/// becoming `Corrupt` — was never provable from a directory (`IsADirectory`
/// is not a kind `from_decode_io` reclassifies) and lives, with the kind that
/// matters, in `probe.rs`'s
/// `a_raw_source_io_error_of_the_identical_kind_stays_io_not_corrupt`.
#[test]
fn a_directory_input_is_a_usage_error_for_every_read_verb() {
    let dir = tmp_dir();
    let d = dir.join("d");
    std::fs::create_dir_all(&d).unwrap();
    let out_dir = dir.join("out");
    let d = d.to_str().unwrap();
    let o = out_dir.to_str().unwrap();

    let out_file = dir.join("out.bin");
    let f = out_file.to_str().unwrap();
    let cases: [&[&str]; 8] = [
        &["list", d],
        &["test", d],
        &["cat", d],
        &["cat", d, "x"],
        &["unpack", d, "-o", f],
        &["unpack", d, "-C", o],
        &["info", d],
        &["salvage", d, "-C", o],
    ];
    for args in cases {
        let out = run_output(args);
        let err = stderr_text(&out);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(
            err.contains("is a directory") && err.contains("stuffr pack"),
            "{args:?}: {err}"
        );
        assert!(!out_dir.exists(), "{args:?} created its destination");
        assert!(!out_file.exists(), "{args:?} created its output file");
    }
}

/// The 21 bytes the `chain` fuzz target's honesty oracle caught after the
/// previous exit-1 defect in this series was fixed. A zstd frame whose
/// DECODED bytes open with ARJ's `60 EA` magic, then run on for about a
/// kilobyte before the frame's second block fails to parse.
///
/// Its route is the one Task 4b's fix does not cover, and cannot: the good
/// prefix satisfies `resolve_chain_deep_with`'s re-probe window completely,
/// so the `probe(decoded)` call Task 4b classified never sees a failure at
/// all. The chain resolves cleanly to `arj` over `zstd`, ARJ declares
/// `needs_seek`, a decoder's output is never seekable — so the ladder takes
/// rung 3 and `SpillSource::materialize` drains the decoded stream into a
/// spool. That drain read through a bare `?`.
///
/// Measured before the fix, on the `0.5.0` binary:
///
/// ```text
/// stuffr list -> exit 1 :: stuffr: i/o error: Failed to parse/decode block body: ...
/// stuffr test -> exit 1 :: same
/// stuffr cat  -> exit 5 :: stuffr: archive is corrupt: ...
/// ```
///
/// Exit 5 and not 6, per `Error::exit_code`'s own rule: stuffr read the bytes
/// and they contradict each other, and no allocation was ever in question.
///
/// The bytes are embedded rather than generated because generating them means
/// encoding zstd, which the default (pure) tier will not do without
/// `--allow-weak-encoder` — and because a reproducer that is recomputed is a
/// reproducer that can quietly stop reproducing.
#[test]
fn list_reports_a_zstd_stream_that_decodes_into_arj_magic_as_corrupt() {
    const ZSTD_OVER_ARJ_MAGIC: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x30, 0x00, 0x00, 0x60, 0xea, 0x05, 0x06, 0x28, 0x0a,
        0x0a, 0x0a, 0x0a, 0x0a, 0x70, 0x00,
    ];

    let dir = tmp_dir();
    let repro = dir.join("repro.zst");
    std::fs::write(&repro, ZSTD_OVER_ARJ_MAGIC).unwrap();
    let path = repro.to_str().unwrap();

    let cat_out = run_output(&["cat", path]);
    assert_eq!(
        cat_out.status.code(),
        Some(5),
        "cat was already right on these bytes and must stay right: {}",
        String::from_utf8_lossy(&cat_out.stderr)
    );

    for verb in ["list", "test"] {
        let out = run_output(&[verb, path]);
        assert_eq!(
            out.status.code(),
            Some(5),
            "`{verb}` must agree with cat on the SAME bytes — exit 1 here means stuffr claimed \
             it failed, when the truth is the input is corrupt: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("archive is corrupt"),
            "must be Error::Corrupt's own wording, not Error::Io's: {err}"
        );
    }
}

/// The second shape the same enumeration turned up, and one no fuzz target
/// found: a `--max-ratio` refusal below a container.
///
/// 60 bytes of zstd expanding to 1 MiB of zeros behind ARJ's `60 EA` magic.
/// `RatioGuardedSource` raises `io::ErrorKind::OutOfMemory` specifically so
/// the classification maps it to `Error::ResourceLimit`, exit 6 — and below a
/// container that conversion never ran, because the refusal met
/// `SpillSource::materialize`'s bare `?` instead. Measured before the fix:
///
/// ```text
/// stuffr list -> exit 1 :: stuffr: i/o error: expansion ratio 17476:1 exceeds the 10000:1 limit
/// stuffr cat  -> exit 6 :: stuffr: resource limit exceeded: <same figures>
/// ```
///
/// Exit 6 and not 5, the other side of `Error::exit_code`'s rule: a LIMIT
/// decided the outcome, nothing was read that contradicts anything, and
/// `--max-ratio` names the knob that changes the answer.
///
/// It fires under the DEFAULT ratio, so no flag is passed — the bomb is real,
/// not a tightened bound arranged to trip.
#[test]
fn a_ratio_refusal_below_a_container_is_a_resource_limit_not_an_io_failure() {
    const ZSTD_BOMB_OVER_ARJ_MAGIC: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0xa4, 0x02, 0x00, 0x10, 0x00, 0x5c, 0x00, 0x00, 0x18, 0x60, 0xea,
        0x00, 0x01, 0x00, 0xfa, 0xff, 0x39, 0x18, 0x02, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
        0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00,
        0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xb2, 0xa6, 0x83,
    ];

    let dir = tmp_dir();
    let bomb = dir.join("bomb.zst");
    std::fs::write(&bomb, ZSTD_BOMB_OVER_ARJ_MAGIC).unwrap();
    let path = bomb.to_str().unwrap();

    let cat_out = run_output(&["cat", path]);
    assert_eq!(
        cat_out.status.code(),
        Some(6),
        "cat was already right and must stay right: {}",
        String::from_utf8_lossy(&cat_out.stderr)
    );

    for verb in ["list", "test"] {
        let out = run_output(&[verb, path]);
        assert_eq!(
            out.status.code(),
            Some(6),
            "`{verb}` must agree with cat: a refused expansion bomb is a limit, never \
             \"stuffr failed\": {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("resource limit exceeded") && err.contains("--max-ratio"),
            "must be Error::ResourceLimit's own wording, naming the knob: {err}"
        );
    }
}
