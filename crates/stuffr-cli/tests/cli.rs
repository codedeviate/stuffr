use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use flate2::Compression;
use flate2::write::GzEncoder;
use tar::{Builder, Header};

const STUFFR: &str = env!("CARGO_BIN_EXE_stuffr");

/// A token unique to THIS test-binary run, mixed into every temp path below.
///
/// `{pid}-{something}` was NOT unique enough, and the failure it caused reads
/// exactly like a code defect. These directories are never removed on a
/// failing path, PIDs are reused within a day, and a later run landing on a
/// recycled PID then inherits its predecessor's directories *with their
/// contents in them* — so five unrelated tests failed with "already exists"
/// against 4436 leftovers, and deleting the leftovers turned the gate green
/// with no code change at all. A false red that costs a session.
///
/// `RandomState` is the dependency-free source of per-process randomness in
/// `std`: its hasher keys are seeded from the OS, so two concurrent or
/// consecutive runs cannot agree on this token however their PIDs land. It
/// makes the name collision-proof rather than merely unlikely, which is the
/// property that matters — a teardown would still leave the window open for
/// a run that crashes or is interrupted.
static RUN_TOKEN: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    use std::hash::{BuildHasher, Hasher};
    let n = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!("{}-{n:016x}", std::process::id())
});

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-cli-{}-{name}", *RUN_TOKEN));
    p
}

// A bare `pack src` with neither `-o` nor `--format` can only default when
// exactly one codec is registered (see `default_format_in`'s doc comment in
// `stuffr::ops`). Phase 1d's `pure` build now registers three, so tests that
// are not actually exercising format inference pin gzip explicitly with
// `--format gzip` rather than relying on a default that no longer exists.

#[test]
fn formats_now_reports_gzip() {
    let out = Command::new(STUFFR).arg("formats").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("gzip"), "gzip must appear: {text}");
    assert!(
        !text.contains("0 formats"),
        "the build is no longer empty: {text}"
    );
}

#[test]
fn info_names_the_format_and_the_rung() {
    let src = tmp("info.txt");
    let gz = tmp("info.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"payload").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let out = Command::new(STUFFR)
        .args(["info", gz.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("gzip"), "{text}");
    assert!(text.contains("exact"), "a file is read exactly: {text}");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn info_json_is_structured_and_names_how_the_format_was_detected() {
    let src = tmp("json2.txt");
    let gz = tmp("json2.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"payload").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let out = Command::new(STUFFR)
        .args(["info", "--json", gz.to_str().unwrap()])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("not JSON: {e}\n{text}"));

    assert_eq!(v["format"], "gzip");
    assert_eq!(v["rung"], "exact");
    assert_eq!(
        v["detected_by"], "magic",
        "a real gzip file is identified by its magic, not its name"
    );
    assert!(v["warnings"].as_array().unwrap().is_empty());

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

/// `info` has no `--threads` (multi-threaded decode is out of scope this
/// phase), so there is no worker count to resolve — only the memory limit a
/// subsequent pack/unpack would use, either the value `--memory-limit`
/// names or `default_memory_limit()`'s auto-detected reading. Pinning an
/// explicit value keeps this test independent of the host's actual RAM.
#[test]
fn info_reports_the_resolved_memory_limit() {
    let src = tmp("info-mem.txt");
    let gz = tmp("info-mem.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"payload").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let out = Command::new(STUFFR)
        .args(["info", "--memory-limit", "512M", gz.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    // Asserts the RENDERED form, because that is what a user reads. `info`
    // prints "512 MiB" rather than "536870912 bytes" — the raw count is
    // technically the same information and unusable for checking a limit at a
    // glance. If this is ever changed back, the assertion should change with
    // it rather than being loosened to match both.
    assert!(
        text.contains("512 MiB"),
        "an explicit --memory-limit must be reflected in the report: {text}"
    );

    let out = Command::new(STUFFR)
        .args([
            "info",
            "--json",
            "--memory-limit",
            "512M",
            gz.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("not JSON: {e}\n{text}"));
    assert_eq!(v["memory_limit"], 512 * 1024 * 1024);

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

/// The whole `info` fidelity rule, all four cases in one place, because the
/// discrimination is TWO-dimensional: it turns on the rung AND on whether the
/// container has anything to lose on a forward read.
///
/// This test exists because the first version of the fix was one-dimensional
/// — it withheld the claim for every container — which merely inverted the
/// dishonesty: "not evaluated" on a `.tar` is a false NEGATIVE, since a
/// forward read of a tar approximates nothing at all. Nothing pinned tar's
/// `info` text, which is exactly how the widening slipped through, so all
/// four cases are pinned here now.
#[test]
fn info_withholds_the_fidelity_claim_only_where_a_forward_read_could_lose_something() {
    let dir = tmp("info-fidelity-matrix");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let one = dir.join("one.txt");
    std::fs::write(&one, b"payload").unwrap();

    // Built through the CLI so these are the same archives a user gets.
    let mut archives = Vec::new();
    for (ext, has_trailing_index) in [("zip", true), ("tar", false), ("cpio", false), ("a", false)]
    {
        let path = dir.join(format!("bundle.{ext}"));
        assert!(
            Command::new(STUFFR)
                .args(["pack", one.to_str().unwrap(), "-o", path.to_str().unwrap()])
                .status()
                .unwrap()
                .success(),
            "packing a .{ext} must succeed"
        );
        archives.push((ext, path, has_trailing_index));
    }

    for (ext, path, has_trailing_index) in &archives {
        let bytes = std::fs::read(path).unwrap();

        // (a) SEEKABLE: the container reads its own structures whatever they
        //     are, so nothing is lost and the claim is true for every format
        //     here — zip included.
        let text = String::from_utf8(
            Command::new(STUFFR)
                .args(["info", path.to_str().unwrap()])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(text.contains("exact"), ".{ext} from a file: {text}");
        assert!(
            text.contains("nothing approximated"),
            ".{ext} from a FILE was read exactly — the claim is true and must be made: {text}"
        );

        // (b) PIPED: now it depends on the format. Only a trailing index can
        //     be missed by a forward read.
        let text = info_over_stdin(&bytes);
        assert!(text.contains("forward-only"), ".{ext} on a pipe: {text}");
        if *has_trailing_index {
            assert!(
                text.contains("not evaluated"),
                ".{ext} keeps its index at the END of the stream, so a forward read may well \
                 have approximated something and info has not looked: {text}"
            );
            assert!(!text.contains("nothing approximated"), ".{ext}: {text}");
        } else {
            assert!(
                text.contains("nothing approximated"),
                ".{ext} carries every entry's metadata inline, so a forward read loses \
                 NOTHING — withholding the claim here is a false negative: {text}"
            );
            assert!(!text.contains("not evaluated"), ".{ext}: {text}");
        }

        // And the ground truth for the `else` branch above, from the command
        // that DOES open the archive: a piped tar/cpio/ar really does report
        // no warnings, so "nothing approximated" is not merely convenient.
        let mut child = Command::new(STUFFR)
            .args(["test", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        if *has_trailing_index {
            assert!(
                stderr.contains("fidelity warning"),
                ".{ext} on a pipe must really have warnings, or info would be right to \
                 claim none: {stderr}"
            );
        } else {
            assert!(
                out.status.success() && !stderr.contains("fidelity warning"),
                ".{ext} on a pipe must really have NO warnings, which is what makes info's \
                 claim true: {stderr}"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// `info` must not report a fidelity conclusion it did not reach.
///
/// `inspect` identifies a stream WITHOUT decoding it — that is its documented
/// contract — so it never opens the container and cannot know what a real
/// read would have approximated. It printed "nothing approximated" anyway,
/// which was harmless for tar, ar and cpio (a forward read of those really
/// does approximate nothing) and a flat contradiction for zip, whose
/// authoritative index is at the END of the stream: `stuffr test -` on the
/// very same bytes reports two warnings.
///
/// The fix is to withhold the claim, not to make `info` open the archive.
/// This test asserts both halves of that: `info` no longer claims, and
/// `test` still does.
#[test]
fn info_on_a_piped_zip_does_not_claim_nothing_was_approximated() {
    let dir = tmp("info-zip-fidelity");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let one = dir.join("one.txt");
    std::fs::write(&one, b"payload").unwrap();
    let zip = dir.join("bundle.zip");
    assert!(
        Command::new(STUFFR)
            .args(["pack", one.to_str().unwrap(), "-o", zip.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let bytes = std::fs::read(&zip).unwrap();

    let text = info_over_stdin(&bytes);
    assert!(
        text.contains("forward-only"),
        "the rung is still real and still reported: {text}"
    );
    assert!(
        !text.contains("nothing approximated"),
        "info has not opened the archive, so it must not claim this: {text}"
    );
    assert!(
        text.contains("not evaluated"),
        "the line must say the conclusion was withheld, not vanish: {text}"
    );

    // The other half: `test`, which DOES open the archive, still reports the
    // two warnings. Without this the assertion above could be satisfied by
    // having lost the warnings altogether.
    let mut child = Command::new(STUFFR)
        .args(["test", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("central/trailing index was never read")
            && stderr.contains("entry count is unknown"),
        "`test` opens the archive and must still report both losses: {stderr}"
    );

    // A real FILE is the other side of the rule and was WRONG in round 2:
    // the rung is `exact`, so a zip read from a file consults its central
    // directory and loses nothing. The claim is true there and must be made.
    // `info_withholds_the_fidelity_claim_only_where_a_forward_read_could_lose_something`
    // covers the full matrix; this keeps the contrast next to the defect.
    let out = Command::new(STUFFR)
        .args(["info", zip.to_str().unwrap()])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("exact"), "a file is read exactly: {text}");
    assert!(
        text.contains("nothing approximated"),
        "a seekable zip reads its central directory, so nothing is approximated: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The other side of the same fix: a bare CODEC stream has no container to
/// open, so its empty warning list is a genuine finding and `info` must go on
/// reporting it. Without this, "withhold the claim" could have been
/// implemented by withholding it everywhere.
#[test]
fn info_on_a_bare_codec_stream_still_reports_nothing_approximated() {
    let src = tmp("info-codec-fidelity.txt");
    let gz = tmp("info-codec-fidelity.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"payload").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );
    let bytes = std::fs::read(&gz).unwrap();

    for (what, text) in [
        (
            "a file",
            String::from_utf8(
                Command::new(STUFFR)
                    .args(["info", gz.to_str().unwrap()])
                    .output()
                    .unwrap()
                    .stdout,
            )
            .unwrap(),
        ),
        ("a pipe", info_over_stdin(&bytes)),
    ] {
        assert!(
            text.contains("nothing approximated"),
            "{what}: a bare codec stream has no container to open, so this claim is real \
             and must survive: {text}"
        );
        assert!(!text.contains("not evaluated"), "{what}: {text}");
    }

    // The JSON shape carries the same distinction, since `warnings: []` is
    // ambiguous on its own.
    let out = Command::new(STUFFR)
        .args(["info", "--json", gz.to_str().unwrap()])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out.stdout).unwrap())
        .expect("info --json must be JSON");
    assert_eq!(v["fidelity_evaluated"], true, "{v}");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

/// Runs `stuffr info -` over `bytes` and returns its stdout.
fn info_over_stdin(bytes: &[u8]) -> String {
    let mut child = Command::new(STUFFR)
        .args(["info", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "stuffr info - must succeed");
    String::from_utf8(out.stdout).unwrap()
}

/// Together with `info_names_the_format_and_the_rung` (a file, "exact"),
/// this proves the rung is COMPUTED from the source's seekability rather
/// than hardcoded — neither test alone would catch a rung that was pinned
/// to a constant.
#[test]
fn info_over_a_pipe_reports_forward_only_not_exact() {
    let src = tmp("pipe-info.txt");
    let gz = tmp("pipe-info.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"payload").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let gz_bytes = std::fs::read(&gz).unwrap();

    let mut child = Command::new(STUFFR)
        .args(["info", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&gz_bytes).unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("gzip"), "{text}");
    assert!(
        text.contains("forward-only"),
        "a pipe cannot seek, so the rung must not be exact: {text}"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

/// `head -c N`, `grep -m1`, `less` — every consumer that decides it has seen
/// enough and closes the pipe early. Rust ignores SIGPIPE, so the writer
/// would otherwise see this as an EPIPE `io::Error` and report a spurious
/// failure; every conventional Unix filter (zcat, gzip -d, cat) treats an
/// early-exiting reader as normal termination instead.
#[test]
fn cat_exits_cleanly_when_the_reader_closes_early() {
    let src = tmp("broken-pipe.txt");
    let gz = tmp("broken-pipe.txt.gz");
    let _ = std::fs::remove_file(&gz);
    // Large enough (and compressible enough) that the decompressed write to
    // stdout badly outlasts the handful of bytes we read below — the point
    // is for the write to still be in flight when we close the read end.
    let payload = "the quick brown fox jumps over the lazy dog\n".repeat(500_000);
    std::fs::write(&src, payload.as_bytes()).unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let mut child = Command::new(STUFFR)
        .args(["cat", gz.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdout = child.stdout.take().unwrap();
    let mut prefix = [0u8; 16];
    stdout
        .read_exact(&mut prefix)
        .expect("at least a few bytes before we stop reading");
    drop(stdout); // close our read end, like `head` exiting early

    let mut stderr = child.stderr.take().unwrap();
    let mut err_text = String::new();
    stderr.read_to_string(&mut err_text).unwrap();

    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "an early-closing reader must not look like a failure: {status:?}"
    );
    assert!(
        err_text.is_empty(),
        "a clean broken-pipe exit prints nothing: {err_text}"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn formats_exits_cleanly_on_a_closed_stdout() {
    // `println!`/`print!` panic on a write error instead of returning one,
    // which bypasses `run`'s BrokenPipe-to-success mapping entirely: `stuffr
    // formats` and `stuffr info` used to exit 101 with "failed printing to
    // stdout: Broken pipe" against a closed reader, even though
    // `destination_is_stdout` already lists both as stdout destinations.
    let mut child = Command::new(STUFFR)
        .arg("formats")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Close our read end without reading anything, before the child has a
    // chance to write — same technique as
    // `cat_exits_cleanly_when_the_reader_closes_early`, just without needing
    // a large payload to keep the write in flight: `formats`' whole output
    // fits in one pipe buffer, so what actually needs to race is the drop
    // here against the child's startup, not against a long write.
    drop(child.stdout.take().unwrap());

    let mut stderr = child.stderr.take().unwrap();
    let mut err_text = String::new();
    stderr.read_to_string(&mut err_text).unwrap();

    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "an early-closing reader must not look like a failure: {status:?}"
    );
    assert!(
        err_text.is_empty(),
        "a clean broken-pipe exit prints nothing: {err_text}"
    );
}

#[test]
fn pack_then_unpack_round_trips_through_the_binary() {
    let src = tmp("e2e.txt");
    let gz = tmp("e2e.txt.gz");
    let back = tmp("e2e-back.txt");
    let _ = std::fs::remove_file(&gz);
    let _ = std::fs::remove_file(&back);

    let plain = b"the quick brown fox ".repeat(2000);
    std::fs::write(&src, &plain).unwrap();

    // Bare invocation, no --format: exercises default_format_in's
    // gzip preference, not just gzip named explicitly.
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        gz.exists(),
        "pack must have written the .gz beside the input"
    );
    assert!(src.exists(), "pack must not destroy its input");

    assert!(
        Command::new(STUFFR)
            .args(["unpack", gz.to_str().unwrap(), "-o", back.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        std::fs::read(&back).unwrap(),
        plain,
        "round trip must be byte-identical"
    );

    for p in [&src, &gz, &back] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn no_sync_is_accepted_by_pack_and_unpack_and_still_round_trips() {
    // Nothing previously exercised --no-sync from the CLI at all. A subprocess
    // test cannot observe the fsync itself being skipped (see
    // stuffr/tests/sync_counter.rs, in the same process as the code under
    // test, for that) — a wrong-polarity `sync: no_sync` instead of
    // `sync: !no_sync` would round-trip identically and this test would not
    // catch it either. What this DOES close is the cheaper, still-real gap
    // that nothing previously confirmed the flag even parses and reaches
    // pack and unpack without breaking anything along the way.
    let src = tmp("nosync-e2e.txt");
    let gz = tmp("nosync-e2e.txt.gz");
    let back = tmp("nosync-e2e-back.txt");
    let _ = std::fs::remove_file(&gz);
    let _ = std::fs::remove_file(&back);

    let plain = b"the quick brown fox ".repeat(500);
    std::fs::write(&src, &plain).unwrap();

    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "--no-sync",
                "--format",
                "gzip"
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(gz.exists(), "pack --no-sync must still write the output");

    assert!(
        Command::new(STUFFR)
            .args([
                "unpack",
                gz.to_str().unwrap(),
                "-o",
                back.to_str().unwrap(),
                "--no-sync",
            ])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        std::fs::read(&back).unwrap(),
        plain,
        "--no-sync must cost durability, never correctness"
    );

    for p in [&src, &gz, &back] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn cat_reads_a_stream_on_stdin() {
    // The project's motivating case: `curl … | stuffr cat - | grep pattern`.
    use std::io::Write;
    use std::process::Stdio;

    let src = tmp("pipe.txt");
    let gz = tmp("pipe.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"needle in a haystack").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );
    let packed = std::fs::read(&gz).unwrap();

    let mut child = Command::new(STUFFR)
        .args(["cat", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&packed).unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(out.status.success());
    assert_eq!(out.stdout, b"needle in a haystack");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

/// The motivating case for the whole flush contract: `stuffr pack - -o out.gz`
/// reads a pipe with no path to fall back on, so the output name must be
/// given explicitly, and the write must still land intact.
#[test]
fn pack_reads_input_from_stdin() {
    let out = tmp("stdin-pack.gz");
    let _ = std::fs::remove_file(&out);
    let plain = b"stdin plaintext, packed then verified byte for byte".repeat(200);

    let mut child = Command::new(STUFFR)
        .args(["pack", "-", "-o", out.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&plain).unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(out.exists(), "pack must have written the output file");

    // Round-trip through the binary rather than just checking the file
    // exists — a truncated or otherwise corrupt stream must fail here.
    let cat_out = Command::new(STUFFR)
        .args(["cat", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(cat_out.status.success());
    assert_eq!(cat_out.stdout, plain, "round trip must be byte-identical");

    let _ = std::fs::remove_file(&out);
}

/// The other motivating case: `stuffr pack x -o -` writes to a destination
/// (stdout) that may be fully buffered and never see a newline — exactly the
/// scenario `Sink::finish`'s flush contract exists for. A stream that was
/// never flushed would truncate here.
#[test]
fn pack_writes_output_to_stdout() {
    let src = tmp("stdout-pack.txt");
    let _ = std::fs::remove_file(&src);
    let plain = b"payload written straight through to stdout by pack".repeat(200);
    std::fs::write(&src, &plain).unwrap();

    let pack_out = Command::new(STUFFR)
        .args(["pack", src.to_str().unwrap(), "--format", "gzip", "-o", "-"])
        .output()
        .unwrap();
    assert!(
        pack_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&pack_out.stderr)
    );
    assert_eq!(
        &pack_out.stdout[..2],
        &[0x1f, 0x8b],
        "must be a real gzip stream"
    );

    // Pipe the captured bytes back through `stuffr cat -`: a truncated stream
    // (an unflushed `Sink::finish`, notably) fails the equality below rather
    // than merely "existing".
    let mut child = Command::new(STUFFR)
        .args(["cat", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&pack_out.stdout)
        .unwrap();
    let cat_out = child.wait_with_output().unwrap();
    assert!(cat_out.status.success());
    assert_eq!(
        cat_out.stdout, plain,
        "round trip through a piped stdout destination must be byte-identical"
    );

    let _ = std::fs::remove_file(&src);
}

/// Mirrors `info_over_a_pipe_reports_forward_only_not_exact`: `compress` must
/// compute its own fidelity rung from the source's actual seekability rather
/// than assuming `Exact`, the same way `decompress` already does.
#[test]
fn pack_over_a_pipe_reports_forward_only_not_exact() {
    let out = tmp("pack-rung-pipe.gz");
    let _ = std::fs::remove_file(&out);
    let plain = b"payload".repeat(50);

    let mut child = Command::new(STUFFR)
        .args(["pack", "-", "-o", out.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&plain).unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let err_text = String::from_utf8_lossy(&result.stderr);
    assert!(
        err_text.contains("forward-only"),
        "a pipe cannot seek, so pack's reported rung must not be exact: {err_text}"
    );

    let _ = std::fs::remove_file(&out);
}

/// The other half of the pair above: together they prove the rung is
/// computed rather than a constant either way.
#[test]
fn pack_of_a_seekable_file_reports_exact() {
    let src = tmp("pack-rung-file.txt");
    let gz = tmp("pack-rung-file.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"payload").unwrap();

    // Bare invocation, no --format: exercises default_format_in's
    // gzip preference, not just gzip named explicitly.
    let out = Command::new(STUFFR)
        .args(["pack", src.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let err_text = String::from_utf8_lossy(&out.stderr);
    assert!(err_text.contains("exact"), "{err_text}");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn an_existing_output_is_refused_with_exit_two() {
    let src = tmp("clash.txt");
    let gz = tmp("clash.txt.gz");
    std::fs::write(&src, b"payload").unwrap();
    std::fs::write(&gz, b"PRE-EXISTING").unwrap();

    let out = Command::new(STUFFR)
        .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--force"));
    assert_eq!(
        std::fs::read(&gz).unwrap(),
        b"PRE-EXISTING",
        "the refused command changed nothing"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn a_bomb_exits_six_and_leaves_no_partial_output() {
    let src = tmp("boom.bin");
    let gz = tmp("boom.bin.gz");
    let out_path = tmp("boom-out.bin");
    let _ = std::fs::remove_file(&gz);
    let _ = std::fs::remove_file(&out_path);

    std::fs::write(&src, vec![0u8; 2 * 1024 * 1024]).unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let out = Command::new(STUFFR)
        .args([
            "unpack",
            gz.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "--max-ratio",
            "100",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(6), "resource limits exit 6");
    assert!(
        !out_path.exists(),
        "a refused decode must leave no partial file"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn an_unknown_verb_exits_two() {
    let out = Command::new(STUFFR).arg("bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

/// Keeps `stuffr --examples` honest as the tool grows: every format this build
/// registers, and every long flag / subcommand clap knows about, must be
/// mentioned on the page. This is what makes the page a contract rather than
/// prose that quietly goes stale — Phase 1d adding a codec, or any future
/// flag, fails this test until the page is updated to match.
#[test]
fn examples_page_covers_every_format_and_flag() {
    use clap::CommandFactory;
    use stuffr_cli::cli::Cli;

    let out = Command::new(STUFFR).arg("--examples").output().unwrap();
    assert!(out.status.success(), "stuffr --examples must exit 0");
    let text = String::from_utf8(out.stdout).unwrap();

    for row in stuffr::registry().matrix() {
        let id = row.id.as_str();
        assert!(
            text.contains(id),
            "the examples page does not mention the `{id}` format"
        );
    }

    let root = Cli::command();
    for sub in root.get_subcommands() {
        let name = sub.get_name();
        if name == "help" {
            continue;
        }
        assert!(
            text.contains(name),
            "the examples page does not mention the `{name}` subcommand"
        );
        for arg in sub.get_arguments() {
            let Some(long) = arg.get_long() else {
                continue;
            };
            if long == "help" || long == "version" {
                continue;
            }
            let flag = format!("--{long}");
            assert!(
                text.contains(flag.as_str()),
                "the examples page does not mention {flag}"
            );
        }
    }
}

/// The Phase 2 final review's I4: `examples_page_covers_every_format_and_flag`
/// above passed a page that still described a THREE-container build with
/// "fourteen rows", "all fourteen formats", "All three containers — tar, ar
/// and cpio", "eleven codecs and three containers" and "Still to come:
/// **zip**" — because the substring "zip" appears elsewhere on the page and
/// a mention was all it checked. This is the one document a user reads, so
/// a mention is not enough.
///
/// Three classes of staleness, each derived from the registry rather than
/// hard-coded, so adding a format in a later phase fails this test until
/// the page is updated:
///
/// 1. A "still to come" claim about a format that is REGISTERED.
/// 2. A written-out count of formats or containers that does not match the
///    registry's own.
/// 3. A registered container missing from the containers sentence.
#[test]
fn the_examples_page_cannot_carry_a_stale_count_or_a_shipped_still_to_come() {
    let out = Command::new(STUFFR).arg("--examples").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();

    let rows = stuffr::registry().matrix();
    let containers: Vec<&str> = rows
        .iter()
        .filter(|r| stuffr::registry().container(r.id).is_some())
        .map(|r| r.id.as_str())
        .collect();
    let codecs: Vec<&str> = rows
        .iter()
        .filter(|r| stuffr::registry().container(r.id).is_none())
        .map(|r| r.id.as_str())
        .collect();

    // `lha` (Phase 3b) is the first container gated behind a feature that
    // `pure` does not carry: `--features legacy` (bundled into
    // `full`/`--all-features`) adds it, the default `pure` build does not.
    // Every OTHER container so far sits in `pure` itself, so "how many
    // containers" used to be one tier-invariant number this whole test
    // could check `stuffr::registry()` against directly. It no longer is:
    // THIS test binary alone reports 4 under `cargo test --workspace`
    // (`make check`'s `test-pure` leg, no `legacy`) and 6 under
    // `--all-features` (`test`, now that Task 6 has added `arj` alongside
    // `lha`) — so a page correctly describing BOTH the default build and
    // an `--all-features` one legitimately states two different container
    // counts, and neither is stale just because it does not match
    // whichever tier happens to compile this assertion.
    //
    // `base_containers` is the tier-invariant quartet (tar/ar/cpio/zip).
    // The "full" count must NOT be `base_containers.len() +
    // LEGACY_ONLY_CONTAINERS.len()` computed as bare arithmetic — a first
    // version of this fix did exactly that, and it cannot tell "the
    // `legacy` feature is simply off" (test-pure; `lha` was never going to
    // be here) apart from "the `legacy` feature IS on but `lha`'s own
    // registration silently broke" (a real regression `stuffr formats`
    // would also show). Both look identical to a formula that only ever
    // adds a constant. So this instead asks the LIVE registry whether the
    // `legacy` Cargo feature bundle was compiled in at all, witnessed by
    // `compress` — a format registered independently of `lha`, by a
    // separate call in `register_all`, but gated by the exact same
    // `legacy` bundle (`stuffr/Cargo.toml`'s `legacy = [".../lha",
    // ".../arj", ".../compress"]`). If `compress` is present, `legacy` was
    // compiled, and `lha` is EXPECTED to be there too — its absence then
    // means a genuine registration bug, not an untested tier, so the "full"
    // count degrades to the tier-invariant base rather than silently
    // staying at a stale "base + 1". If `compress` is absent (the default
    // `pure` tier), there is no way for this run to observe `lha` either
    // way, so the full count is the best available PROJECTION — base plus
    // the fixed legacy list — which is what a page describing a
    // DIFFERENT, `--all-features` build is entitled to claim.
    const LEGACY_ONLY_CONTAINERS: &[&str] = &["lha", "arj"];
    let base_containers: Vec<&str> = containers
        .iter()
        .copied()
        .filter(|id| !LEGACY_ONLY_CONTAINERS.contains(id))
        .collect();
    let legacy_bundle_compiled = rows.iter().any(|r| r.id.as_str() == "compress");
    let full_container_count = if legacy_bundle_compiled {
        // `legacy` is compiled: trust the live registry fully. If `lha`'s
        // own registration is broken, `containers` already reflects that
        // (it simply is not in it), so this collapses to `base_containers
        // .len()` on its own — no separate assertion needed to catch it.
        containers.len()
    } else {
        base_containers.len() + LEGACY_ONLY_CONTAINERS.len()
    };

    // (1) No "still to come" line may name a format this build registers.
    // Checked per SENTENCE, so "still to come: walking a directory tree"
    // sitting in the same paragraph as the word "zip" does not trip it.
    for sentence in text.split(['.', '\n']) {
        let lower = sentence.to_lowercase();
        if !(lower.contains("still to come") || lower.contains("not yet supported")) {
            continue;
        }
        for id in rows.iter().map(|r| r.id.as_str()) {
            assert!(
                !sentence.contains(id),
                "the page says `{id}` is still to come, but this build registers it: \
                 {sentence:?}"
            );
        }
    }

    // (2) Any written-out count applied to "formats", "rows" or
    //     "containers" must be the real one.
    const NUMBERS: &[(&str, usize)] = &[
        ("one", 1),
        ("two", 2),
        ("three", 3),
        ("four", 4),
        ("five", 5),
        ("six", 6),
        ("seven", 7),
        ("eight", 8),
        ("nine", 9),
        ("ten", 10),
        ("eleven", 11),
        ("twelve", 12),
        ("thirteen", 13),
        ("fourteen", 14),
        ("fifteen", 15),
        ("sixteen", 16),
        ("seventeen", 17),
        ("eighteen", 18),
        ("nineteen", 19),
        ("twenty", 20),
    ];
    // Whitespace-normalised: the page wraps, so a count and its noun
    // split across a line break must still read as one phrase.
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let words: Vec<&str> = flat.split(' ').collect();
    for pair in words.windows(2) {
        let (word, next) = (
            pair[0].trim_matches(|c: char| !c.is_alphanumeric()),
            pair[1],
        );
        let Some((_, value)) = NUMBERS.iter().find(|(w, _)| *w == word.to_lowercase()) else {
            continue;
        };
        let noun = next
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_lowercase();
        if noun == "containers" {
            // Either the tier-invariant base count or the full
            // (`pure` + `legacy`) count is a true claim — see
            // `full_container_count`'s own comment above for why there are
            // now two, and why it is derived from the live registry
            // (via `legacy_bundle_compiled`) rather than bare arithmetic:
            // a build where `legacy` is on but `lha` failed to register
            // must NOT still accept a stale "five".
            assert!(
                *value == base_containers.len() || *value == full_container_count,
                "the page says `{word} containers`, but this build has {} base containers \
                 ({} once every legacy container is counted) — the counts on this page are \
                 what a user trusts before running `stuffr formats`",
                base_containers.len(),
                full_container_count
            );
            continue;
        }
        let expected = match noun.as_str() {
            "formats" | "rows" => rows.len(),
            "codecs" => codecs.len(),
            _ => continue,
        };
        assert_eq!(
            *value, expected,
            "the page says `{word} {noun}`, but this build has {expected} — the counts \
             on this page are what a user trusts before running `stuffr formats`"
        );
    }

    // (3) At least one sentence must both COUNT the containers and NAME
    //     every one of them. Matched as whole words, not substrings —
    //     `ar` occurs inside dozens of ordinary words, which is exactly
    //     the weakness that let "Still to come: zip" survive on a page
    //     that had already shipped zip.
    let counting_sentences: Vec<&str> = flat
        .split(". ")
        .filter(|sentence| {
            let l = sentence.to_lowercase();
            NUMBERS
                .iter()
                .any(|(w, _)| l.contains(&format!("{w} containers")))
        })
        .collect();
    assert!(
        !counting_sentences.is_empty(),
        "the page must state how many containers this build has"
    );
    let names_them_all = counting_sentences.iter().any(|sentence| {
        containers.iter().all(|id| {
            sentence
                .split(|c: char| !c.is_alphanumeric())
                .any(|word| word == *id)
        })
    });
    assert!(
        names_them_all,
        "no sentence both counts the containers and names every one of them \
         ({containers:?}); the counting sentences are {counting_sentences:?}"
    );
}

/// Pins ONE documented claim end-to-end rather than all of them: the page's
/// very first example, run verbatim in its own directory. `--examples`'
/// header claims "Everything below runs against this build as shown" —
/// `examples_page_covers_every_format_and_flag` only checks that words are
/// *mentioned*, so a page whose first command was actually broken (as this
/// task's own investigation found `stuffr pack notes.txt` briefly was) would
/// still pass it. A full executable-docs test extracting and running every
/// line on the page is the right long-term fix; this is the narrow stopgap.
#[test]
fn examples_pages_first_worked_example_runs_as_documented() {
    let dir = tmp("examples-first-example-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let notes = dir.join("notes.txt");
    let packed = dir.join("notes.txt.gz");
    std::fs::write(&notes, b"the documented example's payload").unwrap();

    // Verbatim: `stuffr pack notes.txt`, run from the directory containing it.
    let out = Command::new(STUFFR)
        .arg("pack")
        .arg("notes.txt")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        packed.exists(),
        "the page says this writes notes.txt.gz beside it"
    );
    assert!(
        notes.exists(),
        "the page says the input, notes.txt, is left alone"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `pack --format lha`/`arj`/`compress` must refuse CLEARLY — exit 3, naming
/// the format read-only in this build — never fail obscurely (an internal
/// panic, a bare i/o error, or an unrelated exit code). Phase 3b's three
/// legacy formats each answer `Error::Unsupported` from
/// `Codec::encoder`/`Container::create` directly (see `legacy::lha`,
/// `legacy::arj`, `legacy::compress_z`'s own `create`/`encoder`
/// implementations), so this pins that all the way through the CLI rather
/// than only at the trait level each module's own unit tests already cover.
///
/// Runtime-checked, not `cfg`-gated: `stuffr-cli` has no Cargo features of
/// its own (see its `Cargo.toml`), so whether `legacy` is compiled in can
/// only be asked of the live registry, the same way
/// `examples_page_covers_every_format_and_flag` above already asks it for
/// container counts. On the default `pure` tier (`cargo test --workspace`,
/// no `--all-features`) none of the three is registered at all, and
/// `--format lha` is indistinguishable from any other unrecognised name
/// ("unknown format `lha`", exit 2) — a different, already-covered claim,
/// not this test's to make.
#[test]
fn pack_refuses_a_read_only_legacy_format_clearly() {
    let registry = stuffr::registry();
    let dir = tmp("legacy-format-refusal-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload").unwrap();

    for (name, out_ext) in [("lha", "lzh"), ("arj", "arj"), ("compress", "z")] {
        let registered = registry.container(stuffr::FormatId::new(name)).is_some()
            || registry.codec(stuffr::FormatId::new(name)).is_some();
        if !registered {
            // `legacy` was not compiled into this build (the default
            // `pure` tier) — the read-only refusal this test pins simply
            // does not exist on this tier, and asserting "unknown format"
            // instead would duplicate a claim `formats_now_reports_gzip`-
            // style tests already make elsewhere.
            continue;
        }
        let dst = dir.join(format!("out.{out_ext}"));
        let res = Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "--format",
                name,
                "-o",
                dst.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&res.stderr);
        assert_eq!(
            res.status.code(),
            Some(3),
            "`--format {name}` must refuse at exit 3 (this build cannot do that), got \
             {:?}; stderr: {err}",
            res.status.code()
        );
        // `lha`/`arj` (containers, `Container::create`) and `compress` (a
        // codec, `Codec::encoder`) phrase this differently — "read-only in
        // this build" against "can be read but not written by this
        // build" — so the check is per-format rather than one shared
        // substring, to avoid quietly demanding a rewrite neither module
        // actually needs.
        let lower = err.to_lowercase();
        let names_read_only = match name {
            "compress" => lower.contains("read") && lower.contains("not written"),
            _ => lower.contains("read-only") || lower.contains("read only"),
        };
        assert!(
            names_read_only,
            "`--format {name}`'s refusal must name the format as read-only/not-written in \
             this build rather than fail obscurely: {err}"
        );
        assert!(
            !dst.exists(),
            "a refused pack must not leave a partial `{}` behind",
            dst.display()
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_corrupt_archive_exits_five_not_one() {
    let src = tmp("cli-corrupt.txt");
    let gz = tmp("cli-corrupt.txt.gz");
    let out = tmp("cli-corrupt-out.txt");
    let _ = std::fs::remove_file(&gz);
    let _ = std::fs::remove_file(&out);

    std::fs::write(&src, b"the quick brown fox ".repeat(200)).unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let mut bytes = std::fs::read(&gz).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&gz, &bytes).unwrap();

    let res = Command::new(STUFFR)
        .args(["unpack", gz.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(
        res.status.code(),
        Some(5),
        "a corrupt archive must be distinguishable from a full disk"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn unpack_accepts_an_explicit_format() {
    // Detection would find gzip here anyway; the point is that the flag is
    // accepted and honoured, so the codecs that CANNOT be detected have a way in.
    let src = tmp("fmt-unpack.txt");
    let gz = tmp("fmt-unpack.txt.gz");
    let out = tmp("fmt-unpack-out.txt");
    let _ = std::fs::remove_file(&gz);
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, b"payload").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let res = Command::new(STUFFR)
        .args([
            "unpack",
            gz.to_str().unwrap(),
            "--format",
            "gzip",
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"payload");

    for p in [&src, &gz, &out] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn cat_accepts_an_explicit_format() {
    let src = tmp("fmt-cat.txt");
    let gz = tmp("fmt-cat.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"payload").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let res = Command::new(STUFFR)
        .args(["cat", gz.to_str().unwrap(), "--format", "gzip"])
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert_eq!(res.stdout, b"payload");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn pack_with_no_flags_defaults_to_gzip() {
    // Now that this build registers three codecs, a bare `pack src` with
    // neither -o nor --format goes through choose_format's fallback to
    // default_format_in with no extension to infer from at all. This is
    // the path 14 other tests used to exercise incidentally before they
    // were pinned to --format gzip explicitly; this test is the one that
    // exists specifically to cover it, and would fail with the ambiguity
    // usage error ("cannot infer the output format") if default_format_in
    // did not prefer gzip when it is registered alongside other codecs.
    let src = tmp("bare-default.txt");
    let gz = tmp("bare-default.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"payload").unwrap();

    let out = Command::new(STUFFR)
        .args(["pack", src.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        gz.exists(),
        "a bare pack with no --format must default to gzip and write {}.gz",
        src.display()
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn unpack_format_flag_is_honoured_not_merely_accepted() {
    // Raw deflate is the format that can actually prove this: it has no
    // magic and no conventional extension (see deflate::meta), so it is
    // undetectable by construction. gzip cannot make this distinction —
    // it is detectable from its magic regardless of whether --format was
    // read — which is exactly how Task 1's review found all four of its
    // --format tests still green after the resolved format was dropped on
    // the floor in main.rs. This test packs with --format deflate into a
    // name carrying no hint of the format, then requires unpack to FAIL
    // without --format (detection has nothing to go on) and to SUCCEED
    // with it, recovering the original bytes exactly.
    let src = tmp("fmt-deflate.txt");
    let packed = tmp("fmt-deflate.dat");
    let out = tmp("fmt-deflate-out.txt");
    for p in [&packed, &out] {
        let _ = std::fs::remove_file(p);
    }
    let payload = b"the quick brown fox jumps over the lazy dog".repeat(50);
    std::fs::write(&src, &payload).unwrap();

    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "--format",
                "deflate",
                "-o",
                packed.to_str().unwrap(),
            ])
            .status()
            .unwrap()
            .success()
    );

    let no_format = Command::new(STUFFR)
        .args([
            "unpack",
            packed.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(
        !no_format.status.success(),
        "a raw deflate stream must NOT be detectable without --format"
    );

    let with_format = Command::new(STUFFR)
        .args([
            "unpack",
            packed.to_str().unwrap(),
            "--format",
            "deflate",
            "-o",
            out.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(
        with_format.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&with_format.stderr)
    );
    assert_eq!(std::fs::read(&out).unwrap(), payload);

    for p in [&src, &packed, &out] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn cat_format_flag_is_honoured_not_merely_accepted() {
    // Character-for-character the gap Task 1's review found for `unpack` and
    // closed with `unpack_format_flag_is_honoured_not_merely_accepted` above
    // (raw deflate, undetectable by construction) — never mirrored for
    // `cat`. `cat_accepts_an_explicit_format` uses gzip, which detection
    // identifies anyway (its own comment admits this), so it proves
    // `format_by_name` ran, not that its result reaches `DecompressOpts`.
    // Replacing `format: fmt` with `format: None` in main.rs's `Command::Cat`
    // arm would leave that test green; this one requires it to fail without
    // --format and succeed with it, the same shape as the unpack test above.
    let src = tmp("fmt-cat-deflate.txt");
    let packed = tmp("fmt-cat-deflate.dat");
    let _ = std::fs::remove_file(&packed);
    let payload = b"the quick brown fox jumps over the lazy dog".repeat(50);
    std::fs::write(&src, &payload).unwrap();

    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "--format",
                "deflate",
                "-o",
                packed.to_str().unwrap(),
            ])
            .status()
            .unwrap()
            .success()
    );

    let no_format = Command::new(STUFFR)
        .args(["cat", packed.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !no_format.status.success(),
        "a raw deflate stream must NOT be detectable without --format"
    );

    let with_format = Command::new(STUFFR)
        .args(["cat", packed.to_str().unwrap(), "--format", "deflate"])
        .output()
        .unwrap();
    assert!(
        with_format.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&with_format.stderr)
    );
    assert_eq!(with_format.stdout, payload);

    for p in [&src, &packed] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn an_unknown_format_name_is_a_usage_error_on_every_verb() {
    // pack already rejected these; unpack and cat must agree rather than
    // silently ignoring a flag the user believed they had set.
    for verb in ["unpack", "cat"] {
        let out = Command::new(STUFFR)
            .args([verb, "/dev/null", "--format", "bogus"])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{verb} --format bogus must be a usage error"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("gzip"),
            "the error must name what this build does have"
        );
    }
}

#[test]
fn cat_honours_max_ratio() {
    // A bomb reaches stdout as easily as a file; cat had no way to bound it.
    let src = tmp("cat-bomb.bin");
    let gz = tmp("cat-bomb.bin.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, vec![0u8; 2 * 1024 * 1024]).unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "gzip"])
            .status()
            .unwrap()
            .success()
    );

    let out = Command::new(STUFFR)
        .args(["cat", gz.to_str().unwrap(), "--max-ratio", "100"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(6), "resource limits exit 6");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&gz);
}

#[test]
fn formats_lists_every_registered_format() {
    let out = Command::new(STUFFR).arg("formats").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for row in stuffr::registry().matrix() {
        assert!(
            text.contains(row.id.as_str()),
            "`stuffr formats` omits {}: {text}",
            row.id
        );
    }
}

/// The WRITE/`weak` note belongs BELOW the table, after a blank line. It used
/// to sit between the column headings and the first row, which split the
/// headings from the data they label and made the table hard to scan.
///
/// Asserting only that the output `contains` the note — which is all the test
/// above does for the rows — would pass with the note back in its old place,
/// so this pins the position: every format row must come before it, and the
/// line before it must be blank.
#[test]
fn the_formats_note_sits_below_the_table_after_a_blank_line() {
    let out = Command::new(STUFFR).arg("formats").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();

    let note = lines
        .iter()
        .position(|l| l.starts_with("(WRITE shows"))
        .unwrap_or_else(|| panic!("`stuffr formats` printed no WRITE note:\n{text}"));

    for row in stuffr::registry().matrix() {
        let at = lines
            .iter()
            .position(|l| l.starts_with(row.id.as_str()))
            .unwrap_or_else(|| panic!("`stuffr formats` omits {}:\n{text}", row.id));
        assert!(
            at < note,
            "{} is listed at line {at}, below the note at line {note}:\n{text}",
            row.id
        );
    }

    assert!(
        note > 0,
        "the note is the first line, so no table precedes it"
    );
    assert_eq!(
        lines[note - 1],
        "",
        "the note must be separated from the table by a blank line, got {:?}:\n{text}",
        lines[note - 1]
    );
}

#[test]
fn a_malformed_memory_limit_is_a_usage_error() {
    let src = tmp("mem-bad.txt");
    let out_path = tmp("mem-bad.gz");
    let _ = std::fs::remove_file(&out_path);
    std::fs::write(&src, b"payload").unwrap();

    let out = Command::new(STUFFR)
        .args(["pack", "--memory-limit", "512MB", "--format", "gzip", "-o"])
        .arg(&out_path)
        .arg(&src)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "malformed size must be exit 2");
    let err = String::from_utf8_lossy(&out.stderr);
    // `err.contains("512M")` alone is not discriminating: the message echoes
    // the bad input back (`512MB`), which itself contains the substring
    // `512M`, so the assertion would pass even with the actual guidance
    // removed entirely. Same weak-assertion class `size.rs`'s
    // `malformed_input_is_an_error_naming_the_accepted_forms` was
    // strengthened against (R3) — require a form the input cannot supply.
    assert!(
        err.contains("512M") && err.contains("2G"),
        "must name the accepted forms concretely: {err}"
    );
    assert!(!out_path.exists(), "a refused pack must leave no output");

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out_path);
}

#[test]
fn threads_is_not_offered_on_decode_subcommands() {
    // Multi-threaded decode is out of scope, and this project refuses a flag
    // rather than accepting and ignoring it. If MT decode is ever added, this
    // test should fail and be deleted deliberately.
    for sub in ["unpack", "cat"] {
        let out = Command::new(STUFFR)
            .args([sub, "--threads", "4", "-"])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("unexpected argument") || err.contains("--threads"),
            "{sub} must reject --threads, got: {err}"
        );
    }
}

#[test]
fn the_binary_reports_its_version() {
    // `CARGO_PKG_VERSION` resolves to this crate's own version at compile
    // time, so this checks "the binary reports its own version" rather than
    // one number that goes stale at the next bump — a hardcoded literal
    // here was the fifth site a version bump had to touch, discovered only
    // when Phase 2's 0.2.0 bump made this test fail; this formulation needs
    // no manual edit at any future bump.
    let want = env!("CARGO_PKG_VERSION");
    let out = Command::new(STUFFR).arg("--version").output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains(want), "--version must report {want}, got: {s}");
}

// ---------------------------------------------------------------------
// `list` and `test` (Task 8): fixtures and helpers.
//
// Fixtures are built with the `tar` and `flate2` crates directly rather
// than through `stuffr pack`/a `stuffr-formats` writer — this build has no
// way to CREATE a tar archive yet (that's a later task), and using an
// independent generator means a read-side bug in `stuffr-formats::Tar`
// cannot also be hiding in the fixture that exercises it.
// ---------------------------------------------------------------------

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

/// A fresh, empty directory for one test. Real files on disk, not just
/// bytes in memory, so `list_names_every_entry_and_extracts_nothing` can
/// assert the filesystem is untouched afterwards.
///
/// Named from [`RUN_TOKEN`] rather than `{pid}-{counter}`, and the word
/// "fresh" in the sentence above is why — see that constant for the false red
/// the old name produced. `create_dir_all` is deliberately kept (rather than
/// `create_dir`, which would refuse an existing path): with a random token the
/// path cannot pre-exist, so a refusal would only ever fire on a genuine
/// filesystem fault and `create_dir_all` reports that just as loudly.
fn tmp_dir() -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-cli-archive-{}-{n}", *RUN_TOKEN));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Writes a GNU-format tar header for `name`/`data` into `builder`. Kept
/// separate from callers so every fixture builder below sets exactly the
/// same fields the same way.
fn append_tar_entry<W: Write>(builder: &mut Builder<W>, name: &str, data: &[u8]) {
    let mut header = Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    // `append_data` sets the path and recomputes the checksum itself, in
    // that order — see `tar::Builder::append_data`'s own source.
    builder.append_data(&mut header, name, data).unwrap();
}

/// A real tar archive, written to `dir/fixture.tar`.
fn write_fixture_tar(dir: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
    let path = dir.join("fixture.tar");
    let mut builder = Builder::new(std::fs::File::create(&path).unwrap());
    for (name, data) in entries {
        append_tar_entry(&mut builder, name, data);
    }
    builder.finish().unwrap();
    path
}

/// The same tar bytes, real-gzip-wrapped (via `flate2`) under `name` —
/// `"fixture.tar.gz"` or `"fixture.tgz"` — exercising the exact shapes
/// `resolve_chain_deep` must resolve as "tar over gzip".
fn write_fixture_tar_gz(dir: &Path, name: &str, entries: &[(&str, &[u8])]) -> PathBuf {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_bytes);
        for (n, data) in entries {
            append_tar_entry(&mut builder, n, data);
        }
        builder.finish().unwrap();
    }
    let path = dir.join(name);
    let mut enc = GzEncoder::new(
        std::fs::File::create(&path).unwrap(),
        Compression::default(),
    );
    enc.write_all(&tar_bytes).unwrap();
    enc.finish().unwrap();
    path
}

/// Gzip-wraps arbitrary bytes once — used to build a nesting-depth bomb.
fn gzip_wrap(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

/// Truncates `good` to half its length: a real, structural corruption (a
/// missing or partial end-of-archive marker), not a bit flip tar has no way
/// to detect at all — it carries no payload checksum.
fn corrupt_midway(good: &Path) -> PathBuf {
    let bytes = std::fs::read(good).unwrap();
    let cut = bytes.len() / 2;
    let corrupt = good.with_file_name("corrupt.tar");
    std::fs::write(&corrupt, &bytes[..cut]).unwrap();
    corrupt
}

fn run(args: &[&str]) -> std::process::ExitStatus {
    Command::new(STUFFR).args(args).status().unwrap()
}

fn run_output(args: &[&str]) -> std::process::Output {
    Command::new(STUFFR).args(args).output().unwrap()
}

fn run_with_stdin_output(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(STUFFR)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

/// The streaming premise applied to `list`/`test`: stdin, no seek.
fn run_with_stdin(args: &[&str], input: &[u8]) -> String {
    let out = run_with_stdin_output(args, input);
    String::from_utf8(out.stdout).unwrap()
}

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

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_verb_exits_five_on_a_corrupt_archive_and_zero_on_a_good_one() {
    let dir = tmp_dir();
    let good = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    assert_eq!(run(&["test", good.to_str().unwrap()]).code(), Some(0));
    let bad = corrupt_midway(&good);
    assert_eq!(run(&["test", bad.to_str().unwrap()]).code(), Some(5));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn list_works_on_a_pipe() {
    // The streaming premise applied to the new verb.
    let dir = tmp_dir();
    let bytes = std::fs::read(write_fixture_tar(&dir, &[("a.txt", b"alpha")])).unwrap();
    let text = run_with_stdin(&["list", "-"], &bytes);
    assert!(text.contains("a.txt"), "{text}");

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
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

    let _ = std::fs::remove_dir_all(&dir);
}

/// The hazard side of Task 4b's fix: a genuine i/o failure reading the RAW
/// source (never reaching a decoder at all) must stay `Error::Io` — exit 1
/// — and must NOT be swept into `Error::Corrupt` by a fix that reclassifies
/// too broadly. Opening a directory as if it were a file is a real,
/// deterministic i/o failure that arises before any codec sees a single
/// byte: `resolve_chain_deep_with`'s OWN top-level `probe(src)` call reads
/// the raw source.
///
/// This does NOT prove that widening `Error::from_decode_io` to that
/// top-level `probe(src)` call (or into `probe`/`PeekSource::fill`
/// themselves, rather than scoping it to the decoded-stream `probe` call
/// inside the re-probe loop) would be safe — checked, and it is a narrower
/// guard than that. `from_decode_io` only reclassifies `InvalidData` and
/// `OutOfMemory`; a directory read raises `std::io::ErrorKind::IsADirectory`,
/// neither of those, so it comes back `Error::Io` — exit 1 — whether or not
/// that call is widened, and this test cannot tell the two cases apart. What
/// it DOES catch is a cruder fix: one that swept every raw-source
/// `io::Error` into `Error::Corrupt` regardless of kind. The widening claim
/// itself is proven in `probe.rs`'s own
/// `a_raw_source_io_error_of_the_identical_kind_stays_io_not_corrupt`, which
/// deliberately uses an `InvalidData`-kind raw-source error — the one kind
/// `from_decode_io` actually reclassifies — and would flip to `Corrupt` if
/// that call site were widened.
#[test]
fn list_reports_a_directory_as_an_io_failure_not_as_corrupt() {
    let dir = tmp_dir();
    let sub = dir.join("not_a_file");
    std::fs::create_dir_all(&sub).unwrap();

    let out = run_output(&["list", sub.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a genuine i/o failure on the raw source must stay exit 1, not become exit 5: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.starts_with("stuffr: i/o error:"),
        "must be Error::Io's own wording, not Error::Corrupt's \"archive is corrupt\": {err}"
    );
    assert!(
        !err.contains("archive is corrupt"),
        "must not have been reclassified as corrupt: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// `--max-ratio` on `list`/`test`: the codec layer beneath a container is
// bounded the same way `unpack`/`cat` already bound a bare codec stream.
//
// A single gzip member cannot itself reach the 10_000:1 default — its own
// structural ceiling on all-zero input is roughly 1024:1 (measured below,
// and documented on `examples.txt`'s "GUARDING AGAINST DECOMPRESSION
// BOMBS" section for the plain-codec case). `a_bomb_exits_six_and_leaves_
// no_partial_output` above hits this identical ceiling on the codec path
// and works around it with an explicit, tighter `--max-ratio`; these tests
// follow the same convention rather than inventing a new one.
// ---------------------------------------------------------------------

/// A small `.tar.gz` whose single all-zero entry gzip crushes hard — real
/// enough to measure, not assumed. Same 2 MiB size `a_bomb_exits_six_and_
/// leaves_no_partial_output` uses for the bare-codec case.
fn write_bomb_tar_gz(dir: &Path) -> PathBuf {
    write_fixture_tar_gz(
        dir,
        "bomb.tar.gz",
        &[("bomb.bin", &vec![0u8; 2 * 1024 * 1024])],
    )
}

#[test]
fn list_and_test_refuse_a_bomb_tar_gz_at_a_tight_max_ratio() {
    let dir = tmp_dir();
    let bomb = write_bomb_tar_gz(&dir);
    // Real measured ratio is roughly 1000:1 (2 MiB in, ~2 KiB of gzip out);
    // 100 is comfortably below that, exactly as the existing codec-path
    // bomb test uses for the identical reason.
    let list_out = run_output(&["list", bomb.to_str().unwrap(), "--max-ratio", "100"]);
    assert_eq!(
        list_out.status.code(),
        Some(6),
        "list stderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_err = String::from_utf8_lossy(&list_out.stderr);
    assert!(
        list_err.contains("100") && list_err.contains("--max-ratio"),
        "must name the limit and the flag, matching how decompress reports it: {list_err}"
    );

    let test_out = run_output(&["test", bomb.to_str().unwrap(), "--max-ratio", "100"]);
    assert_eq!(
        test_out.status.code(),
        Some(6),
        "test stderr: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
    let test_err = String::from_utf8_lossy(&test_out.stderr);
    assert!(
        test_err.contains("100") && test_err.contains("--max-ratio"),
        "must name the limit and the flag: {test_err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn raising_max_ratio_lets_the_bomb_through() {
    // Proves the flag is wired, not merely accepted and ignored: the exact
    // same archive `list_and_test_refuse_a_bomb_tar_gz_at_a_tight_max_ratio`
    // refuses at 100 must succeed once the limit is raised past its real
    // (roughly 1000:1) ratio.
    let dir = tmp_dir();
    let bomb = write_bomb_tar_gz(&dir);

    let list_out = run_output(&["list", bomb.to_str().unwrap(), "--max-ratio", "100000"]);
    assert!(
        list_out.status.success(),
        "list stderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );

    let test_out = run_output(&["test", bomb.to_str().unwrap(), "--max-ratio", "100000"]);
    assert!(
        test_out.status.success(),
        "test stderr: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The false-positive trap the guard must NOT fall into: a real, sizeable
/// (not trivially tiny) archive that gzip legitimately crushes hard must
/// pass at the UNCHANGED default ratio — no `--max-ratio` given at all.
#[test]
fn a_legitimately_compressible_tar_gz_is_not_refused_at_the_default_ratio() {
    let dir = tmp_dir();
    let text = "the quick brown fox jumps over the lazy dog\n".repeat(200_000);
    let archive = write_fixture_tar_gz(&dir, "legit.tar.gz", &[("log.txt", text.as_bytes())]);

    let list_out = run_output(&["list", archive.to_str().unwrap()]);
    assert!(
        list_out.status.success(),
        "a legitimately compressible archive must not be refused at the default ratio: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    assert!(
        String::from_utf8(list_out.stdout)
            .unwrap()
            .contains("log.txt")
    );

    let test_out = run_output(&["test", archive.to_str().unwrap()]);
    assert!(
        test_out.status.success(),
        "a legitimately compressible archive must not be refused at the default ratio: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// Entry-aware pack/unpack/cat.
//
// The hostile fixtures below are written with the RAW `tar` crate, bypassing
// `Header::set_path` (which refuses `..` and absolute names outright), so
// they carry names stuffr itself would never produce. That is the point:
// containment has to refuse an archive somebody else wrote.
// ---------------------------------------------------------------------

/// The mtime every raw fixture entry carries, so a test can assert that
/// extraction put it back rather than that it happens to be "recent".
const FIXTURE_MTIME: u64 = 1_600_000_000;

/// A tar entry whose name is written straight into the 100-byte header field,
/// bypassing every validation `Builder::append_data`/`Header::set_path` would
/// apply. `write_fixture_tar` cannot express these names at all.
fn raw_header(
    name: &str,
    kind: tar::EntryType,
    link_target: Option<&str>,
    size: u64,
    mode: u32,
) -> Header {
    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_mtime(FIXTURE_MTIME);
    header.set_entry_type(kind);
    {
        let gnu = header.as_gnu_mut().expect("new_gnu is a GNU header");
        let bytes = name.as_bytes();
        assert!(
            bytes.len() <= gnu.name.len(),
            "raw fixture names must fit tar's 100-byte name field"
        );
        gnu.name[..bytes.len()].copy_from_slice(bytes);
        if let Some(target) = link_target {
            let bytes = target.as_bytes();
            assert!(
                bytes.len() <= gnu.linkname.len(),
                "raw fixture link targets must fit tar's 100-byte linkname field"
            );
            gnu.linkname[..bytes.len()].copy_from_slice(bytes);
        }
    }
    header.set_cksum();
    header
}

/// One raw entry, described the way the fixtures below need it.
enum Raw<'a> {
    File(&'a str, &'a [u8]),
    /// A file carrying an explicit mode, for the metadata tests.
    ModedFile(&'a str, &'a [u8], u32),
    Dir(&'a str),
    Symlink(&'a str, &'a str),
    /// A named pipe: `EntryKind::Other`, which has no shape on disk here.
    Fifo(&'a str),
}

/// Writes an archive whose entry names have passed through no validation at
/// all — the shape stuffr must be able to refuse.
fn write_raw_tar(path: &Path, entries: &[Raw<'_>]) -> PathBuf {
    let mut builder = Builder::new(std::fs::File::create(path).unwrap());
    for entry in entries {
        match entry {
            Raw::File(name, data) => {
                let header = raw_header(
                    name,
                    tar::EntryType::Regular,
                    None,
                    data.len() as u64,
                    0o644,
                );
                builder.append(&header, *data).unwrap();
            }
            Raw::ModedFile(name, data, mode) => {
                let header = raw_header(
                    name,
                    tar::EntryType::Regular,
                    None,
                    data.len() as u64,
                    *mode,
                );
                builder.append(&header, *data).unwrap();
            }
            Raw::Dir(name) => {
                let header = raw_header(name, tar::EntryType::Directory, None, 0, 0o755);
                builder.append(&header, std::io::empty()).unwrap();
            }
            Raw::Symlink(name, target) => {
                let header = raw_header(name, tar::EntryType::Symlink, Some(target), 0, 0o777);
                builder.append(&header, std::io::empty()).unwrap();
            }
            Raw::Fifo(name) => {
                let header = raw_header(name, tar::EntryType::Fifo, None, 0, 0o644);
                builder.append(&header, std::io::empty()).unwrap();
            }
        }
    }
    builder.finish().unwrap();
    path.to_path_buf()
}

#[test]
fn a_traversing_entry_is_refused_and_writes_nothing_outside_the_destination() {
    let dir = tmp_dir();
    let evil = dir.join("evil.tar");
    // Written with the raw `tar` crate, NOT through stuffr — stuffr must be
    // able to refuse archives it would never itself produce.
    write_raw_tar(&evil, &[Raw::File("../escaped.txt", b"pwned")]);

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "a traversing entry must be refused as an unsafe path (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("escaped.txt").exists(),
        "the file escaped the destination"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("../escaped.txt"),
        "the refusal must name the offending entry, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn an_absolute_entry_path_is_refused() {
    let dir = tmp_dir();
    let evil = dir.join("abs.tar");
    // PID-qualified: a shared, fixed /tmp name left behind by one failing run
    // would make every later run fail for the wrong reason.
    let escape = std::env::temp_dir().join(format!("stuffr-abs-escape-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&escape);
    write_raw_tar(&evil, &[Raw::File(escape.to_str().unwrap(), b"pwned")]);

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an absolute entry name must be refused as an unsafe path (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !escape.exists(),
        "an absolute entry name wrote outside the destination: {}",
        escape.display()
    );
}

#[test]
fn cat_streams_one_named_entry_from_a_pipe() {
    let bytes = std::fs::read(write_fixture_tar(
        &tmp_dir(),
        &[("a.txt", b"alpha"), ("b.txt", b"beta")],
    ))
    .unwrap();
    assert_eq!(run_with_stdin(&["cat", "-", "b.txt"], &bytes), "beta");
}

#[test]
fn pack_collects_several_paths_into_one_archive() {
    let dir = tmp_dir();
    std::fs::write(dir.join("one.txt"), b"1").unwrap();
    std::fs::write(dir.join("two.txt"), b"2").unwrap();
    let out = dir.join("bundle.tar");
    let packed = run_output(&[
        "pack",
        dir.join("one.txt").to_str().unwrap(),
        dir.join("two.txt").to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]);
    assert!(
        packed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&packed.stderr)
    );
    let listed = String::from_utf8(run_output(&["list", out.to_str().unwrap()]).stdout).unwrap();
    assert!(
        listed.contains("one.txt") && listed.contains("two.txt"),
        "both entries must be listed, got: {listed}"
    );
    // Stored under their basenames, not the absolute paths they came from:
    // stuffr must not write an archive it would itself refuse at exit 7.
    assert!(
        !listed.contains(dir.to_str().unwrap()),
        "absolute paths must not be stored as entry names, got: {listed}"
    );
}

// --- Hostile cases beyond the brief ---------------------------------------

#[test]
fn a_symlink_whose_target_escapes_the_destination_is_refused_before_it_is_created() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("link.tar"),
        &[Raw::Symlink("link", "../../etc/passwd")],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an escaping symlink target must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        std::fs::symlink_metadata(dest.join("link")).is_err(),
        "the symlink must not have been created at all"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("../../etc/passwd"),
        "the refusal must name the offending target, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn an_entry_written_through_an_escaping_symlink_lands_nowhere() {
    // The two-entry attack: entry 1's own PATH is perfectly contained, so
    // only its TARGET can refuse it; entry 2 is then an ordinary contained
    // name that the OS would resolve THROUGH the link. The link points at
    // this test's own directory (outside the destination) so the escape has
    // a checkable artifact rather than needing to inspect /etc.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("through.tar"),
        &[
            Raw::Symlink("evil", dir.to_str().unwrap()),
            Raw::File("evil/pwned.txt", b"pwned"),
        ],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an absolute symlink target must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("pwned.txt").exists(),
        "the second entry was written through the symlink, outside the destination"
    );
    assert!(
        std::fs::symlink_metadata(dest.join("evil")).is_err(),
        "the symlink must not have been created"
    );
}

#[test]
fn a_symlink_chain_cannot_walk_out_of_the_destination() {
    // Neither link's own path escapes, and neither target is absolute: the
    // escape only exists once the two are followed together. `b`'s target is
    // refused on its own terms, which is what keeps the chain from ever
    // being walkable.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("chain.tar"),
        &[
            Raw::Symlink("a", "b"),
            Raw::Symlink("b", "../.."),
            Raw::File("a/pwned.txt", b"pwned"),
        ],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "a chained symlink escape must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("pwned.txt").exists() && !dir.parent().unwrap().join("pwned.txt").exists(),
        "the chain wrote outside the destination"
    );
}

#[test]
fn a_traversal_buried_inside_a_deeper_path_is_refused() {
    // `a/b/../../../escaped.txt` nets one level above the destination, but
    // only after two real components have been pushed — the shape a
    // "does the name start with ..?" check would wave straight through.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("deep.tar"),
        &[Raw::File("a/b/../../../escaped.txt", b"pwned")],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "a buried traversal must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("escaped.txt").exists(),
        "the buried traversal escaped the destination"
    );
}

#[test]
fn a_directory_entry_that_escapes_the_destination_is_refused() {
    // A directory entry creates a path without writing a byte of payload, so
    // a containment check placed on the file-writing branch alone would miss
    // it entirely.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(&dir.join("dir.tar"), &[Raw::Dir("../escaped-dir/")]);

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an escaping directory entry must be refused (exit 7), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("escaped-dir").exists(),
        "the directory escaped the destination"
    );
}

// --- Legitimate archives must still extract ------------------------------

#[test]
fn an_entry_named_dot_extracts_alongside_the_real_entries() {
    // `.` names the destination itself and is accepted, not refused: this is
    // the first entry `tar cf x.tar .` emits, and refusing it would turn a
    // security refusal loose on the most common tarball there is.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("dot.tar"),
        &[Raw::Dir("./"), Raw::File("./a.txt", b"alpha")],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "a `./` entry must be accepted, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
}

/// The `tar cf x.tar .` idiom, built by the SYSTEM tar rather than by the
/// `tar` crate, extracted with stuffr and compared byte for byte. Three
/// safety checks in this phase have each threatened to fire on benign input;
/// this is the one that proves the containment check does not.
#[test]
fn a_system_tar_of_dot_extracts_cleanly() {
    let Some(tar_bin) = which_tar() else {
        eprintln!("system tar not found; skipping");
        return;
    };
    let dir = tmp_dir();
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::write(src.join("top.txt"), b"top level").unwrap();
    std::fs::write(src.join("nested/deep.txt"), b"nested payload").unwrap();

    let archive = dir.join("dot.tar");
    let status = Command::new(&tar_bin)
        .arg("cf")
        .arg(&archive)
        .arg(".")
        .current_dir(&src)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "the system tar failed to build the fixture"
    );

    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "`tar cf x.tar .` must extract cleanly, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("top.txt")).unwrap(), b"top level");
    assert_eq!(
        std::fs::read(dest.join("nested/deep.txt")).unwrap(),
        b"nested payload"
    );
}

/// `tar.rs`'s own tests gate on the system tool the same way rather than
/// failing a machine that has none.
fn which_tar() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("tar"))
        .find(|candidate| candidate.is_file())
}

// Symlink creation is unix-only, the way `ops_compress.rs` gates its own
// symlink tests.
#[cfg(unix)]
#[test]
fn extraction_writes_files_directories_and_contained_symlinks() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("good.tar"),
        &[
            Raw::Dir("sub/"),
            Raw::File("sub/a.txt", b"alpha"),
            Raw::Symlink("sub/link", "a.txt"),
        ],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dest.join("sub").is_dir());
    assert_eq!(std::fs::read(dest.join("sub/a.txt")).unwrap(), b"alpha");
    let link = std::fs::symlink_metadata(dest.join("sub/link")).unwrap();
    assert!(
        link.file_type().is_symlink(),
        "a symlink entry must become a symlink"
    );
    assert_eq!(
        std::fs::read_link(dest.join("sub/link")).unwrap(),
        Path::new("a.txt")
    );
    // Following it stays inside the destination, which is why it was allowed.
    assert_eq!(std::fs::read(dest.join("sub/link")).unwrap(), b"alpha");
}

#[test]
fn extraction_selects_only_the_entries_a_pattern_names() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_fixture_tar(
        &dir,
        &[
            ("a.txt", b"alpha"),
            ("b.txt", b"beta"),
            ("d/c.txt", b"gamma"),
        ],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "b.txt",
        "d",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dest.join("a.txt").exists(),
        "an unmatched entry was extracted"
    );
    assert_eq!(std::fs::read(dest.join("b.txt")).unwrap(), b"beta");
    // A pattern naming a directory selects everything beneath it.
    assert_eq!(std::fs::read(dest.join("d/c.txt")).unwrap(), b"gamma");
}

#[test]
fn a_pattern_matching_no_entry_is_a_usage_error_rather_than_a_silent_success() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
        "nosuch.txt",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "extracting nothing at all must not report success, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run_output(&["cat", archive.to_str().unwrap(), "nosuch.txt"]);
    assert_eq!(out.status.code(), Some(2), "cat must agree with unpack");
}

#[test]
fn extraction_refuses_an_existing_file_unless_force_is_given() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("a.txt"), b"mine").unwrap();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an existing file must be refused like every other output, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"mine");

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--force",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
}

// Symlink creation is unix-only, the way `ops_compress.rs` gates its own
// symlink tests.
#[cfg(unix)]
#[test]
fn a_pre_existing_symlink_at_a_target_path_is_replaced_not_written_through() {
    // `File::create` follows a symlink. Somebody who can plant
    // `dest/a.txt -> outside` before extraction would otherwise redirect the
    // entry's bytes there; --force removes what is in the way rather than
    // writing through it.
    let dir = tmp_dir();
    let dest = dir.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    let outside = dir.join("outside.txt");
    std::fs::write(&outside, b"untouched").unwrap();
    std::os::unix::fs::symlink(&outside, dest.join("a.txt")).unwrap();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--force",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"untouched",
        "the entry was written through the pre-existing symlink"
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
}

#[test]
fn extraction_of_a_corrupt_archive_exits_five_not_seven() {
    // Corrupt, hostile and oversized must stay three distinguishable
    // answers: a script branches on which one it got.
    let dir = tmp_dir();
    let good = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"beta")]);
    let corrupt = corrupt_midway(&good);
    let out = run_output(&[
        "unpack",
        corrupt.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(5),
        "a corrupt archive is exit 5, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn extraction_of_a_bomb_exits_six_at_a_tight_max_ratio() {
    let dir = tmp_dir();
    let bomb = write_bomb_tar_gz(&dir);
    let out = run_output(&[
        "unpack",
        bomb.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
        "--max-ratio",
        "2",
    ]);
    assert_eq!(
        out.status.code(),
        Some(6),
        "a bomb is a resource limit (exit 6), stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cat_streams_every_entry_a_pattern_names_and_bounds_the_ratio() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"beta")]);
    let out = run_output(&["cat", archive.to_str().unwrap(), "a.txt"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "alpha");

    let bomb = write_bomb_tar_gz(&dir);
    let out = run_output(&[
        "cat",
        bomb.to_str().unwrap(),
        "bomb.bin",
        "--max-ratio",
        "2",
    ]);
    assert_eq!(
        out.status.code(),
        Some(6),
        "cat must bound an entry the same way extraction does, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn an_archive_needs_a_destination_and_the_error_says_which_flag() {
    // `unpack backup.tar` with no -C used to reach the single-stream decoder
    // and report "containers arrive in Phase 2". It now names the flag that
    // does what the user meant.
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let out = run_output(&["unpack", archive.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("-C") && stderr.contains("tar"),
        "the error must name both the container and the flag, got: {stderr}"
    );
    assert!(
        !dir.join("fixture").exists(),
        "nothing may be written for a refused command"
    );
}

#[test]
fn pack_refuses_several_paths_when_the_output_is_not_a_container() {
    let dir = tmp_dir();
    std::fs::write(dir.join("one.txt"), b"1").unwrap();
    std::fs::write(dir.join("two.txt"), b"2").unwrap();
    let out = run_output(&[
        "pack",
        dir.join("one.txt").to_str().unwrap(),
        dir.join("two.txt").to_str().unwrap(),
        "-o",
        dir.join("bundle.gz").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a codec cannot hold two inputs, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("bundle.gz").exists(),
        "a refused command must write nothing"
    );
}

#[test]
fn pack_into_a_container_round_trips_through_extraction() {
    let dir = tmp_dir();
    std::fs::write(dir.join("one.txt"), b"first").unwrap();
    std::fs::write(dir.join("two.txt"), b"second").unwrap();
    let archive = dir.join("bundle.tar");
    let out = run_output(&[
        "pack",
        dir.join("one.txt").to_str().unwrap(),
        dir.join("two.txt").to_str().unwrap(),
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("one.txt")).unwrap(), b"first");
    assert_eq!(std::fs::read(dest.join("two.txt")).unwrap(), b"second");
}

#[test]
fn pack_refuses_two_inputs_that_would_share_one_entry_name() {
    let dir = tmp_dir();
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    std::fs::write(dir.join("a/same.txt"), b"1").unwrap();
    std::fs::write(dir.join("b/same.txt"), b"2").unwrap();
    let archive = dir.join("dup.tar");
    let out = run_output(&[
        "pack",
        dir.join("a/same.txt").to_str().unwrap(),
        dir.join("b/same.txt").to_str().unwrap(),
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "two entries with one name would make an archive that cannot be \
         extracted without --force, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!archive.exists(), "a refused command must write nothing");
}

/// Was `pack_of_a_directory_says_so_rather_than_writing_an_empty_archive`,
/// which asserted exit 2 on a directory. Phase 2c walks it instead, so the
/// property worth keeping is the one the old name was really about: a
/// directory must not silently produce an archive with nothing in it. An
/// EMPTY directory is still one real entry.
#[test]
fn pack_of_an_empty_directory_stores_the_directory_itself() {
    let dir = tmp_dir();
    std::fs::create_dir_all(dir.join("tree")).unwrap();
    let archive = dir.join("tree.tar");
    let out = run_output(&[
        "pack",
        dir.join("tree").to_str().unwrap(),
        "-o",
        archive.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let listed = run_output(&["list", archive.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("tree"),
        "the directory itself must be an entry, not an empty archive: {text}"
    );
}

#[test]
fn flags_that_the_container_path_cannot_honour_are_refused_not_ignored() {
    // The tree's rule (see `threads_is_not_offered_on_decode_subcommands`):
    // a flag that would be silently ignored is refused instead.
    //
    // `--memory-limit` used to be in this list and no longer is: the Phase 2
    // final review's C1 threaded it through container resolution, so it is
    // now honoured rather than refused — see
    // `memory_limit_is_honoured_rather_than_refused_on_the_container_path`.
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let dest = dir.join("out");
    for extra in [vec!["--format", "gzip"], vec!["-o", "somewhere"]] {
        let mut args = vec![
            "unpack",
            archive.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ];
        args.extend_from_slice(&extra);
        let out = run_output(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "`{}` must be refused alongside -C, stderr: {}",
            extra.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The same rule, applied to the PACK side, which had it backwards.
///
/// `entries::create_archive` builds `CreateOpts { level, ..Default::default() }`
/// — it hands the container no governor, no worker count and no weak-encoder
/// consent, because none of the four registered containers compresses
/// anything itself. So `--threads`, `--turbo` and `--allow-weak-encoder`
/// were accepted and silently dropped: precisely what the extract side above
/// refuses. Consistency, not new capability.
#[test]
fn pack_flags_the_container_path_cannot_honour_are_refused_not_ignored() {
    let dir = tmp_dir();
    let src = dir.join("a.txt");
    std::fs::write(&src, b"alpha").unwrap();
    let archive = dir.join("bundle.tar");
    for extra in [
        vec!["--threads", "4"],
        vec!["--turbo"],
        vec!["--allow-weak-encoder"],
    ] {
        let mut args = vec![
            "pack",
            src.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
        ];
        args.extend_from_slice(&extra);
        let out = run_output(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "`{}` must be refused on the container pack path, stderr: {}",
            extra.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !archive.exists(),
            "a refused command must write nothing: {}",
            extra.join(" ")
        );
    }

    // The same flags stay ACCEPTED on the single-stream codec path, which
    // genuinely honours them — the refusal above must not have leaked.
    let out = run_output(&[
        "pack",
        src.to_str().unwrap(),
        "--format",
        "gzip",
        "--threads",
        "2",
        "--force",
    ]);
    assert!(
        out.status.success(),
        "the codec path still honours --threads, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The gap the two lexical checks cannot see on their own, demonstrated
/// outside stuffr first (a shell reproduction is in the task report): every
/// step below is contained COMPONENT-WISE from the destination, and the OS
/// still resolves the last one outside it.
///
/// * `a/b/up -> ..` is contained: it resolves to `<dest>/a`.
/// * `a/b/up/link -> ../..` resolves, component-wise from `<dest>`, to `a`
///   — inside. Resolved by the OS through `up`, whose real parent is
///   `<dest>/a`, it lands on `<dest>/..`: the directory holding `<dest>`.
/// * `a/b/up/link/pwned.txt` is then an ordinary contained name written
///   straight through it.
///
/// So an entry whose PATH COMPONENTS include an existing symlink is refused
/// outright — the same defence libarchive's SECURE_SYMLINKS provides, and it
/// closes the pre-existing-hostile-symlink case in the destination too.
#[cfg(unix)]
#[test]
fn an_entry_written_through_a_symlinked_path_component_is_refused() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let evil = write_raw_tar(
        &dir.join("component.tar"),
        &[
            Raw::Dir("a/b/"),
            Raw::Symlink("a/b/up", ".."),
            Raw::Symlink("a/b/up/link", "../.."),
            Raw::File("a/b/up/link/pwned.txt", b"pwned"),
        ],
    );

    let out = run_output(&[
        "unpack",
        evil.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "an entry resolving through a symlinked component must be refused (exit 7), \
         stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.join("pwned.txt").exists(),
        "the entry escaped the destination through a symlinked path component"
    );
}

// ---------------------------------------------------------------------
// Extraction fidelity.
//
// `--strict-fidelity` gates on `FidelityReport::has_warnings`, so a loss that
// raises no warning is a loss the flag reports as success. These tests are
// the difference between the warnings meaning something and being decoration.
// ---------------------------------------------------------------------

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn mtime_secs(path: &Path) -> u64 {
    std::fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(unix)]
#[test]
fn extraction_restores_modes_and_mtimes_for_files_and_directories() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("meta.tar"),
        &[
            Raw::Dir("sub/"),
            Raw::ModedFile("sub/script.sh", b"#!/bin/sh\n", 0o750),
            Raw::ModedFile("readonly.txt", b"ro", 0o400),
        ],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(mode_of(&dest.join("sub/script.sh")), 0o750);
    assert_eq!(mode_of(&dest.join("readonly.txt")), 0o400);
    assert_eq!(mode_of(&dest.join("sub")), 0o755);
    assert_eq!(mtime_secs(&dest.join("sub/script.sh")), FIXTURE_MTIME);
    assert_eq!(mtime_secs(&dest.join("readonly.txt")), FIXTURE_MTIME);
    // A directory's mtime is restored AFTER its children are written —
    // creating one of them would otherwise bump it back to now.
    assert_eq!(mtime_secs(&dest.join("sub")), FIXTURE_MTIME);

    // Nothing was lost, so the gate passes.
    let strict = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("strict").to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert!(
        strict.status.success(),
        "an extraction that lost nothing must pass --strict-fidelity, stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
}

#[cfg(unix)]
#[test]
fn a_setuid_bit_is_not_restored_and_strict_fidelity_fails_on_the_loss() {
    // An archive is untrusted input; honouring its setuid bit hands over a
    // privilege-escalation primitive for free. Dropping it is a real
    // difference from what the archive declared, so it is REPORTED — which is
    // what makes `--strict-fidelity` able to see it.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("setuid.tar"),
        &[Raw::ModedFile("suid", b"payload", 0o4755)],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "the extraction itself succeeds, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        mode_of(&dest.join("suid")),
        0o755,
        "the setuid bit must not be restored"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("suid") && stderr.contains("mode"),
        "the loss must be reported, naming the entry and the field: {stderr}"
    );

    let strict = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("strict").to_str().unwrap(),
        "--force",
        "--strict-fidelity",
    ]);
    assert_eq!(
        strict.status.code(),
        Some(4),
        "a dropped mode must fail --strict-fidelity, stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
}

#[cfg(unix)]
#[test]
fn an_entry_with_no_shape_on_disk_is_skipped_and_said_out_loud() {
    // A fifo is `EntryKind::Other`. Writing it out as a regular file carrying
    // its "contents" would materialise something the archive never held.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("fifo.tar"),
        &[Raw::File("a.txt", b"alpha"), Raw::Fifo("pipe")],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
    assert!(
        std::fs::symlink_metadata(dest.join("pipe")).is_err(),
        "a fifo entry must not become a regular file"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("skipped entry") && stderr.contains("pipe"),
        "the skip must name the entry and why: {stderr}"
    );

    let strict = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("strict").to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(
        strict.status.code(),
        Some(4),
        "a skipped entry must fail --strict-fidelity, stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
}

#[cfg(unix)]
#[test]
fn a_symlinks_own_mode_and_mtime_are_reported_as_lost() {
    // `set_permissions` and `File::set_times` both follow a link, and there
    // is no `lchmod`/`lutimes` in std — so the link's own metadata cannot be
    // restored, and saying so is the whole job of the fidelity report.
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("link.tar"),
        &[Raw::File("a.txt", b"alpha"), Raw::Symlink("link", "a.txt")],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("link") && stderr.contains("mtime"),
        "the loss must name the entry and the field: {stderr}"
    );
    // The link itself still extracted — this is a fidelity report, not a
    // refusal.
    assert_eq!(
        std::fs::read_link(dest.join("link")).unwrap(),
        Path::new("a.txt")
    );
}

#[test]
fn test_verb_passes_strict_fidelity_on_an_ordinary_tarball() {
    // The counterpart assertion to the four above: the flag is not simply
    // "fail whenever it is given". A tar read approximates nothing.
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let out = run_output(&["test", archive.to_str().unwrap(), "--strict-fidelity"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// An `st_mode`-shaped mode field must not read as "setuid was refused".
///
/// Apache Commons Compress writes `TarArchiveEntry.DEFAULT_FILE_MODE =
/// 0100644` — the file-type bit `S_IFREG` still in it — which puts this shape
/// in Java, Gradle and Maven tarballs. `0o100644 & !0o777` is `0o100000`,
/// non-zero, so an unmasked check would report a dropped mode for EVERY entry
/// of an entirely ordinary archive and fail `--strict-fidelity` on all of
/// them, while the file itself lands at `0o644` exactly as it should. The
/// permission apply was always right; only the warning was wrong.
#[cfg(unix)]
#[test]
fn an_st_mode_shaped_header_mode_raises_no_warning() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("commons.tar"),
        &[Raw::ModedFile("a.txt", b"alpha", 0o100_644)],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert!(
        out.status.success(),
        "an st_mode-shaped mode field must not fail the gate, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("missing metadata"),
        "nothing was lost, so nothing may be reported: {stderr}"
    );
    assert_eq!(
        mode_of(&dest.join("a.txt")),
        0o644,
        "the permission bits apply; the type bits are not permissions"
    );

    // The setuid case must still be caught — the mask must not have widened
    // into "ignore everything above 0o777".
    let suid = write_raw_tar(
        &dir.join("suid.tar"),
        &[Raw::ModedFile("b.txt", b"beta", 0o104_755)],
    );
    let out = run_output(&[
        "unpack",
        suid.to_str().unwrap(),
        "-C",
        dir.join("suid-out").to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "setuid inside an st_mode-shaped field is still a dropped mode, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Builds a `.tar.lz` and returns `(legitimate, crafted)`.
///
/// `crafted` differs from `legitimate` in exactly ONE byte: lzip's header
/// byte 5, the coded dictionary size, forced to `0x1D` — 512 MiB. The
/// payload is untouched and still decodes, so anything the crafted file
/// costs comes purely from the DECLARATION, which is what makes it the
/// right probe for a pre-output allocation guard.
fn craft_a_tar_lz_declaring_a_huge_dictionary(tag: &str) -> (PathBuf, PathBuf) {
    let dir = tmp(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let tar_path = dir.join("bundle.tar");
    write_raw_tar(
        &tar_path,
        &[Raw::File("a.txt", b"hello from inside the tar")],
    );

    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                tar_path.to_str().unwrap(),
                "--format",
                "lzip",
                "--force"
            ])
            .status()
            .unwrap()
            .success(),
        "packing the fixture must succeed"
    );
    let legit = dir.join("bundle.tar.lz");

    let mut bytes = std::fs::read(&legit).unwrap();
    assert_eq!(&bytes[..4], b"LZIP", "fixture must really be lzip");
    // Byte 5 is lzip's coded dictionary size. 0x1D asks for 512 MiB.
    bytes[5] = 0x1D;
    let crafted = dir.join("crafted.tar.lz");
    std::fs::write(&crafted, &bytes).unwrap();

    (legit, crafted)
}

/// The Phase 2 final review's C1, pinned on every entry-aware verb.
///
/// `entries::open_archive` resolved the codec layer beneath a container
/// through `resolve_chain_deep`, which built each decoder from
/// `DecodeOpts::default()` — `memory_limit: None`, i.e. unbounded. So a
/// 336-byte `.tar.lz` whose header declares a 512 MiB dictionary drove
/// 182 MB peak RSS through `list` and 307 MB through `test`, both exiting 0,
/// while single-stream `unpack` of the identical bytes refused it at exit 6
/// in 1.7 MB. That is the denial of service Phase 1f closed, reopened behind
/// `list` — the verb advertised as reading nothing and extracting nothing.
///
/// `--max-ratio` cannot substitute: it counts decoded OUTPUT bytes and the
/// allocation precedes any output. Only `DecodeOpts::memory_limit` sees it.
///
/// Every invocation passes `--memory-limit` EXPLICITLY. Relying on the
/// default would make the test host-dependent and green only by accident:
/// `default_memory_limit()` is 25% of available RAM, which is the 256 MiB
/// floor on macOS (no `/proc/meminfo`) but roughly 3.5 GiB on a 16 GB Linux
/// CI runner — comfortably above the 512 MiB this fixture declares, so all
/// four verbs would exit 0 and the assertion would fail on every Linux job.
/// Measured directly: `stuffr list crafted.tar.lz --memory-limit 3500M`
/// exits 0. 0x1D is lzip's LARGEST coded dictionary, so the fixture cannot
/// be made hungrier to compensate. `cli.rs`'s
/// `info_reports_the_resolved_memory_limit` states the same convention.
#[test]
fn a_container_under_a_codec_declaring_a_huge_dictionary_is_refused_on_every_verb() {
    let (_legit, crafted) = craft_a_tar_lz_declaring_a_huge_dictionary("c1-refuse");
    let path = crafted.to_str().unwrap();
    // Below the fixture's 512 MiB declaration, above what the legitimate
    // sibling needs — see `a_legitimate_archive_of_the_same_size_still_works_on_every_verb`.
    const LIMIT: &str = "64M";

    for args in [
        vec!["list", path, "--memory-limit", LIMIT],
        vec!["test", path, "--memory-limit", LIMIT],
        vec!["cat", path, "a.txt", "--memory-limit", LIMIT],
    ] {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert_eq!(
            out.status.code(),
            Some(6),
            "`stuffr {}` must refuse a 512 MiB dictionary declaration at exit 6, \
             not allocate for it; stderr: {stderr}",
            args.join(" ")
        );
        assert!(
            stderr.contains("memory-limit"),
            "the refusal must name the flag that raises it; stderr: {stderr}"
        );
    }

    // The single-stream path already did this; it must keep doing it.
    let out = Command::new(STUFFR)
        .args([
            "unpack",
            path,
            "-o",
            "/dev/null",
            "--force",
            "--memory-limit",
            LIMIT,
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(6),
        "the single-stream path's existing refusal must be unchanged; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // And over a pipe, where there is no path to resolve the chain from.
    let mut child = Command::new(STUFFR)
        .args(["list", "-", "--memory-limit", LIMIT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let bytes = std::fs::read(&crafted).unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(6),
        "a piped crafted archive must be refused too; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The other half of C1, and the one that catches an over-broad fix: a
/// LEGITIMATE archive of the same size, differing in that one header byte,
/// must still work on every verb. A guard that refused this would be a
/// worse defect than the one it closed.
#[test]
fn a_legitimate_archive_of_the_same_size_still_works_on_every_verb() {
    let (legit, crafted) = craft_a_tar_lz_declaring_a_huge_dictionary("c1-allow");
    let path = legit.to_str().unwrap();
    assert_eq!(
        std::fs::metadata(&legit).unwrap().len(),
        std::fs::metadata(&crafted).unwrap().len(),
        "the two fixtures must differ only in that one byte"
    );

    // The SAME explicit limit its crafted sibling is refused at, so the pair
    // proves the bound discriminates on the declaration rather than refusing
    // everything — and so neither half depends on the host's RAM.
    const LIMIT: &str = "64M";

    let out = Command::new(STUFFR)
        .args(["list", path, "--memory-limit", LIMIT])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("a.txt"),
        "list must still show the entry"
    );

    let out = Command::new(STUFFR)
        .args(["test", path, "--memory-limit", LIMIT])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(STUFFR)
        .args(["cat", path, "a.txt", "--memory-limit", LIMIT])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, b"hello from inside the tar");

    let dest = tmp("c1-allow-dest");
    let _ = std::fs::remove_dir_all(&dest);
    let out = Command::new(STUFFR)
        .args([
            "unpack",
            path,
            "-C",
            dest.to_str().unwrap(),
            "--memory-limit",
            LIMIT,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dest.join("a.txt").exists());
    let _ = std::fs::remove_dir_all(&dest);
}

/// `--memory-limit` is now ACCEPTED and honoured on the entry-aware paths,
/// where it used to be refused at exit 2 with "not yet honoured for a
/// container". Raising it past the declaration lets the crafted archive
/// through, which is the proof the flag actually reaches the decoder rather
/// than being parsed and dropped.
#[test]
fn memory_limit_is_honoured_rather_than_refused_on_the_container_path() {
    let (_legit, crafted) = craft_a_tar_lz_declaring_a_huge_dictionary("c1-flag");
    let path = crafted.to_str().unwrap();

    for args in [
        vec!["list", path, "--memory-limit", "1G"],
        vec!["test", path, "--memory-limit", "1G"],
        vec!["cat", path, "a.txt", "--memory-limit", "1G"],
    ] {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "`stuffr {}` must succeed once the limit is raised past the declaration; \
             stderr: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let dest = tmp("c1-flag-dest");
    let _ = std::fs::remove_dir_all(&dest);
    let out = Command::new(STUFFR)
        .args([
            "unpack",
            path,
            "-C",
            dest.to_str().unwrap(),
            "--memory-limit",
            "1G",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "unpack -C must accept --memory-limit rather than refusing it; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dest);
}

/// The Phase 2 final review's I1, end to end.
///
/// `sub/top -> ..` points at the extraction root. bsdtar and GNU tar both
/// extract it; stuffr aborted the whole extraction at exit 7 with "unsafe
/// entry path `sub/..` refused: path traversal nets back to the
/// destination" — naming a path that is not an entry in the archive, so the
/// user could not find it. `dest` is inside `dest`; there is no escape here.
#[test]
fn a_symlink_pointing_at_the_extraction_root_is_extracted_not_refused() {
    let dir = tmp_dir();
    let dest = dir.join("out");
    let archive = write_raw_tar(
        &dir.join("root-link.tar"),
        &[
            Raw::Dir("sub"),
            Raw::Symlink("sub/top", ".."),
            Raw::File("sub/a.txt", b"alpha"),
        ],
    );

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "a symlink netting to the destination is contained, not an escape; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let link = dest.join("sub/top");
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "the symlink must have been created"
    );
    assert_eq!(std::fs::read_link(&link).unwrap(), Path::new(".."));
    assert!(dest.join("sub/a.txt").exists(), "extraction must not abort");
}

/// The regression guard for the test above: one step further out is still
/// an escape, and must still exit 7 with the entry's OWN target named.
#[test]
fn a_symlink_one_step_past_the_extraction_root_is_still_refused() {
    for (tag, target) in [
        ("i1-two-up", "../.."),
        ("i1-deep", "../../../etc"),
        ("i1-mixed", "../sub/../.."),
    ] {
        let dir = tmp_dir();
        let dest = dir.join(tag);
        let archive = write_raw_tar(
            &dir.join(format!("{tag}.tar")),
            &[Raw::Dir("sub"), Raw::Symlink("sub/top", target)],
        );
        let out = run_output(&[
            "unpack",
            archive.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ]);
        assert_eq!(
            out.status.code(),
            Some(7),
            "`{target}` escapes and must still be refused, stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            stderr.contains(target),
            "the refusal must name the archive's own target `{target}`, got: {stderr}"
        );
        assert!(
            std::fs::symlink_metadata(dest.join("sub/top")).is_err(),
            "the symlink must not have been created"
        );
    }
}

/// The Phase 2 final review's I2, across the third dimension round 3
/// missed: container × WRAPPED-IN-A-CODEC × source shape.
///
/// `fidelity_is_knowable_without_opening` returned `true` as soon as the
/// rung was authoritative — but the rung is the RAW INPUT's seekability,
/// which says nothing about a container reached through a decoder.
/// `bundle.zip.gz` on disk is a seekable file, so `info` printed
/// `rung: exact / fidelity: nothing approximated`, while `stuffr test
/// bundle.zip.gz --strict-fidelity` on the same bytes reported
/// `TrailingIndexUnread` and `EntryCountUnknown` and exited 4.
///
/// Every cell is checked against ground truth from `test`, which actually
/// opens the archive — so the assertions cannot drift into merely agreeing
/// with the predicate.
#[test]
fn info_does_not_claim_nothing_was_approximated_for_a_container_under_a_codec() {
    let dir = tmp("info-codec-wrapped-matrix");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let one = dir.join("one.txt");
    std::fs::write(&one, b"payload").unwrap();

    for (ext, has_trailing_index) in [("zip", true), ("tar", false), ("cpio", false), ("a", false)]
    {
        let bare = dir.join(format!("bundle.{ext}"));
        assert!(
            Command::new(STUFFR)
                .args(["pack", one.to_str().unwrap(), "-o", bare.to_str().unwrap()])
                .status()
                .unwrap()
                .success(),
            "packing a .{ext} must succeed"
        );
        // Two steps here on purpose, not because one is impossible: since
        // Phase 2c `-o bundle.tar.gz` composes both layers in a single
        // command. What this test needs is a codec wrapped around an
        // ALREADY-WRITTEN container file, so that `info` sees a codec whose
        // inner layer it must resolve — and packing the container first is
        // the clearest way to get exactly that byte sequence.
        assert!(
            Command::new(STUFFR)
                .args([
                    "pack",
                    bare.to_str().unwrap(),
                    "--format",
                    "gzip",
                    "--force"
                ])
                .status()
                .unwrap()
                .success(),
            "wrapping the .{ext} in gzip must succeed"
        );
        let wrapped = dir.join(format!("bundle.{ext}.gz"));
        let bytes = std::fs::read(&wrapped).unwrap();

        // Ground truth first, from the verb that opens the archive.
        let strict = Command::new(STUFFR)
            .args(["test", wrapped.to_str().unwrap(), "--strict-fidelity"])
            .output()
            .unwrap();
        let strict_err = String::from_utf8_lossy(&strict.stderr).to_string();
        let really_loses = !strict.status.success();
        assert_eq!(
            really_loses, has_trailing_index,
            ".{ext}.gz: only a trailing index can be missed by a forward read; \
             stderr: {strict_err}"
        );

        // (a) A SEEKABLE FILE, where the path's extensions name the whole
        //     chain (`bundle.zip.gz` -> zip over gzip). This is the cell
        //     I2 reported: `rung: exact`, because the FILE is seekable,
        //     over a container that is not read from that file at all.
        let text = String::from_utf8(
            Command::new(STUFFR)
                .args(["info", wrapped.to_str().unwrap()])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(
            text.contains("exact"),
            ".{ext}.gz from a file: the rung is real and unchanged: {text}"
        );
        assert!(
            text.contains(ext),
            ".{ext}.gz from a file must resolve the whole chain: {text}"
        );
        if has_trailing_index {
            assert!(
                text.contains("not evaluated"),
                ".{ext}.gz from a file: the zip is read out of a gzip decoder, which is \
                 forward-only however seekable the FILE is — `test` on these very bytes \
                 exits 4. info has not looked and must not claim: {text}"
            );
            assert!(!text.contains("nothing approximated"), "{text}");
        } else {
            assert!(
                text.contains("nothing approximated"),
                ".{ext}.gz from a file carries every entry's metadata inline, so a forward \
                 read loses nothing — withholding here would be a false negative, the \
                 round-3 defect repeating: {text}"
            );
            assert!(!text.contains("not evaluated"), "{text}");
        }

        // (b) A PIPE with no path. `inspect` resolves the chain with the
        //     SHALLOW `resolve_chain` — it identifies a stream without
        //     decoding it, and seeing the zip inside would mean running the
        //     gzip decoder. With no path to read extensions from, there is
        //     nothing to name the inner layer, so the chain bottoms out at
        //     the codec and `info` reports on the codec alone. That is a
        //     documented limit of `info`, not the I2 defect: the claim it
        //     makes is about what it identified. Pinned so the two cells
        //     cannot be confused for one another later.
        let text = info_over_stdin(&bytes);
        assert!(text.contains("forward-only"), ".{ext}.gz on a pipe: {text}");
        assert!(
            text.contains("chain:    gzip"),
            ".{ext}.gz on a pipe resolves to the codec alone — info does not decode to \
             look inside: {text}"
        );

        // And the codec-wrapped verdict must not have leaked onto the BARE
        // container: a seekable bare zip still reads its central directory.
        let text = String::from_utf8(
            Command::new(STUFFR)
                .args(["info", bare.to_str().unwrap()])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(
            text.contains("nothing approximated"),
            "a bare seekable .{ext} is unaffected by the codec-wrapped rule: {text}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The Phase 2 final review's I3: `entries::test` built no `ArchiveBudget`
/// at all, so a 204 KB zip holding one 200 MB entry verified clean at exit
/// 0 under `--max-ratio 10` while `cat` and `unpack` of the identical file
/// refused it at exit 6. `test` is the verb reached for to inspect an
/// UNTRUSTED archive; it must not be the only unbounded one.
#[test]
fn every_entry_aware_verb_applies_the_same_expansion_bound() {
    let dir = tmp_dir();
    // Highly compressible, and large enough that a ratio of 10 cannot cover
    // it while staying quick to build.
    let payload = vec![0u8; 8 * 1024 * 1024];
    let big = dir.join("big.bin");
    std::fs::write(&big, &payload).unwrap();
    let bomb = dir.join("bomb.zip");
    assert!(
        Command::new(STUFFR)
            .args(["pack", big.to_str().unwrap(), "-o", bomb.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let compressed = std::fs::metadata(&bomb).unwrap().len();
    assert!(
        compressed * 10 < payload.len() as u64,
        "the fixture must actually exceed a ratio of 10 ({compressed} compressed)"
    );

    let dest = dir.join("out");
    for args in [
        vec!["test", bomb.to_str().unwrap(), "--max-ratio", "10"],
        vec![
            "cat",
            bomb.to_str().unwrap(),
            "big.bin",
            "--max-ratio",
            "10",
        ],
        vec![
            "unpack",
            bomb.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
            "--max-ratio",
            "10",
        ],
    ] {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(6),
            "`stuffr {}` must refuse the same bomb the other verbs refuse; stderr: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // The other half: the default ratio still lets the same archive through
    // on all three, so the new bound is not simply refusing everything.
    let _ = std::fs::remove_dir_all(&dest);
    for args in [
        vec!["test", bomb.to_str().unwrap()],
        vec!["cat", bomb.to_str().unwrap(), "big.bin"],
        vec![
            "unpack",
            bomb.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ],
    ] {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "`stuffr {}` must still accept a legitimate archive under the default ratio; \
             stderr: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The Phase 2 re-review's second finding: the pipe path refused every real
/// archive.
///
/// `ArchiveBudget::ceiling` returned a flat `RATIO_FLOOR` (1 MiB) whenever
/// the compressed total was unknown, which is always true of a pipe — so
/// `cat photos.zip | stuffr test -` refused any archive over a megabyte, and
/// `--max-ratio`, the flag the refusal names, could not raise it. The
/// examples page documents that exact invocation. `test` acquired the defect
/// when it gained a budget; `cat` and `unpack -C` had carried it since the
/// budget was introduced.
///
/// The fix gives the ratio a denominator on a pipe: bytes actually pulled so
/// far, which `open_archive`'s `Counting` wrapper already tallies. All three
/// assertions below are needed — one that a real archive passes, one that a
/// bomb is still refused, and one that raising the flag now changes the
/// outcome, which is what proves the flag reaches this path at all.
#[test]
fn a_piped_archive_larger_than_the_ratio_floor_is_not_refused() {
    let dir = tmp_dir();
    // Incompressible, so no codec layer can mask the size, and comfortably
    // past the 1 MiB floor.
    let payload: Vec<u8> = (0..3u32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let src = dir.join("big.bin");
    std::fs::write(&src, &payload).unwrap();
    let archive = dir.join("big.tar");
    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "-o",
                archive.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    let bytes = std::fs::read(&archive).unwrap();
    assert!(
        bytes.len() as u64 > stuffr::RATIO_FLOOR,
        "the fixture must exceed the floor or this test proves nothing"
    );

    // Feed stdin from a THREAD, never inline. `stuffr cat - big.bin` writes
    // the 3 MB entry straight back to stdout, and an inline `write_all` here
    // deadlocks the moment that fills the 64 KB pipe buffer: the child blocks
    // writing stdout while this process blocks writing stdin, and neither
    // moves. `wait_with_output` drains stdout and stderr concurrently, so the
    // writer only needs to be off this thread. (Learned the hard way — this
    // hung the gate for 26 minutes.)
    let piped = |args: &[&str], input: &[u8]| {
        let mut child = Command::new(STUFFR)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut sin = child.stdin.take().unwrap();
        let data = input.to_vec();
        // A refusal closes the pipe early, so a broken pipe is an expected
        // outcome here rather than a test failure.
        let writer = std::thread::spawn(move || {
            let _ = sin.write_all(&data);
        });
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap();
        out
    };

    let dest = dir.join("out");
    for args in [
        vec!["test", "-"],
        vec!["cat", "-", "big.bin"],
        vec!["unpack", "-", "-C", dest.to_str().unwrap()],
    ] {
        let out = piped(&args, &bytes);
        assert!(
            out.status.success(),
            "`stuffr {}` over a pipe must not refuse a {}-byte archive; stderr: {}",
            args.join(" "),
            bytes.len(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // The bound is still real over a pipe. Same fixture shape as
    // `every_entry_aware_verb_applies_the_same_expansion_bound`, piped.
    let zeros = vec![0u8; 8 * 1024 * 1024];
    let zsrc = dir.join("zeros.bin");
    std::fs::write(&zsrc, &zeros).unwrap();
    let bomb = dir.join("bomb.zip");
    assert!(
        Command::new(STUFFR)
            .args(["pack", zsrc.to_str().unwrap(), "-o", bomb.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let bomb_bytes = std::fs::read(&bomb).unwrap();

    let piped_test = |extra: &[&str]| {
        let mut argv = vec!["test", "-"];
        argv.extend_from_slice(extra);
        piped(&argv, &bomb_bytes)
    };

    assert_eq!(
        piped_test(&["--max-ratio", "10"]).status.code(),
        Some(6),
        "a bomb piped in must still be refused"
    );
    assert!(
        piped_test(&["--max-ratio", "100000"]).status.success(),
        "raising --max-ratio must change the outcome on a pipe — that is what \
         proves the flag reaches this path rather than being parsed and dropped"
    );
}

/// The Phase 2 final review's I6, at the exit-code boundary a user sees.
///
/// A valid `odc` cpio archive reported `archive is corrupt: Invalid magic
/// number` at exit 5 — telling the user their intact file was damaged.
#[test]
fn a_valid_odc_cpio_archive_reports_a_capability_limit_not_corruption() {
    let dir = tmp_dir();
    // A real `newc` archive with only its magic rewritten to odc's, so the
    // classification is provably decided on the magic. `cpio.rs`'s own
    // `a_real_odc_archive_from_system_cpio_is_unsupported_not_corrupt`
    // proves that magic is what the reference tool actually emits.
    let src = dir.join("f.txt");
    std::fs::write(&src, b"payload").unwrap();
    let newc = dir.join("archive.cpio");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", newc.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let mut bytes = std::fs::read(&newc).unwrap();
    assert_eq!(&bytes[..6], b"070701");
    bytes[..6].copy_from_slice(b"070707");
    let odc = dir.join("odc.cpio");
    std::fs::write(&odc, &bytes).unwrap();

    let out = Command::new(STUFFR)
        .args(["list", odc.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        out.status.code(),
        Some(3),
        "an intact archive in an unreadable variant is a capability limit, \
         not damage; stderr: {stderr}"
    );
    assert!(
        stderr.contains("odc"),
        "the message must name the variant: {stderr}"
    );
    assert!(
        !stderr.contains("corrupt"),
        "the message must not suggest damage: {stderr}"
    );

    // The neighbour it must not have swallowed: a genuinely damaged newc
    // archive is still exit 5.
    let mut broken = std::fs::read(&newc).unwrap();
    broken.truncate(30);
    let cut = dir.join("cut.cpio");
    std::fs::write(&cut, &broken).unwrap();
    let out = Command::new(STUFFR)
        .args(["list", cut.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(5),
        "a truncated archive really is damaged; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// "You pointed the verb at the wrong file" must be ONE exit code.
///
/// `stuffr list plain.txt.gz` (a codec stream, `NotAnArchive`) exited 2
/// while `stuffr list plain.txt` (no format at all, `UnknownFormat`) exited
/// 1 — an internal failure — for the same class of mistake.
#[test]
fn pointing_a_verb_at_the_wrong_file_always_exits_two() {
    let dir = tmp_dir();

    let plain = dir.join("plain.txt");
    std::fs::write(&plain, b"just some text, no format at all").unwrap();
    let gz = dir.join("plain.txt.gz");
    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                plain.to_str().unwrap(),
                "--format",
                "gzip",
                "-o",
                gz.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );

    for (label, path) in [
        ("a codec stream, which is not an archive", &gz),
        ("a file of no recognised format", &plain),
    ] {
        let out = Command::new(STUFFR)
            .args(["list", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{label}: both are the caller pointing `list` at the wrong file, \
             so both are exit 2; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The Phase 2 final review's I5: three multi-line string literals in
/// `main.rs` had been collapsed with their continuation indentation left
/// in, so users saw runs of 22-30 spaces mid-sentence:
///
/// ```text
/// stuffr: usage error: packing 2 paths needs an output naming a container
/// (`-o bundle.tar`,                      or --format tar); a codec …
/// ```
///
/// All three were on new container paths and nothing asserted on any of
/// them. Asserted structurally rather than by exact text, so rewording a
/// message does not break the test but re-introducing the defect does.
///
/// These three cases are RENDERED evidence — real stderr from a real process —
/// and they are deliberately kept, but they are no longer the guard: three
/// hardcoded invocations could not cover a message a later task adds, and in
/// Phase 2c exactly that happened. See
/// `no_message_literal_in_the_workspace_carries_a_run_of_collapsed_indentation`
/// for the enumeration nothing can escape.
#[test]
fn no_cli_message_contains_a_run_of_collapsed_indentation() {
    let dir = tmp_dir();
    let a = dir.join("a.txt");
    let b = dir.join("b.txt");
    std::fs::write(&a, b"alpha").unwrap();
    std::fs::write(&b, b"beta").unwrap();
    let archive = write_fixture_tar(&dir, &[("x.txt", b"x")]);

    let cases: Vec<Vec<String>> = vec![
        // "packing N paths needs an output naming a container…"
        vec![
            "pack".into(),
            a.to_str().unwrap().into(),
            b.to_str().unwrap().into(),
        ],
        // "collecting several paths into an archive needs an explicit -o…"
        vec![
            "pack".into(),
            a.to_str().unwrap().into(),
            b.to_str().unwrap().into(),
            "--format".into(),
            "tar".into(),
        ],
        // "`x.txt` names an archive entry; pass -C DIR…"
        vec![
            "unpack".into(),
            archive.to_str().unwrap().into(),
            "x.txt".into(),
        ],
    ];

    for args in cases {
        let out = Command::new(STUFFR).args(&args).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert_eq!(
            out.status.code(),
            Some(2),
            "`stuffr {}` must be a usage error; stderr: {stderr}",
            args.join(" ")
        );
        assert!(
            !stderr.contains("   "),
            "a CLI message must not carry a run of collapsed continuation \
             indentation; `stuffr {}` printed: {stderr:?}",
            args.join(" ")
        );
        assert!(
            !stderr.trim().is_empty(),
            "and it must actually say something: {stderr:?}"
        );
    }

    // The exact shape of the worst one, pinned so a reworded message that
    // re-collapses is still caught by a human reading the failure.
    let out = Command::new(STUFFR)
        .args(["pack", a.to_str().unwrap(), b.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("`-o bundle.tar`, or --format tar"),
        "the phrase either side of the old collapse must read as one sentence: {stderr:?}"
    );
}

/// The Phase 2c headline: a container over a codec, written in one step.
///
/// The trailer is checked with the SYSTEM tool, not our own reader. The whole
/// bug this phase fixes is a codec trailer that never got written, and our own
/// decoder may be lenient about a missing one — so asserting with `stuffr
/// list` could pass against the very defect under repair.
#[test]
fn a_container_over_a_codec_is_written_in_one_step() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"hello from inside the tar\n").unwrap();
    let out = dir.join("bundle.tar.gz");

    let st = Command::new(STUFFR)
        .args(["pack", src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    // 1. It really is gzip, and the trailer is intact: `gunzip -t` verifies
    //    the CRC32 and ISIZE that the old code never wrote.
    let t = Command::new("gunzip")
        .args(["-t", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        t.status.success(),
        "gunzip -t rejected it: {}",
        String::from_utf8_lossy(&t.stderr)
    );

    // 2. It really is a tar inside, per the system tar.
    let l = Command::new("tar")
        .args(["tzf", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        l.status.success(),
        "tar tzf failed: {}",
        String::from_utf8_lossy(&l.stderr)
    );
    assert!(String::from_utf8_lossy(&l.stdout).contains("notes.txt"));

    // 3. And stuffr reads back what it wrote.
    let r = Command::new(STUFFR)
        .args(["list", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(r.status.success());
    assert!(String::from_utf8_lossy(&r.stdout).contains("notes.txt"));
}

/// v0.2.0 wrote the wrong format, silently, in three different ways. Each
/// line here failed against that binary.
#[test]
fn a_dot_tar_dot_gz_output_is_never_silently_the_wrong_format() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    // Every spelling that means "tar inside gzip".
    for (name, extra) in [
        ("a.tar.gz", vec![]),
        ("b.tgz", vec![]),
        ("c.tar.gz", vec!["--format", "tar"]),
    ] {
        let out = dir.join(name);
        let mut args = vec!["pack", src.to_str().unwrap(), "-o", out.to_str().unwrap()];
        args.extend(extra);
        let st = Command::new(STUFFR).args(&args).output().unwrap();
        assert!(
            st.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&st.stderr)
        );

        // Must be gzip with a valid trailer...
        let t = Command::new("gunzip")
            .args(["-t", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            t.status.success(),
            "{name} is not valid gzip: {}",
            String::from_utf8_lossy(&t.stderr)
        );
        // ...and a tar inside. v0.2.0 produced one or the other, never both.
        let l = Command::new("tar")
            .args(["tzf", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            l.status.success(),
            "{name} has no tar inside: {}",
            String::from_utf8_lossy(&l.stderr)
        );
        assert!(
            String::from_utf8_lossy(&l.stdout).contains("notes.txt"),
            "{name}"
        );
    }
}

/// The neighbours must not regress: a codec-only output still takes the
/// single-stream path, and a container-only output still takes the bare path.
#[test]
fn a_codec_only_or_container_only_output_is_unaffected() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    let gz = dir.join("plain.gz");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", gz.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    // A bare codec output is NOT a tar — decompressing gives the file itself.
    let out = Command::new("gunzip")
        .args(["-c", gz.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"payload\n");

    let tar = dir.join("plain.tar");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", tar.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let l = Command::new("tar")
        .args(["tf", tar.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&l.stdout).contains("notes.txt"));
}

/// A zip inside a codec: the shape that would have shown the stray
/// `flush_destination` in `ZipWrite::finish`, which emitted a `Z_SYNC_FLUSH`
/// empty stored block into the gzip stream before the trailer. And a bare
/// zip must still round-trip after that call was removed.
#[test]
fn a_zip_round_trips_bare_and_inside_a_codec() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"zip payload\n").unwrap();

    for name in ["bare.zip", "wrapped.zip.gz"] {
        let out = dir.join(name);
        let st = Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        if name.ends_with(".gz") {
            let t = Command::new("gunzip")
                .args(["-t", out.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(
                t.status.success(),
                "{name} is not valid gzip: {}",
                String::from_utf8_lossy(&t.stderr)
            );
        }
        let r = Command::new(STUFFR)
            .args(["list", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            r.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        assert!(
            String::from_utf8_lossy(&r.stdout).contains("notes.txt"),
            "{name}"
        );
    }
}

/// `--format` and the output's own name are two sources of truth about the
/// container, and they can disagree. Writing the file anyway is worse than
/// refusing: the bytes are valid gzip, so `pack` exits 0 and `list` on the
/// very same path then exits 5 — stuffr calling its own output corrupt, at
/// the exit code that publicly means "these bytes are damaged".
///
/// Measured at the commit that introduced composition:
/// `pack notes.txt --format zip -o x.tar.gz` wrote a zip inside gzip under a
/// `.tar.gz` name, `stuffr info` reported "tar over gzip", and `stuffr list`
/// exited 5.
#[test]
fn a_format_flag_contradicting_the_output_name_is_refused_before_anything_is_written() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    for (fmt, name) in [
        ("zip", "x.tar.gz"),
        ("tar", "x.zip.gz"),
        ("tar", "x.cpio"),
        ("cpio", "x.tgz"),
    ] {
        let out = dir.join(name);
        let o = Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "--format",
                fmt,
                "-o",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(
            o.status.code(),
            Some(2),
            "--format {fmt} -o {name} must be a usage error, not a written file"
        );
        let stderr = String::from_utf8_lossy(&o.stderr).to_string();
        assert!(
            stderr.contains(fmt) && stderr.contains(name),
            "the message must name both sides of the contradiction: {stderr:?}"
        );
        // "before anything is written" is the whole point of exit 2 here.
        assert!(!out.exists(), "--format {fmt} -o {name} left a file behind");
    }

    // The agreeing spellings are untouched, including the one where the name
    // carries only a codec and --format supplies the container.
    for (fmt, name) in [("tar", "ok.tar.gz"), ("tar", "ok.gz"), ("zip", "ok.zip.gz")] {
        let out = dir.join(name);
        let o = Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "--format",
                fmt,
                "-o",
                out.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "--format {fmt} -o {name} must still work: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        let l = Command::new(STUFFR)
            .args(["list", out.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            l.status.success(),
            "stuffr must be able to read back what it wrote to {name}: {}",
            String::from_utf8_lossy(&l.stderr)
        );
        assert!(
            String::from_utf8_lossy(&l.stdout).contains("notes.txt"),
            "{name}"
        );
    }
}

/// Phase 2c used to hardcode the composed path's governor to `None`
/// specifically so `STUFFR_THREADS` could not succeed at what `--threads`
/// was refused for (no container compressed anything itself, so there was
/// genuinely nothing to hand a worker count to). Now that
/// `refuse_unhonoured_pack_flags` only refuses these where the resolved
/// chain has NO codec layer, `-o out.tar.xz` names a real codec underneath
/// the container, and `entries::create_archive` builds its governor from
/// `ops::resolved_budget(o)` exactly as the single-stream path does —
/// which means `STUFFR_THREADS` is consulted here now, precisely because
/// `--threads` is honoured here now. The two must not drift apart again.
///
/// This is the reproducibility promise working the other way: a
/// multi-threaded xz encode splits the input per worker, so the same input
/// and the same flags now produce DIFFERENT bytes under a different
/// `STUFFR_THREADS` — where before the fix they were, wrongly, identical.
#[test]
fn the_composed_path_honours_stuffr_threads_now_that_a_codec_is_present() {
    let dir = tmp_dir();
    let src = dir.join("big.txt");
    // Compressible but not trivially so, and large enough that xz would
    // really split it across workers.
    let mut data = Vec::with_capacity(4 << 20);
    let mut x: u32 = 0x1234_5678;
    while data.len() < (4 << 20) {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.extend_from_slice(format!("line {} of the corpus\n", x >> 16).as_bytes());
    }
    std::fs::write(&src, &data).unwrap();

    let plain = dir.join("plain.tar.xz");
    let env = dir.join("env.tar.xz");
    for (out, threads) in [(&plain, None), (&env, Some("4"))] {
        let mut cmd = Command::new(STUFFR);
        cmd.args([
            "pack",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--level",
            "1",
        ]);
        match threads {
            Some(n) => cmd.env("STUFFR_THREADS", n),
            None => cmd.env_remove("STUFFR_THREADS"),
        };
        let o = cmd.output().unwrap();
        assert!(
            o.status.success(),
            "pack failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
    assert_ne!(
        std::fs::read(&plain).unwrap(),
        std::fs::read(&env).unwrap(),
        "STUFFR_THREADS=4 must now change the bytes on a composed write with a codec \
         layer, the same way it already does on a single-stream one; identical bytes \
         here means the governor silently went back to None"
    );

    // And the flag it mirrors is honoured directly too, not just the
    // variable behind it — the two stay consistent by construction, but
    // both are worth asserting since either could regress independently.
    let flagged = Command::new(STUFFR)
        .args([
            "pack",
            src.to_str().unwrap(),
            "-o",
            dir.join("flag.tar.xz").to_str().unwrap(),
            "--threads",
            "4",
        ])
        .output()
        .unwrap();
    assert!(
        flagged.status.success(),
        "--threads must be honoured where a codec is present: {}",
        String::from_utf8_lossy(&flagged.stderr)
    );
}

/// Phase 2's minor 4 refused --threads whenever the output named a container,
/// reasoning that no container compresses anything itself. Composition makes
/// that false: `-o out.tar.xz` HAS a codec layer, and xz encodes in parallel.
#[test]
fn encoder_flags_are_refused_only_where_there_is_no_codec_to_honour_them() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    // Bare container: still refused, still exit 2.
    let st = Command::new(STUFFR)
        .args([
            "pack",
            src.to_str().unwrap(),
            "-o",
            dir.join("a.tar").to_str().unwrap(),
            "--threads",
            "2",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(2),
        "a bare container has no codec to hand threads to"
    );

    // Container over codec: accepted.
    let out = dir.join("b.tar.gz");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--threads",
            "2",
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "a composed write HAS a codec: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    assert!(
        Command::new("gunzip")
            .args(["-t", out.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    // --level likewise reaches the codec layer — and this is asserted on the
    // BYTES, not on exit 0 plus `gunzip -t`, which is what it used to be.
    // Deleting `level: o.level` from the `EncodeOpts` that
    // `entries::create_archive` builds left the old form entirely green: both
    // levels still exited 0 and both still gunzipped. The only evidence that
    // the flag reached the encoder is that the two levels produce DIFFERENT
    // output, so that is what is checked.
    //
    // A payload with real structure, not `notes.txt`'s eight bytes: gzip
    // levels are indistinguishable on input too small or too uniform for the
    // match finder's effort to matter.
    let big = dir.join("big.txt");
    let mut payload = String::new();
    for i in 0..4000 {
        payload.push_str(&format!(
            "line {i} of a log with some repeated shape {}\n",
            i % 97
        ));
    }
    std::fs::write(&big, payload.as_bytes()).unwrap();

    let mut sizes = Vec::new();
    for level in ["1", "9"] {
        let out = dir.join(format!("c{level}.tar.gz"));
        assert!(
            Command::new(STUFFR)
                .args([
                    "pack",
                    big.to_str().unwrap(),
                    "-o",
                    out.to_str().unwrap(),
                    "--level",
                    level,
                ])
                .status()
                .unwrap()
                .success(),
            "--level {level} must be accepted on a composed write"
        );
        assert!(
            Command::new("gunzip")
                .args(["-t", out.to_str().unwrap()])
                .status()
                .unwrap()
                .success(),
            "--level {level} must still produce valid gzip"
        );
        sizes.push(std::fs::metadata(&out).unwrap().len());
    }
    assert!(
        sizes[0] > sizes[1],
        "--level must reach the codec beneath the container: level 1 produced \
         {} bytes and level 9 produced {} — equal sizes mean the flag was \
         accepted and dropped",
        sizes[0],
        sizes[1]
    );

    // And the single-stream codec path is untouched.
    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                src.to_str().unwrap(),
                "-o",
                dir.join("d.gz").to_str().unwrap(),
                "--threads",
                "2",
            ])
            .status()
            .unwrap()
            .success()
    );
}

// ---------------------------------------------------------------------
// Phase 2c: `pack` walks a directory tree, and says what walking it lost.
// ---------------------------------------------------------------------

#[test]
fn pack_walks_a_directory_and_round_trips_it() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir(root.join("empty")).unwrap();
    std::fs::write(root.join("README.md"), b"readme").unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("p.tar");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let back = dir.join("back");
    assert!(
        Command::new(STUFFR)
            .args([
                "unpack",
                out.to_str().unwrap(),
                "-C",
                back.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );

    assert_eq!(
        std::fs::read(back.join("proj/README.md")).unwrap(),
        b"readme"
    );
    assert_eq!(
        std::fs::read(back.join("proj/src/main.rs")).unwrap(),
        b"fn main() {}"
    );
    assert!(
        back.join("proj/empty").is_dir(),
        "an empty directory must survive the round trip"
    );
}

/// A directory INSIDE a codec, in one command — the milestone's own headline
/// (`stuffr pack proj -o backup.tar.gz`), which needs the walk and the
/// composed write together.
#[test]
fn pack_walks_a_directory_into_a_container_inside_a_codec() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("backup.tar.gz");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let back = dir.join("back");
    assert!(
        Command::new(STUFFR)
            .args([
                "unpack",
                out.to_str().unwrap(),
                "-C",
                back.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        std::fs::read(back.join("proj/src/main.rs")).unwrap(),
        b"fn main() {}"
    );
}

#[cfg(unix)]
#[test]
fn pack_stores_a_symlink_inside_a_directory_rather_than_following_it() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink("real.txt", root.join("link.txt")).unwrap();

    let out = dir.join("p.tar");
    assert!(
        Command::new(STUFFR)
            .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    // The system tar must agree it is a link, not a second copy. Its absence
    // panics rather than skipping: the repo's reference-tool convention (see
    // `lzip.rs`'s `require_lzip`) is that failing loudly beats proving
    // nothing, and CI installs tar unconditionally.
    let l = Command::new("tar")
        .args(["tvf", out.to_str().unwrap()])
        .output()
        .expect("the system `tar` is this test's reference authority");
    let text = String::from_utf8_lossy(&l.stdout);
    assert!(
        text.contains("link.txt -> real.txt"),
        "tar tvf said: {text}"
    );
}

/// The opposite rule, and the reason the two must not be unified: a symlink
/// NAMED on the command line is followed, because storing the link itself
/// would let `pack` write an archive `unpack` then refuses at exit 7.
#[cfg(unix)]
#[test]
fn pack_follows_a_symlink_named_on_the_command_line() {
    let dir = tmp_dir();
    std::fs::write(dir.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink("real.txt", dir.join("link.txt")).unwrap();

    let out = dir.join("named.tar");
    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                dir.join("link.txt").to_str().unwrap(),
                "-o",
                out.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );

    let back = dir.join("back");
    assert!(
        Command::new(STUFFR)
            .args([
                "unpack",
                out.to_str().unwrap(),
                "-C",
                back.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        std::fs::read(back.join("link.txt")).unwrap(),
        b"real",
        "a named symlink is followed, so the entry holds the target's bytes"
    );
}

#[test]
fn packing_a_directory_into_a_container_that_cannot_hold_it_warns_rather_than_refusing() {
    // `ar` has no directory concept at all. Refusing would be the tenth
    // instance of this project's signature defect; warning is honest.
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/a.txt"), b"a").unwrap();

    let out = dir.join("p.a");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "must not refuse: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let err = String::from_utf8_lossy(&st.stderr);
    // The DROPPED ENTRY'S NAME, not the word "fidelity". The pack summary
    // line carries a loss count on every successful pack, warnings or none,
    // so an assertion on that word passes against an implementation with the
    // whole warnings vector deleted — which is exactly what it was before
    // this was caught. Naming `proj/sub` is the property this test claims to
    // test.
    assert!(
        err.contains("proj/sub"),
        "it must SAY WHAT it dropped, by name; stderr: {err}"
    );

    // And --strict-fidelity turns that into a refusal, as it does on read.
    let out2 = dir.join("p2.a");
    let st2 = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            out2.to_str().unwrap(),
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st2.status.code(),
        Some(4),
        "strict fidelity must exit 4 on the write side too"
    );
}

/// The flag must not fire on a clean pack. A gate that always trips is a gate
/// nobody leaves on.
///
/// The tree carries a SYMLINK, and that is the case worth pinning rather than
/// an afterthought: `README.md:35` records that `--strict-fidelity` "fails on
/// essentially any tarball containing a symlink" on the READ side, because a
/// symlink's mtime cannot be restored without following the link (`std` has no
/// `lutimes`). The write side has no such limit — tar stores the link, target
/// and all, and loses nothing — so the two sides disagree about the same tree
/// on purpose, and this is the half most likely to be "fixed" into a refusal
/// by someone reading only the README.
#[test]
fn strict_fidelity_passes_on_a_pack_that_lost_nothing() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("main.rs", root.join("src/alias.rs")).unwrap();

    let archive = dir.join("clean.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "an ordinary tree into tar loses nothing, symlink included: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    // And the symlink really is IN there, as a link. Without this the test
    // above would pass just as happily against a walk that dropped it —
    // strict fidelity cannot complain about an entry nobody tried to store.
    #[cfg(unix)]
    {
        let listed = Command::new("tar")
            .args(["tvf", archive.to_str().unwrap()])
            .output()
            .expect("the system `tar` is this test's reference authority");
        let text = String::from_utf8_lossy(&listed.stdout);
        assert!(
            text.contains("alias.rs -> main.rs"),
            "the symlink must be stored as a link, not dropped or copied: {text}"
        );
    }
}

/// The walk names entries beneath the root's own final component, so two
/// directories with the same name collide before anything is written — the
/// same rule two identically-named files have always had.
#[test]
fn two_directories_with_the_same_final_component_are_refused_before_writing() {
    let dir = tmp_dir();
    std::fs::create_dir_all(dir.join("a/proj")).unwrap();
    std::fs::create_dir_all(dir.join("b/proj")).unwrap();
    std::fs::write(dir.join("a/proj/x.txt"), b"x").unwrap();
    std::fs::write(dir.join("b/proj/y.txt"), b"y").unwrap();

    let out = dir.join("dup.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            dir.join("a/proj").to_str().unwrap(),
            dir.join("b/proj").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(2),
        "a name collision is a usage error"
    );
    assert!(
        !out.exists(),
        "nothing may be written: the refusal happens before the destination is opened"
    );
}
/// `stuffr pack . -o x.tar` — the single most common archiving idiom there
/// is, and what `tar cf x.tar .` teaches. `Path::file_name` returns `None`
/// for `.`, which used to make this exit 2 at the naming step, before the
/// walk this phase added ever ran.
#[test]
fn pack_of_dot_names_entries_after_the_directory_it_resolves_to() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("dot.tar");
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args(["pack", ".", "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "`pack .` must work: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("proj/src/main.rs"),
        "`.` resolves to its canonical final component, so entries sit under \
         `proj/` exactly as `pack ../proj` would name them: {text}"
    );
}

/// The same rule one level up. `..` from `proj/src` is `proj`, so the entries
/// are named the same way `pack proj` names them — the final-component rule
/// applied consistently rather than a special case bolted onto `.`.
#[test]
fn pack_of_dotdot_names_entries_after_the_parent_it_resolves_to() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("dotdot.tar");
    let st = Command::new(STUFFR)
        .current_dir(root.join("src"))
        .args(["pack", "..", "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "`pack ..` must work: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("proj/src/main.rs"),
        "`..` must name entries after the directory it resolves to: {text}"
    );
}

/// A trailing slash is noise, and `Path::file_name` already reads `proj/` as
/// `proj`. Pinned anyway: a hand-rolled "split on `/`, take the last" — the
/// obvious way to rewrite this function — yields an EMPTY name here, and an
/// archive of entries named `/src/main.rs` is one stuffr itself refuses to
/// extract at exit 7.
#[test]
fn a_trailing_slash_on_a_packed_directory_is_noise() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("slash.tar");
    let with_slash = format!("{}/", root.to_str().unwrap());
    let st = Command::new(STUFFR)
        .args(["pack", &with_slash, "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "a trailing slash must not change anything: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("proj/src/main.rs"),
        "entries must sit under `proj/`, not under an empty name: {text}"
    );
}

/// `stuffr pack . -o backup.tar` — `examples.txt`'s own headline idiom for
/// the directory walk — writes `backup.tar` INSIDE the directory it is
/// walking. The first run has nothing to exclude (`backup.tar` does not
/// exist until this command creates it), but a `--force` re-run walks a
/// directory that now contains the PREVIOUS run's archive; left unhandled
/// that nests the old archive inside the new one and the file grows on
/// every run. GNU tar's answer to the identical shape is `file is the
/// archive; not dumped`.
#[test]
fn pack_excludes_its_own_output_from_the_walk() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"a").unwrap();

    // First run: `backup.tar` does not exist yet, so there is nothing for
    // the walk to exclude, and the archive holds exactly `a.txt`.
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args(["pack", ".", "-o", "backup.tar"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let out = root.join("backup.tar");
    let first_len = std::fs::metadata(&out).unwrap().len();

    // Second run, `--force`: `backup.tar` now exists INSIDE the directory
    // being walked. If it were not excluded, this would nest the first
    // run's archive inside the second and the file would grow; if it were
    // silently dropped with no warning, `stderr` would say nothing about it.
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args(["pack", ".", "-o", "backup.tar", "--force"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    // The EXCLUDED ENTRY'S NAME, not the word "fidelity" — the pack summary
    // line prints a count on every successful pack regardless, so asserting
    // on the word alone would pass even with the whole reporting deleted.
    let err = String::from_utf8_lossy(&st.stderr);
    assert!(
        err.contains("proj/backup.tar"),
        "it must SAY WHAT it excluded, by name; stderr: {err}"
    );
    let second_len = std::fs::metadata(&out).unwrap().len();
    assert_eq!(
        first_len, second_len,
        "a --force re-run must not nest the previous archive inside the new one"
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        !text.contains("backup.tar"),
        "the archive must not contain an entry naming itself: {text}"
    );
    assert!(
        text.contains("proj/a.txt"),
        "everything else in the directory is still stored: {text}"
    );

    // And a THIRD run, `--force --strict-fidelity`, stays GREEN. This
    // assertion was `Some(4)` until the Phase 2c final review: a fidelity
    // warning means "you lost something you asked for", and stuffr declining
    // to put a file inside itself is not that — it is stuffr being correct.
    // Gating on it made the nightly-backup shape `examples.txt` advertises
    // exit 4 on every run after the first, forever, which is a gate nobody
    // keeps. See `excluding_the_output_from_its_own_walk_is_a_note_not_a_
    // fidelity_loss`, which owns the property; this run only pins that the
    // verdict did not drift back.
    let st3 = Command::new(STUFFR)
        .current_dir(&root)
        .args([
            "pack",
            ".",
            "-o",
            "backup.tar",
            "--force",
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st3.status.code(),
        Some(0),
        "excluding the archive from its own walk costs no fidelity, so the strict \
         gate must not fire on it: {}",
        String::from_utf8_lossy(&st3.stderr)
    );
}

/// The hole the two rulings above left between them, measured through the
/// binary rather than the library.
///
/// Excluding the output from its own walk is right; recasting that exclusion
/// from a fidelity warning to a note is right. Together they meant that when
/// the output was the ONLY thing named, `pack` walked nothing, wrote an empty
/// 1024-byte tar over a healthy one, and `--strict-fidelity` — the strongest
/// gate this tool has — reported it clean at exit 0.
///
/// It is now `Error::Usage`, exit 2, raised while the plan is still being
/// built and before `dst.create` opens anything. That ordering is the whole
/// benefit and is what the byte-identity assertion below pins: a warning
/// would have let the empty archive replace the good one first, which is the
/// actual harm. Exit code alone would not have caught it.
#[test]
fn pack_refuses_when_the_only_input_is_the_output_and_leaves_it_untouched() {
    let dir = tmp_dir();
    let root = dir.join("backups");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("data.txt"), b"last night's data").unwrap();

    // A healthy archive, written the ordinary way.
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args(["pack", "data.txt", "-o", "backup.tar"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let archive = root.join("backup.tar");
    let before = std::fs::read(&archive).unwrap();
    assert!(
        before.len() > 1024,
        "the fixture must be a real archive, not an empty one: {} bytes",
        before.len()
    );

    // The reproduction, verbatim.
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args([
            "pack",
            "backup.tar",
            "-o",
            "backup.tar",
            "--force",
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&st.stderr);
    assert_eq!(
        st.status.code(),
        Some(2),
        "an empty plan is a usage refusal, not a successful empty archive: {err}"
    );
    assert!(
        err.contains("nothing to pack") && err.contains("backup.tar"),
        "the refusal must name the cause and the destination: {err}"
    );

    assert_eq!(
        std::fs::read(&archive).unwrap(),
        before,
        "refusing before the destination is opened means no temp file and no \
         rename, so the existing archive must be byte-identical"
    );
}

/// The same hole one step further in, measured through the binary: the shape
/// the refusal above was written FOR and did not reach.
///
/// A nightly job pointed at the directory its archive lives in. Last night's
/// archive is the directory's only member, the walk correctly leaves it out,
/// and `/backups`'s own directory entry keeps the plan non-empty — so the
/// guard did not fire, and a good archive was replaced by a 1536-byte shell
/// holding one directory entry, at exit 0, with `--strict-fidelity` calling
/// it clean. Measured on `70ca649`:
///
/// ```text
/// $ stuffr pack nb -o nb/nightly.tar --force --strict-fidelity
/// 1 path(s) -> tar (0 -> 1536 bytes, no fidelity loss)
/// stuffr: note: `nb/nightly.tar` is the archive being written …
/// exit=0   contains: nb
/// ```
///
/// The byte-identity assertion is the one that matters: an exit code alone
/// would not distinguish refusing from writing the shell and then complaining.
#[test]
fn pack_refuses_a_nightly_over_a_directory_holding_only_its_own_archive() {
    let dir = tmp_dir();
    let root = dir.join("backups");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(dir.join("data.txt"), b"last night's data").unwrap();

    // A healthy archive of something else, sitting in `backups`.
    let st = Command::new(STUFFR)
        .current_dir(&dir)
        .args(["pack", "data.txt", "-o", "backups/nightly.tar"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let archive = root.join("nightly.tar");
    let before = std::fs::read(&archive).unwrap();

    // Tonight: the job is pointed at the directory instead.
    let st = Command::new(STUFFR)
        .current_dir(&dir)
        .args([
            "pack",
            "backups",
            "-o",
            "backups/nightly.tar",
            "--force",
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&st.stderr);
    assert_eq!(
        st.status.code(),
        Some(2),
        "a plan reduced to the directory the output was removed from is a usage \
         refusal, not an archive of one empty directory: {err}"
    );
    assert!(
        err.contains("No archive was written") && err.contains("is unchanged"),
        "the refusal must say plainly that the destination survives: {err}"
    );
    assert_eq!(
        std::fs::read(&archive).unwrap(),
        before,
        "last night's archive must be byte-identical, not replaced by a shell"
    );
}

/// The read-side half of the same session: `stuffr test` on a zip whose index
/// declares more records than the reader can reach.
///
/// `ZipArchive` collapses central-directory records that share a name, so a
/// real 8-record archive that `unzip -t` reads whole enumerated 6 entries and
/// reported "exact fidelity" at exit 0 — under `--strict-fidelity`, the
/// strongest gate this tool has. The fixture is built here rather than
/// depending on that file, and `zip` itself will not write this shape, so the
/// central directory is forged: a verbatim copy of the first record appended
/// to the index, with the declared count bumped to match.
#[test]
fn test_reports_a_zip_whose_index_declares_more_records_than_are_reachable() {
    let dir = tmp_dir();
    let src = dir.join("a.txt");
    std::fs::write(&src, b"alpha").unwrap();
    let zip_path = dir.join("dup.zip");
    let st = Command::new(STUFFR)
        .current_dir(&dir)
        .args(["pack", "a.txt", "-o", "dup.zip"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    // A clean archive must gain nothing, or the assertions below prove only
    // that `test` prints warnings.
    let st = Command::new(STUFFR)
        .args(["test", zip_path.to_str().unwrap(), "--strict-fidelity"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&st.stderr);
    assert_eq!(st.status.code(), Some(0), "a clean zip is clean: {err}");
    assert!(err.contains("exact fidelity"), "and still says so: {err}");

    // Forge a second central-directory record naming the same entry.
    let mut bytes = std::fs::read(&zip_path).unwrap();
    let eocd = bytes.len() - 22;
    assert_eq!(&bytes[eocd..eocd + 4], b"PK\x05\x06", "no EOCD");
    let le16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let cd_size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
    let cd_at = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let cd = bytes[cd_at..cd_at + cd_size].to_vec();
    let first = 46 + le16(&cd[28..]) as usize + le16(&cd[30..]) as usize + le16(&cd[32..]) as usize;
    let entries = le16(&bytes[eocd + 10..]);

    let mut out = bytes[..cd_at + cd_size].to_vec();
    out.extend_from_slice(&cd[..first]);
    let tail = &mut bytes[eocd..];
    tail[8..10].copy_from_slice(&(entries + 1).to_le_bytes());
    tail[10..12].copy_from_slice(&(entries + 1).to_le_bytes());
    tail[12..16].copy_from_slice(&((cd_size + first) as u32).to_le_bytes());
    out.extend_from_slice(tail);
    let forged = dir.join("shadowed.zip");
    std::fs::write(&forged, &out).unwrap();

    let st = Command::new(STUFFR)
        .args(["test", forged.to_str().unwrap()])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&st.stderr);
    assert_eq!(
        st.status.code(),
        Some(0),
        "a shadowed record is a fidelity loss, not corruption: {err}"
    );
    assert!(
        err.contains("declares 2") && err.contains("only 1"),
        "the warning must name both counts: {err}"
    );
    assert!(
        !err.contains("exact fidelity"),
        "a read that reached one of two records must not announce exact \
         fidelity: {err}"
    );

    let st = Command::new(STUFFR)
        .args(["test", forged.to_str().unwrap(), "--strict-fidelity"])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(4),
        "--strict-fidelity must refuse it: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}

// ---------------------------------------------------------------------------
// Phase 2c, Task 6: the properties that would otherwise pass while being
// structurally unable to fail.
// ---------------------------------------------------------------------------

/// Locates `bin` on `PATH`.
///
/// A local copy rather than a shared helper, matching this tree's existing
/// convention: `ar.rs`, `cpio.rs`, `zip.rs` and `zip_on_a_pipe.rs` each carry
/// their own. That four-copy situation was examined in Phase 2 and accepted
/// deliberately; extracting a shared test helper is a tree-wide refactor, not
/// something to smuggle into a testing task.
fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(bin);
        candidate.is_file().then_some(candidate)
    })
}

/// Locates `bin` on `PATH`, panicking rather than silently skipping if it is
/// absent. CI installs every tool named here (`tar` and `ar` ship with the
/// image; `.github/workflows/ci.yml` installs `cpio`, `zip` and `unzip` on all
/// three test jobs), so an absence means only a contributor's own machine
/// lacks it — and a silent `return` would report a cross-implementation test
/// as PASSING having verified nothing at all.
fn require_bin(bin: &str) -> PathBuf {
    which(bin).unwrap_or_else(|| {
        panic!(
            "no reference `{bin}` tool found on PATH — this test proved nothing, which is \
             worth knowing rather than passing silently"
        )
    })
}

/// The permission bits only. The file-type bits are not what any container
/// carries in its mode field, and comparing them would fail on the kind rather
/// than on the permissions.
#[cfg(unix)]
fn perm_bits(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o7777
}

/// A tree fixture whose every distinguishable fact is one a container is
/// expected to carry: a nested directory, an EMPTY directory (which only a
/// directory entry can preserve), a symlink, and two files with DIFFERENT
/// modes.
///
/// Every mode is `0o600`/`0o700` deliberately: extraction tools mask restored
/// permissions with the process umask, so a fixture using `0o644`/`0o755`
/// compares equal under umask 022 and unequal under umask 077. These two have
/// no bits any umask can clear, which makes the comparison umask-independent
/// rather than passing on this machine's umask alone.
#[cfg(unix)]
fn build_reference_tree(root: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::create_dir(root.join("empty")).unwrap();
    std::fs::write(root.join("a.txt"), b"alpha").unwrap();
    std::fs::write(root.join("sub/b.bin"), b"\x00\xff\x00beta").unwrap();
    std::os::unix::fs::symlink("a.txt", root.join("link")).unwrap();
    for (p, mode) in [
        (root.to_path_buf(), 0o700),
        (root.join("sub"), 0o700),
        (root.join("empty"), 0o700),
        (root.join("a.txt"), 0o600),
        (root.join("sub/b.bin"), 0o600),
    ] {
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// Everything under `root`, relative, sorted: name, kind, mode, and the file's
/// own bytes or the link's own target.
///
/// NOT just names — the whole point of the cross-implementation property is
/// that two tools agree about the CONTENTS of a tree, and a comparison of
/// names alone passes against an extractor that produced empty files with the
/// wrong modes.
///
/// A symlink's mode is deliberately omitted: `std` cannot restore one (no
/// `lchmod`), which is the same limitation `README.md` records for mtime, and
/// every tool here leaves it at the platform default.
#[cfg(unix)]
fn tree_snapshot(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().display().to_string();
            let md = std::fs::symlink_metadata(&path).unwrap();
            if md.is_symlink() {
                out.push(format!(
                    "{rel}: symlink -> {}",
                    std::fs::read_link(&path).unwrap().display()
                ));
            } else if md.is_dir() {
                out.push(format!("{rel}: dir mode {:o}", perm_bits(&md)));
                stack.push(path);
            } else {
                out.push(format!(
                    "{rel}: file mode {:o} bytes {:?}",
                    perm_bits(&md),
                    std::fs::read(&path).unwrap()
                ));
            }
        }
    }
    out.sort();
    out
}

/// Runs a reference tool, with `COPYFILE_DISABLE=1` set unconditionally.
///
/// That variable is macOS's: bsdtar stores every file's extended attributes as
/// a companion `._name` AppleDouble entry, and macOS puts a
/// `com.apple.provenance` xattr on ordinary files, so a tree written by the
/// system tar comes back with a `._` sibling for every entry and the
/// comparison below fails for a reason that has nothing to do with stuffr.
/// Linux's tar ignores the variable, so setting it always costs nothing and
/// keeps the two platforms running the same command.
fn run_tool(bin: &Path, args: &[&std::ffi::OsStr], cwd: &Path, stdin: &[u8]) -> Vec<u8> {
    let mut child = Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .env("COPYFILE_DISABLE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "reference tool {} {:?} failed: {}",
        bin.display(),
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// `OsStr` borrow, so `run_tool`'s argument list can mix `&str` and `&Path`.
fn os(s: &impl AsRef<std::ffi::OsStr>) -> &std::ffi::OsStr {
    s.as_ref()
}

fn pack_ok(args: &[&std::ffi::OsStr]) -> String {
    let out = Command::new(STUFFR)
        .arg("pack")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stuffr pack {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn unpack_ok(archive: &Path, dest: &Path) {
    let out = Command::new(STUFFR)
        .args([
            std::ffi::OsStr::new("unpack"),
            archive.as_ref(),
            std::ffi::OsStr::new("-C"),
            dest.as_ref(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stuffr unpack {} failed: {}",
        archive.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Property 1 — cross-implementation, BOTH directions, per container.
///
/// "The system tool reads what we write" and "we read what it writes" are
/// different claims; Phase 2's tar work proved it. Reference tools are
/// required, never skipped: a silent skip proves nothing.
///
/// Compared as whole TREES — names, contents, modes and symlink targets — and
/// through the CLI, which is what makes this new coverage rather than a second
/// copy of `tar.rs`'s and `ar.rs`'s own byte-level cross-implementation tests:
/// those build archives in memory and never walk a directory.
///
/// `ar` gets its documented DEGRADATION asserted instead of a faithful round
/// trip, because it has no directory and no symlink entries. `cpio` (newc) is
/// in the faithful group on measurement, not on assumption: it carries
/// directories, symlinks and modes, and both directions are checked below.
#[cfg(unix)]
#[test]
fn every_container_round_trips_a_tree_against_its_reference_tool() {
    let tar_bin = require_bin("tar");
    let zip_bin = require_bin("zip");
    let unzip_bin = require_bin("unzip");
    let cpio_bin = require_bin("cpio");
    let ar_bin = require_bin("ar");

    let dir = tmp_dir();
    let tree = dir.join("tree");
    let root = tree.join("proj");
    build_reference_tree(&root);
    let want = tree_snapshot(&root);

    // The fixture itself, asserted rather than assumed: every comparison below
    // is only as strong as what the tree actually contains, and a fixture that
    // silently lost its symlink would make four of the eight comparisons
    // prove nothing.
    assert_eq!(
        want,
        vec![
            "a.txt: file mode 600 bytes [97, 108, 112, 104, 97]".to_string(),
            "empty: dir mode 700".to_string(),
            "link: symlink -> a.txt".to_string(),
            "sub/b.bin: file mode 600 bytes [0, 255, 0, 98, 101, 116, 97]".to_string(),
            "sub: dir mode 700".to_string(),
        ],
        "the fixture must carry a nested dir, an EMPTY dir, a symlink and two \
         differently-named files, or the comparisons below prove less than they claim"
    );

    // ---- tar: stuffr writes, the system tar reads ----
    let out_tar = dir.join("out.tar");
    pack_ok(&[os(&root), os(&"-o"), os(&out_tar)]);
    let back = dir.join("back-tar");
    std::fs::create_dir(&back).unwrap();
    run_tool(
        &tar_bin,
        &[os(&"-xf"), os(&out_tar), os(&"-C"), os(&back)],
        &dir,
        b"",
    );
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "the system tar read our tar back as a different tree"
    );

    // ---- tar: the system tar writes, stuffr reads ----
    let ref_tar = dir.join("ref.tar");
    run_tool(
        &tar_bin,
        &[os(&"-cf"), os(&ref_tar), os(&"proj")],
        &tree,
        b"",
    );
    let back = dir.join("back-ref-tar");
    unpack_ok(&ref_tar, &back);
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "we read a tar the system tar wrote as a different tree"
    );

    // ---- zip: stuffr writes, unzip reads ----
    let out_zip = dir.join("out.zip");
    pack_ok(&[os(&root), os(&"-o"), os(&out_zip)]);
    let back = dir.join("back-zip");
    run_tool(
        &unzip_bin,
        &[os(&"-q"), os(&out_zip), os(&"-d"), os(&back)],
        &dir,
        b"",
    );
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "unzip read our zip back as a different tree"
    );

    // ---- zip: the system zip writes, stuffr reads ----
    // `-y` stores symlinks as symlinks rather than following them; without it
    // the reverse direction would compare a copy of `a.txt` against a link and
    // fail for the fixture's reason rather than ours.
    let ref_zip = dir.join("ref.zip");
    run_tool(
        &zip_bin,
        &[os(&"-qry"), os(&ref_zip), os(&"proj")],
        &tree,
        b"",
    );
    let back = dir.join("back-ref-zip");
    unpack_ok(&ref_zip, &back);
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "we read a zip the system zip wrote as a different tree"
    );

    // ---- cpio: stuffr writes, the system cpio reads ----
    //
    // This direction is PLATFORM-DEPENDENT in what it can prove, and that is
    // not fixable from here. `newc` records an entry's kind only in its mode
    // field's `S_IFMT` bits; GNU cpio 2.15 refuses an entry carrying none
    // with `unknown file type`, skips it and exits 0 anyway, while bsdcpio
    // (libarchive — what macOS ships as `cpio`) infers a regular file and
    // extracts the archive whole. So when `require_bin("cpio")` resolves to
    // GNU cpio this comparison catches a missing `S_IFREG`, and when it
    // resolves to bsdcpio it cannot: the tree comes back identical either
    // way. That is exactly how the 0.2.0 defect survived a phase of
    // macOS-only review, red on CI's Linux runners at the first push.
    //
    // Preferring a GNU cpio is not a portable fix either — Homebrew's is
    // keg-only and not on PATH under any name. The portable proof lives
    // where the format knowledge is, as a byte-level assertion on the header
    // this test cannot see: `cpio.rs`'s
    // `a_permission_only_file_mode_gains_the_regular_file_type_bits`. What
    // remains valuable HERE is the other direction and the whole-tree
    // comparison against whichever real tool is installed.
    let out_cpio = dir.join("out.cpio");
    pack_ok(&[os(&root), os(&"-o"), os(&out_cpio)]);
    let back = dir.join("back-cpio");
    std::fs::create_dir(&back).unwrap();
    run_tool(
        &cpio_bin,
        &[os(&"-i"), os(&"-d"), os(&"--quiet")],
        &back,
        &std::fs::read(&out_cpio).unwrap(),
    );
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "the system cpio read our cpio back as a different tree"
    );

    // ---- cpio: the system cpio writes, stuffr reads ----
    // The name list comes from this test rather than from `find`, so no shell
    // and no second traversal implementation is involved.
    let names = b"proj\nproj/a.txt\nproj/empty\nproj/link\nproj/sub\nproj/sub/b.bin\n";
    let ref_cpio_bytes = run_tool(
        &cpio_bin,
        &[os(&"-o"), os(&"--format=newc"), os(&"--quiet")],
        &tree,
        names,
    );
    let ref_cpio = dir.join("ref.cpio");
    std::fs::write(&ref_cpio, &ref_cpio_bytes).unwrap();
    let back = dir.join("back-ref-cpio");
    unpack_ok(&ref_cpio, &back);
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "we read a cpio the system cpio wrote as a different tree"
    );

    // ---- ar: the documented degradation, both directions ----
    //
    // `ar` has no directory and no symlink entries at all, so a faithful tree
    // round trip is not the property — what it must do is store the regular
    // files, drop the rest, and SAY SO. Asserted against the system `ar`'s own
    // listing, not against our reader.
    //
    // The member NAMES below are platform-dependent in the same way the cpio
    // comparison above is, and for a sibling reason. In the GNU variant a
    // short name is stored with `/` as its terminator, so GNU `ar` truncates
    // an inline `proj/a.txt` to `proj` — and `proj/sub/b.bin` to `proj` as
    // well, two members with one name. macOS's `ar` reads the 16-byte field
    // whole and cannot see it. `ar.rs`'s `write_safe_identifier` forces any
    // `/`-bearing name into the BSD extended form, which BOTH tools read back
    // verbatim (measured against GNU ar 2.47 and BSD ar), so the expectation
    // below is true of either. The portable proof that it stays that way is
    // `ar.rs`'s `a_name_containing_a_slash_is_never_stored_inline`.
    let out_ar = dir.join("out.a");
    let stderr = pack_ok(&[os(&root), os(&"-o"), os(&out_ar)]);
    for dropped in ["proj/empty", "proj/link", "proj/sub"] {
        assert!(
            stderr.contains(dropped),
            "`ar` dropping `{dropped}` must be named in the fidelity report; stderr: {stderr}"
        );
    }
    let listed = run_tool(&ar_bin, &[os(&"t"), os(&out_ar)], &dir, b"");
    let mut members: Vec<String> = String::from_utf8_lossy(&listed)
        .lines()
        .map(str::to_string)
        .collect();
    members.sort();
    assert_eq!(
        members,
        vec!["proj/a.txt".to_string(), "proj/sub/b.bin".to_string()],
        "the system ar must list exactly the regular files, and nothing standing in for \
         the directories or the symlink"
    );

    // And the other direction. `rcS` rather than `rc`: macOS's `ar` runs a
    // ranlib-style index over plain files by default and then silently emits
    // an archive holding ONLY an empty `__.SYMDEF SORTED` — measured, and
    // already documented in `ar.rs`'s own `we_accept_what_system_ar_writes`.
    let ref_ar = dir.join("ref.a");
    run_tool(
        &ar_bin,
        &[os(&"rcS"), os(&ref_ar), os(&"a.txt")],
        &root,
        b"",
    );
    let back = dir.join("back-ref-ar");
    unpack_ok(&ref_ar, &back);
    assert_eq!(
        std::fs::read(back.join("a.txt")).unwrap(),
        b"alpha",
        "we read an ar the system ar wrote as different bytes"
    );
}

/// Property 2 — the same tree packed twice is byte-identical, AND the entries
/// are in sorted order.
///
/// The two halves are not the same claim, and the second is the one that
/// needed adding. Byte-identity alone asserts DETERMINISM, not ordering:
/// `read_dir` is stable within a filesystem, so deleting the sort in
/// `walk.rs` entirely leaves two consecutive packs byte-identical and this
/// property green — measured, by deleting it (see `walk.rs`'s own
/// `each_directory_level_is_sorted_regardless_of_readdir_order`, which exists
/// for exactly this reason). So the archive's own entry ORDER is asserted
/// here too, against a fixture created in reverse-alphabetical order so that
/// readdir order and sorted order provably differ.
///
/// Byte-identity is still worth its half: it is what pins the composed
/// container-inside-codec path, where a codec could introduce a timestamp of
/// its own.
#[test]
fn packing_the_same_tree_twice_produces_identical_bytes() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("b")).unwrap();
    // Created in reverse-alphabetical order, so a filesystem that hands back
    // creation order (tmpfs, ext4 for a small directory) is provably not
    // handing back sorted order. The premise is asserted below rather than
    // assumed, because a filesystem that DID sort would make the ordering
    // half of this test unable to fail.
    for n in ["z.txt", "m.txt", "a.txt"] {
        std::fs::write(root.join(n), n.as_bytes()).unwrap();
    }
    std::fs::write(root.join("b/inner.txt"), b"inner").unwrap();

    let readdir_order: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    let mut sorted = readdir_order.clone();
    sorted.sort();
    assert_ne!(
        readdir_order, sorted,
        "this filesystem hands back directory entries already sorted, so the ordering \
         assertion below could not fail; the fixture needs a name order this filesystem \
         does not reproduce"
    );

    let listing = dir.join("order.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            listing.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let listed = run_output(&["list", listing.to_str().unwrap()]);
    let names: Vec<String> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(|l| l.split_whitespace().last().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "proj",
            "proj/a.txt",
            "proj/b",
            "proj/b/inner.txt",
            "proj/m.txt",
            "proj/z.txt",
        ],
        "entries must be written in sorted, depth-first order — `readdir` order was {readdir_order:?}"
    );

    for ext in ["tar", "tar.gz", "zip"] {
        let one = dir.join(format!("one.{ext}"));
        let two = dir.join(format!("two.{ext}"));
        for out in [&one, &two] {
            let st = Command::new(STUFFR)
                .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(
                st.status.success(),
                "stderr: {}",
                String::from_utf8_lossy(&st.stderr)
            );
        }
        assert_eq!(
            std::fs::read(&one).unwrap(),
            std::fs::read(&two).unwrap(),
            "the same tree must pack to the same `.{ext}` bytes; readdir order is not stable"
        );
    }
}

/// Property 3 — a failed write must leave the destination unpublished, and
/// must not take an existing archive at that path down with it.
///
/// The point of the outcome temp-then-rename, and of finishing the whole chain
/// BEFORE `publish`. Two failures, at the two points a pack can fail:
///
/// 1. AFTER the destination is opened, from inside the write loop, with
///    earlier entries already in the temp file — the only state `discard`
///    exists to clean up.
/// 2. BEFORE it is opened at all — a destination directory that cannot be
///    written, which fails in `Output::create`.
///
/// Only (1) exercises the `discard` arm, and the distinction is not
/// theoretical: the read-only-directory mechanism used for (1) in the first
/// round looked obviously correct and failed inside `Output::create`, before
/// `finish` existed at all, so `discard` was structurally unreachable and the
/// property tested nothing. That is why (1) is now driven by a container
/// REFUSING an entry the destination has already begun to hold, and why the
/// report records the `discard(finish)` -> `publish(finish)` mutation that
/// proves this one does reach it.
///
/// The refusal is cpio's 4 GiB `u32` size field, reached with a SPARSE file:
/// `check_u32_size` runs "before a single byte is read or allocated" (its own
/// comment), so this costs no disk and no time. Every other candidate needs a
/// race — a file truncated between the walk's `stat` and the write would do
/// it, but nothing outside the process can schedule that window, and a test
/// that only fails when it loses a race is worse than no test.
///
/// **This test is therefore coupled to that ordering**, which is the sort of
/// coupling a later refactor breaks without noticing: if `CpioWrite::add`
/// ever stops checking the DECLARED size and checks only the buffered one,
/// this test starts reading 4 GiB off a sparse file before it fails — slow
/// enough to look like a hang, and on a filesystem without sparse support it
/// would not run at all. `cpio.rs` carries the matching note at the check.
/// Anything that moves it needs a new mechanism for reaching a mid-write
/// failure cheaply, not a faster machine.
#[cfg(unix)]
#[test]
fn a_failed_write_never_replaces_an_existing_archive() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir(&root).unwrap();
    // Sorted first, so it is written into the temp file BEFORE the entry that
    // fails — without an entry already written, `discard` would have nothing
    // to clean up and this property would be about `create` again.
    std::fs::write(root.join("a.txt"), b"alpha").unwrap();

    let big = root.join("zbig.bin");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(u64::from(u32::MAX) + 1).unwrap();
    drop(f);
    let md = std::fs::metadata(&big).unwrap();
    assert!(
        md.len() > u64::from(u32::MAX),
        "the premise: the entry must exceed cpio's u32 size field"
    );
    assert!(
        md.blocks() * 512 < md.len(),
        "this filesystem did not make the fixture sparse ({} blocks for {} bytes); a \
         non-sparse one would write 4 GiB to disk here",
        md.blocks(),
        md.len()
    );

    let out = dir.join("existing.cpio");
    std::fs::write(&out, b"PRECIOUS EXISTING CONTENT").unwrap();

    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(3),
        "an entry this container cannot express is a capability limit, exit 3; stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    assert_eq!(
        std::fs::read(&out).unwrap(),
        b"PRECIOUS EXISTING CONTENT",
        "a pack that failed mid-write must not have replaced the archive already there"
    );
    // Nothing half-written left behind either: the destination directory holds
    // exactly what it held before, plus nothing.
    let mut siblings: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    siblings.sort();
    assert_eq!(
        siblings,
        vec!["existing.cpio".to_string(), "proj".to_string()],
        "a failed pack must leave no temp file behind"
    );

    // The second failure point: the destination cannot be created at all.
    let ro = dir.join("readonly");
    std::fs::create_dir(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        std::fs::File::create(ro.join("probe")).is_err(),
        "this test needs a non-root user; the read-only directory is still writable"
    );
    let target = ro.join("out.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.join("a.txt").to_str().unwrap(),
            "-o",
            target.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(1),
        "a destination that cannot be created is an i/o failure, exit 1; stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    assert!(!target.exists(), "a failed pack must publish nothing");

    // Restored before the harness's own cleanup walks the tree.
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// An unreadable FILE is a warning, not a failure — the ruling that makes the
/// walk consistent with itself.
///
/// `walk.rs`'s `descend` already skips a directory it cannot list, on the
/// stated grounds that "backing up a home directory with one root-owned
/// subdirectory in it is the ordinary case", and R9 chose skip-plus-warning
/// for the analogous case. An unreadable file was never ruled on and, until
/// this, propagated with a bare `?`: one unreadable file in a home directory
/// aborted `stuffr pack ~ -o backup.tar` and produced nothing at all.
///
/// Skipping is not silent. The entry is named, and `--strict-fidelity` turns
/// it into exit 4, the same as every other loss.
#[cfg(unix)]
#[test]
fn an_unreadable_file_is_skipped_with_a_warning_rather_than_failing_the_pack() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"alpha").unwrap();
    let unreadable = root.join("secret.txt");
    std::fs::write(&unreadable, b"beta").unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Loud rather than skipped: running as root makes the file readable, and
    // this test would then pass having proved nothing at all.
    assert!(
        std::fs::File::open(&unreadable).is_err(),
        "this test needs a non-root user; the unreadable file is still readable"
    );

    let out = dir.join("backup.tar");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "one unreadable file must not lose the whole backup: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let stderr = String::from_utf8_lossy(&st.stderr);
    // The entry's NAME, not the word "fidelity": the pack summary carries a
    // loss count on every successful pack, warnings or none, so asserting on
    // that word would pass with the whole warnings vector gone.
    assert!(
        stderr.contains("proj/secret.txt"),
        "it must SAY WHAT it skipped, by name; stderr: {stderr}"
    );

    // And the rest of the tree really is in there.
    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(text.contains("proj/a.txt"), "{text}");
    assert!(
        !text.contains("secret.txt"),
        "an entry that could not be read must not be written as an empty one: {text}"
    );

    // Strict fidelity is what turns the loss into a refusal.
    let strict = dir.join("strict.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            strict.to_str().unwrap(),
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(4),
        "strict fidelity must refuse a pack that skipped a file; stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600)).unwrap();
}

// ---------------------------------------------------------------------------
// The collapsed-indentation guard, enumerated structurally.
// ---------------------------------------------------------------------------

/// Every `.rs` file under the workspace's `crates/*/src/`.
///
/// Discovered by walking, not listed: a message added by a future task in a
/// file that does not exist yet is exactly the case the hardcoded version of
/// this guard could not cover.
///
/// `CARGO_MANIFEST_DIR` bakes an absolute path at compile time, the same
/// hazard `CARGO_BIN_EXE_stuffr` already carries at the top of this file — if
/// the repository is moved, `cargo clean -p stuffr-cli` is the fix for both
/// (see `CLAUDE.md`).
fn workspace_source_files() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = std::fs::read_dir(crates)
        .unwrap()
        .map(|e| e.unwrap().path().join("src"))
        .filter(|p| p.is_dir())
        .collect();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Every Rust string literal in `src`, as the compiler will see it: `\` at
/// end of line strips the newline AND the next line's leading whitespace, so a
/// literal written with that continuation contains no indentation at all,
/// while one that lost its `\` carries the indentation into the message.
///
/// Comments, char literals and lifetimes are skipped so that a `"` inside one
/// cannot desynchronise the scan. Raw strings are included: they cannot use
/// `\`-continuation, so a multi-line one carries its indentation too.
fn rust_string_literals(src: &str) -> Vec<(usize, String)> {
    let c: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;
    while i < c.len() {
        if c[i] == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c[i] == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c[i] == '/' && c.get(i + 1) == Some(&'*') {
            let mut depth = 1usize;
            i += 2;
            while i < c.len() && depth > 0 {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if c[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            continue;
        }
        // A char literal (`'a'`, `'\''`, `'"'`) or a lifetime (`'a`). Telling
        // them apart matters: treating `'"'` as a lifetime would leave the
        // scan inside a string it never entered.
        if c[i] == '\'' {
            if c.get(i + 1) == Some(&'\\') {
                let mut j = i + 2;
                while j < c.len() && c[j] != '\'' {
                    j += 1;
                }
                i = j + 1;
                continue;
            }
            if c.get(i + 2) == Some(&'\'') {
                i += 3;
                continue;
            }
            i += 1;
            continue;
        }
        // A raw string, optionally byte: `r"…"`, `r#"…"#`, `br##"…"##`.
        let ident_before = i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_');
        if (c[i] == 'r' || c[i] == 'b') && !ident_before {
            let mut j = i;
            if c[j] == 'b' {
                j += 1;
            }
            if c.get(j) == Some(&'r') {
                j += 1;
                let mut hashes = 0usize;
                while c.get(j) == Some(&'#') {
                    hashes += 1;
                    j += 1;
                }
                if c.get(j) == Some(&'"') {
                    let start_line = line;
                    j += 1;
                    let mut text = String::new();
                    loop {
                        if j >= c.len() {
                            break;
                        }
                        if c[j] == '"' && c[j + 1..].iter().take(hashes).all(|h| *h == '#') {
                            j += 1 + hashes;
                            break;
                        }
                        if c[j] == '\n' {
                            line += 1;
                        }
                        text.push(c[j]);
                        j += 1;
                    }
                    out.push((start_line, text));
                    i = j;
                    continue;
                }
            }
        }
        if c[i] == '"' {
            let start_line = line;
            let mut text = String::new();
            let mut j = i + 1;
            while j < c.len() && c[j] != '"' {
                if c[j] == '\\' && c.get(j + 1) == Some(&'\n') {
                    // The continuation rustc applies, and the whole reason a
                    // correctly-written message carries no indentation.
                    line += 1;
                    j += 2;
                    while matches!(c.get(j), Some(' ' | '\t' | '\r' | '\n')) {
                        if c[j] == '\n' {
                            line += 1;
                        }
                        j += 1;
                    }
                    continue;
                }
                if c[j] == '\\' {
                    text.push(c[j]);
                    if let Some(&e) = c.get(j + 1) {
                        text.push(e);
                    }
                    j += 2;
                    continue;
                }
                if c[j] == '\n' {
                    line += 1;
                }
                text.push(c[j]);
                j += 1;
            }
            out.push((start_line, text));
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// The byte offset of the first run of three or more spaces in `text`, if any.
fn first_space_run(text: &str) -> Option<usize> {
    text.as_bytes().windows(3).position(|w| w == b"   ")
}

/// Whether a run of spaces is a deliberate COLUMN, not a collapsed
/// continuation: everything before it on its own line is a ONE-WORD label
/// ending in a colon, which is `stuffr info`'s output shape (`format:   gzip`)
/// and the `/proc/meminfo` fixture's (`MemAvailable:    1048576 kB`).
///
/// Anything else — the historical defect's `` (`-o bundle.tar`, `` — is prose,
/// and prose never needs three spaces in a row.
///
/// The single-word rule is load-bearing, not tidiness. An earlier version
/// allowed any label of alphanumerics and SPACES, which exempted a whole prose
/// clause that happened to end in a colon —
/// `"stuffr cannot do this:                    try force"` passed it — and
/// messages in this tree routinely end a clause with a colon before a list.
/// One word still admits all seven exemptions the workspace actually has
/// (`format:`, `chain:`, `rung:`, `size:` twice, `memory:`, `MemTotal:`).
fn is_column_label(prefix: &str) -> bool {
    let tail = prefix
        .rsplit('\n')
        .next()
        .unwrap_or(prefix)
        .rsplit("\\n")
        .next()
        .unwrap_or(prefix);
    match tail.strip_suffix(':') {
        Some(label) => {
            !label.is_empty()
                && !label.contains(' ')
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        }
        None => false,
    }
}

/// Phase 2's final review found three multi-line literals in `main.rs`
/// collapsed with their continuation indentation left in, so users saw runs of
/// 22-30 spaces mid-sentence:
///
/// ```text
/// stuffr: usage error: packing 2 paths needs an output naming a container
/// (`-o bundle.tar`,                      or --format tar); a codec …
/// ```
///
/// The guard written then enumerated three hardcoded invocations, and in Phase
/// 2c it failed to catch the identical defect recurring, because the new
/// message was not one of its three. This is the same guard enumerated from
/// something a future task cannot escape: every string literal in every
/// source file of every crate, discovered by walking the tree, whether or not
/// any test ever reaches the code that prints it.
///
/// The mechanism is the one that produced the defect twice: a heredoc (or any
/// other editor) eating the `\` that ends a continued line leaves the next
/// line's indentation INSIDE the literal, and `cargo fmt` then folds the whole
/// thing onto one line. Neither the compiler nor the gate sees anything wrong;
/// only running the binary does.
#[test]
fn no_message_literal_in_the_workspace_carries_a_run_of_collapsed_indentation() {
    // The scanner is tested before it is trusted. Without this, a scanner that
    // silently found no literals at all would report the whole workspace
    // clean — the exact shape of defect this test exists to catch.
    let defective = "fn f() { err(\"packing paths needs a container (`-o bundle.tar`,                      or --format tar)\"); }";
    let found = rust_string_literals(defective);
    assert_eq!(
        found.len(),
        1,
        "the scanner must find the literal: {found:?}"
    );
    assert!(
        first_space_run(&found[0].1).is_some_and(|at| !is_column_label(&found[0].1[..at])),
        "the scanner must flag the historical defect: {:?}",
        found[0].1
    );

    let continued = "fn f() { err(\"packing paths needs a container \\\n                     (`-o bundle.tar`, or --format tar)\"); }";
    let found = rust_string_literals(continued);
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].1, "packing paths needs a container (`-o bundle.tar`, or --format tar)",
        "a `\\`-continued literal carries no indentation, and the scanner must apply that \
         rule rather than report the source text"
    );
    assert!(first_space_run(&found[0].1).is_none());

    let aligned = "fn f() { println!(\"format:   {}\", x); }";
    let found = rust_string_literals(aligned);
    let at = first_space_run(&found[0].1).expect("the column really is three spaces");
    assert!(
        is_column_label(&found[0].1[..at]),
        "a deliberate column label must not be reported as a collapse"
    );

    // The exemption must not widen back into prose. A whole clause ending in a
    // colon is the historical defect verbatim — messages here routinely end a
    // clause with a colon before a list — and an exemption that allowed spaces
    // in the label let exactly this through.
    let colon_prose = "fn f() { err(\"stuffr cannot do this:                    try force\"); }";
    let found = rust_string_literals(colon_prose);
    assert_eq!(found.len(), 1);
    let at = first_space_run(&found[0].1).expect("the run is there");
    assert!(
        !is_column_label(&found[0].1[..at]),
        "a prose clause ending in a colon is not a column label: {:?}",
        found[0].1
    );

    // The two shapes either side of the one-word rule, so its boundary is
    // pinned rather than incidental.
    assert!(is_column_label("MemAvailable:"));
    assert!(!is_column_label("two words:"));

    let quoted_char = "fn f() { let q = '\"'; err(\"a   collapse\"); }";
    let found = rust_string_literals(quoted_char);
    assert_eq!(
        found.iter().map(|(_, t)| t.as_str()).collect::<Vec<_>>(),
        vec!["a   collapse"],
        "a `\"` inside a char literal must not desynchronise the scan"
    );

    // And now the workspace itself.
    let files = workspace_source_files();
    assert!(
        files.len() > 20,
        "the walk found only {} source files, which is not this workspace: {files:?}",
        files.len()
    );
    assert!(
        files.iter().any(|p| p.ends_with("stuffr-cli/src/main.rs")),
        "the walk must reach the crate every user-facing message is printed from"
    );

    let mut scanned = 0usize;
    let mut offenders = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file).unwrap();
        for (line, text) in rust_string_literals(&src) {
            scanned += 1;
            let Some(at) = first_space_run(&text) else {
                continue;
            };
            if is_column_label(&text[..at]) {
                continue;
            }
            offenders.push(format!("{}:{line}: {text:?}", file.display()));
        }
    }
    assert!(
        scanned > 1000,
        "only {scanned} literals scanned, which is not this workspace"
    );
    assert!(
        offenders.is_empty(),
        "a string literal carries a run of three or more spaces, which reaches the user as \
         collapsed continuation indentation mid-sentence. Re-join the sentence and end each \
         continued line with `\\` (which strips the newline AND the next line's indentation); \
         a deliberate column is written `label:   value`. Offenders:\n{}",
        offenders.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Three branches of `entries.rs` that were verified by reading, not by test.
// ---------------------------------------------------------------------------

/// `/` has no final component to name an entry after, and the refusal is a
/// usage error — not an `Io` error, and not an archive named `/`, which
/// `unpack` would then refuse at exit 7.
#[test]
fn packing_the_filesystem_root_is_a_usage_error_that_says_why() {
    let dir = tmp_dir();
    let out = dir.join("root.tar");
    let st = Command::new(STUFFR)
        .args(["pack", "/", "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(2),
        "packing `/` is the caller's mistake, not an i/o failure; stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let stderr = String::from_utf8_lossy(&st.stderr);
    assert!(
        stderr.contains("no final path component"),
        "the message must say what is wrong with `/`: {stderr}"
    );
    assert!(
        !out.exists(),
        "the refusal happens before the destination is opened"
    );
}

/// A path ending in `..` that does not exist fails as the `Io` error it is
/// (exit 1), not as a naming complaint.
///
/// `entry_name_for` reaches `canonicalize` for any path whose final component
/// is `.` or `..`, and that call is what reports a missing path here — a
/// deliberate exit-code decision (`Usage` before Phase 2c) with nothing
/// pinning it.
#[test]
fn a_nonexistent_dotdot_path_is_reported_as_an_io_error() {
    let dir = tmp_dir();
    let out = dir.join("dd.tar");
    let missing = dir.join("nosuch/..");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            missing.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(1),
        "a path that does not exist is an i/o error, whatever its final component; \
         stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    assert!(!out.exists());
}

/// `pack .` from a SYMLINKED working directory names entries after the
/// directory the link resolves to, not after the link.
///
/// Surprising the first time it happens (`cd proj && stuffr pack .` writes
/// `real/…`), and correct: `Path::file_name` gives `None` for `.`, so the name
/// comes from `canonicalize`, which resolves every symlink in the path. Pinned
/// because the obvious "fix" — using the shell's `$PWD` or the un-resolved cwd
/// — would silently change every such archive's entry names.
#[cfg(unix)]
#[test]
fn pack_of_dot_from_a_symlinked_directory_names_entries_after_the_real_one() {
    let dir = tmp_dir();
    std::fs::create_dir_all(dir.join("real/src")).unwrap();
    std::fs::write(dir.join("real/src/main.rs"), b"fn main() {}").unwrap();
    std::os::unix::fs::symlink("real", dir.join("proj")).unwrap();

    let out = dir.join("sym.tar");
    let st = Command::new(STUFFR)
        .current_dir(dir.join("proj"))
        .args(["pack", ".", "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("real/src/main.rs"),
        "`.` resolves through the symlink, so entries sit under the real directory's \
         name: {text}"
    );
    assert!(
        !text.contains("proj/"),
        "nothing may be named after the link itself: {text}"
    );
}

// ---------------------------------------------------------------------
// Phase 2c final review: the four findings whose reproduction is a CLI
// invocation, and the summary line that reports them.
// ---------------------------------------------------------------------

/// Finding 3. `pack . -o backup.tar` excludes the archive from its own walk,
/// which is stuffr being correct — and Phase 2c recorded it as a fidelity
/// warning, so `--strict-fidelity` exited 0 on the first run and **4 on every
/// run after**, forever, on an archive that had lost nothing the user wanted.
/// That is the flagship nightly-backup shape `examples.txt` advertises.
#[test]
fn excluding_the_output_from_its_own_walk_is_a_note_not_a_fidelity_loss() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"payload\n").unwrap();
    let out = root.join("backup.tar");

    // Three runs, because the defect only appears from the SECOND: on the
    // first there is no `backup.tar` on disk for the walk to find.
    for run in 1..=3 {
        let st = Command::new(STUFFR)
            .args([
                "pack",
                root.to_str().unwrap(),
                "-o",
                out.to_str().unwrap(),
                "--force",
                "--strict-fidelity",
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&st.stderr).to_string();
        assert_eq!(
            st.status.code(),
            Some(0),
            "run {run}: declining to store the archive inside itself is not a \
             fidelity loss, so the strict gate must stay green; stderr: {stderr}"
        );
        // Still SAID, every run — routing it off the gate must not silence
        // it. Without this half the test passes against an implementation
        // that simply drops the file without a word.
        if run > 1 {
            assert!(
                stderr.contains("proj/backup.tar"),
                "run {run}: the user must still be told, by name: {stderr}"
            );
        }
        // And the summary line must not claim a loss it is not reporting.
        assert!(
            stderr.contains("no fidelity loss"),
            "run {run}: the count in the summary must agree with the (empty) \
             warning list: {stderr}"
        );
    }

    // The archive is real and does not nest a copy of itself.
    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(text.contains("proj/a.txt"), "{text}");
    assert!(
        !text.contains("backup.tar"),
        "the archive must not be inside itself: {text}"
    );
}

/// Finding 4. `compound_alias` stripped the `t` and looked up `bz`, which
/// bzip2 does not register (it registers `bz2`), so the whole name resolved
/// to `Chain::Raw` — which on the write side is not a refusal but a silent
/// fall back to `default_format()`. `-o f.tbz` wrote a **gzip stream with no
/// tar inside it, at exit 0**: a name promising one thing, bytes that are
/// another, reported as success.
#[test]
fn a_tbz_output_writes_tar_inside_bzip2_and_not_a_bare_gzip() {
    let dir = tmp_dir();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload\n").unwrap();

    let out = dir.join("f.tbz");
    let st = Command::new(STUFFR)
        .args(["pack", src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    // The BYTES, not the exit code: exit 0 is exactly what the defect gave.
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(
        &bytes[..3],
        b"BZh",
        "a .tbz must be bzip2 — it was gzip (1f 8b) before this: {:02x?}",
        &bytes[..4.min(bytes.len())]
    );
    // And a tar really is inside it, which the gzip it used to write had no
    // room for at all.
    let listed = run_output(&["list", out.to_str().unwrap()]);
    assert!(
        listed.status.success(),
        "a .tbz must open as an archive: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("notes.txt"),
        "the tar layer must be there: {}",
        String::from_utf8_lossy(&listed.stdout)
    );

    // `.tbz2` was never broken and must stay unbroken: stripping its `t`
    // already yields bzip2's own registered `bz2`.
    let out2 = dir.join("f.tbz2");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", out2.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(&std::fs::read(&out2).unwrap()[..3], b"BZh");

    // The fix is in the compound alias, NOT the registry: `.bz` is bzip1, a
    // different and obsolete format, and must not have become writable as
    // bzip2 on the way past.
    let out3 = dir.join("f.bz");
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "-o", out3.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert_ne!(
        &std::fs::read(&out3).unwrap()[..3],
        b"BZh",
        "`bz` must not resolve to bzip2 outside the `t`-prefixed compound form"
    );
}

/// Finding 5. Phase 2c made a directory a legitimate input on the container
/// path and left it landing on `Error::exit_code`'s `_ => 1` wildcard on the
/// other: `File::open` on a directory succeeds on unix and fails at the first
/// `read`, so `pack proj -o proj.gz` reported `i/o error: Is a directory
/// (os error 21)` at exit 1 — as if stuffr had failed.
#[test]
fn a_directory_on_the_single_stream_path_is_a_usage_error_naming_the_fix() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"payload\n").unwrap();

    let out = dir.join("proj.gz");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&st.stderr).to_string();
    assert_eq!(
        st.status.code(),
        Some(2),
        "asking a codec for a tree is the caller's mistake, not an i/o \
         failure; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("os error 21"),
        "the raw EISDIR must not reach the user: {stderr}"
    );
    // Naming the fix is the point of the finding — an exit code alone leaves
    // the reader no better off than the wildcard did.
    assert!(
        stderr.contains("proj.tar.gz"),
        "the message must name the output that works: {stderr}"
    );
    assert!(
        !out.exists(),
        "the refusal happens before the destination is touched"
    );

    // And the output it names really does work.
    let good = dir.join("proj.tar.gz");
    assert!(
        Command::new(STUFFR)
            .args(["pack", root.to_str().unwrap(), "-o", good.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
}

/// Minor 1. The pack summary printed `out.fidelity.rung`, which
/// `create_archive` hardcodes to `Rung::Exact` — so `pack proj -o out.ar`
/// announced "exact fidelity" and then named four losses on the next four
/// lines. The number printed must be one the following lines agree with.
#[test]
fn the_pack_summary_counts_losses_rather_than_claiming_exact_fidelity() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("sub").join("a.txt"), b"payload\n").unwrap();

    // `ar` stores neither directories nor symlinks, so a walked tree loses
    // its directory entries there and nowhere else.
    let out = dir.join("p.a");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let stderr = String::from_utf8_lossy(&st.stderr).to_string();

    assert!(
        !stderr.contains("exact fidelity"),
        "a pack that lost entries must not announce exact fidelity: {stderr}"
    );
    // The two numbers must be the SAME number, read out of the two lines
    // that print it. An assertion on either alone passes against a summary
    // that prints a constant.
    let reported: usize = stderr
        .lines()
        .find_map(|l| l.split_once(" fidelity loss(es)"))
        .and_then(|(head, _)| head.rsplit(", ").next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("the summary must carry a loss count: {stderr}"));
    let listed: usize = stderr
        .lines()
        .find_map(|l| l.strip_prefix("stuffr: "))
        .and_then(|l| l.split_once(" fidelity warning(s):"))
        .and_then(|(n, _)| n.parse().ok())
        .unwrap_or_else(|| panic!("the warning header must carry a count: {stderr}"));
    assert_eq!(
        reported, listed,
        "the summary's count and the warning list's count are the same fact: {stderr}"
    );
    assert!(
        reported > 0,
        "packing a tree into `ar` really does lose the \
                          directory entries: {stderr}"
    );

    // And a pack that loses nothing says so, rather than saying "0".
    let clean = dir.join("p.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            clean.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&st.stderr).to_string();
    assert!(
        stderr.contains("no fidelity loss"),
        "a lossless pack must say so: {stderr}"
    );
}

// ---------------------------------------------------------------------
// Selecting entries by index.
//
// `ArchiveRead::by_index` existed and was implemented on all four
// containers from Phase 2 onward with no call site above the container
// layer at all — built and dormant, the same shape `UnsafePath` and
// `ContainerCaps` were in earlier phases. These tests are the contract for
// the surface that finally reaches it.
//
// Index is 0-based and counts in ARCHIVE ORDER: the order `next_entry`
// yields, which is the order `list` prints. `list`'s first column and
// `--index` therefore read one enumeration, and the first test here is the
// one that keeps them from drifting apart.
// ---------------------------------------------------------------------

/// Builds a zip through `stuffr pack` itself. There is no `zip` dev-dependency
/// here (unlike `tar`/`flate2`), and for these tests that is fine: the point
/// is not to validate stuffr's zip WRITER but to have an archive whose
/// container carries a real central directory, which is what puts `--index`
/// on its random-access route.
fn write_zip_via_pack(dir: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let mut paths = Vec::new();
    for (name, data) in entries {
        let p = src.join(name);
        std::fs::write(&p, data).unwrap();
        paths.push(p);
    }
    let zip = dir.join("bundle.zip");
    let mut args: Vec<String> = vec!["pack".into()];
    args.extend(paths.iter().map(|p| p.to_string_lossy().into_owned()));
    args.push("-o".into());
    args.push(zip.to_string_lossy().into_owned());
    let out = Command::new(STUFFR).args(&args).output().unwrap();
    assert!(
        out.status.success(),
        "building the zip fixture failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    zip
}

/// The index column and `--index` must name the same entry, because a user
/// reads the first and types the second. Checked for EVERY row rather than
/// one, so an off-by-one that happens to be invisible at position 0 still
/// fails.
#[test]
fn the_index_list_prints_is_the_index_cat_selects_by() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(
        &dir,
        &[
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("c.txt", b"charlie"),
        ],
    );
    let listing =
        String::from_utf8(run_output(&["list", archive.to_str().unwrap()]).stdout).unwrap();
    let rows: Vec<&str> = listing.lines().collect();
    assert_eq!(rows.len(), 3, "{listing}");

    for (want_index, (_, payload)) in [
        ("a.txt", &b"alpha"[..]),
        ("b.txt", &b"bravo"[..]),
        ("c.txt", &b"charlie"[..]),
    ]
    .iter()
    .enumerate()
    {
        // The first column of the listing is the number `--index` takes.
        let printed = rows[want_index].split_whitespace().next().unwrap();
        assert_eq!(
            printed,
            want_index.to_string(),
            "list's first column must be the 0-based archive position: {listing}"
        );
        let out = run_output(&[
            "cat",
            archive.to_str().unwrap(),
            "--index",
            &want_index.to_string(),
        ]);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout, *payload,
            "row {want_index} of the listing and `--index {want_index}` must be \
             the same entry"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The property the two-route implementation rests on, at the level a user
/// meets it: a zip on a real file is reached through its central directory,
/// the same zip on a pipe is reached by counting the forward walk, and the
/// two must hand back the same bytes.
///
/// Compared against the ORIGINAL content as well as against each other —
/// two routes wrong in the same direction would agree with each other
/// perfectly and both be wrong.
#[test]
fn index_selection_agrees_between_a_seekable_zip_and_the_same_zip_on_a_pipe() {
    let dir = tmp_dir();
    let payloads: [&[u8]; 4] = [b"first", b"second!!", b"third:::", b"fourth"];
    let zip = write_zip_via_pack(
        &dir,
        &[
            ("one.txt", payloads[0]),
            ("two.txt", payloads[1]),
            ("three.txt", payloads[2]),
            ("four.txt", payloads[3]),
        ],
    );
    let bytes = std::fs::read(&zip).unwrap();

    for (i, payload) in payloads.iter().enumerate() {
        let n = i.to_string();
        let seekable = run_output(&["cat", zip.to_str().unwrap(), "--index", &n]);
        assert!(
            seekable.status.success(),
            "index {n} on a file: {}",
            String::from_utf8_lossy(&seekable.stderr)
        );
        let piped = run_with_stdin_output(&["cat", "-", "--index", &n], &bytes);
        assert!(
            piped.status.success(),
            "index {n} on a pipe: {}",
            String::from_utf8_lossy(&piped.stderr)
        );

        assert_eq!(
            seekable.stdout, piped.stdout,
            "the random-access and counted routes disagreed at index {n}"
        );
        assert_eq!(
            seekable.stdout,
            payload.to_vec(),
            "index {n} did not reach the entry the archive was built with"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Repeatable, delivered in archive order however the flags were ordered,
/// and a repeat selects its entry once. That contract is what lets the two
/// routes above agree at all: the counted route can only ever produce
/// archive order.
#[test]
fn repeated_index_flags_are_deduplicated_and_delivered_in_archive_order() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(
        &dir,
        &[
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("c.txt", b"charlie"),
        ],
    );
    let out = run_output(&[
        "cat",
        archive.to_str().unwrap(),
        "--index",
        "2",
        "--index",
        "0",
        "--index",
        "2",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, b"alphacharlie",
        "archive order, once each — not typed order, and not twice"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An index past the end is the caller's mistake, so exit 2 and say how many
/// entries there actually are. Pinned on both routes, since each discovers
/// the overrun at a different moment.
#[test]
fn an_index_past_the_end_is_a_usage_error_naming_the_real_entry_count() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let zip = write_zip_via_pack(&dir, &[("one.txt", b"first"), ("two.txt", b"second")]);

    for path in [&archive, &zip] {
        let out = run_output(&["cat", path.to_str().unwrap(), "--index", "9"]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}: stderr {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("#9") && stderr.contains("0-1"),
            "the refusal must name the index asked for and the VALID range, \
             whichever route found it: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "an out-of-range index must not stream anything first"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--index` and PATTERNS are alternative ways of saying "which entries",
/// never a combination — exit 2 rather than a guess at union or
/// intersection.
#[test]
fn index_and_patterns_together_are_a_usage_error() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let dest = dir.join("out");

    let out = run_output(&["cat", archive.to_str().unwrap(), "a.txt", "--index", "1"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--index"), "{stderr}");

    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "a.txt",
        "-C",
        dest.to_str().unwrap(),
        "--index",
        "1",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !dest.exists(),
        "the refusal must come before anything is created"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--index` selects entries, so on `unpack` it needs -C for exactly the
/// reason a pattern does — and the refusal names the flag the user typed.
#[test]
fn unpack_by_index_without_a_directory_names_the_index_in_its_refusal() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);

    let out = run_output(&["unpack", archive.to_str().unwrap(), "--index", "1"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--index 1") && stderr.contains("-C"),
        "the refusal must name what was typed and what to do instead: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The containered half of the feature: `unpack --index N -C out` writes
/// exactly that entry and nothing else.
#[test]
fn unpack_by_index_extracts_only_the_selected_entry() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(
        &dir,
        &[
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("c.txt", b"charlie"),
        ],
    );
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--index",
        "1",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dest.join("b.txt")).unwrap(), b"bravo");
    assert!(!dest.join("a.txt").exists(), "only the selected entry");
    assert!(!dest.join("c.txt").exists(), "only the selected entry");

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--json` carries the index too, since a script selecting by position has
/// to read it from somewhere.
#[test]
fn list_json_carries_the_archive_index_of_every_entry() {
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let out = run_output(&["list", "--json", archive.to_str().unwrap()]);
    let text = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let rows = v.as_array().unwrap();
    assert_eq!(rows[0]["index"], 0);
    assert_eq!(rows[0]["name"], "a.txt");
    assert_eq!(rows[1]["index"], 1);
    assert_eq!(rows[1]["name"], "b.txt");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// `list` reports its fidelity, through the same printer `test` uses.
// ---------------------------------------------------------------------

/// `list` used to drop the container's fidelity report entirely. On a piped
/// zip — the one shape whose forward read provably loses metadata — `test`
/// warned and `list` printed its rows in silence.
///
/// Fixed by handing `report_fidelity` the report, the same call `test` and
/// `unpack -C` make. Asserted against `test`'s own stderr on the identical
/// bytes so the two verbs cannot drift: whatever `test` says was lost,
/// `list` says too.
#[test]
fn list_reports_the_same_fidelity_warnings_test_does() {
    let dir = tmp_dir();
    let zip = write_zip_via_pack(&dir, &[("one.txt", b"first"), ("two.txt", b"second")]);
    let bytes = std::fs::read(&zip).unwrap();

    let listed = run_with_stdin_output(&["list", "-"], &bytes);
    assert!(
        listed.status.success(),
        "a warning is not a failure without --strict-fidelity"
    );
    let list_err = String::from_utf8_lossy(&listed.stderr).to_string();
    let tested = run_with_stdin_output(&["test", "-"], &bytes);
    let test_err = String::from_utf8_lossy(&tested.stderr).to_string();

    assert!(
        test_err.contains("fidelity warning(s)"),
        "the fixture must be a shape that really does lose something: {test_err}"
    );
    assert!(
        list_err.contains("fidelity warning(s)"),
        "`list` must report what it lost, not print rows in silence: {list_err}"
    );
    // Same warnings, verbatim, because it is the same printer over the same
    // report — not a second one that could word things differently.
    let warnings_of = |s: &str| -> Vec<String> {
        s.lines()
            .filter(|l| l.trim_start().starts_with("- "))
            .map(|l| l.trim().to_string())
            .collect()
    };
    assert_eq!(
        warnings_of(&list_err),
        warnings_of(&test_err),
        "list:\n{list_err}\ntest:\n{test_err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// And the gate: `list --strict-fidelity` exits 4 on the same archive it
/// exits 0 on without the flag, the same contract `test` and `unpack -C`
/// have.
#[test]
fn list_strict_fidelity_turns_a_warning_into_exit_four() {
    let dir = tmp_dir();
    let zip = write_zip_via_pack(&dir, &[("one.txt", b"first")]);
    let bytes = std::fs::read(&zip).unwrap();

    let lenient = run_with_stdin_output(&["list", "-"], &bytes);
    assert_eq!(lenient.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&lenient.stdout).contains("one.txt"),
        "the listing itself is still printed"
    );

    let strict = run_with_stdin_output(&["list", "-", "--strict-fidelity"], &bytes);
    assert_eq!(
        strict.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
    assert!(
        String::from_utf8_lossy(&strict.stdout).contains("one.txt"),
        "the gate is a verdict on a listing that was still produced"
    );

    // A read that loses nothing is still exit 0 under the flag — the gate is
    // on what was LOST, never on the rung.
    let clean = run_output(&["list", zip.to_str().unwrap(), "--strict-fidelity"]);
    assert_eq!(
        clean.status.code(),
        Some(0),
        "a seekable zip loses nothing: {}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// The test suite's own temp directories.
// ---------------------------------------------------------------------

/// `tmp_dir()` named its directories `stuffr-cli-archive-{pid}-{counter}`,
/// never removed them on a failing path, and so accumulated thousands of
/// them. PIDs are reused, so a later run landing on a recycled PID inherited
/// its predecessor's directories WITH CONTENTS, and five unrelated tests
/// failed with "already exists" — a red gate that went green again when the
/// leftovers were deleted, with no code change at all.
///
/// The fix is a random component no other run can reproduce. What this test
/// pins is precisely that: the part of the name that is not derivable from
/// the pid and the counter must exist. Under the old scheme the whole name
/// was derivable, and the tail below was the counter's digits alone.
#[test]
fn a_temp_directory_name_is_not_reproducible_from_the_pid_and_a_counter() {
    let dir = tmp_dir();
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "a fresh temp directory must be empty — inheriting one with contents \
         in it is the whole failure this guards against"
    );

    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    let derivable = format!("stuffr-cli-archive-{}-", std::process::id());
    let tail = name
        .strip_prefix(&derivable)
        .unwrap_or_else(|| panic!("unexpected temp directory name: {name}"));
    assert!(
        tail.contains('-') && !tail.chars().all(|c| c.is_ascii_digit()),
        "everything after the pid was the counter alone, so a second run on a \
         recycled pid reproduced this name exactly: {name}"
    );

    // `tmp()` shares the same token, and had the same weakness: its old name
    // was `stuffr-cli-{pid}-{name}` exactly, every character of it derivable
    // by any other run that landed on the same pid.
    let other = tmp("token-check");
    let other_name = other.file_name().unwrap().to_string_lossy().into_owned();
    assert_ne!(
        other_name,
        format!("stuffr-cli-{}-token-check", std::process::id()),
        "tmp() must carry the run token too"
    );
    assert!(
        other_name.ends_with("-token-check"),
        "…and must still end in the caller's own name: {other_name}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
