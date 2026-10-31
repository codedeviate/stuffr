use crate::common::*;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn a_failing_test_leaves_no_scratch_behind() {
    let seen = std::cell::RefCell::new(None::<PathBuf>);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let probe = tmp("probe");
        std::fs::write(&probe, b"left behind?").unwrap();
        *seen.borrow_mut() = Some(probe.to_path_buf());
        panic!("a failing test, on purpose");
    }));
    assert!(r.is_err());
    let probe = seen.into_inner().expect("the closure ran");
    assert!(!probe.exists(), "{} survived a panic", probe.display());
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

        // And the ground truth for both branches above, from the command
        // that DOES open the archive: a piped tar/cpio/ar really does report
        // no warnings, so "nothing approximated" is not merely convenient.
        // For zip, what a forward read finds is known only once it has read
        // the central directory at the END (ruling B2): these bytes agree
        // with their index and report nothing, the same bytes with one local
        // name cloaked report a disagreement. info reads neither far, so it
        // cannot tell them apart and must withhold.
        let tested = |bytes: &[u8]| {
            let mut child = Command::new(STUFFR)
                .args(["test", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(bytes).unwrap();
            child.wait_with_output().unwrap()
        };
        let out = tested(&bytes);
        let stderr = String::from_utf8_lossy(&out.stderr);
        if *has_trailing_index {
            let cloaked = tested(&cloak_first_local_name(&bytes));
            let cloaked_err = String::from_utf8_lossy(&cloaked.stderr);
            assert!(
                cloaked_err.contains("fidelity warning"),
                ".{ext} on a pipe must be able to really have warnings, or info would be \
                 right to claim none: {cloaked_err}"
            );
            assert!(
                out.status.success() && !stderr.contains("fidelity warning"),
                ".{ext} on a pipe whose index agrees reports nothing since B2: {stderr}"
            );
        } else {
            assert!(
                out.status.success() && !stderr.contains("fidelity warning"),
                ".{ext} on a pipe must really have NO warnings, which is what makes info's \
                 claim true: {stderr}"
            );
        }
    }
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
/// `test` still finds what a forward read can lose. Since ruling B2 that is
/// known only at the end of the stream: these bytes agree with their central
/// directory and `test -` reports nothing, while the same bytes with a
/// cloaked local name report the disagreement. Both look alike to `info`.
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

    // The other half: `test`, which DOES open the archive and reads it to
    // the end, finds a loss where there is one. Without this the assertion
    // above could be satisfied by having lost the warnings altogether.
    let tested = |bytes: &[u8]| {
        let mut child = Command::new(STUFFR)
            .args(["test", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        child.wait_with_output().unwrap()
    };
    let cloaked = tested(&cloak_first_local_name(&bytes));
    let stderr = String::from_utf8_lossy(&cloaked.stderr);
    assert!(
        stderr.contains("local header and central directory disagree on name"),
        "`test` reads the archive to its index and must report the cloak: {stderr}"
    );
    assert_eq!(
        info_over_stdin(&cloak_first_local_name(&bytes)),
        text,
        "info cannot tell the cloaked bytes from the clean ones"
    );
    let out = tested(&bytes);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && !stderr.contains("fidelity warning"),
        "the clean bytes' index was read and agrees (ruling B2; two warnings in 0.22.0): \
         {stderr}"
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
}

/// The other side of the same fix: a bare CODEC stream has no container to
/// open, so its empty warning list is a genuine finding and `info` must go on
/// reporting it. Without this, "withhold the claim" could have been
/// implemented by withholding it everywhere.
///
/// xz, not gzip: since the T10 review's I1 a codec declaring
/// `reports_trailing_data` (gzip, bzip2) withholds the claim, because what
/// follows its last member is judged only at the end of the stream — see
/// `info_withholds_the_claim_for_a_codec_that_judges_its_trailing_bytes`.
#[test]
fn info_on_a_bare_codec_stream_still_reports_nothing_approximated() {
    let src = tmp("info-codec-fidelity.txt");
    let xz = tmp("info-codec-fidelity.txt.xz");
    let _ = std::fs::remove_file(&xz);
    std::fs::write(&src, b"payload").unwrap();
    assert!(
        Command::new(STUFFR)
            .args(["pack", src.to_str().unwrap(), "--format", "xz"])
            .status()
            .unwrap()
            .success()
    );
    let bytes = std::fs::read(&xz).unwrap();

    for (what, text) in [
        (
            "a file",
            String::from_utf8(
                Command::new(STUFFR)
                    .args(["info", xz.to_str().unwrap()])
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
        .args(["info", "--json", xz.to_str().unwrap()])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8(out.stdout).unwrap())
        .expect("info --json must be JSON");
    assert_eq!(v["fidelity_evaluated"], true, "{v}");
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
}

/// A write line says what the write LOST, in the words every write line uses.
/// The read rung (`forward-only` over a pipe) is a claim about reading, and
/// `info` still reports it; it must not appear on pack's summary.
#[test]
fn pack_over_a_pipe_says_no_fidelity_loss_not_a_read_rung() {
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
    assert!(err_text.contains("no fidelity loss"), "{err_text}");
    assert!(
        !err_text.contains("forward-only") && !err_text.contains("exact"),
        "a write line makes no read-rung claim: {err_text}"
    );
}

/// The other half of the pair above: same words from a seekable file.
#[test]
fn pack_of_a_seekable_file_says_no_fidelity_loss() {
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
    assert!(err_text.contains("no fidelity loss"), "{err_text}");
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

    // `lha`/`arj` (Phase 3b) used to be the first containers gated behind a
    // feature `pure` did not carry, back when `default = ["pure"]` and
    // `legacy` lived only in `full`/`--all-features` — so this test binary
    // could genuinely see two different container counts depending on
    // which `make check` leg compiled it (4 under `test-pure`, 6 under
    // `--all-features`), and the code below used to carry a PROJECTED count
    // (`base_containers.len() + LEGACY_ONLY_CONTAINERS.len()`) for the legs
    // where it could not observe `lha`/`arj` directly.
    //
    // That projection is now dead code, not just an unused branch: `legacy`
    // joined `stuffr`'s `default` feature set, and — measured, not assumed —
    // there is no longer any `cargo build`/`cargo test` of the `stuffr-cli`
    // binary that lacks it, `--no-default-features` included.
    // `crates/stuffr-cli/Cargo.toml`'s `[dependencies]` entry,
    // `stuffr = { path = "../stuffr", ..., features = ["serde"] }`, does not
    // set `default-features = false`, so it always requests `stuffr`'s
    // `default` (now `pure` **and** `legacy`) regardless of what
    // `--no-default-features`/`--features` this binary itself was built
    // with — `stuffr-cli` declares no `[features] default` of its own for
    // `--no-default-features` to even disable. Verified directly: `cargo
    // build -p stuffr-cli --no-default-features` (no `--features` at all)
    // still ships `lha`, `arj` and `compress` in `stuffr formats`. So
    // `containers.len()` is trusted unconditionally below — there is no
    // real build left for a projection to stand in for.
    //
    // `base_containers` (the tier-invariant round-trip quartet: tar/ar/
    // cpio/zip) is kept, because the page still legitimately describes that
    // subset by itself in some sentences (e.g. "four round-trip
    // containers", distinct from "six total").
    const LEGACY_ONLY_CONTAINERS: &[&str] = &["lha", "arj", "arc", "zoo"];
    let base_containers: Vec<&str> = containers
        .iter()
        .copied()
        .filter(|id| !LEGACY_ONLY_CONTAINERS.contains(id))
        .collect();
    let full_container_count = containers.len();

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
            // Either the tier-invariant base count (the round-trip
            // quartet) or the full (`pure` + `legacy`) count is a true
            // claim — see `full_container_count`'s own comment above for
            // why it is now trusted straight from the live registry with
            // no projection: every real build of this binary compiles
            // `legacy` in, so a `lha`/`arj` registration failure would
            // already show up as `containers.len()` shrinking, not as a
            // stale count surviving here.
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
}

/// **A behavioural claim on the `--examples` page, pinned by RUNNING it.**
///
/// The page ships INSIDE the binary and is where this project points users
/// for exit-code contracts, and the count guards around it derive their
/// expectations from the live registry — which is exactly why the COUNT
/// claims were all correct and a BEHAVIOURAL one was not. Phase 3c's final
/// review found `examples.txt`'s ARJ entry promising "A symlink is refused
/// rather than stored (exit 3)" when the measured answer is exit 0 with a
/// fidelity warning, exit 4 under `--strict-fidelity`. Nothing in the tree
/// could have said so: the sentence was prose, and prose is not checked.
///
/// Two arms, and the first is what gives the second its authority:
///
/// 1. **Measured.** Every container the registry says can WRITE is packed
///    over a tree holding a symlink, plain and `--strict-fidelity`. The
///    answer is 0 or 4 — stored (tar, cpio, zip) or skipped with a named
///    fidelity loss (ar, lha, arj) — and never 3. That is a real contract
///    of its own, derived from the registry rather than a list here, so a
///    seventh writable container joins it automatically.
/// 2. **The page is held to it.** No sentence may say a symlink is refused
///    at exit 3, because no container does that.
///
/// What this does NOT reach, stated so the next reader does not overtrust
/// it: only the symlink class, and only the exit-3 verdict. A page claiming
/// the wrong exit code for some other refusal is still unchecked prose. The
/// class is cheap to extend one measured case at a time; it is not a general
/// executable-docs harness and does not pretend to be.
#[cfg(unix)]
#[test]
fn a_symlink_in_a_walked_tree_is_never_refused_and_the_page_may_not_say_it_is() {
    let dir = tmp("examples-symlink-verdict");
    let _ = std::fs::remove_dir_all(&dir);
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("file.txt"), b"payload").unwrap();
    std::os::unix::fs::symlink("file.txt", tree.join("link.txt")).unwrap();

    let registry = stuffr::registry();
    let mut measured = 0usize;
    for row in registry.matrix() {
        if registry.container(row.id).is_none() || !row.write {
            continue;
        }
        let id = row.id.as_str();
        let out_path = dir.join(format!("out-{id}"));
        for strict in [false, true] {
            let _ = std::fs::remove_file(&out_path);
            let mut cmd = Command::new(STUFFR);
            cmd.arg("pack")
                .arg(&tree)
                .arg("-o")
                .arg(&out_path)
                .arg("--format")
                .arg(id);
            if strict {
                cmd.arg("--strict-fidelity");
            }
            let out = cmd.output().unwrap();
            let code = out.status.code();
            assert!(
                matches!(code, Some(0) | Some(4)),
                "`pack` over a tree containing a symlink answered exit {code:?} for `{id}` \
                 (strict-fidelity: {strict}). A kind a container cannot store is a fidelity \
                 LOSS, never a refusal — and exit 3 in particular is what `examples.txt` \
                 wrongly promised for `arj` until Phase 3c's final review measured it. \
                 stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        measured += 1;
    }
    assert!(
        measured >= 6,
        "only {measured} writable containers were exercised; this build registers six, so the \
         registry walk has stopped finding them and the measurement proves nothing"
    );
    let _ = std::fs::remove_dir_all(&dir);

    let out = Command::new(STUFFR).arg("--examples").output().unwrap();
    assert!(out.status.success(), "stuffr --examples must exit 0");
    let text = String::from_utf8(out.stdout).unwrap();
    // Whitespace-normalised, because the page wraps and a claim split across
    // a line break must still read as one sentence.
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    for sentence in flat.split(". ") {
        let lower = sentence.to_lowercase();
        if !lower.contains("symlink") {
            continue;
        }
        if !(lower.contains("refused") || lower.contains("refuses")) {
            continue;
        }
        assert!(
            !lower.contains("exit 3"),
            "the examples page says a symlink is refused at exit 3, which the measurement \
             above proves no writable container does: {sentence:?}"
        );
    }
}

/// `pack --format arc`/`zoo` must refuse CLEARLY — exit 3, naming
/// the format as readable but not writable by this build — never fail
/// obscurely (an internal panic, a bare i/o error, or an unrelated exit
/// code). All three take the SAME route: `Registry::require_container_writer`
/// refuses on the declared capability, raising `Error::CapabilityUnavailable`.
/// Each module's own `create()` still returns that same error as an
/// unreachable backstop. This pins it all the way through the CLI rather
/// than only at the trait level each module's unit tests already cover.
///
/// **`compress` left this list in Phase 3c Task 5, `lha` in Task 6 and
/// `arj` in Task 7** — none is read-only any more, so none belongs among
/// the formats this test proves REFUSE to write.
/// `pack_writes_a_compress_stream_the_system_tool_reads`,
/// `pack_writes_an_lha_archive_the_system_tool_reads` and
/// `pack_writes_an_arj_archive_stuffr_reads_back` below are their positive
/// counterparts, proving the opposite claim for the three formats that
/// changed. The third is named differently on purpose: no `arj`/`unarj`
/// binary is obtainable, so that one is a round trip through stuffr's own
/// reader and nothing outside this project judges it.
///
/// Runtime-checked, not `cfg`-gated. `stuffr-cli` does declare a `legacy`
/// feature (a passthrough to `stuffr/legacy`, so `cargo install stuffr-cli
/// --features legacy` still works — it is just no longer required), but
/// `cargo test --workspace --all-features` unifies features across the
/// workspace, so this binary's own `cfg!(feature = "legacy")` is not what
/// decides whether the four formats are compiled in — the live registry
/// is, the same way `examples_page_covers_every_format_and_flag` above
/// already asks it for container counts.
///
/// The `!registered` skip below is now believed unreachable rather than
/// removed: `legacy` joined `stuffr`'s `default` feature set, and
/// `stuffr-cli`'s own dependency on `stuffr` requests `stuffr`'s defaults
/// unconditionally (see the dead-projection comment in
/// `the_examples_page_cannot_carry_a_stale_count_or_a_shipped_still_to_come`
/// above for the measured proof), so there is no longer a `cargo test`
/// invocation of this binary where any of the four is absent. Kept as a
/// guard rather than an assertion of reachability: if a future Cargo.toml
/// edit ever makes a legacy-less `stuffr-cli` build possible again (e.g. by
/// adding `default-features = false` to that dependency edge), this test
/// should degrade gracefully rather than fail on a tier it was never
/// written to cover.
#[test]
fn pack_refuses_a_read_only_legacy_format_clearly() {
    let registry = stuffr::registry();
    let dir = tmp("legacy-format-refusal-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("notes.txt");
    std::fs::write(&src, b"payload").unwrap();

    for (name, out_ext) in [("arc", "arc"), ("zoo", "zoo")] {
        let registered = registry.container(stuffr::FormatId::new(name)).is_some()
            || registry.codec(stuffr::FormatId::new(name)).is_some();
        if !registered {
            // `legacy` was not compiled into this build — believed
            // unreachable now that `legacy` is in `stuffr`'s `default`
            // feature set (see this test's own doc comment), but if it ever
            // fires again, the read-only refusal this test pins simply
            // does not exist on that build, and asserting "unknown format"
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
        // ONE sentence for both, which is the point of the shared
        // gate: the containers used to say "unsupported: ARJ is
        // read-only in this build" (their own hand-rolled
        // `Container::create` refusal) before `require_container_writer`
        // existed, and a comment here called that difference "phrasing" when
        // it was two different code paths. A per-format substring would let
        // them drift apart again without failing.
        let lower = err.to_lowercase();
        assert!(
            lower.contains(&format!(
                "`{name}` can be read but not written by this build"
            )),
            "`--format {name}`'s refusal must be the one shared capability sentence, \
             naming the format, rather than a per-format phrasing: {err}"
        );
        assert!(
            !dst.exists(),
            "a refused pack must not leave a partial `{}` behind",
            dst.display()
        );
    }
}

/// The positive counterpart to `pack_refuses_a_read_only_legacy_format_
/// clearly` above, for the one format Phase 3c Task 5 moved out of that
/// list: `pack --format compress` must actually write a `.Z` file the real
/// system `uncompress` can read back, at the default level (16, not the
/// maxbits-9 special case `compress_z.rs`'s own unit tests cover directly).
#[test]
fn pack_writes_a_compress_stream_the_system_tool_reads() {
    let uncompress_bin = require_bin("uncompress");
    let dir = tmp("compress-write-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("notes.txt");
    let plain = b"the quick brown fox jumps over the lazy dog\n".repeat(200);
    std::fs::write(&src, &plain).unwrap();
    // Uppercase `.Z`, deliberately: the system `uncompress` appends `.Z`
    // itself when the name it is given does not already end in it (both
    // implementations), so a lowercase `.z` — this format's own registered
    // extension, and the natural spelling `--format compress` writing to a
    // bare `-o` name would otherwise pick — would have it look for
    // `notes.txt.z.Z` and fail with "No such file or directory".
    let dst = dir.join("notes.txt.Z");

    let res = Command::new(STUFFR)
        .args([
            "pack",
            src.to_str().unwrap(),
            "--format",
            "compress",
            "-o",
            dst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "pack --format compress must now succeed: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(dst.exists(), "pack must have written {}", dst.display());

    let out = Command::new(&uncompress_bin)
        .arg("-c")
        .arg(&dst)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the system uncompress must read this build's own .Z output: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, plain,
        "the system uncompress's output must match the original plaintext exactly"
    );

    // stuffr's own reader must agree too.
    let cat = Command::new(STUFFR)
        .args(["cat", dst.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(cat.status.success());
    assert_eq!(cat.stdout, plain);
}

/// The positive counterpart to `pack_refuses_a_read_only_legacy_format_
/// clearly` above, for the format Phase 3c Task 6 moved out of that list.
///
/// A CONTAINER, not a codec, so this proves more than its `compress`
/// sibling does: a whole directory tree is packed — files and the directory
/// entry above them — the real `lhasa` reads the result back, and stuffr's
/// own `list` agrees on the entry names. `lhasa` is decompress-only, which
/// is exactly what makes it the right witness here and why no such test
/// could exist while LHA was read-only.
#[test]
fn pack_writes_an_lha_archive_the_system_tool_reads() {
    let lha_bin = require_lhasa();
    let banner = lhasa_banner(&lha_bin);
    let dir = tmp("lha-write-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
    let alpha = b"the quick brown fox jumps over the lazy dog\n".repeat(120);
    std::fs::write(dir.join("tree/alpha.txt"), &alpha).unwrap();
    std::fs::write(dir.join("tree/sub/beta.bin"), b"beta\n").unwrap();
    let dst = dir.join("out.lzh");

    let res = Command::new(STUFFR)
        .args([
            "pack",
            dir.join("tree").to_str().unwrap(),
            "--format",
            "lha",
            "-o",
            dst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "pack --format lha must now succeed: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(dst.exists(), "pack must have written {}", dst.display());

    // The external witness: lhasa verifies every entry's CRC-16 itself.
    let test = Command::new(&lha_bin).arg("t").arg(&dst).output().unwrap();
    assert!(
        test.status.success(),
        "{banner} must accept an archive stuffr wrote: {}\n{}",
        String::from_utf8_lossy(&test.stdout),
        String::from_utf8_lossy(&test.stderr)
    );

    // ...and the bytes it extracts must be the bytes that went in. A CRC
    // agreeing proves the check value matches, not that the plaintext is
    // right.
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let extract = Command::new(&lha_bin)
        .arg(format!("xfw={}", out.display()))
        .arg(&dst)
        .output()
        .unwrap();
    assert!(
        extract.status.success(),
        "{banner} must extract it: {}",
        String::from_utf8_lossy(&extract.stderr)
    );
    assert_eq!(std::fs::read(out.join("tree/alpha.txt")).unwrap(), alpha);
    assert_eq!(
        std::fs::read(out.join("tree/sub/beta.bin")).unwrap(),
        b"beta\n"
    );

    // stuffr's own reader must agree on what is in there.
    let list = Command::new(STUFFR)
        .args(["list", dst.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(list.status.success());
    let listing = String::from_utf8_lossy(&list.stdout);
    for name in ["tree/alpha.txt", "tree/sub/beta.bin"] {
        assert!(
            listing.contains(name),
            "`stuffr list` lost {name}: {listing}"
        );
    }
}

/// The positive counterpart to `pack_refuses_a_read_only_legacy_format_
/// clearly` above, for the format Phase 3c Task 7 moved out of that list —
/// **and the one with no external witness at all.**
///
/// Its two siblings are judged from outside this project: the real
/// `uncompress`(1) reads what `--format compress` writes, and `lhasa` reads
/// what `--format lha` writes. No `arj`/`unarj` binary is obtainable here,
/// so this is a round trip through stuffr's OWN reader and proves exactly
/// that much — the archive stuffr writes is one stuffr reads back with the
/// tree intact. Everything that could be done about that gap was done in
/// `legacy::arj`'s unit tests (`spec_constraints_the_reader_never_checks`
/// asserts, on emitted bytes, the spec constraints `unarj-rs` ignores) and
/// it is named here so this test is not mistaken for the same kind of
/// evidence its two siblings carry.
///
/// A CONTAINER, so a whole tree goes in — files and the directory entry
/// above them — and the entries come back with their names, their contents
/// and their kinds.
#[test]
fn pack_writes_an_arj_archive_stuffr_reads_back() {
    let dir = tmp("arj-write-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
    let alpha = b"the quick brown fox jumps over the lazy dog\n".repeat(120);
    std::fs::write(dir.join("tree/alpha.txt"), &alpha).unwrap();
    std::fs::write(dir.join("tree/sub/beta.bin"), b"beta\n").unwrap();
    let dst = dir.join("out.arj");

    let res = Command::new(STUFFR)
        .args([
            "pack",
            dir.join("tree").to_str().unwrap(),
            "--format",
            "arj",
            "-o",
            dst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "pack --format arj must now succeed: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(dst.exists(), "pack must have written {}", dst.display());

    // The magic the registry detects it by, at offset 0 — so the file is
    // recognised as ARJ without `--format`, which the `list` below relies
    // on.
    let head = std::fs::read(&dst).unwrap();
    assert_eq!(
        &head[0..2],
        &[0x60, 0xEA],
        "an ARJ archive opens with its own header id"
    );

    // `test` verifies every entry's CRC-32, which is the strongest check
    // available without a second implementation.
    let verify = Command::new(STUFFR)
        .args(["test", dst.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "`stuffr test` must accept an archive stuffr wrote: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let list = Command::new(STUFFR)
        .args(["list", dst.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(list.status.success());
    let listing = String::from_utf8_lossy(&list.stdout);
    for name in ["tree/alpha.txt", "tree/sub/beta.bin"] {
        assert!(
            listing.contains(name),
            "`stuffr list` lost {name}: {listing}"
        );
    }

    // ...and the bytes have to come back, not merely the names.
    let out = dir.join("out");
    let unpack = Command::new(STUFFR)
        .args(["unpack", dst.to_str().unwrap(), "-C", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        unpack.status.success(),
        "unpack must restore the tree: {}",
        String::from_utf8_lossy(&unpack.stderr)
    );
    assert_eq!(std::fs::read(out.join("tree/alpha.txt")).unwrap(), alpha);
    assert_eq!(
        std::fs::read(out.join("tree/sub/beta.bin")).unwrap(),
        b"beta\n"
    );
    assert!(
        out.join("tree/sub").is_dir(),
        "the directory entries must come back as directories, which is what \
         ContainerCaps::stores_dirs claims"
    );
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
