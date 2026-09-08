use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use flate2::Compression;
use flate2::write::GzEncoder;
use tar::{Builder, Header};

const STUFFR: &str = env!("CARGO_BIN_EXE_stuffr");

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-cli-{}-{}", std::process::id(), name));
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
    let out = Command::new(STUFFR).arg("--version").output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("0.1.0"), "--version must report 0.1.0, got: {s}");
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
fn tmp_dir() -> PathBuf {
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-cli-archive-{}-{}", std::process::id(), n));
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

#[test]
fn pack_of_a_directory_says_so_rather_than_writing_an_empty_archive() {
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
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!archive.exists(), "a refused command must write nothing");
}

#[test]
fn flags_that_the_container_path_cannot_honour_are_refused_not_ignored() {
    // The tree's rule (see `threads_is_not_offered_on_decode_subcommands`):
    // a flag that would be silently ignored is refused instead.
    let dir = tmp_dir();
    let archive = write_fixture_tar(&dir, &[("a.txt", b"alpha")]);
    let dest = dir.join("out");
    for extra in [
        vec!["--format", "gzip"],
        vec!["--memory-limit", "64M"],
        vec!["-o", "somewhere"],
    ] {
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
