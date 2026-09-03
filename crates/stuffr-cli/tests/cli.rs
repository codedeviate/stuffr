use std::io::{Read, Write};
use std::process::{Command, Stdio};

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
