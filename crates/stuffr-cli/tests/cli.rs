use std::io::{Read, Write};
use std::process::{Command, Stdio};

const STF: &str = env!("CARGO_BIN_EXE_stf");

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stf-cli-{}-{}", std::process::id(), name));
    p
}

#[test]
fn formats_now_reports_gzip() {
    let out = Command::new(STF).arg("formats").output().unwrap();
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
        Command::new(STF)
            .args(["pack", src.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    let out = Command::new(STF)
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
fn info_json_is_parseable_and_carries_the_same_facts() {
    let src = tmp("json.txt");
    let gz = tmp("json.txt.gz");
    let _ = std::fs::remove_file(&gz);
    std::fs::write(&src, b"payload").unwrap();
    assert!(
        Command::new(STF)
            .args(["pack", src.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    let out = Command::new(STF)
        .args(["info", "--json", gz.to_str().unwrap()])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.trim_start().starts_with('{'), "must be JSON: {text}");
    assert!(text.contains("\"format\""), "{text}");
    assert!(text.contains("\"rung\""), "{text}");

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
        Command::new(STF)
            .args(["pack", src.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    let gz_bytes = std::fs::read(&gz).unwrap();

    let mut child = Command::new(STF)
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
        Command::new(STF)
            .args(["pack", src.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    let mut child = Command::new(STF)
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
