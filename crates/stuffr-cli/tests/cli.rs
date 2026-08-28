use std::process::Command;

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
