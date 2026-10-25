use crate::common::*;

#[test]
fn bench_refuses_a_debug_build() {
    let f = tmp("bench-refuse.txt");
    std::fs::write(&f, b"hello bench\n").unwrap();
    let (code, err) = bench_err(&["bench", f.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert_eq!(
        err,
        "stuffr: bench: timings from a debug build are meaningless; build with --release\n"
    );
    assert!(!err.contains("usage error"), "{err}");
}

#[test]
fn bench_with_no_match_is_a_usage_error() {
    let dir = tmp_dir();
    let pattern = format!("{}/nomatch*.log", dir.display());
    let (code, err) = bench_err(&["bench", &pattern]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("no input matched"), "{err}");
}

#[test]
fn bench_on_a_missing_path_is_a_usage_error() {
    let dir = tmp_dir();
    let missing = dir.join("absent.log");
    let (code, err) = bench_err(&["bench", missing.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("no input matched"), "{err}");
}

#[cfg(unix)]
#[test]
fn bench_on_a_dangling_symlink_is_a_usage_error() {
    let dir = tmp_dir();
    std::fs::write(dir.join("real.log"), b"x").unwrap();
    let link = dir.join("dangling.log");
    std::os::unix::fs::symlink(dir.join("gone.log"), &link).unwrap();
    let want = format!("{}: cannot read it (", link.display());
    let (code, err) = bench_err(&["bench", link.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains(&want), "{err}");
    let pattern = format!("{}/*.log", dir.display());
    let (code, err) = bench_err(&["bench", &pattern]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains(&want), "{err}");
}

#[cfg(unix)]
#[test]
fn bench_on_an_unreadable_directory_under_a_pattern_is_a_usage_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir();
    std::fs::write(dir.join("a.log"), b"x").unwrap();
    let locked = dir.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("b.log"), b"x").unwrap();
    // `Scratch` restores the permissions when it drops.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        return; // root reads it anyway
    }
    let pattern = format!("{}/*/*.log", dir.display());
    let (code, err) = bench_err(&["bench", &pattern]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("locked: cannot read it ("), "{err}");
}

#[cfg(unix)]
#[test]
fn bench_on_a_file_it_cannot_open_is_a_usage_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir();
    std::fs::write(dir.join("a.log"), b"x").unwrap();
    let locked = dir.join("locked.log");
    std::fs::write(&locked, b"secret").unwrap();
    // `Scratch` restores the permissions when it drops.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&locked).is_ok() {
        return; // root opens it anyway
    }
    let want = format!("{}: cannot read it (", locked.display());
    let (code, err) = bench_err(&["bench", "-q", locked.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains(&want), "{err}");
    let pattern = format!("{}/*.log", dir.display());
    let (code, err) = bench_err(&["bench", "-q", &pattern]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains(&want), "{err}");
}

/// glob drops a literal component it cannot stat; the pattern's literal
/// prefix is reported instead of "no input matched".
#[cfg(unix)]
#[test]
fn bench_on_a_pattern_under_an_unreadable_directory_names_it() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir();
    let locked = dir.join("locked");
    std::fs::create_dir_all(locked.join("sub")).unwrap();
    std::fs::write(locked.join("sub/b.log"), b"x").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_dir(&locked).is_ok() {
        return; // root reads it anyway
    }
    let pattern = format!("{}/locked/sub/*.log", dir.display());
    let (code, err) = bench_err(&["bench", &pattern]);
    assert_eq!(code, Some(2), "{err}");
    let want = format!("{}: cannot read it (", locked.join("sub").display());
    assert!(err.contains(&want), "{err}");
}

#[test]
fn bench_on_a_directory_is_a_usage_error() {
    let dir = tmp_dir();
    let (code, err) = bench_err(&["bench", dir.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("is a directory"), "{err}");
}

#[test]
fn bench_rejects_json_with_csv() {
    let f = tmp("bench-json-csv.txt");
    std::fs::write(&f, b"x").unwrap();
    let (code, err) = bench_err(&["bench", "--json", "--csv", f.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("cannot be used with"), "{err}");
}

#[test]
fn bench_rejects_an_unknown_format() {
    let f = tmp("bench-unknown.txt");
    std::fs::write(&f, b"x").unwrap();
    let (code, err) = bench_err(&["bench", "--formats", "nosuch", f.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("unknown format `nosuch`"), "{err}");
}

#[test]
fn bench_rejects_a_container_format() {
    let f = tmp("bench-container.txt");
    std::fs::write(&f, b"x").unwrap();
    let (code, err) = bench_err(&["bench", "--formats", "tar", f.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("cannot be benchmarked"), "{err}");
    assert!(err.contains("container"), "{err}");
}

#[test]
fn bench_rejects_a_zero_repeat() {
    let f = tmp("bench-repeat.txt");
    std::fs::write(&f, b"x").unwrap();
    let (code, err) = bench_err(&["bench", "--repeat", "0", f.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("--repeat"), "{err}");
}

/// `--no-memory` is a flag: it takes no value (a usage error naming the
/// value, not an unknown option), and bare it is accepted, so a debug build
/// gets as far as its refusal.
#[test]
fn bench_rejects_no_memory_with_an_unknown_value() {
    let f = tmp("bench-no-memory.txt");
    std::fs::write(&f, b"x").unwrap();
    let (code, err) = bench_err(&["bench", "--no-memory=yes", f.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("unexpected value 'yes' for '--no-memory'"),
        "{err}"
    );
    let (code, err) = bench_err(&["bench", "--no-memory", f.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("timings from a debug build are meaningless"),
        "{err}"
    );
}

/// A FIFO is refused from its metadata, never opened: opening one with no
/// writer would block bench for ever.
#[cfg(unix)]
#[test]
fn bench_refuses_a_fifo_named_or_matched() {
    let dir = tmp_dir();
    let fifo = dir.join("pipe.log");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    let want = format!(
        "{} is not a regular file; bench needs files whose size it can read",
        fifo.display()
    );
    let (code, err) = bench_err(&["bench", fifo.to_str().unwrap()]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains(&want), "{err}");
    let pattern = format!("{}/*.log", dir.display());
    let (code, err) = bench_err(&["bench", &pattern]);
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains(&want), "{err}");
}

#[test]
fn bench_table_only_conflicts_with_json_and_csv() {
    let f = tmp("bench-q-json.txt");
    std::fs::write(&f, b"x").unwrap();
    for machine in ["--json", "--csv"] {
        for q in ["-q", "--table-only"] {
            let (code, err) = bench_err(&["bench", q, machine, f.to_str().unwrap()]);
            assert_eq!(code, Some(2), "{q} {machine}: {err}");
            assert!(err.contains("cannot be used with"), "{q} {machine}: {err}");
        }
    }
}
