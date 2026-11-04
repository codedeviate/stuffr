//! An input path that cannot be opened is a usage error (exit 2) in every
//! verb that names one, before anything is created.

use std::path::Path;

use super::common::{gzip_wrap, run_output, run_with_stdin_output, tmp_dir};

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn missing_input_is_a_usage_error_in_every_verb() {
    let dir = tmp_dir();
    let p = dir.join("nope.zip");
    let p = p.to_str().unwrap();
    let d = dir.join("out-dir");
    let out_tar = dir.join("out.tar");
    let out_zip = dir.join("out.zip");
    let out_gz = dir.join("out.gz");
    let (d_s, tar_s, zip_s, gz_s) = (
        d.to_str().unwrap(),
        out_tar.to_str().unwrap(),
        out_zip.to_str().unwrap(),
        out_gz.to_str().unwrap(),
    );
    let e = std::fs::File::open(p).unwrap_err();
    let want = format!("stuffr: usage error: cannot read {p}: {e}\n");
    let cases: Vec<Vec<&str>> = vec![
        vec!["list", p],
        vec!["test", p],
        vec!["info", p],
        vec!["cat", p],
        vec!["cat", "--index", "0", p],
        vec!["unpack", p, "-C", d_s],
        vec!["convert", p, tar_s],
        vec!["salvage", p, "--list"],
        vec!["pack", p, "-o", zip_s],
        vec!["pack", p, "-o", gz_s],
    ];
    for args in cases {
        let out = run_output(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(text(&out.stderr), want, "{args:?}");
        for made in [&d, &out_tar, &out_zip, &out_gz] {
            assert!(!made.exists(), "{args:?} created {}", made.display());
        }
        assert_eq!(names(&dir), Vec::<String>::new(), "{args:?}");
    }
}

#[test]
fn pack_refuses_when_any_named_path_is_missing() {
    let dir = tmp_dir();
    let a = dir.join("a.txt");
    std::fs::write(&a, b"a").unwrap();
    let b = dir.join("b.txt");
    let o = dir.join("out.zip");
    let out = run_output(&[
        "pack",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "-o",
        o.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("b.txt"), "{}", text(&out.stderr));
    assert!(!o.exists());
}

#[cfg(unix)]
#[test]
fn unreadable_input_is_a_usage_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir();
    let p = dir.join("locked.gz");
    std::fs::write(&p, gzip_wrap(b"hi")).unwrap();
    struct Restore<'a>(&'a Path);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o600));
        }
    }
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
    let _restore = Restore(&p);
    let Err(e) = std::fs::File::open(&p) else {
        eprintln!("skipped: root can read a mode-000 file");
        return;
    };
    let ps = p.to_str().unwrap();
    let want = format!("stuffr: usage error: cannot read {ps}: {e}\n");
    for verb in ["cat", "list"] {
        let out = run_output(&[verb, ps]);
        assert_eq!(out.status.code(), Some(2), "{verb}");
        assert_eq!(text(&out.stderr), want, "{verb}");
    }
}

#[cfg(unix)]
#[test]
fn dangling_symlink_is_a_usage_error() {
    let dir = tmp_dir();
    let l = dir.join("x.gz");
    std::os::unix::fs::symlink("gone", &l).unwrap();
    let out = run_output(&["cat", l.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("cannot read"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn directory_input_keeps_its_own_message() {
    let dir = tmp_dir();
    let out = run_output(&["cat", dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("is a directory, and cat reads one archive"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn stdin_is_never_checked() {
    let out = run_with_stdin_output(&["cat", "-"], &gzip_wrap(b"hi"));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"hi");
}

#[cfg(unix)]
#[test]
fn pack_keeps_skipping_an_unreadable_named_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir();
    let a = dir.join("a.txt");
    std::fs::write(&a, b"a").unwrap();
    let l = dir.join("locked.gz");
    std::fs::write(&l, b"x").unwrap();
    struct Restore<'a>(&'a Path);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o600));
        }
    }
    std::fs::set_permissions(&l, std::fs::Permissions::from_mode(0o000)).unwrap();
    let _restore = Restore(&l);
    if std::fs::File::open(&l).is_ok() {
        eprintln!("skipped: root can read a mode-000 file");
        return;
    }
    let o = dir.join("out.zip");
    let out = run_output(&[
        "pack",
        a.to_str().unwrap(),
        l.to_str().unwrap(),
        "-o",
        o.to_str().unwrap(),
    ]);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(o.exists());
    assert!(err.contains("skipped entry"), "{err}");
    assert!(err.contains("could not be opened"), "{err}");
}
