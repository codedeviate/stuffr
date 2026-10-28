//! `stuffr ls` / `stuffr files`: a folder lists what stuffr can open; a file
//! (or `-`) is `stuffr list`, unchanged.
//!
//! Every child runs with `TZ=UTC` (see `run_in_dir_output`) so the date
//! column is fixed text. Old mtimes are fixed instants; recent ones are a day
//! or two before now, and their expected text is computed here with the same
//! `ls -l` rule.

use std::path::Path;
use std::process::Output;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::common::*;

const GZ: &[u8] = &[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3];
const ZIP: &[u8] = b"PK\x03\x04\x14\0\0\0\0\0";
const XZ: &[u8] = &[0xfd, b'7', b'z', b'X', b'Z', 0, 0, 0, 0, 0];

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// A fixed UTC instant at noon (so no zone moves its day).
fn utc(y: i64, m: i64, d: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs((days_from_civil(y, m, d) * 86_400 + 12 * 3600) as u64)
}

/// A whole minute `days` days before now.
fn days_ago(days: u64) -> SystemTime {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    UNIX_EPOCH + Duration::from_secs((now - days * 86_400) / 60 * 60)
}

/// `ls -l`'s recent form, `Mon %e HH:MM`, in UTC.
fn recent(t: SystemTime) -> String {
    let s = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let (_, m, d) = civil_from_days(s.div_euclid(86_400));
    let r = s.rem_euclid(86_400);
    format!(
        "{} {d:>2} {:02}:{:02}",
        MONTHS[(m - 1) as usize],
        r / 3600,
        r % 3600 / 60
    )
}

fn set_mtime(p: &Path, t: SystemTime) {
    let f = std::fs::File::open(p).unwrap();
    f.set_modified(t).unwrap();
}

fn put(dir: &Path, name: &str, magic: &[u8], len: usize, t: SystemTime) {
    let mut bytes = magic.to_vec();
    bytes.resize(len.max(magic.len()), 0);
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    set_mtime(&p, t);
}

fn texts(o: &Output) -> (String, String, Option<i32>) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
        o.status.code(),
    )
}

fn ls(dir: &Path, args: &[&str]) -> (String, String, Option<i32>) {
    texts(&run_in_dir_output(dir, args))
}

/// The spec's option C: a three-archive folder, a subfolder, a text file.
fn sample_tree(dir: &Path) -> (SystemTime, SystemTime) {
    let t_backup = days_ago(1);
    let t_export = days_ago(2);
    put(dir, "backup.tar.gz", GZ, 4_404_019, t_backup);
    put(dir, "photos.zip", ZIP, 1_153_434, utc(2020, 6, 15));
    put(dir, "export", GZ, 831_488, t_export);
    put(dir, "notes.txt", b"hello, world\n", 0, utc(2021, 3, 1));
    let old = dir.join("old");
    std::fs::create_dir(&old).unwrap();
    set_mtime(&old, utc(2019, 1, 5));
    (t_backup, t_export)
}

#[test]
fn lists_a_folder_in_option_c_layout() {
    let dir = tmp_dir();
    let (tb, te) = sample_tree(&dir);
    let (out, err, code) = ls(&dir, &["ls", "."]);
    let want = format!(
        "tar+gzip  4.2M  {}  backup.tar.gz\n\
         gzip      812K  {}  export\n\
         zip       1.1M  Jun 15  2020  photos.zip\n\
         [FOLDER]        Jan  5  2019  old/\n\
         3 of 4 files shown, 1 not openable\n",
        recent(tb),
        recent(te)
    );
    assert_eq!(out, want);
    assert_eq!(err, "");
    assert_eq!(code, Some(0));
}

#[test]
fn no_argument_lists_the_current_folder() {
    let dir = tmp_dir();
    sample_tree(&dir);
    let with_dot = ls(&dir, &["ls", "."]);
    let bare = ls(&dir, &["ls"]);
    assert_eq!(bare, with_dot);
    assert!(bare.0.contains("backup.tar.gz"), "{}", bare.0);
}

#[test]
fn files_is_an_alias_for_folders() {
    let dir = tmp_dir();
    sample_tree(&dir);
    let d = dir.to_str().unwrap();
    assert_eq!(ls(&dir, &["files", d]), ls(&dir, &["ls", d]));
    assert_eq!(ls(&dir, &["files"]), ls(&dir, &["ls"]));
    assert_eq!(
        ls(&dir, &["files", "-r", "-n"]),
        ls(&dir, &["ls", "-r", "-n"])
    );
}

#[test]
fn files_refuses_a_file() {
    let dir = tmp_dir();
    let a = write_fixture_tar_gz(&dir, "x.tar.gz", &[("a.txt", b"alpha")]);
    let want = "stuffr: usage error: files lists a folder; use stuffr list for an archive\n";
    let (out, err, code) = ls(&dir, &["files", a.to_str().unwrap()]);
    assert_eq!((out.as_str(), err.as_str(), code), ("", want, Some(2)));
    let o = run_with_stdin_output(&["files", "-"], b"");
    let (out, err, code) = texts(&o);
    assert_eq!((out.as_str(), err.as_str(), code), ("", want, Some(2)));
}

#[test]
fn recursive_blocks() {
    let dir = tmp_dir();
    put(&dir, "a.gz", GZ, 10, utc(2020, 6, 15));
    put(&dir, "notes.txt", b"text", 0, utc(2020, 6, 15));
    std::fs::create_dir_all(dir.join("old/deeper")).unwrap();
    std::fs::create_dir_all(dir.join("empty")).unwrap();
    std::fs::create_dir_all(dir.join(".hidden")).unwrap();
    put(&dir.join("old"), "b.xz", XZ, 10, utc(2019, 1, 5));
    put(&dir.join("old/deeper"), "c.zip", ZIP, 2048, utc(2018, 2, 3));
    put(&dir.join(".hidden"), "d.gz", GZ, 10, utc(2018, 2, 3));
    let (out, err, code) = ls(&dir, &["ls", "-r"]);
    let want = "gzip   10B  Jun 15  2020  a.gz\n\
                \n\
                old/:\n\
                xz     10B  Jan  5  2019  b.xz\n\
                \n\
                old/deeper/:\n\
                zip   2.0K  Feb  3  2018  c.zip\n\
                3 of 4 files shown, 1 not openable\n";
    assert_eq!(out, want);
    assert_eq!(err, "");
    assert_eq!(code, Some(0));
}

#[test]
fn by_name_sorts_by_name() {
    let dir = tmp_dir();
    put(&dir, "a.gz", GZ, 10, utc(2019, 1, 1));
    put(&dir, "b.zip", ZIP, 10, utc(2020, 1, 1));
    put(&dir, "c.xz", XZ, 10, utc(2018, 1, 1));
    let newest = "zip   10B  Jan  1  2020  b.zip\n\
                  gzip  10B  Jan  1  2019  a.gz\n\
                  xz    10B  Jan  1  2018  c.xz\n";
    let by_name = "gzip  10B  Jan  1  2019  a.gz\n\
                   zip   10B  Jan  1  2020  b.zip\n\
                   xz    10B  Jan  1  2018  c.xz\n";
    assert_eq!(ls(&dir, &["ls"]).0, newest);
    assert_eq!(ls(&dir, &["ls", "-n"]).0, by_name);
    assert_eq!(ls(&dir, &["ls", "--by-name"]).0, by_name);
}

#[test]
fn footer_omitted_when_everything_openable() {
    let dir = tmp_dir();
    put(&dir, "a.gz", GZ, 10, utc(2019, 1, 1));
    put(&dir, ".hidden.txt", b"not counted", 0, utc(2019, 1, 1));
    let (out, err, code) = ls(&dir, &["ls"]);
    assert_eq!(out, "gzip  10B  Jan  1  2019  a.gz\n");
    assert_eq!((err.as_str(), code), ("", Some(0)));
}

#[test]
fn empty_folder_prints_nothing_exit_0() {
    let dir = tmp_dir();
    assert_eq!(ls(&dir, &["ls"]), (String::new(), String::new(), Some(0)));
    assert_eq!(
        ls(&dir, &["ls", "-r"]),
        (String::new(), String::new(), Some(0))
    );
}

#[test]
fn json_shape() {
    let dir = tmp_dir();
    let (tb, _) = sample_tree(&dir);
    let o = run_in_dir_output(&dir, &["ls", "--json"]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 4);
    let first = &entries[0];
    assert_eq!(first["path"], "backup.tar.gz");
    assert_eq!(first["kind"], "file");
    assert_eq!(first["format"], "tar over gzip");
    assert_eq!(first["size"], 4_404_019);
    let secs = tb.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let r = secs.rem_euclid(86_400);
    let want = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        r / 3600,
        r % 3600 / 60,
        r % 60
    );
    assert_eq!(first["modified"], want.as_str());
    let folder = &entries[3];
    assert_eq!(folder["path"], "old");
    assert_eq!(folder["kind"], "folder");
    assert!(folder["format"].is_null());
    assert!(folder["size"].is_null());
    assert_eq!(folder["modified"], "2019-01-05T12:00:00Z");
    assert_eq!(entries[2]["format"], "zip");
    assert_eq!(v["shown"], 3);
    assert_eq!(v["skipped"], 1);
    assert_eq!(v["warnings"], serde_json::json!([]));

    // With -r the path is relative to the listed folder.
    put(&dir.join("old"), "b.xz", XZ, 10, utc(2019, 1, 5));
    let o = run_in_dir_output(&dir, &["ls", "-r", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let paths: Vec<&str> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["backup.tar.gz", "export", "photos.zip", "old/b.xz"]);
}

#[test]
fn a_file_argument_is_list() {
    let dir = tmp_dir();
    let a = write_fixture_tar_gz(&dir, "x.tar.gz", &[("a.txt", b"alpha"), ("b/c", b"")]);
    let a = a.to_str().unwrap();
    let t = dir.join("t.txt");
    std::fs::write(&t, b"just text\n").unwrap();
    let t = t.to_str().unwrap();
    for args in [
        vec![a],
        vec!["--json", a],
        vec!["--strict-fidelity", a],
        vec!["--max-ratio", "5", a],
        vec![t],
    ] {
        let mut l = vec!["ls"];
        l.extend(&args);
        let mut li = vec!["list"];
        li.extend(&args);
        let got = ls(&dir, &l);
        assert_eq!(got, ls(&dir, &li), "{args:?}");
        if args == [a] {
            assert!(got.0.contains("a.txt") && got.2 == Some(0), "{got:?}");
        }
        if args == [t] {
            assert_ne!(got.2, Some(0), "{got:?}");
        }
    }
    let bytes = std::fs::read(a).unwrap();
    let via_ls = texts(&run_with_stdin_output(&["ls", "-"], &bytes));
    let via_list = texts(&run_with_stdin_output(&["list", "-"], &bytes));
    assert_eq!(via_ls, via_list);
    assert!(via_ls.0.contains("a.txt"), "{via_ls:?}");
}

#[test]
fn folder_flags_with_a_file_are_usage_errors() {
    let dir = tmp_dir();
    let a = write_fixture_tar_gz(&dir, "x.tar.gz", &[("a.txt", b"alpha")]);
    let a = a.to_str().unwrap();
    for (flag, named) in [
        ("-r", "-r"),
        ("--recursive", "-r"),
        ("-a", "-a"),
        ("--all", "-a"),
        ("-n", "-n"),
        ("--by-name", "-n"),
    ] {
        let want = format!("stuffr: usage error: {named} applies to a folder, not a file\n");
        let (out, err, code) = ls(&dir, &["ls", flag, a]);
        assert_eq!(
            (out.as_str(), err.as_str(), code),
            ("", want.as_str(), Some(2))
        );
        let (out, err, code) = texts(&run_with_stdin_output(&["ls", flag, "-"], b""));
        assert_eq!(
            (out.as_str(), err.as_str(), code),
            ("", want.as_str(), Some(2))
        );
    }
    // The first of several is named.
    let (_, err, _) = ls(&dir, &["ls", "-n", "-r", a]);
    assert_eq!(
        err,
        "stuffr: usage error: -r applies to a folder, not a file\n"
    );
}

#[test]
fn list_flags_with_a_folder_are_usage_errors() {
    let dir = tmp_dir();
    let d = dir.to_str().unwrap();
    for (args, named) in [
        (vec!["--max-ratio", "5"], "--max-ratio"),
        (vec!["--memory-limit", "1G"], "--memory-limit"),
        (vec!["--strict-fidelity"], "--strict-fidelity"),
        (
            vec!["--strict-fidelity", "--memory-limit", "1G"],
            "--memory-limit",
        ),
    ] {
        let want = format!("stuffr: usage error: {named} applies to an archive, not a folder\n");
        for with_path in [true, false] {
            let mut a = vec!["ls"];
            a.extend(&args);
            if with_path {
                a.push(d);
            }
            let (out, err, code) = ls(&dir, &a);
            assert_eq!(
                (out.as_str(), err.as_str(), code),
                ("", want.as_str(), Some(2)),
                "{a:?}"
            );
        }
    }
}

#[test]
fn list_still_refuses_a_folder() {
    let dir = tmp_dir();
    let (out, err, code) = ls(&dir, &["list", dir.to_str().unwrap()]);
    assert_eq!((out.as_str(), code), ("", Some(2)));
    assert!(
        err.contains("is a directory") && err.contains("stuffr pack"),
        "{err}"
    );
}

#[test]
fn list_has_no_ls_alias_but_ls_still_lists_archives() {
    let dir = tmp_dir();
    let a = write_fixture_tar_gz(&dir, "x.tar.gz", &[("a.txt", b"alpha")]);
    let a = a.to_str().unwrap();
    let (out, err, code) = ls(&dir, &["list", "-r", a]);
    assert_eq!((out.as_str(), code), ("", Some(2)));
    assert!(err.contains("unexpected argument '-r'"), "{err}");
    let (out, _, code) = ls(&dir, &["ls", a]);
    assert_eq!(code, Some(0));
    assert!(out.contains("a.txt"), "{out}");
    let help = texts(&run_output(&["list", "--help"])).0;
    assert!(!help.contains("aliases"), "{help}");
}

#[test]
fn missing_path_is_exit_2() {
    let dir = tmp_dir();
    let p = dir.join("nope");
    let e = std::fs::metadata(&p).unwrap_err();
    let (out, err, code) = ls(&dir, &["ls", p.to_str().unwrap()]);
    let want = format!("stuffr: usage error: cannot read {}: {e}\n", p.display());
    assert_eq!(
        (out.as_str(), err.as_str(), code),
        ("", want.as_str(), Some(2))
    );
    let (_, err2, code2) = ls(&dir, &["files", p.to_str().unwrap()]);
    assert_eq!((err2.as_str(), code2), (want.as_str(), Some(2)));
}

#[cfg(unix)]
#[test]
fn unreadable_folder_argument_is_exit_2() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root can read a mode-000 folder");
        return;
    }
    let dir = tmp_dir();
    let locked = dir.join("locked");
    std::fs::create_dir(&locked).unwrap();
    put(&locked, "a.gz", GZ, 10, utc(2020, 6, 15));
    struct Restore<'a>(&'a Path);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    // Write and search but no read: `read_dir` fails, yet a child can still
    // chdir into it for the implicit `.` case.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o300)).unwrap();
    let _restore = Restore(&locked);
    let e = std::fs::read_dir(&locked).unwrap_err();
    let want = format!("stuffr: usage error: cannot read locked: {e}\n");
    for args in [
        &["ls", "locked"][..],
        &["ls", "-r", "locked"],
        &["files", "locked"],
    ] {
        let (out, err, code) = ls(&dir, args);
        assert_eq!(
            (out.as_str(), err.as_str(), code),
            ("", want.as_str(), Some(2)),
            "{args:?}"
        );
    }
    // The implicit `.` too.
    let (out, err, code) = ls(&locked, &["ls"]);
    let want = format!("stuffr: usage error: cannot read .: {e}\n");
    assert_eq!(
        (out.as_str(), err.as_str(), code),
        ("", want.as_str(), Some(2))
    );
}

#[cfg(unix)]
#[test]
fn unreadable_inside_is_exit_4() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root can read a mode-000 file");
        return;
    }
    let dir = tmp_dir();
    put(&dir, "a.gz", GZ, 10, utc(2020, 6, 15));
    put(&dir, "secret.gz", GZ, 10, utc(2020, 6, 15));
    let secret = dir.join("secret.gz");
    struct Restore<'a>(&'a Path);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o600));
        }
    }
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
    let _restore = Restore(&secret);
    let e = std::fs::File::open(&secret).unwrap_err();
    let (out, err, code) = ls(&dir, &["ls"]);
    assert_eq!(
        out,
        "gzip  10B  Jun 15  2020  a.gz\n1 of 2 files shown, 1 not openable\n"
    );
    assert_eq!(err, format!("stuffr: cannot read secret.gz: {e}\n"));
    assert_eq!(code, Some(4));
    // The JSON carries the warning too, and the exit is the same.
    let o = run_in_dir_output(&dir, &["ls", "--json"]);
    assert_eq!(o.status.code(), Some(4));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(
        v["warnings"],
        serde_json::json!([format!("cannot read secret.gz: {e}")])
    );
}

#[cfg(unix)]
#[test]
fn odd_names_are_escaped_in_rows_and_real_in_json() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = tmp_dir();
    // A non-UTF-8 byte where the filesystem takes one (APFS refuses it with
    // EILSEQ); a bidi override, which fmt_name escapes too, where it does not.
    let mut p = dir.join(OsStr::from_bytes(b"a\nb\xff.gz"));
    let mut shown = "a\\nb\u{fffd}.gz";
    let mut real = "a\nb\u{fffd}.gz";
    if std::fs::write(&p, GZ).is_err() {
        p = dir.join("a\nb\u{202e}.gz");
        shown = "a\\nb\\u{202e}.gz";
        real = "a\nb\u{202e}.gz";
        std::fs::write(&p, GZ).unwrap();
    }
    set_mtime(&p, utc(2020, 6, 15));
    put(&dir, "plain.zip", ZIP, 2048, utc(2019, 6, 15));
    let (out, _, code) = ls(&dir, &["ls"]);
    assert_eq!(code, Some(0));
    assert_eq!(
        out,
        format!(
            "gzip   10B  Jun 15  2020  {shown}\n\
             zip   2.0K  Jun 15  2019  plain.zip\n"
        )
    );
    // The same escaping `list` gives an entry name.
    let a = write_fixture_tar_gz(&dir, "x.tgz", &[("a\nb", b"")]);
    let listed = texts(&run_output(&["list", a.to_str().unwrap()])).0;
    assert!(listed.ends_with("  a\\nb\n"), "{listed:?}");
    let o = run_in_dir_output(&dir, &["ls", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    // JSON carries the real name (lossy only for non-UTF-8), as `list --json`
    // does: JSON's own escaping keeps it unambiguous (ruling T4-d).
    assert_eq!(v["entries"][1]["path"], real);
}
