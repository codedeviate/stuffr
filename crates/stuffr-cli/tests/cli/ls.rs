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

/// What a fixture file holds: a real stream of its format (`ls` lists only
/// what confirms, so a magic followed by zeros, as 0.21.0's fixtures were,
/// no longer stands in for one), or plain bytes.
#[derive(Clone, Copy)]
enum Fixture<'a> {
    /// A gzip of zeros (stored blocks), exactly the given size.
    Gz,
    /// A gzip of a real tar padded with zeros, exactly the given size.
    TarGz,
    /// A stored zip of one entry, exactly the given size (at least 100).
    Zip,
    /// The empty xz stream; always 32 bytes.
    Xz,
    /// These bytes as they are.
    Bytes(&'a [u8]),
}
use Fixture::{Bytes, Gz, TarGz, Xz, Zip};

/// The size of `Xz`.
const XZ_LEN: usize = 32;

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

fn fixture(what: Fixture<'_>, len: usize) -> Vec<u8> {
    match what {
        Gz => stored_gzip(&[], len),
        TarGz => stored_gzip(&small_tar(), len),
        Zip => stored_zip(len),
        Xz => {
            assert_eq!(len, XZ_LEN, "the xz fixture has one size");
            EMPTY_XZ.to_vec()
        }
        Bytes(b) => b.to_vec(),
    }
}

/// One `ls` row, its columns padded as `ls` pads them: FORMAT to `fw`
/// left-aligned, SIZE to `sw` right-aligned.
fn row(format: &str, size: &str, date: &str, name: &str, fw: usize, sw: usize) -> String {
    format!("{format:<fw$}  {size:>sw$}  {date}  {name}\n")
}

fn put(dir: &Path, name: &str, what: Fixture<'_>, len: usize, t: SystemTime) {
    let bytes = fixture(what, len);
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
    put(dir, "backup.tar.gz", TarGz, 4_404_019, t_backup);
    put(dir, "photos.zip", Zip, 1_153_434, utc(2020, 6, 15));
    put(dir, "export", Gz, 831_488, t_export);
    put(
        dir,
        "notes.txt",
        Bytes(b"hello, world\n"),
        0,
        utc(2021, 3, 1),
    );
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
    put(&dir, "a.gz", Gz, 30, utc(2020, 6, 15));
    put(&dir, "notes.txt", Bytes(b"text"), 0, utc(2020, 6, 15));
    std::fs::create_dir_all(dir.join("old/deeper")).unwrap();
    std::fs::create_dir_all(dir.join("empty")).unwrap();
    std::fs::create_dir_all(dir.join(".hidden")).unwrap();
    put(&dir.join("old"), "b.xz", Xz, XZ_LEN, utc(2019, 1, 5));
    put(&dir.join("old/deeper"), "c.zip", Zip, 2048, utc(2018, 2, 3));
    put(&dir.join(".hidden"), "d.gz", Gz, 30, utc(2018, 2, 3));
    let (out, err, code) = ls(&dir, &["ls", "-r"]);
    let want = format!(
        "{}\nold/:\n{}\nold/deeper/:\n{}3 of 4 files shown, 1 not openable\n",
        row("gzip", "30B", "Jun 15  2020", "a.gz", 4, 4),
        row("xz", "32B", "Jan  5  2019", "b.xz", 4, 4),
        row("zip", "2.0K", "Feb  3  2018", "c.zip", 4, 4),
    );
    assert_eq!(out, want);
    assert_eq!(err, "");
    assert_eq!(code, Some(0));
}

#[test]
fn by_name_sorts_by_name() {
    let dir = tmp_dir();
    put(&dir, "a.gz", Gz, 30, utc(2019, 1, 1));
    put(&dir, "b.zip", Zip, 100, utc(2020, 1, 1));
    put(&dir, "c.xz", Xz, XZ_LEN, utc(2018, 1, 1));
    let a = row("gzip", "30B", "Jan  1  2019", "a.gz", 4, 4);
    let b = row("zip", "100B", "Jan  1  2020", "b.zip", 4, 4);
    let c = row("xz", "32B", "Jan  1  2018", "c.xz", 4, 4);
    let newest = format!("{b}{a}{c}");
    let by_name = format!("{a}{b}{c}");
    assert_eq!(ls(&dir, &["ls"]).0, newest);
    assert_eq!(ls(&dir, &["ls", "-n"]).0, by_name);
    assert_eq!(ls(&dir, &["ls", "--by-name"]).0, by_name);
}

#[test]
fn footer_omitted_when_everything_openable() {
    let dir = tmp_dir();
    put(&dir, "a.gz", Gz, 30, utc(2019, 1, 1));
    put(
        &dir,
        ".hidden.txt",
        Bytes(b"not counted"),
        0,
        utc(2019, 1, 1),
    );
    let (out, err, code) = ls(&dir, &["ls"]);
    assert_eq!(out, row("gzip", "30B", "Jan  1  2019", "a.gz", 4, 3));
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
    put(&dir.join("old"), "b.xz", Xz, XZ_LEN, utc(2019, 1, 5));
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
    put(&locked, "a.gz", Gz, 30, utc(2020, 6, 15));
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
    put(&dir, "a.gz", Gz, 30, utc(2020, 6, 15));
    put(&dir, "secret.gz", Gz, 30, utc(2020, 6, 15));
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
        row("gzip", "30B", "Jun 15  2020", "a.gz", 4, 3) + "1 of 2 files shown, 1 not openable\n"
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
    let gz = fixture(Gz, 30);
    if std::fs::write(&p, &gz).is_err() {
        p = dir.join("a\nb\u{202e}.gz");
        shown = "a\\nb\\u{202e}.gz";
        real = "a\nb\u{202e}.gz";
        std::fs::write(&p, &gz).unwrap();
    }
    set_mtime(&p, utc(2020, 6, 15));
    put(&dir, "plain.zip", Zip, 2048, utc(2019, 6, 15));
    let (out, _, code) = ls(&dir, &["ls"]);
    assert_eq!(code, Some(0));
    assert_eq!(
        out,
        row("gzip", "30B", "Jun 15  2020", shown, 4, 4)
            + &row("zip", "2.0K", "Jun 15  2019", "plain.zip", 4, 4)
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

// ---------------------------------------------------------------------------
// Truthful identification: `ls` lists only what confirms.
// ---------------------------------------------------------------------------

/// The footer `ls` prints when something was not openable.
fn footer(shown: usize, files: usize) -> String {
    format!(
        "{shown} of {files} files shown, {} not openable\n",
        files - shown
    )
}

#[test]
fn ls_hides_disk_images() {
    let dir = tmp_dir();
    std::fs::write(dir.join("synthetic.dmg"), crate::foreign::synthetic_dmg()).unwrap();
    let images = 1 + crate::foreign::real_disk_images(&dir).len();
    put(&dir, "a.gz", Gz, 30, utc(2020, 6, 15));
    let (out, err, code) = ls(&dir, &["ls"]);
    let want = row("gzip", "30B", "Jun 15  2020", "a.gz", 4, 3) + &footer(1, images + 1);
    assert_eq!(
        (out.as_str(), err.as_str(), code),
        (want.as_str(), "", Some(0))
    );
}

#[cfg(unix)]
#[test]
fn ls_hides_a_symlink_to_a_disk_image() {
    let elsewhere = tmp_dir();
    let image = elsewhere.join("x.dmg");
    std::fs::write(&image, crate::foreign::synthetic_dmg()).unwrap();
    let dir = tmp_dir();
    std::os::unix::fs::symlink(&image, dir.join("link.dmg")).unwrap();
    std::os::unix::fs::symlink(&image, dir.join("link")).unwrap();
    put(&dir, "a.gz", Gz, 30, utc(2020, 6, 15));
    let (out, err, code) = ls(&dir, &["ls"]);
    let want = row("gzip", "30B", "Jun 15  2020", "a.gz", 4, 3) + &footer(1, 3);
    assert_eq!(
        (out.as_str(), err.as_str(), code),
        (want.as_str(), "", Some(0))
    );
}

/// recon's `headers.js`: source text with `ustar` at offset 257 (the shape
/// `tar_rejects_ustar_in_source_code` pins).
fn ustar_in_source() -> Vec<u8> {
    let line = "export function headers(req, res) {\n  return { 'content-type': 'text/x' };\n}\n";
    let mut text = line.repeat(600 / line.len() + 1).into_bytes();
    text.truncate(600);
    text[257..262].copy_from_slice(b"ustar");
    text
}

#[test]
fn ls_hides_recon_false_positives() {
    let dir = tmp_dir();
    put(
        &dir,
        "pixels.scube",
        Bytes(&crate::foreign::arc_pixel_like()),
        0,
        utc(2020, 1, 1),
    );
    put(
        &dir,
        "headers.js",
        Bytes(&ustar_in_source()),
        0,
        utc(2020, 1, 1),
    );
    put(
        &dir,
        "pixels.arc",
        Bytes(&crate::foreign::arc_pixel_like()),
        0,
        utc(2020, 1, 1),
    );
    put(
        &dir,
        "headers.tar",
        Bytes(&ustar_in_source()),
        0,
        utc(2020, 1, 1),
    );
    let (out, err, code) = ls(&dir, &["ls"]);
    assert_eq!(
        (out.as_str(), err.as_str(), code),
        (footer(0, 4).as_str(), "", Some(0))
    );
}

#[test]
fn ls_lists_gzip_not_tar_gzip_for_a_gzipped_non_tar() {
    let dir = tmp_dir();
    let gz = gzip_wrap(&ustar_in_source());
    put(&dir, "headers.js.gz", Bytes(&gz), 0, utc(2020, 1, 1));
    put(&dir, "x.tar.gz", Bytes(&gz), 0, utc(2019, 1, 1));
    let size = human(gz.len());
    let (out, err, code) = ls(&dir, &["ls"]);
    let want = row(
        "gzip",
        &size,
        "Jan  1  2020",
        "headers.js.gz",
        4,
        size.len(),
    ) + &row("gzip", &size, "Jan  1  2019", "x.tar.gz", 4, size.len());
    assert_eq!(
        (out.as_str(), err.as_str(), code),
        (want.as_str(), "", Some(0))
    );
}

/// `ls`'s size cell for a size under 1 KiB.
fn human(len: usize) -> String {
    assert!(len < 1000, "{len}");
    format!("{len}B")
}

#[test]
fn ls_keeps_zip_documents() {
    let dir = tmp_dir();
    let src = tmp_dir();
    let zip = std::fs::read(write_zip_via_pack(&src, &[("doc.xml", b"<doc/>\n")])).unwrap();
    for name in ["model.3mf", "letter.docx", "app.jar"] {
        put(&dir, name, Bytes(&zip), 0, utc(2020, 1, 1));
    }
    let o = run_in_dir_output(&dir, &["ls", "--json"]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let got: Vec<(String, String)> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["path"].as_str().unwrap().to_string(),
                e["format"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let want: Vec<(String, String)> = ["app.jar", "letter.docx", "model.3mf"]
        .iter()
        .map(|n| (n.to_string(), "zip".to_string()))
        .collect();
    assert_eq!(got, want);
    assert_eq!(v["skipped"], 0);
}

#[test]
fn ls_lists_brotli_by_name() {
    let dir = tmp_dir();
    let src = dir.join("plain.txt");
    std::fs::write(&src, b"hello hello hello hello brotli").unwrap();
    let br = dir.join("out.br");
    let o = run_output(&["pack", src.to_str().unwrap(), "-o", br.to_str().unwrap()]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    std::fs::remove_file(&src).unwrap();
    let o = run_in_dir_output(&dir, &["ls", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["entries"][0]["path"], "out.br");
    assert_eq!(v["entries"][0]["format"], "brotli");
}

#[test]
fn ls_lists_lzma_only_when_its_header_checks_out() {
    let dir = tmp_dir();
    let src = dir.join("plain.txt");
    std::fs::write(&src, b"hello hello hello hello lzma").unwrap();
    let lzma = dir.join("real.lzma");
    let o = run_output(&["pack", src.to_str().unwrap(), "-o", lzma.to_str().unwrap()]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    std::fs::remove_file(&src).unwrap();
    // Properties byte 0xff is past 224: no lzma tool writes it.
    let mut bad = std::fs::read(&lzma).unwrap();
    bad[0] = 0xff;
    std::fs::write(dir.join("fake.lzma"), bad).unwrap();
    std::fs::write(dir.join("text.lzma"), b"just some text, named lzma\n").unwrap();
    let o = run_in_dir_output(&dir, &["ls", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{v}");
    assert_eq!(entries[0]["path"], "real.lzma");
    assert_eq!(entries[0]["format"], "lzma");
    assert_eq!(v["skipped"], 2);
}

#[test]
fn a_corrupt_tar_inside_a_named_gzip_is_still_corrupt() {
    let dir = tmp_dir();
    let mut tar = small_tar();
    // Break the header checksum (offset 148, eight octal digits).
    tar[148] = if tar[148] == b'1' { b'2' } else { b'1' };
    put(
        &dir,
        "x.tar.gz",
        Bytes(&gzip_wrap(&tar)),
        0,
        utc(2020, 1, 1),
    );
    let (_, _, code) = ls(&dir, &["list", "x.tar.gz"]);
    assert_eq!(code, Some(5));
    let o = run_in_dir_output(&dir, &["ls", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["entries"][0]["path"], "x.tar.gz");
    assert_eq!(v["entries"][0]["format"], "gzip");
}

/// Review Focus 2: a small real `.tar.gz` (the whole file inside the probe
/// window) lists as `tar+gzip`; a `.tar.xz` whose first 4096 bytes decode
/// to less than one tar header lists as `xz` — neither is ever hidden.
#[test]
fn small_and_slow_archives_stay_listed() {
    let dir = tmp_dir();
    let tgz = write_fixture_tar_gz(&dir, "small.tar.gz", &[("a.txt", b"alpha")]);
    let tgz_len = std::fs::metadata(&tgz).unwrap().len();
    assert!(tgz_len < 4096, "{tgz_len}");
    let o = run_in_dir_output(&dir, &["ls", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["entries"][0]["format"], "tar over gzip", "{v}");

    // One-byte xz blocks: each costs 23 bytes of framing, so the window
    // decodes to well under 512 bytes of the tar.
    let xz = one_byte_block_xz(&small_tar());
    assert!(xz.len() > 4096, "{}", xz.len());
    std::fs::write(dir.join("slow.tar.xz"), &xz).unwrap();
    let o = run_in_dir_output(&dir, &["ls", "-n", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let formats: Vec<(&str, &str)> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["path"].as_str().unwrap(), e["format"].as_str().unwrap()))
        .collect();
    assert_eq!(
        formats,
        [("slow.tar.xz", "xz"), ("small.tar.gz", "tar over gzip")],
        "{v}"
    );
    // The verbs still read it whole.
    let (out, _, code) = ls(&dir, &["list", "slow.tar.xz"]);
    assert_eq!(code, Some(0));
    assert!(out.contains("a.txt"), "{out}");
}

/// The xz varint: seven bits at a time, low first, high bit = more.
fn xz_varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// A real xz stream (per the .xz file format 1.2.0) holding `data` one byte
/// per block: LZMA2 with an uncompressed chunk per block, CRC32 checks.
/// `xz --block-size=1` writes this shape; built by hand so the test needs no
/// tool and both tiers read the same bytes.
fn one_byte_block_xz(data: &[u8]) -> Vec<u8> {
    let flags = [0u8, 1]; // check type 1: CRC32
    let mut out = vec![0xfd, b'7', b'z', b'X', b'Z', 0];
    out.extend_from_slice(&flags);
    out.extend_from_slice(&salvage_fixture_crc32(&flags).to_le_bytes());
    // Block header: size byte (12 / 4 - 1), block flags (one filter, no
    // sizes), LZMA2 (0x21) with one property byte (dictionary 0 = 4 KiB),
    // padding to 8, CRC32.
    let mut header = vec![2u8, 0, 0x21, 1, 0, 0, 0, 0];
    header.extend_from_slice(&salvage_fixture_crc32(&header.clone()).to_le_bytes());
    for &b in data {
        out.extend_from_slice(&header);
        // An uncompressed chunk with a dictionary reset, one byte, the end
        // marker; padded to four; the check.
        out.extend_from_slice(&[1, 0, 0, b, 0, 0, 0, 0]);
        out.extend_from_slice(&salvage_fixture_crc32(&[b]).to_le_bytes());
    }
    let mut index = vec![0u8];
    xz_varint(&mut index, data.len() as u64);
    for _ in data {
        xz_varint(&mut index, 12 + 5 + 4); // unpadded size
        xz_varint(&mut index, 1); // uncompressed size
    }
    while index.len() % 4 != 0 {
        index.push(0);
    }
    index.extend_from_slice(&salvage_fixture_crc32(&index.clone()).to_le_bytes());
    let backward = (index.len() / 4 - 1) as u32;
    out.extend_from_slice(&index);
    let mut footer = backward.to_le_bytes().to_vec();
    footer.extend_from_slice(&flags);
    out.extend_from_slice(&salvage_fixture_crc32(&footer).to_le_bytes());
    out.extend_from_slice(&footer);
    out.extend_from_slice(b"YZ");
    out
}
