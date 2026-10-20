//! The unzip side of the differential harness against itself (0.16.0 Task
//! 2): the tree snapshot must see what unzip changes (bytes, modes, times,
//! link targets and, on macOS, quarantine), the comparison must name each
//! single difference, `zip_with` must build archives the reference accepts,
//! and the forced flavour must reach stuffr's side only.
//!
//! Nothing here runs stuffr as `unzip`: the sensitivity test compares two
//! hand-made directories, and the round trip and environment tests run real
//! programs on the reference side only.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    fn scratch(tag: &str) -> ScratchDir {
        let d = ScratchDir::at(std::env::temp_dir().join(format!(
            "stuffr-unzip-selftest-{tag}-{}",
            std::process::id()
        )));
        fs::create_dir_all(&*d).unwrap();
        d
    }

    fn chmod(p: &Path, mode: u32) {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The mtime of a file or a directory (opened read-only: the owner may
    /// set its times).
    fn set_mtime(p: &Path, secs: u64) {
        fs::File::open(p)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    }

    #[test]
    fn tree_sees_modes_times_symlinks_and_quarantine() {
        let d = scratch("tree");
        fs::write(d.join("a.zip"), b"PK\x05\x06").unwrap();
        fs::create_dir(d.join("dir")).unwrap();
        fs::write(d.join("dir/f"), b"hello").unwrap();
        chmod(&d.join("dir/f"), 0o640);
        set_mtime(&d.join("dir/f"), 1_200_000_000);
        symlink("../nowhere", d.join("dir/l")).unwrap();
        #[cfg(target_os = "macos")]
        set_quarantine(&d.join("dir/f"), b"0081;5f000000;Test;");
        chmod(&d.join("dir"), 0o750);
        set_mtime(&d.join("dir"), 1_100_000_000);

        let t = snapshot_unzip_tree(&d, &["a.zip"]);
        let keys: Vec<&[u8]> = t.keys().map(Vec::as_slice).collect();
        assert_eq!(keys, [&b"dir"[..], b"dir/f", b"dir/l"], "a.zip is excluded");
        let quarantine = if cfg!(target_os = "macos") {
            Some(b"0081;5f000000;Test;".to_vec())
        } else {
            None
        };
        assert_eq!(
            t[&b"dir/f"[..]],
            UnzipNode::File {
                bytes: b"hello".to_vec(),
                mode: 0o640,
                mtime: 1_200_000_000,
                quarantine,
            }
        );
        assert_eq!(
            t[&b"dir"[..]],
            UnzipNode::Dir {
                mode: 0o750,
                mtime: 1_100_000_000,
                quarantine: None,
            }
        );
        assert_eq!(
            t[&b"dir/l"[..]],
            UnzipNode::Symlink {
                target: b"../nowhere".to_vec(),
                quarantine: None,
            }
        );
        // Without the exclusion the archive is part of the tree.
        assert!(snapshot_unzip_tree(&d, &[]).contains_key(&b"a.zip"[..]));
    }

    /// Two directories alike but for one byte of `x`, the mode of `y` and the
    /// target of `l`.
    fn two_trees() -> (ScratchDir, ScratchDir) {
        let (a, b) = (scratch("same-a"), scratch("same-b"));
        for (d, x, ymode, l) in [(&a, b"abc", 0o644, "t"), (&b, b"abd", 0o600, "u")] {
            fs::write(d.join("x"), x).unwrap();
            fs::write(d.join("y"), b"y").unwrap();
            chmod(&d.join("y"), ymode);
            symlink(l, d.join("l")).unwrap();
            for f in ["x", "y"] {
                set_mtime(&d.join(f), 1_000_000_000);
            }
        }
        (a, b)
    }

    fn unzip_run(dir: &Path) -> UnzipRun {
        UnzipRun {
            code: 0,
            stdout: b"Archive:  a.zip\n".to_vec(),
            stderr: String::new(),
            tree: snapshot_unzip_tree(dir, &[]),
            start: now_secs(),
            tty_mode: None,
        }
    }

    #[test]
    fn assert_same_unzip_reports_each_difference() {
        let c = unzip_case("unzip", vec!["a.zip"], vec![]);
        let (a, b) = two_trees();
        let (r, mut s) = (unzip_run(&a), unzip_run(&b));
        assert!(unzip_differences(&c, &r, &r).is_empty());

        let d = unzip_differences(&c, &r, &s);
        assert_eq!(d.len(), 3, "{d:#?}");
        assert!(
            d.iter().any(|x| x.contains("x") && x.contains("bytes")),
            "{d:#?}"
        );
        assert!(
            d.iter()
                .any(|x| x.contains("y") && x.contains("mode reference 644 vs stuffr 600")),
            "{d:#?}"
        );
        assert!(
            d.iter()
                .any(|x| x.contains("l") && x.contains("link target")),
            "{d:#?}"
        );

        s.code = 9;
        s.stdout = b"Archive:  b.zip\n".to_vec();
        s.stderr = "unzip:  cannot find\n".to_owned();
        let d = unzip_differences(&c, &r, &s);
        assert_eq!(d.len(), 6, "{d:#?}");
        for what in ["exit code", "stdout", "stderr"] {
            assert!(d.iter().any(|x| x.starts_with(what)), "{what}: {d:#?}");
        }
        let p = std::panic::catch_unwind(|| compare_unzip(&c, &r, &s)).unwrap_err();
        assert!(panic_text(p).contains("in 6 way(s)"));
    }

    /// R11: another Apple build's `-v` gives a header naming the lines that
    /// differ and the drift prefix; the recorded one, or none, gives nothing.
    #[test]
    fn apple_drift_note_names_the_differing_identity_lines() {
        assert!(apple_drift_note(None).is_none());
        assert!(apple_drift_note(Some(APPLE_UNZIP_IDENTITY)).is_none());
        let other = APPLE_UNZIP_IDENTITY.replace("on Aug  8 2026.", "on Jan  1 2027.");
        let (head, prefix) = apple_drift_note(Some(&other)).unwrap();
        assert_eq!(prefix, "[apple drift?] ");
        assert!(
            head.starts_with("[the installed /usr/bin/unzip is not the build"),
            "{head}"
        );
        let recorded = head.find("recorded -v only:").unwrap();
        let installed = head.find("installed -v only:").unwrap();
        assert!(
            head[recorded..installed].contains("on Aug  8 2026."),
            "{head}"
        );
        assert!(head[installed..].contains("on Jan  1 2027."), "{head}");
        assert!(
            !head.contains("SET_DIR_ATTRIB"),
            "only differing lines: {head}"
        );
    }

    #[test]
    fn banners_are_masked_only_when_each_side_prints_its_own() {
        let apple = "UnZip 6.00 of 20 April 2009, by Info-ZIP, with modifications by Apple Inc.\n";
        let ours = format!(
            "UnZip 6.00 of 20 April 2009, by stuffr {} (altered; original by Info-ZIP, \
             with modifications by Apple Inc.).\n",
            env!("CARGO_PKG_VERSION")
        );
        let ubuntu_ours = format!(
            "UnZip 6.00 of 20 April 2009, by stuffr {} (altered; Debian's build, original by \
             Info-ZIP).\n",
            env!("CARGO_PKG_VERSION")
        );
        let run = |out: &str| UnzipRun {
            code: 0,
            stdout: format!("{out}\nUsage: unzip\n").into_bytes(),
            stderr: String::new(),
            tree: Default::default(),
            start: now_secs(),
            tty_mode: None,
        };
        let mut c = unzip_case("unzip", vec![], vec![]);
        c.unzip_flavour = Some("apple");
        assert!(unzip_differences(&c, &run(apple), &run(&ours)).is_empty());
        // The other flavour's banner, or the reference's own text, differs.
        assert_eq!(
            unzip_differences(&c, &run(apple), &run(&ubuntu_ours)).len(),
            1
        );
        assert_eq!(
            unzip_differences(&c, &run(apple), &run("UnZip 6.00")).len(),
            1
        );
        c.unzip_flavour = Some("ubuntu");
        let ubuntu = "UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.\n";
        assert!(unzip_differences(&c, &run(ubuntu), &run(&ubuntu_ours)).is_empty());
    }

    #[test]
    fn zip_with_round_trips_through_the_reference() {
        let Some(dir) = unzip_dir() else { return };
        let text = text(5000, 7);
        let ut = [0x55, 0x54, 5, 0, 1, 0x00, 0xca, 0x9a, 0x3b]; // UT: mtime 1e9
        let entries = [
            ZipEntrySpec::new(b"a.txt", b"stored\n"),
            ZipEntrySpec {
                method: 8,
                flags: 8,
                ..ZipEntrySpec::new(b"sub/b.txt", &text)
            },
            ZipEntrySpec {
                external_attr: 0o40755 << 16,
                ..ZipEntrySpec::new(b"sub/", b"")
            },
            ZipEntrySpec {
                extra: &ut,
                ..ZipEntrySpec::new(b"c.txt", b"with an extra field\n")
            },
        ];
        let archive = zip_with(&entries, b"a comment", b"");
        let mut c = unzip_case(
            "unzip",
            vec!["-t", "t.zip"],
            vec![("t.zip", archive.clone())],
        );
        let r = reference(dir, &c).unwrap();
        assert_eq!(
            r.code,
            0,
            "{}{}",
            String::from_utf8_lossy(&r.stdout),
            r.stderr
        );
        let out = String::from_utf8_lossy(&r.stdout);
        assert!(
            out.contains("No errors detected in compressed data of t.zip."),
            "{out}"
        );
        assert!(out.contains("a comment"), "{out}");
        c.args = vec!["-p", "t.zip", "sub/b.txt"];
        let r = reference(dir, &c).unwrap();
        assert_eq!((r.code, r.stdout == text), (0, true), "{}", r.stderr);

        // A preamble is "extra bytes at beginning": a warning (on standard
        // output), exit 1.
        let sfx = zip_with(&entries, b"", b"#!/bin/sh\nexit 0\n");
        let c = unzip_case("unzip", vec!["-tq", "s.zip"], vec![("s.zip", sfx)]);
        let r = reference(dir, &c).unwrap();
        let out = String::from_utf8_lossy(&r.stdout);
        assert_eq!(r.code, 1, "{out}{}", r.stderr);
        assert!(
            out.contains("17 extra bytes at beginning or within zipfile"),
            "{out}"
        );
    }

    /// `zip()`, which the gzip suites use, is `zip_with` with its defaults:
    /// the same bytes as before the generalisation.
    #[test]
    fn zip_is_zip_with_at_msdos_defaults() {
        let old = zip(&[ZipEntry {
            name: b"plain",
            data: b"data",
            method: 8,
            flags: 8,
        }]);
        let new = zip_with(
            &[ZipEntrySpec {
                method: 8,
                flags: 8,
                version_made_by: 20,
                external_attr: 0,
                dos_time: 0,
                ..ZipEntrySpec::new(b"plain", b"data")
            }],
            b"",
            b"",
        );
        assert_eq!(old, new);
    }

    #[test]
    fn the_flavour_reaches_stuffr_only_and_tz_defaults_to_utc() {
        let env = Path::new("/usr/bin/env");
        if !require_reference(env) {
            return;
        }
        let mut c = unzip_case("env", vec![], vec![]);
        c.unzip_flavour = Some("ubuntu");
        let theirs = String::from_utf8(run_program(env, &c, false).stdout).unwrap();
        let ours = String::from_utf8(run_program(env, &c, true).stdout).unwrap();
        assert!(!theirs.contains("STUFFR_UNZIP_FLAVOR"), "{theirs}");
        assert!(
            ours.lines().any(|l| l == "STUFFR_UNZIP_FLAVOR=ubuntu"),
            "{ours}"
        );
        for out in [&theirs, &ours] {
            assert!(out.lines().any(|l| l == "TZ=UTC"), "{out}");
            assert!(out.lines().any(|l| l == "LANG=C"), "{out}");
        }
        c.tz = Some("Europe/Stockholm");
        for side in [false, true] {
            let out = String::from_utf8(run_program(env, &c, side).stdout).unwrap();
            assert!(out.lines().any(|l| l == "TZ=Europe/Stockholm"), "{out}");
        }
    }

    /// R12: `tty_ctl` makes standard input the controlling terminal
    /// (`/dev/tty` opens it, `tty` names it), and types each line only once
    /// the program waits for it with echo off (each prompt is written
    /// before its `stty`).
    #[test]
    fn tty_ctl_types_each_line_at_its_prompt() {
        let sh = Path::new("/bin/sh");
        let script = concat!(
            "for p in one two three; do ",
            "printf '%s: ' $p >&2; stty -echo </dev/tty; ",
            "IFS= read -r x </dev/tty; stty echo </dev/tty; got=\"$got$x/\"; ",
            "done; printf '%s\\n' \"$got\"; tty -s && echo tty",
        );
        let mut c = unzip_case("sh", vec!["-c", script], vec![]);
        c.tty_ctl = true;
        c.stdin = Some(b"first\nsecond\nthird\n".to_vec());
        let r = run_program(sh, &c, false);
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert_eq!(
            String::from_utf8_lossy(&r.stdout),
            "first/second/third/\ntty\n"
        );
        assert_eq!(r.stderr, "one: two: three: ");
    }

    /// An unzip-family case without `tty_ctl` runs in a session of its
    /// own, with no controlling terminal: `/dev/tty` cannot be opened, so
    /// a password prompt answers as R7 does even when the tests run from a
    /// terminal. Other families' cases (no `unzip_flavour`) keep the
    /// harness's session.
    #[test]
    fn an_unzip_case_has_no_controlling_terminal() {
        let sh = Path::new("/bin/sh");
        let script = concat!(
            "if (exec 3</dev/tty) 2>/dev/null; then echo tty; else echo none; fi; ",
            "[ \"$(ps -o pgid= -p $$ | tr -d ' ')\" = \"$$\" ] && echo leader || echo member",
        );
        let mut c = unzip_case("sh", vec!["-c", script], vec![]);
        let r = run_program(sh, &c, false);
        assert_eq!(
            String::from_utf8_lossy(&r.stdout),
            "none\nleader\n",
            "{}",
            r.stderr
        );
        c.unzip_flavour = None;
        let r = run_program(sh, &c, false);
        let out = String::from_utf8_lossy(&r.stdout).into_owned();
        assert!(out.ends_with("member\n"), "{out}");
    }
}
