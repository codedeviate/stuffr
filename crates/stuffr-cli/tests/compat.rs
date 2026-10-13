//! Compatibility links: the `stuffr` binary behaving as another tool when
//! invoked through a symlink named after it.

#[cfg(unix)]
mod unix {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// A scratch directory holding `stuffr` and the symlink chain
    /// `bzcat` -> `bzip2` -> `stuffr`.
    fn link_chain(dir: &Path) -> PathBuf {
        let stuffr = dir.join("stuffr");
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_stuffr"), &stuffr).unwrap();
        let bzip2 = dir.join("bzip2");
        std::os::unix::fs::symlink(&stuffr, &bzip2).unwrap();
        let bzcat = dir.join("bzcat");
        std::os::unix::fs::symlink(&bzip2, &bzcat).unwrap();
        bzcat
    }

    /// Only the invoked name counts, not what the chain resolves to: the
    /// usage text names the program it was called as.
    #[test]
    fn symlink_named_bzcat_dispatches_to_bzcat() {
        let dir = std::env::temp_dir().join(format!("stuffr-compat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bzcat = link_chain(&dir);
        let out = Command::new(&bzcat).arg("-h").output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(out.status.code(), Some(0));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("usage: bzcat [flags and input files in any order]"),
            "stderr: {err}"
        );
    }

    const STUFFR: &str = env!("CARGO_BIN_EXE_stuffr");
    const ALL: [&str; 14] = [
        "bzip2",
        "bunzip2",
        "bzcat",
        "bzip2recover",
        "gzip",
        "gunzip",
        "zcat",
        "gzcat",
        "xz",
        "unxz",
        "xzcat",
        "lzma",
        "unlzma",
        "lzcat",
    ];

    /// A scratch directory removed on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("stuffr-il-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Scratch(d)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn canon_stuffr() -> PathBuf {
        Path::new(STUFFR).canonicalize().unwrap()
    }

    fn il(dir: &Path, args: &[&str]) -> std::process::Output {
        Command::new(STUFFR)
            .arg("install-links")
            .arg("--dir")
            .arg(dir)
            .args(args)
            .output()
            .unwrap()
    }

    fn stdout(o: &std::process::Output) -> String {
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
    fn stderr(o: &std::process::Output) -> String {
        String::from_utf8_lossy(&o.stderr).into_owned()
    }

    #[test]
    fn install_links_creates_every_name_and_is_idempotent() {
        let s = Scratch::new("all");
        let o = il(&s.0, &[]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let dir = s.0.canonicalize().unwrap();
        for n in ALL {
            let p = dir.join(n);
            assert_eq!(std::fs::read_link(&p).unwrap(), canon_stuffr());
            assert!(stdout(&o).contains(&format!("created {} -> ", p.display())));
        }
        let o = il(&s.0, &[]);
        assert_eq!(o.status.code(), Some(0));
        assert_eq!(
            stdout(&o).matches("already present").count(),
            ALL.len(),
            "{}",
            stdout(&o)
        );
        assert!(!stdout(&o).contains("created"));
    }

    #[test]
    fn install_links_refuses_a_regular_file_unless_forced() {
        let s = Scratch::new("force");
        let f = s.0.join("bzip2");
        std::fs::write(&f, b"mine").unwrap();
        let o = il(&s.0, &[]);
        assert_eq!(o.status.code(), Some(2));
        assert!(stderr(&o).contains("bzip2"), "{}", stderr(&o));
        assert_eq!(std::fs::read(&f).unwrap(), b"mine");
        assert!(!s.0.join("bzcat").exists(), "a refusal must change nothing");
        let o = il(&s.0, &["--force"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(stdout(&o).contains("replaced"));
        assert_eq!(std::fs::read_link(&f).unwrap(), canon_stuffr());
    }

    #[test]
    fn install_links_names_selects_and_rejects() {
        let s = Scratch::new("names");
        let o = il(&s.0, &["--names", "bzcat"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(s.0.join("bzcat").symlink_metadata().is_ok());
        assert!(s.0.join("bzip2").symlink_metadata().is_err());
        let o = il(&s.0, &["--names", "zstd"]);
        assert_eq!(o.status.code(), Some(2));
        assert!(stderr(&o).contains("zstd"));
    }

    #[test]
    fn install_links_remove_leaves_foreign_entries() {
        let s = Scratch::new("remove");
        assert_eq!(il(&s.0, &[]).status.code(), Some(0));
        std::fs::remove_file(s.0.join("bzcat")).unwrap();
        std::os::unix::fs::symlink("/bin/ls", s.0.join("bzcat")).unwrap();
        std::fs::remove_file(s.0.join("bunzip2")).unwrap();
        std::fs::write(s.0.join("bunzip2"), b"x").unwrap();
        let o = il(&s.0, &["--remove"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(s.0.join("bzip2").symlink_metadata().is_err());
        assert!(s.0.join("bzip2recover").symlink_metadata().is_err());
        assert_eq!(
            std::fs::read_link(s.0.join("bzcat")).unwrap(),
            Path::new("/bin/ls")
        );
        assert_eq!(std::fs::read(s.0.join("bunzip2")).unwrap(), b"x");
        let dir = s.0.canonicalize().unwrap();
        for (n, why) in [("bzcat", "not a stuffr link"), ("bunzip2", "not a link")] {
            let line = format!("left {}: {why}", dir.join(n).display());
            assert!(stdout(&o).lines().any(|l| l == line), "{}", stdout(&o));
        }
    }

    #[test]
    fn install_links_remove_tells_this_stuffr_from_elsewhere() {
        let s = Scratch::new("stale");
        let canon = s.0.canonicalize().unwrap();
        // Dangling, but to a file named `stuffr`: a stale stuffr link.
        std::os::unix::fs::symlink(canon.join("gone/stuffr"), s.0.join("bzip2")).unwrap();
        // Ours by its recorded target.
        std::os::unix::fs::symlink(canon_stuffr(), s.0.join("bzcat")).unwrap();
        // Dangling to something else: never ours.
        std::os::unix::fs::symlink(canon.join("gone/other-tool"), s.0.join("bunzip2")).unwrap();
        let o = il(&s.0, &["--remove"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(s.0.join("bzip2").symlink_metadata().is_err());
        assert!(s.0.join("bzcat").symlink_metadata().is_err());
        assert_eq!(
            std::fs::read_link(s.0.join("bunzip2")).unwrap(),
            canon.join("gone/other-tool")
        );
        assert!(
            stdout(&o).contains(&format!(
                "left {}: not a stuffr link",
                canon.join("bunzip2").display()
            )),
            "{}",
            stdout(&o)
        );
    }

    /// A link through another link resolves to this stuffr, so it is ours.
    #[test]
    fn install_links_treats_a_link_through_another_link_as_ours() {
        let s = Scratch::new("via-link");
        let canon = s.0.canonicalize().unwrap();
        let l = canon.join("L");
        std::os::unix::fs::symlink(canon_stuffr(), &l).unwrap();
        std::os::unix::fs::symlink(&l, canon.join("bzip2")).unwrap();
        // Install leaves it, reporting it as present.
        let o = il(&s.0, &["--names", "bzip2"]);
        assert!(stdout(&o).contains("already present"), "{}", stdout(&o));
        let line = stdout(&o);
        let line = line
            .lines()
            .find(|l| l.contains("already present"))
            .unwrap();
        assert!(line.ends_with(&format!(" -> {}", l.display())), "{line}");
        assert_eq!(std::fs::read_link(canon.join("bzip2")).unwrap(), l);
        // Remove deletes the link, never what it leads through.
        let o = il(&s.0, &["--remove"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(canon.join("bzip2").symlink_metadata().is_err());
        assert_eq!(std::fs::read_link(&l).unwrap(), canon_stuffr());
    }

    /// The line shows the link's own text, even a relative one.
    #[test]
    fn install_links_shows_a_relative_link_text_as_is() {
        let s = Scratch::new("rel-text");
        let canon = s.0.canonicalize().unwrap();
        std::os::unix::fs::symlink(canon_stuffr(), canon.join("l")).unwrap();
        std::os::unix::fs::symlink("./l", canon.join("gzip")).unwrap();
        let o = il(&s.0, &["--names", "gzip"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let out = stdout(&o);
        let line = out.lines().find(|l| l.contains("already present")).unwrap();
        assert!(line.ends_with(" -> ./l"), "{line}");
    }

    /// The Homebrew shape: links made by an older version point into a
    /// `Cellar/stuffr/<ver>` that `brew upgrade` and cleanup deleted.
    #[test]
    fn install_links_recovers_links_left_dangling_by_an_upgrade() {
        let s = Scratch::new("upgrade");
        let canon = s.0.canonicalize().unwrap();
        let bin = canon.join("Cellar/stuffr/0.10.4/bin");
        let links = canon.join("links");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&links).unwrap();
        let old = bin.join("stuffr");
        let make_stale = || {
            std::fs::write(&old, b"old stuffr").unwrap();
            for n in ALL {
                let _ = std::fs::remove_file(links.join(n));
                std::os::unix::fs::symlink(&old, links.join(n)).unwrap();
            }
            std::fs::remove_file(&old).unwrap();
        };

        make_stale();
        let o = il(&links, &["--remove"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(
            stdout(&o).matches("removed").count(),
            ALL.len(),
            "{}",
            stdout(&o)
        );
        assert_eq!(std::fs::read_dir(&links).unwrap().count(), 0);

        make_stale();
        let o = il(&links, &["--dry-run"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(
            stdout(&o).matches("would replace").count(),
            ALL.len(),
            "{}",
            stdout(&o)
        );
        let o = il(&links, &[]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(
            stdout(&o).matches("replaced").count(),
            ALL.len(),
            "{}",
            stdout(&o)
        );
        for n in ALL {
            assert_eq!(std::fs::read_link(links.join(n)).unwrap(), canon_stuffr());
        }
    }

    #[test]
    fn install_links_refuses_a_dangling_link_to_another_tool() {
        let s = Scratch::new("other-dangling");
        let canon = s.0.canonicalize().unwrap();
        let t = canon.join("gone/other-tool");
        std::os::unix::fs::symlink(&t, canon.join("bzip2")).unwrap();
        let o = il(&s.0, &[]);
        assert_eq!(o.status.code(), Some(2), "{}", stdout(&o));
        assert!(stderr(&o).contains("bzip2"), "{}", stderr(&o));
        assert_eq!(std::fs::read_link(canon.join("bzip2")).unwrap(), t);
        assert!(canon.join("bzcat").symlink_metadata().is_err());
    }

    #[test]
    fn install_links_leaves_a_link_to_another_live_binary() {
        let s = Scratch::new("other-live");
        let canon = s.0.canonicalize().unwrap();
        let other = canon.join("stuffr-not");
        std::fs::write(&other, b"another program").unwrap();
        // Even a live binary that happens to be named `stuffr`.
        std::fs::create_dir_all(canon.join("elsewhere")).unwrap();
        let named = canon.join("elsewhere/stuffr");
        std::fs::write(&named, b"another stuffr").unwrap();
        std::os::unix::fs::symlink(&other, canon.join("bzip2")).unwrap();
        std::os::unix::fs::symlink(&named, canon.join("bzcat")).unwrap();
        let o = il(&s.0, &["--names", "bzip2"]);
        assert_eq!(o.status.code(), Some(2));
        let o = il(&s.0, &["--names", "bzcat"]);
        assert_eq!(o.status.code(), Some(2));
        let o = il(&s.0, &["--remove"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(
            stdout(&o).matches("not a stuffr link").count(),
            2,
            "{}",
            stdout(&o)
        );
        assert_eq!(std::fs::read_link(canon.join("bzip2")).unwrap(), other);
        assert_eq!(std::fs::read_link(canon.join("bzcat")).unwrap(), named);
    }

    #[test]
    fn install_links_takes_the_directory_only_as_dir() {
        let s = Scratch::new("positional");
        let o = Command::new(STUFFR)
            .arg("install-links")
            .arg(&s.0)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
        assert_eq!(std::fs::read_dir(&s.0).unwrap().count(), 0);
        let o = Command::new(STUFFR).arg("install-links").output().unwrap();
        assert_eq!(o.status.code(), Some(2));
        assert!(stderr(&o).contains("--dir"), "{}", stderr(&o));
    }

    #[test]
    fn install_links_duplicate_names_equal_one_name() {
        let s = Scratch::new("dup");
        let o = il(&s.0, &["--names", "bzcat,bzcat"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(stdout(&o).lines().count(), 1, "{}", stdout(&o));
        assert_eq!(std::fs::read_dir(&s.0).unwrap().count(), 1);
    }

    #[test]
    fn install_links_replace_leaves_no_temp_files() {
        let s = Scratch::new("atomic");
        std::fs::write(s.0.join("bzip2"), b"x").unwrap();
        let o = il(&s.0, &["--force", "--names", "bzip2"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let names: Vec<_> = std::fs::read_dir(&s.0).unwrap().collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn install_links_dry_run_changes_nothing() {
        let s = Scratch::new("dry");
        let o = il(&s.0, &["--dry-run"]);
        assert_eq!(o.status.code(), Some(0));
        assert_eq!(
            stdout(&o).matches("would create").count(),
            ALL.len(),
            "{}",
            stdout(&o)
        );
        assert_eq!(std::fs::read_dir(&s.0).unwrap().count(), 0);
        assert_eq!(il(&s.0, &[]).status.code(), Some(0));
        std::fs::remove_file(s.0.join("bzip2")).unwrap();
        std::fs::write(s.0.join("bzip2"), b"x").unwrap();
        let o = il(&s.0, &["--force", "--dry-run"]);
        assert!(stdout(&o).contains("would replace"), "{}", stdout(&o));
        assert_eq!(std::fs::read(s.0.join("bzip2")).unwrap(), b"x");
        std::fs::remove_file(s.0.join("bzip2")).unwrap();
        std::os::unix::fs::symlink(canon_stuffr(), s.0.join("bzip2")).unwrap();
        let o = il(&s.0, &["--remove", "--dry-run"]);
        assert_eq!(stdout(&o).matches("would remove").count(), ALL.len());
        assert_eq!(std::fs::read_dir(&s.0).unwrap().count(), ALL.len());
    }

    #[test]
    fn install_links_missing_dir_is_a_usage_error() {
        let s = Scratch::new("missing");
        let o = il(&s.0.join("nope"), &[]);
        assert_eq!(o.status.code(), Some(2));
        assert!(stderr(&o).contains("nope"), "{}", stderr(&o));
    }

    #[test]
    fn install_links_unwritable_dir_is_exit_1_with_the_cause() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("ro");
        std::fs::set_permissions(&s.0, std::fs::Permissions::from_mode(0o555)).unwrap();
        let o = il(&s.0, &[]);
        // Restore first so the scratch directory can be removed.
        std::fs::set_permissions(&s.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        if std::fs::write(s.0.join("probe"), b"").is_ok() {
            // Running as a user the mode does not bind (root).
            return;
        }
        assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
        assert!(stderr(&o).contains("ermission denied"), "{}", stderr(&o));
        let link = s.0.canonicalize().unwrap().join("bzip2");
        assert!(
            stderr(&o).contains(&link.display().to_string()),
            "{}",
            stderr(&o)
        );
    }

    #[test]
    fn install_links_force_through_a_symlinked_dir_stays_inside_it() {
        let s = Scratch::new("viadir");
        let real = s.0.join("real");
        let other = s.0.join("other");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("bzip2"), b"keep").unwrap();
        std::fs::write(real.join("bzip2"), b"old").unwrap();
        let via = s.0.join("via");
        std::os::unix::fs::symlink(&real, &via).unwrap();
        let o = il(&via, &["--force"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(
            std::fs::read_link(real.join("bzip2")).unwrap(),
            canon_stuffr()
        );
        assert_eq!(std::fs::read(other.join("bzip2")).unwrap(), b"keep");
        assert!(stdout(&o).contains(&real.canonicalize().unwrap().display().to_string()));
    }

    #[test]
    fn install_links_creates_the_gzip_names() {
        let s = Scratch::new("gzip");
        let o = il(&s.0, &[]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let dir = s.0.canonicalize().unwrap();
        for n in ["gzip", "gunzip", "zcat", "gzcat"] {
            assert_eq!(
                std::fs::read_link(dir.join(n)).unwrap(),
                canon_stuffr(),
                "{n}"
            );
        }
        let one = Scratch::new("gzcat");
        let o = il(&one.0, &["--names", "gzcat"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(std::fs::read_dir(&one.0).unwrap().count(), 1);
        // A link it made runs as gzip.
        let o = Command::new(dir.join("gzip"))
            .arg("-h")
            .env("STUFFR_GZIP_FLAVOR", "gnu")
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(stdout(&o).starts_with("Usage: gzip "), "{}", stdout(&o));
    }

    /// The six xz names are links like the rest, and a link runs as its
    /// name: each prints its own name in `--help`'s usage line, and
    /// `--robot --version` is XZ Utils 5.8.4's.
    #[test]
    fn install_links_creates_the_xz_names() {
        let s = Scratch::new("xz");
        let o = il(&s.0, &[]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        let dir = s.0.canonicalize().unwrap();
        for n in ["xz", "unxz", "xzcat", "lzma", "unlzma", "lzcat"] {
            let link = dir.join(n);
            assert_eq!(std::fs::read_link(&link).unwrap(), canon_stuffr(), "{n}");
            let o = Command::new(&link).arg("--help").output().unwrap();
            assert_eq!(o.status.code(), Some(0), "{n}: {}", stderr(&o));
            let want = format!("Usage: {} [OPTION]... [FILE]...\n", link.display());
            assert!(stdout(&o).starts_with(&want), "{n}: {}", stdout(&o));
            let o = Command::new(&link)
                .args(["--robot", "--version"])
                .output()
                .unwrap();
            assert_eq!(
                stdout(&o),
                "XZ_VERSION=50080042\nLIBLZMA_VERSION=50080042\n",
                "{n}"
            );
        }
        let one = Scratch::new("lzcat");
        let o = il(&one.0, &["--names", "lzcat,unxz"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(std::fs::read_dir(&one.0).unwrap().count(), 2);
    }

    /// Run `exe` (with `stdin` piped in) under `flavor` as the only extra
    /// variable; `None` leaves `STUFFR_GZIP_FLAVOR` unset.
    fn run_with_flavor(
        exe: &Path,
        args: &[&str],
        stdin: &[u8],
        flavor: Option<&str>,
    ) -> std::process::Output {
        use std::io::Write;
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .env_remove("STUFFR_GZIP_FLAVOR")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(v) = flavor {
            cmd.env("STUFFR_GZIP_FLAVOR", v);
        }
        let mut child = cmd.spawn().unwrap();
        // A child that exits without reading its stdin closes the pipe; EPIPE is fine.
        match child.stdin.take().unwrap().write_all(stdin) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            r => r.unwrap(),
        }
        child.wait_with_output().unwrap()
    }

    /// Review Focus 4: `STUFFR_GZIP_FLAVOR` never leaks. Set to `bsd` or to
    /// garbage, it changes nothing for `stuffr` itself or for `bzip2`; under
    /// a gzip name an unknown value is refused, exit 1, in stuffr's words.
    #[test]
    fn the_flavour_variable_touches_only_the_gzip_family() {
        let s = Scratch::new("flavour");
        let stuffr = s.0.join("stuffr");
        std::os::unix::fs::symlink(STUFFR, &stuffr).unwrap();
        for n in ["bzip2", "gzip", "gunzip", "zcat", "gzcat"] {
            std::os::unix::fs::symlink(STUFFR, s.0.join(n)).unwrap();
        }
        let data = b"the flavour variable touches only the gzip family\n".repeat(20);
        let same = |exe: &Path, args: &[&str]| {
            let base = run_with_flavor(exe, args, &data, None);
            assert_eq!(base.status.code(), Some(0), "{}", stderr(&base));
            for v in ["bsd", "gnu", "garbage", ""] {
                let o = run_with_flavor(exe, args, &data, Some(v));
                assert_eq!(o.status.code(), base.status.code(), "{v:?} {args:?}");
                assert_eq!(o.stdout, base.stdout, "{v:?} {args:?}");
                assert_eq!(o.stderr, base.stderr, "{v:?} {args:?}");
            }
        };
        same(&stuffr, &["--version"]);
        same(&s.0.join("bzip2"), &["-c"]);
        for n in ["gzip", "gunzip", "zcat", "gzcat"] {
            let o = run_with_flavor(&s.0.join(n), &["-c"], &data, Some("garbage"));
            assert_eq!(o.status.code(), Some(1), "{n}");
            assert_eq!(
                stderr(&o),
                format!("{n}: STUFFR_GZIP_FLAVOR must be gnu or bsd, not 'garbage'\n")
            );
            assert!(o.stdout.is_empty(), "{n}");
        }
        // `gnu` selects GNU gzip whatever the platform's default.
        let o = run_with_flavor(&s.0.join("gzip"), &[], &data, Some("gnu"));
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(
            o.stdout.starts_with(&[0x1f, 0x8b, 8]),
            "{:?}",
            &o.stdout[..4]
        );
    }

    #[test]
    fn install_links_is_documented_on_the_examples_page() {
        let out = Command::new(STUFFR).arg("--examples").output().unwrap();
        let text = stdout(&out);
        for needle in [
            "install-links --dir",
            "--names",
            "--force",
            "--remove",
            "--dry-run",
        ] {
            assert!(text.contains(needle), "examples page lacks {needle}");
        }
    }

    /// zstd 1.5.7's `INThandler` (fileio.c), R6, through the debug-only
    /// `__compat-signal-test exit FILE` helper, which arms FILE with
    /// `arm_cleanup_exit` and waits: SIGINT removes it, writes `"\n"` to
    /// standard error and exits 2 (an exit, not a death by the signal).
    /// SIGTERM is not zstd's: it keeps its default action, the process dies
    /// of it, and the file stays, as zstd leaves it.
    #[cfg(debug_assertions)]
    #[test]
    fn an_interrupt_exits_2_and_removes_the_armed_file() {
        use std::io::Read;
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        let s = Scratch::new("signal-exit");
        for (sig, answered) in [(libc::SIGINT, true), (libc::SIGTERM, false)] {
            let file = s.0.join(format!("armed-{sig}"));
            let ready = s.0.join(format!("armed-{sig}.ready"));
            std::fs::write(&file, b"partial").unwrap();
            let mut cmd = Command::new(STUFFR);
            cmd.arg0("__compat-signal-test")
                .arg("exit")
                .arg(&file)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped());
            // SAFETY: only async-signal-safe calls between fork and exec;
            // the child starts with both signals at their default action,
            // whatever this test process inherited.
            unsafe {
                cmd.pre_exec(|| {
                    libc::signal(libc::SIGINT, libc::SIG_DFL);
                    libc::signal(libc::SIGTERM, libc::SIG_DFL);
                    Ok(())
                });
            }
            let mut child = cmd.spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            while !ready.exists() {
                if let Some(st) = child.try_wait().unwrap() {
                    let mut err = Vec::new();
                    let _ = child.stderr.take().unwrap().read_to_end(&mut err);
                    panic!(
                        "signal {sig}: the helper ended before arming: {st:?}, {:?}",
                        String::from_utf8_lossy(&err)
                    );
                }
                assert!(Instant::now() < deadline, "signal {sig}: never armed");
                std::thread::sleep(Duration::from_millis(2));
            }
            // SAFETY: kill on a child we spawned and have not reaped.
            unsafe { libc::kill(child.id() as i32, sig) };
            let status = loop {
                if let Some(st) = child.try_wait().unwrap() {
                    break st;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("signal {sig}: the helper hung after the signal");
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            let mut err = Vec::new();
            child.stderr.take().unwrap().read_to_end(&mut err).unwrap();
            if answered {
                assert_eq!(status.signal(), None, "SIGINT killed it: {status:?}");
                assert_eq!(status.code(), Some(2), "{status:?}");
                assert_eq!(err, b"\n", "{:?}", String::from_utf8_lossy(&err));
                assert!(!file.exists(), "the armed file survived SIGINT");
            } else {
                assert_eq!(status.signal(), Some(sig), "{status:?}");
                assert!(err.is_empty(), "{:?}", String::from_utf8_lossy(&err));
                assert!(file.exists(), "SIGTERM removed the armed file");
            }
        }
    }
}
