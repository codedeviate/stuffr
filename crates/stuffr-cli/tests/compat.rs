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
    const ALL: [&str; 4] = ["bzip2", "bunzip2", "bzcat", "bzip2recover"];

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
            4,
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
        let o = il(&s.0, &["--names", "gzip"]);
        assert_eq!(o.status.code(), Some(2));
        assert!(stderr(&o).contains("gzip"));
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
    }

    #[test]
    fn install_links_remove_tells_this_stuffr_from_elsewhere() {
        let s = Scratch::new("stale");
        let canon = s.0.canonicalize().unwrap();
        // Stale: leads to a path that no longer exists, so it is not ours.
        std::os::unix::fs::symlink(canon.join("gone/stuffr"), s.0.join("bzip2")).unwrap();
        // Ours by its recorded target.
        std::os::unix::fs::symlink(canon_stuffr(), s.0.join("bzcat")).unwrap();
        let o = il(&s.0, &["--remove"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert!(s.0.join("bzip2").symlink_metadata().is_ok());
        assert!(s.0.join("bzcat").symlink_metadata().is_err());
    }

    #[test]
    fn install_links_remove_spares_a_link_through_another_link() {
        let s = Scratch::new("via-link");
        let canon = s.0.canonicalize().unwrap();
        let l = canon.join("L");
        std::os::unix::fs::symlink(canon_stuffr(), &l).unwrap();
        std::os::unix::fs::symlink(&l, canon.join("bzip2")).unwrap();
        let o = il(&s.0, &["--remove"]);
        assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
        assert_eq!(std::fs::read_link(canon.join("bzip2")).unwrap(), l);
        // Install leaves it too, reporting it as present.
        let o = il(&s.0, &["--names", "bzip2"]);
        assert!(stdout(&o).contains("already present"), "{}", stdout(&o));
        assert_eq!(std::fs::read_link(canon.join("bzip2")).unwrap(), l);
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
            4,
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
        assert_eq!(stdout(&o).matches("would remove").count(), 4);
        assert_eq!(std::fs::read_dir(&s.0).unwrap().count(), 4);
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
    fn install_links_is_documented_on_the_examples_page() {
        let out = Command::new(STUFFR).arg("--examples").output().unwrap();
        let text = stdout(&out);
        for needle in [
            "install-links",
            "--names",
            "--force",
            "--remove",
            "--dry-run",
        ] {
            assert!(text.contains(needle), "examples page lacks {needle}");
        }
    }
}
