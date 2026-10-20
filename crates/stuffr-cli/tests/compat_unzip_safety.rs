//! stuffr-only checks of the unzip family's extraction safety (0.16.0 Task
//! 10), in both flavours (`STUFFR_UNZIP_FLAVOR`), on every unix: nothing is
//! ever written outside the extraction root (deviation 3: a symlink already
//! in the destination, or one an archive makes, never takes an operation
//! out of the root), the archive being read is never overwritten
//! (deviation 4), and the rulings on upstream's undefined behaviour and
//! hangs that only stuffr can show (T10-2, T10-3, T10-9, T10-10, T10-11).
//!
//! No reference runs here: these are the places stuffr departs from it, or
//! where it has no defined answer.

#[cfg(unix)]
mod compat_harness;

#[cfg(unix)]
mod unix {
    use super::compat_harness::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    const FLAVOURS: [&str; 2] = ["apple", "ubuntu"];

    /// stuffr as `flavour`, `unzip args` over `files` after `setup`.
    fn run(
        flavour: &'static str,
        args: &[&'static str],
        files: &[(&'static str, Vec<u8>)],
        setup: Option<fn(&Path)>,
        stdin: Option<&[u8]>,
    ) -> UnzipRun {
        let mut c = unzip_case("unzip", args.to_vec(), files.to_vec());
        c.unzip_flavour = Some(flavour);
        c.setup = setup;
        c.stdin = stdin.map(<[u8]>::to_vec);
        stuffr_unzip(&c)
    }

    /// The entries of `tree` under `prefix/`.
    fn under<'t>(tree: &'t UnzipTree, prefix: &str) -> Vec<&'t [u8]> {
        let p = format!("{prefix}/");
        tree.keys()
            .filter(|k| k.starts_with(p.as_bytes()))
            .map(|k| &k[..])
            .collect()
    }

    fn lossy(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    /// `strerror(n)` as the platform's libc words it.
    fn strerror(n: i32) -> String {
        let s = std::io::Error::from_raw_os_error(n).to_string();
        s.strip_suffix(&format!(" (os error {n})"))
            .unwrap_or(&s)
            .to_owned()
    }

    fn escaping_links(w: &Path) {
        std::fs::create_dir_all(w.join("outside/existing")).unwrap();
        std::fs::write(w.join("outside/f.txt"), b"outside\n").unwrap();
        std::fs::create_dir_all(w.join("dst/d")).unwrap();
        symlink("../outside", w.join("dst/rel")).unwrap();
        symlink(w.join("outside"), w.join("dst/abs")).unwrap();
        symlink("../../outside", w.join("dst/d/up2")).unwrap();
        symlink("../outside/f.txt", w.join("dst/file")).unwrap();
    }

    /// Deviation 3 (and Apple's own `AT_RESOLVE_BENEATH`): symlinks in the
    /// destination that point out of it (relative, absolute, two levels up,
    /// one to a file) are never followed by anything that writes: every
    /// entry through them is refused, in both flavours, whatever `-o` and
    /// the answers say, and `outside/` is as it was.
    #[test]
    fn a_preexisting_symlink_never_leads_out() {
        let z = zip_with(
            &[
                ZipEntrySpec::new(b"rel/f.txt", b"through rel\n"),
                ZipEntrySpec::new(b"abs/f.txt", b"through abs\n"),
                ZipEntrySpec::new(b"rel/sub/g.txt", b"a directory through rel\n"),
                ZipEntrySpec {
                    external_attr: 0o40755 << 16,
                    ..ZipEntrySpec::new(b"rel/newdir/", b"")
                },
                ZipEntrySpec::new(b"d/up2/h.txt", b"two levels up\n"),
                ZipEntrySpec::new(b"existing/x.txt", b"no link\n"),
                ZipEntrySpec::new(b"file", b"over a link to a file\n"),
            ],
            b"",
            b"",
        );
        let files = [("e.zip", z)];
        for f in FLAVOURS {
            for (args, stdin) in [
                (&["-d", "dst", "e.zip"][..], None),
                (&["-o", "-d", "dst", "e.zip"], None),
                (&["-d", "dst", "e.zip"], Some(&b"y\ny\ny\ny\ny\ny\ny\n"[..])),
                (&["-B", "-d", "dst", "e.zip"], None),
            ] {
                let r = run(f, args, &files, Some(escaping_links), stdin);
                let what = format!("{f} {args:?}: exit {} stderr {:?}", r.code, r.stderr);
                assert_eq!(
                    under(&r.tree, "outside"),
                    [&b"outside/existing"[..], b"outside/f.txt"],
                    "{what}"
                );
                match r.tree.get(&b"outside/f.txt"[..]) {
                    Some(UnzipNode::File { bytes, .. }) => {
                        assert_eq!(bytes, b"outside\n", "{what}")
                    }
                    other => panic!("{what}: outside/f.txt is {other:?}"),
                }
                for l in ["dst/rel", "dst/abs", "dst/d/up2"] {
                    assert!(
                        matches!(r.tree.get(l.as_bytes()), Some(UnzipNode::Symlink { .. })),
                        "{what}: {l} is no longer the symlink"
                    );
                }
                assert_eq!(r.code, 50, "{what}");
                // each flavour's answer (without -o, Apple's stat sees the
                // outside file through the link and asks first)
                if !args.contains(&"-o") {
                    // (asked about the outside file first: no answer)
                } else if f == "apple" {
                    assert!(
                        r.stderr
                            .contains("error:  cannot enter dst/rel\n        Permission denied\n"),
                        "{what}"
                    );
                } else {
                    assert!(
                        r.stderr.contains(
                            "error:  cannot create dst/rel/f.txt\n        Permission denied\n"
                        ),
                        "{what}"
                    );
                }
                // the link to a file is replaced by the entry, not written
                // through
                if args.contains(&"-o") {
                    match r.tree.get(&b"dst/file"[..]) {
                        Some(UnzipNode::File { bytes, .. }) => {
                            assert_eq!(bytes, b"over a link to a file\n", "{what}")
                        }
                        other => panic!("{what}: dst/file is {other:?}"),
                    }
                }
                // what is beneath the root is extracted
                assert!(r.tree.contains_key(&b"dst/existing/x.txt"[..]), "{what}");
            }
        }
    }

    /// A symlink the archive makes and a file meant to go through it, in one
    /// archive: symlinks are made last (deferred), so the file meets a
    /// placeholder, not a door; and the symlink, once made, is only a link.
    #[test]
    fn a_symlink_then_file_chain_never_leads_out() {
        let z = zip_with(
            &[
                ZipEntrySpec {
                    external_attr: 0o120777 << 16,
                    ..ZipEntrySpec::new(b"s", b"../outside")
                },
                ZipEntrySpec::new(b"s/k.txt", b"through the archive's own link\n"),
                ZipEntrySpec {
                    external_attr: 0o120777 << 16,
                    ..ZipEntrySpec::new(b"t", b"/")
                },
                ZipEntrySpec::new(b"t/etc/k.txt", b"through an absolute link\n"),
            ],
            b"",
            b"",
        );
        fn outside(w: &Path) {
            std::fs::create_dir_all(w.join("outside")).unwrap();
        }
        for f in FLAVOURS {
            for args in [&["-d", "dst", "c.zip"][..], &["-o", "-d", "dst", "c.zip"]] {
                let r = run(f, args, &[("c.zip", z.clone())], Some(outside), None);
                let what = format!("{f} {args:?}: exit {} stderr {:?}", r.code, r.stderr);
                assert!(under(&r.tree, "outside").is_empty(), "{what}");
                assert!(
                    matches!(r.tree.get(&b"dst/s"[..]), Some(UnzipNode::Symlink { target, .. }) if target == b"../outside"),
                    "{what}"
                );
                assert!(!r.tree.contains_key(&b"dst/s/k.txt"[..]), "{what}");
            }
        }
        // a second run, the links now in place: refused through them
        fn after(w: &Path) {
            std::fs::create_dir_all(w.join("outside")).unwrap();
            std::fs::create_dir_all(w.join("dst")).unwrap();
            symlink("../outside", w.join("dst/s")).unwrap();
            symlink("/", w.join("dst/t")).unwrap();
        }
        let through = zip_with(
            &[
                ZipEntrySpec::new(b"s/k.txt", b"through the earlier link\n"),
                ZipEntrySpec::new(b"t/etc/k.txt", b"through an absolute link\n"),
            ],
            b"",
            b"",
        );
        for f in FLAVOURS {
            let r = run(
                f,
                &["-o", "-d", "dst", "c.zip"],
                &[("c.zip", through.clone())],
                Some(after),
                None,
            );
            assert!(under(&r.tree, "outside").is_empty(), "{f}: {}", r.stderr);
            assert_eq!(r.code, 50, "{f}: {}", r.stderr);
        }
    }

    /// `../`, absolute and dot names never climb out, with or without
    /// `-:` (which keeps `../` components): the root's parent is never
    /// written, made or changed.
    /// ruling: T10-10. With `-:`, a directory entry that climbs above the
    /// root (`../`) makes Apple's unzip `chmod()` (and at the end set the
    /// times and mode of) the directory above the root, with plain paths.
    /// stuffr refuses every change outside the root: `chmod (directory
    /// attributes) error: Permission denied` and the warnings of the
    /// attributes it could not set.
    #[test]
    fn names_never_climb_out() {
        let z = zip_with(
            &[
                ZipEntrySpec::new(b"../x.txt", b"x\n"),
                ZipEntrySpec::new(b"../../y.txt", b"y\n"),
                ZipEntrySpec::new(b"/abs.txt", b"abs\n"),
                ZipEntrySpec::new(b"a/../../b.txt", b"b\n"),
                ZipEntrySpec::new(b"..", b"dotdot\n"),
                ZipEntrySpec {
                    external_attr: 0o40700 << 16,
                    ..ZipEntrySpec::new(b"../", b"")
                },
                ZipEntrySpec {
                    external_attr: 0o40700 << 16,
                    ..ZipEntrySpec::new(b"../../", b"")
                },
            ],
            b"",
            b"",
        );
        fn nested(w: &Path) {
            std::fs::create_dir_all(w.join("dst/inner")).unwrap();
            std::fs::set_permissions(w.join("dst"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_234_567_890);
            std::fs::File::open(w.join("dst"))
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(t))
                .unwrap();
        }
        for f in FLAVOURS {
            for args in [
                &["-d", "dst/inner", "z.zip"][..],
                &["-:", "-d", "dst/inner", "z.zip"],
                &["-:", "-o", "-d", "dst/inner", "z.zip"],
            ] {
                let r = run(f, args, &[("z.zip", z.clone())], Some(nested), None);
                let what = format!("{f} {args:?}: exit {} stderr {:?}", r.code, r.stderr);
                // nothing beside dst/inner in dst, and dst itself unchanged
                let beside: Vec<_> = under(&r.tree, "dst")
                    .into_iter()
                    .filter(|k| !k.starts_with(b"dst/inner"))
                    .collect();
                assert!(
                    beside.is_empty(),
                    "{what}: {:?}",
                    beside.iter().map(|k| lossy(k)).collect::<Vec<_>>()
                );
                match r.tree.get(&b"dst"[..]) {
                    Some(UnzipNode::Dir { mode, mtime, .. }) => {
                        assert_eq!((*mode, *mtime), (0o755, 1_234_567_890), "{what}")
                    }
                    other => panic!("{what}: dst is {other:?}"),
                }
                let top: Vec<_> = r
                    .tree
                    .keys()
                    .filter(|k| !k.starts_with(b"dst") && *k != b"z.zip")
                    .map(|k| lossy(k))
                    .collect();
                assert!(top.is_empty(), "{what}: {top:?}");
                // Apple's `mkdirat(.., "..")` is EEXIST, so it "made" the
                // directory and goes on to change it: refused. Upstream's
                // `stat()` finds it there and leaves it.
                if args.contains(&"-:") && f == "apple" {
                    assert!(
                        r.stderr
                            .contains("chmod (directory attributes) error: Permission denied\n"),
                        "{what}"
                    );
                }
            }
        }
    }

    /// Deviation 4: an entry whose output is the archive being read (the
    /// same file: by its own name, or a hard link to it) is refused with
    /// the "cannot create" answer, whatever `-o`, `-B` and the answers say;
    /// the archive stays whole and the run goes on. A symlink to the
    /// archive is another file: it is replaced, the archive untouched.
    #[test]
    fn the_archive_being_read_is_never_overwritten() {
        let z = zip_with(
            &[
                ZipEntrySpec::new(b"self.zip", b"not the archive\n"),
                ZipEntrySpec::new(b"hard.zip", b"not the archive either\n"),
                ZipEntrySpec::new(b"soft.zip", b"replaces the link\n"),
                ZipEntrySpec::new(b"other.txt", b"extracted\n"),
            ],
            b"",
            b"",
        );
        fn links(w: &Path) {
            std::fs::hard_link(w.join("self.zip"), w.join("hard.zip")).unwrap();
            symlink("self.zip", w.join("soft.zip")).unwrap();
        }
        let busy = strerror(libc::EBUSY);
        for f in FLAVOURS {
            for (args, stdin) in [
                (&["-o", "self.zip"][..], None),
                (&["self.zip"], Some(&b"y\ny\ny\n"[..])),
                (&["self.zip"], Some(&b"A\n"[..])),
                (&["-oB", "self.zip"], None),
                (&["-o", "-d", ".", "self.zip"], None),
            ] {
                let r = run(f, args, &[("self.zip", z.clone())], Some(links), stdin);
                let what = format!("{f} {args:?}: exit {} stderr {:?}", r.code, r.stderr);
                for name in ["self.zip", "hard.zip"] {
                    match r.tree.get(name.as_bytes()) {
                        Some(UnzipNode::File { bytes, .. }) => {
                            assert_eq!(bytes, &z, "{what}: {name}")
                        }
                        other => panic!("{what}: {name} is {other:?}"),
                    }
                    let shown = if args.contains(&"-d") {
                        format!("./{name}")
                    } else {
                        name.to_owned()
                    };
                    let want = format!("error:  cannot create {shown}\n        {busy}\n");
                    assert!(r.stderr.contains(&want), "{what}: want {want:?}");
                }
                assert!(
                    matches!(r.tree.get(&b"soft.zip"[..]), Some(UnzipNode::File { bytes, .. }) if bytes == b"replaces the link\n"),
                    "{what}"
                );
                assert!(r.tree.contains_key(&b"other.txt"[..]), "{what}");
                assert_eq!(r.code, 50, "{what}");
            }
        }
    }

    /// Deviation 4 under `-B` (fix round 1): the backup's name is the
    /// archive being read (`c.zip~` holds `c.zip`, which exists). `-oB`
    /// would remove the "old backup" and rename over it; `-B` would stop its
    /// numbered search there. Refused, the archive whole.
    #[test]
    fn a_backup_never_lands_on_the_archive() {
        let z = zip_with(
            &[ZipEntrySpec::new(b"c.zip", b"from the archive\n")],
            b"",
            b"",
        );
        fn existing(w: &Path) {
            std::fs::write(w.join("c.zip"), b"was here\n").unwrap();
        }
        let busy = strerror(libc::EBUSY);
        for f in FLAVOURS {
            for args in [&["-oB", "c.zip~"][..], &["-B", "c.zip~"]] {
                let r = run(
                    f,
                    args,
                    &[("c.zip~", z.clone())],
                    Some(existing),
                    Some(b"y\n"),
                );
                let what = format!("{f} {args:?}: exit {} stderr {:?}", r.code, r.stderr);
                match r.tree.get(&b"c.zip~"[..]) {
                    Some(UnzipNode::File { bytes, .. }) => assert_eq!(bytes, &z, "{what}"),
                    other => panic!("{what}: the archive is {other:?}"),
                }
                if args[0] == "-oB" {
                    assert!(
                        r.stderr
                            .contains(&format!("error:  cannot create c.zip\n        {busy}\n")),
                        "{what}"
                    );
                    assert_eq!(r.code, 50, "{what}");
                }
            }
        }
    }

    /// A real full disk (fix round 1): `RLIMIT_FSIZE` with `SIGXFSZ`
    /// ignored, so a write past the limit fails (`EFBIG`) mid-entry, the
    /// decoder holding the window. Against this platform's reference when
    /// it has one (Apple on macOS, Ubuntu on Linux), stuffr in its flavour:
    /// the same streams, exit code and file sizes, with no answer and with
    /// `y`. Without a reference: the question and exit 50.
    #[test]
    fn a_file_size_limit_is_a_full_disk() {
        use std::os::unix::process::CommandExt;
        let big: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let z = zip_with(
            &[
                ZipEntrySpec::new(b"big.bin", &big),
                ZipEntrySpec {
                    method: 8,
                    ..ZipEntrySpec::new(b"big2.bin", &big)
                },
                ZipEntrySpec::new(b"small.txt", b"small\n"),
            ],
            b"",
            b"",
        );
        let base = std::env::temp_dir().join(format!("stuffr-unzip-fsize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("bin")).unwrap();
        let link = base.join("bin/unzip");
        symlink(env!("CARGO_BIN_EXE_stuffr"), &link).unwrap();
        let flavour = platform_unzip_flavour();
        let mut n = 0;
        let mut run_one = |exe: &Path, args: &[&str], stdin: &[u8]| {
            n += 1;
            let w = base.join(format!("w{n}"));
            std::fs::create_dir_all(&w).unwrap();
            std::fs::write(w.join("a.zip"), &z).unwrap();
            let mut cmd = std::process::Command::new(exe);
            cmd.args(args)
                .current_dir(&w)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LANG", "C")
                .env("TZ", "UTC")
                .env("STUFFR_UNZIP_FLAVOR", flavour)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            // SAFETY: between fork and exec only async-signal-safe calls:
            // `signal` and `setrlimit`, on plain values.
            unsafe {
                cmd.pre_exec(|| {
                    libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                    let lim = libc::rlimit {
                        rlim_cur: 200 * 512,
                        rlim_max: 200 * 512,
                    };
                    if libc::setrlimit(libc::RLIMIT_FSIZE, &lim) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = cmd.spawn().unwrap();
            {
                use std::io::Write;
                let _ = child.stdin.take().unwrap().write_all(stdin);
            }
            let out = child.wait_with_output().unwrap();
            let real = std::fs::canonicalize(&w).unwrap();
            let mask = |b: &[u8]| {
                String::from_utf8_lossy(b)
                    .replace(&*real.to_string_lossy(), "<work>")
                    .replace(&*w.to_string_lossy(), "<work>")
            };
            let mut sizes: Vec<(String, u64)> = std::fs::read_dir(&w)
                .unwrap()
                .map(|e| e.unwrap())
                .filter(|e| e.file_name() != "a.zip")
                .map(|e| {
                    (
                        e.file_name().to_string_lossy().into_owned(),
                        e.metadata().unwrap().len(),
                    )
                })
                .collect();
            sizes.sort();
            (
                out.status.code(),
                mask(&out.stdout),
                mask(&out.stderr),
                sizes,
            )
        };
        for args in [&["-o", "a.zip"][..], &["-oq", "a.zip"]] {
            for stdin in [&b""[..], b"y\ny\n"] {
                let ours = run_one(&link, args, stdin);
                let what = format!("{args:?} {stdin:?}: {ours:?}");
                assert!(
                    ours.2
                        .contains("big.bin:  write error (disk full?).  Continue? (y/n/^C) "),
                    "{what}"
                );
                if stdin.is_empty() {
                    assert_eq!(ours.0, Some(50), "{what}");
                }
                if let Some(dir) = unzip_dir() {
                    let theirs = run_one(&Path::new(dir).join("unzip"), args, stdin);
                    assert_eq!(theirs, ours, "{args:?} {stdin:?}: reference vs stuffr");
                }
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// ruling: T10-9. "r", an empty new name, then the end of input: the C
    /// asks "new name: " forever; stuffr answers as the first question's end
    /// of input does ("[N]one"), and the file is kept.
    #[test]
    fn an_empty_new_name_at_the_end_of_input_ends_the_questions() {
        let z = zip_with(
            &[
                ZipEntrySpec::new(b"a.txt", b"from the archive\n"),
                ZipEntrySpec::new(b"b.txt", b"from the archive\n"),
            ],
            b"",
            b"",
        );
        fn existing(w: &Path) {
            std::fs::write(w.join("a.txt"), b"mine\n").unwrap();
            std::fs::write(w.join("b.txt"), b"mine\n").unwrap();
            for n in ["a.txt", "b.txt"] {
                let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
                std::fs::File::options()
                    .write(true)
                    .open(w.join(n))
                    .unwrap()
                    .set_modified(t)
                    .unwrap();
            }
        }
        for f in FLAVOURS {
            let r = run(
                f,
                &["a.zip"],
                &[("a.zip", z.clone())],
                Some(existing),
                Some(b"r\n\n"),
            );
            assert_eq!(
                r.stderr,
                concat!(
                    "replace a.txt? [y]es, [n]o, [A]ll, [N]one, [r]ename: new name: new name:  NULL\n",
                    "(EOF or read error, treating as \"[N]one\" ...)\n"
                ),
                "{f}"
            );
            assert_eq!(r.code, 1, "{f}");
            for n in ["a.txt", "b.txt"] {
                assert!(
                    matches!(r.tree.get(n.as_bytes()), Some(UnzipNode::File { bytes, .. }) if bytes == b"mine\n"),
                    "{f}: {n}"
                );
            }
        }
    }

    /// ruling: T10-2. Apple's `close_outfile()` falls off its end without a
    /// `return` on a regular file (undefined behaviour); its binary answers
    /// as 0, so the decoder's error is replaced and the CRC check follows
    /// (` bad CRC 00000000`). The Ubuntu flavour (upstream) keeps the error
    /// and prints no CRC line. Both keep the file, exit 2.
    #[test]
    fn a_failed_inflate_then_the_crc_is_each_trees_own() {
        let text = b"the quick brown fox jumps over the lazy dog\n".repeat(2000);
        let mut body = deflate_raw(&text);
        body[3..11].copy_from_slice(b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8");
        let z = zip_with(
            &[ZipEntrySpec {
                method: 8,
                stored_data: Some(&body),
                ..ZipEntrySpec::new(b"f.txt", &text)
            }],
            b"",
            b"",
        );
        for f in FLAVOURS {
            let r = run(f, &["bad.zip"], &[("bad.zip", z.clone())], None, None);
            assert_eq!(r.code, 2, "{f}: {}", r.stderr);
            assert!(
                r.stderr
                    .starts_with("\n  error:  invalid compressed data to inflate\n"),
                "{f}: {}",
                r.stderr
            );
            assert_eq!(
                r.stderr.contains(" bad CRC "),
                f == "apple",
                "{f}: {}",
                r.stderr
            );
            assert!(r.tree.contains_key(&b"f.txt"[..]), "{f}");
        }
    }

    /// ruling: T10-3. A name given at "new name: " that is absolute: Apple's
    /// tree reads its relative part past the built path (stale memory: its
    /// binary said "No such file or directory"), stuffr says so for every
    /// operation; upstream (Ubuntu) drops the leading `/` and extracts it
    /// under the current directory.
    #[test]
    fn an_absolute_new_name() {
        let z = zip_with(&[ZipEntrySpec::new(b"f.txt", b"new\n")], b"", b"");
        fn existing(w: &Path) {
            std::fs::write(w.join("f.txt"), b"old\n").unwrap();
            let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
            std::fs::File::options()
                .write(true)
                .open(w.join("f.txt"))
                .unwrap()
                .set_modified(t)
                .unwrap();
        }
        let apple = run(
            "apple",
            &["a.zip"],
            &[("a.zip", z.clone())],
            Some(existing),
            Some(b"r\n/abs/dir/renamed.txt\n"),
        );
        assert_eq!(apple.code, 2, "{}", apple.stderr);
        assert!(
            apple.stderr.ends_with(
                "new name: checkdir error:  cannot create /abs\n                 No such file or directory\n                 unable to process /abs/dir/renamed.txt.\n"
            ),
            "{}",
            apple.stderr
        );
        let ubuntu = run(
            "ubuntu",
            &["a.zip"],
            &[("a.zip", z)],
            Some(existing),
            Some(b"r\n/abs/dir/renamed.txt\n"),
        );
        assert_eq!(ubuntu.code, 0, "{}", ubuntu.stderr);
        assert!(ubuntu.tree.contains_key(&b"abs/dir/renamed.txt"[..]));
    }

    /// ruling: T10-11. When the output cannot be made after an earlier entry
    /// was extracted, Apple's `__open_outfile()` leaves `G.outfile` at the
    /// earlier entry's closed stream and writes through it (a use after
    /// `fclose`: its binary then reports "write error (disk full?)" and
    /// stops); stuffr gives upstream's answer, "cannot create", and goes on.
    /// On macOS an ISO 8859-1 name is no UTF-8 name APFS takes (`EILSEQ`).
    #[cfg(target_os = "macos")]
    #[test]
    fn an_output_that_cannot_be_made_after_another() {
        let z = zip_with(
            &[
                ZipEntrySpec::new(b"first.txt", b"first\n"),
                ZipEntrySpec::new(b"caf\xe9.txt", b"latin-1\n"),
                ZipEntrySpec::new(b"last.txt", b"last\n"),
            ],
            b"",
            b"",
        );
        let r = run("apple", &["l1.zip"], &[("l1.zip", z)], None, None);
        assert_eq!(r.code, 50, "{}", r.stderr);
        assert_eq!(
            r.stderr,
            format!(
                "error:  cannot create caf?.txt\n        {}\n",
                strerror(libc::EILSEQ)
            )
        );
        assert!(r.tree.contains_key(&b"last.txt"[..]));
    }
}
