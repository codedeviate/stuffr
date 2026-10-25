use crate::common::*;
use tar::{Builder, Header};

// ---- Hard links on unpack (0.10.0 Task 8) --------------------------------

#[cfg(unix)]
#[test]
fn unpack_recreates_gnu_tar_hard_links() {
    let dir = tmp_dir();
    let tree = hard_link_tree(&dir);
    let tar = dir.join("x.tar");
    run_tool(
        &require_gnu_tar(),
        &[os(&"-cf"), os(&tar), os(&"-C"), os(&tree), os(&".")],
        &dir,
        b"",
    );
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        tar.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_links_recreated(&out, &dest);
}

#[cfg(unix)]
#[test]
fn unpack_recreates_gnu_cpio_hard_links() {
    let dir = tmp_dir();
    let tree = hard_link_tree(&dir);
    // `find .`'s shape, handed over on stdin; `current_dir(tree)` is a
    // `Command` setting inside `run_tool`, not a shell `cd`.
    let bytes = run_tool(
        &require_gnu_cpio(),
        &[os(&"-o"), os(&"-H"), os(&"newc")],
        &tree,
        b".\n./a\n./a1\n./a2\n./e\n./e2\n./p\n",
    );
    let cpio = dir.join("x.cpio");
    std::fs::write(&cpio, bytes).unwrap();
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        cpio.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_links_recreated(&out, &dest);
}

/// Review Focus 4: forward-only, from a pipe, links are created exactly as
/// from a file.
#[cfg(unix)]
#[test]
fn unpack_recreates_hard_links_from_a_piped_tar() {
    let dir = tmp_dir();
    let tree = hard_link_tree(&dir);
    let tar = dir.join("x.tar");
    run_tool(
        &require_gnu_tar(),
        &[os(&"-cf"), os(&tar), os(&"-C"), os(&tree), os(&".")],
        &dir,
        b"",
    );
    let dest = dir.join("out");
    let out = run_with_stdin_output(
        &[
            "unpack",
            "-",
            "-C",
            dest.to_str().unwrap(),
            "--strict-fidelity",
        ],
        &std::fs::read(&tar).unwrap(),
    );
    assert_links_recreated(&out, &dest);
}

/// A link whose target was not selected is skipped, named on stderr, and
/// `--strict-fidelity` makes it exit 4.
#[cfg(unix)]
#[test]
fn unpack_skips_a_link_whose_target_was_not_selected() {
    let dir = tmp_dir();
    let tree = hard_link_tree(&dir);
    let tar = dir.join("x.tar");
    run_tool(
        &require_gnu_tar(),
        &[
            os(&"-cf"),
            os(&tar),
            os(&"-C"),
            os(&tree),
            os(&"a"),
            os(&"a1"),
        ],
        &dir,
        b"",
    );
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        tar.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
        "--index",
        "1",
        "--strict-fidelity",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "stderr: {stderr}");
    assert!(
        stderr.contains("skipped entry `a1`: its hard-link target `a` was not extracted"),
        "{stderr}"
    );
    assert!(std::fs::symlink_metadata(dest.join("a1")).is_err());
}

/// `gtar -cf x.tar a a b`, with `a` and `b` hard-linked, writes `a`, then
/// `a` as a link to ITSELF, then `b` as a link to `a`. GNU tar and bsdtar
/// read it; stuffr drops the self-link (the same file declared twice) and
/// lists, tests and unpacks the rest. 0.10.0's reader refused it (exit 5).
#[cfg(unix)]
#[test]
fn a_gnu_tar_naming_a_file_twice_lists_and_unpacks() {
    let dir = tmp_dir();
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a"), b"shared payload").unwrap();
    std::fs::hard_link(src.join("a"), src.join("b")).unwrap();
    let tar = dir.join("x.tar");
    run_tool(
        &require_gnu_tar(),
        &[os(&"-cf"), os(&tar), os(&"a"), os(&"a"), os(&"b")],
        &src,
        b"",
    );
    let listing = run_tool(&require_gnu_tar(), &[os(&"-tvf"), os(&tar)], &dir, b"");
    let listing = String::from_utf8_lossy(&listing);
    assert!(listing.contains("a link to a"), "the shape: {listing}");

    let p = tar.to_str().unwrap();
    let out = run_output(&["list", p]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().count(), 2, "a and b, once each: {stdout}");
    let out = run_output(&["test", p]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        p,
        "-C",
        dest.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"shared payload");
    assert_eq!(std::fs::read(dest.join("b")).unwrap(), b"shared payload");
}

/// tar into zip: every link name holds its target's bytes, as a copy, and
/// that is no loss, so `--strict-fidelity` passes.
#[cfg(unix)]
#[test]
fn convert_gnu_tar_with_hard_links_to_zip_copies_them() {
    let dir = tmp_dir();
    let tar = gnu_tar_of_hard_link_tree(&dir);
    let zip = dir.join("out.zip");
    let out = run_output(&[
        "convert",
        tar.to_str().unwrap(),
        zip.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let unzip = require_bin("unzip");
    for (name, want) in [
        ("./a", &b"alpha payload"[..]),
        ("./a1", b"alpha payload"),
        ("./a2", b"alpha payload"),
        ("./e", b""),
        ("./e2", b""),
        ("./p", b"plain"),
    ] {
        let got = run_tool(&unzip, &[os(&"-p"), os(&zip), os(&name)], &dir, b"");
        assert_eq!(got, want, "{name}");
    }
}

/// cpio into tar: the target stores links, so GNU tar sees links.
#[cfg(unix)]
#[test]
fn convert_gnu_cpio_with_hard_links_to_tar_keeps_links() {
    let dir = tmp_dir();
    let tree = hard_link_tree(&dir);
    let bytes = run_tool(
        &require_gnu_cpio(),
        &[os(&"-o"), os(&"-H"), os(&"newc")],
        &tree,
        b"./a\n./a1\n./a2\n./e\n./e2\n./p\n",
    );
    let cpio = dir.join("x.cpio");
    std::fs::write(&cpio, bytes).unwrap();
    let tar = dir.join("t.tar");
    let out = run_output(&[
        "convert",
        cpio.to_str().unwrap(),
        tar.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let listing = run_tool(&require_gnu_tar(), &[os(&"-tvf"), os(&tar)], &dir, b"");
    let listing = String::from_utf8_lossy(&listing);
    assert_eq!(listing.matches(" link to ").count(), 3, "{listing}");
}

/// A tar link whose target is larger than the copy cache's memory tier (the
/// default 64 MiB) cannot be copied into a container without links: it is
/// skipped and named, and `--strict-fidelity` makes that exit 4. Piped, so
/// the source is read forward only. cpio is the target because it stores
/// the 64 MiB without compressing it, which keeps the test fast.
#[cfg(unix)]
#[test]
fn convert_strict_fidelity_exits_4_when_a_link_cannot_be_copied() {
    let dir = tmp_dir();
    let mut tar = tar::Builder::new(Vec::new());
    let big = vec![0x5au8; 64 * 1024 * 1024 + 512];
    let mut h = tar::Header::new_gnu();
    h.set_size(big.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(1_000_000_000);
    h.set_entry_type(tar::EntryType::Regular);
    tar.append_data(&mut h, "big", &big[..]).unwrap();
    let mut l = tar::Header::new_gnu();
    l.set_size(0);
    l.set_mode(0o644);
    l.set_mtime(1_000_000_000);
    l.set_entry_type(tar::EntryType::Link);
    tar.append_link(&mut l, "link", "big").unwrap();
    let bytes = tar.into_inner().unwrap();
    drop(big);
    let out_path = dir.join("out.cpio");
    let out = run_with_stdin_output(
        &[
            "convert",
            "-",
            out_path.to_str().unwrap(),
            "--strict-fidelity",
        ],
        &bytes,
    );
    let stderr = stderr_text(&out);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert!(
        stderr
            .contains("skipped entry `link`: its hard-link target `big` was not kept for copying"),
        "{stderr}"
    );
}

/// `cat` of a link and its target writes the target's bytes for both.
#[cfg(unix)]
#[test]
fn cat_of_a_link_writes_its_targets_bytes() {
    let dir = tmp_dir();
    let tar = gnu_tar_of_hard_link_tree(&dir);
    let out = run_output(&["cat", tar.to_str().unwrap(), "./a", "./a1", "./a2"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    assert_eq!(out.stdout, b"alpha payload".repeat(3));
}

/// `cat` of a link alone, its target not selected: a usage refusal (exit 2)
/// saying it is a link and naming the TARGET to select too, never "not
/// found" for an entry `list` shows, never exit 1, never invented bytes.
#[cfg(unix)]
#[test]
fn cat_of_a_link_without_its_target_is_classified_not_1() {
    let dir = tmp_dir();
    let tree = hard_link_tree(&dir);
    let tar = dir.join("x.tar");
    run_tool(
        &require_gnu_tar(),
        &[
            os(&"-cf"),
            os(&tar),
            os(&"-C"),
            os(&tree),
            os(&"a"),
            os(&"a1"),
        ],
        &dir,
        b"",
    );
    let out = run_output(&["cat", tar.to_str().unwrap(), "a1"]);
    let stderr = stderr_text(&out);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("`a1` is a hard link to `a`, so its bytes are `a`'s; select `a` too"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("not found"),
        "`a` IS in the archive: {stderr}"
    );
    assert!(out.stdout.is_empty());
}

/// GNU cpio into zip, `--strict-fidelity`: every link is a full copy, the
/// empty file's two names included (an all-empty group, which announces
/// nothing), so the run is lossless and exits 0.
#[cfg(unix)]
#[test]
fn convert_gnu_cpio_with_hard_links_to_zip_copies_them_strictly() {
    let dir = tmp_dir();
    let tree = hard_link_tree(&dir);
    let bytes = run_tool(
        &require_gnu_cpio(),
        &[os(&"-o"), os(&"-H"), os(&"newc")],
        &tree,
        b"./a\n./a1\n./a2\n./e\n./e2\n./p\n",
    );
    let cpio = dir.join("x.cpio");
    std::fs::write(&cpio, bytes).unwrap();
    let zip = dir.join("out.zip");
    let out = run_output(&[
        "convert",
        cpio.to_str().unwrap(),
        zip.to_str().unwrap(),
        "--strict-fidelity",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_text(&out));
    let unzip = require_bin("unzip");
    for (name, want) in [
        ("a", &b"alpha payload"[..]),
        ("a1", b"alpha payload"),
        ("a2", b"alpha payload"),
        ("e", b""),
        ("e2", b""),
        ("p", b"plain"),
    ] {
        let got = run_tool(&unzip, &[os(&"-p"), os(&zip), os(&name)], &dir, b"");
        assert_eq!(got, want, "{name}");
    }
}

/// 0.10.1: an archive that contradicts itself on disk — directory `x` then
/// file `x`, file `a` then `a/b` — used to exit 1 ("Is a directory" / "Not a
/// directory"). Each later entry is now skipped and named, the rest is
/// extracted, and `--strict-fidelity` turns the skips into exit 4.
#[test]
fn unpack_skips_entries_an_archive_contradicts() {
    let dir = tmp_dir();
    let tar = dir.join("c.tar");
    {
        let mut builder = Builder::new(std::fs::File::create(&tar).unwrap());
        let mut d = Header::new_gnu();
        d.set_entry_type(tar::EntryType::Directory);
        d.set_size(0);
        d.set_mode(0o755);
        builder.append_data(&mut d, "x", std::io::empty()).unwrap();
        append_tar_entry(&mut builder, "x", b"file over dir");
        append_tar_entry(&mut builder, "a", b"alpha");
        append_tar_entry(&mut builder, "a/b", b"beneath a file");
        append_tar_entry(&mut builder, "ok.txt", b"fine");
        builder.finish().unwrap();
    }
    let expect = [
        "skipped entry `x`: a directory `x` from earlier in this archive is in the way",
        "skipped entry `a/b`: `a`, earlier in this archive, is not a directory, so `a/b` \
         cannot be placed beneath it",
    ];

    for (strict, code) in [(false, 0), (true, 4)] {
        let dest = dir.join(format!("out-{strict}"));
        let mut args = vec![
            "unpack",
            tar.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ];
        if strict {
            args.push("--strict-fidelity");
        }
        let out = run_output(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "strict={strict}: {stderr}");
        for line in expect {
            assert!(stderr.contains(line), "strict={strict}: {stderr}");
        }
        assert_eq!(std::fs::read(dest.join("ok.txt")).unwrap(), b"fine");
        assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"alpha");
        assert!(std::fs::symlink_metadata(dest.join("x")).unwrap().is_dir());
    }
}

/// 0.10.1 fix round 1: a 300-byte entry name is past the filesystem's
/// limit. `unpack` used to end at exit 1 ("File name too long") and never
/// write `z.txt`; the entry is now skipped and named, the rest extracted,
/// and `--strict-fidelity` makes it exit 4.
#[test]
fn unpack_skips_a_name_too_long_for_the_filesystem() {
    let dir = tmp_dir();
    let tar = dir.join("long.tar");
    let long = format!("{}.txt", "L".repeat(300));
    {
        let mut builder = Builder::new(std::fs::File::create(&tar).unwrap());
        append_tar_entry(&mut builder, "a.txt", b"alpha");
        append_tar_entry(&mut builder, &long, b"long");
        append_tar_entry(&mut builder, "z.txt", b"zulu");
        builder.finish().unwrap();
    }
    let expect = format!("skipped entry `{long}`: its path is too long for this filesystem");
    for (strict, code) in [(false, 0), (true, 4)] {
        let dest = dir.join(format!("out-{strict}"));
        let mut args = vec![
            "unpack",
            tar.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ];
        if strict {
            args.push("--strict-fidelity");
        }
        let out = run_output(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "strict={strict}: {stderr}");
        assert!(stderr.contains(&expect), "strict={strict}: {stderr}");
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(dest.join("z.txt")).unwrap(), b"zulu");
    }
}

/// 0.13.2: a skip reason names an ancestor this run made as the archive
/// spelled it, not as the later entry spells it. File `A`, then `a/b`.
#[test]
fn skip_reason_names_the_case_folded_ancestor_as_archived() {
    let Some(stderr) = unpack_folded(&[("A", b"alpha"), ("a/b", b"beneath")], "A", "a") else {
        return;
    };
    assert!(
        stderr.contains(
            "skipped entry `a/b`: `A`, earlier in this archive, is not a directory, so `a/b` \
             cannot be placed beneath it"
        ),
        "{stderr}"
    );
}

/// The same for a normalisation fold: NFC `é` as a file, then NFD `é/x`.
#[test]
fn skip_reason_names_the_normalisation_folded_ancestor_as_archived() {
    let nfc = "\u{e9}";
    let nfd = "e\u{301}";
    let Some(stderr) = unpack_folded(
        &[(nfc, b"alpha"), (&format!("{nfd}/x"), b"beneath")],
        nfc,
        nfd,
    ) else {
        return;
    };
    assert!(
        stderr.contains(&format!(
            "`{nfc}`, earlier in this archive, is not a directory"
        )),
        "{stderr}"
    );
}

/// A directory `A` this run made, then file `a`: the directory is named as
/// the archive spelled it.
#[test]
fn skip_reason_names_the_folded_directory_as_archived() {
    let dir = tmp_dir();
    let tar = dir.join("d.tar");
    {
        let mut builder = Builder::new(std::fs::File::create(&tar).unwrap());
        let mut d = Header::new_gnu();
        d.set_entry_type(tar::EntryType::Directory);
        d.set_size(0);
        d.set_mode(0o755);
        builder.append_data(&mut d, "A", std::io::empty()).unwrap();
        append_tar_entry(&mut builder, "a", b"file");
        builder.finish().unwrap();
    }
    std::fs::write(dir.join("A.probe"), b"p").unwrap();
    if std::fs::symlink_metadata(dir.join("a.probe")).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        tar.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("a directory `A` from earlier in this archive is in the way"),
        "{stderr}"
    );
}

/// Review Focus 2: a file `a` the destination held before the run is not the
/// run's own record; the wording stays what it is today.
#[test]
fn skip_reason_for_a_prior_destination_file_is_unchanged() {
    let dir = tmp_dir();
    let tar = dir.join("p.tar");
    {
        let mut builder = Builder::new(std::fs::File::create(&tar).unwrap());
        append_tar_entry(&mut builder, "a/b", b"beneath");
        builder.finish().unwrap();
    }
    let dest = dir.join("out");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("a"), b"prior").unwrap();
    let out = run_output(&[
        "unpack",
        tar.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "usage error: `{}` exists and is not a directory, so `a/b` cannot be placed beneath it",
            dest.join("a").display()
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("earlier in this archive"), "{stderr}");
    assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"prior");
}

/// A hard link the run made shares its target's inode but is not a fold of
/// it: file `a`, hard link `B -> a`, then `a/x` still names `a`. Runs on any
/// unix volume.
#[cfg(unix)]
#[test]
fn skip_reason_never_names_a_hard_link_as_the_ancestor() {
    let dir = tmp_dir();
    let tar = dir.join("h.tar");
    {
        let mut builder = Builder::new(std::fs::File::create(&tar).unwrap());
        append_tar_entry(&mut builder, "a", b"alpha");
        let mut h = Header::new_gnu();
        h.set_entry_type(tar::EntryType::Link);
        h.set_size(0);
        h.set_mode(0o644);
        builder.append_link(&mut h, "B", "a").unwrap();
        append_tar_entry(&mut builder, "a/x", b"beneath");
        builder.finish().unwrap();
    }
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        tar.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("skipped entry `a/x`: `a`, earlier in this archive, is not a directory"),
        "{stderr}"
    );
}

/// Directory `A`, directory `a` (re-recorded onto the same inode on a folding
/// volume), then file `A`: the exact spelling wins, so the reason names `A`.
#[test]
fn skip_reason_keeps_the_exact_spelling_when_a_folded_directory_was_rerecorded() {
    let dir = tmp_dir();
    std::fs::write(dir.join("A.probe"), b"p").unwrap();
    if std::fs::symlink_metadata(dir.join("a.probe")).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let tar = dir.join("r.tar");
    {
        let mut builder = Builder::new(std::fs::File::create(&tar).unwrap());
        for n in ["A", "a"] {
            let mut d = Header::new_gnu();
            d.set_entry_type(tar::EntryType::Directory);
            d.set_size(0);
            d.set_mode(0o755);
            builder.append_data(&mut d, n, std::io::empty()).unwrap();
        }
        append_tar_entry(&mut builder, "A", b"file");
        builder.finish().unwrap();
    }
    let dest = dir.join("out");
    let out = run_output(&[
        "unpack",
        tar.to_str().unwrap(),
        "-C",
        dest.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("skipped entry `A`: a directory `A` from earlier in this archive"),
        "{stderr}"
    );
}
