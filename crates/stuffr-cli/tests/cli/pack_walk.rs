use crate::common::*;
use std::process::Command;

// ---------------------------------------------------------------------
// Phase 2c: `pack` walks a directory tree, and says what walking it lost.
// ---------------------------------------------------------------------

#[test]
fn pack_walks_a_directory_and_round_trips_it() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir(root.join("empty")).unwrap();
    std::fs::write(root.join("README.md"), b"readme").unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("p.tar");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let back = dir.join("back");
    assert!(
        Command::new(STUFFR)
            .args([
                "unpack",
                out.to_str().unwrap(),
                "-C",
                back.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );

    assert_eq!(
        std::fs::read(back.join("proj/README.md")).unwrap(),
        b"readme"
    );
    assert_eq!(
        std::fs::read(back.join("proj/src/main.rs")).unwrap(),
        b"fn main() {}"
    );
    assert!(
        back.join("proj/empty").is_dir(),
        "an empty directory must survive the round trip"
    );
}

/// A directory INSIDE a codec, in one command — the milestone's own headline
/// (`stuffr pack proj -o backup.tar.gz`), which needs the walk and the
/// composed write together.
#[test]
fn pack_walks_a_directory_into_a_container_inside_a_codec() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("backup.tar.gz");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let back = dir.join("back");
    assert!(
        Command::new(STUFFR)
            .args([
                "unpack",
                out.to_str().unwrap(),
                "-C",
                back.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        std::fs::read(back.join("proj/src/main.rs")).unwrap(),
        b"fn main() {}"
    );
}

#[cfg(unix)]
#[test]
fn pack_stores_a_symlink_inside_a_directory_rather_than_following_it() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink("real.txt", root.join("link.txt")).unwrap();

    let out = dir.join("p.tar");
    assert!(
        Command::new(STUFFR)
            .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );

    // The system tar must agree it is a link, not a second copy. Its absence
    // panics rather than skipping: the repo's reference-tool convention (see
    // `lzip.rs`'s `require_lzip`) is that failing loudly beats proving
    // nothing, and CI installs tar unconditionally.
    let l = Command::new("tar")
        .args(["tvf", out.to_str().unwrap()])
        .output()
        .expect("the system `tar` is this test's reference authority");
    let text = String::from_utf8_lossy(&l.stdout);
    assert!(
        text.contains("link.txt -> real.txt"),
        "tar tvf said: {text}"
    );
}

/// The opposite rule, and the reason the two must not be unified: a symlink
/// NAMED on the command line is followed, because storing the link itself
/// would let `pack` write an archive `unpack` then refuses at exit 7.
#[cfg(unix)]
#[test]
fn pack_follows_a_symlink_named_on_the_command_line() {
    let dir = tmp_dir();
    std::fs::write(dir.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink("real.txt", dir.join("link.txt")).unwrap();

    let out = dir.join("named.tar");
    assert!(
        Command::new(STUFFR)
            .args([
                "pack",
                dir.join("link.txt").to_str().unwrap(),
                "-o",
                out.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );

    let back = dir.join("back");
    assert!(
        Command::new(STUFFR)
            .args([
                "unpack",
                out.to_str().unwrap(),
                "-C",
                back.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        std::fs::read(back.join("link.txt")).unwrap(),
        b"real",
        "a named symlink is followed, so the entry holds the target's bytes"
    );
}

#[test]
fn packing_a_directory_into_a_container_that_cannot_hold_it_warns_rather_than_refusing() {
    // `ar` has no directory concept at all. Refusing would be the tenth
    // instance of this project's signature defect; warning is honest.
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/a.txt"), b"a").unwrap();

    let out = dir.join("p.a");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "must not refuse: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let err = String::from_utf8_lossy(&st.stderr);
    // The DROPPED ENTRY'S NAME, not the word "fidelity". The pack summary
    // line carries a loss count on every successful pack, warnings or none,
    // so an assertion on that word passes against an implementation with the
    // whole warnings vector deleted — which is exactly what it was before
    // this was caught. Naming `proj/sub` is the property this test claims to
    // test.
    assert!(
        err.contains("proj/sub"),
        "it must SAY WHAT it dropped, by name; stderr: {err}"
    );

    // And --strict-fidelity turns that into a refusal, as it does on read.
    let out2 = dir.join("p2.a");
    let st2 = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            out2.to_str().unwrap(),
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st2.status.code(),
        Some(4),
        "strict fidelity must exit 4 on the write side too"
    );
}

/// The flag must not fire on a clean pack. A gate that always trips is a gate
/// nobody leaves on.
///
/// The tree carries a SYMLINK, and that is the case worth pinning rather than
/// an afterthought: `README.md:35` records that `--strict-fidelity` "fails on
/// essentially any tarball containing a symlink" on the READ side, because a
/// symlink's mtime cannot be restored without following the link (`std` has no
/// `lutimes`). The write side has no such limit — tar stores the link, target
/// and all, and loses nothing — so the two sides disagree about the same tree
/// on purpose, and this is the half most likely to be "fixed" into a refusal
/// by someone reading only the README.
#[test]
fn strict_fidelity_passes_on_a_pack_that_lost_nothing() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("main.rs", root.join("src/alias.rs")).unwrap();

    let archive = dir.join("clean.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "an ordinary tree into tar loses nothing, symlink included: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    // And the symlink really is IN there, as a link. Without this the test
    // above would pass just as happily against a walk that dropped it —
    // strict fidelity cannot complain about an entry nobody tried to store.
    #[cfg(unix)]
    {
        let listed = Command::new("tar")
            .args(["tvf", archive.to_str().unwrap()])
            .output()
            .expect("the system `tar` is this test's reference authority");
        let text = String::from_utf8_lossy(&listed.stdout);
        assert!(
            text.contains("alias.rs -> main.rs"),
            "the symlink must be stored as a link, not dropped or copied: {text}"
        );
    }
}

/// The walk names entries beneath the root's own final component, so two
/// directories with the same name collide before anything is written — the
/// same rule two identically-named files have always had.
#[test]
fn two_directories_with_the_same_final_component_are_refused_before_writing() {
    let dir = tmp_dir();
    std::fs::create_dir_all(dir.join("a/proj")).unwrap();
    std::fs::create_dir_all(dir.join("b/proj")).unwrap();
    std::fs::write(dir.join("a/proj/x.txt"), b"x").unwrap();
    std::fs::write(dir.join("b/proj/y.txt"), b"y").unwrap();

    let out = dir.join("dup.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            dir.join("a/proj").to_str().unwrap(),
            dir.join("b/proj").to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(2),
        "a name collision is a usage error"
    );
    assert!(
        !out.exists(),
        "nothing may be written: the refusal happens before the destination is opened"
    );
}

/// `stuffr pack . -o x.tar` — the single most common archiving idiom there
/// is, and what `tar cf x.tar .` teaches. `Path::file_name` returns `None`
/// for `.`, which used to make this exit 2 at the naming step, before the
/// walk this phase added ever ran.
#[test]
fn pack_of_dot_names_entries_after_the_directory_it_resolves_to() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("dot.tar");
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args(["pack", ".", "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "`pack .` must work: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("proj/src/main.rs"),
        "`.` resolves to its canonical final component, so entries sit under \
         `proj/` exactly as `pack ../proj` would name them: {text}"
    );
}

/// The same rule one level up. `..` from `proj/src` is `proj`, so the entries
/// are named the same way `pack proj` names them — the final-component rule
/// applied consistently rather than a special case bolted onto `.`.
#[test]
fn pack_of_dotdot_names_entries_after_the_parent_it_resolves_to() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("dotdot.tar");
    let st = Command::new(STUFFR)
        .current_dir(root.join("src"))
        .args(["pack", "..", "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "`pack ..` must work: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("proj/src/main.rs"),
        "`..` must name entries after the directory it resolves to: {text}"
    );
}

/// A trailing slash is noise, and `Path::file_name` already reads `proj/` as
/// `proj`. Pinned anyway: a hand-rolled "split on `/`, take the last" — the
/// obvious way to rewrite this function — yields an EMPTY name here, and an
/// archive of entries named `/src/main.rs` is one stuffr itself refuses to
/// extract at exit 7.
#[test]
fn a_trailing_slash_on_a_packed_directory_is_noise() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

    let out = dir.join("slash.tar");
    let with_slash = format!("{}/", root.to_str().unwrap());
    let st = Command::new(STUFFR)
        .args(["pack", &with_slash, "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "a trailing slash must not change anything: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        text.contains("proj/src/main.rs"),
        "entries must sit under `proj/`, not under an empty name: {text}"
    );
}

/// `stuffr pack . -o backup.tar` — `examples.txt`'s own headline idiom for
/// the directory walk — writes `backup.tar` INSIDE the directory it is
/// walking. The first run has nothing to exclude (`backup.tar` does not
/// exist until this command creates it), but a `--force` re-run walks a
/// directory that now contains the PREVIOUS run's archive; left unhandled
/// that nests the old archive inside the new one and the file grows on
/// every run. GNU tar's answer to the identical shape is `file is the
/// archive; not dumped`.
#[test]
fn pack_excludes_its_own_output_from_the_walk() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"a").unwrap();

    // First run: `backup.tar` does not exist yet, so there is nothing for
    // the walk to exclude, and the archive holds exactly `a.txt`.
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args(["pack", ".", "-o", "backup.tar"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let out = root.join("backup.tar");
    let first_len = std::fs::metadata(&out).unwrap().len();

    // Second run, `--force`: `backup.tar` now exists INSIDE the directory
    // being walked. If it were not excluded, this would nest the first
    // run's archive inside the second and the file would grow; if it were
    // silently dropped with no warning, `stderr` would say nothing about it.
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args(["pack", ".", "-o", "backup.tar", "--force"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    // The EXCLUDED ENTRY'S NAME, not the word "fidelity" — the pack summary
    // line prints a count on every successful pack regardless, so asserting
    // on the word alone would pass even with the whole reporting deleted.
    let err = String::from_utf8_lossy(&st.stderr);
    assert!(
        err.contains("proj/backup.tar"),
        "it must SAY WHAT it excluded, by name; stderr: {err}"
    );
    let second_len = std::fs::metadata(&out).unwrap().len();
    assert_eq!(
        first_len, second_len,
        "a --force re-run must not nest the previous archive inside the new one"
    );

    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(
        !text.contains("backup.tar"),
        "the archive must not contain an entry naming itself: {text}"
    );
    assert!(
        text.contains("proj/a.txt"),
        "everything else in the directory is still stored: {text}"
    );

    // And a THIRD run, `--force --strict-fidelity`, stays GREEN. This
    // assertion was `Some(4)` until the Phase 2c final review: a fidelity
    // warning means "you lost something you asked for", and stuffr declining
    // to put a file inside itself is not that — it is stuffr being correct.
    // Gating on it made the nightly-backup shape `examples.txt` advertises
    // exit 4 on every run after the first, forever, which is a gate nobody
    // keeps. See `excluding_the_output_from_its_own_walk_is_a_note_not_a_
    // fidelity_loss`, which owns the property; this run only pins that the
    // verdict did not drift back.
    let st3 = Command::new(STUFFR)
        .current_dir(&root)
        .args([
            "pack",
            ".",
            "-o",
            "backup.tar",
            "--force",
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st3.status.code(),
        Some(0),
        "excluding the archive from its own walk costs no fidelity, so the strict \
         gate must not fire on it: {}",
        String::from_utf8_lossy(&st3.stderr)
    );
}

/// The hole the two rulings above left between them, measured through the
/// binary rather than the library.
///
/// Excluding the output from its own walk is right; recasting that exclusion
/// from a fidelity warning to a note is right. Together they meant that when
/// the output was the ONLY thing named, `pack` walked nothing, wrote an empty
/// 1024-byte tar over a healthy one, and `--strict-fidelity` — the strongest
/// gate this tool has — reported it clean at exit 0.
///
/// It is now `Error::Usage`, exit 2, raised while the plan is still being
/// built and before `dst.create` opens anything. That ordering is the whole
/// benefit and is what the byte-identity assertion below pins: a warning
/// would have let the empty archive replace the good one first, which is the
/// actual harm. Exit code alone would not have caught it.
#[test]
fn pack_refuses_when_the_only_input_is_the_output_and_leaves_it_untouched() {
    let dir = tmp_dir();
    let root = dir.join("backups");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("data.txt"), b"last night's data").unwrap();

    // A healthy archive, written the ordinary way.
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args(["pack", "data.txt", "-o", "backup.tar"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let archive = root.join("backup.tar");
    let before = std::fs::read(&archive).unwrap();
    assert!(
        before.len() > 1024,
        "the fixture must be a real archive, not an empty one: {} bytes",
        before.len()
    );

    // The reproduction, verbatim.
    let st = Command::new(STUFFR)
        .current_dir(&root)
        .args([
            "pack",
            "backup.tar",
            "-o",
            "backup.tar",
            "--force",
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&st.stderr);
    assert_eq!(
        st.status.code(),
        Some(2),
        "an empty plan is a usage refusal, not a successful empty archive: {err}"
    );
    assert!(
        err.contains("nothing to pack") && err.contains("backup.tar"),
        "the refusal must name the cause and the destination: {err}"
    );

    assert_eq!(
        std::fs::read(&archive).unwrap(),
        before,
        "refusing before the destination is opened means no temp file and no \
         rename, so the existing archive must be byte-identical"
    );
}

/// The same hole one step further in, measured through the binary: the shape
/// the refusal above was written FOR and did not reach.
///
/// A nightly job pointed at the directory its archive lives in. Last night's
/// archive is the directory's only member, the walk correctly leaves it out,
/// and `/backups`'s own directory entry keeps the plan non-empty — so the
/// guard did not fire, and a good archive was replaced by a 1536-byte shell
/// holding one directory entry, at exit 0, with `--strict-fidelity` calling
/// it clean. Measured on `70ca649`:
///
/// ```text
/// $ stuffr pack nb -o nb/nightly.tar --force --strict-fidelity
/// 1 path(s) -> tar (0 -> 1536 bytes, no fidelity loss)
/// stuffr: note: `nb/nightly.tar` is the archive being written …
/// exit=0   contains: nb
/// ```
///
/// The byte-identity assertion is the one that matters: an exit code alone
/// would not distinguish refusing from writing the shell and then complaining.
#[test]
fn pack_refuses_a_nightly_over_a_directory_holding_only_its_own_archive() {
    let dir = tmp_dir();
    let root = dir.join("backups");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(dir.join("data.txt"), b"last night's data").unwrap();

    // A healthy archive of something else, sitting in `backups`.
    let st = Command::new(STUFFR)
        .current_dir(&dir)
        .args(["pack", "data.txt", "-o", "backups/nightly.tar"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let archive = root.join("nightly.tar");
    let before = std::fs::read(&archive).unwrap();

    // Tonight: the job is pointed at the directory instead.
    let st = Command::new(STUFFR)
        .current_dir(&dir)
        .args([
            "pack",
            "backups",
            "-o",
            "backups/nightly.tar",
            "--force",
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&st.stderr);
    assert_eq!(
        st.status.code(),
        Some(2),
        "a plan reduced to the directory the output was removed from is a usage \
         refusal, not an archive of one empty directory: {err}"
    );
    assert!(
        err.contains("No archive was written") && err.contains("is unchanged"),
        "the refusal must say plainly that the destination survives: {err}"
    );
    assert_eq!(
        std::fs::read(&archive).unwrap(),
        before,
        "last night's archive must be byte-identical, not replaced by a shell"
    );
}

/// The read-side half of the same session: `stuffr test` on a zip whose index
/// declares more records than the reader can reach.
///
/// `ZipArchive` collapses central-directory records that share a name, so a
/// real 8-record archive that `unzip -t` reads whole enumerated 6 entries and
/// reported "exact fidelity" at exit 0 — under `--strict-fidelity`, the
/// strongest gate this tool has. The fixture is built here rather than
/// depending on that file, and `zip` itself will not write this shape, so the
/// central directory is forged: a verbatim copy of the first record appended
/// to the index, with the declared count bumped to match.
#[test]
fn test_reports_a_zip_whose_index_declares_more_records_than_are_reachable() {
    let dir = tmp_dir();
    let src = dir.join("a.txt");
    std::fs::write(&src, b"alpha").unwrap();
    let zip_path = dir.join("dup.zip");
    let st = Command::new(STUFFR)
        .current_dir(&dir)
        .args(["pack", "a.txt", "-o", "dup.zip"])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    // A clean archive must gain nothing, or the assertions below prove only
    // that `test` prints warnings.
    let st = Command::new(STUFFR)
        .args(["test", zip_path.to_str().unwrap(), "--strict-fidelity"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&st.stderr);
    assert_eq!(st.status.code(), Some(0), "a clean zip is clean: {err}");
    assert!(err.contains("exact fidelity"), "and still says so: {err}");

    // Forge a second central-directory record naming the same entry.
    let mut bytes = std::fs::read(&zip_path).unwrap();
    let eocd = bytes.len() - 22;
    assert_eq!(&bytes[eocd..eocd + 4], b"PK\x05\x06", "no EOCD");
    let le16 = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let cd_size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
    let cd_at = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let cd = bytes[cd_at..cd_at + cd_size].to_vec();
    let first = 46 + le16(&cd[28..]) as usize + le16(&cd[30..]) as usize + le16(&cd[32..]) as usize;
    let entries = le16(&bytes[eocd + 10..]);

    let mut out = bytes[..cd_at + cd_size].to_vec();
    out.extend_from_slice(&cd[..first]);
    let tail = &mut bytes[eocd..];
    tail[8..10].copy_from_slice(&(entries + 1).to_le_bytes());
    tail[10..12].copy_from_slice(&(entries + 1).to_le_bytes());
    tail[12..16].copy_from_slice(&((cd_size + first) as u32).to_le_bytes());
    out.extend_from_slice(tail);
    let forged = dir.join("shadowed.zip");
    std::fs::write(&forged, &out).unwrap();

    let st = Command::new(STUFFR)
        .args(["test", forged.to_str().unwrap()])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&st.stderr);
    assert_eq!(
        st.status.code(),
        Some(0),
        "a shadowed record is a fidelity loss, not corruption: {err}"
    );
    assert!(
        err.contains("declares 2") && err.contains("but 1 were enumerated"),
        "the warning must name both counts: {err}"
    );
    assert!(
        !err.contains("exact fidelity"),
        "a read that reached one of two records must not announce exact \
         fidelity: {err}"
    );

    let st = Command::new(STUFFR)
        .args(["test", forged.to_str().unwrap(), "--strict-fidelity"])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(4),
        "--strict-fidelity must refuse it: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}
