use crate::common::*;
use std::process::Command;

// ---------------------------------------------------------------------------
// Phase 2c, Task 6: the properties that would otherwise pass while being
// structurally unable to fail.
// ---------------------------------------------------------------------------

/// Property 1 — cross-implementation, BOTH directions, per container.
///
/// "The system tool reads what we write" and "we read what it writes" are
/// different claims; Phase 2's tar work proved it. Reference tools are
/// required, never skipped: a silent skip proves nothing.
///
/// Compared as whole TREES — names, contents, modes and symlink targets — and
/// through the CLI, which is what makes this new coverage rather than a second
/// copy of `tar.rs`'s and `ar.rs`'s own byte-level cross-implementation tests:
/// those build archives in memory and never walk a directory.
///
/// `ar` gets its documented DEGRADATION asserted instead of a faithful round
/// trip, because it has no directory and no symlink entries. `cpio` (newc) is
/// in the faithful group on measurement, not on assumption: it carries
/// directories, symlinks and modes, and both directions are checked below.
#[cfg(unix)]
#[test]
fn every_container_round_trips_a_tree_against_its_reference_tool() {
    let tar_bin = require_bin("tar");
    let zip_bin = require_bin("zip");
    let unzip_bin = require_bin("unzip");
    let cpio_bin = require_bin("cpio");
    let ar_bin = require_bin("ar");

    let dir = tmp_dir();
    let tree = dir.join("tree");
    let root = tree.join("proj");
    build_reference_tree(&root);
    let want = tree_snapshot(&root);

    // The fixture itself, asserted rather than assumed: every comparison below
    // is only as strong as what the tree actually contains, and a fixture that
    // silently lost its symlink would make four of the eight comparisons
    // prove nothing.
    assert_eq!(
        want,
        vec![
            "a.txt: file mode 600 bytes [97, 108, 112, 104, 97]".to_string(),
            "empty: dir mode 700".to_string(),
            "link: symlink -> a.txt".to_string(),
            "sub/b.bin: file mode 600 bytes [0, 255, 0, 98, 101, 116, 97]".to_string(),
            "sub: dir mode 700".to_string(),
        ],
        "the fixture must carry a nested dir, an EMPTY dir, a symlink and two \
         differently-named files, or the comparisons below prove less than they claim"
    );

    // ---- tar: stuffr writes, the system tar reads ----
    let out_tar = dir.join("out.tar");
    pack_ok(&[os(&root), os(&"-o"), os(&out_tar)]);
    let back = dir.join("back-tar");
    std::fs::create_dir(&back).unwrap();
    run_tool(
        &tar_bin,
        &[os(&"-xf"), os(&out_tar), os(&"-C"), os(&back)],
        &dir,
        b"",
    );
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "the system tar read our tar back as a different tree"
    );

    // ---- tar: the system tar writes, stuffr reads ----
    let ref_tar = dir.join("ref.tar");
    run_tool(
        &tar_bin,
        &[os(&"-cf"), os(&ref_tar), os(&"proj")],
        &tree,
        b"",
    );
    let back = dir.join("back-ref-tar");
    unpack_ok(&ref_tar, &back);
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "we read a tar the system tar wrote as a different tree"
    );

    // ---- zip: stuffr writes, unzip reads ----
    let out_zip = dir.join("out.zip");
    pack_ok(&[os(&root), os(&"-o"), os(&out_zip)]);
    let back = dir.join("back-zip");
    run_tool(
        &unzip_bin,
        &[os(&"-q"), os(&out_zip), os(&"-d"), os(&back)],
        &dir,
        b"",
    );
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "unzip read our zip back as a different tree"
    );

    // ---- zip: the system zip writes, stuffr reads ----
    // `-y` stores symlinks as symlinks rather than following them; without it
    // the reverse direction would compare a copy of `a.txt` against a link and
    // fail for the fixture's reason rather than ours.
    let ref_zip = dir.join("ref.zip");
    run_tool(
        &zip_bin,
        &[os(&"-qry"), os(&ref_zip), os(&"proj")],
        &tree,
        b"",
    );
    let back = dir.join("back-ref-zip");
    unpack_ok(&ref_zip, &back);
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "we read a zip the system zip wrote as a different tree"
    );

    // ---- cpio: stuffr writes, the system cpio reads ----
    //
    // This direction is PLATFORM-DEPENDENT in what it can prove, and that is
    // not fixable from here. `newc` records an entry's kind only in its mode
    // field's `S_IFMT` bits; GNU cpio 2.15 refuses an entry carrying none
    // with `unknown file type`, skips it and exits 0 anyway, while bsdcpio
    // (libarchive — what macOS ships as `cpio`) infers a regular file and
    // extracts the archive whole. So when `require_bin("cpio")` resolves to
    // GNU cpio this comparison catches a missing `S_IFREG`, and when it
    // resolves to bsdcpio it cannot: the tree comes back identical either
    // way. That is exactly how the 0.2.0 defect survived a phase of
    // macOS-only review, red on CI's Linux runners at the first push.
    //
    // Preferring a GNU cpio is not a portable fix either — Homebrew's is
    // keg-only and not on PATH under any name. The portable proof lives
    // where the format knowledge is, as a byte-level assertion on the header
    // this test cannot see: `cpio.rs`'s
    // `a_permission_only_file_mode_gains_the_regular_file_type_bits`. What
    // remains valuable HERE is the other direction and the whole-tree
    // comparison against whichever real tool is installed.
    let out_cpio = dir.join("out.cpio");
    pack_ok(&[os(&root), os(&"-o"), os(&out_cpio)]);
    let back = dir.join("back-cpio");
    std::fs::create_dir(&back).unwrap();
    run_tool(
        &cpio_bin,
        &[os(&"-i"), os(&"-d"), os(&"--quiet")],
        &back,
        &std::fs::read(&out_cpio).unwrap(),
    );
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "the system cpio read our cpio back as a different tree"
    );

    // ---- cpio: the system cpio writes, stuffr reads ----
    // The name list comes from this test rather than from `find`, so no shell
    // and no second traversal implementation is involved.
    let names = b"proj\nproj/a.txt\nproj/empty\nproj/link\nproj/sub\nproj/sub/b.bin\n";
    let ref_cpio_bytes = run_tool(
        &cpio_bin,
        &[os(&"-o"), os(&"--format=newc"), os(&"--quiet")],
        &tree,
        names,
    );
    let ref_cpio = dir.join("ref.cpio");
    std::fs::write(&ref_cpio, &ref_cpio_bytes).unwrap();
    let back = dir.join("back-ref-cpio");
    unpack_ok(&ref_cpio, &back);
    assert_eq!(
        tree_snapshot(&back.join("proj")),
        want,
        "we read a cpio the system cpio wrote as a different tree"
    );

    // ---- ar: the documented degradation, both directions ----
    //
    // `ar` has no directory and no symlink entries at all, so a faithful tree
    // round trip is not the property — what it must do is store the regular
    // files, drop the rest, and SAY SO. Asserted against the system `ar`'s own
    // listing, not against our reader.
    //
    // The member NAMES below are platform-dependent in the same way the cpio
    // comparison above is, and for a sibling reason. In the GNU variant a
    // short name is stored with `/` as its terminator, so GNU `ar` truncates
    // an inline `proj/a.txt` to `proj` — and `proj/sub/b.bin` to `proj` as
    // well, two members with one name. macOS's `ar` reads the 16-byte field
    // whole and cannot see it. `ar.rs`'s `write_safe_identifier` forces any
    // `/`-bearing name into the BSD extended form, which BOTH tools read back
    // verbatim (measured against GNU ar 2.47 and BSD ar), so the expectation
    // below is true of either. The portable proof that it stays that way is
    // `ar.rs`'s `a_name_containing_a_slash_is_never_stored_inline`.
    let out_ar = dir.join("out.a");
    let stderr = pack_ok(&[os(&root), os(&"-o"), os(&out_ar)]);
    for dropped in ["proj/empty", "proj/link", "proj/sub"] {
        assert!(
            stderr.contains(dropped),
            "`ar` dropping `{dropped}` must be named in the fidelity report; stderr: {stderr}"
        );
    }
    let listed = run_tool(&ar_bin, &[os(&"t"), os(&out_ar)], &dir, b"");
    let mut members: Vec<String> = String::from_utf8_lossy(&listed)
        .lines()
        .map(str::to_string)
        .collect();
    members.sort();
    assert_eq!(
        members,
        vec!["proj/a.txt".to_string(), "proj/sub/b.bin".to_string()],
        "the system ar must list exactly the regular files, and nothing standing in for \
         the directories or the symlink"
    );

    // And the other direction. `rcS` rather than `rc`: macOS's `ar` runs a
    // ranlib-style index over plain files by default and then silently emits
    // an archive holding ONLY an empty `__.SYMDEF SORTED` — measured, and
    // already documented in `ar.rs`'s own `we_accept_what_system_ar_writes`.
    let ref_ar = dir.join("ref.a");
    run_tool(
        &ar_bin,
        &[os(&"rcS"), os(&ref_ar), os(&"a.txt")],
        &root,
        b"",
    );
    let back = dir.join("back-ref-ar");
    unpack_ok(&ref_ar, &back);
    assert_eq!(
        std::fs::read(back.join("a.txt")).unwrap(),
        b"alpha",
        "we read an ar the system ar wrote as different bytes"
    );
}

/// Property 2 — the same tree packed twice is byte-identical, AND the entries
/// are in sorted order.
///
/// The two halves are not the same claim, and the second is the one that
/// needed adding. Byte-identity alone asserts DETERMINISM, not ordering:
/// `read_dir` is stable within a filesystem, so deleting the sort in
/// `walk.rs` entirely leaves two consecutive packs byte-identical and this
/// property green — measured, by deleting it (see `walk.rs`'s own
/// `each_directory_level_is_sorted_regardless_of_readdir_order`, which exists
/// for exactly this reason). So the archive's own entry ORDER is asserted
/// here too, against a fixture created in reverse-alphabetical order so that
/// readdir order and sorted order provably differ.
///
/// Byte-identity is still worth its half: it is what pins the composed
/// container-inside-codec path, where a codec could introduce a timestamp of
/// its own.
#[test]
fn packing_the_same_tree_twice_produces_identical_bytes() {
    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir_all(root.join("b")).unwrap();
    // Created in reverse-alphabetical order, so a filesystem that hands back
    // creation order (tmpfs, ext4 for a small directory) is provably not
    // handing back sorted order. The premise is asserted below rather than
    // assumed, because a filesystem that DID sort would make the ordering
    // half of this test unable to fail.
    for n in ["z.txt", "m.txt", "a.txt"] {
        std::fs::write(root.join(n), n.as_bytes()).unwrap();
    }
    std::fs::write(root.join("b/inner.txt"), b"inner").unwrap();

    let readdir_order: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    let mut sorted = readdir_order.clone();
    sorted.sort();
    assert_ne!(
        readdir_order, sorted,
        "this filesystem hands back directory entries already sorted, so the ordering \
         assertion below could not fail; the fixture needs a name order this filesystem \
         does not reproduce"
    );

    let listing = dir.join("order.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            listing.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let listed = run_output(&["list", listing.to_str().unwrap()]);
    let names: Vec<String> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(|l| l.split_whitespace().last().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        names,
        vec![
            "proj",
            "proj/a.txt",
            "proj/b",
            "proj/b/inner.txt",
            "proj/m.txt",
            "proj/z.txt",
        ],
        "entries must be written in sorted, depth-first order — `readdir` order was {readdir_order:?}"
    );

    for ext in ["tar", "tar.gz", "zip"] {
        let one = dir.join(format!("one.{ext}"));
        let two = dir.join(format!("two.{ext}"));
        for out in [&one, &two] {
            let st = Command::new(STUFFR)
                .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
                .output()
                .unwrap();
            assert!(
                st.status.success(),
                "stderr: {}",
                String::from_utf8_lossy(&st.stderr)
            );
        }
        assert_eq!(
            std::fs::read(&one).unwrap(),
            std::fs::read(&two).unwrap(),
            "the same tree must pack to the same `.{ext}` bytes; readdir order is not stable"
        );
    }
}

/// Property 3 — a failed write must leave the destination unpublished, and
/// must not take an existing archive at that path down with it.
///
/// The point of the outcome temp-then-rename, and of finishing the whole chain
/// BEFORE `publish`. Two failures, at the two points a pack can fail:
///
/// 1. AFTER the destination is opened, from inside the write loop, with
///    earlier entries already in the temp file — the only state `discard`
///    exists to clean up.
/// 2. BEFORE it is opened at all — a destination directory that cannot be
///    written, which fails in `Output::create`.
///
/// Only (1) exercises the `discard` arm, and the distinction is not
/// theoretical: the read-only-directory mechanism used for (1) in the first
/// round looked obviously correct and failed inside `Output::create`, before
/// `finish` existed at all, so `discard` was structurally unreachable and the
/// property tested nothing. That is why (1) is now driven by a container
/// REFUSING an entry the destination has already begun to hold, and why the
/// report records the `discard(finish)` -> `publish(finish)` mutation that
/// proves this one does reach it.
///
/// The refusal is cpio's 4 GiB `u32` size field, reached with a SPARSE file:
/// `check_u32_size` runs "before a single byte is read or allocated" (its own
/// comment), so this costs no disk and no time. Every other candidate needs a
/// race — a file truncated between the walk's `stat` and the write would do
/// it, but nothing outside the process can schedule that window, and a test
/// that only fails when it loses a race is worse than no test.
///
/// **This test is therefore coupled to that ordering**, which is the sort of
/// coupling a later refactor breaks without noticing: if `CpioWrite::add`
/// ever stops checking the DECLARED size and checks only the buffered one,
/// this test starts reading 4 GiB off a sparse file before it fails — slow
/// enough to look like a hang, and on a filesystem without sparse support it
/// would not run at all. `cpio.rs` carries the matching note at the check.
/// Anything that moves it needs a new mechanism for reaching a mid-write
/// failure cheaply, not a faster machine.
#[cfg(unix)]
#[test]
fn a_failed_write_never_replaces_an_existing_archive() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir(&root).unwrap();
    // Sorted first, so it is written into the temp file BEFORE the entry that
    // fails — without an entry already written, `discard` would have nothing
    // to clean up and this property would be about `create` again.
    std::fs::write(root.join("a.txt"), b"alpha").unwrap();

    let big = root.join("zbig.bin");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(u64::from(u32::MAX) + 1).unwrap();
    drop(f);
    let md = std::fs::metadata(&big).unwrap();
    assert!(
        md.len() > u64::from(u32::MAX),
        "the premise: the entry must exceed cpio's u32 size field"
    );
    assert!(
        md.blocks() * 512 < md.len(),
        "this filesystem did not make the fixture sparse ({} blocks for {} bytes); a \
         non-sparse one would write 4 GiB to disk here",
        md.blocks(),
        md.len()
    );

    let out = dir.join("existing.cpio");
    std::fs::write(&out, b"PRECIOUS EXISTING CONTENT").unwrap();

    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(3),
        "an entry this container cannot express is a capability limit, exit 3; stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    assert_eq!(
        std::fs::read(&out).unwrap(),
        b"PRECIOUS EXISTING CONTENT",
        "a pack that failed mid-write must not have replaced the archive already there"
    );
    // Nothing half-written left behind either: the destination directory holds
    // exactly what it held before, plus nothing.
    let mut siblings: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    siblings.sort();
    assert_eq!(
        siblings,
        vec!["existing.cpio".to_string(), "proj".to_string()],
        "a failed pack must leave no temp file behind"
    );

    // The second failure point: the destination cannot be created at all.
    let ro = dir.join("readonly");
    std::fs::create_dir(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        std::fs::File::create(ro.join("probe")).is_err(),
        "this test needs a non-root user; the read-only directory is still writable"
    );
    let target = ro.join("out.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.join("a.txt").to_str().unwrap(),
            "-o",
            target.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(1),
        "a destination that cannot be created is an i/o failure, exit 1; stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    assert!(!target.exists(), "a failed pack must publish nothing");

    // Restored before the harness's own cleanup walks the tree.
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// An unreadable FILE is a warning, not a failure — the ruling that makes the
/// walk consistent with itself.
///
/// `walk.rs`'s `descend` already skips a directory it cannot list, on the
/// stated grounds that "backing up a home directory with one root-owned
/// subdirectory in it is the ordinary case", and R9 chose skip-plus-warning
/// for the analogous case. An unreadable file was never ruled on and, until
/// this, propagated with a bare `?`: one unreadable file in a home directory
/// aborted `stuffr pack ~ -o backup.tar` and produced nothing at all.
///
/// Skipping is not silent. The entry is named, and `--strict-fidelity` turns
/// it into exit 4, the same as every other loss.
#[cfg(unix)]
#[test]
fn an_unreadable_file_is_skipped_with_a_warning_rather_than_failing_the_pack() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_dir();
    let root = dir.join("proj");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("a.txt"), b"alpha").unwrap();
    let unreadable = root.join("secret.txt");
    std::fs::write(&unreadable, b"beta").unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Loud rather than skipped: running as root makes the file readable, and
    // this test would then pass having proved nothing at all.
    assert!(
        std::fs::File::open(&unreadable).is_err(),
        "this test needs a non-root user; the unreadable file is still readable"
    );

    let out = dir.join("backup.tar");
    let st = Command::new(STUFFR)
        .args(["pack", root.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "one unreadable file must not lose the whole backup: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let stderr = String::from_utf8_lossy(&st.stderr);
    // The entry's NAME, not the word "fidelity": the pack summary carries a
    // loss count on every successful pack, warnings or none, so asserting on
    // that word would pass with the whole warnings vector gone.
    assert!(
        stderr.contains("proj/secret.txt"),
        "it must SAY WHAT it skipped, by name; stderr: {stderr}"
    );

    // And the rest of the tree really is in there.
    let listed = run_output(&["list", out.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(text.contains("proj/a.txt"), "{text}");
    assert!(
        !text.contains("secret.txt"),
        "an entry that could not be read must not be written as an empty one: {text}"
    );

    // Strict fidelity is what turns the loss into a refusal.
    let strict = dir.join("strict.tar");
    let st = Command::new(STUFFR)
        .args([
            "pack",
            root.to_str().unwrap(),
            "-o",
            strict.to_str().unwrap(),
            "--strict-fidelity",
        ])
        .output()
        .unwrap();
    assert_eq!(
        st.status.code(),
        Some(4),
        "strict fidelity must refuse a pack that skipped a file; stderr: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600)).unwrap();
}
